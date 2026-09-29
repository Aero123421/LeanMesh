#include "core/link/exchange.hpp"

#include <algorithm>
#include <cstring>

#include "core/engine.hpp"
#include "core/wire/cbor.hpp"
#include "core/wire/cbor_reader.hpp"
#include "security/crypto.hpp"

namespace lm::link {
namespace {

constexpr Duration k_linger = Duration::from_s(5);   // responder keeps its ACK for bind retransmits
constexpr uint8_t k_bind_version = 1;

} // namespace

// ---- RateGate ----
bool RateGate::allow(const MacAddr &mac, MonoTime now, Duration min) const {
    for (const Entry &e : entries_) {
        if (e.used && e.mac == mac) {
            return now - e.at >= min;
        }
    }
    return true;
}

void RateGate::touch(const MacAddr &mac, MonoTime now) {
    Entry *slot = nullptr;
    for (Entry &e : entries_) {
        if (e.used && e.mac == mac) {
            slot = &e;
            break;
        }
        if (!e.used && slot == nullptr) {
            slot = &e;
        }
    }
    if (slot == nullptr) {
        slot = &*std::min_element(entries_.begin(), entries_.end(),
                                  [](const Entry &a, const Entry &b) { return a.at < b.at; });
    }
    *slot = Entry{mac, now, true};
}

void RateGate::forget(const MacAddr &mac) {
    for (Entry &e : entries_) {
        if (e.used && e.mac == mac) {
            e = Entry{};
        }
    }
}

// ---- lifecycle ----
Status Exchange::start_initiator(const MacAddr &mac, MonoTime now) {
    if (!s_.identity.is_member()) {
        return Status::AuthPending;
    }
    if (busy()) {
        return Status::Busy;
    }
    if (phase_ == Phase::Linger) {
        finish_idle();
    }
    if (!s_.gate.allow(mac, now, s_.policy.handshake_gate)) {
        ++s_.stats.hs_rate_limited;
        return Status::RateLimited;
    }
    LM_TRY(begin_common(mac, true, now));
    s_.gate.touch(mac, now); // we chose to spend a full handshake on this peer
    s_.engine.random(MutByteView{xid_});
    phase_ = Phase::SendCred;
    expect_ = ObjKind::CredR;
    send_object(Tx::Cred, ObjKind::CredI, false);
    pump(now);
    return Status::Ok;
}

Status Exchange::begin_common(const MacAddr &mac, bool initiator, MonoTime now) {
    peer_ = PeerHandle{};
    peer_transient_ = false;
    if (Neighbor *n = s_.neighbors.find_mac(mac)) {
        peer_ = n->peer;
    } else {
        LM_TRY(s_.engine.acquire_peer(mac, PeerClass::Transient, peer_));
        peer_transient_ = true;
    }
    mac_ = mac;
    initiator_ = initiator;
    handle_ = Handle{0, ++handle_gen_};
    hard_deadline_ = now + s_.policy.exchange_deadline;
    deadline_ = hard_deadline_;
    rto_at_ = MonoTime::never();
    attempts_ = 0;
    rx_len_ = rx_total_ = 0;
    tx_ = Tx::None;
    tx_inflight_ = false;
    last_len_ = 0;
    peer_state_reset();
    pend_.wipe();
    last_failure_ = Status::Ok;
    phase_ = Phase::AwaitMsg;
    expect_ = ObjKind::CredI;
    ++s_.stats.hs_started;
    return Status::Ok;
}

void Exchange::peer_state_reset() { peer_state_ = PeerState{}; }

void Exchange::abort(Status why) {
    if (phase_ == Phase::Idle || phase_ == Phase::Zombie) {
        return;
    }
    if (phase_ != Phase::Linger) {
        ++s_.stats.hs_failed;
        last_failure_ = why;
    }
    if (peer_transient_ && !peer_.is_none()) {
        (void)s_.engine.release_peer(peer_);
    }
    peer_ = PeerHandle{};
    peer_transient_ = false;
    pend_.wipe();
    tx_ = Tx::None;
    rto_at_ = MonoTime::never();
    retry_at_ = MonoTime::never();
    deadline_ = MonoTime::never();
    rx_len_ = 0;
    (void)hs_.cancel(); // Busy when a job is in flight: wiped by its completion (zombie rule)
    if (job_ != Job::None) {
        cancelled_ = true;
        phase_ = Phase::Zombie;
    } else {
        phase_ = Phase::Idle;
    }
}

void Exchange::stop() {
    if (phase_ != Phase::Idle && phase_ != Phase::Zombie) {
        phase_ = Phase::Linger; // stopping is not a failure of the exchange: no failure count
        abort(Status::Ok);
    }
}

void Exchange::wipe() {
    (void)hs_.cancel();
    pend_.wipe();
}

MonoTime Exchange::deadline() const {
    if (phase_ == Phase::Idle || phase_ == Phase::Zombie) {
        return MonoTime::never();
    }
    return earliest(earliest(deadline_, rto_at_), retry_at_);
}

// ---- jobs ----
Status Exchange::job_entry(port::JobEnv &env, void *arg) {
    auto *x = static_cast<Exchange *>(arg);
    return x->job_ == Job::Verify ? verify_body(*x) : sec::HandshakeSlot::run_job(env, &x->hs_);
}

Status Exchange::verify_body(Exchange &x) {
    member::Bundle b;
    LM_TRY(member::bundle_parse(ByteView{x.rx_.data(), x.rx_len_}, b));
    PeerState &p = x.peer_state_;
    LM_TRY(member::check_device_credential(x.vin_.trust, b.device_cose, p.dc));
    LM_TRY(member::check_member_credential(x.vin_.delegation, b.member_cose, p.mc));
    LM_TRY(member::check_binding(p.dc, b.device_cose, p.mc));
    LM_TRY(sec::ccs_encode(ByteView{p.dc.serial.data(), p.dc.serial_len}, p.dc.key,
                           MutByteView{p.ccs}, p.ccs_len));
    p.mc_off = static_cast<std::size_t>(b.member_cose.data() - x.rx_.data());
    p.mc_len = b.member_cose.size();
    return sec::sha256(b.member_cose, p.mc_hash);
}

Status Exchange::run_verify() {
    vin_.trust = s_.identity.trust();
    vin_.delegation = s_.identity.delegation();
    job_ = Job::Verify;
    const Status st = s_.engine.submit_job(JobOwner::Link, handle_, JobClass::PublicKey, &job_entry, this);
    if (st != Status::Ok) {
        job_ = Job::None;
    }
    return st;
}

Status Exchange::run_hs(sec::HsStep step, ByteView input) {
    LM_TRY(hs_.prepare(step, input));
    job_ = Job::Hs;
    const Status st = s_.engine.submit_job(JobOwner::Link, handle_, JobClass::PublicKey, &job_entry, this);
    if (st != Status::Ok) {
        job_ = Job::None;
        hs_.unprepare();
        return st;
    }
    hs_step_ = step;
    return Status::Ok;
}

void Exchange::on_job_done(Handle slot, Status job_status, MonoTime now) {
    if (phase_ == Phase::Zombie) {
        if (job_ == Job::Hs) {
            (void)hs_.complete(job_status); // wipes the cancelled slot
        }
        job_ = Job::None;
        cancelled_ = false;
        phase_ = Phase::Idle;
        return;
    }
    if (slot != handle_ || job_ == Job::None) {
        return; // stale completion of an earlier exchange
    }
    const Job j = job_;
    job_ = Job::None;
    if (job_status != Status::Ok) {
        if (j == Job::Hs) {
            (void)hs_.complete(job_status); // aborts the handshake, wipes the secrets
        } else {
            ++s_.stats.cred_rejected;
        }
        abort(job_status);
        return;
    }
    if (j == Job::Verify) {
        after_verify(now);
    } else {
        after_hs(now);
    }
}

// ---- owner-side steps ----
void Exchange::after_verify(MonoTime now) {
    const member::MemberCredential &mc = peer_state_.mc;
    Status st = Status::Ok;
    if (peer_state_.dc.device == s_.identity.self()) {
        st = Status::AuthRejected; // a device does not link to itself
    } else {
        st = s_.identity.floors().check(peer_state_.dc.device, mc.assignment, mc.membership);
    }
    if (st == Status::Ok) {
        switch (member::check_lease(mc, s_.root_time)) {
        case DeadlineCheck::After:
            st = Status::Expired;
            break;
        case DeadlineCheck::Uncertain:
            ++s_.stats.cred_time_uncertain; // no root time yet: link comes first, time sync follows
            break;
        case DeadlineCheck::Before:
            break;
        }
    }
    if (st != Status::Ok) {
        ++s_.stats.cred_rejected;
        abort(st);
        return;
    }
    if (initiator_) {
        start_hs_initiator(now);
        return;
    }
    phase_ = Phase::SendCred;
    send_object(Tx::Cred, ObjKind::CredR, false);
    pump(now);
}

void Exchange::start_hs_initiator(MonoTime /*now*/) {
    const ByteView peers[1] = {ByteView{peer_state_.ccs.data(), peer_state_.ccs_len}};
    Status st = hs_.begin(sec::HsRole::Initiator, s_.identity.key(), s_.identity.ccs(), peers, 1);
    if (st == Status::Ok) {
        phase_ = Phase::Hs;
        st = run_hs(sec::HsStep::M1Compose);
    }
    if (st != Status::Ok) {
        abort(st);
    }
}

Status Exchange::make_context(sec::SessionContext &ctx) const {
    const member::LocalIdentity &id = s_.identity;
    Sha256Digest self_hash{};
    LM_TRY(sec::sha256(id.member_cose(), self_hash));
    ctx.purpose = sec::Purpose::Link;
    ctx.fleet = id.trust().fleet;
    ctx.domain = id.delegation().domain;
    const member::MemberCredential &pm = peer_state_.mc;
    if (initiator_) {
        ctx.initiator = id.self();
        ctx.responder = peer_state_.dc.device;
        ctx.assignment_i = id.member().assignment;
        ctx.assignment_r = pm.assignment;
        ctx.membership_i = id.member().membership;
        ctx.membership_r = pm.membership;
        ctx.credential_hash_i = self_hash;
        ctx.credential_hash_r = peer_state_.mc_hash;
    } else {
        ctx.initiator = peer_state_.dc.device;
        ctx.responder = id.self();
        ctx.assignment_i = pm.assignment;
        ctx.assignment_r = id.member().assignment;
        ctx.membership_i = pm.membership;
        ctx.membership_r = id.member().membership;
        ctx.credential_hash_i = peer_state_.mc_hash;
        ctx.credential_hash_r = self_hash;
    }
    return Status::Ok;
}

void Exchange::after_hs(MonoTime now) {
    const sec::HsStep step = hs_step_;
    Status st = hs_.complete(Status::Ok);
    if (st != Status::Ok) {
        abort(st);
        return;
    }
    using S = sec::HsStep;
    switch (step) {
    case S::M1Compose:
        stage_frame(ObjKind::Msg1, hs_.output());
        phase_ = Phase::AwaitMsg;
        expect_ = ObjKind::Msg2;
        send_object(Tx::Frame, ObjKind::Msg1, false);
        break;
    case S::M2Process:
        phase_ = Phase::Hs;
        st = run_hs(S::M3Compose);
        break;
    case S::M3Compose:
        stage_frame(ObjKind::Msg3, hs_.output());
        phase_ = Phase::AwaitMsg;
        expect_ = ObjKind::Msg4;
        send_object(Tx::Frame, ObjKind::Msg3, false);
        break;
    case S::M4Process:
    case S::M3Process:
        st = make_context(ctx_);
        if (st == Status::Ok) {
            st = hs_.set_context(ctx_);
        }
        if (st == Status::Ok) {
            ctx_hash_ = hs_.context_hash();
            phase_ = Phase::Hs;
            // Initiator: keys next. Responder: compose message_4, then keys.
            st = run_hs(step == S::M4Process ? S::Export : S::M4Compose);
        }
        break;
    case S::M1Process:
        phase_ = Phase::Hs;
        st = run_hs(S::M2Compose);
        break;
    case S::M2Compose:
        stage_frame(ObjKind::Msg2, hs_.output());
        phase_ = Phase::AwaitMsg;
        expect_ = ObjKind::Msg3;
        send_object(Tx::Frame, ObjKind::Msg2, false);
        break;
    case S::M4Compose:
        // Held back until the keys exist: SESSION_BIND may follow message_4 immediately.
        stage_frame(ObjKind::Msg4, hs_.output());
        phase_ = Phase::Hs;
        st = run_hs(S::Export);
        break;
    case S::Export:
        finish_keys(now);
        return;
    case S::None:
        st = Status::RecoveryRequired;
        break;
    }
    if (st != Status::Ok) {
        abort(st);
        return;
    }
    pump(now);
}

Status Exchange::alloc_sid(uint32_t &sid) {
    for (int i = 0; i < 8; ++i) {
        std::array<uint8_t, 4> b{};
        s_.engine.random(MutByteView{b});
        const uint32_t v = (uint32_t{b[0]} << 24U) | (uint32_t{b[1]} << 16U) | (uint32_t{b[2]} << 8U) | b[3];
        if (v != 0 && !s_.neighbors.sid_in_use(v)) {
            sid = v;
            return Status::Ok;
        }
    }
    return Status::RecoveryRequired;
}

void Exchange::finish_keys(MonoTime now) {
    sec::RecordKeys keys;
    Status st = hs_.take_keys(keys);
    if (st == Status::Ok) {
        pend_.rec.install(keys);
        sec::secure_zero(MutByteView{reinterpret_cast<uint8_t *>(&keys), sizeof keys});
        pend_.ctx_hash = ctx_hash_;
        pend_.born = now;
        pend_.valid_until = now + s_.policy.key_lifetime;
        pend_.active = true;
        st = alloc_sid(pend_.rx_sid);
    }
    if (st == Status::Ok && initiator_) {
        s_.engine.random(MutByteView{bind_nonce_});
        st = seal_bind(pend_, bind_nonce_);
    }
    if (st != Status::Ok) {
        abort(st);
        return;
    }
    phase_ = Phase::AwaitBind;
    send_object(Tx::Frame, ObjKind::Msg4, false);
    pump(now);
}

// SESSION_BIND / ACK = [1, ctx_hash, receiver_sid, nonce]; sealed under the new key with the
// sender's own reserved SID in the header (S5-D3). Kept in last_ for byte-identical retransmission.
Status Exchange::seal_bind(SessionKeys &k, const std::array<uint8_t, 16> &nonce) {
    std::array<uint8_t, 64> plain{};
    wire::CborWriter w{MutByteView{plain}};
    w.array(4);
    w.uint(k_bind_version);
    w.bytes(ByteView{k.ctx_hash});
    w.uint(k.rx_sid);
    w.bytes(ByteView{nonce});
    LM_TRY(w.finish());
    SealedFrame f;
    LM_TRY(seal_frame(k, wire::FrameKind::Edhoc, domain_hint_of(s_.identity.delegation().domain),
                      k.rx_sid, w.written(), f));
    std::memcpy(last_.data(), f.bytes.data(), f.len);
    last_len_ = f.len;
    return Status::Ok;
}

bool Exchange::check_bind_body(ByteView plain, uint32_t header_sid, uint32_t &sid,
                               std::array<uint8_t, 16> &nonce) const {
    if (wire::cbor_validate(plain) != Status::Ok) {
        return false;
    }
    wire::CborReader r{plain};
    (void)r.array(4, 4);
    (void)r.uint_in(k_bind_version, k_bind_version);
    const ByteView hash = r.bstr(32, 32);
    const uint64_t s = r.uint_in(1, 0xFFFFFFFFULL);
    const ByteView n = r.bstr(16, 16);
    if (r.finish() != Status::Ok || !bytes_equal(hash, ByteView{ctx_hash_}) || s != header_sid) {
        return false;
    }
    sid = static_cast<uint32_t>(s);
    std::copy(n.begin(), n.end(), nonce.begin());
    return true;
}

bool Exchange::on_bind_frame(const MacAddr &src, const wire::LinkHeader &h, ByteView frame,
                             MonoTime now) {
    if (src != mac_) {
        return false;
    }
    if (phase_ == Phase::Linger && !initiator_) {
        // A bind retransmission: the peer did not see our ACK. Answer with the same bytes.
        Neighbor *n = s_.neighbors.by_tx_sid(src, h.link_sid);
        if (n == nullptr) {
            return false;
        }
        Opened op;
        const Status st = open_frame(n->cur, h, frame, op);
        if (st == Status::Replay && op.verdict == sec::ReplayVerdict::Duplicate) {
            send_object(Tx::Frame, ObjKind::Msg4, true);
            pump(now);
        }
        return true;
    }
    if (phase_ != Phase::AwaitBind || !pend_.active) {
        return false;
    }
    Opened op;
    const Status st = open_frame(pend_, h, frame, op);
    if (st != Status::Ok) {
        if (st == Status::AuthRejected) {
            ++s_.stats.rx_auth_fail;
        }
        return true; // not accepted; the exchange continues until its retransmissions/deadline
    }
    uint32_t sid = 0;
    std::array<uint8_t, 16> nonce{};
    if (!check_bind_body(op.view(), h.link_sid, sid, nonce) ||
        (initiator_ && nonce != bind_nonce_)) {
        ++s_.stats.bind_bad;
        return true;
    }
    pend_.rec.accept(h.link_counter);
    pend_.tx_sid = sid;
    peer_sid_ = sid;
    Status is = install_session(now);
    if (is != Status::Ok) {
        abort(is);
        return true;
    }
    ++s_.stats.hs_completed;
    if (initiator_) {
        finish_idle();
        return true;
    }
    Neighbor *n = s_.neighbors.find_device(peer_state_.dc.device);
    is = n != nullptr ? seal_bind(n->cur, nonce) : Status::RecoveryRequired;
    if (is != Status::Ok) {
        // The session exists on our side; the peer will retry and fail its own attempts.
        finish_idle();
        return true;
    }
    phase_ = Phase::Linger;
    deadline_ = now + k_linger;
    rto_at_ = MonoTime::never();
    send_object(Tx::Frame, ObjKind::Msg4, false);
    pump(now);
    return true;
}

Status Exchange::install_session(MonoTime now) {
    Neighbors &nb = s_.neighbors;
    const DeviceId &device = peer_state_.dc.device;
    Neighbor *n = nb.find_device(device);
    const bool fresh_entry = n == nullptr;
    if (n != nullptr && n->mac != mac_) {
        (void)s_.engine.release_peer(n->peer); // the same device now answers from another address
        n->peer = PeerHandle{};
        n->mac = mac_;
    }
    Neighbor *other = nb.find_mac(mac_);
    if (other != nullptr && other != n) {
        other->peer = PeerHandle{}; // its handle is ours (same MAC): keep the driver registration
        nb.remove(*other);
        ++s_.stats.sessions_replaced;
    }
    if (n == nullptr) {
        n = nb.acquire();
        if (n == nullptr) {
            return Status::NoCapacity;
        }
    }
    PeerHandle reg = peer_;
    if (peer_transient_) {
        const Status ps = s_.engine.peers().promote(peer_, reg);
        if (ps != Status::Ok) {
            if (fresh_entry) {
                nb.remove(*n);
            }
            return ps; // NoCapacity keeps the transient reservation; abort() releases it
        }
        peer_transient_ = false;
        peer_ = reg;
    }
    n->peer = reg;
    n->mac = mac_;
    n->device = device;
    n->address = peer_state_.mc.address;
    n->assignment = peer_state_.mc.assignment;
    n->membership = peer_state_.mc.membership;
    n->role = peer_state_.mc.role;
    n->prev.wipe();
    if (n->cur.active) {
        n->prev = n->cur;
        n->prev.valid_until = earliest(n->prev.valid_until, now + s_.policy.prev_grace);
        ++s_.stats.sessions_replaced;
    }
    n->cur = pend_;
    pend_.wipe();
    n->rotate_wanted = false;
    return Status::Ok;
}

void Exchange::finish_idle() {
    pend_.wipe();
    tx_ = Tx::None;
    rto_at_ = MonoTime::never();
    retry_at_ = MonoTime::never();
    deadline_ = MonoTime::never();
    rx_len_ = 0;
    phase_ = Phase::Idle;
}

} // namespace lm::link
