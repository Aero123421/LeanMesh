// The exchange state machine: lifecycle, worker jobs, owner-side steps and the link session
// binding. exchange_io.cpp holds the carrier side (receive, assembly, transmit, timers);
// exchange_join.cpp and exchange_end.cpp what differs for the JOIN_ONLY and the end-session modes.
#include "core/link/exchange.hpp"

#include <algorithm>
#include <cstring>
#include <utility>

#include "core/engine.hpp"
#include "core/wire/cbor.hpp"
#include "core/wire/cbor_reader.hpp"
#include "security/crypto.hpp"

namespace lm::link {
namespace {

// The same handshake event counted in the link counters (link/join modes) or the end counters.
struct CountField {
    uint64_t LinkStats::*link;
    uint64_t EndStats::*end;
};
constexpr CountField k_count_fields[] = {
    {&LinkStats::hs_started, &EndStats::started},
    {&LinkStats::hs_completed, &EndStats::completed},
    {&LinkStats::hs_failed, &EndStats::failed},
    {&LinkStats::hs_rate_limited, &EndStats::rate_limited},
    {&LinkStats::hs_retransmits, &EndStats::retransmits},
    {&LinkStats::cred_rejected, &EndStats::cred_rejected},
    {&LinkStats::cred_time_uncertain, &EndStats::cred_time_uncertain},
    {&LinkStats::bind_bad, &EndStats::bind_bad},
};

} // namespace

void Exchange::count(Count c) {
    const CountField &f = k_count_fields[static_cast<std::size_t>(c)];
    ++(mode_ == Mode::End ? end_stats_.*f.end : s_.stats.*f.link);
}

// ---- lifecycle ----
Status Exchange::start_initiator(const MacAddr &mac, MonoTime now) {
    if (!s_.identity.is_member()) {
        return Status::AuthPending;
    }
    return start_1hop(Mode::Link, mac, now);
}

// Initiator over one hop (link or join): the slot, the MAC's rate gate, a driver registration.
Status Exchange::start_1hop(Mode mode, const MacAddr &mac, MonoTime now) {
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
    LM_TRY(acquire_link_peer(mac));
    begin_common(mode, true, now);
    s_.gate.touch(mac, now); // we chose to spend a full handshake on this peer
    s_.engine.random(MutByteView{xid_});
    phase_ = Phase::SendCred;
    expect_ = ObjKind::CredR;
    send_object(ObjKind::CredI, false);
    pump(now);
    return Status::Ok;
}

// The driver registration of a 1-hop peer: the neighbour's own, or a transient one for the
// exchange.
Status Exchange::acquire_link_peer(const MacAddr &mac) {
    peer_ = PeerHandle{};
    peer_transient_ = false;
    if (Neighbor *n = s_.neighbors.find_mac(mac)) {
        peer_ = n->peer;
    } else {
        LM_TRY(s_.engine.acquire_peer(mac, PeerClass::Transient, peer_));
        peer_transient_ = true;
    }
    mac_ = mac;
    return Status::Ok;
}

void Exchange::begin_common(Mode mode, bool initiator, MonoTime now) {
    mode_ = mode;
    initiator_ = initiator;
    handle_ = Handle{0, ++handle_gen_ == 0 ? ++handle_gen_ : handle_gen_};
    hard_deadline_ = now + s_.policy.exchange_deadline;
    deadline_ = hard_deadline_;
    rto_at_ = retry_at_ = MonoTime::never();
    attempts_ = 0;
    rx_len_ = rx_total_ = 0;
    tx_active_ = tx_inflight_ = false;
    stage_len_ = 0;
    peer_state_ = PeerState{};
    peer_known_ = false;
    pend_.wipe();
    last_failure_ = Status::Ok;
    phase_ = Phase::AwaitMsg;
    expect_ = ObjKind::CredI;
    count(Count::Started);
}

void Exchange::abort(Status why) {
    if (phase_ == Phase::Idle || phase_ == Phase::Zombie) {
        return;
    }
    const bool lingering = phase_ == Phase::Linger;
    if (!lingering) {
        count(Count::Failed);
        last_failure_ = why;
        if ((mode_ == Mode::JoinInit || (mode_ == Mode::Link && initiator_)) &&
            s_.join.exchange_failed != nullptr) {
            s_.join.exchange_failed(s_.join.ctx, why); // [S8] the joiner learns the attempt is over
        }
    }
    if (peer_transient_ && !peer_.is_none()) {
        (void)s_.engine.release_peer(peer_);
    }
    peer_ = PeerHandle{};
    peer_transient_ = false;
    const bool notify_end = mode_ == Mode::End && !lingering && peer_known_ && end_.done != nullptr;
    const DeviceId peer = peer_id_;
    finish_idle();
    (void)hs_.cancel(); // Busy when a job is in flight: wiped by its completion (zombie rule)
    if (job_ != Job::None) {
        cancelled_ = true;
        phase_ = Phase::Zombie;
    }
    if (notify_end) {
        end_.done(end_.ctx, peer, why,
                  s_.engine.step_time()); // the delivery module re-plans its sends
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

void Exchange::finish_idle() {
    pend_.wipe();
    stage_release();
    tx_active_ = false;
    rto_at_ = retry_at_ = deadline_ = MonoTime::never();
    rx_len_ = 0;
    phase_ = Phase::Idle;
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

// Worker. Link and end: the bundle [DeviceCredential, MemberCredential] under the fleet trust
// anchor and this domain's delegation, bound to each other; the peer's CCS for EDHOC.
Status Exchange::verify_body(Exchange &x) {
    if (x.mode_ == Mode::JoinInit || x.mode_ == Mode::JoinResp) {
        return verify_join_body(x);
    }
    member::Bundle b;
    LM_TRY(member::bundle_parse(ByteView{x.rx_.data(), x.rx_len_}, b));
    PeerState &p = x.peer_state_;
    LM_TRY(member::check_device_credential(x.vin_.trust, b.device_cose, p.dc));
    LM_TRY(member::check_member_credential(x.vin_.delegation, b.member_cose, p.mc));
    LM_TRY(member::check_binding(p.dc, b.device_cose, p.mc));
    LM_TRY(sec::ccs_encode(ByteView{p.dc.serial.data(), p.dc.serial_len}, p.dc.key,
                           MutByteView{p.ccs}, p.ccs_len));
    return sec::sha256(b.member_cose, p.mc_hash);
}

Status Exchange::run_verify() {
    vin_.trust = s_.identity.trust();
    vin_.delegation = s_.identity.delegation();
    job_ = Job::Verify;
    const Status st =
        s_.engine.submit_job(JobOwner::Link, handle_, JobClass::PublicKey, &job_entry, this);
    if (st != Status::Ok) {
        job_ = Job::None;
    }
    return st;
}

Status Exchange::run_hs(sec::HsStep step, ByteView input) {
    LM_TRY(hs_.prepare(step, input));
    job_ = Job::Hs;
    const Status st =
        s_.engine.submit_job(JobOwner::Link, handle_, JobClass::PublicKey, &job_entry, this);
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
            count(Count::CredRejected);
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
    if (mode_ == Mode::JoinInit || mode_ == Mode::JoinResp) {
        // [S8] JOIN_ONLY: no member credentials exist yet, so no floors/lease checks here; the
        // ledger decides on the JoinRequest (ticket, expected entry, revocation, capacity).
        if (mode_ == Mode::JoinInit) {
            join_out_->known = true;
            start_hs(sec::HsRole::Initiator, ByteView{}, now);
            return;
        }
        const Status st = build_join_response();
        if (st != Status::Ok) {
            abort(st);
            return;
        }
        phase_ = Phase::SendCred;
        send_object(ObjKind::CredR, false);
        pump(now);
        return;
    }
    const Status st = admit_peer();
    if (st != Status::Ok) {
        count(Count::CredRejected);
        abort(st);
        return;
    }
    if (mode_ == Mode::End) {
        peer_id_ = peer_state_.dc.device;
        peer_known_ = true;
    }
    if (initiator_) {
        start_hs(sec::HsRole::Initiator, ByteView{}, now);
        return;
    }
    phase_ = Phase::SendCred;
    send_object(ObjKind::CredR, false);
    pump(now);
}

// Link and end: may this verified member hold a session with us now?
Status Exchange::admit_peer() {
    const member::MemberCredential &mc = peer_state_.mc;
    const DeviceId &device = peer_state_.dc.device;
    if (device == s_.identity.self()) {
        return Status::AuthRejected; // a device does not talk to itself
    }
    if (mode_ == Mode::End && ((peer_known_ && device != peer_id_) || mc.address != route_.dest)) {
        return Status::AuthRejected; // not the peer we asked for / the route ends at another node
    }
    LM_TRY(s_.identity.floors().check(device, mc.assignment, mc.membership));
    if (mode_ == Mode::Link && !initiator_ && s_.join.link_admit != nullptr &&
        !s_.join.link_admit(s_.join.ctx, device, mc)) {
        return Status::Revoked; // [S8] root ledger: not ACTIVE with this membership generation
    }
    const RootTimeBound rt = mode_ == Mode::End ? root_time(s_.engine.step_time()) : s_.root_time;
    switch (member::check_lease(mc, rt)) {
    case DeadlineCheck::After:
        return Status::Expired;
    case DeadlineCheck::Uncertain:
        count(Count::TimeUncertain); // no root time yet: the session comes first, time sync follows
        break;
    case DeadlineCheck::Before:
        break;
    }
    return Status::Ok;
}

// Starts EDHOC with the verified peer's CCS as the only acceptable credential. The initiator
// composes message_1, the responder processes the received one.
void Exchange::start_hs(sec::HsRole role, ByteView msg1, MonoTime /*now*/) {
    const ByteView peers[1] = {ByteView{peer_state_.ccs.data(), peer_state_.ccs_len}};
    Status st = hs_.begin(role, s_.identity.key(), s_.identity.ccs(), peers, 1);
    if (st == Status::Ok) {
        phase_ = Phase::Hs;
        st = role == sec::HsRole::Initiator ? run_hs(sec::HsStep::M1Compose)
                                            : run_hs(sec::HsStep::M1Process, msg1);
    }
    if (st != Status::Ok) {
        abort(st);
    }
}

Status Exchange::make_context(sec::SessionContext &ctx) const {
    if (mode_ == Mode::JoinInit || mode_ == Mode::JoinResp) {
        return make_join_context(ctx);
    }
    const member::LocalIdentity &id = s_.identity;
    Sha256Digest self_hash{};
    LM_TRY(sec::sha256(id.member_cose(), self_hash));
    ctx.purpose = mode_ == Mode::End ? sec::Purpose::End : sec::Purpose::Link;
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

FrameBuf *Exchange::stage_buf() {
    if (TxFrame *f = s_.engine.frames().get(stage_h_)) {
        return &f->frame;
    }
    TxFrame *f = s_.engine.frames().borrow(stage_h_);
    return f != nullptr ? &f->frame : nullptr;
}

void Exchange::stage_release() {
    (void)s_.engine.frames().release(stage_h_); // false for a stale handle: nothing to give back
    stage_h_ = Handle{};
    stage_len_ = 0;
}

// Local shortage (no pool frame) or an object that cannot be one frame: the exchange is aborted by the
// caller, never truncated.
Status Exchange::stage(ObjKind kind, ByteView bytes) {
    FrameBuf *b = stage_buf();
    if (b == nullptr) {
        return Status::NoCapacity;
    }
    if (bytes.size() > k_stage_bytes) {
        return Status::PayloadTooLarge;
    }
    std::memcpy(b->bytes.data(), bytes.data(), bytes.size());
    stage_len_ = bytes.size();
    staged_ = kind;
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
        st = stage(ObjKind::Msg1, hs_.output());
        if (st != Status::Ok) {
            break;
        }
        phase_ = Phase::AwaitMsg;
        expect_ = ObjKind::Msg2;
        send_object(ObjKind::Msg1, false);
        break;
    case S::M2Process:
        phase_ = Phase::Hs;
        st = run_hs(S::M3Compose);
        break;
    case S::M3Compose:
        st = stage(ObjKind::Msg3, hs_.output());
        if (st != Status::Ok) {
            break;
        }
        phase_ = Phase::AwaitMsg;
        expect_ = ObjKind::Msg4;
        send_object(ObjKind::Msg3, false);
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
        st = stage(ObjKind::Msg2, hs_.output());
        if (st != Status::Ok) {
            break;
        }
        phase_ = Phase::AwaitMsg;
        expect_ = ObjKind::Msg3;
        send_object(ObjKind::Msg2, false);
        break;
    case S::M4Compose:
        // Held back until the keys exist: SESSION_BIND may follow message_4 immediately.
        st = stage(ObjKind::Msg4, hs_.output());
        if (st != Status::Ok) {
            break;
        }
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

// A receiver-assigned SID, unique among this node's sessions of the same purpose (docs/06 §5).
Status Exchange::alloc_sid(uint32_t &sid) {
    for (int i = 0; i < 8; ++i) {
        std::array<uint8_t, 4> b{};
        s_.engine.random(MutByteView{b});
        const uint32_t v =
            (uint32_t{b[0]} << 24U) | (uint32_t{b[1]} << 16U) | (uint32_t{b[2]} << 8U) | b[3];
        const bool used = mode_ == Mode::End
                              ? delivery::is_reserved_sid(v) || end_.sessions->sid_in_use(v)
                              : s_.neighbors.sid_in_use(v);
        if (v != 0 && !used) {
            sid = v;
            return Status::Ok;
        }
    }
    return Status::RecoveryRequired;
}

// Keys exist: the initiator seals SESSION_BIND, the responder sends its held message_4. Nothing is
// installed before the peer's bind (initiator: its ACK) was verified.
void Exchange::finish_keys(MonoTime now) {
    sec::RecordKeys keys;
    Status st = hs_.take_keys(keys);
    if (st == Status::Ok) {
        st =
            pend_.rec.install(std::move(keys)); // one-shot: Conflict if pend_ still holds a session
        if (st == Status::Ok) {
            pend_.ctx_hash = ctx_hash_;
            pend_.born = now;
            pend_.valid_until = now + s_.policy.key_lifetime;
            pend_.active = true;
            st = alloc_sid(pend_.rx_sid);
        }
    }
    if (st == Status::Ok && initiator_) {
        s_.engine.random(MutByteView{bind_nonce_});
        st = mode_ == Mode::End ? seal_end_bind(pend_.rec, pend_.ctx_hash, pend_.rx_sid)
                                : seal_bind(pend_, bind_nonce_);
    }
    if (st != Status::Ok) {
        abort(st);
        return;
    }
    phase_ = Phase::AwaitBind;
    send_object(staged_, false); // initiator: SESSION_BIND; responder: message_4
    pump(now);
}

// SESSION_BIND / ACK = [1, ctx_hash, receiver_sid, nonce]; sealed under the new key with the
// sender's own reserved SID in the header (S5-D3). Staged for byte-identical retransmission.
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
    LM_TRY(seal_frame(k, wire::FrameKind::Edhoc, hint(), k.rx_sid, w.written(), f));
    return stage(initiator_ ? ObjKind::Bind : ObjKind::BindAck, f.view());
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
    if (src != mac_ || mode_ == Mode::End) {
        return false;
    }
    if (phase_ == Phase::Linger && !initiator_) {
        // A bind retransmission: the peer did not see our ACK. Answer with the same bytes.
        Neighbor *n = s_.neighbors.by_tx_sid(src, h.link_sid);
        if (n == nullptr || n->join_only != (mode_ != Mode::Link)) {
            return false;
        }
        Opened op;
        const Status st = open_frame(n->cur, h, frame, op);
        if (st == Status::Replay && op.verdict == sec::ReplayVerdict::Duplicate) {
            send_object(ObjKind::BindAck, true);
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
        count(Count::BindBad);
        return true;
    }
    pend_.rec.accept(h.link_counter);
    pend_.tx_sid = sid;
    Status is = mode_ == Mode::Link ? install_session(now) : install_join_session(now);
    if (is != Status::Ok) {
        abort(is);
        return true;
    }
    count(Count::Completed);
    if (initiator_) {
        finish_idle();
        return true;
    }
    Neighbor *n = installed();
    is = n != nullptr ? seal_bind(n->cur, nonce) : Status::RecoveryRequired;
    if (is != Status::Ok) {
        // The session exists on our side; the peer will retry and fail its own attempts.
        finish_idle();
        return true;
    }
    phase_ = Phase::Linger;
    deadline_ = now + s_.policy.linger;
    rto_at_ = MonoTime::never();
    send_object(ObjKind::BindAck, false);
    pump(now);
    return true;
}

Neighbor *Exchange::installed() {
    return mode_ == Mode::Link ? s_.neighbors.find_device(peer_state_.dc.device)
                               : s_.neighbors.find_join(peer_state_.dc.device);
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
    if (n->cur.active) {
        nb.retire(n->mac, std::move(n->cur), now + s_.policy.prev_grace);
        ++s_.stats.sessions_replaced;
    }
    n->cur = std::move(pend_);
    pend_.wipe();
    n->rotate_wanted = false;
    if (s_.join.link_up != nullptr) {
        s_.join.link_up(s_.join.ctx, n->device,
                        n->role); // [S8] e.g. the root confirmation still owed
    }
    return Status::Ok;
}

} // namespace lm::link
