#include "core/delivery/end_exchange.hpp"

#include <algorithm>
#include <cstring>
#include <utility>

#include "core/engine.hpp"
#include "core/wire/cbor.hpp"
#include "core/wire/cbor_reader.hpp"
#include "security/crypto.hpp"

namespace lm::delivery {
namespace {

constexpr Duration k_pump_retry = Duration::from_ms(20);
constexpr Duration k_msg1_wait = Duration::from_s(4); // an unauthenticated CredI holds the slot this long
constexpr uint8_t k_bind_version = 1;
constexpr std::size_t k_obj_header = 5; // kind u8, total u16, offset u16

} // namespace

// ---- lifecycle ----
Status EndExchange::begin_common(const DeviceId *peer, MonoTime now) {
    owner_ = Handle{0, ++owner_gen_};
    hard_deadline_ = now + policy_.exchange_deadline;
    deadline_ = hard_deadline_;
    rto_at_ = retry_at_ = MonoTime::never();
    attempts_ = 0;
    rx_len_ = rx_total_ = 0;
    tx_active_ = tx_inflight_ = false;
    peer_state_ = PeerState{};
    pend_.wipe();
    last_failure_ = Status::Ok;
    peer_known_ = peer != nullptr;
    if (peer != nullptr) {
        peer_ = *peer;
    }
    bind_len_ = 0;
    phase_ = EndPhase::AwaitMsg;
    expect_ = Obj::CredI;
    ++stats_.started;
    return Status::Ok;
}

Status EndExchange::start_initiator(const DeviceId &peer, const PathSpec &route, MonoTime now) {
    now_ = now;
    if (!identity_.is_member()) {
        return Status::AuthPending;
    }
    if (busy()) {
        return Status::Busy;
    }
    if (phase_ == EndPhase::Linger) {
        finish_idle();
    }
    if (route.len == 0 || peer == identity_.self()) {
        return Status::InvalidArgument;
    }
    if (!gate_allow(peer, now)) {
        ++stats_.rate_limited;
        return Status::RateLimited;
    }
    LM_TRY(begin_common(&peer, now));
    gate_touch(peer, now); // we chose to spend a full handshake on this peer
    initiator_ = true;
    route_ = route;
    engine_.random(MutByteView{xid_});
    phase_ = EndPhase::SendCred;
    expect_ = Obj::CredR;
    send_object(Obj::CredI, identity_.bundle(), false);
    pump(now);
    return Status::Ok;
}

void EndExchange::abort(Status why) {
    if (phase_ == EndPhase::Idle || phase_ == EndPhase::Zombie) {
        return;
    }
    const bool lingering = phase_ == EndPhase::Linger;
    if (!lingering) {
        ++stats_.failed;
        last_failure_ = why;
    }
    pend_.wipe();
    tx_active_ = false;
    rto_at_ = retry_at_ = deadline_ = MonoTime::never();
    rx_len_ = 0;
    (void)mem_.hs.cancel(); // Busy when a job is in flight: wiped by its completion (zombie rule)
    const bool had_peer = peer_known_;
    const DeviceId peer = peer_;
    phase_ = job_ != Job::None ? EndPhase::Zombie : EndPhase::Idle;
    if (!lingering && had_peer && tr_.done != nullptr) {
        tr_.done(tr_.ctx, peer, why, now_);
    }
}

void EndExchange::finish_idle() {
    pend_.wipe();
    tx_active_ = false;
    rto_at_ = retry_at_ = deadline_ = MonoTime::never();
    rx_len_ = 0;
    phase_ = EndPhase::Idle;
}

void EndExchange::stop() {
    if (phase_ != EndPhase::Idle && phase_ != EndPhase::Zombie) {
        phase_ = EndPhase::Linger; // stopping is not a failure of the exchange
        abort(Status::Ok);
    }
}

MonoTime EndExchange::deadline() const {
    if (phase_ == EndPhase::Idle || phase_ == EndPhase::Zombie) {
        return MonoTime::never();
    }
    return earliest(earliest(deadline_, rto_at_), retry_at_);
}

Duration EndExchange::rto() const { return round_timeout(route_.len); }

bool EndExchange::gate_allow(const DeviceId &p, MonoTime now) const {
    for (const Gate &g : gate_) {
        if (g.used && g.peer == p) {
            return now - g.at >= policy_.handshake_gate;
        }
    }
    return true;
}

void EndExchange::gate_forget(const DeviceId &p) {
    for (Gate &g : gate_) {
        if (g.used && g.peer == p) {
            g = Gate{};
        }
    }
}

void EndExchange::gate_touch(const DeviceId &p, MonoTime now) {
    Gate *slot = nullptr;
    for (Gate &g : gate_) {
        if (g.used && g.peer == p) {
            slot = &g;
            break;
        }
        if (!g.used && slot == nullptr) {
            slot = &g;
        }
    }
    if (slot == nullptr) {
        slot = &*std::min_element(gate_.begin(), gate_.end(),
                                  [](const Gate &a, const Gate &b) { return a.at < b.at; });
    }
    *slot = Gate{p, now, true};
}

// ---- jobs ----
Status EndExchange::job_entry(port::JobEnv &env, void *arg) {
    auto *x = static_cast<EndExchange *>(arg);
    return x->job_ == Job::Verify ? verify_body(*x) : sec::HandshakeSlot::run_job(env, &x->mem_.hs);
}

Status EndExchange::verify_body(EndExchange &x) {
    member::Bundle b;
    LM_TRY(member::bundle_parse(ByteView{x.mem_.rx.data(), x.rx_len_}, b));
    PeerState &p = x.peer_state_;
    LM_TRY(member::check_device_credential(x.vin_.trust, b.device_cose, p.dc));
    LM_TRY(member::check_member_credential(x.vin_.delegation, b.member_cose, p.mc));
    LM_TRY(member::check_binding(p.dc, b.device_cose, p.mc));
    LM_TRY(sec::ccs_encode(ByteView{p.dc.serial.data(), p.dc.serial_len}, p.dc.key, MutByteView{p.ccs},
                           p.ccs_len));
    return sec::sha256(b.member_cose, p.mc_hash);
}

Status EndExchange::run_verify() {
    vin_.trust = identity_.trust();
    vin_.delegation = identity_.delegation();
    job_ = Job::Verify;
    const Status st = engine_.submit_job(JobOwner::EndExchange, owner_, JobClass::PublicKey, &job_entry, this);
    if (st != Status::Ok) {
        job_ = Job::None;
    }
    return st;
}

Status EndExchange::run_hs(sec::HsStep step, ByteView input) {
    LM_TRY(mem_.hs.prepare(step, input));
    job_ = Job::Hs;
    const Status st = engine_.submit_job(JobOwner::EndExchange, owner_, JobClass::PublicKey, &job_entry, this);
    if (st != Status::Ok) {
        job_ = Job::None;
        mem_.hs.unprepare();
        return st;
    }
    hs_step_ = step;
    return Status::Ok;
}

void EndExchange::on_job_done(Handle slot, Status job_status, MonoTime now) {
    now_ = now;
    if (phase_ == EndPhase::Zombie) {
        if (job_ == Job::Hs) {
            (void)mem_.hs.complete(job_status); // wipes the cancelled slot
        }
        job_ = Job::None;
        phase_ = EndPhase::Idle;
        return;
    }
    if (slot != owner_ || job_ == Job::None) {
        return; // stale completion of an earlier exchange
    }
    const Job j = job_;
    job_ = Job::None;
    if (job_status != Status::Ok) {
        if (j == Job::Hs) {
            (void)mem_.hs.complete(job_status); // aborts the handshake, wipes the secrets
        } else {
            ++stats_.cred_rejected;
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

// ---- receive ----
void EndExchange::on_carrier(const PathSpec &reply, const wire::EndHeader &h, ByteView plain,
                             OpenedEnd &scratch, MonoTime now) {
    now_ = now;
    Reader r{plain};
    const auto kind = r.u8();
    const uint16_t total = r.u16be();
    const uint16_t offset = r.u16be();
    const ByteView body = r.bytes(r.remaining());
    if (!r.ok() || kind < 1 || kind > 8 || body.empty() || total == 0 ||
        total > wire::k_bootstrap_max_total || std::size_t{offset} + body.size() > total) {
        return;
    }
    std::array<uint8_t, 16> xid = h.message_id;
    const Obj obj = static_cast<Obj>(kind);
    const bool cred = obj == Obj::CredI || obj == Obj::CredR;
    if (phase_ == EndPhase::Linger &&
        !((obj == Obj::CredI || obj == Obj::Bind) && xid == xid_ && reply.dest == route_.dest)) {
        finish_idle(); // a new exchange takes the slot from a lingering responder
    }
    if (phase_ == EndPhase::Idle) {
        if (obj != Obj::CredI || offset != 0 || !identity_.is_member()) {
            return;
        }
        if (begin_common(nullptr, now) != Status::Ok) {
            return;
        }
        initiator_ = false;
        xid_ = xid;
        route_ = reply;
    } else {
        if (phase_ == EndPhase::Zombie || reply.dest != route_.dest) {
            ++stats_.busy_drop;
            return;
        }
        const bool same = xid == xid_;
        const bool normal = initiator_ && phase_ == EndPhase::SendCred && obj == Obj::CredR && same;
        const bool glare = initiator_ && phase_ == EndPhase::SendCred && obj == Obj::CredI && !same;
        const bool receiving = !initiator_ && phase_ == EndPhase::AwaitMsg && obj == expect_ && same;
        const bool repeat = !initiator_ && same && phase_ == EndPhase::AwaitMsg &&
                            ((expect_ == Obj::Msg1 && obj == Obj::CredI) ||
                             (expect_ == Obj::Msg3 && obj == Obj::Msg1));
        const bool repeat_m3 = !initiator_ && same && phase_ == EndPhase::AwaitBind && obj == Obj::Msg3;
        const bool init_msg = initiator_ && same && phase_ == EndPhase::AwaitMsg && obj == expect_;
        const bool bind_in = !initiator_ && same && obj == Obj::Bind &&
                             (phase_ == EndPhase::AwaitBind || phase_ == EndPhase::Linger);
        const bool ack_in = initiator_ && same && phase_ == EndPhase::AwaitBind && obj == Obj::BindAck;
        if (repeat || repeat_m3) {
            if (offset == 0) { // the initiator did not see our answer: repeat it byte for byte
                if (obj == Obj::CredI) {
                    send_object(Obj::CredR, identity_.bundle(), true);
                } else {
                    send_object(staged_, ByteView{mem_.stage.data(), stage_len_}, true);
                }
                route_ = reply;
                pump(now);
            }
            return;
        }
        if (!normal && !glare && !receiving && !init_msg && !bind_in && !ack_in) {
            ++stats_.busy_drop;
            return;
        }
        if (!initiator_) {
            route_ = reply;
        }
    }
    if (offset == 0) {
        rx_kind_ = obj;
        rx_total_ = total;
        rx_len_ = 0;
        rx_xid_ = xid;
    }
    const bool bind = obj == Obj::Bind || obj == Obj::BindAck;
    const std::size_t limit = cred ? mem_.rx.size() : (bind ? k_bind_record_max : sec::k_edhoc_max_message);
    if (obj != rx_kind_ || total != rx_total_ || offset != rx_len_ || rx_len_ + body.size() > limit ||
        rx_len_ + body.size() > mem_.rx.size()) {
        return; // out of order or foreign: the sender repeats the whole object
    }
    std::memcpy(mem_.rx.data() + rx_len_, body.data(), body.size());
    rx_len_ += body.size();
    if (rx_len_ == rx_total_) {
        obj_complete(reply, obj, scratch, now);
    }
}

void EndExchange::obj_complete(const PathSpec &reply, Obj kind, OpenedEnd &scratch, MonoTime now) {
    Status st = Status::Ok;
    switch (kind) {
    case Obj::CredI:
    case Obj::CredR:
        if (initiator_ && kind == Obj::CredI) {
            // Both sides started: the lower DeviceId keeps the initiator role. The peek is only
            // structural; the winner still verifies everything.
            member::Bundle b;
            member::Envelope env;
            ByteView data;
            member::DeviceCredential dc;
            const bool ok = member::bundle_parse(ByteView{mem_.rx.data(), rx_len_}, b) == Status::Ok &&
                            member::peek_signed(b.device_cose, member::k_type_device_credential, env,
                                                data) == Status::Ok &&
                            member::decode_device_credential(data, dc) == Status::Ok;
            if (!ok || !(dc.device < identity_.self())) {
                rx_len_ = rx_total_ = 0; // we keep initiating; the peer yields on seeing our credentials
                return;
            }
            gate_forget(peer_); // the attempt we abandon must not gate the winner's message_1
            initiator_ = false; // yield: answer as responder to the winner's exchange
            xid_ = rx_xid_;
            route_ = reply;
            tx_active_ = false;
            rto_at_ = MonoTime::never();
            attempts_ = 0;
            peer_known_ = false;
            expect_ = Obj::CredI;
        } else if (initiator_) {
            rto_at_ = MonoTime::never();
        }
        phase_ = EndPhase::Verify;
        st = run_verify();
        break;
    case Obj::Msg2:
    case Obj::Msg4:
        rto_at_ = MonoTime::never();
        phase_ = EndPhase::Hs;
        st = run_hs(kind == Obj::Msg2 ? sec::HsStep::M2Process : sec::HsStep::M4Process,
                    ByteView{mem_.rx.data(), rx_len_});
        break;
    case Obj::Msg1: {
        // From here the responder spends EDHOC work (ECDH, signature): one full handshake per peer
        // per 30 s (docs/06 §8). Credential checks before this point are cheap and slot-bounded.
        if (!gate_allow(peer_, now)) {
            ++stats_.rate_limited;
            abort(Status::RateLimited);
            return;
        }
        gate_touch(peer_, now);
        deadline_ = hard_deadline_;
        const ByteView peers[1] = {ByteView{peer_state_.ccs.data(), peer_state_.ccs_len}};
        st = mem_.hs.begin(sec::HsRole::Responder, identity_.key(), identity_.ccs(), peers, 1);
        if (st == Status::Ok) {
            phase_ = EndPhase::Hs;
            st = run_hs(sec::HsStep::M1Process, ByteView{mem_.rx.data(), rx_len_});
        }
        break;
    }
    case Obj::Msg3:
        phase_ = EndPhase::Hs;
        st = run_hs(sec::HsStep::M3Process, ByteView{mem_.rx.data(), rx_len_});
        break;
    case Obj::Bind:
    case Obj::BindAck:
        handle_bind(reply, ByteView{mem_.rx.data(), rx_len_}, scratch, now);
        return;
    }
    if (st != Status::Ok) {
        abort(st);
    }
}

// ---- owner-side steps ----
void EndExchange::after_verify(MonoTime now) {
    const member::MemberCredential &mc = peer_state_.mc;
    Status st = Status::Ok;
    if (peer_state_.dc.device == identity_.self() || (peer_known_ && peer_state_.dc.device != peer_)) {
        st = Status::AuthRejected; // not the peer we asked for / a device does not talk to itself
    } else if (mc.address != route_.dest) {
        st = Status::AuthRejected; // the route ends at another node than the credential's address
    } else {
        st = identity_.floors().check(peer_state_.dc.device, mc.assignment, mc.membership);
    }
    if (st == Status::Ok && member::check_lease(mc, root_time_) == DeadlineCheck::After) {
        st = Status::Expired; // Uncertain (no root time yet) does not block: time sync follows
    }
    if (st != Status::Ok) {
        ++stats_.cred_rejected;
        abort(st);
        return;
    }
    peer_ = peer_state_.dc.device;
    peer_known_ = true;
    if (initiator_) {
        const ByteView peers[1] = {ByteView{peer_state_.ccs.data(), peer_state_.ccs_len}};
        st = mem_.hs.begin(sec::HsRole::Initiator, identity_.key(), identity_.ccs(), peers, 1);
        if (st == Status::Ok) {
            phase_ = EndPhase::Hs;
            st = run_hs(sec::HsStep::M1Compose);
        }
        if (st != Status::Ok) {
            abort(st);
        }
        return;
    }
    phase_ = EndPhase::SendCred;
    send_object(Obj::CredR, identity_.bundle(), false);
    pump(now);
}

Status EndExchange::make_context(sec::SessionContext &ctx) const {
    const member::LocalIdentity &id = identity_;
    Sha256Digest self_hash{};
    LM_TRY(sec::sha256(id.member_cose(), self_hash));
    ctx.purpose = sec::Purpose::End;
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

void EndExchange::after_hs(MonoTime now) {
    const sec::HsStep step = hs_step_;
    Status st = mem_.hs.complete(Status::Ok);
    if (st != Status::Ok) {
        abort(st);
        return;
    }
    using S = sec::HsStep;
    auto stage = [&](Obj kind) {
        const ByteView out = mem_.hs.output();
        stage_len_ = std::min(out.size(), mem_.stage.size());
        std::memcpy(mem_.stage.data(), out.data(), stage_len_);
        staged_ = kind;
    };
    switch (step) {
    case S::M1Compose:
        stage(Obj::Msg1);
        phase_ = EndPhase::AwaitMsg;
        expect_ = Obj::Msg2;
        send_object(Obj::Msg1, ByteView{mem_.stage.data(), stage_len_}, false);
        break;
    case S::M2Process:
        phase_ = EndPhase::Hs;
        st = run_hs(S::M3Compose);
        break;
    case S::M3Compose:
        stage(Obj::Msg3);
        phase_ = EndPhase::AwaitMsg;
        expect_ = Obj::Msg4;
        send_object(Obj::Msg3, ByteView{mem_.stage.data(), stage_len_}, false);
        break;
    case S::M4Process:
    case S::M3Process:
        st = make_context(ctx_);
        if (st == Status::Ok) {
            st = mem_.hs.set_context(ctx_);
        }
        if (st == Status::Ok) {
            ctx_hash_ = mem_.hs.context_hash();
            phase_ = EndPhase::Hs;
            st = run_hs(step == S::M4Process ? S::Export : S::M4Compose);
        }
        break;
    case S::M1Process:
        phase_ = EndPhase::Hs;
        st = run_hs(S::M2Compose);
        break;
    case S::M2Compose:
        stage(Obj::Msg2);
        phase_ = EndPhase::AwaitMsg;
        expect_ = Obj::Msg3;
        send_object(Obj::Msg2, ByteView{mem_.stage.data(), stage_len_}, false);
        break;
    case S::M4Compose:
        stage(Obj::Msg4); // held back until the keys exist
        phase_ = EndPhase::Hs;
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

Status EndExchange::alloc_sid(uint32_t &sid) {
    for (int i = 0; i < 8; ++i) {
        std::array<uint8_t, 4> b{};
        engine_.random(MutByteView{b});
        const uint32_t v = (uint32_t{b[0]} << 24U) | (uint32_t{b[1]} << 16U) | (uint32_t{b[2]} << 8U) | b[3];
        if (v != 0 && v != k_handshake_sid && !sessions_.sid_in_use(v)) {
            sid = v;
            return Status::Ok;
        }
    }
    return Status::RecoveryRequired;
}

void EndExchange::finish_keys(MonoTime now) {
    sec::RecordKeys keys;
    Status st = mem_.hs.take_keys(keys);
    if (st == Status::Ok) {
        st = pend_.rec.install(std::move(keys));
    }
    if (st == Status::Ok) {
        pend_.used = true;
        pend_.peer = peer_state_.dc.device;
        pend_.peer_addr = peer_state_.mc.address;
        pend_.peer_assignment = peer_state_.mc.assignment;
        pend_.peer_membership = peer_state_.mc.membership;
        pend_.ctx_hash = ctx_hash_;
        pend_.born = now;
        pend_.valid_until = now + policy_.key_lifetime;
        st = alloc_sid(pend_.rx_sid);
    }
    if (st == Status::Ok && initiator_) {
        engine_.random(MutByteView{bind_nonce_});
        st = send_bind(false, now);
    }
    if (st != Status::Ok) {
        abort(st);
        return;
    }
    phase_ = EndPhase::AwaitBind;
    if (initiator_) {
        send_object(Obj::Bind, ByteView{bind_rec_.data(), bind_len_}, false); // SESSION_BIND
        pump(now);
        return;
    }
    // Responder: message_4 goes out now; SESSION_BIND from the initiator comes after it.
    send_object(Obj::Msg4, ByteView{mem_.stage.data(), stage_len_}, false);
    pump(now);
}

// SESSION_BIND / ACK = [1, ctx_hash, receiver_sid, nonce], sealed under the new keys with the
// sender's own reserved SID in the header (S5-D3). The record is kept for identical repeats.
static Status seal_bind_record(EndSession &s, uint32_t own_sid, RootTerm term,
                               const std::array<uint8_t, 16> &xid, const std::array<uint8_t, 16> &nonce,
                               MutByteView out, std::size_t &len) {
    std::array<uint8_t, 64> plain{};
    wire::CborWriter w{MutByteView{plain}};
    w.array(4);
    w.uint(k_bind_version);
    w.bytes(ByteView{s.ctx_hash});
    w.uint(own_sid);
    w.bytes(ByteView{nonce});
    LM_TRY(w.finish());
    wire::EndHeader h;
    h.message_id = xid;
    h.app_port = 0;
    h.record_kind = wire::RecordKind::Control;
    h.flags = wire::make_end_flags(wire::Delivery::BestEffort, wire::Priority::Control, false);
    return seal_end_record(s, own_sid, term, h, w.written(), out, len);
}

Status EndExchange::send_bind(bool ack, MonoTime /*now*/) {
    EndSession *s = ack ? sessions_.find_peer(peer_) : &pend_;
    if (s == nullptr) {
        return Status::RecoveryRequired;
    }
    return seal_bind_record(*s, s->rx_sid, route_.term, xid_, bind_nonce_, MutByteView{bind_rec_}, bind_len_);
}

// SESSION_BIND (initiator -> responder) or its ACK arrived as a carrier object: the sealed record.
void EndExchange::handle_bind(const PathSpec &reply, ByteView record, OpenedEnd &op, MonoTime now) {
    if (phase_ == EndPhase::Linger) {
        // A bind repeat: the peer did not see our ACK. Answer with the same bytes.
        EndSession *s = sessions_.find_peer(peer_);
        wire::EndHeader h;
        ByteView sealed;
        if (s == nullptr || wire::decode_end_record(record, h, sealed) != Status::Ok || h.end_sid != s->tx_sid) {
            return;
        }
        const Status st = open_end_record(*s, reply.term, record, op);
        if (st == Status::Replay && op.verdict == sec::ReplayVerdict::Duplicate) {
            send_object(Obj::BindAck, ByteView{bind_rec_.data(), bind_len_}, true);
            pump(now);
        }
        return;
    }
    if (phase_ != EndPhase::AwaitBind || !pend_.rec.active()) {
        return;
    }
    const Status st = open_end_record(pend_, reply.term, record, op);
    if (st != Status::Ok) {
        return; // not authentic (or a stale copy): no state change, the exchange runs to its deadline
    }
    uint32_t sid = 0;
    std::array<uint8_t, 16> nonce{};
    bool ok = op.header.record_kind == wire::RecordKind::Control && op.header.app_port == 0 &&
              wire::cbor_validate(op.view()) == Status::Ok;
    if (ok) {
        wire::CborReader r{op.view()};
        (void)r.array(4, 4);
        (void)r.uint_in(k_bind_version, k_bind_version);
        const ByteView hash = r.bstr(32, 32);
        const uint64_t s = r.uint_in(1, 0xFFFFFFFFULL);
        const ByteView n = r.bstr(16, 16);
        ok = r.finish() == Status::Ok && bytes_equal(hash, ByteView{ctx_hash_}) &&
             s == op.header.end_sid && s != k_handshake_sid;
        if (ok) {
            sid = static_cast<uint32_t>(s);
            std::copy(n.begin(), n.end(), nonce.begin());
            ok = !initiator_ || nonce == bind_nonce_;
        }
    }
    if (!ok) {
        ++stats_.bind_bad;
        return;
    }
    pend_.rec.accept(op.header.end_counter);
    pend_.tx_sid = sid;
    Status is = install_session(now);
    if (is != Status::Ok) {
        abort(is);
        return;
    }
    ++stats_.completed;
    const DeviceId peer = peer_;
    if (initiator_) {
        finish_idle();
        if (tr_.done != nullptr) {
            tr_.done(tr_.ctx, peer, Status::Ok, now);
        }
        return;
    }
    bind_nonce_ = nonce;
    is = send_bind(true, now);
    phase_ = EndPhase::Linger;
    deadline_ = now + policy_.linger;
    rto_at_ = MonoTime::never();
    if (is == Status::Ok) {
        send_object(Obj::BindAck, ByteView{bind_rec_.data(), bind_len_}, false);
        pump(now);
    }
    if (tr_.done != nullptr) {
        tr_.done(tr_.ctx, peer, Status::Ok, now); // the session exists on our side
    }
}

Status EndExchange::install_session(MonoTime /*now*/) {
    EndSession *slot = sessions_.find_peer(pend_.peer);
    if (slot == nullptr) {
        slot = &sessions_.acquire();
    } else {
        slot->wipe(); // a fresh session replaces the old keys of the same peer
    }
    *slot = std::move(pend_);
    pend_.wipe();
    slot->epoch = sessions_.next_epoch(); // records sealed under the old keys are re-sealed
    slot->suspect = false;
    sessions_.touch(*slot);
    return Status::Ok;
}

// ---- transmit ----
void EndExchange::send_object(Obj kind, ByteView data, bool retransmit) {
    tx_active_ = true;
    tx_kind_ = kind;
    tx_data_ = data.data();
    tx_len_ = data.size();
    tx_off_ = 0;
    rto_at_ = MonoTime::never();
    attempts_ = retransmit ? static_cast<uint8_t>(attempts_ + 1) : 1;
}

void EndExchange::arm_rto(MonoTime now) {
    if (!initiator_) {
        if (phase_ == EndPhase::SendCred) { // CredR is out: wait for message_1, but not for long
            phase_ = EndPhase::AwaitMsg;
            expect_ = Obj::Msg1;
            deadline_ = earliest(deadline_, now + k_msg1_wait);
        }
        return;
    }
    if (phase_ == EndPhase::SendCred || phase_ == EndPhase::AwaitMsg || phase_ == EndPhase::AwaitBind) {
        rto_at_ = now + rto();
    }
}

void EndExchange::pump(MonoTime now) {
    if (!tx_active_ || tx_inflight_ || phase_ == EndPhase::Idle || phase_ == EndPhase::Zombie ||
        tr_.send == nullptr) {
        return;
    }
    // The record is built in the delivery module's shared TX buffer (no big locals on the owner stack).
    const MutByteView rec = tr_.record_buf;
    std::size_t len = 0;
    std::size_t chunk = 0;
    {
        const std::size_t cap = wire::data_capacity(route_.len);
        if (cap <= k_obj_header || rec.size() < wire::k_end_header_bytes + cap + wire::k_tag_bytes) {
            abort(Status::NoRoute);
            return;
        }
        chunk = std::min<std::size_t>(cap - k_obj_header, tx_len_ - tx_off_);
        const std::size_t plain_len = k_obj_header + chunk;
        wire::EndHeader h;
        h.end_sid = k_handshake_sid;
        h.end_counter = ++tx_seq_;
        h.message_id = xid_;
        h.app_port = 0;
        h.record_kind = wire::RecordKind::Control;
        h.flags = wire::make_end_flags(wire::Delivery::BestEffort, wire::Priority::Control, false);
        h.plaintext_length = static_cast<uint16_t>(plain_len);
        Status st = wire::encode_end_header(h, rec.first(wire::k_end_header_bytes));
        if (st != Status::Ok) {
            abort(st);
            return;
        }
        Writer w{rec.subspan(wire::k_end_header_bytes, plain_len + wire::k_tag_bytes)};
        w.u8(static_cast<uint8_t>(tx_kind_));
        w.u16be(static_cast<uint16_t>(tx_len_));
        w.u16be(static_cast<uint16_t>(tx_off_));
        w.bytes(ByteView{tx_data_ + tx_off_, chunk});
        w.zeros(wire::k_tag_bytes); // tag field stays zero: the carrier is not end-authenticated
        len = wire::k_end_header_bytes + plain_len + wire::k_tag_bytes;
        if (!w.ok()) {
            abort(Status::NoCapacity);
            return;
        }
    }
    // Set before sending: the hop layer may report the frame's end from inside send().
    const std::size_t prev_off = tx_off_;
    tx_inflight_ = true;
    tx_off_ += chunk;
    const Status st = tr_.send(tr_.ctx, route_, ByteView{rec.data(), len}, owner_, now);
    if (st == Status::Busy || st == Status::NoCapacity) {
        ++stats_.send_deferred; // TX pool/radio shortage: local, retried, never counted as loss
        tx_inflight_ = false;
        tx_off_ = prev_off;
        retry_at_ = now + k_pump_retry;
        return;
    }
    if (st != Status::Ok) {
        tx_inflight_ = false;
        abort(st);
        return;
    }
    retry_at_ = MonoTime::never();
}

void EndExchange::on_frame_done(Handle owner, HopEnd end, MonoTime now) {
    now_ = now;
    if (owner != owner_ || phase_ == EndPhase::Idle || phase_ == EndPhase::Zombie || !tx_inflight_) {
        return;
    }
    tx_inflight_ = false;
    if (end != HopEnd::Accepted) {
        // The object is broken; the initiator's next RTO repeats it as a whole, the responder waits
        // for the initiator's repeat.
        tx_active_ = false;
        if (initiator_) {
            rto_at_ = now + Duration::from_ms(100);
        }
        return;
    }
    if (tx_off_ >= tx_len_) {
        tx_active_ = false;
        arm_rto(now);
        return;
    }
    pump(now);
}

void EndExchange::on_timer(MonoTime now) {
    now_ = now;
    if (phase_ == EndPhase::Idle || phase_ == EndPhase::Zombie) {
        return;
    }
    if (now >= deadline_) {
        if (phase_ == EndPhase::Linger) {
            finish_idle();
        } else {
            abort(Status::Expired);
        }
        return;
    }
    if (initiator_ && now >= rto_at_) {
        if (attempts_ >= policy_.max_attempts) {
            abort(Status::Expired);
            return;
        }
        ++stats_.retransmits;
        rto_at_ = MonoTime::never();
        switch (phase_) {
        case EndPhase::SendCred:
            send_object(Obj::CredI, identity_.bundle(), true);
            break;
        case EndPhase::AwaitBind:
            send_object(Obj::Bind, ByteView{bind_rec_.data(), bind_len_}, true);
            break;
        default:
            send_object(staged_, ByteView{mem_.stage.data(), stage_len_}, true);
            break;
        }
    }
    if (now >= retry_at_) {
        retry_at_ = MonoTime::never();
    }
    pump(now);
}

} // namespace lm::delivery
