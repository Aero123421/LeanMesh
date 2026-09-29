#include "core/member/membership.hpp"

#include <algorithm>
#include <cstring>

#include "core/codec.hpp"
#include "core/engine.hpp"
#include "core/wire/cbor.hpp"
#include "security/crypto.hpp"

// The joiner's protocol: JoinRequest out, JoinPrepare / JoinCommit / final acknowledgement in, activation, and
// the durable retry of the root's acknowledgement over an ordinary link. Boot, discovery, the Flash chain and
// the timers are in membership.cpp.
namespace lm::member {
namespace {

constexpr Duration k_busy_retry = Duration::from_ms(50);   // borrowed memory is taken: try again
constexpr Duration k_request_wait = Duration::from_s(310); // approval timeout 300 s + margin

bool all_zero(const Sha256Digest &h) {
    return std::all_of(h.begin(), h.end(), [](uint8_t b) { return b == 0; });
}

// Refusals that mean "not now": the join may be asked again with the same request.
bool transient(Status s) { return s == Status::Busy || s == Status::NoCapacity || s == Status::RateLimited; }

} // namespace
// Ticket loaded: check it belongs to this device and to the root we are talking to, then send the
// JoinRequest. A ticket for another domain or root is never shown to this peer (docs/07 §4).
void Membership::request_ready(MonoTime now) {
    const ByteView ticket{rec_->payload.data(), rec_->payload_len};
    Envelope env;
    ByteView data;
    AssignmentTicket t;
    Status st = peek_signed(ticket, k_type_assignment_ticket, env, data);
    if (st == Status::Ok) {
        st = decode_assignment_ticket(data, t);
    }
    const LocalIdentity &id = engine_.identity();
    if (st == Status::Ok && constrain_ && peer_.delegation.domain != target_) {
        st = Status::NetworkMismatch; // the app asked for one domain only (lm_join_request_t.constrain_target)
    }
    if (st == Status::Ok &&
        (t.device != id.self() || t.fleet != id.trust().fleet || t.target != peer_.delegation.domain ||
         t.root_delegation_hash != peer_.delegation_hash || env.domain != t.target ||
         t.new_generation <= t.expected_old)) {
        st = Status::AuthRejected;
    }
    if (st == Status::Ok && (!t.source.is_zero() || t.expected_old != 0)) {
        st = Status::Unsupported; // transfer tickets belong to the lifecycle slice (S18)
    }
    if (st == Status::Ok) { // a consumed grant/generation stays consumed (docs/07 §8, docs/21 §9)
        for (std::size_t i = 0; i < id.floors().count(); ++i) {
            if (id.floors().at(i).device == id.self() && t.new_generation < id.floors().at(i).assignment) {
                st = Status::Revoked;
            }
        }
    }
    if (st != Status::Ok) {
        finish_join(st, LM_OUTCOME_REJECTED, now);
        return;
    }
    if (!lend_scratch_only()) {
        retry_at_ = now + k_busy_retry; // the credential buffer is in use: try again shortly
        return;
    }
    req_.assignment = t.new_generation;
    if (!req_.known) {
        engine_.random(MutByteView{req_.nonce});
        req_.known = true;
    }
    JoinObjectHeader h;
    h.type = k_type_join_request;
    h.request = req_.id;
    h.domain = peer_.delegation.domain;
    h.issuer = id.self();
    std::size_t plen = 0;
    std::size_t dlen = 0;
    JoinRequestData d;
    d.device_credential = id.device_cose();
    d.ticket = ticket;
    d.nonce = req_.nonce;
    d.capabilities = engine_.config().role == Role::Leaf ? 0 : 1; // bit 0: relay-capable
    st = join_object_begin(h, scratch_, plen);
    if (st == Status::Ok) {
        st = encode_join_request(d, scratch_.from(plen), dlen);
    }
    if (st != Status::Ok) {
        finish_join(st, LM_OUTCOME_REJECTED, now);
        return;
    }
    engine_.identity().return_record(); // the ticket now lives inside the request object
    rec_ = nullptr;
    req_.evidence |= kEvRequested;
    request_deadline_ = now + k_request_wait;
    phase_ = JoinPhase::RequestOut;
    emit_state(0);
    pipe_.send(ByteView{scratch_.data(), plen + dlen}, now);
}

bool Membership::lend_scratch_only() {
    if (!scratch_.empty()) {
        return true;
    }
    scratch_ = engine_.link().exchange().lend_scratch();
    if (scratch_.empty()) {
        ++stats_.scratch_busy;
    }
    return !scratch_.empty();
}

// ---- messages from the root ----
void Membership::join_control(const link::RxInfo &info, ByteView plain, MonoTime now) {
    if (!pipe_.bound() || info.peer != pipe_.peer()) {
        return;
    }
    if (phase_ == JoinPhase::RequestOut) {
        pipe_.acked(); // any authentic answer of the root proves the request arrived: free the buffer
    }
    ByteView object;
    const JoinPipe::Feed f = pipe_.feed(plain, scratch_, object, now);
    if (f == JoinPipe::Feed::Duplicate) {
        repeat_last(now);
        return;
    }
    if (f == JoinPipe::Feed::NeedBuffer) {
        ++stats_.scratch_busy;
        return;
    }
    if (f != JoinPipe::Feed::Object) {
        return;
    }
    JoinObjectHeader h;
    ByteView data;
    if (join_object_parse(object, h, data) != Status::Ok || h.request != req_.id ||
        h.issuer != pipe_.peer()) {
        return;
    }
    switch (h.type) {
    case k_type_join_prepare:
        on_prepare(data, now);
        break;
    case k_type_join_commit:
        on_commit(data, now);
        break;
    case k_type_join_active:
        on_active_echo(data, now);
        break;
    default:
        break;
    }
}

// The root sent something we already processed: it did not see our answer. Say it again.
void Membership::repeat_last(MonoTime now) {
    if ((phase_ == JoinPhase::StoredOut || phase_ == JoinPhase::ActiveOut) && staged_len_ != 0) {
        pipe_.send_staged(staged_len_, now);
    }
}

void Membership::on_prepare(ByteView data, MonoTime now) {
    if (phase_ == JoinPhase::StoredOut) {
        repeat_last(now); // our JoinStored was lost
        return;
    }
    JoinPrepareData p;
    Sha256Digest h{};
    if (phase_ != JoinPhase::RequestOut || decode_join_prepare(data, p) != Status::Ok ||
        sec::sha256(p.member, h) != Status::Ok || h != p.prepare_hash) {
        return;
    }
    if (have_prepared_) {
        // Resume: the root repeats the credential of the request we already stored.
        if (p.prepare_hash != req_.prepare_hash) {
            finish_join(Status::Conflict, LM_OUTCOME_REJECTED, now); // same request, other content
            return;
        }
        req_.reservation_ms = p.reservation_ms;
        req_.evidence |= kEvRootStored | kEvDeviceStored;
        prepared_until_ = now + Duration::from_ms(p.reservation_ms);
        phase_ = JoinPhase::StoredOut;
        send_stored(now);
        return;
    }
    req_.prepare_hash = p.prepare_hash;
    req_.membership = p.membership;
    req_.reservation_ms = p.reservation_ms;
    prep_address_ = p.address;
    prep_term_ = p.root_term;
    verify_input_ = p.member;
    mc_verified_ = false;
    phase_ = JoinPhase::Verify;
    if (start_verify(now) != Status::Ok) {
        finish_join(Status::Busy, LM_OUTCOME_REJECTED, now);
    }
}

// The credential verified under the delegation: it must be for this device, this assignment and
// exactly what the JoinPrepare announced; then it is stored (PREPARED, read back by the record layer).
void Membership::prepared_verified(MonoTime now) {
    const MemberCredential &mc = req_.mc;
    const LocalIdentity &id = engine_.identity();
    Status st = check_binding(id.device_credential(), id.device_cose(), mc);
    if (st == Status::Ok && (mc.device != id.self() || mc.address != prep_address_ ||
                             mc.membership.value() != req_.membership || mc.assignment.value() != req_.assignment ||
                             mc.root_term.value() != prep_term_ || mc.membership.value() == 0)) {
        st = Status::AuthRejected;
    }
    if (st != Status::Ok) {
        finish_join(st, LM_OUTCOME_REJECTED, now);
        return;
    }
    if (!lend_record_or_retry(now)) {
        return;
    }
    std::memcpy(rec_->payload.data(), req_.id.bytes.data(), 16);
    std::memcpy(rec_->payload.data() + 16, req_.nonce.data(), 16);
    std::memcpy(rec_->payload.data() + 32, req_.prepare_hash.data(), 32);
    std::memcpy(rec_->payload.data() + k_prepared_head, verify_input_.data(), verify_input_.size());
    mc_verified_ = true;
    phase_ = JoinPhase::PersistPrepared;
    if (start_flash(Step::CommitPrepared, store::RecordJob::Op::Commit, store::rec::membership_prepared,
                    k_prepared_state, k_prepared_head + verify_input_.size(), now) != Status::Ok) {
        finish_join(Status::Busy, LM_OUTCOME_REJECTED, now);
    }
}

bool Membership::lend_record_or_retry(MonoTime now) {
    if (rec_ != nullptr) {
        return true;
    }
    rec_ = engine_.identity().lend_record();
    if (rec_ == nullptr) {
        ++stats_.scratch_busy;
        retry_at_ = now + k_busy_retry;
    }
    return rec_ != nullptr;
}

void Membership::send_stored(MonoTime now) {
    JoinAckData a;
    a.prepare_hash = req_.prepare_hash;
    a.value = req_.prepared_generation;
    stage_ack(k_type_join_stored, a, now);
}

void Membership::stage_ack(uint8_t type, const JoinAckData &a, MonoTime now) {
    JoinObjectHeader h;
    h.type = type;
    h.request = req_.id;
    h.domain = peer_.delegation.domain;
    h.issuer = engine_.identity().self();
    MutByteView out = pipe_.stage();
    std::size_t plen = 0;
    std::size_t dlen = 0;
    Status st = join_object_begin(h, out, plen);
    if (st == Status::Ok) {
        st = encode_join_ack(a, out.from(plen), dlen);
    }
    if (st != Status::Ok) {
        finish_join(st, LM_OUTCOME_REJECTED, now);
        return;
    }
    staged_len_ = plen + dlen;
    pipe_.send_staged(staged_len_, now);
}

void Membership::on_commit(ByteView data, MonoTime now) {
    JoinAckData a;
    if (decode_join_ack(data, a) != Status::Ok) {
        return;
    }
    if (all_zero(a.prepare_hash)) { // refusal: the value is the reason (S8-D3)
        ++stats_.refusals;
        pipe_.acked();
        const Status why = a.value <= 0xFFFF ? static_cast<Status>(a.value) : Status::Conflict;
        if (why == Status::NotFound && !have_prepared_ && phase_ == JoinPhase::RequestOut && now < search_deadline_) {
            not_expected(now); // NOT_EXPECTED is a hold with a re-evaluation, not a rejection (docs/07 §3)
            return;
        }
        req_.reason = why;
        req_.outcome = why == Status::Expired ? LM_OUTCOME_EXPIRED : LM_OUTCOME_REJECTED;
        if (have_prepared_ && !transient(why)) {
            fail_and_consume(why, now); // the request is dead at the root: forget our PREPARED record
        } else {
            finish_join(why, req_.outcome, now);
        }
        return;
    }
    if (phase_ == JoinPhase::ActiveOut) {
        repeat_last(now); // our JoinActive was lost; the root asks again by repeating its commit
        return;
    }
    if ((phase_ != JoinPhase::StoredOut && phase_ != JoinPhase::RequestOut) || !have_prepared_ ||
        a.prepare_hash != req_.prepare_hash || a.value != req_.membership) {
        return;
    }
    pipe_.acked();
    activate(now);
}

void Membership::activate(MonoTime now) {
    phase_ = JoinPhase::Activate;
    prepared_until_ = MonoTime::never();
    if (!lend_record_or_retry(now)) {
        return;
    }
    if (start_flash(Step::ActivateLoad, store::RecordJob::Op::Load, store::rec::membership_prepared, 0, 0, now) !=
        Status::Ok) {
        finish_join(Status::Busy, LM_OUTCOME_INDETERMINATE, now);
    }
}

// The PREPARED record is the source of the credential that goes live: what was stored and read back
// is what is activated (never a copy that only lives in RAM).
void Membership::activate_loaded(Status s, MonoTime now) {
    if (s != Status::Ok || rec_->state != k_prepared_state || rec_->payload_len <= k_prepared_head ||
        std::memcmp(rec_->payload.data(), req_.id.bytes.data(), 16) != 0 ||
        std::memcmp(rec_->payload.data() + 32, req_.prepare_hash.data(), 32) != 0) {
        finish_join(s != Status::Ok ? s : Status::RecoveryRequired, LM_OUTCOME_INDETERMINATE, now);
        return;
    }
    const std::size_t n = rec_->payload_len - k_prepared_head;
    std::memmove(rec_->payload.data(), rec_->payload.data() + k_prepared_head, n);
    rec_->payload_len = static_cast<uint32_t>(n);
    if (!mc_verified_) {
        verify_input_ = ByteView{rec_->payload.data(), n};
        if (start_verify(now) != Status::Ok) {
            finish_join(Status::Busy, LM_OUTCOME_INDETERMINATE, now);
        }
        return;
    }
    activate_commit(now);
}

void Membership::activate_commit(MonoTime now) {
    if (start_flash(Step::ActivateCommit, store::RecordJob::Op::Commit, store::rec::membership,
                    k_membership_active, rec_->payload_len, now) != Status::Ok) {
        finish_join(Status::Busy, LM_OUTCOME_INDETERMINATE, now);
    }
}

void Membership::active_out(MonoTime now) {
    engine_.identity().return_record();
    rec_ = nullptr;
    phase_ = JoinPhase::ActiveOut;
    // 5 s for a neighbour; a proxied join adds three of its (longer) retransmission periods.
    final_wait_until_ = now + Duration::from_s(5) + Duration{3 * (engine_.link().policy().rto - link::LinkPolicy{}.rto).us};
    JoinAckData a;
    a.prepare_hash = req_.prepare_hash;
    a.value = activated_generation_;
    stage_ack(k_type_join_active, a, now);
    emit_state(0);
}

void Membership::on_active_echo(ByteView data, MonoTime now) {
    JoinAckData a;
    if (phase_ != JoinPhase::ActiveOut || decode_join_ack(data, a) != Status::Ok ||
        a.prepare_hash != req_.prepare_hash) {
        return;
    }
    pipe_.acked();
    req_.evidence |= kEvRootConfirmed;
    confirm_pending_ = false;
    confirm_at_ = MonoTime::never();
    // The acknowledgement is durable evidence too: the ACTIVATED record is consumed before "complete".
    if (!lend_record_or_retry(now) ||
        start_flash(Step::ConfirmConsume, store::RecordJob::Op::Commit, store::rec::membership_prepared,
                    k_prepared_consumed, 0, now) != Status::Ok) {
        finish_join(Status::Ok, LM_OUTCOME_APPLIED, now); // record stays ACTIVATED: repeated later, harmless
    }
}

// A refusal that ended the request at the root: the PREPARED record (if any) is finished so the
// next boot does not ask about a dead request again.
void Membership::fail_and_consume(Status why, MonoTime now) {
    req_.reason = why;
    if (!lend_record_or_retry(now)) {
        retry_consume_ = true;
        return;
    }
    if (start_flash(Step::ConsumePrepared, store::RecordJob::Op::Commit, store::rec::membership_prepared,
                    k_prepared_consumed, 0, now) != Status::Ok) {
        finish_join(why, req_.outcome, now);
    }
}

void Membership::finish_join(Status why, uint32_t outcome, MonoTime now) {
    const bool active = engine_.identity().is_member();
    const bool connect = active && !link_resume_ && outcome != LM_OUTCOME_REJECTED;
    link_resume_ = false;
    const MacAddr root_mac = pipe_.bound() ? pipe_.mac() : cand_;
    if (connect) {
        engine_.link().forget_handshake_gate(root_mac);
    }
    req_.reason = why;
    req_.outcome = outcome;
    phase_ = JoinPhase::Idle;
    disc_.stop();
    collect_until_ = MonoTime::never();
    retry_at_ = search_deadline_ = request_deadline_ = prepared_until_ = final_wait_until_ = MonoTime::never();
    retry_consume_ = false;
    resume_ = false;
    release_join();
    engine_.emit_event(LM_EVENT_OPERATION, static_cast<uint32_t>(why), req_.operation, nullptr);
    if (active) {
        emit_state(0);
        // Joined: the first ordinary link session (a fresh EDHOC bound to the member credential).
        if (connect) {
            (void)engine_.link().connect(root_mac, now);
        }
    }
}

// ---- timers ----

// ---- the root's acknowledgement, over an ordinary link session (LC06, docs/21 §5) ----
void Membership::parse_activated_record(const store::RecordJob &rec) {
    if (rec.state == k_prepared_activated && rec.payload_len == 16 + 16 + 32 + 8) {
        Reader r{ByteView{rec.payload.data(), rec.payload_len}};
        r.copy_to(req_.id.bytes);
        r.copy_to(req_.nonce);
        r.copy_to(req_.prepare_hash);
        activated_generation_ = r.u64be();
        confirm_pending_ = r.ok();
    } else if (rec.state == k_prepared_state && rec.payload_len > k_prepared_head) {
        // Cut between the ACTIVE commit and the ACTIVATED mark: the PREPARED record still names the request,
        // and the live credential is exactly the one it holds, so the acknowledgement is owed all the same.
        Sha256Digest h{};
        Sha256Digest stored{};
        std::memcpy(stored.data(), rec.payload.data() + 32, 32);
        if (sec::sha256(engine_.identity().member_cose(), h) != Status::Ok || h != stored) {
            return; // an older, unrelated PREPARED record: ACTIVE outranks it
        }
        std::memcpy(req_.id.bytes.data(), rec.payload.data(), 16);
        std::memcpy(req_.nonce.data(), rec.payload.data() + 16, 16);
        req_.prepare_hash = stored;
        activated_generation_ = rec.generation;
        confirm_pending_ = true;
    } else {
        return;
    }
    req_.known = true;
    req_.evidence = kEvRequested | kEvRootStored | kEvDeviceStored | kEvDeviceActive;
    have_prepared_ = true;
}

void Membership::link_up(const DeviceId & /*peer*/, uint8_t role, MonoTime now) {
    if (phase_ == JoinPhase::Connect && link_resume_) {
        finish_join(Status::Ok, LM_OUTCOME_APPLIED, now); // RESUME: a fresh ordinary session exists
    }
    if (confirm_pending_ && role == 2) {
        confirm_attempts_ = 0;
        send_confirm(now);
    }
}

// JoinActive again, sealed on the link session to the root with a fresh counter each attempt.
void Membership::send_confirm(MonoTime now) {
    confirm_at_ = MonoTime::never();
    const LocalIdentity &id = engine_.identity();
    if (!confirm_pending_ || !id.is_member() || confirm_attempts_ >= 3) {
        return; // the next link_up (or lm_join RESUME) tries again: no timer runs without a session
    }
    const link::Neighbor *root = nullptr;
    engine_.link().neighbors().for_each([&](Handle, link::Neighbor &n) {
        if (root == nullptr && n.role == 2 && n.cur.active && !n.join_only) {
            root = &n;
        }
    });
    if (root == nullptr) {
        return;
    }
    JoinObjectHeader h;
    h.type = k_type_join_active;
    h.request = req_.id;
    h.domain = id.delegation().domain;
    h.issuer = id.self();
    JoinAckData a;
    a.prepare_hash = req_.prepare_hash;
    a.value = activated_generation_;
    std::array<uint8_t, 192> obj{};
    std::size_t plen = 0;
    std::size_t dlen = 0;
    Status st = join_object_begin(h, MutByteView{obj}, plen);
    if (st == Status::Ok) {
        st = encode_join_ack(a, MutByteView{obj}.from(plen), dlen);
    }
    link::SealedFrame f;
    if (st == Status::Ok) {
        st = engine_.link().seal(root->device, wire::FrameKind::Control, ByteView{obj.data(), plen + dlen}, f, now);
    }
    if (st == Status::Ok) {
        st = engine_.transmit(root->mac, f.view(), k_tag_confirm, now);
    }
    if (st == Status::Busy || st == Status::DriverResultUnknown) {
        confirm_at_ = now + Duration::from_ms(20); // radio occupied: local, not an attempt
        return;
    }
    if (st == Status::Ok) {
        ++confirm_attempts_;
        confirm_at_ = now + engine_.link().policy().rto; // no answer: again, at most 3 times per session
    }
}

// The root's echo of our JoinActive: the acknowledgement finally exists, so the record is consumed.
bool Membership::link_control(const link::RxInfo &info, ByteView plain, MonoTime now) {
    JoinObjectHeader h;
    ByteView data;
    JoinAckData a;
    if (join_object_parse(plain, h, data) != Status::Ok || h.type != k_type_join_active) {
        return false;
    }
    if (!confirm_pending_ || info.duplicate || h.request != req_.id || decode_join_ack(data, a) != Status::Ok ||
        a.prepare_hash != req_.prepare_hash) {
        return true;
    }
    confirm_pending_ = false;
    confirm_at_ = MonoTime::never();
    req_.evidence |= kEvRootConfirmed;
    req_.outcome = LM_OUTCOME_APPLIED;
    if (rec_ == nullptr && !job_in_flight_ && phase_ == JoinPhase::Idle && lend_record_only() &&
        start_flash(Step::ConfirmConsume, store::RecordJob::Op::Commit, store::rec::membership_prepared,
                    k_prepared_consumed, 0, now) == Status::Ok) {
        confirm_consume_ = true;
    } else {
        have_prepared_ = false; // the record is consumed at the next opportunity; repeating is harmless
        engine_.emit_event(LM_EVENT_OPERATION, 0, req_.operation, nullptr);
    }
    return true;
}

} // namespace lm::member

