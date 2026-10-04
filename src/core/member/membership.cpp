#include "core/member/membership.hpp"

#include <algorithm>
#include <cstring>

#include "core/codec.hpp"
#include "core/engine.hpp"
#include "core/wire/cbor.hpp"
#include "security/crypto.hpp"

namespace lm::member {
namespace {

constexpr Duration k_default_budget = Duration::from_s(30);   // docs/07 §3: one search, at most 30 s
constexpr Duration k_collect = Duration::from_ms(300);       // wait for a shallower offer than the first
constexpr Duration k_busy_retry = Duration::from_ms(50);      // borrowed memory is taken: try again
constexpr Duration k_connect_retry = Duration::from_ms(500);

} // namespace

Membership::Membership(Engine &engine) : engine_(engine), pipe_(engine, k_tag_join) {}

// ---- small helpers ----
uint32_t Membership::hint() const {
    return peer_.known ? link::domain_hint_of(peer_.delegation.domain) : 0;
}

void Membership::emit_state(uint32_t reason) {
    engine_.emit_event(LM_EVENT_MEMBERSHIP, reason, req_.operation, nullptr);
}

// ---- worker plumbing ----
Status Membership::start_flash(Step step, store::RecordJob::Op op, uint16_t id, uint8_t state,
                               std::size_t payload_len, MonoTime /*now*/) {
    if (rec_ == nullptr || job_in_flight_) {
        return Status::Busy;
    }
    rec_->arm(op, id, state, payload_len);
    job_slot_ = Handle{0, ++job_gen_};
    LM_TRY(engine_.submit_job(JobOwner::Join, job_slot_, JobClass::Flash, &store::record_job, rec_));
    step_ = step;
    job_in_flight_ = true;
    return Status::Ok;
}

Status Membership::verify_job(port::JobEnv & /*env*/, void *arg) {
    auto &m = *static_cast<Membership *>(arg);
    if (m.step_ == Step::RevokeVerify) { // [S18] the fleet or this domain's root (revoke permission) signed it
        RevokeObject rv;
        return verify_revoke(m.engine_.identity().trust(), &m.peer_.delegation, m.verify_input_, rv);
    }
    MemberCredential renewed; // [S18] a renewal only needs the check: the owner read its fields already
    return check_member_credential(m.peer_.delegation, m.verify_input_,
                                   m.step_ == Step::RenewVerify ? renewed : m.req_.mc);
}

// `step` is set before the worker can read it.
Status Membership::start_verify(Step step) {
    if (job_in_flight_) {
        return Status::Busy;
    }
    job_slot_ = Handle{0, ++job_gen_};
    step_ = step;
    const Status st = engine_.submit_job(JobOwner::Join, job_slot_, JobClass::PublicKey, &verify_job, this);
    if (st != Status::Ok) {
        step_ = Step::None;
        return st;
    }
    job_in_flight_ = true;
    return Status::Ok;
}

void Membership::on_job_done(Handle slot, Status s, MonoTime now) {
    job_in_flight_ = false;
    if (cancelled_) {
        cancelled_ = false;
        step_ = Step::None;
        release_join(); // stop() kept the borrows reserved for this job (zombie rule): the late result is discarded
        return;
    }
    if (slot != job_slot_ || step_ == Step::None) {
        ++stats_.stale_job_completions;
        return;
    }
    const Step step = step_;
    step_ = Step::None;
    flash_done(step, s, now);
}

void Membership::stop() {
    step_ = Step::None;
    if (phase_ != JoinPhase::Idle) {
        phase_ = JoinPhase::Idle;
        req_.outcome = LM_OUTCOME_INDETERMINATE;
    }
    leave_ = LeavePhase::Idle;
    if (job_in_flight_) {
        cancelled_ = true; // the worker may still write into the borrowed record memory: keep it reserved
        if (pipe_.bound()) {
            (void)engine_.link().close_join(pipe_.peer());
        }
        pipe_.reset();
    } else {
        release_join();
    }
    disc_.stop();
    collect_until_ = search_deadline_ = retry_at_ = request_deadline_ = prepared_until_ = MonoTime::never();
    final_wait_until_ = leave_deadline_ = leave_tx_wait_ = MonoTime::never();
    have_prepared_ = false;
    resume_ = false;
    confirm_pending_ = confirm_consume_ = false;
    confirm_at_ = MonoTime::never();
    switch_ = handover_ = renew_adopt_ = boot_load_ = false;
}

void Membership::release_join() {
    if (pipe_.bound()) {
        (void)engine_.link().close_join(pipe_.peer());
    }
    pipe_.reset();
    if (!scratch_.empty()) {
        engine_.link().exchange().return_scratch();
        scratch_ = MutByteView{};
    }
    engine_.identity().return_record(rec_);
    have_cand_ = false;
    // FIX8-D13 (review L5): `peer_` is the output of the exchange's JoinInit verify job; a job of a cancelled join may
    // still run (zombie) and write it. Only `known` is the owner's: the rest is reset once no such job exists.
    if (engine_.link().exchange().writes_join_out(&peer_)) {
        peer_.known = false;
    } else {
        peer_ = link::JoinPeerOut{};
    }
    apply_pacing(0); // the policy of a proxied join ends with it
}

// ---- boot ----
void Membership::on_identity_ready(MonoTime now) {
    auto_enabled_ = auto_loaded_ = auto_fault_ = false;
    auto_revision_ = 0;
    isolation_ms_ = 0;
    isolated_since_ = auto_at_ = MonoTime::never();
    have_prepared_ = false;
    resume_ = false;
    state_since_ = now;
    confirm_pending_ = confirm_consume_ = false;
    confirm_at_ = MonoTime::never();
    boot_load_ = engine_.config().role != Role::Root;
    boot_load(now);
}

// A member only cares about an ACTIVATED record (root acknowledgement owed); a stale PREPARED one is ignored because
// ACTIVE is authoritative. A non-member resumes a PREPARED request. The load needs the node's one record memory,
// which another module's boot job (the channel record, the journal) may hold at this moment: then it waits on the
// retry timer, it is never skipped (ADR-002 P4).
void Membership::boot_load(MonoTime now) {
    if (!boot_load_ || engine_.identity().state() != LocalIdentity::State::Ready) {
        boot_load_ = false;
        return;
    }
    if (job_in_flight_ || !lend_record_or_retry(now)) {
        retry_at_ = now + k_busy_retry;
        return;
    }
    // [S18] A switch cut between its two commits: root_delegation is rewritten from the pending record first.
    const bool repair = engine_.identity().delegation_behind();
    if (start_flash(repair ? Step::SwitchLoad : Step::BootLoadPrepared, store::RecordJob::Op::Load,
                    repair ? store::rec::pending_delegation : store::rec::membership_prepared, 0, 0, now) != Status::Ok) {
        engine_.identity().return_record(rec_);
        retry_at_ = now + k_busy_retry; // the job table or the worker queue is full: local, tried again
        return;
    }
    boot_load_ = false;
}

// [S18] The delegation of a switch is written (or its write failed and the next boot repairs it). A live transfer
// goes on with the ACTIVATED mark; a boot-time repair goes on with the boot's own load of the PREPARED record.
void Membership::switch_done(MonoTime now) {
    if (phase_ == JoinPhase::Activate) {
        mark_activated(now);
        return;
    }
    if (start_flash(Step::BootLoadPrepared, store::RecordJob::Op::Load, store::rec::membership_prepared, 0, 0, now) !=
        Status::Ok) {
        engine_.identity().return_record(rec_);
    }
}

// ACTIVE is durable. The record now says "the root's acknowledgement is owed": if JoinActive or the root's answer is
// lost, the next link session repeats it (docs/21 §5, LC06) instead of guessing.
void Membership::mark_activated(MonoTime now) {
    Writer w{MutByteView{rec_->payload}};
    w.bytes(req_.id.view());
    w.bytes(ByteView{req_.nonce});
    w.bytes(ByteView{req_.prepare_hash});
    w.u64be(activated_generation_);
    if (w.finish() != Status::Ok ||
        start_flash(Step::ActivateMark, store::RecordJob::Op::Commit, store::rec::membership_prepared,
                    k_prepared_activated, w.size(), now) != Status::Ok) {
        active_out(now);
    }
}

// The PREPARED record: request | nonce | prepare hash | MemberCredential COSE. Its content is what
// the device has to present again when it queries the root by request_id.
Status Membership::parse_prepared_record(const store::RecordJob &rec) {
    if (rec.state != k_prepared_state || rec.payload_len <= k_prepared_head ||
        rec.payload_len > k_prepared_head + k_max_member_cose) {
        return Status::NotFound; // consumed/aborted: nothing to resume
    }
    Request r;
    std::memcpy(r.id.bytes.data(), rec.payload.data(), 16);
    std::memcpy(r.nonce.data(), rec.payload.data() + 16, 16);
    std::memcpy(r.prepare_hash.data(), rec.payload.data() + 32, 32);
    Envelope env;
    ByteView data;
    LM_TRY(peek_signed(ByteView{rec.payload.data() + k_prepared_head, rec.payload_len - k_prepared_head},
                       k_type_member_credential, env, data));
    LM_TRY(decode_member_credential(data, r.mc));
    r.membership = r.mc.membership.value();
    r.assignment = r.mc.assignment.value();
    r.prepared_generation = rec.generation;
    r.evidence = kEvRequested | kEvRootStored | kEvDeviceStored;
    r.known = true;
    req_ = r;
    return Status::Ok;
}

// ---- discovery and connection ----
void Membership::begin_discovery(MonoTime now) {
    phase_ = JoinPhase::Discover;
    engine_.random(MutByteView{hello_nonce_});
    have_cand_ = false;
    offers_ = {};
    collect_until_ = MonoTime::never();
    std::array<uint8_t, 2> j{};
    engine_.random(MutByteView{j});
    // Listen 800 ms without transmitting, then the first hello after 0..399 ms of jitter (docs/07 §3). The
    // operation's own budget (search_deadline_) ends the search; the policy object only paces it.
    disc_.begin(now, static_cast<uint16_t>((uint32_t{j[0]} << 8U | j[1]) % 400), true, Duration::from_s(3600));
    retry_at_ = MonoTime::never();
}

void Membership::send_hello(MonoTime now) {
    std::array<uint8_t, wire::k_link_header_bytes + wire::k_bootstrap_header_bytes + 9> frame{};
    std::size_t len = 0;
    OfferHint h; // SEC-Da: a scoped device tags its hello
    if (scope_sign(engine_.identity().scope_key(), k_obj_join_hello, hello_nonce_, h) != Status::Ok ||
        encode_discovery(false, hello_nonce_, 0, MutByteView{frame}, len, &h) != Status::Ok) {
        return;
    }
    (void)engine_.transmit(MacAddr::broadcast(), ByteView{frame.data(), len}, k_tag_hello, now);
    // A busy radio only costs this hello: the policy object sends the next one a second later.
}

// Offers are hints (docs/07 §3): nothing they say authorises anything, every candidate goes through the full
// bounded handshake. The root itself (depth 0) is taken at once; otherwise the shallowest of the first
// 300 ms wins. A higher expected-list revision than the one we were refused at ends a NOT_EXPECTED hold.
void Membership::discovery(const MacAddr &src, const wire::BootstrapCarrier &c, uint32_t domain_hint, MonoTime now) {
    OfferHint h;
    if (phase_ != JoinPhase::Discover || c.object_kind != k_obj_join_offer || decode_offer_hint(c.body, h) != Status::Ok ||
        !scope_ok(engine_.identity().scope_key(), k_obj_join_offer, c.exchange_id, h)) {
        return; // SEC-Da: a scoped device hears only offers of its own scope
    }
    // [S18] A member looks in one domain: its own (RESUME: a link session needs it) or, switching, the target's.
    const LocalIdentity &id = engine_.identity();
    if ((switch_ || id.is_member()) &&
        domain_hint != link::domain_hint_of(switch_ ? switch_domain_ : id.delegation().domain)) {
        return;
    }
    // An offer is unauthenticated: its higher revision ends a NOT_EXPECTED hold only through the rate-limited hint
    // bucket, and it neither resets the backoff nor the hold's escalation (docs/21 §3, review finding 1).
    if (disc_.revision_advanced(h.expected_revision) && disc_.hint(now)) {
        disc_.clear_suppress();
    }
    if (have_cand_ || c.exchange_id != hello_nonce_) {
        return; // only answers to our own hello are followed
    }
    ++stats_.offers_seen;
    Offer *slot = nullptr;
    for (Offer &o : offers_) {
        if (o.used && o.mac == src) {
            slot = &o;
        }
    }
    for (Offer &o : offers_) {
        if (slot == nullptr && !o.used) {
            slot = &o;
        }
    }
    if (slot == nullptr) {
        return; // three candidates are enough
    }
    *slot = Offer{true, false, src, h.depth, h.expected_revision};
    if (h.depth == 0) {
        choose_offer(now);
    } else if (collect_until_.is_never()) {
        collect_until_ = now + k_collect;
    }
}

// The proxied joiner speaks slower and in smaller steps: a relay needs a moment per frame and each round
// trip crosses `depth` more hops. Bounded (docs/07 §3 does not lengthen the 30 s search).
void Membership::apply_pacing(uint8_t depth) {
    link::LinkPolicy &p = engine_.link().policy();
    const link::LinkPolicy defaults;
    p.rto = depth == 0 ? defaults.rto : defaults.rto + Duration::from_ms(200 * std::min<int>(depth, 20));
    p.tx_gap = depth == 0 ? defaults.tx_gap : Duration::from_ms(60);
}

void Membership::choose_offer(MonoTime now) {
    collect_until_ = MonoTime::never();
    Offer *best = nullptr;
    for (Offer &o : offers_) {
        if (o.used && !o.tried && (best == nullptr || o.depth < best->depth)) {
            best = &o;
        }
    }
    if (best == nullptr) {
        return;
    }
    best->tried = true;
    cand_ = best->mac;
    cand_revision_ = best->revision;
    have_cand_ = true;
    apply_pacing(best->depth);
    try_connect(now);
}

void Membership::try_connect(MonoTime now) {
    Status st;
    if (engine_.identity().is_member() && !switch_) {
        st = engine_.link().connect(cand_, now); // RESUME: an ordinary fresh link session
    } else {
        st = engine_.link().exchange().start_join(cand_, &peer_, now, switch_); // [S18] a member's transfer too
    }
    if (st == Status::Ok) {
        phase_ = JoinPhase::Connect;
        disc_.note_handshake();
        retry_at_ = MonoTime::never();
        return;
    }
    if (st == Status::Conflict && engine_.identity().is_member() && !switch_) {
        finish_join(Status::Ok, LM_OUTCOME_APPLIED, now); // a session already exists
        return;
    }
    if (st == Status::Busy || st == Status::RateLimited || st == Status::NoCapacity) {
        retry_at_ = now + k_connect_retry; // local shortage or the 30 s handshake gate: not RF loss
        return;
    }
    finish_join(st, LM_OUTCOME_REJECTED, now);
}

void Membership::exchange_failed(Status why, MonoTime now) {
    if (phase_ != JoinPhase::Connect) {
        return;
    }
    apply_pacing(0);
    have_cand_ = false;
    const bool another = std::any_of(offers_.begin(), offers_.end(), [](const Offer &o) { return o.used && !o.tried; });
    if (!disc_.may_handshake() && !another) {
        finish_join(why, LM_OUTCOME_REJECTED, now);
        return;
    }
    phase_ = JoinPhase::Discover; // one more candidate within the search budget: the next offer, or the next hello
    if (another && disc_.may_handshake()) {
        choose_offer(now);
    }
}

// The root does not expect this device (yet): a hint, not a verdict (docs/07 §3). No hello for 10..60 s, then
// asked again; a higher expected revision heard meanwhile ends the hold at once (J02).
void Membership::not_expected(MonoTime now) {
    release_join();
    phase_ = JoinPhase::Discover;
    offers_ = {};
    collect_until_ = MonoTime::never();
    // The hold is at least the 30 s full-handshake gate towards this root (docs/06 §8: asking again earlier would
    // only be RATE_LIMITED); the next search gets its own budget after the hold. 30 s, then 60 s.
    const Duration hold = Duration::from_s(not_expected_ == 0 ? 30 : 60);
    ++not_expected_;
    disc_.not_expected(now, hold, cand_revision_);
    disc_.wake(now, 0);
    if (budget_default_) { // a caller who gave no budget waits for the next search; an explicit budget is kept
        search_deadline_ = now + hold + k_default_budget;
    }
    emit_state(static_cast<uint32_t>(Status::NotFound));
}

void Membership::session_up(bool initiator, const MacAddr &mac, const DeviceId &peer, ByteView bundle,
                            MonoTime now) {
    if (!initiator || phase_ != JoinPhase::Connect) {
        return;
    }
    ByteView dc_cose;
    ByteView del_cose;
    if (cred_pair_parse(bundle, k_max_delegation_cose, dc_cose, del_cose) != Status::Ok || !lend_record_only()) {
        finish_join(Status::Busy, LM_OUTCOME_REJECTED, now);
        return;
    }
    pipe_.bind(mac, peer, hint());
    std::memcpy(rec_->payload.data(), del_cose.data(), del_cose.size());
    phase_ = JoinPhase::PersistDelegation;
    // [S18] A member's transfer/handover must not touch root_delegation before its new credential is committed: the
    // new root's delegation waits in pending_delegation (every cut then loads the old or the new membership).
    if (start_flash(switch_ ? Step::CommitPending : Step::CommitDelegation, store::RecordJob::Op::Commit,
                    switch_ ? store::rec::pending_delegation : store::rec::root_delegation, 0,
                    del_cose.size(), now) != Status::Ok) {
        finish_join(Status::Busy, LM_OUTCOME_REJECTED, now);
    }
}

bool Membership::lend_record_only() {
    if (rec_ != nullptr) {
        return true;
    }
    rec_ = engine_.identity().lend_record();
    if (rec_ == nullptr) {
        ++stats_.scratch_busy;
    }
    return rec_ != nullptr;
}

// ---- Flash chain of the joiner ----
void Membership::flash_done(Step step, Status s, MonoTime now) {
    switch (step) {
    case Step::AutoPolicyLoad:
    case Step::AutoPolicyCommit: {
        auto_loaded_ = true;
        auto_fault_ = s != Status::Ok && !(step == Step::AutoPolicyLoad && s == Status::NotFound);
        if (s == Status::Ok) {
            Reader r{ByteView{rec_->payload.data(), rec_->payload_len}};
            const uint8_t version = r.u8();
            const uint64_t revision = r.u64be();
            const uint8_t enabled = r.u8();
            const uint32_t interval = r.u32be();
            if (r.finish() != Status::Ok || version != 2 || revision > INT64_MAX || enabled > 1 ||
                (enabled && interval < 600000)) {
                auto_fault_ = true;
            } else {
                auto_revision_ = revision;
                auto_enabled_ = enabled != 0;
                isolation_ms_ = interval;
            }
        }
        if (auto_fault_) {
            auto_enabled_ = false;
            engine_.emit_event(LM_EVENT_FAULT, static_cast<uint32_t>(Status::RecoveryRequired), 0,
                               nullptr);
        }
        isolated_since_ = auto_at_ = MonoTime::never();
        engine_.identity().return_record(rec_);
        if (step == Step::AutoPolicyCommit) {
            engine_.emit_event(
                LM_EVENT_OPERATION,
                static_cast<uint32_t>(auto_fault_ ? Status::RecoveryRequired : Status::Ok),
                auto_policy_op_, nullptr);
        }
        return;
    }
    case Step::BootLoadPrepared:
        if (s == Status::Ok && engine_.identity().is_member()) {
            parse_activated_record(*rec_);
        } else if (s == Status::Ok && parse_prepared_record(*rec_) == Status::Ok) {
            have_prepared_ = true;
            resume_ = true;
            req_.operation = engine_.next_control_op();
        } else if (s != Status::Ok && s != Status::NotFound) {
            engine_.emit_event(LM_EVENT_FAULT, static_cast<uint32_t>(s), 0, nullptr);
        }
        engine_.identity().return_record(rec_);
        if (resume_) { // docs/07 §10: ask the root again about the same request, no new approval
            begin_discovery(now);
            search_deadline_ = now + k_default_budget;
            not_expected_ = 0;
            emit_state(0);
        }
        return;

    case Step::CommitDelegation:
    case Step::CommitPending:
        if (s != Status::Ok) {
            finish_join(s, LM_OUTCOME_REJECTED, now);
            return;
        }
        phase_ = JoinPhase::LoadTicket;
        if (start_flash(Step::LoadTicket, store::RecordJob::Op::Load, k_rec_assignment_ticket, 0, 0, now) !=
            Status::Ok) {
            finish_join(Status::Busy, LM_OUTCOME_REJECTED, now);
        }
        return;

    case Step::LoadTicket:
        if (s != Status::Ok) { // no ticket: nothing authorises this device to ask (docs/07 §4)
            finish_join(s == Status::NotFound ? Status::AuthPending : s, LM_OUTCOME_REJECTED, now);
            return;
        }
        request_ready(now);
        return;

    case Step::VerifyActivation:
        if (s != Status::Ok) { // the signature does not complete what was announced: nothing goes live
            finish_join(s == Status::AuthRejected || s == Status::BadFrame ? Status::AuthRejected : s,
                        LM_OUTCOME_REJECTED, now);
            return;
        }
        activate_commit(now);
        return;

    case Step::CommitPrepared:
        if (s != Status::Ok) { // the record may or may not exist: the next boot reads it (INDETERMINATE)
            finish_join(s, LM_OUTCOME_INDETERMINATE, now);
            return;
        }
        have_prepared_ = true;
        req_.prepared_generation = rec_->generation;
        req_.evidence |= kEvRootStored | kEvDeviceStored;
        prepared_until_ = now + Duration::from_ms(req_.reservation_ms);
        engine_.identity().return_record(rec_);
        phase_ = JoinPhase::StoredOut;
        emit_state(0);
        send_stored(now);
        return;

    case Step::ActivateLoad:
        activate_loaded(s, now);
        return;

    case Step::ActivateCommit:
        if (s != Status::Ok) { // ACTIVE may or may not be durable: the next boot decides (allowed state)
            finish_join(s, LM_OUTCOME_INDETERMINATE, now);
            return;
        }
        activated_generation_ = rec_->generation;
        if (const Status a = engine_.identity().adopt_member(peer_.delegation, req_.mc,
                                                             ByteView{rec_->payload.data(), rec_->payload_len});
            a != Status::Ok) {
            finish_join(a, LM_OUTCOME_INDETERMINATE, now);
            return;
        }
        req_.evidence |= kEvDeviceActive;
        ++stats_.joins_active;
        if (switch_ && start_flash(Step::SwitchLoad, store::RecordJob::Op::Load, store::rec::pending_delegation, 0, 0,
                                   now) == Status::Ok) {
            return; // [S18] root_delegation follows the committed credential (the loader bridges a cut between)
        }
        mark_activated(now);
        return;

    case Step::SwitchLoad: // [S18]
        if (s != Status::Ok || start_flash(Step::SwitchCommit, store::RecordJob::Op::Commit, store::rec::root_delegation,
                                           0, rec_->payload_len, now) != Status::Ok) {
            switch_done(now); // the loader repairs it at the next boot (delegation_behind)
        }
        return;

    case Step::SwitchCommit:
        if (s == Status::Ok) {
            engine_.identity().delegation_repaired();
        }
        switch_done(now);
        return;

    case Step::SwitchPeek:
        switch_peeked(s, now);
        return;

    case Step::ActivateMark:
        have_prepared_ = true; // the ACTIVATED record stays until the root acknowledged
        confirm_pending_ = true;
        active_out(now);
        return;

    case Step::ConfirmConsume:
        confirm_consume_ = false;
        engine_.identity().return_record(rec_);
        if (phase_ == JoinPhase::ActiveOut) {
            have_prepared_ = false;
            finish_join(Status::Ok, LM_OUTCOME_APPLIED, now);
        } else {
            have_prepared_ = false;
            engine_.emit_event(LM_EVENT_OPERATION, 0, req_.operation, nullptr);
        }
        return;

    case Step::ConsumePrepared:
        have_prepared_ = false;
        finish_join(req_.reason, req_.outcome, now);
        return;

    case Step::InstallTicket:
        install_done(s, now);
        return;

    case Step::LeaveCommit:
    case Step::LeaveCheck: // [FIX8-D6]
        leave_flash_done(step, s, now);
        return;

    case Step::RenewVerify: // [S18]
    case Step::RenewCommit:
    case Step::RenewReload:
        renew_step(step, s, now);
        return;

    case Step::RevokeVerify: // [S18]
        revoke_verified(s, now);
        return;

    case Step::None:
        return;
    }
}

MonoTime Membership::deadline() const {
    MonoTime next = earliest(pipe_.deadline(), retry_at_);
    if (phase_ == JoinPhase::Discover) {
        next = earliest(next, earliest(disc_.deadline(), search_deadline_));
        next = earliest(next, collect_until_);
    }
    next = earliest(next, earliest(request_deadline_, prepared_until_));
    next = earliest(next, final_wait_until_);
    next = earliest(next, leave_tx_wait_); // (the DRAIN deadline is folded into it by leave_timer)
    next = earliest(next, confirm_at_);
    next = earliest(next, auto_at_);
    return next;
}

void Membership::on_tx_outcome(const TxOutcome &o, MonoTime now) {
    if (pipe_.owns_tag(o.tag)) {
        pipe_.on_tx_outcome(o, now);
    } else if ((o.tag & 0xFFFF0000U) == k_tag_leave) {
        leave_tx_done(o, now);
    }
}

void Membership::on_timer(MonoTime now) {
    if (phase_ != JoinPhase::Idle) {
        const Status e = pipe_.on_timer(now);
        if (e != Status::Ok && phase_ != JoinPhase::Idle) {
            pipe_failed(e, now);
        }
    }
    if (phase_ == JoinPhase::Discover) {
        if (now >= search_deadline_) {
            finish_join(Status::Expired, LM_OUTCOME_EXPIRED, now); // budget spent: not a device fault
            return;
        }
        if (disc_.poll(now) == Discovery::Act::Hello && !have_cand_ && collect_until_.is_never()) {
            send_hello(now);
        }
        if (!have_cand_ && !collect_until_.is_never() && now >= collect_until_) {
            choose_offer(now);
        }
        if (have_cand_ && now >= retry_at_) {
            try_connect(now);
        }
    }
    if (now >= retry_at_ && phase_ != JoinPhase::Discover) {
        retry_at_ = MonoTime::never();
        retry_work(now);
    }
    if (phase_ == JoinPhase::RequestOut && now >= request_deadline_) {
        finish_join(Status::Expired, LM_OUTCOME_EXPIRED, now); // approval never came: ask again later
    } else if (phase_ == JoinPhase::StoredOut && now >= prepared_until_) {
        // The reservation ran out before COMMIT. The PREPARED record stays: a later query decides.
        finish_join(Status::Expired, LM_OUTCOME_EXPIRED, now);
    } else if (phase_ == JoinPhase::ActiveOut && now >= final_wait_until_) {
        // ACTIVE is durable here but the root's acknowledgement never arrived: not "complete".
        finish_join(Status::Expired, LM_OUTCOME_INDETERMINATE, now);
    }
    leave_timer(now);
    auto_timer(now);
    if (confirm_pending_ && now >= confirm_at_) {
        send_confirm(now);
    }
}

// The root did not answer `max_attempts` times. What that means depends on how far we got.
void Membership::pipe_failed(Status why, MonoTime now) {
    if (phase_ == JoinPhase::ActiveOut) {
        finish_join(Status::Expired, LM_OUTCOME_INDETERMINATE, now);
    } else if (phase_ == JoinPhase::RequestOut || phase_ == JoinPhase::StoredOut) {
        finish_join(why == Status::Expired ? Status::Expired : why, LM_OUTCOME_EXPIRED, now);
    } else {
        finish_join(why, LM_OUTCOME_REJECTED, now);
    }
}

// A borrow was busy earlier: resume the step that needed it.
void Membership::retry_work(MonoTime now) {
    switch (phase_) {
    case JoinPhase::LoadTicket:
        request_ready(now);
        break;
    case JoinPhase::Verify:
        prepared_verified(now);
        break;
    case JoinPhase::Activate:
        activate(now);
        break;
    default:
        if (retry_consume_) {
            fail_and_consume(req_.reason, now);
        } else if (renew_adopt_) {
            renew_adopt(now); // [S18] the exchange was sending our bundle
        } else if (boot_load_) {
            boot_load(now); // [P4] the record memory was lent at boot
        }
        break;
    }
}

Status Membership::local_policy(lm_policy_t &out) const {
    out = lm_policy_t{};
    out.struct_size = sizeof(out);
    out.abi_version = LM_ABI_VERSION;
    out.revision = auto_revision_;
    out.channel_automatic = 1;
    out.relay_allowed = engine_.config().role == Role::Relay ? 1U : 0U;
    out.auto_transfer_on_isolation = auto_enabled_ ? 1U : 0U;
    out.isolation_before_transfer_ms = isolation_ms_;
    return auto_fault_ ? Status::RecoveryRequired
                       : (auto_loaded_ ? Status::Ok : Status::AuthPending);
}

Reply Membership::set_local_policy(const lm_policy_t &want, uint64_t expected, MonoTime now) {
    if (!auto_loaded_ || auto_fault_) {
        return Reply{auto_fault_ ? Status::RecoveryRequired : Status::AuthPending, 0, 0};
    }
    if (expected != auto_revision_) {
        return Reply{Status::Conflict, 0, 0};
    }
    lm_policy_t cur{};
    (void)local_policy(cur);
    if (want.join_mode != cur.join_mode || want.relay_allowed != cur.relay_allowed ||
        want.channel_automatic != cur.channel_automatic ||
        want.channel_freeze != cur.channel_freeze) {
        return Reply{Status::Unsupported, 0, 0};
    }
    if (want.auto_transfer_on_isolation > 1 ||
        (want.auto_transfer_on_isolation && want.isolation_before_transfer_ms < 600000) ||
        auto_revision_ == INT64_MAX) {
        return Reply{Status::InvalidArgument, 0, 0};
    }
    if (phase_ != JoinPhase::Idle || leaving() || job_in_flight_ || !lend_record_only()) {
        return Reply{Status::Busy, 0, 0};
    }
    Writer w{MutByteView{rec_->payload}};
    w.u8(2);
    w.u64be(auto_revision_ + 1);
    w.u8(static_cast<uint8_t>(want.auto_transfer_on_isolation));
    w.u32be(want.isolation_before_transfer_ms);
    const Status st = start_flash(Step::AutoPolicyCommit, store::RecordJob::Op::Commit,
                                  store::rec::policy, 0, w.size(), now);
    if (st != Status::Ok) {
        engine_.identity().return_record(rec_);
        return Reply{st, 0, 0};
    }
    auto_policy_op_ = engine_.next_control_op();
    return Reply{Status::Ok, auto_policy_op_, 0};
}

void Membership::pause_isolation(Duration gap) {
    if (!isolated_since_.is_never()) {
        isolated_since_ = isolated_since_ + gap;
    }
    if (!auto_at_.is_never()) {
        auto_at_ = auto_at_ + gap;
    }
}

void Membership::auto_timer(MonoTime now) {
    if (engine_.identity().state() != LocalIdentity::State::Ready ||
        engine_.radio_state() == RadioState::Stopped) {
        isolated_since_ = auto_at_ = MonoTime::never();
        return; // boot/start owns the record first; no policy job may race identity loading
    }
    if (!auto_loaded_ && !auto_fault_ && !boot_load_ && phase_ == JoinPhase::Idle &&
        !job_in_flight_) {
        if (!lend_record_only()) {
            auto_at_ = now + k_busy_retry;
            return;
        }
        const Status st = start_flash(Step::AutoPolicyLoad, store::RecordJob::Op::Load,
                                      store::rec::policy, 0, 0, now);
        if (st != Status::Ok) {
            engine_.identity().return_record(rec_);
            auto_at_ = now + k_busy_retry;
        } else {
            auto_at_ = MonoTime::never();
        }
        return;
    }
    if (!auto_enabled_ || auto_fault_ || !engine_.identity().is_member()) {
        isolated_since_ = auto_at_ = MonoTime::never();
        return;
    }
    const uint32_t conn = engine_.mesh().connectivity(now);
    if (conn != LM_ISOLATED && conn != LM_DEGRADED) {
        isolated_since_ = auto_at_ = MonoTime::never();
        return;
    }
    if (isolated_since_.is_never()) {
        isolated_since_ = now;
        auto_at_ = now + Duration::from_ms(isolation_ms_);
    }
    if (now < auto_at_) {
        return;
    }
    if (phase_ != JoinPhase::Idle || leaving() || have_prepared_ || confirm_pending_ ||
        job_in_flight_ || engine_.chan().unsettled() || !engine_.power().search_allowed(now)) {
        auto_at_ = now + Duration::from_s(30);
        return;
    }
    // The existing transfer path keeps A live, checks the installed signed grant and authenticates
    // B. A missing grant stays AUTH_PENDING: never turn isolation into permission to change
    // domains.
    JoinArgs a;
    a.mode = LM_JOIN_TRANSFER_CANDIDATE;
    engine_.random(MutByteView{a.request.bytes});
    uint64_t operation = 0;
    (void)join(a, now, operation);
    auto_at_ = now + Duration::from_ms(
                         isolation_ms_); // bounded attempts, including missing/expired grants
}

} // namespace lm::member
