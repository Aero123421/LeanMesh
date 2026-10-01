// Membership commands (lm_join, lm_leave, lm_install_control(ticket), lm_membership_get,
// lm_get_request) and the leave state machine. The join protocol itself is in membership.cpp.
#include <algorithm>
#include <cstring>

#include "core/engine.hpp"
#include "core/member/membership.hpp"

namespace lm::member {
namespace {

constexpr Duration k_default_budget = Duration::from_s(30);
constexpr Duration k_leave_poll = Duration::from_ms(250);   // only while an explicit DRAIN is waiting
constexpr Duration k_leave_tx_wait = Duration::from_s(2);   // the notice is best effort, never blocks a leave
constexpr Duration k_busy_retry = Duration::from_ms(50);
constexpr uint8_t k_leave_notice_attempts = 3;
constexpr uint8_t k_leave_checks = 3;                        // FIX8-D6: read-backs / re-commits of a tombstone
constexpr Duration k_leave_check_gap = Duration::from_ms(1000);

} // namespace

// ---- lm_join ----
Status Membership::join(const JoinArgs &a, MonoTime now, uint64_t &operation) {
    if (a.mode > LM_JOIN_TRANSFER_CANDIDATE) {
        return Status::InvalidArgument;
    }
    const LocalIdentity &id = engine_.identity();
    if (id.state() != LocalIdentity::State::Ready) {
        return id.state() == LocalIdentity::State::Failed ? Status::RecoveryRequired : Status::AuthPending;
    }
    if (boot_failed_) {
        return Status::RecoveryRequired; // the PREPARED record could not be read: state unknown
    }
    if (phase_ != JoinPhase::Idle || job_in_flight_ || leave_ != LeavePhase::Idle) {
        return Status::Busy;
    }
    const Duration budget = a.search_budget_ms == 0 ? k_default_budget
                                                    : Duration::from_ms(std::min<uint32_t>(a.search_budget_ms, 30000));
    switch_ = handover_ = false;
    if (id.is_member() && a.mode == LM_JOIN_TRANSFER_CANDIDATE) {
        // [S18] The member keeps its membership while it asks the root its installed object names (a transfer ticket:
        // another domain's root; a RootHandover: its domain's new root) for the next one (docs/07 §8, docs/21 §8).
        if (a.request.is_zero()) {
            return Status::InvalidArgument;
        }
        if (have_prepared_ && (confirm_pending_ || a.request != req_.id)) {
            // An acknowledgement still owed first; a switch cut after its PREPARED commit is asked about by its id.
            return confirm_pending_ ? Status::Busy : Status::Conflict;
        }
        if (!have_prepared_ && !lend_record_only()) {
            return Status::Busy; // the installed object is read first (where to look)
        }
        if (!have_prepared_) {
            req_ = Request{};
            req_.id = a.request;
        }
        switch_ = true;
        handover_ = have_prepared_ && switch_domain_ == id.delegation().domain;
    } else if (id.is_member()) {
        if (a.mode != LM_JOIN_RESUME) {
            return Status::Conflict; // already ACTIVE: nothing to join
        }
        // RESUME of an ACTIVE member needs no human approval and no ledger change: a fresh link session.
        if (!confirm_pending_) { // a durable acknowledgement still owed keeps its request (id, hash) intact
            req_ = Request{};
            req_.id = a.request;
        }
        link_resume_ = true;
    } else if (a.mode == LM_JOIN_TRANSFER_CANDIDATE) {
        return Status::NotFound; // no membership to transfer: a device without one joins (LM_JOIN_NEW)
    } else {
        if (a.request.is_zero()) {
            return Status::InvalidArgument;
        }
        if (a.mode == LM_JOIN_RESUME && !have_prepared_) {
            return Status::NotFound; // no ACTIVE credential and no PREPARED request to resume
        }
        if (have_prepared_ && a.request != req_.id) {
            return Status::Conflict; // the outstanding request is resolved under its own id first
        }
        if (!have_prepared_) {
            req_ = Request{};
            req_.id = a.request;
        }
    }
    target_ = a.target;
    constrain_ = a.constrain;
    operation = engine_.next_control_op();
    req_.operation = operation;
    req_.outcome = LM_OUTCOME_PENDING;
    req_.reason = Status::Ok;
    not_expected_ = 0;
    budget_default_ = a.search_budget_ms == 0;
    search_deadline_ = now + budget;
    if (switch_ && !have_prepared_) {
        // [S18] A transfer looks for its ticket's target domain, a handover for its own domain's new root: the
        // installed object is read before the search starts (switch_peeked).
        phase_ = JoinPhase::LoadTicket;
        if (start_flash(Step::SwitchPeek, store::RecordJob::Op::Load, k_rec_assignment_ticket, 0, 0, now) !=
            Status::Ok) {
            engine_.identity().return_record(rec_);
            switch_ = false;
            phase_ = JoinPhase::Idle;
            return Status::Busy;
        }
        ++stats_.joins_started;
        emit_state(0);
        return Status::Ok;
    }
    ++stats_.joins_started;
    begin_discovery(now);
    disc_.clear_suppress();
    emit_state(0);
    return Status::Ok;
}

// ---- ticket record ----
Status Membership::install_ticket(ByteView cose, MonoTime now, uint64_t &operation) {
    const LocalIdentity &id = engine_.identity();
    if (id.state() != LocalIdentity::State::Ready) {
        return Status::AuthPending;
    }
    if (have_prepared_) {
        return Status::Conflict;
    }
    if (phase_ != JoinPhase::Idle || job_in_flight_ || rec_ != nullptr) {
        return Status::Busy;
    }
    if (cose.empty() || cose.size() > store::k_max_payload) {
        return Status::NoCapacity;
    }
    Envelope env;
    ByteView data;
    if (peek_signed(cose, k_type_root_handover, env, data) == Status::Ok) {
        RootHandover h; // [S18] kept like a ticket: what authorises this member's next membership (docs/21 §8)
        LM_TRY(decode_handover(data, h));
        LM_TRY(check_handover(h)); // FIX5-D4: never stored when no member could follow it
        if (!id.is_member() || env.domain != id.delegation().domain || h.old_root != id.delegation().root ||
            h.old_generation != id.delegation().generation) {
            return Status::AuthRejected; // not a handover of this device's root
        }
    } else {
        AssignmentTicket t;
        LM_TRY(peek_signed(cose, k_type_assignment_ticket, env, data));
        LM_TRY(decode_assignment_ticket(data, t));
        // Structure and addressee only: the fleet signature is verified by whoever acts on the ticket
        // (the root when it is presented); a wrong ticket costs this device its own join, nothing more.
        if (t.device != id.self() || t.fleet != id.trust().fleet ||
            (id.is_member() && (t.source != id.delegation().domain || t.expected_old != id.member().assignment.value()))) {
            return Status::AuthRejected; // [S18] a member installs only a transfer away from its current assignment
        }
        // SEC-D4a / S18: mode 0 names a fresh nonce this device issued (transfer_nonce); any other is a replay.
        if (t.mode == 0 && (!nonce_valid_ || t.nonce != nonce_)) {
            return Status::AuthRejected;
        }
        if (t.new_generation < id.own_floor().assignment) {
            return Status::Revoked; // SEC-D8: this generation was consumed before the device left
        }
    }
    if (!lend_record_only()) {
        return Status::Busy;
    }
    std::memcpy(rec_->payload.data(), cose.data(), cose.size());
    const Status st = start_flash(Step::InstallTicket, store::RecordJob::Op::Commit, k_rec_assignment_ticket, 0,
                                  cose.size(), now);
    if (st != Status::Ok) {
        engine_.identity().return_record(rec_);
        return st;
    }
    install_op_ = engine_.next_control_op();
    operation = install_op_;
    return Status::Ok;
}

void Membership::install_done(Status s, MonoTime /*now*/) {
    engine_.identity().return_record(rec_);
    engine_.emit_event(LM_EVENT_OPERATION, static_cast<uint32_t>(s), install_op_, nullptr);
}

// ---- views ----
void Membership::get_membership(lm_membership_t &out, MonoTime /*now*/) const {
    view(engine_.identity(), this, state_since_, out);
}

// lm_membership_get. `m` is the joiner/member side; the root holds none (ADR-002 P8): it is provisioned and never
// joins or leaves, so its answer is the identity's alone.
void Membership::view(const LocalIdentity &id, const Membership *m, MonoTime since, lm_membership_t &out) {
    out = lm_membership_t{};
    out.struct_size = sizeof(out);
    out.abi_version = LM_ABI_VERSION;
    if (id.state() == LocalIdentity::State::Ready) {
        std::memcpy(out.device.bytes, id.self().bytes.data(), 32);
    }
    uint32_t state = LM_UNASSIGNED;
    if (id.state() == LocalIdentity::State::Failed) {
        state = LM_QUARANTINED;
    } else if (id.is_member()) {
        std::memcpy(out.domain.bytes, id.delegation().domain.bytes.data(), 16);
        out.assignment_generation = id.member().assignment.value();
        out.membership_generation = id.member().membership.value();
        state = m != nullptr && m->leave_ != LeavePhase::Idle ? LM_LEAVING : LM_ACTIVE;
    } else if (id.state() == LocalIdentity::State::Ready && id.member_status() == Status::Revoked) {
        state = LM_MEMBER_REVOKED;
    } else if (m != nullptr) {
        switch (m->phase_) {
        case JoinPhase::Idle:
            state = m->have_prepared_ ? LM_PREPARED : LM_UNASSIGNED;
            break;
        case JoinPhase::Discover:
            state = LM_DISCOVERING;
            break;
        case JoinPhase::Connect:
        case JoinPhase::PersistDelegation:
        case JoinPhase::LoadTicket:
            state = LM_AUTHENTICATING;
            break;
        case JoinPhase::RequestOut:
        case JoinPhase::Verify:
            state = LM_APPROVAL_PENDING;
            break;
        case JoinPhase::PersistPrepared:
        case JoinPhase::StoredOut:
        case JoinPhase::Activate:
        case JoinPhase::ActiveOut:
            state = LM_PREPARED;
            break;
        }
        if (m->peer_.known) {
            std::memcpy(out.domain.bytes, m->peer_.delegation.domain.bytes.data(), 16);
        }
    }
    out.state = state;
    // the last refusal is history once ACTIVE
    out.reason = state == LM_ACTIVE || m == nullptr ? 0 : static_cast<uint32_t>(m->req_.reason);
    out.state_since_mono_ms = since.to_ms();
}

Status Membership::get_request(const RequestId &id, lm_operation_t &out, MonoTime now) const {
    if (!req_.known && req_.id.is_zero()) {
        return Status::NotFound;
    }
    if (id != req_.id) {
        return Status::NotFound;
    }
    out = lm_operation_t{};
    out.struct_size = sizeof(out);
    out.abi_version = LM_ABI_VERSION;
    out.operation_id = req_.operation;
    // FIX8-D8 (second review #13): the public phase (LM_PHASE_*), never the private join step: FINAL once the request
    // has its outcome; WAITING_RECEIPT while the root holds it (JoinRequest sent, until the final acknowledgement);
    // PENDING before (search, handshake, ticket).
    out.phase = req_.outcome != LM_OUTCOME_PENDING ? LM_PHASE_FINAL
                : phase_ >= JoinPhase::RequestOut      ? LM_PHASE_WAITING_RECEIPT
                                                       : LM_PHASE_PENDING;
    out.outcome = req_.outcome;
    out.reason = static_cast<uint32_t>(req_.reason);
    out.evidence_bits = req_.evidence;
    out.accepted_mono_ms = 0;
    out.last_evidence_mono_ms = now.to_ms();
    return Status::Ok;
}

// ---- lm_leave ----
Status Membership::leave(uint8_t mode, uint32_t deadline_ms, MonoTime now, uint64_t &operation) {
    if (mode > LM_LEAVE_IMMEDIATE || deadline_ms > 30000) {
        return Status::InvalidArgument;
    }
    const LocalIdentity &id = engine_.identity();
    if (id.state() != LocalIdentity::State::Ready) {
        return Status::AuthPending;
    }
    if (leave_ != LeavePhase::Idle || phase_ != JoinPhase::Idle || job_in_flight_) {
        return Status::Busy;
    }
    if (!id.is_member() && !have_prepared_) {
        return Status::NotFound; // nothing to leave
    }
    leave_mode_ = mode;
    leave_op_ = engine_.next_control_op();
    operation = leave_op_;
    leave_deadline_ = now + Duration::from_ms(deadline_ms);
    leave_attempts_ = 0;
    leave_tx_inflight_ = false;
    leave_prepared_only_ = !id.is_member();
    leave_checks_ = 0;
    if (!leave_prepared_only_) {
        // SEC-D8: the tombstone records what this device consumed (the generations below its floor); [S18] a
        // revocation's floors when they are higher (a revocation notice starts its own leave; one that arrives while
        // a leave runs is dropped - the root refuses the device all the same).
        leave_assignment_ = std::max(id.member().assignment.value() + 1, revoked_ ? revoke_af_ : 0) - 1;
        leave_membership_ = std::max(id.member().membership.value() + 1, revoked_ ? revoke_mf_ : 0) - 1;
    }
    if (hooks_.refuse_sends != nullptr) {
        hooks_.refuse_sends(hooks_.ctx, true); // DRAIN and IMMEDIATE both stop new sends
    }
    if (leave_prepared_only_) { // abandoning a PREPARED join: one tombstone
        leave_ = LeavePhase::Committing;
        leave_commit(now);
        return Status::Ok;
    }
    engine_.emit_event(LM_EVENT_MEMBERSHIP, 0, leave_op_, nullptr); // state LEAVING
    if (mode == LM_LEAVE_IMMEDIATE) {
        // Unfinished work becomes INDETERMINATE / NOT_SENT and the domain credential is erased.
        leave_ = LeavePhase::Notifying;
        leave_notify(now);
    } else {
        leave_ = LeavePhase::Draining;
        if (engine_.config().role == Role::Relay) {
            engine_.mesh().begin_drain(now, leave_deadline_);
        }
        leave_timer(now);
    }
    return Status::Ok;
}

void Membership::leave_timer(MonoTime now) {
    switch (leave_) {
    case LeavePhase::Idle:
        return;
    case LeavePhase::Draining:
        if (!revoked_ && now >= leave_deadline_) {
            leave_finish(Status::DeadlineUnreachable, LM_OUTCOME_EXPIRED, now);
            return;
        }
        if (revoked_ || hooks_.drained == nullptr || hooks_.drained(hooks_.ctx)) {
            leave_ = LeavePhase::Notifying;
            leave_tx_wait_ = MonoTime::never();
            leave_notify(now);
        } else if (now >= leave_deadline_) {
            // Never turned into IMMEDIATE on our own (docs/07 §6): an explicit failure, still ACTIVE.
            leave_finish(Status::DeadlineUnreachable, LM_OUTCOME_EXPIRED, now);
        } else {
            leave_tx_wait_ = std::min(now + k_leave_poll, leave_deadline_);
        }
        return;
    case LeavePhase::Notifying:
        if (now >= leave_tx_wait_) {
            if (leave_tx_inflight_ || leave_attempts_ >= k_leave_notice_attempts) {
                leave_commit(now); // the notice is best effort; root revocation is the fallback
            } else {
                leave_notify(now);
            }
        }
        return;
    case LeavePhase::Committing:
        if (rec_ == nullptr && !job_in_flight_ && now >= leave_tx_wait_) {
            leave_commit(now); // the record memory was busy: try again
        }
        return;
    case LeavePhase::Reconciling:
        if (!job_in_flight_ && now >= leave_tx_wait_) {
            leave_check(now);
        }
        return;
    }
}

// One LeaveRequest (type 27) over the link session to the root neighbour, sealed with a fresh
// counter on every attempt. The root learns of the leave from an authenticated peer only.
void Membership::leave_notify(MonoTime now) {
    const LocalIdentity &id = engine_.identity();
    const link::Neighbor *root = nullptr;
    engine_.link().neighbors().for_each([&](Handle, link::Neighbor &n) {
        if (root == nullptr && n.role == 2 && n.cur.active && !n.join_only) {
            root = &n;
        }
    });
    if (root == nullptr) {
        leave_commit(now);
        return;
    }
    JoinObjectHeader h;
    h.type = k_type_leave_request;
    engine_.random(MutByteView{h.request.bytes});
    h.domain = id.delegation().domain;
    h.issuer = id.self();
    LeaveData d;
    d.device = id.self();
    d.mode = leave_mode_;
    d.deadline_ms = static_cast<uint32_t>(std::max<int64_t>(0, (leave_deadline_ - now).to_ms()));
    std::array<uint8_t, 192> obj{};
    std::size_t plen = 0;
    std::size_t dlen = 0;
    Status st = join_object_begin(h, MutByteView{obj}, plen);
    if (st == Status::Ok) {
        st = encode_leave(d, MutByteView{obj}.from(plen), dlen);
    }
    if (st == Status::Ok) {
        st = engine_.link().send_sealed(root->device, root->mac, wire::FrameKind::Control,
                                        ByteView{obj.data(), plen + dlen}, k_tag_leave, now);
    }
    if (st == Status::Busy || st == Status::DriverResultUnknown) {
        leave_tx_wait_ = now + Duration::from_ms(20); // radio occupied: local, not an attempt
        return;
    }
    if (st != Status::Ok) {
        leave_commit(now); // no session to speak on: leave anyway
        return;
    }
    ++leave_attempts_;
    leave_tx_inflight_ = true;
    leave_tx_wait_ = now + k_leave_tx_wait;
}

void Membership::leave_tx_done(const TxOutcome &o, MonoTime now) {
    if (leave_ != LeavePhase::Notifying || !leave_tx_inflight_) {
        return;
    }
    leave_tx_inflight_ = false;
    if (o.result == port::TxResult::MacAcked || leave_attempts_ >= k_leave_notice_attempts) {
        leave_commit(now);
    } else {
        leave_tx_wait_ = now; // MacFailed sample: send it again (fresh counter)
    }
}

void Membership::leave_commit(MonoTime now) {
    leave_ = LeavePhase::Committing;
    if (rec_ == nullptr) {
        rec_ = engine_.identity().lend_record();
        if (rec_ == nullptr) {
            ++stats_.scratch_busy;
            leave_tx_wait_ = now + k_busy_retry;
            return;
        }
    }
    if (hooks_.settle_pending != nullptr) {
        hooks_.settle_pending(hooks_.ctx);
    }
    std::size_t len = 0;
    if (!leave_prepared_only_) {
        // SEC-D8: one atomic commit ends the membership AND records what it consumed (the generations below the
        // floor, fixed when the leave began). No room in the revocation-floor table is needed.
        Writer w{MutByteView{rec_->payload}};
        w.u64be(leave_assignment_ + 1);
        w.u64be(leave_membership_ + 1);
        len = w.size();
    }
    const Status st = leave_prepared_only_
                          ? start_flash(Step::LeaveCommit, store::RecordJob::Op::Commit,
                                        store::rec::membership_prepared, k_prepared_consumed, 0, now)
                          : start_flash(Step::LeaveCommit, store::RecordJob::Op::Commit, store::rec::membership,
                                        revoked_ ? k_membership_revoked : k_membership_left, len, now);
    if (st == Status::Ok) {
        leave_tx_wait_ = MonoTime::never(); // its completion goes on (a deadline in the past would spin the owner)
        return;
    }
    if (!leave_prepared_only_ && (revoked_ || !engine_.identity().is_member())) {
        // FIX8-D6: a verified revocation (or a leave that already ended the membership in RAM) never turns back: the
        // membership ends in RAM now and the tombstone is written again later (bounded).
        if (engine_.identity().is_member()) {
            apply_left();
        }
        engine_.identity().return_record(rec_);
        leave_ = LeavePhase::Reconciling;
        leave_tx_wait_ = now + k_leave_check_gap;
        return;
    }
    leave_finish(st, LM_OUTCOME_INDETERMINATE, now);
}

void Membership::leave_flash_done(Step step, Status s, MonoTime now) {
    if (step == Step::LeaveCheck) {
        leave_checked(s, now);
        return;
    }
    if (leave_prepared_only_) { // (a PREPARED join abandoned: no membership to end)
        if (s == Status::Ok) {
            have_prepared_ = false;
        }
        leave_finish(s, s == Status::Ok ? LM_OUTCOME_APPLIED : LM_OUTCOME_INDETERMINATE, now);
        return;
    }
    if (engine_.identity().is_member()) {
        apply_left(); // FIX8-D6: whatever the commit said (the tombstone may be on the Flash, its read-back failed)
    }
    if (s != Status::Ok) {
        // Second review #3: 8668c69 reported the failure and kept the member live (storage LEFT, RAM ACTIVE, sends OK).
        // The leave stays done in RAM; the stored record is read back and the operation ends by what it holds.
        engine_.identity().return_record(rec_);
        leave_ = LeavePhase::Reconciling;
        leave_tx_wait_ = now + k_leave_check_gap;
        return;
    }
    leave_finish(Status::Ok, LM_OUTCOME_APPLIED, now);
}

// FIX8-D6: the stored membership record after a failed tombstone commit (Reconciling): a tombstone = the leave is
// durable (APPLIED); the old credential = it is not: written again; unreadable = read again. Bounded (k_leave_checks);
// then INDETERMINATE - RAM stays left in this boot and the stored record decides at the next start.
void Membership::leave_check(MonoTime now) {
    if (++leave_checks_ > k_leave_checks) {
        leave_finish(Status::StorageFailure, LM_OUTCOME_INDETERMINATE, now);
        return;
    }
    if (rec_ == nullptr && (rec_ = engine_.identity().lend_record()) == nullptr) {
        --leave_checks_; // the record memory is another module's for a moment: not an attempt
        leave_tx_wait_ = now + k_busy_retry;
        return;
    }
    if (start_flash(Step::LeaveCheck, store::RecordJob::Op::Load, store::rec::membership, 0, 0, now) != Status::Ok) {
        engine_.identity().return_record(rec_);
        leave_tx_wait_ = now + k_leave_check_gap;
        return;
    }
    leave_tx_wait_ = MonoTime::never(); // the job's completion goes on (a deadline in the past would spin the owner)
}

void Membership::leave_checked(Status s, MonoTime now) {
    if (s == Status::Ok && (rec_->state == k_membership_left || rec_->state == k_membership_revoked)) {
        leave_finish(Status::Ok, LM_OUTCOME_APPLIED, now); // the tombstone is durable
        return;
    }
    if (s == Status::Ok) {
        leave_commit(now); // the credential is still stored: the tombstone again (same floors)
        return;
    }
    engine_.identity().return_record(rec_); // unreadable now: read again later
    leave_tx_wait_ = now + k_leave_check_gap;
}

// The credential is gone (durably, or the store could not say): erase it from RAM too and end every session of the
// domain, link and end sessions alike (an end session is bound to this membership generation: a peer that still holds
// one must find it gone and make a fresh one, which shows it the generation of a later join, docs/04 §7).
void Membership::apply_left() {
    LocalIdentity &id = engine_.identity();
    DeviceId peers[link::k_max_neighbors];
    std::size_t n = 0;
    engine_.link().neighbors().for_each([&](Handle, link::Neighbor &nb) {
        if (n < link::k_max_neighbors && !nb.join_only) {
            peers[n++] = nb.device;
        }
    });
    for (std::size_t i = 0; i < n; ++i) {
        (void)engine_.link().close(peers[i]);
    }
    engine_.delivery().sessions().clear();
    engine_.delivery().invalidate_routes();
    // Fleet identity stays; the floor records what this device consumed (SEC-D8).
    id.drop_member(Floors::Entry{id.self(), leave_assignment_ + 1, leave_membership_ + 1}, revoked_);
    have_prepared_ = false;
}

void Membership::leave_finish(Status why, uint32_t outcome, MonoTime now) {
    engine_.mesh().end_drain(engine_.identity().is_member(), now);
    (void)outcome; // (the event carries `why`: a storage failure or RECOVERY_REQUIRED reads as INDETERMINATE)
    engine_.identity().return_record(rec_);
    if (hooks_.refuse_sends != nullptr) {
        // A drain that failed: the member sends again. A device that left (or whose tombstone is in doubt: RAM left) is
        // refused as a non-member from here on, whatever this flag says (FIX8-D6: never restored by a failure).
        hooks_.refuse_sends(hooks_.ctx, false);
    }
    leave_ = LeavePhase::Idle;
    leave_tx_wait_ = leave_deadline_ = MonoTime::never();
    leave_tx_inflight_ = false;
    revoked_ = false;
    req_.reason = why;
    engine_.emit_event(LM_EVENT_OPERATION, static_cast<uint32_t>(why), leave_op_, nullptr);
    engine_.emit_event(LM_EVENT_MEMBERSHIP, static_cast<uint32_t>(why), leave_op_, nullptr);
}

} // namespace lm::member
