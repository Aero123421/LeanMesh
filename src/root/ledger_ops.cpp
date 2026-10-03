// Root-side commands of the ledger: leave notices, the expected entries (signed ExpectedSet pages).
// The join transaction itself is in ledger.cpp.
#include <algorithm>
#include <cstring>

#include "core/codec.hpp"
#include "core/engine.hpp"
#include "root/ledger.hpp"
#include "root/ledger_internal.hpp"
#include "security/crypto.hpp"

namespace lm::root {

// A LeaveRequest (type 27) arrives over an ordinary link session, so its origin is the authenticated
// peer: a device can only leave itself. Anything else is not ours (false) or ignored (true).
bool Ledger::link_control(const link::RxInfo &info, ByteView plain, MonoTime now) {
    member::JoinObjectHeader h;
    ByteView data;
    if (member::join_object_parse(plain, h, data) != Status::Ok ||
        (h.type != member::k_type_leave_request && h.type != member::k_type_join_active)) {
        return false;
    }
    if (info.duplicate || !loaded_ || failed_) {
        return true;
    }
    Entry *e = find_mut(info.peer);
    if (e == nullptr || e->state != EntryState::Active) {
        return true;
    }
    const std::size_t slot = static_cast<std::size_t>(e - entries_.data());
    if (h.type == member::k_type_leave_request) {
        member::LeaveData d;
        if (member::decode_leave(data, d) != Status::Ok || d.device != info.peer) {
            return true; // a device can only leave itself
        }
        leave_mask_ |= 1ULL << slot; // FIX8-D3: each member's own bit (one pending leave overwrote the other)
        maintenance(now);
        return true;
    }
    // JoinActive from an authenticated ACTIVE member: the device repeats its evidence because the
    // acknowledgement of the join session never arrived (JOIN_ACTIVE or our echo was lost).
    member::JoinAckData a;
    if (h.request != e->request || member::decode_join_ack(data, a) != Status::Ok || confirm_pending_) {
        return true;
    }
    confirm_.device = info.peer;
    confirm_.request = h.request;
    confirm_.hash = a.prepare_hash;
    confirm_.value = a.value;
    confirm_.slot = slot;
    confirm_pending_ = true;
    maintenance(now);
    return true;
}

// The flash record is the truth: it must hold this request and exactly this credential hash.
void Ledger::confirm_loaded(Status s, MonoTime now) {
    Entry loaded;
    ByteView cose;
    Sha256Digest h{};
    if (s != Status::Ok || detail::decode_entry(*rec_, loaded, cose) != Status::Ok || loaded.state != EntryState::Active ||
        loaded.request != confirm_.request || member::withheld_hash(cose, h) != Status::Ok || h != confirm_.hash) {
        confirm_pending_ = false;
        release(-2);
        return;
    }
    if (loaded.confirmed) {
        confirm_done(now);
        return;
    }
    rec_->payload[0] = 1; // the confirmed flag; everything else of the record stays byte for byte
    rec_->op = store::RecordJob::Op::Commit;
    job_entry_ = entries_[confirm_.slot];
    job_entry_.confirmed = true;
    job_slot_index_ = confirm_.slot;
    if (submit(Step::ConfirmCommit, JobClass::Flash, &store::record_job, rec_, -2) != Status::Ok) {
        confirm_pending_ = false;
        release(-2);
    }
}

void Ledger::confirm_done(MonoTime now) {
    Entry &e = entries_[confirm_.slot];
    if (!e.confirmed) {
        e.confirmed = true;
        ++stats_.confirmed;
        engine_.emit_event(LM_EVENT_MEMBERSHIP, LM_ACTIVE, 0, &confirm_.device);
    }
    send_echo(now);
    confirm_pending_ = false;
    release(-2);
}

// The final acknowledgement repeats the device's own evidence, over the same link session.
void Ledger::send_echo(MonoTime now) {
    const member::LocalIdentity &id = engine_.identity();
    const link::Neighbor *n = engine_.link().neighbors().find_device(confirm_.device);
    if (n == nullptr) {
        return;
    }
    member::JoinObjectHeader h;
    h.type = member::k_type_join_active;
    h.request = confirm_.request;
    h.domain = id.delegation().domain;
    h.issuer = id.self();
    member::JoinAckData a;
    a.prepare_hash = confirm_.hash;
    a.value = confirm_.value;
    std::array<uint8_t, 192> obj{};
    std::size_t plen = 0;
    std::size_t dlen = 0;
    Status st = member::join_object_begin(h, MutByteView{obj}, plen);
    if (st == Status::Ok) {
        st = member::encode_join_ack(a, MutByteView{obj}.from(plen), dlen);
    }
    if (st == Status::Ok) { // best effort: the device repeats
        (void)engine_.link().send_sealed(confirm_.device, n->mac, wire::FrameKind::Control,
                                         ByteView{obj.data(), plen + dlen}, k_tag_offer, now);
    }
}

// Left is durable: the entry stops admitting the device, its sessions end and the revocation floors
// remember which generations it consumed (a left device's old credential cannot come back, R09).
void Ledger::leave_committed(Status s, MonoTime now) {
    entry_written(job_slot_index_, s == Status::Ok);
    if (s != Status::Ok) { // the commit's result is unknown: RAM keeps Active, flash decides at boot
        release(-2);
        return;
    }
    Entry &e = entries_[job_slot_index_];
    e.state = EntryState::Left;
    e.confirmed = false;
    ++stats_.left;
    const DeviceId device = e.device;
    forget_member(device, e.address);
    engine_.delivery().end_sends_to(device, now, Status::NotFound); // #16: no send to a member that left stays open
    engine_.emit_event(LM_EVENT_MEMBERSHIP, LM_UNASSIGNED, 0, &device);
    release(-2);
    cover(job_slot_index_, now);
}

// FIX8-D1: a departed entry (Left, Blocked) is the floor record of its device. A copy in the table, when there is room,
// is what lets its slot be given to another device later (reusable(): only once that copy is durable); a full table
// costs no revocation capacity, only this slot's reuse (a redundant copy even gives way to an unlisted device's floor).
void Ledger::cover(std::size_t slot, MonoTime now) {
    const Entry &e = entries_[slot];
    if ((e.state == EntryState::Left || e.state == EntryState::Blocked) &&
        engine_.identity().floors().raise(e.device, std::max(e.assignment, e.consumed) + 1, e.membership + 1) ==
            Status::Ok) {
        floors_dirty_ = true;
        recon_fails_ = 0;
        maint_retry_ = earliest(maint_retry_, now);
    }
}

// The identity's floor table into the revocation_floors record, committed by one Flash job (holder -2).
Status Ledger::commit_floors(Step step) {
    std::size_t len = 0;
    LM_TRY(member::encode_floors(engine_.identity().floors(), MutByteView{rec_->payload}, len));
    rec_->arm(store::RecordJob::Op::Commit, store::rec::revocation_floors, 0, len);
    return submit(step, JobClass::Flash, &store::record_job, rec_, -2);
}

// Left is durable: nothing of the member may keep serving it. Its link session and its end session end now,
// the approved tree forgets its address (its children re-register; a lease would only lapse it within 180 s) and
// so do the routes the root learned through that address.
void Ledger::forget_member(const DeviceId &device, ShortAddr address) {
    (void)engine_.link().close(device);
    if (delivery::EndSession *s = engine_.delivery().sessions().find_peer(device)) {
        engine_.delivery().sessions().remove(*s);
    }
    engine_.routes().forget(address);
    engine_.delivery().invalidate_addr(address);
}

// ---- [FIX8-D10] group registry and [FIX8-D12] join-mode policy: one record each, committed by maintenance ----
void Ledger::want_groups_commit(MonoTime now) {
    groups_pending_ = true;
    maintenance(now);
}

void Ledger::groups_done(Status s) { engine_.groups().committed(s); }

Status Ledger::set_policy_mode(JoinMode m, uint64_t op, MonoTime now) {
    if (failed_ || policy_doubt_) {
        return Status::RecoveryRequired;
    }
    if (!loaded_ || policy_pending_ || (step_ == Step::CommitPolicy && job_in_flight_)) {
        return Status::Busy;
    }
    if (policy_count_ >= k_u63_max) {
        return Status::RecoveryRequired; // (the revision would wrap)
    }
    policy_stage_ = m;
    policy_op_ = op;
    policy_pending_ = true;
    maintenance(now);
    return Status::Ok;
}

// The committed mode applies from now on; a commit whose result is unknown leaves the root CLOSED (the stricter state)
// until the stored record is read again at the next start (lm_policy_set answers RECOVERY_REQUIRED meanwhile).
void Ledger::policy_done(Status s) {
    if (s == Status::Ok) {
        mode_ = policy_stage_;
        ++policy_count_;
    } else {
        mode_ = JoinMode::Closed;
        policy_doubt_ = true;
    }
    engine_.emit_event(LM_EVENT_OPERATION, s == Status::Ok ? 0U : static_cast<uint32_t>(Status::RecoveryRequired),
                       policy_op_, nullptr);
}

// ---- expected entries (docs/07 §2, docs/21 §4) ----
Status Ledger::begin_install(ByteView cose, std::size_t max_bytes, bool other) {
    if (failed_) {
        return Status::RecoveryRequired;
    }
    if (!loaded_ || other || holder_ != -1 || job_in_flight_) {
        return Status::Busy;
    }
    if (cose.empty() || cose.size() > max_bytes) {
        return Status::PayloadTooLarge;
    }
    if (!acquire(-2)) {
        return Status::Busy;
    }
    std::memcpy(scratch_.data(), cose.data(), cose.size());
    vargs_.trust = engine_.identity().trust();
    vargs_.delegation = engine_.identity().delegation();
    return Status::Ok;
}

Status Ledger::install_expected(ByteView cose, MonoTime /*now*/, uint64_t &operation) {
    LM_TRY(begin_install(cose, 1024, exp_active_));
    vargs_.ticket_cose = ByteView{scratch_.data(), cose.size()};
    exp_active_ = true;
    exp_op_ = engine_.next_control_op(); // FIX9-D5: one namespace with the group sets
    if (submit(Step::VerifyExpected, JobClass::PublicKey, &verify_expected_job, this, -2) != Status::Ok) {
        exp_active_ = false;
        release(-2);
        return Status::Busy;
    }
    operation = exp_op_;
    return Status::Ok;
}

// Worker. The page is signed by the fleet or by this root's delegation (approve permission), lies inside its own
// set (page < pages) and is identified by the digest of its data (SEC-D7).
Status Ledger::verify_expected_job(port::JobEnv & /*env*/, void *arg) {
    auto &l = *static_cast<Ledger *>(arg);
    LM_TRY(member::check_expected_set(l.vargs_.trust, &l.vargs_.delegation, l.vargs_.ticket_cose, l.exp_));
    member::Envelope env;
    ByteView data;
    LM_TRY(member::peek_signed(l.vargs_.ticket_cose, member::k_type_expected_set, env, data));
    if (env.domain != l.vargs_.delegation.domain && !env.domain.is_zero()) {
        return Status::NetworkMismatch;
    }
    if (l.exp_.page >= l.exp_.pages) {
        return Status::BadFrame; // a page outside the set it names
    }
    Sha256Digest h{};
    LM_TRY(sec::sha256(data, h));
    std::copy_n(h.begin(), l.exp_digest_.size(), l.exp_digest_.begin());
    l.exp_revision_ = env.revision;
    return Status::Ok;
}

void Ledger::expected_finish(Status s) {
    exp_active_ = false;
    release(-2);
    engine_.emit_event(LM_EVENT_OPERATION, static_cast<uint32_t>(s), exp_op_, nullptr);
}

// SEC-D7: a revision is one signed set. A page of an older revision, of this revision with another set hash or
// page count, or a page number already taken with other content is CONFLICT; the same page again is the same
// answer (applied: Ok at once; pending: applied again, which completes it). A newer revision starts a new set.
// Ok: the page is to be applied (exp_man_ holds the manifest that marks it pending), unless `applied`.
Status Ledger::expected_admit(bool &applied) {
    const uint16_t bit = static_cast<uint16_t>(1U << exp_.page);
    applied = false;
    exp_man_ = man_;
    if (exp_revision_ < man_.expected_revision) {
        return Status::Conflict;
    }
    if (exp_revision_ == man_.expected_revision && man_.pages != 0) {
        if (exp_.pages != man_.pages || exp_.set_hash != man_.set_hash) {
            return Status::Conflict;
        }
        const bool known = ((man_.received | man_.pending) & bit) != 0;
        if (known && man_.digests[exp_.page] != exp_digest_) {
            return Status::Conflict;
        }
        if ((man_.received & bit) != 0) {
            applied = true; // nothing to do: this very page is applied
            return Status::Ok;
        }
    } else {
        exp_man_.expected_revision = exp_revision_;
        exp_man_.set_hash = exp_.set_hash;
        exp_man_.pages = exp_.pages;
        exp_man_.received = exp_man_.pending = 0;
        exp_man_.digests = {};
    }
    if (!expected_room()) {
        return Status::NoCapacity; // refused before anything changes
    }
    exp_man_.pending |= bit;
    exp_man_.digests[exp_.page] = exp_digest_;
    return Status::Ok;
}

// Room for every device of the page that needs a slot of its own, counted before the first entry changes.
bool Ledger::expected_room() const {
    std::size_t need = 0;
    for (std::size_t i = 0; i < exp_.count; ++i) {
        bool seen = find(exp_.entries[i].device) != nullptr;
        for (std::size_t j = 0; j < i && !seen; ++j) {
            seen = exp_.entries[j].device == exp_.entries[i].device;
        }
        need += seen ? 0 : 1;
    }
    std::size_t room = 0;
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        room += entries_[i].state == EntryState::Free || reusable(i) ? 1 : 0;
    }
    return room >= need;
}

void Ledger::expected_step_done(Step step, Status s, MonoTime now) {
    if (step == Step::CommitExpectedEntry) {
        entry_written(job_slot_index_, s == Status::Ok); // (also after the install ended: RAM did not take it then)
    }
    if (!exp_active_) {
        return;
    }
    if (s != Status::Ok) {
        if (step == Step::CommitExpectedHeader || step == Step::CommitExpectedDone) {
            man_dirty_ = true; // the manifest carried the used bits too: written again with the next change
        }
        if (step == Step::CommitExpectedHeader) {
            expected_finish(s); // no entry was touched
            return;
        }
        // An entry may have changed already: authorisation moved and the page is pending. The same page again
        // completes it (SEC-D7); an ordinary refusal would hide the change.
        expected_finish(Status::RecoveryRequired);
        return;
    }
    switch (step) {
    case Step::VerifyExpected: {
        bool applied = false;
        const Status a = expected_admit(applied);
        if (a != Status::Ok || applied) {
            expected_finish(a);
            return;
        }
        exp_man_.used = man_.used;
        if (commit_manifest(exp_man_, Step::CommitExpectedHeader) != Status::Ok) {
            expected_finish(Status::Busy);
        }
        return;
    }
    case Step::CommitExpectedHeader:
        man_ = exp_man_; // the page is pending durably: from here on a failure is RECOVERY_REQUIRED
        exp_next_ = 0;
        break;
    case Step::CommitExpectedEntry:
        set_entry(job_slot_index_, job_entry_);
        mark_used(job_slot_index_);
        ++exp_next_;
        break;
    case Step::CommitExpectedDone:
        man_ = exp_man_;
        expected_finish(Status::Ok);
        return;
    default:
        return;
    }
    expected_next(now);
}

// One entry per commit. An entry that is Prepared or Active is never demoted by an expected page. After the last
// entry the page is marked received.
void Ledger::expected_next(MonoTime /*now*/) {
    while (exp_next_ < exp_.count) {
        const member::ExpectedEntry &x = exp_.entries[exp_next_];
        std::size_t slot = 0;
        const Entry *old = find(x.device);
        if (pick_slot(x.device, slot) != Status::Ok) { // counted before the page started (expected_room): a
            expected_finish(Status::RecoveryRequired);  // shortage here means the ledger changed under it
            return;
        }
        if (old != nullptr) {
            slot = static_cast<std::size_t>(old - entries_.data());
        }
        if (old != nullptr && (old->state == EntryState::Prepared || old->state == EntryState::Active)) {
            ++exp_next_;
            continue;
        }
        job_entry_ = old != nullptr ? *old : Entry{};
        if (old == nullptr) { // FIX8-D4: a device the ledger lists again starts from its own floor (the entry keeps it)
            const member::Floors::Entry f = engine_.identity().floors().floor_of(x.device);
            job_entry_.consumed = f.assignment > 0 ? f.assignment - 1 : 0;
            job_entry_.membership = f.membership > 0 ? f.membership - 1 : 0;
        }
        job_entry_.device = x.device;
        job_entry_.hash = x.grant_hash;
        job_entry_.assignment = x.assignment;
        job_entry_.request = RequestId{};
        job_entry_.reserved_until = MonoTime::never();
        if (commit_entry(Step::CommitExpectedEntry, slot, x.allowed ? EntryState::Expected : EntryState::Blocked,
                         false, ByteView{}, -2) != Status::Ok) {
            expected_finish(Status::RecoveryRequired); // the page is pending: the same page completes it
        }
        return;
    }
    const uint16_t bit = static_cast<uint16_t>(1U << exp_.page);
    exp_man_ = man_;
    exp_man_.received |= bit;
    exp_man_.pending &= static_cast<uint16_t>(~bit);
    if (commit_manifest(exp_man_, Step::CommitExpectedDone) != Status::Ok) {
        expected_finish(Status::RecoveryRequired);
    }
}

} // namespace lm::root
