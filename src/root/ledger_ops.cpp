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
namespace {

constexpr Duration k_busy_retry = Duration::from_ms(50);

} // namespace

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
        leave_slot_ = slot;
        leave_pending_ = true;
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
        loaded.request != confirm_.request || sec::sha256(cose, h) != Status::Ok || h != confirm_.hash) {
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
    job_txn_ = -2;
    job_slot_index_ = confirm_.slot;
    if (submit(Step::ConfirmCommit, JobClass::Flash, &store::record_job, rec_) != Status::Ok) {
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
    link::SealedFrame f;
    if (st == Status::Ok) {
        st = engine_.link().seal(confirm_.device, wire::FrameKind::Control, ByteView{obj.data(), plen + dlen}, f, now);
    }
    if (st == Status::Ok) {
        (void)engine_.transmit(n->mac, f.view(), k_tag_offer, now); // best effort: the device repeats
    }
}

// Left is durable: the entry stops admitting the device, its sessions end and the revocation floors
// remember which generations it consumed (a left device's old credential cannot come back, R09).
void Ledger::leave_committed(Status s, MonoTime now) {
    (void)now;
    if (s != Status::Ok) { // the commit's result is unknown: RAM keeps Active, flash decides at boot
        release(-2);
        return;
    }
    Entry &e = entries_[job_slot_index_];
    e.state = EntryState::Left;
    e.confirmed = false;
    ++stats_.left;
    const DeviceId device = e.device;
    (void)engine_.link().close(device);
    engine_.emit_event(LM_EVENT_MEMBERSHIP, LM_UNASSIGNED, 0, &device);
    member::Floors &floors = engine_.identity().floors();
    std::size_t len = 0;
    if (floors.raise(device, e.assignment + 1, e.membership + 1) != Status::Ok ||
        member::encode_floors(floors, MutByteView{rec_->payload}, len) != Status::Ok) {
        release(-2); // floor table full: the entry stays Left and its slot is not reused (pick_slot)
        return;
    }
    rec_->op = store::RecordJob::Op::Commit;
    rec_->id = store::rec::revocation_floors;
    rec_->state = 0;
    rec_->payload_len = static_cast<uint32_t>(len);
    job_txn_ = -2;
    if (submit(Step::CommitFloors, JobClass::Flash, &store::record_job, rec_) != Status::Ok) {
        release(-2);
    }
}

// ---- expected entries (docs/07 §2, docs/21 §4) ----
Status Ledger::install_expected(ByteView cose, MonoTime /*now*/, uint64_t &operation) {
    if (failed_) {
        return Status::RecoveryRequired;
    }
    if (!loaded_ || exp_active_ || holder_ != -1 || job_in_flight_) {
        return Status::Busy;
    }
    if (cose.empty() || cose.size() > 1024) {
        return Status::PayloadTooLarge;
    }
    if (!acquire(-2)) {
        return Status::Busy;
    }
    std::memcpy(scratch_.data(), cose.data(), cose.size());
    const member::LocalIdentity &id = engine_.identity();
    vargs_.trust = id.trust();
    vargs_.delegation = id.delegation();
    vargs_.ticket_cose = ByteView{scratch_.data(), cose.size()};
    job_txn_ = -2;
    exp_active_ = true;
    exp_op_ = member::k_op_tag | ++op_counter_;
    if (submit(Step::VerifyExpected, JobClass::PublicKey, &verify_expected_job, this) != Status::Ok) {
        exp_active_ = false;
        release(-2);
        return Status::Busy;
    }
    operation = exp_op_;
    return Status::Ok;
}

// Worker. The page is signed by the fleet or by this root's delegation (approve permission).
Status Ledger::verify_expected_job(port::JobEnv & /*env*/, void *arg) {
    auto &l = *static_cast<Ledger *>(arg);
    LM_TRY(member::check_expected_set(l.vargs_.trust, &l.vargs_.delegation, l.vargs_.ticket_cose, l.exp_));
    member::Envelope env;
    ByteView data;
    LM_TRY(member::peek_signed(l.vargs_.ticket_cose, member::k_type_expected_set, env, data));
    if (env.domain != l.vargs_.delegation.domain && !env.domain.is_zero()) {
        return Status::NetworkMismatch;
    }
    l.exp_revision_ = env.revision;
    return Status::Ok;
}

void Ledger::expected_finish(Status s) {
    exp_active_ = false;
    release(-2);
    engine_.emit_event(LM_EVENT_OPERATION, static_cast<uint32_t>(s), exp_op_, nullptr);
}

void Ledger::expected_step_done(Step step, Status s, MonoTime now) {
    if (!exp_active_) {
        return;
    }
    if (s != Status::Ok) {
        expected_finish(s);
        return;
    }
    if (step == Step::VerifyExpected) {
        if (exp_revision_ < expected_revision_) {
            expected_finish(Status::Conflict); // an older revision never replaces a newer one
            return;
        }
        if (exp_revision_ > expected_revision_) {
            Writer w{MutByteView{rec_->payload}};
            w.u64be(exp_revision_);
            rec_->op = store::RecordJob::Op::Commit;
            rec_->id = store::rec::root_ledger;
            rec_->state = 0;
            rec_->payload_len = static_cast<uint32_t>(w.size());
            job_txn_ = -2;
            if (submit(Step::CommitExpectedHeader, JobClass::Flash, &store::record_job, rec_) != Status::Ok) {
                expected_finish(Status::Busy);
            }
            return;
        }
    } else if (step == Step::CommitExpectedHeader) {
        expected_revision_ = exp_revision_;
    } else { // CommitExpectedEntry
        entries_[job_slot_index_] = job_entry_;
        ++exp_next_;
    }
    if (step == Step::VerifyExpected || step == Step::CommitExpectedHeader) {
        exp_next_ = 0;
    }
    expected_next(now);
}

// One entry per commit. An entry that is Prepared or Active is never demoted by an expected page.
void Ledger::expected_next(MonoTime /*now*/) {
    while (exp_next_ < exp_.count) {
        const member::ExpectedEntry &x = exp_.entries[exp_next_];
        std::size_t slot = 0;
        const Entry *old = find(x.device);
        if (pick_slot(x.device, slot) != Status::Ok) { // the same slot policy as a join: existing, free, or a
            expected_finish(Status::NoCapacity);        // departed device whose credential is below its floor
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
        job_entry_.device = x.device;
        job_entry_.hash = x.grant_hash;
        job_entry_.assignment = x.assignment;
        job_entry_.request = RequestId{};
        job_entry_.reserved_until = MonoTime::never();
        job_txn_ = -2;
        if (commit_entry(Step::CommitExpectedEntry, slot, x.allowed ? EntryState::Expected : EntryState::Blocked,
                         false, ByteView{}, -2) != Status::Ok) {
            expected_finish(Status::Busy);
        }
        return;
    }
    expected_finish(Status::Ok);
}

} // namespace lm::root
