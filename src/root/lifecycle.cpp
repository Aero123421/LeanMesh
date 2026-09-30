// Root side of the membership lifecycle after the join (docs/06 §7, docs/07 §8, docs/21): renewal of the
// members' authorisation leases. Everything here is a queued maintenance operation of the ledger: it borrows the
// ledger's shared memory (the identity's record job and the exchange's credential buffer) for one short chain of
// worker jobs and gives it back; a busy worker or control lane only postpones it.
#include <algorithm>
#include <cstring>
#include <new>

#include "core/engine.hpp"
#include "root/ledger.hpp"
#include "root/ledger_internal.hpp"
#include "security/crypto.hpp"

namespace lm::root {
namespace {

constexpr Duration k_retry = Duration::from_ms(200);

} // namespace

// ---- renewal ----
void Ledger::renew_due(const DeviceId &device, uint32_t term, uint64_t lease_ms, MonoTime now) {
    const Entry *e = find(device);
    if (!loaded_ || failed_ || retired_ || e == nullptr || e->state != EntryState::Active ||
        (!e->reserved_until.is_never() && now < e->reserved_until) || // renewed a moment ago
        engine_.identity().floors().check(device, AssignmentGen{e->assignment}, MembershipGen{e->membership}) !=
            Status::Ok) {
        return;
    }
    const uint64_t root_ms = now.to_ms(); // the root is the time base of its term
    if (term == engine_.identity().member().root_term.value() &&
        lease_ms > root_ms + static_cast<uint64_t>(k_renew_before.to_ms())) {
        return; // not due yet
    }
    renew_mask_ |= 1ULL << static_cast<std::size_t>(e - entries_.data());
    maintenance(now);
}

// Holder -2 (maintenance). The entry record holds the credential the join issued (or provisioning wrote); the
// renewal repeats every field of it but the lease, the term and the request id.
void Ledger::start_renew(MonoTime now) {
    while (renew_mask_ != 0) {
        const auto slot = static_cast<std::size_t>(__builtin_ctzll(renew_mask_));
        renew_mask_ &= renew_mask_ - 1U;
        if (entries_[slot].state != EntryState::Active) {
            continue;
        }
        rec_->arm(store::RecordJob::Op::Load, static_cast<uint16_t>(k_rec_ledger_base + slot));
        job_slot_index_ = slot;
        // The renewal leaves by the one control lane: while it carries another object, loading and signing now would
        // only be done again (ARCH2-D1: after a root restart every member is renewed, one after the other).
        if (!engine_.delivery().control_lane_free() ||
            submit(Step::RenewLoad, JobClass::Flash, &store::record_job, rec_, -2) != Status::Ok) {
            renew_mask_ |= 1ULL << slot;
            ++stats_.renew_deferred;
            maint_retry_ = now + k_retry;
            release(-2);
        }
        return;
    }
    release(-2);
}

void Ledger::renew_step(Step step, Status s, MonoTime now) {
    const std::size_t slot = job_slot_index_;
    Entry &e = entries_[slot];
    if (step == Step::RenewLoad) {
        Entry stored;
        ByteView cose;
        member::Envelope env;
        ByteView data;
        member::MemberCredential mc;
        if (s != Status::Ok || detail::decode_entry(*rec_, stored, cose) != Status::Ok ||
            stored.state != EntryState::Active || stored.device != e.device || stored.assignment != e.assignment ||
            stored.membership != e.membership ||
            member::peek_signed(cose, member::k_type_member_credential, env, data) != Status::Ok ||
            member::decode_member_credential(data, mc) != Status::Ok || mc.device != e.device) {
            release(-2); // the record is the truth: nothing to renew from (the member asks again at its next READY)
            return;
        }
        const member::LocalIdentity &id = engine_.identity();
        SignArgs &a = sargs_;
        a = SignArgs{};
        a.key = id.key();
        a.mc = mc;
        a.mc.root_term = id.member().root_term;
        a.mc.lease_expires_root_ms = now.to_ms() + static_cast<uint64_t>(k_member_lease.to_ms());
        a.env.type = member::k_type_member_credential;
        engine_.random(MutByteView{a.env.request.bytes});
        a.env.domain = id.delegation().domain;
        a.env.issuer = id.self();
        a.env.revision = mc.membership.value();
        a.out = scratch_.from(detail::k_cose_off);
        if (submit(Step::RenewSign, JobClass::PublicKey, &sign_job, this, -2) != Status::Ok) {
            renew_mask_ |= 1ULL << slot; // the one public-key slot is busy (a handshake): later
            ++stats_.renew_deferred;
            maint_retry_ = now + k_retry;
            release(-2);
        }
        return;
    }
    // RenewSign: the signed credential goes to the member as one control object over its end session.
    const delivery::ControlSendRequest cr{e.device, engine_.identity().member().root_term.value(), now.to_ms() + 30000};
    const ByteView cose{scratch_.data() + detail::k_cose_off, sargs_.len};
    if (s == Status::Ok && e.state == EntryState::Active && sargs_.len != 0 &&
        engine_.delivery().send_control(cr, cose, now).status == Status::Ok) {
        ++stats_.renewals;
        e.reserved_until = now + k_renew_gap; // a READY racing the delivery does not sign again
    } else if (s == Status::Ok && e.state == EntryState::Active) {
        renew_mask_ |= 1ULL << slot; // the control lane is busy (a snapshot page, another renewal): later
        ++stats_.renew_deferred;
        maint_retry_ = now + k_retry;
    }
    release(-2);
}

// ---- lifecycle installs ----
Status Ledger::install_lifecycle(uint8_t type, ByteView cose, MonoTime /*now*/, uint64_t &operation) {
    LM_TRY(begin_install(cose, detail::k_cose_off, lc_.active || exp_active_));
    lc_ = Lifecycle{};
    lc_.active = true;
    lc_.type = type;
    lc_.len = cose.size();
    lc_.op = member::k_op_tag | ++op_counter_;
    if (submit(Step::LcVerify, JobClass::PublicKey, &lc_verify_job, this, -2) != Status::Ok) {
        lc_.active = false;
        release(-2);
        return Status::Busy;
    }
    operation = lc_.op;
    return Status::Ok;
}

// Worker. Who may sign what: revocations the fleet or this root (revoke permission); a transfer ticket and a
// handover only the fleet; a commissioning window the fleet or this root (approve permission). Every object names
// this root's domain.
Status Ledger::lc_verify_job(port::JobEnv & /*env*/, void *arg) {
    auto &l = *static_cast<Ledger *>(arg);
    Lifecycle &c = l.lc_;
    const VerifyArgs &v = l.vargs_;
    const ByteView cose{l.scratch_.data(), c.len};
    member::Envelope env;
    ByteView data;
    switch (c.type) {
    case member::k_type_revoke:
        return member::verify_revoke(v.trust, &v.delegation, cose, *new (&c.obj.revoke) member::RevokeObject{});
    case member::k_type_assignment_ticket: {
        member::AssignmentTicket &t = *new (&c.obj.ticket) member::AssignmentTicket{};
        LM_TRY(member::open_signed(cose, v.trust.key, member::k_type_assignment_ticket, env, data));
        LM_TRY(member::decode_assignment_ticket(data, t));
        return t.fleet == v.trust.fleet && t.source == v.delegation.domain ? Status::Ok : Status::NetworkMismatch;
    }
    case member::k_type_commissioning_window:
        LM_TRY(member::open_authority(v.trust, &v.delegation, member::k_perm_approve, cose, c.type, env, data));
        LM_TRY(member::decode_window(data, *new (&c.obj.window) member::CommissioningWindow{}));
        return env.domain == v.delegation.domain ? Status::Ok : Status::NetworkMismatch;
    case member::k_type_root_handover:
        LM_TRY(member::open_signed(cose, v.trust.key, member::k_type_root_handover, env, data));
        LM_TRY(member::decode_handover(data, *new (&c.obj.handover) member::RootHandover{}));
        return env.domain == v.delegation.domain ? Status::Ok : Status::NetworkMismatch;
    default:
        return Status::Unsupported;
    }
}

void Ledger::lc_finish(Status s, MonoTime /*now*/) {
    lc_.active = false;
    release(-2);
    engine_.emit_event(LM_EVENT_OPERATION, static_cast<uint32_t>(s), lc_.op, nullptr);
}

void Ledger::lc_step(Step step, Status s, MonoTime now) {
    if (!lc_.active) {
        return;
    }
    if (s != Status::Ok) {
        // Before a commit nothing changed (the object was refused); after one the durable state may or may not
        // have moved (floors raised in RAM, an entry commit unknown): RECOVERY_REQUIRED, never "rejected".
        lc_finish(step == Step::LcVerify ? s : Status::RecoveryRequired, now);
        return;
    }
    switch (step) {
    case Step::LcVerify:
        lc_verified(now);
        return;
    case Step::LcFloors:
        lc_retire_entry(now);
        return;
    case Step::LcEntry: {
        Entry e = job_entry_;
        const DeviceId device = e.device;
        const ShortAddr addr = e.address;
        set_entry(lc_.slot, e);
        if (lc_.type == member::k_type_revoke) {
            ++stats_.revoked;
            // The signed notice goes to the device over its end session first; its sessions end when that had its
            // chance (network refusal is already durable: the ledger admits and renews it no more).
            const delivery::ControlSendRequest cr{device, engine_.identity().member().root_term.value(),
                                                  now.to_ms() + 10000};
            if (!notice_until_.is_never()) {
                forget_member(notice_device_, notice_addr_); // an earlier notice's time is over now
            }
            if (engine_.delivery().has_session(device, now) &&
                engine_.delivery().send_control(cr, ByteView{scratch_.data(), lc_.len}, now).status == Status::Ok) {
                notice_device_ = device;
                notice_addr_ = addr;
                notice_until_ = now + Duration::from_s(10);
            } else {
                notice_until_ = MonoTime::never();
                forget_member(device, addr);
            }
            engine_.emit_event(LM_EVENT_MEMBERSHIP, LM_MEMBER_REVOKED, 0, &device);
        } else {
            ++stats_.reconciled;
            forget_member(device, addr);
            engine_.emit_event(LM_EVENT_MEMBERSHIP, LM_UNASSIGNED, 0, &device);
        }
        lc_finish(Status::Ok, now);
        return;
    }
    case Step::LcRetire:
        retired_ = true;
        stop_admitting(now);
        lc_finish(Status::Ok, now);
        return;
    case Step::LcWindow:
        window_rec_id_ = window_.id;
        window_rec_used_ = 0;
        window_used_ = 0;
        window_set_ = true;
        lc_finish(Status::Ok, now);
        return;
    default:
        return;
    }
}

void Ledger::lc_verified(MonoTime now) {
    const member::LocalIdentity &id = engine_.identity();
    member::Floors &floors = engine_.identity().floors();
    uint64_t af = 0;
    uint64_t mf = 0;
    DeviceId device;
    switch (lc_.type) {
    case member::k_type_revoke:
        device = lc_.obj.revoke.device;
        af = lc_.obj.revoke.assignment_floor;
        mf = lc_.obj.revoke.membership_floor;
        lc_.to = EntryState::Blocked;
        break;
    case member::k_type_assignment_ticket: { // docs/07 §8: A learns that its member moved away with this grant
        const Entry *e = find(lc_.obj.ticket.device);
        if (e == nullptr || e->assignment != lc_.obj.ticket.expected_old || lc_.obj.ticket.new_generation <= e->assignment) {
            lc_finish(e == nullptr ? Status::NotFound : Status::Conflict, now);
            return;
        }
        device = e->device;
        af = e->assignment + 1;
        mf = e->membership + 1;
        lc_.to = EntryState::Left;
        break;
    }
    case member::k_type_commissioning_window: {
        const member::CommissioningWindow &w = lc_.obj.window;
        const bool ok = w.term == id.member().root_term && w.not_before_ms < w.expires_ms &&
                        w.expires_ms - w.not_before_ms <= 15ULL * 60 * 1000 && now.to_ms() < w.expires_ms;
        if (!ok || w.expected_revision != man_.expected_revision) {
            lc_finish(ok ? Status::Conflict : Status::InvalidArgument, now); // another expected set / term / span
            return;
        }
        window_ = w;
        if (w.id == window_rec_id_) { // the same window again (after a restart): its count goes on
            window_set_ = true;
            window_used_ = window_rec_used_;
            lc_finish(Status::Ok, now);
            return;
        }
        if (commit_window(Step::LcWindow, 0, -2) != Status::Ok) {
            lc_finish(Status::Busy, now);
        }
        return;
    }
    case member::k_type_root_handover: {
        const member::RootHandover &h = lc_.obj.handover;
        if (h.old_root == id.self() && h.old_generation == id.delegation().generation &&
            h.new_generation > h.old_generation) {
            rec_->arm(store::RecordJob::Op::Commit, store::rec::root_handover, 0, lc_.len); // it retires, durably
            std::memcpy(rec_->payload.data(), scratch_.data(), lc_.len);
            if (submit(Step::LcRetire, JobClass::Flash, &store::record_job, rec_, -2) != Status::Ok) {
                lc_finish(Status::Busy, now);
            }
            return;
        }
        Sha256Digest dh{};
        const bool ours = h.new_root == id.self() && sec::sha256(id.delegation_cose(), dh) == Status::Ok &&
                          dh == h.new_delegation_hash && h.new_generation == id.delegation().generation &&
                          !(id.member().root_term < h.new_term); // its first term or a later boot's (ARCH2-D1)
        lc_finish(ours ? Status::Ok : Status::NetworkMismatch, now); // the new root: it knows itself already
        return;
    }
    default:
        lc_finish(Status::Unsupported, now);
        return;
    }
    // Revocation / reconciliation: the floors first (fail closed in RAM at once, then durable), then the entry.
    if (floors.raise(device, af, mf) != Status::Ok) {
        lc_finish(Status::NoCapacity, now); // the floor table is full: nothing changed
        return;
    }
    if (commit_floors(Step::LcFloors) != Status::Ok) {
        lc_finish(Status::RecoveryRequired, now); // RAM refuses already; the commit did not happen
    }
}

// The entry of a revoked device becomes Blocked, that of a device that moved away Left (with what it consumed), when
// the ledger lists it below the new floors; a revocation of generations it no longer holds changes nothing more.
void Ledger::lc_retire_entry(MonoTime now) {
    const DeviceId &device = lc_.type == member::k_type_revoke ? lc_.obj.revoke.device : lc_.obj.ticket.device;
    const Entry *e = find(device);
    if (e == nullptr || e->state == lc_.to || // (the same object again: done already)
        engine_.identity().floors().check(device, AssignmentGen{e->assignment}, MembershipGen{e->membership}) ==
            Status::Ok) {
        lc_finish(Status::Ok, now);
        return;
    }
    lc_.slot = static_cast<std::size_t>(e - entries_.data());
    job_entry_ = *e;
    job_entry_.consumed = std::max(e->consumed, e->assignment);
    job_entry_.reserved_until = MonoTime::never();
    ByteView cose; // the credential stays in the record (a repeated join request is answered from it)
    if (commit_entry(Step::LcEntry, lc_.slot, lc_.to, false, cose, -2) != Status::Ok) {
        lc_finish(Status::RecoveryRequired, now);
    }
}

// ---- commissioning window, retirement ----
bool Ledger::window_open(MonoTime now) const {
    const uint64_t ms = now.to_ms();
    return window_set_ && window_.term == engine_.identity().member().root_term && ms >= window_.not_before_ms &&
           ms < window_.expires_ms && window_used_ < window_.max_new_members &&
           window_.expected_revision == man_.expected_revision;
}

// A retired root ends every session it holds and takes no join: the new root is the domain's root now.
void Ledger::stop_admitting(MonoTime /*now*/) {
    for (Txn &t : txns_) {
        end_txn(t);
    }
    for (const Entry &e : entries_) {
        if (e.state == EntryState::Active) {
            forget_member(e.device, e.address);
        }
    }
}

} // namespace lm::root
