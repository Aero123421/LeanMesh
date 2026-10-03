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
    const Entry *e = authorized(device); // ACTIVE and above every floor (FIX5-D2)
    if (!loaded_ || failed_ || retired_ || e == nullptr ||
        (!e->reserved_until.is_never() && now < e->reserved_until)) { // renewed a moment ago
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
        if (retired_ || !authorizes(entries_[slot])) {
            continue; // FIX5-D2: revoked (or this root retired) since the renewal was asked for
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
    const bool still = !retired_ && authorizes(e); // FIX5-D2: not revoked (floors) while the worker signed
    if (s == Status::Ok && still && sargs_.len != 0 && engine_.delivery().send_control(cr, cose, now).status == Status::Ok) {
        ++stats_.renewals;
        e.reserved_until = now + k_renew_gap; // a READY racing the delivery does not sign again
    } else if (s == Status::Ok && still) {
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
    lc_.op = engine_.next_control_op(); // FIX9-D5: one namespace with the group sets
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
    if (step == Step::LcRetire || step == Step::LcRetireCheck) {
        retire_step(step, s, now);
        return;
    }
    if (s != Status::Ok) {
        // Before a commit nothing changed (the object was refused); after one the durable state may or may not have
        // moved: RECOVERY_REQUIRED, never "rejected". RAM refuses already (FIX5-D2, FIX8-D1).
        if (step == Step::LcEntry) {
            lc_entry_failed(now);
        } else if (step == Step::LcFloors) {
            floors_dirty_ = true; // the RAM floor refuses the device; the table is written again (bounded)
            recon_fails_ = 0;
            maint_retry_ = earliest(maint_retry_, now + detail::k_recon_gap);
        } else if (step == Step::LcWindow) {
            // FIX5-D6: the new window's record may be on the Flash all the same: its replay floor holds from now on, and
            // no window is open until one is installed again (the same object then goes on with this record's count).
            window_rec_ = window_stage_;
            window_set_ = false;
        }
        lc_finish(step == Step::LcVerify ? s : Status::RecoveryRequired, now);
        return;
    }
    switch (step) {
    case Step::LcVerify:
        lc_verified(now);
        return;
    case Step::LcFloors: // an unlisted device's floor is durable
        lc_finish(Status::Ok, now);
        return;
    case Step::LcEntry: {
        const Entry &e = entries_[lc_.slot];
        const DeviceId device = e.device;
        const ShortAddr addr = e.address;
        mark_used(lc_.slot); // (a new entry for an unlisted device: after its record, SEC-D5)
        entry_written(lc_.slot, true); // RAM and the record agree again (an earlier failed commit is superseded)
        if (lc_.type == member::k_type_revoke) {
            ++stats_.revoked;
            if (lc_.was_active) {
                // The signed notice goes to the device over its end session first; its sessions end when that had its
                // chance (the network's refusal is already in force: the ledger admits and renews it no more).
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
            }
            if (e.state == EntryState::Blocked) {
                engine_.delivery().end_sends_to(device, now, Status::Revoked); // HIL-F6: no send to it stays open forever
                engine_.emit_event(LM_EVENT_MEMBERSHIP, LM_MEMBER_REVOKED, 0, &device);
            }
        } else {
            ++stats_.reconciled;
            forget_member(device, addr);
            engine_.delivery().end_sends_to(device, now, Status::NotFound); // #16: it moved to another domain
            engine_.emit_event(LM_EVENT_MEMBERSHIP, LM_UNASSIGNED, 0, &device);
        }
        const std::size_t slot = lc_.slot;
        lc_finish(Status::Ok, now);
        cover(slot, now);
        return;
    }
    case Step::LcWindow: // a new window's record is durable: it is the one counted from now on (FIX5-D6)
        window_rec_ = window_stage_;
        window_ = lc_.obj.window;
        window_set_ = true;
        lc_finish(Status::Ok, now);
        return;
    default:
        return;
    }
}

void Ledger::lc_verified(MonoTime now) {
    const member::LocalIdentity &id = engine_.identity();
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
        const bool ok = w.term == id.term() && w.not_before_ms < w.expires_ms &&
                        w.expires_ms - w.not_before_ms <= 15ULL * 60 * 1000 && now.to_ms() < w.expires_ms;
        if (!ok || w.expected_revision != man_.expected_revision) {
            lc_finish(ok ? Status::Conflict : Status::InvalidArgument, now); // another expected set / term / span
            return;
        }
        // FIX5-D6: the counted window's policy revision is the replay floor. The same window again (re-signed, or
        // re-issued for a new term with new times) goes on with its count; an older window, or another one at the
        // counted revision, fails closed - alternating two valid windows can no longer start a count from zero.
        if (window_rec_.present && w.policy_revision <= window_rec_.policy_revision) {
            if (!window_rec_.same_window(w)) {
                lc_finish(Status::Conflict, now);
                return;
            }
            window_ = w;
            window_set_ = true;
            lc_finish(Status::Ok, now);
            return;
        }
        const WindowRecord fresh{w.policy_revision, w.id, w.expected_revision, w.max_new_members, w.allowed_roles, 0,
                                 true};
        if (commit_window(Step::LcWindow, fresh, -2) != Status::Ok) {
            lc_finish(Status::Busy, now); // nothing changed: RAM moves to the new window only once it is durable
        }
        return;
    }
    case member::k_type_root_handover: {
        const member::RootHandover &h = lc_.obj.handover;
        // FIX5-D4: the rules every party applies (credentials.hpp). This root retires only on an object its members can
        // follow: another root, a higher generation, a new term above the one it lives in.
        const Status from = member::handover_from(h, id.self(), id.delegation().generation, id.term());
        if (from == Status::Ok) {
            retire(now);
            return;
        }
        if (from != Status::NetworkMismatch) {
            lc_finish(from, now); // not a valid handover (InvalidArgument), or its new term is not above ours (Conflict)
            return;
        }
        Sha256Digest dh{};
        const bool ours = sec::sha256(id.delegation_cose(), dh) == Status::Ok &&
                          member::handover_to(h, id.self(), id.delegation().generation, dh) == Status::Ok &&
                          !(id.term() < h.new_term); // its first term or a later boot's (ARCH2-D1)
        lc_finish(ours ? Status::Ok : Status::NetworkMismatch, now); // the new root: it knows itself already
        return;
    }
    default:
        lc_finish(Status::Unsupported, now);
        return;
    }
    if (const Entry *e = find(device)) {
        lc_listed(static_cast<std::size_t>(e - entries_.data()), af, mf, now);
    } else {
        lc_unlisted(device, af, mf, now);
    }
}

// FIX8-D1: a listed device's floor is its ledger entry (C1: routine leaves filled the 10-entry table and revocation
// then failed for room). Tickets at or below `consumed` and memberships at or below `membership` are dead for good, so the
// revocation (or reconciliation) folds its floors into those two and makes the entry Blocked (Left: the member moved
// away) when they cut its generations. RAM first - the entry refuses at once (authorizes()) - then one commit. No table
// room is needed: a revocation of a listed device never fails for capacity. A reservation keeps its credential in its
// record, which this commit does not carry: a fold that would change it blocks the reservation instead (fail closed).
void Ledger::lc_listed(std::size_t slot, uint64_t af, uint64_t mf, MonoTime now) {
    const Entry &e = entries_[slot];
    Entry x = e;
    x.consumed = std::max(x.consumed, af > 0 ? af - 1 : 0);
    x.membership = std::max(x.membership, mf > 0 ? mf - 1 : 0);
    const bool cut = e.assignment < af || e.membership < mf;
    const bool folded = x.consumed != e.consumed || x.membership != e.membership;
    const bool holds_credential = e.state == EntryState::Prepared || e.state == EntryState::Active;
    if (e.state != EntryState::Blocked && (cut || (holds_credential && folded))) {
        x.state = e.state == EntryState::Left && lc_.to == EntryState::Left ? EntryState::Left : lc_.to;
    }
    // FIX12-D1: an unchanged entry is an idempotent success only when its record is durable; one in doubt (an earlier
    // commit of this revocation failed, RAM alone refuses it) is committed again and answers by that commit.
    const bool in_doubt = (doubt_ >> slot & 1U) != 0 && !holds_credential;
    if (x.state == e.state && !folded && !in_doubt) {
        lc_finish(Status::Ok, now); // generations it no longer holds (or the same object again): nothing more
        return;
    }
    x.confirmed = x.state == EntryState::Active && e.confirmed;
    x.reserved_until = MonoTime::never();
    lc_.slot = slot;
    lc_.was_active = e.state == EntryState::Active && x.state != EntryState::Active;
    entries_[slot] = x; // fail closed at once: the entry refuses from here on, whatever the commit does
    job_entry_ = x;
    if (commit_entry(Step::LcEntry, slot, x.state, x.confirmed, ByteView{}, -2) != Status::Ok) {
        lc_entry_failed(now);
        lc_finish(Status::RecoveryRequired, now);
    }
}

// A device this ledger does not list: its floor goes to the table (RAM at once, then the record). A full table first
// drops a copy an entry holds anyway (evict_cover); if the table holds only floors nothing else keeps, the device gets
// a Blocked entry of its own in any slot a join could take (free, or a departed one whose floor the table keeps): that
// entry is its floor record then. No such slot: nothing changed (NO_CAPACITY) - and while that lasts no join can
// reserve a slot here either (the same pick_slot rule), so the device cannot become a member of this root.
void Ledger::lc_unlisted(const DeviceId &device, uint64_t af, uint64_t mf, MonoTime now) {
    member::Floors &f = engine_.identity().floors();
    if (f.raise(device, af, mf) == Status::Ok || (evict_cover() && f.raise(device, af, mf) == Status::Ok)) {
        if (commit_floors(Step::LcFloors) != Status::Ok) {
            floors_dirty_ = true;
            recon_fails_ = 0;
            maint_retry_ = earliest(maint_retry_, now + detail::k_recon_gap);
            lc_finish(Status::RecoveryRequired, now);
        }
        return;
    }
    std::size_t i = 0;
    if (pick_slot(device, i) != Status::Ok) {
        lc_finish(Status::NoCapacity, now);
        return;
    }
    Entry x;
    x.device = device;
    x.consumed = af > 0 ? af - 1 : 0;
    x.membership = mf > 0 ? mf - 1 : 0;
    x.state = EntryState::Blocked;
    x.address = ShortAddr{static_cast<uint16_t>(2 + i)};
    lc_.slot = i;
    lc_.was_active = false;
    set_entry(i, x); // (a reused slot's departed device keeps its floor in the table: that is what made it reusable)
    job_entry_ = x;
    if (commit_entry(Step::LcEntry, i, EntryState::Blocked, false, ByteView{}, -2) != Status::Ok) {
        lc_entry_failed(now);
        lc_finish(Status::RecoveryRequired, now);
    }
}

// A table floor whose device's ledger entry holds it at least as high (the copy a departure left so that the slot could
// be reused) makes room for a floor nothing else keeps. That slot is not reused from then on. False: none.
bool Ledger::evict_cover() {
    member::Floors &f = engine_.identity().floors();
    for (std::size_t i = 0; i < f.count(); ++i) {
        const member::Floors::Entry c = f.at(i);
        const Entry *e = find(c.device);
        // (A slot whose record is in doubt may not hold what RAM shows: its floor is not known to be kept.)
        if (e != nullptr && e->state != EntryState::Active && e->state != EntryState::Prepared &&
            (doubt_ >> static_cast<std::size_t>(e - entries_.data()) & 1U) == 0 && e->consumed + 1 >= c.assignment &&
            e->membership + 1 >= c.membership) {
            f.remove(i);
            ++stats_.covers_evicted;
            return true;
        }
    }
    return false;
}

// FIX5-D2 / FIX8-D1: the entry commit of a revocation or reconciliation failed and its result is unknown. RAM refuses
// the member already; nothing of it may keep serving: its link and end sessions end and its routes go now, and
// maintenance writes the entry again (bounded).
void Ledger::lc_entry_failed(MonoTime now) {
    mark_dirty(lc_.slot, now);
    if (lc_.was_active) {
        const Entry &e = entries_[lc_.slot];
        forget_member(e.device, e.address);
        engine_.delivery().end_sends_to(e.device, now, lc_.to == EntryState::Left ? Status::NotFound : Status::Revoked);
        engine_.emit_event(LM_EVENT_MEMBERSHIP, lc_.to == EntryState::Left ? LM_UNASSIGNED : LM_MEMBER_REVOKED, 0,
                           &e.device);
    }
}

void Ledger::mark_dirty(std::size_t slot, MonoTime now) {
    dirty_ |= 1ULL << slot;
    doubt_ |= 1ULL << slot;
    recon_fails_ = 0;
    maint_retry_ = earliest(maint_retry_, now + detail::k_recon_gap);
}

// At boot: an ACTIVE entry below a durable table floor (provisioned, or a record written before FIX8) is refused at
// once and made Blocked durably, the floor folded into it (so that the entry keeps it).
void Ledger::block_below_floors(MonoTime now) {
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        Entry &e = entries_[i];
        if (e.state != EntryState::Active || authorizes(e)) {
            continue;
        }
        const member::Floors::Entry f = engine_.identity().floors().floor_of(e.device);
        e.consumed = std::max({e.consumed, e.assignment, f.assignment > 0 ? f.assignment - 1 : 0});
        e.membership = std::max(e.membership, f.membership > 0 ? f.membership - 1 : 0);
        e.state = EntryState::Blocked;
        e.confirmed = false;
        mark_dirty(i, now);
        maint_retry_ = earliest(maint_retry_, now);
    }
}

// Maintenance (holder -2): the lowest dirty slot is written as RAM holds it. False: nothing is left to do (the shared
// memory stays with the caller, which goes on with its other items).
bool Ledger::start_dirty(MonoTime now) {
    while (dirty_ != 0 && (entries_[static_cast<std::size_t>(__builtin_ctzll(dirty_))].state == EntryState::Active ||
                           entries_[static_cast<std::size_t>(__builtin_ctzll(dirty_))].state == EntryState::Prepared)) {
        // A repair writes no credential: an entry that holds one again (a later join) is never overwritten by it.
        dirty_ &= dirty_ - 1U;
    }
    if (dirty_ == 0) {
        return false;
    }
    const auto slot = static_cast<std::size_t>(__builtin_ctzll(dirty_));
    job_entry_ = entries_[slot];
    if (commit_entry(Step::CommitDirty, slot, job_entry_.state, job_entry_.confirmed, ByteView{}, -2) != Status::Ok) {
        release(-2);
        recon_retry(now);
    }
    return true;
}

void Ledger::dirty_done(Status s, MonoTime now) {
    const std::size_t slot = job_slot_index_;
    release(-2);
    if (s != Status::Ok) {
        ++stats_.floored_failed;
        recon_retry(now); // unknown durable result: RAM keeps refusing, the next try decides
        return;
    }
    const Entry &e = entries_[slot];
    if (e.state == job_entry_.state && e.consumed == job_entry_.consumed && e.membership == job_entry_.membership &&
        e.device == job_entry_.device) {
        entry_written(slot, true); // (RAM moved on meanwhile: written again)
    }
    recon_fails_ = 0;
    ++stats_.floored;
    mark_used(slot);
    if (job_entry_.state == EntryState::Left || job_entry_.state == EntryState::Blocked) {
        engine_.emit_event(LM_EVENT_MEMBERSHIP, job_entry_.state == EntryState::Left ? LM_UNASSIGNED : LM_MEMBER_REVOKED,
                           0, &job_entry_.device);
    }
    cover(slot, now);
}

// Bounded retry of the repairs above: k_recon_tries failures in a row (the gap doubling) end them for this boot.
void Ledger::recon_retry(MonoTime now) {
    if (++recon_fails_ < detail::k_recon_tries) {
        const Duration gap = Duration::from_us(detail::k_recon_gap.us << (recon_fails_ - 1U));
        maint_retry_ = earliest(maint_retry_, now + gap);
    }
}

// ---- commissioning window, retirement ----
bool Ledger::window_open(MonoTime now) const {
    const uint64_t ms = now.to_ms();
    return window_set_ && window_.term == engine_.identity().term() && ms >= window_.not_before_ms &&
           ms < window_.expires_ms && window_rec_.used < window_.max_new_members &&
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

// FIX5-D1: the verified RootHandover names this root the old one. It is retired from this moment - it admits, renews
// and serves nobody more, whatever the commit's result - because the fleet has handed the domain to another root; the
// commit only decides whether a restart still knows it. (Before: RAM changed only on an Ok commit, and a commit that
// reached the Flash but failed its read-back left the old root serving beside the new one until its next boot.)
void Ledger::retire(MonoTime now) {
    retired_ = true;
    renew_mask_ = 0;
    stop_admitting(now);
    lc_.checks = 0;
    rec_->arm(store::RecordJob::Op::Commit, store::rec::root_handover, 0, lc_.len);
    std::memcpy(rec_->payload.data(), scratch_.data(), lc_.len);
    if (submit(Step::LcRetire, JobClass::Flash, &store::record_job, rec_, -2) != Status::Ok) {
        lc_finish(Status::RecoveryRequired, now); // retired for this boot only: the object installed again makes it durable
    }
}

// The commit's result, and after a failed one what the record says: present = durable (applied), absent = this boot
// only (RECOVERY_REQUIRED: the object installed again makes it durable), unreadable = read again, a bounded number of
// times, with the node's record memory given back in between.
void Ledger::retire_step(Step step, Status s, MonoTime now) {
    if (s == Status::Ok || (step == Step::LcRetireCheck && s == Status::NotFound)) {
        lc_finish(s == Status::Ok ? Status::Ok : Status::RecoveryRequired, now);
        return;
    }
    if (step == Step::LcRetire) {
        retire_check(now); // the commit failed: it may have reached the Flash all the same (a failed read-back)
        return;
    }
    if (++lc_.checks >= detail::k_retire_checks) {
        lc_finish(Status::RecoveryRequired, now);
        return;
    }
    give_back_record(); // unreadable now: read again later; the record memory is the other modules' meanwhile
    lc_.retry_at = now + detail::k_retire_check_gap;
}

void Ledger::retire_check(MonoTime now) {
    if (!hold_record()) {
        lc_.retry_at = now + detail::k_busy_retry; // another module's record job: shortly
        return;
    }
    rec_->arm(store::RecordJob::Op::Load, store::rec::root_handover);
    if (submit(Step::LcRetireCheck, JobClass::Flash, &store::record_job, rec_, -2) != Status::Ok) {
        give_back_record();
        lc_.retry_at = now + detail::k_busy_retry;
    }
}

} // namespace lm::root
