#include <algorithm>
#include <cstring>

#include "core/codec.hpp"
#include "core/engine.hpp"
#include "root/ledger.hpp"
#include "root/ledger_internal.hpp"
#include "security/crypto.hpp"

// The root's join transaction with one unjoined device: JoinRequest -> ticket check -> policy -> signed
// MemberCredential -> PREPARED -> JoinPrepare -> JoinStored -> ACTIVE -> JoinCommit -> JoinActive -> confirmed.
namespace lm::root {

using detail::decode_entry;
using detail::k_busy_retry;
using detail::k_cose_off;
using detail::k_linger;
using detail::k_session_wait;

Ledger::Txn *Ledger::txn_by_device(const DeviceId &d) {
    for (Txn &t : txns_) {
        if (t.state != TxnState::Free && t.device == d) {
            return &t;
        }
    }
    return nullptr;
}

void Ledger::end_txn(Txn &t, bool close_session) {
    if (t.state == TxnState::Free) {
        return;
    }
    const int idx = txn_index(&t);
    if (close_session && t.pipe.bound()) {
        (void)engine_.link().close_join(t.pipe.peer());
    }
    t.pipe.reset();
    t.state = TxnState::Free;
    t.deadline = t.retry_at = MonoTime::never();
    if (!job_in_flight_) {
        release(idx);
    } else if (job_txn_ == idx) {
        job_txn_ = -3; // its job's completion finds no owner and just frees the memory
        orphan_release_ = idx;
    }
}

// ---- RX ----
void Ledger::join_control(const link::RxInfo &info, ByteView plain, MonoTime now) {
    Txn *tp = txn_by_device(info.peer);
    if (tp == nullptr) {
        return;
    }
    Txn &t = *tp;
    const int idx = txn_index(&t);
    if (t.state == TxnState::Session && holder_ != idx && !acquire(idx)) {
        ++stats_.busy_drops; // another join holds the credential buffer: the joiner repeats its chunks
        return;
    }
    ByteView object;
    const member::JoinPipe::Feed f = t.pipe.feed(plain, holder_ == idx ? scratch_ : MutByteView{}, object, now);
    if (f == member::JoinPipe::Feed::Duplicate) {
        repeat_last(t, now);
        return;
    }
    if (f != member::JoinPipe::Feed::Object) {
        return;
    }
    member::JoinObjectHeader h;
    ByteView data;
    if (member::join_object_parse(object, h, data) != Status::Ok || h.issuer != t.device) {
        return;
    }
    switch (h.type) {
    case member::k_type_join_request:
        on_request(t, data, h, now);
        break;
    case member::k_type_join_stored:
        on_stored(t, data, h, now);
        break;
    case member::k_type_join_active:
        on_active(t, data, h, now);
        break;
    default:
        break;
    }
}

// The device sent something again that we already processed: our answer did not reach it.
void Ledger::repeat_last(Txn &t, MonoTime now) {
    if (t.state == TxnState::PrepareOut && t.obj_len != 0) {
        t.pipe.send(ByteView{scratch_.data(), t.obj_len}, now);
    } else if ((t.state == TxnState::CommitOut || t.state == TxnState::Linger) && t.staged_len != 0) {
        t.pipe.send_staged(t.staged_len, now);
    }
}

void Ledger::stage_ack(Txn &t, uint8_t type, const member::JoinAckData &a, MonoTime now) {
    member::JoinObjectHeader h;
    h.type = type;
    h.request = t.request;
    h.domain = engine_.identity().delegation().domain;
    h.revision = 0;
    h.issuer = engine_.identity().self();
    MutByteView out = t.pipe.stage();
    std::size_t plen = 0;
    std::size_t dlen = 0;
    Status st = member::join_object_begin(h, out, plen);
    if (st == Status::Ok) {
        st = member::encode_join_ack(a, out.from(plen), dlen);
    }
    if (st != Status::Ok) {
        end_txn(t);
        return;
    }
    t.staged_len = plen + dlen;
    t.pipe.send_staged(t.staged_len, now);
}

// JoinCommit (SEC-D1): the signature that completes the credential JoinPrepare announced. Sent only once the
// ACTIVE entry is durable; it is the last 64 bytes of the credential the entry holds (at the scratch tail).
void Ledger::stage_commit(Txn &t, MonoTime now) {
    member::JoinCommitData c;
    c.prepare_hash = t.prepare_hash;
    c.membership = t.membership;
    const uint8_t *cose = scratch_.data() + k_cose_off;
    std::copy_n(cose + t.cose_len - member::k_signature_bytes, member::k_signature_bytes, c.signature.begin());
    stage_commit_data(t, c, now);
}

void Ledger::stage_commit_data(Txn &t, const member::JoinCommitData &c, MonoTime now) {
    member::JoinObjectHeader h;
    h.type = member::k_type_join_commit;
    h.request = t.request;
    h.domain = engine_.identity().delegation().domain;
    h.revision = c.refusal ? 0 : t.membership;
    h.issuer = engine_.identity().self();
    MutByteView out = t.pipe.stage();
    std::size_t plen = 0;
    std::size_t dlen = 0;
    Status st = member::join_object_begin(h, out, plen);
    if (st == Status::Ok) {
        st = member::encode_join_commit(c, out.from(plen), dlen);
    }
    if (st != Status::Ok) {
        end_txn(t);
        return;
    }
    t.staged_len = plen + dlen;
    t.pipe.send_staged(t.staged_len, now);
}

void Ledger::refuse(Txn &t, Status why, MonoTime now) {
    ++stats_.refused;
    if (why == Status::Conflict) {
        ++stats_.conflicts;
    }
    member::JoinCommitData c; // prepare-hash all zero and no signature: a refusal; the value is the reason (S8-D3)
    c.membership = static_cast<uint64_t>(why);
    c.refusal = true;
    t.state = TxnState::Linger;
    t.deadline = now + k_linger;
    stage_commit_data(t, c, now);
    release(txn_index(&t));
}

// ---- the JoinRequest ----
void Ledger::on_request(Txn &t, ByteView data, const member::JoinObjectHeader &h, MonoTime now) {
    if (t.state != TxnState::Session) {
        return;
    }
    ++stats_.requests;
    const member::LocalIdentity &id = engine_.identity();
    member::JoinRequestData d;
    Sha256Digest dc_hash{};
    if (member::decode_join_request(data, d) != Status::Ok || h.request.is_zero() ||
        h.domain != id.delegation().domain || sec::sha256(d.device_credential, dc_hash) != Status::Ok ||
        dc_hash != t.dc_hash) {
        refuse(t, Status::AuthRejected, now); // not the credential of this session's handshake
        return;
    }
    t.deadline = now + Duration::from_s(60); // guards the ticket check and the credential signature
    t.request = h.request;
    t.role = (d.capabilities & 1U) != 0 ? 1 : 0;
    t.dc = d.device_credential;
    t.ticket_cose = d.ticket;
    if (sec::sha256(data, t.content) != Status::Ok) {
        refuse(t, Status::RecoveryRequired, now);
        return;
    }
    Entry *e = find_mut(t.device);
    if (retired_) {
        refuse(t, Status::RecoveryRequired, now); // [S18] a root the fleet replaced issues nothing
        return;
    }
    if (e != nullptr && e->request == t.request && e->state != EntryState::Expected &&
        e->state != EntryState::Blocked && e->state != EntryState::Free) {
        // The same request_id again (docs/07 §4): one reservation, one prepare hash, one content.
        if (e->hash != t.content) {
            refuse(t, Status::Conflict, now); // J06: same request, other content
            return;
        }
        answer_repeat(t, *e, now);
        return;
    }
    // [S18] An ACTIVE entry may be superseded by the device's transfer back here (A->B->A: a fleet ticket whose new
    // generation is above it, docs/07 §8) or re-issued under a RootHandover; the ticket check decides which.
    const bool supersede = e != nullptr && e->state == EntryState::Active;
    if (e != nullptr && (e->state == EntryState::Prepared || e->state == EntryState::Active) && !supersede) {
        if (e->state == EntryState::Prepared && e->recovered) {
            // The old reservation's deadline is unknown after a restart and is never extended: abort it now
            // (durably, when the shared memory is free); this request asks again once it is gone.
            e->state = EntryState::Aborted;
            abort_slot_ = static_cast<std::size_t>(e - entries_.data());
            abort_pending_ = true;
        }
        refuse(t, Status::Conflict, now); // another request while one reserved/active: never a 2nd address
        return;
    }
    // A new join: the ticket is checked on the worker before anything is reserved. While another ledger job runs, its
    // arguments are the worker's and its completion finds its transaction by job_txn_: refuse before touching either
    // (the joiner repeats the request).
    if (job_in_flight_) {
        t.pipe.rx_forget();
        ++stats_.busy_drops;
        refuse(t, Status::Busy, now);
        return;
    }
    vargs_.trust = id.trust();
    vargs_.delegation = id.delegation();
    vargs_.device = t.device;
    vargs_.dc_hash = t.dc_hash;
    vargs_.ticket_cose = t.ticket_cose;
    vargs_.nonce = d.nonce;
    vargs_.term = id.member().root_term;
    vargs_.out = TicketInfo{};
    if (sec::sha256(id.delegation_cose(), vargs_.delegation_hash) != Status::Ok) {
        refuse(t, Status::RecoveryRequired, now);
        return;
    }
    t.state = TxnState::Verifying;
    if (submit(Step::VerifyTicket, JobClass::PublicKey, &verify_ticket_job, this, txn_index(&t)) != Status::Ok) {
        t.state = TxnState::Session; // worker busy (one public-key job): the joiner repeats the request
        t.pipe.rx_forget();
        ++stats_.busy_drops;
        refuse(t, Status::Busy, now);
        return;
    }
}

void Ledger::verified(Txn &t, Status s, MonoTime now) {
    if (s != Status::Ok) {
        refuse(t, s == Status::RecoveryRequired ? Status::RecoveryRequired : s, now);
        return;
    }
    t.ticket = vargs_.out;
    decide_policy(t, now);
}

// Preapproved needs a valid signed ticket AND an expected entry that grants exactly this ticket;
// external needs the operator. A consumed grant (generation not above the last issued) never works.
void Ledger::decide_policy(Txn &t, MonoTime now) {
    const Entry *e = find(t.device);
    Status v = Status::Ok;
    const bool window = mode_ != JoinMode::Preapproved && window_open(now); // [S18] docs/21 §2
    const bool preapproved = mode_ == JoinMode::Preapproved || window;
    if (t.ticket.kind == 2) { // [S18] re-issue under a RootHandover: exactly this ledger's ACTIVE member (or one whose
                              // re-issue was aborted: it still holds the assignment it consumed here)
        const bool member = e != nullptr && (e->state == EntryState::Active ||
                                             (e->state == EntryState::Aborted && e->assignment != 0 &&
                                              e->consumed >= e->assignment));
        if (!member) {
            v = e == nullptr ? Status::NotFound : Status::Conflict;
        }
        t.ticket.new_generation = e != nullptr ? e->assignment : 0;
    } else if (e != nullptr && e->state == EntryState::Active && (t.ticket.kind != 1 || t.ticket.new_generation <= e->assignment)) {
        v = Status::Conflict; // [S18] only a transfer back with a higher generation supersedes an ACTIVE entry
    } else if (e != nullptr && e->state == EntryState::Blocked) {
        v = Status::Revoked;
    } else if (e != nullptr && t.ticket.new_generation <= e->consumed) {
        v = Status::Conflict; // SEC-D4: that generation was made ACTIVE here already: a consumed grant
    } else if (mode_ == JoinMode::Closed && !window) {
        // [S18] A CLOSED root admits inside a commissioning window only (authenticated in it, decided after it).
        v = window_set_ ? Status::Expired : Status::AuthRejected;
    } else if (window && ((window_.allowed_roles >> t.role) & 1U) == 0) {
        v = Status::RoleNotAllowed; // the window admits other roles only
    } else if (preapproved) {
        if (e == nullptr || e->state != EntryState::Expected) {
            v = Status::NotFound; // NOT_EXPECTED (docs/07 §3): a hint, not a permanent verdict; a former member
                                  // needs a new expected entry as well
        } else if (e->assignment != t.ticket.new_generation || e->hash != t.ticket.grant) {
            v = Status::Conflict;
        }
    }
    const uint64_t next = e != nullptr ? e->membership + 1 : 1;
    if (v == Status::Ok && (next > k_u63_max || engine_.identity().floors().check(t.device,
                                                                                  AssignmentGen{t.ticket.new_generation},
                                                                                  MembershipGen{next}) != Status::Ok)) {
        v = Status::Revoked;
    }
    if (v != Status::Ok) {
        refuse(t, v, now);
        return;
    }
    if (preapproved || t.ticket.kind == 2) { // a handover re-issue needs no new approval: the member is ACTIVE here
        t.windowed = window && t.ticket.kind != 2;
        start_prepare(t, now);
        return;
    }
    // External: the approval belongs to the operator; nothing is reserved while it is pending, and
    // the shared buffers go back so other joins are not blocked for up to 300 s.
    t.state = TxnState::Pending;
    t.deadline = now + k_approval_timeout;
    t.dc = t.ticket_cose = ByteView{};
    release(txn_index(&t));
    engine_.emit_event(LM_EVENT_MEMBERSHIP, LM_APPROVAL_PENDING, 0, &t.device);
}

Status Ledger::decide(const JoinDecision &d, MonoTime now) {
    for (Txn &t : txns_) {
        if (t.state == TxnState::Pending && t.request == d.request) {
            if (d.verify && (t.device != d.device || t.dc_hash != d.credential)) {
                return Status::Conflict; // not the request the operator looked at
            }
            if (!d.approve) {
                refuse(t, Status::AuthRejected, now);
            } else {
                start_prepare(t, now);
            }
            return Status::Ok;
        }
    }
    return Status::NotFound;
}

bool Ledger::pending_join(std::size_t i, PendingJoin &out) const {
    if (i >= txns_.size() || txns_[i].state != TxnState::Pending) {
        return false;
    }
    out.request = txns_[i].request;
    out.device = txns_[i].device;
    out.credential = txns_[i].dc_hash;
    return true;
}

Status Ledger::pick_slot(const DeviceId &device, std::size_t &slot) const {
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        if (entries_[i].state != EntryState::Free && entries_[i].device == device) {
            slot = i;
            return Status::Ok;
        }
    }
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        if (entries_[i].state == EntryState::Free) {
            slot = i;
            return Status::Ok;
        }
    }
    // Full: a departed or aborted device gives up its address, but only when its old credential is
    // already below the revocation floor (R09: no old session or credential can match the new owner).
    const member::Floors &f = engine_.identity().floors();
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        const Entry &e = entries_[i];
        if ((e.state == EntryState::Left || e.state == EntryState::Aborted || e.state == EntryState::Blocked) &&
            f.check(e.device, AssignmentGen{e.assignment}, MembershipGen{e.membership}) == Status::Revoked) {
            slot = i;
            return Status::Ok;
        }
    }
    return Status::NoCapacity;
}

void Ledger::start_prepare(Txn &t, MonoTime now) {
    const int idx = txn_index(&t);
    if (t.windowed && !window_open(now)) {
        refuse(t, Status::Expired, now); // [S18] authenticated before the window closed, approved after: refused
        return;
    }
    std::size_t slot = 0;
    const Status ps = pick_slot(t.device, slot);
    if (ps != Status::Ok) {
        refuse(t, ps, now);
        return;
    }
    if (!acquire(idx)) { // the buffers are busy (another join, a maintenance commit): try shortly
        t.state = TxnState::Pending;
        t.retry_at = now + k_busy_retry;
        t.retry_kind_ = 1;
        return;
    }
    const Entry &old = entries_[slot];
    t.slot = static_cast<uint16_t>(slot);
    t.membership = old.state != EntryState::Free && old.device == t.device ? old.membership + 1 : 1;
    // What the entry becomes when PREPARED commits (RAM changes only after the commit is durable). What this
    // device consumed stays (SEC-D4); a slot taken over from another device starts from nothing.
    job_entry_ = Entry{};
    job_entry_.consumed = old.state != EntryState::Free && old.device == t.device ? old.consumed : 0;
    job_entry_.device = t.device;
    job_entry_.hash = t.content;
    job_entry_.request = t.request;
    job_entry_.assignment = t.ticket.new_generation;
    job_entry_.membership = t.membership;
    job_entry_.address = ShortAddr{static_cast<uint16_t>(2 + slot)};
    const member::LocalIdentity &id = engine_.identity();
    SignArgs &s = sargs_;
    s = SignArgs{};
    s.key = id.key();
    s.mc.device = t.device;
    s.mc.address = job_entry_.address;
    s.mc.assignment = AssignmentGen{t.ticket.new_generation};
    s.mc.membership = MembershipGen{t.membership};
    s.mc.role = t.role;
    s.mc.relay_allowed = t.role == 1;
    s.mc.root_term = id.member().root_term;
    s.mc.lease_expires_root_ms = now.to_ms() + static_cast<uint64_t>(k_member_lease.to_ms());
    s.mc.credential_hash = t.dc_hash; // SHA-256 of the DeviceCredential it is issued against (S5-D2)
    s.env.type = member::k_type_member_credential;
    s.env.request = t.request;
    s.env.domain = id.delegation().domain;
    s.env.issuer = id.self();
    s.env.revision = t.membership;
    s.out = scratch_.from(k_cose_off);
    t.state = TxnState::Signing;
    t.deadline = now + Duration::from_s(10);
    if (submit(Step::SignMember, JobClass::PublicKey, &sign_job, this, idx) != Status::Ok) {
        t.state = TxnState::Pending;
        t.retry_at = now + k_busy_retry; // the single public-key slot is busy (a handshake): retry
        t.retry_kind_ = 1;
    }
}

void Ledger::prepare_signed(Txn &t, Status s, MonoTime now) {
    if (s != Status::Ok || sargs_.len == 0 || sargs_.len > member::k_max_member_cose) {
        refuse(t, Status::RecoveryRequired, now); // a local signing fault is never blamed on the device
        return;
    }
    t.cose_len = sargs_.len;
    // SEC-D1: the JoinPrepare carries the credential with its signature withheld; this is the hash of that form.
    if (member::withheld_hash(ByteView{scratch_.data() + k_cose_off, t.cose_len}, t.prepare_hash) != Status::Ok) {
        refuse(t, Status::RecoveryRequired, now);
        return;
    }
    t.state = TxnState::Preparing;
    commit_prepared(t, now);
}

// [P4] The transaction's record jobs take the node's record memory when they start; lent to another module for a
// moment (a journal write, a channel record), the step waits for it on the transaction's retry timer.
bool Ledger::record_or_retry(Txn &t, uint8_t kind, MonoTime now) {
    if (hold_record()) {
        return true;
    }
    t.retry_kind_ = kind;
    t.retry_at = now + k_busy_retry;
    return false;
}

void Ledger::commit_prepared(Txn &t, MonoTime now) {
    if (!record_or_retry(t, 3, now)) {
        return;
    }
    if (t.windowed) {
        // [S18] docs/21 §2: the window's budget counts durable reservations. The count is committed first (a cut
        // between the two commits over-counts, never under-counts), and checked again (joins run in parallel).
        WindowRecord counted = window_rec_;
        ++counted.used;
        if (!window_open(now)) {
            refuse(t, Status::Expired, now);
        } else if (commit_window(Step::WindowReserve, counted, txn_index(&t)) != Status::Ok) {
            refuse(t, Status::Busy, now);
        }
        return;
    }
    if (commit_entry(Step::CommitPrepared, t.slot, EntryState::Prepared, false,
                     ByteView{scratch_.data() + k_cose_off, t.cose_len}, txn_index(&t)) != Status::Ok) {
        refuse(t, Status::Busy, now);
    }
}

void Ledger::window_reserved(Txn &t, Status s, MonoTime now) {
    if (s != Status::Ok) {
        refuse(t, Status::RecoveryRequired, now); // counted or not: no reservation, never more than the budget
        return;
    }
    window_rec_ = window_stage_;
    ++stats_.window_admitted;
    if (commit_entry(Step::CommitPrepared, t.slot, EntryState::Prepared, false,
                     ByteView{scratch_.data() + k_cose_off, t.cose_len}, txn_index(&t)) != Status::Ok) {
        refuse(t, Status::Busy, now);
    }
}

Status Ledger::commit_window(Step step, const WindowRecord &r, int holder) {
    std::size_t len = 0;
    LM_TRY(detail::encode_window_record(r, MutByteView{rec_->payload}, len));
    rec_->arm(store::RecordJob::Op::Commit, store::rec::commissioning_window, 0, len);
    LM_TRY(submit(step, JobClass::Flash, &store::record_job, rec_, holder));
    window_stage_ = r; // what RAM counts once the commit is durable
    return Status::Ok;
}

void Ledger::prepare_committed(Txn &t, Status s, MonoTime now) {
    if (s != Status::Ok) { // the record may or may not be durable: RAM stays as it was
        refuse(t, s, now);
        return;
    }
    job_entry_.reserved_until = now + k_reservation;
    set_entry(t.slot, job_entry_);
    mark_used(t.slot); // entry first, then its manifest bit (SEC-D5)
    if (man_dirty_ && maint_retry_.is_never()) {
        maint_retry_ = now + k_busy_retry; // committed once this join gives the record memory back
    }
    ++stats_.prepared;
    send_prepare(t, now);
}

void Ledger::send_prepare(Txn &t, MonoTime now) {
    const Entry &e = entries_[t.slot];
    const member::LocalIdentity &id = engine_.identity();
    member::JoinObjectHeader h;
    h.type = member::k_type_join_prepare;
    h.request = t.request;
    h.domain = id.delegation().domain;
    h.revision = t.membership;
    h.issuer = id.self();
    member::JoinPrepareData p;
    p.member = ByteView{scratch_.data() + k_cose_off, t.cose_len}; // the encoder withholds its signature (SEC-D1)
    p.prepare_hash = t.prepare_hash;
    p.address = e.address;
    p.membership = t.membership;
    p.root_term = id.member().root_term.value();
    const int64_t left = e.reserved_until.is_never() ? 120000 : (e.reserved_until - now).to_ms();
    p.reservation_ms = static_cast<uint32_t>(std::clamp<int64_t>(left, 1, 120000));
    std::size_t plen = 0;
    std::size_t dlen = 0;
    Status st = member::join_object_begin(h, scratch_.first(k_cose_off), plen);
    if (st == Status::Ok) {
        st = member::encode_join_prepare(p, scratch_.subspan(plen, k_cose_off - plen), dlen);
    }
    if (st != Status::Ok) {
        refuse(t, Status::RecoveryRequired, now);
        return;
    }
    t.obj_len = plen + dlen;
    t.state = TxnState::PrepareOut;
    t.deadline = e.reserved_until;
    t.pipe.send(ByteView{scratch_.data(), t.obj_len}, now);
}

// ---- STORED -> COMMIT ----
void Ledger::on_stored(Txn &t, ByteView data, const member::JoinObjectHeader &h, MonoTime now) {
    member::JoinAckData a;
    if (t.state != TxnState::PrepareOut || h.request != t.request ||
        member::decode_join_ack(data, a) != Status::Ok || a.prepare_hash != t.prepare_hash) {
        return;
    }
    const Entry &e = entries_[t.slot];
    if (e.state != EntryState::Prepared || e.request != t.request || !(now < e.reserved_until)) {
        refuse(t, Status::Expired, now); // ABORTED (or timed out): a late STORED never revives it
        return;
    }
    t.pipe.acked();
    t.device_generation = a.value;
    t.state = TxnState::Activating;
    t.deadline = now + Duration::from_s(10);
    commit_active(t, now);
}

void Ledger::commit_active(Txn &t, MonoTime now) {
    if (!record_or_retry(t, 4, now)) {
        return;
    }
    const Entry &e = entries_[t.slot];
    job_entry_ = e;
    job_entry_.consumed = std::max(e.consumed, e.assignment); // durable with the ACTIVE entry (SEC-D4)
    if (commit_entry(Step::CommitActive, t.slot, EntryState::Active, false,
                     ByteView{scratch_.data() + k_cose_off, t.cose_len}, txn_index(&t)) != Status::Ok) {
        refuse(t, Status::Busy, now);
    }
}

void Ledger::active_committed(Txn &t, Status s, MonoTime now) {
    if (s != Status::Ok) {
        // ACTIVE may or may not be durable; RAM keeps Prepared and the flash record is the truth on the
        // next query (the repeated request reads it back). No answer: the device queries again.
        end_txn(t);
        return;
    }
    job_entry_.reserved_until = MonoTime::never();
    entries_[t.slot] = job_entry_;
    ++stats_.activated;
    engine_.link().forget_handshake_gate(t.mac); // the device's first ordinary handshake follows (S8-D6)
    t.state = TxnState::CommitOut;
    t.deadline = now + Duration::from_s(30);
    stage_commit(t, now); // ACTIVE is durable: now the signature may leave the root (SEC-D1)
}

void Ledger::on_active(Txn &t, ByteView data, const member::JoinObjectHeader &h, MonoTime now) {
    member::JoinAckData a;
    if (h.request != t.request || member::decode_join_ack(data, a) != Status::Ok || a.prepare_hash != t.prepare_hash) {
        return;
    }
    if (t.state == TxnState::Linger && t.confirmed_done) {
        t.pipe.send_staged(t.staged_len, now); // our final ack was lost: same bytes again
        return;
    }
    const Entry &e = entries_[t.slot];
    if (t.state != TxnState::CommitOut || e.state != EntryState::Active || e.request != t.request) {
        return;
    }
    t.pipe.acked();
    t.device_generation = a.value;
    t.state = TxnState::Confirming;
    t.deadline = now + Duration::from_s(10);
    commit_confirmed(t, now);
}

void Ledger::commit_confirmed(Txn &t, MonoTime now) {
    if (!record_or_retry(t, 5, now)) {
        return;
    }
    job_entry_ = entries_[t.slot];
    if (commit_entry(Step::CommitConfirmed, t.slot, EntryState::Active, true,
                     ByteView{scratch_.data() + k_cose_off, t.cose_len}, txn_index(&t)) != Status::Ok) {
        end_txn(t);
    }
}

void Ledger::confirmed_committed(Txn &t, Status s, MonoTime now) {
    if (s != Status::Ok) {
        end_txn(t); // unconfirmed stays unconfirmed: the device's next query completes it
        return;
    }
    entries_[t.slot] = job_entry_;
    ++stats_.confirmed;
    engine_.link().forget_handshake_gate(t.mac);
    engine_.emit_event(LM_EVENT_MEMBERSHIP, LM_ACTIVE, 0, &t.device);
    member::JoinAckData a; // the final acknowledgement repeats the device's own evidence
    a.prepare_hash = t.prepare_hash;
    a.value = t.device_generation;
    t.state = TxnState::Linger;
    t.confirmed_done = true;
    t.deadline = now + k_linger;
    stage_ack(t, member::k_type_join_active, a, now);
    release(txn_index(&t));
}

// ---- the same request again ----
void Ledger::answer_repeat(Txn &t, const Entry &e, MonoTime now) {
    t.resend = true;
    if (e.state == EntryState::Prepared && e.recovered) {
        // Reservation deadline unknown after a restart: never extended, aborted (docs/07 §4).
        entries_[&e - entries_.data()].state = EntryState::Aborted;
        abort_slot_ = static_cast<std::size_t>(&e - entries_.data());
        abort_pending_ = true;
        refuse(t, Status::Expired, now);
        return;
    }
    if (e.state == EntryState::Aborted) {
        refuse(t, Status::Expired, now);
        return;
    }
    if (e.state == EntryState::Left) {
        refuse(t, Status::Conflict, now);
        return;
    }
    if (e.state == EntryState::Prepared && !(now < e.reserved_until)) {
        refuse(t, Status::Expired, now);
        return;
    }
    const int idx = txn_index(&t);
    if ((holder_ != idx && !acquire(idx)) || !hold_record()) {
        t.retry_kind_ = 2;
        t.retry_at = now + k_busy_retry;
        t.deadline = now + k_session_wait;
        t.state = TxnState::Session;
        return;
    }
    t.slot = static_cast<uint16_t>(&e - entries_.data());
    t.membership = e.membership;
    rec_->arm(store::RecordJob::Op::Load, static_cast<uint16_t>(k_rec_ledger_base + t.slot));
    job_slot_index_ = t.slot;
    t.state = TxnState::Verifying;
    if (submit(Step::ResendLoad, JobClass::Flash, &store::record_job, rec_, idx) != Status::Ok) {
        refuse(t, Status::Busy, now);
    }
}

// The flash record is the truth about the request (RAM may lag after a failed commit): a Prepared
// record gets its JoinPrepare again byte for byte, an Active one its JoinCommit.
void Ledger::resend_loaded(Txn &t, Status s, MonoTime now) {
    Entry loaded;
    ByteView cose;
    if (s != Status::Ok || decode_entry(*rec_, loaded, cose) != Status::Ok || cose.empty() ||
        cose.size() > member::k_max_member_cose || loaded.request != t.request || loaded.device != t.device) {
        refuse(t, s != Status::Ok ? s : Status::RecoveryRequired, now);
        return;
    }
    std::memmove(scratch_.data() + k_cose_off, cose.data(), cose.size());
    t.cose_len = cose.size();
    t.membership = loaded.membership;
    if (member::withheld_hash(ByteView{scratch_.data() + k_cose_off, t.cose_len}, t.prepare_hash) != Status::Ok) {
        refuse(t, Status::RecoveryRequired, now);
        return;
    }
    Entry &e = entries_[t.slot];
    if (loaded.state == EntryState::Active) {
        e.state = EntryState::Active; // RAM catches up with a commit whose result was lost
        e.confirmed = loaded.confirmed;
        e.consumed = std::max(e.consumed, loaded.consumed);
        e.reserved_until = MonoTime::never();
        t.state = TxnState::CommitOut;
        t.deadline = now + Duration::from_s(30);
        stage_commit(t, now); // the ACTIVE record is durable: its signature may be sent (SEC-D1)
        return;
    }
    if (loaded.state != EntryState::Prepared || !(now < e.reserved_until)) {
        refuse(t, Status::Expired, now);
        return;
    }
    send_prepare(t, now);
}


} // namespace lm::root
