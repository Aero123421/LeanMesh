#include "root/ledger.hpp"
#include "root/ledger_internal.hpp"

#include <algorithm>
#include <cstring>

#include "core/codec.hpp"
#include "core/engine.hpp"
#include "security/crypto.hpp"

namespace lm::root {
namespace detail {

Status encode_entry(const Entry &e, bool confirmed, ByteView cose, MutByteView out, std::size_t &len) {
    Writer w{out};
    w.u8(confirmed ? 1 : 0);
    w.u64be(e.assignment);
    w.u64be(e.membership);
    w.bytes(e.device.view());
    w.bytes(e.request.view());
    w.bytes(ByteView{e.hash});
    w.bytes(cose);
    len = w.size();
    return w.finish();
}

Status decode_entry(const store::RecordJob &rec, Entry &out, ByteView &cose) {
    if (rec.payload_len < k_entry_head || rec.state > static_cast<uint8_t>(EntryState::Blocked)) {
        return Status::BadFrame;
    }
    Reader r{ByteView{rec.payload.data(), rec.payload_len}};
    Entry e;
    e.confirmed = r.u8() != 0;
    e.assignment = r.u64be();
    e.membership = r.u64be();
    r.copy_to(e.device.bytes);
    r.copy_to(e.request.bytes);
    r.copy_to(e.hash);
    cose = r.bytes(r.remaining());
    LM_TRY(r.finish());
    e.state = static_cast<EntryState>(rec.state);
    out = e;
    return Status::Ok;
}

} // namespace detail

using detail::decode_entry;
using detail::encode_entry;
using detail::k_busy_retry;
using detail::k_cose_off;
using detail::k_entry_head;
using detail::k_linger;
using detail::k_session_wait;

Ledger::Ledger(Engine &engine) : engine_(engine) {
    for (std::size_t i = 0; i < txns_.size(); ++i) {
        txns_[i].pipe.attach(engine, k_tag_ledger + (static_cast<uint32_t>(i) << 16));
    }
}

uint32_t Ledger::hint() const { return link::domain_hint_of(engine_.identity().delegation().domain); }

const Entry *Ledger::find(const DeviceId &d) const { return const_cast<Ledger *>(this)->find_mut(d); }

Entry *Ledger::find_mut(const DeviceId &d) {
    for (Entry &e : entries_) {
        if (e.state != EntryState::Free && e.device == d) {
            return &e;
        }
    }
    return nullptr;
}

std::size_t Ledger::count(EntryState s) const {
    return static_cast<std::size_t>(std::count_if(entries_.begin(), entries_.end(),
                                                  [s](const Entry &e) { return e.state == s; }));
}

// ---- shared memory ----
bool Ledger::acquire(int txn) {
    if (holder_ == txn) {
        return true;
    }
    if (holder_ != -1 || job_in_flight_) {
        return false;
    }
    rec_ = engine_.identity().lend_record();
    if (rec_ == nullptr) {
        return false;
    }
    scratch_ = engine_.link().exchange().lend_scratch();
    if (scratch_.empty()) {
        engine_.identity().return_record();
        rec_ = nullptr;
        return false;
    }
    holder_ = txn;
    return true;
}

void Ledger::release(int txn) {
    if (holder_ != txn || job_in_flight_) {
        return;
    }
    engine_.link().exchange().return_scratch();
    scratch_ = MutByteView{};
    engine_.identity().return_record();
    rec_ = nullptr;
    holder_ = -1;
}

// ---- worker plumbing ----
Status Ledger::submit(Step step, JobClass cls, port::JobFn fn, void *arg) {
    if (job_in_flight_) {
        return Status::Busy;
    }
    job_slot_ = Handle{0, ++job_gen_};
    LM_TRY(engine_.submit_job(JobOwner::Ledger, job_slot_, cls, fn, arg));
    step_ = step;
    job_in_flight_ = true;
    return Status::Ok;
}

// Commits one ledger record. `job_entry_` is what RAM becomes when the commit is durable.
Status Ledger::commit_entry(Step step, std::size_t slot, EntryState state, bool confirmed, ByteView cose,
                            int txn) {
    if (rec_ == nullptr || holder_ != txn) {
        return Status::Busy;
    }
    job_entry_.state = state;
    job_entry_.confirmed = confirmed;
    job_entry_.address = ShortAddr{static_cast<uint16_t>(2 + slot)}; // the address is the slot
    std::size_t len = 0;
    LM_TRY(encode_entry(job_entry_, confirmed, cose, MutByteView{rec_->payload}, len));
    rec_->op = store::RecordJob::Op::Commit;
    rec_->id = static_cast<uint16_t>(k_rec_ledger_base + slot);
    rec_->state = static_cast<uint8_t>(state);
    rec_->payload_len = static_cast<uint32_t>(len);
    job_slot_index_ = slot;
    job_txn_ = txn;
    return submit(step, JobClass::Flash, &store::record_job, rec_);
}

void Ledger::on_job_done(Handle slot, Status s, MonoTime now) {
    job_in_flight_ = false;
    if (cancelled_) {
        cancelled_ = false;
        step_ = Step::None;
        return_memory();
        return;
    }
    if (slot != job_slot_ || step_ == Step::None) {
        return;
    }
    const Step step = step_;
    step_ = Step::None;
    step_done(step, s, now);
}

Status Ledger::load_all_job(port::JobEnv &env, void *arg) {
    auto &l = *static_cast<Ledger *>(arg);
    store::RecordJob &rec = *l.rec_;
    rec.op = store::RecordJob::Op::Load;
    rec.id = store::rec::root_ledger;
    Status st = store::record_load(env.store, rec);
    if (st == Status::Ok) {
        Reader r{ByteView{rec.payload.data(), rec.payload_len}};
        l.expected_revision_ = r.u64be();
        LM_TRY(r.finish());
    } else if (st != Status::NotFound) {
        return st;
    }
    for (std::size_t i = 0; i < k_ledger_slots; ++i) {
        rec.id = static_cast<uint16_t>(k_rec_ledger_base + i);
        st = store::record_load(env.store, rec);
        if (st == Status::NotFound) {
            l.entries_[i] = Entry{};
            continue;
        }
        LM_TRY(st); // a quarantined or unreadable record is never "empty" (docs/12 §2)
        ByteView cose;
        LM_TRY(decode_entry(rec, l.entries_[i], cose));
        l.entries_[i].address = ShortAddr{static_cast<uint16_t>(2 + i)};
        // Prepared and Aborted survive a restart, but the reservation deadline does not (docs/07 §4):
        // it is unknown, and an old reservation is never extended.
        l.entries_[i].recovered = l.entries_[i].state == EntryState::Prepared;
    }
    return Status::Ok;
}

// Worker. The fleet-signed ticket names this device, its credential and this root's delegation;
// only initial assignments exist in this slice (source domain zero, expected-old 0).
Status Ledger::verify_ticket_job(port::JobEnv & /*env*/, void *arg) {
    auto &l = *static_cast<Ledger *>(arg);
    VerifyArgs &v = l.vargs_;
    member::Envelope env;
    ByteView data;
    LM_TRY(member::open_signed(v.ticket_cose, v.trust.key, member::k_type_assignment_ticket, env, data));
    member::AssignmentTicket t;
    LM_TRY(member::decode_assignment_ticket(data, t));
    if (t.fleet != v.trust.fleet || env.domain != t.target || t.target != v.delegation.domain) {
        return Status::NetworkMismatch;
    }
    if (t.device != v.device || t.device_credential_hash != v.dc_hash ||
        t.root_delegation_hash != v.delegation_hash || t.new_generation <= t.expected_old) {
        return Status::AuthRejected;
    }
    if (!t.source.is_zero() || t.expected_old != 0) {
        return Status::Unsupported; // signed replacement (transfer) is the lifecycle slice's
    }
    v.out.new_generation = t.new_generation;
    v.out.mode = t.mode;
    return sec::sha256(v.ticket_cose, v.out.grant);
}

// Worker. Builds and signs the MemberCredential into the staged tail buffer.
Status Ledger::sign_job(port::JobEnv & /*env*/, void *arg) {
    auto &l = *static_cast<Ledger *>(arg);
    SignArgs &s = l.sargs_;
    std::array<uint8_t, 256> data{};
    std::size_t dlen = 0;
    LM_TRY(member::encode_member_credential(s.mc, MutByteView{data}, dlen));
    return member::issue_signed(s.key, s.env, ByteView{data.data(), dlen}, s.out, s.len);
}

// ---- boot ----
void Ledger::on_identity_ready(MonoTime now) {
    loaded_ = false;
    failed_ = false;
    if (engine_.config().role != Role::Root || !engine_.identity().is_member()) {
        return;
    }
    if (!acquire(-2)) {
        maint_retry_ = now + k_busy_retry;
        load_pending_ = true;
        return;
    }
    load_pending_ = false;
    if (submit(Step::LoadAll, JobClass::Flash, &load_all_job, this) != Status::Ok) {
        release(-2);
        load_pending_ = true;
        maint_retry_ = now + k_busy_retry;
    }
}

void Ledger::return_memory() {
    if (holder_ != -1) {
        engine_.link().exchange().return_scratch();
        engine_.identity().return_record();
    }
    scratch_ = MutByteView{};
    rec_ = nullptr;
    holder_ = -1;
}

void Ledger::stop() {
    for (Txn &t : txns_) {
        if (t.pipe.bound()) {
            (void)engine_.link().close_join(t.pipe.peer());
        }
        t.pipe.reset();
        t.state = TxnState::Free;
        t.deadline = t.retry_at = MonoTime::never();
    }
    if (job_in_flight_) {
        cancelled_ = true; // the worker may still write into the borrowed buffers: they stay reserved until the
        step_ = Step::None; // completion is polled (zombie rule, docs/IMPLEMENTATION.md §3)
    } else {
        return_memory();
    }
    loaded_ = false;
    exp_active_ = false;
    leave_pending_ = abort_pending_ = load_pending_ = confirm_pending_ = false;
    maint_retry_ = MonoTime::never();
}

// ---- hooks ----
bool Ledger::responder_open() const {
    if (!loaded_ || failed_ || mode_ == JoinMode::Closed || !engine_.identity().is_member()) {
        return false;
    }
    return std::any_of(txns_.begin(), txns_.end(), [](const Txn &t) { return t.state == TxnState::Free; });
}

// The ledger only ever *denies*: an entry that is not Active with exactly this membership generation
// (left, aborted, reserved but not committed) refuses the link. A device the ledger has no entry for
// is judged by its credential chain and the revocation floors alone (decision S8-D7).
bool Ledger::link_admit(const DeviceId &device, const member::MemberCredential &mc) const {
    if (!loaded_ || failed_) {
        return false;
    }
    const Entry *e = find(device);
    if (e == nullptr) {
        return true;
    }
    return e->state == EntryState::Active && e->membership == mc.membership.value() &&
           e->address.value() == mc.address.value();
}

void Ledger::discovery(const MacAddr & /*src*/, const wire::BootstrapCarrier &c, MonoTime now) {
    if (c.object_kind != member::k_obj_join_hello || !responder_open() || now < last_offer_ + detail::k_offer_gap) {
        return; // one offer per gap: a hello flood costs airtime only once
    }
    last_offer_ = now;
    // Offers are broadcast: the joiner picks the source of the first one that echoes its own nonce.
    std::array<uint8_t, wire::k_link_header_bytes + wire::k_bootstrap_header_bytes + 6> frame{};
    std::size_t len = 0;
    member::OfferHint oh;
    oh.expected_revision = static_cast<uint32_t>(expected_revision_);
    if (member::encode_discovery(true, c.exchange_id, hint(), MutByteView{frame}, len, &oh) == Status::Ok) {
        (void)engine_.transmit(MacAddr::broadcast(), ByteView{frame.data(), len}, k_tag_offer, now);
    }
}

void Ledger::session_up(const MacAddr &mac, const DeviceId &peer, const Sha256Digest &peer_dc_hash, MonoTime now) {
    Txn *free_txn = nullptr;
    for (Txn &t : txns_) {
        if (t.state != TxnState::Free && t.device == peer) {
            end_txn(t); // the same device started again: its old session is superseded
        }
        if (t.state == TxnState::Free && free_txn == nullptr) {
            free_txn = &t;
        }
    }
    if (free_txn == nullptr) {
        ++stats_.busy_drops;
        (void)engine_.link().close_join(peer);
        return;
    }
    Txn &t = *free_txn;
    t = Txn{};
    t.pipe.attach(engine_, k_tag_ledger + (static_cast<uint32_t>(txn_index(&t)) << 16));
    t.state = TxnState::Session;
    t.device = peer;
    t.mac = mac;
    t.dc_hash = peer_dc_hash;
    t.deadline = now + k_session_wait;
    t.pipe.bind(mac, peer, hint());
}

// ---- job completions ----
// A finished job may leave its transaction ended (a refusal, an aborted request) while it still holds the
// shared buffers: they go back here, never later than the job that used them.
void Ledger::step_done(Step step, Status s, MonoTime now) {
    const int idx = job_txn_;
    handle_step(step, s, now);
    if (idx >= 0 && holder_ == idx && !job_in_flight_) {
        const TxnState st = txns_[static_cast<std::size_t>(idx)].state;
        if (st == TxnState::Free || st == TxnState::Linger) {
            release(idx);
        }
    }
}

void Ledger::handle_step(Step step, Status s, MonoTime now) {
    Txn *t = job_txn_ >= 0 ? &txns_[static_cast<std::size_t>(job_txn_)] : nullptr;
    if (job_txn_ == -3) { // the transaction ended while its job ran
        job_txn_ = -1;
        release(orphan_release_);
        return;
    }
    switch (step) {
    case Step::LoadAll:
        release(-2);
        if (s == Status::Ok) {
            loaded_ = true;
        } else {
            failed_ = true; // fail closed: no joins, no admissions, and the application is told
            engine_.emit_event(LM_EVENT_FAULT, static_cast<uint32_t>(s), 0, nullptr);
        }
        return;
    case Step::VerifyTicket:
        if (t != nullptr && t->state == TxnState::Verifying) {
            verified(*t, s, now);
        }
        return;
    case Step::SignMember:
        if (t != nullptr && t->state == TxnState::Signing) {
            prepare_signed(*t, s, now);
        }
        return;
    case Step::CommitPrepared:
        if (t != nullptr && t->state == TxnState::Preparing) {
            prepare_committed(*t, s, now);
        }
        return;
    case Step::CommitActive:
        if (t != nullptr && t->state == TxnState::Activating) {
            active_committed(*t, s, now);
        }
        return;
    case Step::CommitConfirmed:
        if (t != nullptr && t->state == TxnState::Confirming) {
            confirmed_committed(*t, s, now);
        }
        return;
    case Step::ResendLoad:
        if (t != nullptr && t->state == TxnState::Verifying) {
            resend_loaded(*t, s, now);
        }
        return;
    case Step::CommitAborted:
        if (s == Status::Ok) {
            entries_[job_slot_index_].reserved_until = MonoTime::never();
            ++stats_.aborted;
        }
        release(-2);
        return;
    case Step::ConfirmLoad:
        confirm_loaded(s, now);
        return;
    case Step::ConfirmCommit:
        if (s == Status::Ok) {
            confirm_done(now);
        } else {
            confirm_pending_ = false; // unknown durable result: the device repeats its evidence
            release(-2);
        }
        return;
    case Step::CommitLeft:
        leave_committed(s, now);
        return;
    case Step::CommitFloors:
        release(-2);
        return;
    case Step::VerifyExpected:
    case Step::CommitExpectedHeader:
    case Step::CommitExpectedEntry:
        expected_step_done(step, s, now);
        return;
    case Step::None:
        return;
    }
}

// ---- timers ----
MonoTime Ledger::deadline() const {
    MonoTime next = maint_retry_;
    for (const Txn &t : txns_) {
        if (t.state != TxnState::Free) {
            next = earliest(next, earliest(t.deadline, earliest(t.retry_at, t.pipe.deadline())));
        }
    }
    for (const Entry &e : entries_) {
        if (e.state == EntryState::Prepared && !e.recovered) {
            next = earliest(next, e.reserved_until);
        }
    }
    return next;
}

void Ledger::on_tx_outcome(const TxOutcome &o, MonoTime now) {
    for (Txn &t : txns_) {
        if (t.state != TxnState::Free && t.pipe.owns_tag(o.tag)) {
            t.pipe.on_tx_outcome(o, now);
        }
    }
}

void Ledger::on_timer(MonoTime now) {
    if (load_pending_ && now >= maint_retry_) {
        on_identity_ready(now);
    }
    for (Txn &t : txns_) {
        if (t.state == TxnState::Free) {
            continue;
        }
        const Status e = t.pipe.on_timer(now);
        if (e != Status::Ok && t.state != TxnState::Linger) {
            end_txn(t); // the device did not answer: the entry keeps its durable state
            continue;
        }
        if (now >= t.retry_at) {
            t.retry_at = MonoTime::never();
            retry_txn(t, now);
        }
        if (t.state != TxnState::Free && now >= t.deadline) {
            if (t.state == TxnState::Pending) {
                refuse(t, Status::Expired, now); // approval timed out: the device may ask again
            } else {
                end_txn(t);
            }
        }
    }
    abort_expired(now);
    if (maint_retry_ != MonoTime::never() && now >= maint_retry_) {
        maint_retry_ = MonoTime::never();
        maintenance(now);
    }
}

void Ledger::retry_txn(Txn &t, MonoTime now) {
    if (t.retry_kind_ == 1 && t.state == TxnState::Pending) {
        t.retry_kind_ = 0;
        start_prepare(t, now);
    } else if (t.retry_kind_ == 2 && t.state == TxnState::Session) {
        t.retry_kind_ = 0;
        if (const Entry *e = find(t.device)) {
            answer_repeat(t, *e, now);
        }
    }
}

// Expired reservations become ABORTED durably (a later COMMIT for them is refused); a restart's
// Prepared entries are aborted lazily when their device asks (answer_repeat).
void Ledger::abort_expired(MonoTime now) {
    if (abort_pending_ || holder_ != -1) {
        if (abort_pending_) {
            maintenance(now);
        }
        return;
    }
    for (std::size_t i = 0; i < entries_.size(); ++i) {
        Entry &e = entries_[i];
        if (e.state == EntryState::Prepared && !e.recovered && !e.reserved_until.is_never() &&
            now >= e.reserved_until && txn_by_slot(i) == nullptr) {
            e.state = EntryState::Aborted; // logically at once: no COMMIT is accepted for it any more
            abort_slot_ = i;
            abort_pending_ = true;
            maintenance(now);
            return;
        }
    }
}

Ledger::Txn *Ledger::txn_by_slot(std::size_t slot) {
    for (Txn &t : txns_) {
        if (t.state != TxnState::Free && t.state != TxnState::Session && t.state != TxnState::Verifying &&
            t.state != TxnState::Pending && t.state != TxnState::Linger && t.slot == slot) {
            return &t;
        }
    }
    return nullptr;
}

// Queued maintenance commits (abort, leave) run when the shared memory is free.
void Ledger::maintenance(MonoTime now) {
    if (holder_ != -1 || job_in_flight_ || !acquire(-2)) {
        maint_retry_ = now + k_busy_retry;
        return;
    }
    if (leave_pending_) {
        leave_pending_ = false;
        Entry &e = entries_[leave_slot_];
        job_entry_ = e;
        job_entry_.reserved_until = MonoTime::never();
        if (commit_entry(Step::CommitLeft, leave_slot_, EntryState::Left, false, ByteView{}, -2) != Status::Ok) {
            release(-2);
        }
        return;
    }
    if (confirm_pending_) {
        rec_->op = store::RecordJob::Op::Load;
        rec_->id = static_cast<uint16_t>(k_rec_ledger_base + confirm_.slot);
        rec_->payload_len = 0;
        job_txn_ = -2;
        job_slot_index_ = confirm_.slot;
        if (submit(Step::ConfirmLoad, JobClass::Flash, &store::record_job, rec_) != Status::Ok) {
            confirm_pending_ = false;
            release(-2);
        }
        return;
    }
    if (abort_pending_) {
        abort_pending_ = false;
        job_entry_ = entries_[abort_slot_];
        if (commit_entry(Step::CommitAborted, abort_slot_, EntryState::Aborted, false, ByteView{}, -2) != Status::Ok) {
            release(-2);
        }
        return;
    }
    release(-2);
}

} // namespace lm::root
