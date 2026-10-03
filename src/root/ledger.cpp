#include "root/ledger.hpp"
#include "root/ledger_internal.hpp"

#include <algorithm>
#include <cstring>

#include "core/codec.hpp"
#include "core/engine.hpp"
#include "security/crypto.hpp"

namespace lm::root {
namespace {

// One field list per record (core/codec.hpp): it writes and reads the same layout.
template <class F> void io(F &f, Entry &e) { // the entry head after its confirmed byte; the credential COSE follows
    f.u64(e.assignment);
    f.u64(e.membership);
    f.u64(e.consumed);
    f.raw(e.device.bytes);
    f.raw(e.request.bytes);
    f.raw(e.hash);
}
template <class F> void io(F &f, Manifest &m) {
    f.is(k_manifest_version);
    f.raw(m.domain.bytes);
    f.u64(m.expected_revision);
    f.u64(m.used);
    f.raw(m.set_hash);
    f.u8(m.pages);
    f.u16(m.received);
    f.u16(m.pending);
    for (auto &d : m.digests) {
        f.raw(d);
    }
}
template <class F> void io(F &f, WindowRecord &r) {
    f.is(k_window_record_version);
    f.u64(r.policy_revision);
    f.raw(r.id);
    f.u64(r.expected_revision);
    f.u8(r.max_new_members);
    f.u8(r.allowed_roles);
    f.u8(r.used);
}

} // namespace

namespace detail {

Status encode_entry(const Entry &e, bool confirmed, ByteView cose, MutByteView out, std::size_t &len) {
    return put_record(e, out, len, [&](auto &f, auto &m) {
        f.flag(confirmed);
        io(f, m);
        f.w.bytes(cose);
    });
}

Status decode_entry(const store::RecordJob &rec, Entry &out, ByteView &cose) {
    if (rec.payload_len < k_entry_head || rec.state > static_cast<uint8_t>(EntryState::Blocked)) {
        return Status::BadFrame;
    }
    Entry e;
    LM_TRY(get_record(ByteView{rec.payload.data(), rec.payload_len}, e, [&](auto &f, auto &m) {
        f.flag(m.confirmed);
        io(f, m);
        cose = f.r.bytes(f.r.remaining());
    }));
    e.state = static_cast<EntryState>(rec.state);
    out = e;
    return Status::Ok;
}

Status decode_manifest(ByteView payload, Manifest &out) {
    Manifest m;
    if (get_record(payload, m, [](auto &f, auto &x) { io(f, x); }) != Status::Ok || m.pages > 16) {
        return Status::BadFrame;
    }
    out = m;
    return Status::Ok;
}

Status encode_window_record(const WindowRecord &r, MutByteView out, std::size_t &len) {
    return put_record(r, out, len, [](auto &f, auto &x) { io(f, x); });
}

Status decode_window_record(ByteView payload, WindowRecord &out) {
    WindowRecord r;
    LM_TRY(get_record(payload, r, [](auto &f, auto &x) { io(f, x); }));
    r.present = true;
    out = r;
    return Status::Ok;
}

// store::rec::policy (FIX8-D12): version u8 (1) | join mode u8 (0 closed, 1 external, 2 preapproved) | changes u64.
Status encode_policy(JoinMode mode, uint64_t changes, MutByteView out, std::size_t &len) {
    Writer w{out};
    w.u8(k_policy_version);
    w.u8(static_cast<uint8_t>(mode));
    w.u64be(changes);
    len = w.size();
    return w.finish();
}

Status decode_policy(ByteView payload, JoinMode &mode, uint64_t &changes) {
    Reader r{payload};
    const uint8_t v = r.u8();
    const uint8_t m = r.u8();
    const uint64_t c = r.u64be();
    if (r.finish() != Status::Ok || v != k_policy_version || m > static_cast<uint8_t>(JoinMode::Preapproved) ||
        c > k_u63_max) {
        return Status::BadFrame;
    }
    mode = static_cast<JoinMode>(m);
    changes = c;
    return Status::Ok;
}

} // namespace detail

Status encode_manifest(const Manifest &m, MutByteView out, std::size_t &len) {
    return put_record(m, out, len, [](auto &f, auto &x) { io(f, x); });
}

Status encode_provisioned_member(const member::MemberCredential &mc, ByteView member_cose, uint16_t &record_id,
                                 MutByteView out, std::size_t &len) {
    const uint16_t a = mc.address.value();
    if (a < 2 || a >= 2 + k_ledger_slots || member_cose.size() > member::k_max_member_cose) {
        return Status::InvalidArgument; // the ledger's slots are addresses 2..65
    }
    Entry e;
    e.device = mc.device;
    e.assignment = mc.assignment.value();
    e.membership = mc.membership.value();
    e.consumed = e.assignment; // an ACTIVE membership consumed its assignment
    record_id = static_cast<uint16_t>(k_rec_ledger_base + (a - 2U));
    return detail::encode_entry(e, true, member_cose, out, len);
}

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
// The credential buffer (the exchange's lent scratch) belongs to one holder for a whole join transaction or
// maintenance chain. The node's one record memory (ADR-002 P4) is taken with it by a maintenance chain (a few
// back-to-back jobs), but a join transaction takes it only for its own record jobs (hold_record) and gives it
// back while it waits for the device: the journal and the other modules' records go on meanwhile.
bool Ledger::acquire(int txn) {
    if (holder_ == txn) {
        return true;
    }
    if (holder_ != -1 || job_in_flight_) {
        return false;
    }
    if (txn < 0 && !hold_record()) {
        return false;
    }
    scratch_ = engine_.link().exchange().lend_scratch();
    if (scratch_.empty()) {
        give_back_record();
        return false;
    }
    holder_ = txn;
    return true;
}

bool Ledger::hold_record() {
    if (rec_ == nullptr) {
        rec_ = engine_.identity().lend_record();
    }
    return rec_ != nullptr;
}

void Ledger::give_back_record() {
    engine_.identity().return_record(rec_);
}

void Ledger::release(int txn) {
    if (holder_ != txn || job_in_flight_) {
        return;
    }
    engine_.link().exchange().return_scratch();
    scratch_ = MutByteView{};
    give_back_record();
    holder_ = -1;
}

// ---- worker plumbing ----
Status Ledger::submit(Step step, JobClass cls, port::JobFn fn, void *arg, int owner) {
    if (job_in_flight_) {
        return Status::Busy;
    }
    job_slot_ = Handle{0, ++job_gen_};
    LM_TRY(engine_.submit_job(JobOwner::Ledger, job_slot_, cls, fn, arg));
    if (fn == &store::record_job && arg == rec_ &&
        (rec_->op == store::RecordJob::Op::Commit || rec_->op == store::RecordJob::Op::Recover)) {
        ++change_; // ISSUE5: a durable write of the ledger's records is under way: a backup cut before it is stale
    }
    step_ = step;
    job_in_flight_ = true;
    job_txn_ = owner;
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
    rec_->arm(store::RecordJob::Op::Commit, static_cast<uint16_t>(k_rec_ledger_base + slot), static_cast<uint8_t>(state),
              len);
    job_slot_index_ = slot;
    return submit(step, JobClass::Flash, &store::record_job, rec_, txn);
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
    // FIX8-D3: queued maintenance (the other leaves of a batch, a registry or policy commit, renewals) goes on as soon
    // as the shared memory is free again, not at an unrelated later wake. (The repairs of dirty entries and floors keep
    // their own doubling gap: recon_retry, mark_dirty.)
    if (holder_ == -1 && !job_in_flight_ &&
        (leave_mask_ != 0 || abort_pending_ || confirm_pending_ || groups_pending_ || policy_pending_ || man_dirty_ ||
         renew_mask_ != 0)) {
        maint_retry_ = earliest(maint_retry_, now);
    }
}

// SEC-D5: the manifest must exist and name this root's domain; a slot it lists as used must still hold its
// record. Anything else is RECOVERY_REQUIRED: a lost or foreign ledger never becomes an empty one (docs/12 §5).
Status Ledger::load_all_job(port::JobEnv &env, void *arg) {
    auto &l = *static_cast<Ledger *>(arg);
    store::RecordJob &rec = *l.rec_;
    rec.arm(store::RecordJob::Op::Load, store::rec::root_ledger);
    Status st = store::record_load(env.store, rec);
    if (st == Status::NotFound) {
        return Status::RecoveryRequired; // a domain root without its ledger: only new-network provisioning writes one
    }
    LM_TRY(st);
    if (detail::decode_manifest(ByteView{rec.payload.data(), rec.payload_len}, l.man_) != Status::Ok ||
        l.man_.domain != l.load_domain_) {
        return Status::RecoveryRequired; // unreadable, or another domain's ledger
    }
    // [S18] A RootHandover that named this root the old one retired it for good (docs/21 §8).
    rec.id = store::rec::root_handover;
    st = store::record_load(env.store, rec);
    if (st != Status::NotFound) {
        LM_TRY(st);
        l.retired_ = true;
    }
    // [S18] The budget record of the last commissioning window (docs/21 §2: counted by durable reservations); FIX5-D6:
    // with its replay floor. Unreadable is never "no window yet".
    rec.id = store::rec::commissioning_window;
    st = store::record_load(env.store, rec);
    l.window_rec_ = WindowRecord{};
    if (st != Status::NotFound) {
        LM_TRY(st);
        if (detail::decode_window_record(ByteView{rec.payload.data(), rec.payload_len}, l.window_rec_) != Status::Ok) {
            return Status::RecoveryRequired;
        }
    }
    for (std::size_t i = 0; i < k_ledger_slots; ++i) {
        rec.id = static_cast<uint16_t>(k_rec_ledger_base + i);
        st = store::record_load(env.store, rec);
        if (st == Status::NotFound) {
            if ((l.man_.used >> i & 1U) != 0) {
                return Status::RecoveryRequired; // an entry that existed is gone
            }
            l.entries_[i] = Entry{};
            continue;
        }
        LM_TRY(st); // a quarantined or unreadable record is never "empty" (docs/12 §2)
        if ((l.man_.used >> i & 1U) == 0) {
            l.man_.used |= 1ULL << i; // entry committed before its manifest bit (the order of every first use)
            l.man_dirty_ = true;
        }
        ByteView cose;
        LM_TRY(decode_entry(rec, l.entries_[i], cose));
        l.entries_[i].address = ShortAddr{static_cast<uint16_t>(2 + i)};
        // Prepared and Aborted survive a restart, but the reservation deadline does not (docs/07 §4):
        // it is unknown, and an old reservation is never extended.
        l.entries_[i].recovered = l.entries_[i].state == EntryState::Prepared;
    }
    // [FIX8-D12] The join mode the policy set. Unreadable is never "the default": the root stays CLOSED (policy in
    // doubt) while it still admits its members (a policy is no authorisation of a member).
    rec.id = store::rec::policy;
    st = store::record_load(env.store, rec);
    l.load_policy_ = st;
    if (st == Status::Ok &&
        detail::decode_policy(ByteView{rec.payload.data(), rec.payload_len}, l.load_mode_, l.load_count_) !=
            Status::Ok) {
        l.load_policy_ = Status::RecoveryRequired;
    }
    // [ISSUE5] The last backup sequence number. Unreadable is never "none yet": no backup is signed on a number that might
    // repeat (the ledger itself is not affected: a backup is no authorisation).
    rec.id = store::rec::ledger_backup_seq;
    st = store::record_load(env.store, rec);
    l.load_seq_ = 0;
    l.load_seq_ok_ = st == Status::NotFound;
    if (st == Status::Ok && rec.payload_len == 8) {
        Reader r{ByteView{rec.payload.data(), rec.payload_len}};
        l.load_seq_ = r.u64be();
        l.load_seq_ok_ = r.finish() == Status::Ok && l.load_seq_ <= k_u63_max;
    }
    // [FIX8-D10] The group registry last: its payload stays in the record memory for the owner to restore.
    rec.id = store::rec::root_groups;
    l.groups_load_ = store::record_load(env.store, rec);
    return Status::Ok;
}

// Worker. The fleet-signed ticket names this device, its credential and this root's delegation. An initial
// assignment comes from no domain (expected-old 0); a transfer (docs/07 §8) from another one. Mode 1 is a one-time
// grant (consumed by generation, SEC-D4); mode 0 is bound to the nonce the device issued and presents in its
// authenticated JoinRequest (S18: the device exports it, lm_transfer_nonce_get). [S18] The object may instead be the
// fleet's RootHandover naming this root the new one: this ledger's own member asks for its credential again.
Status Ledger::verify_ticket_job(port::JobEnv & /*env*/, void *arg) {
    auto &l = *static_cast<Ledger *>(arg);
    VerifyArgs &v = l.vargs_;
    member::Envelope env;
    ByteView data;
    if (member::peek_signed(v.ticket_cose, member::k_type_root_handover, env, data) == Status::Ok) {
        member::RootHandover h;
        LM_TRY(member::open_signed(v.ticket_cose, v.trust.key, member::k_type_root_handover, env, data));
        LM_TRY(member::decode_handover(data, h));
        // FIX5-D4: the rules every party applies (another root, a higher generation), this root named as the new one.
        const Status to = env.domain == v.delegation.domain
                              ? member::handover_to(h, v.delegation.root, v.delegation.generation, v.delegation_hash)
                              : Status::NetworkMismatch;
        if (to != Status::Ok || v.term < h.new_term) {
            // A handover to another root or delegation, or to a term this root has not reached. The handover names the
            // new root's first term; every boot of the new root is one more (ARCH2-D1), so a later term still is it.
            return to == Status::InvalidArgument ? to : Status::NetworkMismatch;
        }
        v.out.kind = 2;
        return sec::sha256(v.ticket_cose, v.out.grant);
    }
    LM_TRY(member::open_signed(v.ticket_cose, v.trust.key, member::k_type_assignment_ticket, env, data));
    member::AssignmentTicket t;
    LM_TRY(member::decode_assignment_ticket(data, t));
    if (t.fleet != v.trust.fleet || env.domain != t.target || t.target != v.delegation.domain ||
        t.source == v.delegation.domain) {
        return Status::NetworkMismatch;
    }
    if (t.device != v.device || t.device_credential_hash != v.dc_hash ||
        t.root_delegation_hash != v.delegation_hash || t.new_generation <= t.expected_old ||
        (t.source.is_zero() != (t.expected_old == 0)) || (t.mode == 0 && t.nonce != v.nonce)) {
        return Status::AuthRejected; // mode 0: not the nonce the device vouched for in this very request
    }
    v.out.new_generation = t.new_generation;
    v.out.mode = t.mode;
    v.out.kind = t.source.is_zero() ? 0 : 1;
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
    man_ = Manifest{};
    man_dirty_ = false;
    retired_ = false;
    load_domain_ = engine_.identity().delegation().domain; // the job reads only its own copies
    if (submit(Step::LoadAll, JobClass::Flash, &load_all_job, this, -2) != Status::Ok) {
        release(-2);
        load_pending_ = true;
        maint_retry_ = now + k_busy_retry;
    }
}

void Ledger::return_memory() {
    if (holder_ != -1) {
        engine_.link().exchange().return_scratch();
    }
    give_back_record(); // (a join transaction that waits for its device holds the scratch only)
    scratch_ = MutByteView{};
    holder_ = -1;
}

void Ledger::stop() {
    // A join-mode change the stop cuts ends now: its record may or may not be durable (INDETERMINATE); the next start
    // reads it (lm_policy_get), never a silent operation that no event ends.
    if (policy_pending_ || (job_in_flight_ && step_ == Step::CommitPolicy)) {
        engine_.emit_event(LM_EVENT_OPERATION, static_cast<uint32_t>(Status::RecoveryRequired), policy_op_, nullptr);
    }
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
    bk_ = Backup{}; // [ISSUE5] (a step the stop cut ends with the engine's stop; nothing is signed or written after it)
    rs_ = Restore{};
    renew_mask_ = 0;
    lc_.active = false;
    lc_.retry_at = MonoTime::never();
    dirty_ = doubt_ = 0; // (a stricter state that never became durable is decided again by the records at the next load)
    floors_dirty_ = false;
    groups_pending_ = policy_pending_ = false; // (their operations ended above / in Groups::stop)
    window_set_ = false;
    notice_until_ = MonoTime::never();
    leave_mask_ = 0;
    abort_pending_ = load_pending_ = confirm_pending_ = false;
    maint_retry_ = MonoTime::never();
}

// ---- hooks ----
bool Ledger::responder_open() const {
    if (!loaded_ || failed_ || retired_ || !engine_.identity().is_member() ||
        (mode_ == JoinMode::Closed && !window_open(engine_.step_time()))) {
        return false; // [S18] a CLOSED root admits during a commissioning window only
    }
    return std::any_of(txns_.begin(), txns_.end(), [](const Txn &t) { return t.state == TxnState::Free; });
}

// SEC-D2 (supersedes S8-D7): every Link and End session of the root, whichever side started it, needs an
// ACTIVE entry of exactly this device with the credential's address, assignment and membership. A credential
// the ledger does not list was never issued by this ledger or outlived it (left, aborted, reused slot).
bool Ledger::link_admit(const DeviceId &device, const member::MemberCredential &mc) const {
    if (!loaded_ || failed_ || retired_) {
        return false;
    }
    const Entry *e = authorized(device);
    return e != nullptr && e->address == mc.address && e->assignment == mc.assignment.value() &&
           e->membership == mc.membership.value();
}

// FIX5-D2: the floors are the authorisation as soon as they are raised (before the entry's commit, or after it failed).
bool Ledger::authorizes(const Entry &e) const {
    return e.state == EntryState::Active &&
           engine_.identity().floors().check(e.device, AssignmentGen{e.assignment}, MembershipGen{e.membership}) ==
               Status::Ok;
}

const Entry *Ledger::authorized(const DeviceId &d) const {
    const Entry *e = find(d);
    return e != nullptr && authorizes(*e) ? e : nullptr;
}

EntryState Ledger::effective(const Entry &e) const {
    return e.state == EntryState::Active && !authorizes(e) ? EntryState::Blocked : e.state;
}

void Ledger::discovery(const MacAddr & /*src*/, const wire::BootstrapCarrier &c, MonoTime now) {
    const ByteView scope = engine_.identity().scope_key();
    member::OfferHint hello;
    if (c.object_kind != member::k_obj_join_hello || member::decode_hello(c.body, hello) != Status::Ok ||
        !member::scope_ok(scope, member::k_obj_join_hello, c.exchange_id, hello)) {
        return; // SEC-Da: a scoped root answers only hellos of its own scope
    }
    if (!responder_open() || now < last_offer_ + detail::k_offer_gap) {
        return; // one offer per gap: a hello flood costs airtime only once
    }
    last_offer_ = now;
    // Offers are broadcast: the joiner picks the source of the first one that echoes its own nonce.
    std::array<uint8_t, wire::k_link_header_bytes + wire::k_bootstrap_header_bytes + 14> frame{};
    std::size_t len = 0;
    member::OfferHint oh;
    oh.expected_revision = static_cast<uint32_t>(man_.expected_revision);
    if (member::scope_sign(scope, member::k_obj_join_offer, c.exchange_id, oh) == Status::Ok &&
        member::encode_discovery(true, c.exchange_id, hint(), MutByteView{frame}, len, &oh) == Status::Ok) {
        (void)engine_.transmit(MacAddr::broadcast(), ByteView{frame.data(), len}, k_tag_offer, now);
    }
}

void Ledger::session_up(const MacAddr &mac, const DeviceId &peer, const Sha256Digest &peer_dc_hash, MonoTime now) {
    Txn *free_txn = nullptr;
    for (Txn &t : txns_) {
        if (t.state != TxnState::Free && t.device == peer) {
            end_txn(t, false); // the same device started again: its old session is superseded (the link layer
                               // replaced it already; closing by device now would end the NEW session)
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
// shared buffers: they go back here, never later than the job that used them. A transaction that goes on
// without a job of its own (it waits for its device) keeps the credential buffer and gives the record back.
void Ledger::step_done(Step step, Status s, MonoTime now) {
    const int idx = job_txn_;
    handle_step(step, s, now);
    if (idx >= 0 && holder_ == idx && !job_in_flight_) {
        const TxnState st = txns_[static_cast<std::size_t>(idx)].state;
        if (st == TxnState::Free || st == TxnState::Linger) {
            release(idx);
        } else {
            give_back_record();
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
        if (s == Status::Ok) { // (the registry's payload is still in the record memory: restored before it goes back)
            engine_.groups().restore(groups_load_, ByteView{rec_->payload.data(), rec_->payload_len});
            policy_doubt_ = load_policy_ != Status::Ok && load_policy_ != Status::NotFound;
            mode_ = policy_doubt_ ? JoinMode::Closed : (load_policy_ == Status::Ok ? load_mode_ : mode_);
            policy_count_ = load_policy_ == Status::Ok ? load_count_ : 0;
            bk_seq_ = load_seq_;
            bk_seq_ok_ = load_seq_ok_;
            bk_ = Backup{}; // (a backup held before a reload was cut from the ledger as it was)
        }
        release(-2);
        if (s == Status::Ok) {
            loaded_ = true;
            dirty_ = doubt_ = 0; // RAM is what the records say
            // FIX5-D2: an ACTIVE entry below a durable floor of the table (provisioned, or written before FIX8) is
            // refused at once and made Blocked durably by maintenance.
            recon_fails_ = 0;
            block_below_floors(now);
            engine_.delivery().end_refused_sends(now); // #16: sends the journal recovered to a revoked / left device
            if (man_dirty_ || dirty_ != 0) {
                maintenance(now); // make the repaired used bits durable
            }
        } else {
            failed_ = true; // fail closed: no joins, no admissions, and the application is told
            engine_.emit_event(LM_EVENT_FAULT, static_cast<uint32_t>(s), 0, nullptr);
        }
        rs_loaded(s); // [ISSUE5] the load a restore ended with
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
        entry_written(job_slot_index_, s == Status::Ok);
        release(-2);
        return;
    case Step::ConfirmLoad:
        confirm_loaded(s, now);
        return;
    case Step::ConfirmCommit:
        entry_written(job_slot_index_, s == Status::Ok);
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
        if (s != Status::Ok) { // FIX5-D2: RAM keeps the raised floors; written again (bounded)
            floors_dirty_ = true;
            recon_retry(now);
        } else {
            recon_fails_ = 0;
            if (dirty_ != 0) {
                maintenance(now);
            }
        }
        return;
    case Step::CommitManifest:
        if (s != Status::Ok) {
            man_dirty_ = true; // not known to be durable: written again with the next change
        }
        release(-2);
        return;
    case Step::VerifyExpected:
    case Step::CommitExpectedHeader:
    case Step::CommitExpectedEntry:
    case Step::CommitExpectedDone:
        expected_step_done(step, s, now);
        return;
    case Step::RenewLoad: // [S18]
    case Step::RenewSign:
        renew_step(step, s, now);
        return;
    case Step::LcVerify: // [S18]
    case Step::LcFloors:
    case Step::LcEntry:
    case Step::LcRetire:
    case Step::LcRetireCheck:
    case Step::LcWindow:
        lc_step(step, s, now);
        return;
    case Step::WindowReserve: // [S18]
        if (t != nullptr && t->state == TxnState::Preparing) {
            window_reserved(*t, s, now);
        }
        return;
    case Step::CommitDirty: // [FIX5-D2, FIX8-D1]
        dirty_done(s, now);
        return;
    case Step::CommitGroups: // [FIX8-D10]
        release(-2);
        groups_done(s);
        return;
    case Step::CommitPolicy: // [FIX8-D12]
        release(-2);
        policy_done(s);
        return;
    case Step::BkScan: // [ISSUE5]
    case Step::BkSeq:
    case Step::BkSign:
    case Step::BkPage:
        bk_step(step, s, now);
        return;
    case Step::RsHandover:
    case Step::RsProbe:
    case Step::RsHeader:
    case Step::RsElem:
    case Step::RsFloors:
    case Step::RsSeq:
    case Step::RsManifest:
        rs_step(step, s, now);
        return;
    case Step::None:
        return;
    }
}

// ---- timers ----
MonoTime Ledger::deadline() const {
    MonoTime next = earliest(earliest(maint_retry_, notice_until_), lc_.active ? lc_.retry_at : MonoTime::never());
    next = earliest(next, rs_.deadline); // [ISSUE5] a restore waiting for its next step gives up after a while
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
    if (!rs_.deadline.is_never() && now >= rs_.deadline &&
        (rs_.phase == RsPhase::HeaderWait || rs_.phase == RsPhase::Elements)) {
        rs_ = Restore{}; // [ISSUE5] nothing is held while it waits: the records written so far are cleared by the next one
    }
    if (now >= notice_until_) { // [S18] the revoked member's notice had its chance: its sessions end now
        notice_until_ = MonoTime::never();
        forget_member(notice_device_, notice_addr_);
    }
    if (lc_.active && now >= lc_.retry_at) { // [FIX5-D1] the retirement record is read again
        lc_.retry_at = MonoTime::never();
        retire_check(now);
    }
    if (maint_retry_ != MonoTime::never() && now >= maint_retry_) {
        maint_retry_ = MonoTime::never();
        maintenance(now);
    }
}

void Ledger::retry_txn(Txn &t, MonoTime now) {
    const uint8_t kind = t.retry_kind_;
    t.retry_kind_ = 0;
    if (kind == 1 && t.state == TxnState::Pending) {
        start_prepare(t, now);
    } else if (kind == 2 && t.state == TxnState::Session) {
        if (const Entry *e = find(t.device)) {
            answer_repeat(t, *e, now);
        }
    } else if (kind == 3 && t.state == TxnState::Preparing) { // [P4] the record memory was lent for a moment
        commit_prepared(t, now);
    } else if (kind == 4 && t.state == TxnState::Activating) {
        commit_active(t, now);
    } else if (kind == 5 && t.state == TxnState::Confirming) {
        commit_confirmed(t, now);
    } else {
        t.retry_kind_ = kind;
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
    while (leave_mask_ != 0) { // FIX8-D3: every member that asked to leave, one commit each
        const auto slot = static_cast<std::size_t>(__builtin_ctzll(leave_mask_));
        leave_mask_ &= leave_mask_ - 1U;
        if (entries_[slot].state != EntryState::Active) {
            continue; // revoked, moved or left meanwhile
        }
        job_entry_ = entries_[slot];
        job_entry_.reserved_until = MonoTime::never();
        if (commit_entry(Step::CommitLeft, slot, EntryState::Left, false, ByteView{}, -2) != Status::Ok) {
            leave_mask_ |= 1ULL << slot;
            release(-2);
            maint_retry_ = now + k_busy_retry;
        }
        return;
    }
    if (confirm_pending_) {
        rec_->arm(store::RecordJob::Op::Load, static_cast<uint16_t>(k_rec_ledger_base + confirm_.slot));
        job_slot_index_ = confirm_.slot;
        if (submit(Step::ConfirmLoad, JobClass::Flash, &store::record_job, rec_, -2) != Status::Ok) {
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
    // FIX5-D2: the durable state catches up with floors that already refuse (the floors first, then each entry).
    if (recon_fails_ < detail::k_recon_tries && floors_dirty_) {
        floors_dirty_ = false;
        if (commit_floors(Step::CommitFloors) != Status::Ok) {
            floors_dirty_ = true;
            release(-2);
            recon_retry(now);
        }
        return;
    }
    if (recon_fails_ < detail::k_recon_tries && dirty_ != 0 && start_dirty(now)) {
        return;
    }
    if (groups_pending_) { // [FIX8-D10] one registry image, committed before the set's operation ends
        std::size_t len = 0;
        if (engine_.groups().encode(MutByteView{rec_->payload}, len) == Status::Ok) {
            rec_->arm(store::RecordJob::Op::Commit, store::rec::root_groups, 0, len);
            if (submit(Step::CommitGroups, JobClass::Flash, &store::record_job, rec_, -2) == Status::Ok) {
                groups_pending_ = false;
                return;
            }
        }
        release(-2);
        maint_retry_ = now + k_busy_retry;
        return;
    }
    if (policy_pending_) { // [FIX8-D12]
        std::size_t len = 0;
        if (detail::encode_policy(policy_stage_, policy_count_ + 1, MutByteView{rec_->payload}, len) == Status::Ok) {
            rec_->arm(store::RecordJob::Op::Commit, store::rec::policy, 0, len);
            if (submit(Step::CommitPolicy, JobClass::Flash, &store::record_job, rec_, -2) == Status::Ok) {
                policy_pending_ = false;
                return;
            }
        }
        release(-2);
        maint_retry_ = now + k_busy_retry;
        return;
    }
    if (man_dirty_) {
        if (commit_manifest(man_, Step::CommitManifest) != Status::Ok) {
            release(-2);
            maint_retry_ = now + k_busy_retry;
        }
        return;
    }
    if (renew_mask_ != 0) { // [S18] last: renewals never delay a durable ledger change
        start_renew(now);
        return;
    }
    release(-2);
}

void Ledger::entry_written(std::size_t slot, bool ok) {
    const uint64_t bit = 1ULL << slot;
    if (ok) {
        doubt_ &= ~bit;
        dirty_ &= ~bit;
    } else {
        doubt_ |= bit;
    }
}

void Ledger::set_entry(std::size_t slot, const Entry &e) {
    const Entry &old = entries_[slot];
    if (old.state != EntryState::Free && old.device != e.device) {
        forget_member(old.device, old.address); // the routes through its address go with it
    } else if (old.state != EntryState::Free && old.membership != e.membership) {
        engine_.delivery().invalidate_addr(e.address); // the same device under a new membership generation
    }
    entries_[slot] = e;
}

void Ledger::mark_used(std::size_t slot) {
    if ((man_.used >> slot & 1U) == 0) {
        man_.used |= 1ULL << slot;
        man_dirty_ = true;
    }
}

// `m` carries every used bit RAM has (holder -2). man_dirty_ is cleared at submit: a change made while the job
// runs sets it again, and a failed job sets it again (CommitManifest).
Status Ledger::commit_manifest(const Manifest &m, Step step) {
    std::size_t len = 0;
    LM_TRY(encode_manifest(m, MutByteView{rec_->payload}, len));
    rec_->arm(store::RecordJob::Op::Commit, store::rec::root_ledger, 0, len);
    LM_TRY(submit(step, JobClass::Flash, &store::record_job, rec_, -2));
    man_dirty_ = false;
    return Status::Ok;
}

} // namespace lm::root
