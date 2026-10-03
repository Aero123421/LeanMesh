// ISSUE5: backup of the root's ledger and its restore onto a replacement root (docs/12 §5, docs/21 §8, protocol/control.cddl 34).
//
// Export. A backup is one cut of the durable records (backup.hpp), read from the Flash - never from RAM, which may be ahead
// (a refusal that is not durable yet). The cut is made by a chain of worker jobs, one record each, in reverse canonical order,
// folding every record into the hash chain; nothing else may write the ledger meanwhile (the chain holds the ledger's
// maintenance memory). Then the next sequence number is made durable BEFORE anything is signed on it (a power cut can lose a
// number, never repeat one), and the header is signed with the root's key on the public-key worker. The Host reads the header
// and the records page by page; a page is one Flash read, so it answers BUSY until the record is in, and the whole backup
// is dropped (CONFLICT) as soon as the ledger writes anything: the pages of one backup are always one consistent cut.
//
// Restore. A replacement root has its own identity, delegation and credential and no ledger (manifest absent: RECOVERY_REQUIRED,
// docs/12 §5). Three steps, each an operation that ends with an OPERATION event: the fleet's RootHandover that names this root,
// the old root's signed header, then the records in order. The handover is part of the restore, not installed before it:
// a root without a ledger refuses lm_install_control(31) (it must not act on a domain it cannot vouch for), and a verified
// handover alone says who the old root was - which is what ties the backup to this replacement. Every record is checked
// against the chain the signed header fixed, and only then written; the manifest, the record that makes a ledger exist, is
// written last, after the sequence number. A power cut anywhere before it leaves the root exactly as it was (RECOVERY_REQUIRED,
// no manifest); the records written so far are never read without it, and the next restore clears them first.
#include <algorithm>
#include <cstring>

#include "core/codec.hpp"
#include "core/engine.hpp"
#include "root/backup.hpp"
#include "root/ledger.hpp"
#include "root/ledger_internal.hpp"
#include "security/crypto.hpp"

namespace lm::root {
namespace {

constexpr Duration k_restore_wait = Duration::from_s(120); // between two requests of a restore
constexpr std::size_t k_candidates = 1 + k_ledger_slots + 3; // manifest, every slot, policy, groups, floors (reverse order)

// The record the scan reads at `pos`: the manifest, the slots from the last, then policy, groups, floors.
uint16_t candidate_id(std::size_t pos) {
    if (pos == 0) {
        return store::rec::root_ledger;
    }
    if (pos <= k_ledger_slots) {
        return static_cast<uint16_t>(k_rec_ledger_base + (k_ledger_slots - pos));
    }
    constexpr uint16_t k_tail[] = {store::rec::policy, store::rec::root_groups, store::rec::revocation_floors};
    return k_tail[pos - 1 - k_ledger_slots];
}

bool is_entry(uint16_t id) { return id >= k_rec_ledger_base && id < k_rec_ledger_base + k_ledger_slots; }

// What a restore may write: the ledger's own records, nothing else.
bool restorable(uint16_t id) {
    return is_entry(id) || id == store::rec::root_ledger || id == store::rec::revocation_floors ||
           id == store::rec::root_groups || id == store::rec::policy;
}

constexpr Sha256Digest k_zero{};

} // namespace

// ---- export ----
// The ledger is quiet: nothing in RAM is ahead of the records (a revocation whose commit failed refuses already; a backup
// cut from the Flash would be laxer than the root is), and no operation of the ledger is in flight.
bool Ledger::backup_ready() const { return dirty_ == 0 && doubt_ == 0 && !floors_dirty_; }

Status Ledger::backup_begin(uint64_t op, MonoTime /*now*/) {
    if (failed_ || retired_) {
        return Status::RecoveryRequired; // no ledger to vouch for (lost), or a root that acts as root no more
    }
    if (!loaded_ || rs_.phase != RsPhase::Idle || bk_.phase == BkPhase::Scan || bk_.phase == BkPhase::Seq ||
        bk_.phase == BkPhase::Sign) {
        return Status::Busy;
    }
    if (!bk_seq_ok_ || bk_seq_ >= k_u63_max) {
        return Status::RecoveryRequired; // a number that might repeat (or the last one) is never signed on
    }
    if (!backup_ready()) {
        return recon_fails_ >= detail::k_recon_tries ? Status::RecoveryRequired : Status::Busy;
    }
    if (!acquire(-2)) {
        return Status::Busy; // a join, an install or a repair holds the ledger's memory
    }
    bk_ = Backup{};
    bk_.phase = BkPhase::Scan;
    bk_.op = op;
    if (submit(Step::BkScan, JobClass::Flash, &bk_scan_job, this, -2) != Status::Ok) {
        bk_ = Backup{};
        release(-2);
        return Status::Busy;
    }
    return Status::Ok;
}

// Worker. One record per job: loaded into the record memory and folded into the chain. The manifest first (the last record
// of the canonical order): its domain must be this root's and every slot it lists must hold its record.
Status Ledger::bk_scan_job(port::JobEnv &env, void *arg) {
    auto &l = *static_cast<Ledger *>(arg);
    Backup &b = l.bk_;
    store::RecordJob &rec = *l.rec_;
    const uint16_t id = candidate_id(b.pos);
    rec.arm(store::RecordJob::Op::Load, id);
    const Status st = store::record_load(env.store, rec);
    if (st == Status::NotFound) {
        if (id == store::rec::root_ledger) {
            return Status::RecoveryRequired; // a ledger that is lost is not backed up
        }
        const bool listed = is_entry(id) && (b.used >> (id - k_rec_ledger_base) & 1U) != 0;
        return listed ? Status::RecoveryRequired : Status::Ok; // an entry the manifest lists is gone
    }
    LM_TRY(st);
    const ByteView payload{rec.payload.data(), rec.payload_len};
    if (id == store::rec::root_ledger) {
        Manifest m;
        if (detail::decode_manifest(payload, m) != Status::Ok || m.domain != l.load_domain_) {
            return Status::RecoveryRequired;
        }
        b.used = m.used;
    } else if (is_entry(id)) {
        Entry e;
        ByteView cose;
        LM_TRY(detail::decode_entry(rec, e, cose)); // a record the load itself would refuse is not a backup
        b.entries |= uint64_t{1} << (id - k_rec_ledger_base);
    } else {
        b.extras = static_cast<uint8_t>(b.extras | (id == store::rec::revocation_floors ? backup::k_extra_floors
                                                    : id == store::rec::root_groups     ? backup::k_extra_groups
                                                                                         : backup::k_extra_policy));
    }
    return backup::link(id, rec.state, payload, b.chain, b.chain);
}

void Ledger::bk_fail(Status s) {
    const uint64_t op = bk_.op;
    bk_ = Backup{};
    release(-2);
    engine_.emit_event(LM_EVENT_OPERATION, static_cast<uint32_t>(s), op, nullptr);
}

void Ledger::bk_scanned(MonoTime /*now*/) {
    // The sequence number first: durable before a signature exists on it.
    std::size_t len = 0;
    Writer w{MutByteView{rec_->payload}};
    w.u64be(bk_seq_ + 1);
    len = w.size();
    rec_->arm(store::RecordJob::Op::Commit, store::rec::ledger_backup_seq, 0, len);
    bk_.phase = BkPhase::Seq;
    if (w.finish() != Status::Ok || submit(Step::BkSeq, JobClass::Flash, &store::record_job, rec_, -2) != Status::Ok) {
        bk_fail(Status::Busy); // nothing was written
    }
}

void Ledger::bk_step(Step step, Status s, MonoTime now) {
    if (step == Step::BkPage) { // a page read for the Host: the record memory goes back at once
        bk_.page_loading = false;
        bk_.page_status = s;
        if (s == Status::Ok && rec_ != nullptr && rec_->id != 0 && rec_->payload_len <= bk_page_.size()) {
            std::memcpy(bk_page_.data(), rec_->payload.data(), rec_->payload_len);
            bk_.page_len = rec_->payload_len;
            bk_.page_id = rec_->id;
            bk_.page_state = rec_->state;
        } else if (s == Status::Ok) {
            bk_.page_status = Status::StorageFailure;
        }
        release(-2);
        return;
    }
    if (bk_.phase == BkPhase::Idle) {
        return; // the backup was dropped while the step ran
    }
    if (s != Status::Ok) {
        // A failed seq commit may have reached the Flash: the next backup goes on from the RAM value, so a number is at
        // worst skipped, never signed twice (nothing was signed on this one).
        bk_fail(s == Status::StorageFailure || s == Status::NotFound ? Status::RecoveryRequired : s);
        return;
    }
    if (step == Step::BkScan) {
        if (++bk_.pos < k_candidates) {
            if (submit(Step::BkScan, JobClass::Flash, &bk_scan_job, this, -2) != Status::Ok) {
                bk_fail(Status::Busy);
            }
            return;
        }
        bk_scanned(now);
        return;
    }
    if (step == Step::BkSeq) {
        ++bk_seq_;
        bk_.seq = bk_seq_;
        bk_.change = change_; // after the sequence commit (it is no ledger content): the cut is what the scan saw
        const member::LocalIdentity &id = engine_.identity();
        bk_hdr_ = backup::Header{};
        bk_hdr_.seq = bk_.seq;
        bk_hdr_.term = id.term().value();
        bk_hdr_.generation = id.delegation().generation;
        bk_hdr_.delegation = id.delegation_cose();
        bk_hdr_.change = bk_.change;
        bk_hdr_.entries = bk_.entries;
        bk_hdr_.extras = bk_.extras;
        bk_hdr_.head = bk_.chain;
        bk_key_ = id.key();
        bk_env_ = member::Envelope{};
        bk_env_.type = member::k_type_ledger_backup;
        engine_.random(MutByteView{bk_env_.request.bytes});
        bk_env_.domain = id.delegation().domain;
        bk_env_.issuer = id.self();
        bk_env_.revision = bk_.seq;
        bk_.phase = BkPhase::Sign;
        if (submit(Step::BkSign, JobClass::PublicKey, &bk_sign_job, this, -2) != Status::Ok) {
            bk_fail(Status::Busy); // the one public-key slot is busy: the number is used up, a later backup takes the next
        }
        return;
    }
    // BkSign: the backup is held.
    bk_.phase = BkPhase::Ready;
    const uint64_t op = bk_.op;
    release(-2);
    engine_.emit_event(LM_EVENT_OPERATION, 0, op, nullptr);
}

// Worker (public key). The header of the cut, signed by this root: type 34, kid = its DeviceId, revision = the sequence.
Status Ledger::bk_sign_job(port::JobEnv & /*env*/, void *arg) {
    auto &l = *static_cast<Ledger *>(arg);
    std::array<uint8_t, 640> data{};
    std::size_t dlen = 0;
    LM_TRY(backup::encode_header(l.bk_hdr_, MutByteView{data}, dlen));
    std::size_t len = 0;
    LM_TRY(member::issue_signed(l.bk_key_, l.bk_env_, ByteView{data.data(), dlen}, MutByteView{l.bk_cose_}, len));
    l.bk_.cose_len = len;
    return Status::Ok;
}

Status Ledger::backup_get(uint64_t seq, uint32_t index, BackupPage &out, MonoTime /*now*/) {
    if (!loaded_ || bk_.phase != BkPhase::Ready) {
        return bk_.phase == BkPhase::Idle ? Status::NotFound : Status::Busy;
    }
    if (seq != bk_.seq && !(seq == 0 && index == 0)) { // (seq 0 asks for the header of the backup held: its number is in it)
        return Status::Conflict; // another backup was made since
    }
    if (bk_.change != change_) {
        bk_ = Backup{}; // the ledger wrote something: this cut is stale, a page of it would not match its chain
        return Status::Conflict;
    }
    backup::Header cut;
    cut.entries = bk_.entries;
    cut.extras = bk_.extras;
    const auto count = static_cast<uint32_t>(cut.count());
    if (index > count) {
        return Status::InvalidArgument;
    }
    out = BackupPage{};
    out.index = index;
    out.count = count;
    if (index == 0) {
        out.data = ByteView{bk_cose_.data(), bk_.cose_len};
        return Status::Ok;
    }
    if (bk_.page_index == index && !bk_.page_loading && bk_.page_status == Status::Ok) {
        out.id = bk_.page_id;
        out.state = bk_.page_state;
        out.data = ByteView{bk_page_.data(), bk_.page_len};
        return Status::Ok;
    }
    if (bk_.page_loading) {
        return Status::Busy;
    }
    if (bk_.page_index == index && bk_.page_status != Status::Ok) {
        const Status failed = bk_.page_status; // a read that failed is told once; the next ask reads again
        bk_.page_index = 0;
        bk_.page_status = Status::Ok;
        return failed == Status::NotFound ? Status::RecoveryRequired : failed;
    }
    if (!acquire(-2)) {
        return Status::Busy;
    }
    rec_->arm(store::RecordJob::Op::Load, backup::element_id(cut, index - 1U));
    bk_.page_index = index;
    bk_.page_loading = true;
    bk_.page_status = Status::Ok;
    if (submit(Step::BkPage, JobClass::Flash, &bk_page_job, this, -2) != Status::Ok) {
        bk_.page_index = 0;
        bk_.page_loading = false;
        release(-2);
    }
    return Status::Busy;
}

Status Ledger::bk_page_job(port::JobEnv &env, void *arg) {
    auto &l = *static_cast<Ledger *>(arg);
    return store::record_load(env.store, *l.rec_);
}

// ---- restore ----
// Takes the ledger's memory and starts the step's job. Busy: nothing was started.
Status Ledger::rs_begin(Step step, JobClass cls, port::JobFn fn, uint64_t op) {
    if (job_in_flight_ || !acquire(-2)) {
        return Status::Busy;
    }
    if (submit(step, cls, fn, this, -2) != Status::Ok) {
        release(-2);
        return Status::Busy;
    }
    rs_.op = op;
    return Status::Ok;
}

// The root has no ledger to restore onto: Conflict when it has one (or is loading it), RecoveryRequired when it is not even
// a member (nothing to authenticate the restore with).
static Status restorable_state(bool failed, bool loaded, bool member) {
    if (!member) {
        return Status::RecoveryRequired;
    }
    if (failed) {
        return Status::Ok;
    }
    return loaded ? Status::Conflict : Status::Busy;
}

Status Ledger::restore_handover(ByteView cose, uint64_t op, MonoTime now) {
    LM_TRY(restorable_state(failed_, loaded_, engine_.identity().is_member() && engine_.config().role == Role::Root));
    if (cose.empty() || cose.size() > backup::k_cose_max) {
        return Status::PayloadTooLarge;
    }
    if (rs_.phase == RsPhase::Handover || rs_.phase == RsPhase::Probe || rs_.phase == RsPhase::Header ||
        rs_.phase == RsPhase::Element || rs_.phase == RsPhase::Seq || rs_.phase == RsPhase::Manifest ||
        rs_.phase == RsPhase::Loading) {
        return Status::Busy; // a step is running: it is not interrupted
    }
    const member::LocalIdentity &id = engine_.identity();
    vargs_.trust = id.trust();
    vargs_.delegation = id.delegation();
    vargs_.term = id.term();
    if (sec::sha256(id.delegation_cose(), vargs_.delegation_hash) != Status::Ok) {
        return Status::RecoveryRequired;
    }
    std::memcpy(bk_cose_.data(), cose.data(), cose.size());
    bk_.cose_len = cose.size();
    rs_ = Restore{}; // (a restore that waited for its next step starts again)
    rs_.phase = RsPhase::Handover;
    const Status st = rs_begin(Step::RsHandover, JobClass::PublicKey, &rs_handover_job, op);
    if (st != Status::Ok) {
        rs_ = Restore{};
    }
    (void)now;
    return st;
}

// Worker. The fleet's RootHandover names THIS root: its delegation (hash, generation) and a first term it has reached
// (the same rules as the install on a member, FIX5-D4).
Status Ledger::rs_handover_job(port::JobEnv & /*env*/, void *arg) {
    auto &l = *static_cast<Ledger *>(arg);
    const VerifyArgs &v = l.vargs_;
    member::Envelope env;
    ByteView data;
    member::RootHandover h;
    LM_TRY(member::open_signed(ByteView{l.bk_cose_.data(), l.bk_.cose_len}, v.trust.key, member::k_type_root_handover, env,
                               data));
    LM_TRY(member::decode_handover(data, h));
    if (env.domain != v.delegation.domain) {
        return Status::NetworkMismatch;
    }
    LM_TRY(member::check_handover(h));
    if (member::handover_to(h, v.delegation.root, v.delegation.generation, v.delegation_hash) != Status::Ok ||
        v.term < h.new_term) {
        return Status::NetworkMismatch; // another root or delegation, or a term this root has not reached
    }
    l.rs_.ho = h;
    return Status::Ok;
}

// Worker (Flash). The manifest must not exist (a root with a ledger is never restored over); the records an earlier,
// unfinished restore may have left are made neutral: an entry slot is a Free record, the registry empty, the policy the default.
// Without a manifest none of them is read, but a later manifest would claim them.
Status Ledger::rs_probe_job(port::JobEnv &env, void *arg) {
    auto &l = *static_cast<Ledger *>(arg);
    store::RecordJob &rec = *l.rec_;
    rec.arm(store::RecordJob::Op::Load, store::rec::root_ledger);
    const Status m = store::record_load(env.store, rec);
    if (m == Status::Ok) {
        return Status::Conflict; // this root has a ledger
    }
    if (m != Status::NotFound) {
        return Status::RecoveryRequired; // quarantined or unreadable: not a ledger that is absent
    }
    // The sequence number this root knows of: a backup below it is older than a state this root has seen.
    rec.arm(store::RecordJob::Op::Load, store::rec::ledger_backup_seq);
    const Status sq = store::record_load(env.store, rec);
    l.rs_.own_seq = 0;
    if (sq == Status::Ok && rec.payload_len == 8) {
        Reader r{ByteView{rec.payload.data(), rec.payload_len}};
        l.rs_.own_seq = r.u64be();
    } else if (sq != Status::NotFound) {
        return Status::RecoveryRequired; // unreadable: no restore on a number that might be below it
    }
    std::size_t len = 0;
    for (std::size_t slot = 0; slot < k_ledger_slots; ++slot) {
        const auto id = static_cast<uint16_t>(k_rec_ledger_base + slot);
        rec.arm(store::RecordJob::Op::Load, id);
        Status st = store::record_load(env.store, rec);
        if (st == Status::NotFound || (st == Status::Ok && rec.state == static_cast<uint8_t>(EntryState::Free))) {
            continue;
        }
        LM_TRY(st == Status::Ok ? Status::Ok : Status::RecoveryRequired);
        LM_TRY(detail::encode_entry(Entry{}, false, ByteView{}, MutByteView{rec.payload}, len));
        rec.arm(store::RecordJob::Op::Commit, id, static_cast<uint8_t>(EntryState::Free), len);
        LM_TRY(store::record_commit(env.store, rec));
    }
    for (const uint16_t id : {store::rec::root_groups, store::rec::policy}) {
        rec.arm(store::RecordJob::Op::Load, id);
        const Status st = store::record_load(env.store, rec);
        if (st == Status::NotFound) {
            continue;
        }
        LM_TRY(st == Status::Ok ? Status::Ok : Status::RecoveryRequired);
        if (id == store::rec::root_groups) {
            rec.payload[0] = k_groups_record_version;
            rec.payload[1] = 0;
            len = 2;
        } else {
            LM_TRY(detail::encode_policy(JoinMode::External, 0, MutByteView{rec.payload}, len));
        }
        rec.arm(store::RecordJob::Op::Commit, id, 0, len);
        LM_TRY(store::record_commit(env.store, rec));
    }
    return Status::Ok;
}

Status Ledger::restore_header(ByteView cose, uint64_t op, MonoTime /*now*/) {
    if (rs_.phase != RsPhase::HeaderWait) {
        return Status::Conflict; // no restore waits for a header (the handover comes first)
    }
    if (cose.empty() || cose.size() > backup::k_cose_max) {
        return Status::PayloadTooLarge;
    }
    if (job_in_flight_ || holder_ != -1) {
        return Status::Busy;
    }
    const member::LocalIdentity &id = engine_.identity();
    vargs_.trust = id.trust();
    vargs_.delegation = id.delegation();
    std::memcpy(bk_cose_.data(), cose.data(), cose.size());
    bk_.cose_len = cose.size();
    rs_.phase = RsPhase::Header;
    rs_.deadline = MonoTime::never();
    const Status st = rs_begin(Step::RsHeader, JobClass::PublicKey, &rs_header_job, op);
    if (st != Status::Ok) {
        rs_.phase = RsPhase::HeaderWait;
        rs_.deadline = engine_.step_time() + k_restore_wait;
    }
    return st;
}

// Worker. The chain of trust of a backup: the fleet's anchor -> the old root's delegation in the header -> the old root's
// signature over the header. The old root is the one the handover hands over from, in the delegation generation it names;
// the domain is this root's; the sequence in the envelope is the header's.
Status Ledger::rs_header_job(port::JobEnv & /*env*/, void *arg) {
    auto &l = *static_cast<Ledger *>(arg);
    const VerifyArgs &v = l.vargs_;
    const ByteView cose{l.bk_cose_.data(), l.bk_.cose_len};
    member::Envelope env;
    ByteView data;
    backup::Header h;
    LM_TRY(member::peek_signed(cose, member::k_type_ledger_backup, env, data)); // structure only: to reach the delegation
    LM_TRY(backup::decode_header(data, h));
    member::RootDelegation d;
    LM_TRY(member::check_root_delegation(v.trust, h.delegation, d));
    if (d.domain != v.delegation.domain || d.root != l.rs_.ho.old_root || d.generation != l.rs_.ho.old_generation ||
        d.generation != h.generation) {
        return Status::NetworkMismatch;
    }
    LM_TRY(member::open_signed(cose, d.key, member::k_type_ledger_backup, env, data));
    if (env.domain != v.delegation.domain || env.issuer != d.root || env.revision != h.seq) {
        return Status::AuthRejected;
    }
    if (h.term >= l.rs_.ho.new_term.value()) {
        return Status::Conflict; // signed in a term the handover's first term does not follow
    }
    if (h.seq < l.rs_.own_seq) {
        return Status::Conflict; // older than a backup sequence this root has seen: restoring it would roll the ledger back
    }
    h.delegation = ByteView{};
    l.rs_.hdr = h;
    return Status::Ok;
}

Status Ledger::restore_element(const RestoreElement &e, uint64_t op, MonoTime now) {
    if (rs_.phase != RsPhase::Elements) {
        return rs_.phase == RsPhase::Element || rs_.phase == RsPhase::Seq || rs_.phase == RsPhase::Manifest ? Status::Busy
                                                                                                          : Status::Conflict;
    }
    if (e.index != rs_.index) {
        return Status::Conflict; // the records go in order
    }
    if (e.id != backup::element_id(rs_.hdr, e.index) || !restorable(e.id) || e.payload.size() > bk_page_.size() ||
        (is_entry(e.id) && e.state > static_cast<uint8_t>(EntryState::Blocked))) {
        return Status::InvalidArgument;
    }
    if (job_in_flight_ || holder_ != -1) {
        return Status::Busy;
    }
    std::memcpy(bk_page_.data(), e.payload.data(), e.payload.size());
    rs_.id = e.id;
    rs_.state = e.state;
    rs_.len = e.payload.size();
    rs_.next = e.next;
    rs_.phase = RsPhase::Element;
    rs_.deadline = MonoTime::never();
    const Status st = rs_begin(Step::RsElem, JobClass::Flash, &rs_elem_job, op);
    if (st != Status::Ok) {
        rs_.phase = RsPhase::Elements;
        rs_.deadline = now + k_restore_wait;
    }
    return st;
}

// Worker. The record is the one the signed header fixed at this place of the chain; only then is it checked for its own
// shape and written. The manifest is checked here and written last (rs_write_manifest). The floors are merged by the owner.
Status Ledger::rs_elem_job(port::JobEnv &env, void *arg) {
    auto &l = *static_cast<Ledger *>(arg);
    Restore &r = l.rs_;
    const ByteView payload{l.bk_page_.data(), r.len};
    Sha256Digest h{};
    LM_TRY(backup::link(r.id, r.state, payload, r.next, h));
    if (!sec::ct_equal(ByteView{h}, ByteView{r.expect})) {
        return Status::AuthRejected; // not the record the signed header names at this place
    }
    if (r.index + 1 == r.hdr.count() && r.next != k_zero) {
        return Status::AuthRejected; // the chain ends after the manifest
    }
    store::RecordJob &rec = *l.rec_;
    if (r.id == store::rec::revocation_floors) {
        member::Floors f;
        return member::decode_floors(payload, f);
    }
    if (r.id == store::rec::root_ledger) {
        Manifest m;
        return detail::decode_manifest(payload, m) == Status::Ok && m.domain == l.load_domain_ ? Status::Ok
                                                                                              : Status::BadFrame;
    }
    if (is_entry(r.id)) {
        std::memcpy(rec.payload.data(), payload.data(), payload.size());
        rec.payload_len = static_cast<uint32_t>(payload.size());
        rec.state = r.state;
        Entry e;
        ByteView cose;
        LM_TRY(detail::decode_entry(rec, e, cose));
    } else if (r.id == store::rec::policy) {
        JoinMode mode;
        uint64_t changes = 0;
        LM_TRY(detail::decode_policy(payload, mode, changes));
    } else if (payload.size() < 2 || payload[0] != k_groups_record_version) { // the registry: Groups::restore reads the rest
        return Status::BadFrame;
    }
    std::memcpy(rec.payload.data(), payload.data(), payload.size());
    rec.arm(store::RecordJob::Op::Commit, r.id, r.state, payload.size());
    return store::record_commit(env.store, rec);
}

// The sequence number of the backup becomes this root's own floor: its next backup goes on above it, and the Host (which
// keeps the newest sequence per domain) accepts it.
Status Ledger::rs_seq_job(port::JobEnv &env, void *arg) {
    auto &l = *static_cast<Ledger *>(arg);
    store::RecordJob &rec = *l.rec_;
    rec.arm(store::RecordJob::Op::Load, store::rec::ledger_backup_seq);
    const Status st = store::record_load(env.store, rec);
    if (st == Status::Ok) {
        Reader r{ByteView{rec.payload.data(), rec.payload_len}};
        const uint64_t have = r.u64be();
        if (r.finish() != Status::Ok) {
            return Status::RecoveryRequired;
        }
        if (have >= l.rs_.hdr.seq) {
            return Status::Ok; // this root signed above it already
        }
    } else if (st != Status::NotFound) {
        return Status::RecoveryRequired;
    }
    Writer w{MutByteView{rec.payload}};
    w.u64be(l.rs_.hdr.seq);
    LM_TRY(w.finish());
    rec.arm(store::RecordJob::Op::Commit, store::rec::ledger_backup_seq, 0, w.size());
    return store::record_commit(env.store, rec);
}

void Ledger::rs_fail(Status s) {
    const uint64_t op = rs_.op;
    // Refused by the handover / header / a record: the restore ends. A step that ran into the store may have written (the
    // manifest never), so the ledger is still absent: the same restore again starts by clearing what is there.
    rs_ = Restore{};
    release(-2);
    engine_.emit_event(LM_EVENT_OPERATION, static_cast<uint32_t>(s), op, nullptr);
}

// A step ended Ok and asks for the next one: the memory goes back (the Host's round trip is long), the idle timer runs.
void Ledger::rs_wait(MonoTime now, Status s) {
    const uint64_t op = rs_.op;
    rs_.phase = rs_.index == 0 && rs_.hdr.seq == 0 ? RsPhase::HeaderWait : RsPhase::Elements;
    rs_.deadline = now + k_restore_wait;
    release(-2);
    engine_.emit_event(LM_EVENT_OPERATION, static_cast<uint32_t>(s), op, nullptr);
}

void Ledger::rs_merge_floors(MonoTime now) {
    member::Floors f;
    member::Floors &live = engine_.identity().floors();
    if (member::decode_floors(ByteView{bk_page_.data(), rs_.len}, f) != Status::Ok) {
        rs_fail(Status::BadFrame);
        return;
    }
    for (std::size_t i = 0; i < f.count(); ++i) {
        if (live.raise(f.at(i).device, f.at(i).assignment, f.at(i).membership) != Status::Ok) {
            rs_fail(Status::NoCapacity); // the table cannot hold the old root's floors too: nothing may be dropped
            return;
        }
    }
    if (commit_floors(Step::RsFloors) != Status::Ok) {
        rs_fail(Status::Busy);
    }
    (void)now;
}

void Ledger::rs_write_manifest(MonoTime /*now*/) {
    std::memcpy(rec_->payload.data(), bk_page_.data(), rs_.len);
    rec_->arm(store::RecordJob::Op::Commit, store::rec::root_ledger, 0, rs_.len);
    rs_.phase = RsPhase::Manifest;
    if (submit(Step::RsManifest, JobClass::Flash, &store::record_job, rec_, -2) != Status::Ok) {
        rs_fail(Status::Busy);
    }
}

void Ledger::rs_step(Step step, Status s, MonoTime now) {
    if (rs_.phase == RsPhase::Idle) {
        return; // the restore was dropped while the step ran
    }
    if (step == Step::RsManifest) {
        // Whatever the commit answered, the record decides: a manifest that reached the Flash is a ledger (a failed
        // read-back after a durable write), none is the root as it was. The load reads it and ends the operation.
        rs_.phase = RsPhase::Loading;
        const uint64_t op = rs_.op;
        release(-2);
        rs_.op = op;
        on_identity_ready(now);
        return;
    }
    if (s != Status::Ok) {
        // A refused handover / header / record is a clean refusal; a failed write may or may not have landed: the
        // records are not read without the manifest, so it is the same: RECOVERY_REQUIRED for the store, the status for
        // the rest.
        rs_fail(s == Status::StorageFailure || s == Status::NotFound ? Status::RecoveryRequired : s);
        return;
    }
    switch (step) {
    case Step::RsHandover:
        rs_.phase = RsPhase::Probe;
        if (submit(Step::RsProbe, JobClass::Flash, &rs_probe_job, this, -2) != Status::Ok) {
            rs_fail(Status::Busy);
        }
        return;
    case Step::RsProbe:
        rs_.phase = RsPhase::HeaderWait;
        rs_wait(now, Status::Ok);
        return;
    case Step::RsHeader:
        rs_.expect = rs_.hdr.head;
        rs_.index = 0;
        rs_wait(now, Status::Ok);
        return;
    case Step::RsElem:
        rs_.expect = rs_.next;
        if (rs_.id == store::rec::revocation_floors) {
            rs_merge_floors(now);
            return;
        }
        if (rs_.id == store::rec::root_ledger) { // the last record: the sequence number, then the manifest
            rs_.phase = RsPhase::Seq;
            if (submit(Step::RsSeq, JobClass::Flash, &rs_seq_job, this, -2) != Status::Ok) {
                rs_fail(Status::Busy);
            }
            return;
        }
        ++rs_.index;
        rs_wait(now, Status::Ok);
        return;
    case Step::RsFloors:
        ++rs_.index;
        rs_wait(now, Status::Ok);
        return;
    case Step::RsSeq:
        rs_write_manifest(now);
        return;
    default:
        return;
    }
}

// The load that follows the manifest has ended (Ledger::handle_step LoadAll): the restore's last operation ends with it.
void Ledger::rs_loaded(Status s) {
    if (rs_.phase != RsPhase::Loading) {
        return;
    }
    const uint64_t op = rs_.op;
    rs_ = Restore{};
    engine_.emit_event(LM_EVENT_OPERATION, s == Status::Ok ? 0U : static_cast<uint32_t>(Status::RecoveryRequired), op,
                       nullptr);
}

} // namespace lm::root
