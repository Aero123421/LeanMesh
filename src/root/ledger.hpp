// Root side of membership (docs/07 §4, docs/12 §4, docs/21 §5): the member ledger, the expected
// entries, and the Join transactions with unjoined devices. One durable record per ledger slot
// (a slot is a fixed short address: address = 2 + index), so one commit is one atomic ledger change:
//
//   Expected --JoinRequest verified--> Prepared --JoinStored--> Active(unconfirmed) --JoinActive--> Active
//   Prepared --reservation 120 s / restart--> Aborted        Active --LeaveRequest--> Left
//
// A COMMITTED (Active) entry is never moved back to Aborted by a timeout, and a late COMMIT/STORED
// for an Aborted request is refused (docs/21 §5). One request_id maps to one reservation and one
// prepare hash: the same request with other content is CONFLICT and never gets a second address.
// Entry state after each cut (docs/12 §4): before the PREPARED commit the ledger is unchanged; after
// it Prepared; after the ACTIVE commit Active/unconfirmed; the device's own evidence completes it.
//
// The ledger is bound to its domain by a manifest record (SEC-D5): a domain root that finds no manifest, or
// one of another domain, or no record for a slot the manifest says was used, is RECOVERY_REQUIRED and admits
// nobody (docs/12 §5: a lost ledger never restarts as an empty one). Only the provisioning of a new network
// writes the first manifest (encode_manifest). Every Link and End session of the root, in either direction,
// needs an ACTIVE entry of exactly that device, address, assignment and membership (SEC-D2, link_admit()).
//
// Shared-resource rules: one join transaction at a time holds the exchange's credential buffer and the
// identity's record memory (docs/IMPLEMENTATION.md §13), from the JoinRequest until its final
// acknowledgement; other joiners see Busy (their exchange is dropped, they retry). The worker runs one
// job at a time for the ledger; the public-key jobs (ticket check, credential signature) are matched by
// (job table, slot handle) like every other completion.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "core/bytes.hpp"
#include "core/ids.hpp"
#include "core/jobs.hpp"
#include "core/link/exchange.hpp"
#include "core/member/credentials.hpp"
#include "core/member/join.hpp"
#include "core/member/join_wire.hpp"
#include "core/pool.hpp"
#include "core/profile.hpp"
#include "core/time.hpp"
#include "leanmesh.h"
#include "store/record.hpp"

namespace lm {
class Engine;
}

namespace lm::root {

inline constexpr uint16_t k_rec_ledger_base = 0x100;      // entry records: base + slot
inline constexpr std::size_t k_ledger_slots = gen::k_profile_root.members; // 64
inline constexpr std::size_t k_join_txns = gen::k_profile_root.join_slots; // 4
inline constexpr uint32_t k_tag_ledger = 0x4A520000;      // "JR"+i: the root's join pipes (one tag per txn)
inline constexpr uint32_t k_tag_offer = 0x4A4F0000;       // "JO": the discovery offer (broadcast)
inline constexpr Duration k_reservation = Duration::from_ms(120000); // registry/defaults prepared_timeout_ms
inline constexpr Duration k_approval_timeout = Duration::from_ms(300000);
inline constexpr Duration k_member_lease = Duration::from_s(15 * 60); // docs/06 §7: at most 15 min
inline constexpr Duration k_renew_before = Duration::from_s(5 * 60);  // docs/06 §7: renewed after ~10 min
inline constexpr Duration k_renew_gap = Duration::from_s(60);         // one renewal per member per READY period

enum class EntryState : uint8_t { Free = 0, Expected = 1, Prepared = 2, Active = 3, Left = 4, Aborted = 5, Blocked = 6 };
static_assert(k_ledger_slots <= 64, "the manifest's used-slot bitmap is 64 bits");

// store::rec::root_ledger (SEC-D5, SEC-D7): version u8 (1) | domain 16 | expected revision u64 | used slots u64
// (bit i: slot i holds an entry record; set once, never cleared) | set hash 32 | pages u8 | received u16 |
// pending u16 | 16 x page digest 8. The ExpectedSet revision being installed is one signed set: every page carries
// its set hash and page count; `received` are the pages applied, `pending` the pages whose entries are being (or
// were partly) applied, and a page's digest (SHA-256 of its data, first 8 bytes) fixes what that page is.
struct Manifest {
    DomainId domain;
    uint64_t expected_revision = 0;
    uint64_t used = 0;
    Sha256Digest set_hash{};
    uint8_t pages = 0;
    uint16_t received = 0;
    uint16_t pending = 0;
    std::array<std::array<uint8_t, 8>, 16> digests{};
};
inline constexpr uint8_t k_manifest_version = 1;
inline constexpr std::size_t k_manifest_bytes = 1 + 16 + 8 + 8 + 32 + 1 + 2 + 2 + 16 * 8;

// store::rec::commissioning_window (FIX5-D6): version u8 (1) | policy revision u64 | window id 16 | expected revision u64
// | max new members u8 | allowed roles u8 | reservations u8. The policy revision is the window replay floor: a window of
// a lower revision, or another window (id or budget) at the counted revision, is refused; the same window again - also
// re-issued for a new term with new times (docs/21 §2) - goes on with its count. Nothing a replay can present resets it.
// The record holds the counted window's fields themselves (no digest of them is needed to compare).
struct WindowRecord {
    uint64_t policy_revision = 0;
    std::array<uint8_t, 16> id{};
    uint64_t expected_revision = 0;
    uint8_t max_new_members = 0;
    uint8_t allowed_roles = 0;
    uint8_t used = 0;     // reservations counted, each before its PREPARED entry (a cut over-counts, never under)
    bool present = false; // RAM: a record exists (loaded or committed)
    [[nodiscard]] bool same_window(const member::CommissioningWindow &w) const {
        return present && w.policy_revision == policy_revision && w.id == id && w.expected_revision == expected_revision &&
               w.max_new_members == max_new_members && w.allowed_roles == allowed_roles;
    }
};
inline constexpr uint8_t k_window_record_version = 1; // 36 B
[[nodiscard]] Status encode_manifest(const Manifest &m, MutByteView out, std::size_t &len);
// Bench provisioning only (tools/lmfleet): the ACTIVE entry record of a member whose credential was issued
// outside a join (address 2..65 is its slot). Out: the record id and its payload; the record state is Active.
[[nodiscard]] Status encode_provisioned_member(const member::MemberCredential &mc, ByteView member_cose,
                                               uint16_t &record_id, MutByteView out, std::size_t &len);
enum class JoinMode : uint8_t { Closed = 0, External = 1, Preapproved = 2 };

struct Entry {
    DeviceId device;
    Sha256Digest hash{};      // Expected: SHA-256 of the granting ticket; else SHA-256 of the JoinRequest content
    RequestId request;        // the request that reserved / activated it
    uint64_t assignment = 0;  // Expected: the assignment generation to be granted; else the one issued
    uint64_t membership = 0;  // the last membership generation issued to this device (never reused)
    // SEC-D4: the highest assignment generation this device ever made ACTIVE here. A ticket at or below it is a
    // consumed grant, whatever its mode or the join policy; never lowered (expected pages keep it).
    uint64_t consumed = 0;
    ShortAddr address;        // 2 + slot: the slot is the address
    EntryState state = EntryState::Free;
    bool confirmed = false;   // Active: the device's own JOIN_ACTIVE evidence was recorded
    bool recovered = false;   // Prepared and read at boot: its reservation deadline is unknown
    // RAM only: the reservation deadline while Prepared; while Active [S18] the earliest next renewal.
    MonoTime reserved_until = MonoTime::never();
};

// Decision of the operator for a pending (external mode) request. Root-local command (D4).
struct JoinDecision {
    RequestId request;
    bool approve = false;
    // [S13] The Host re-checks who it approves: with `verify` a request whose device or credential hash
    // differs from these is CONFLICT and stays pending (docs/19 §4 JOIN_DECIDE).
    bool verify = false;
    DeviceId device;
    Sha256Digest credential{};
};
// A request waiting for the operator's decision (external mode), as the Host is told about it.
struct PendingJoin {
    RequestId request;
    DeviceId device;
    Sha256Digest credential{}; // SHA-256 of the DeviceCredential the joiner presented
};

class Ledger {
  public:
    explicit Ledger(Engine &engine);
    Ledger(const Ledger &) = delete;
    Ledger &operator=(const Ledger &) = delete;

    // ---- Engine wiring ----
    void on_identity_ready(MonoTime now); // root only: loads the ledger from Flash
    void on_job_done(Handle slot, Status s, MonoTime now);
    void on_tx_outcome(const TxOutcome &o, MonoTime now);
    void on_timer(MonoTime now);
    [[nodiscard]] MonoTime deadline() const;
    void stop();
    // link::JoinHooks trampolines
    [[nodiscard]] bool responder_open() const;
    // SEC-D2: may a Link or End session (either direction) with this verified member be installed?
    [[nodiscard]] bool link_admit(const DeviceId &device, const member::MemberCredential &mc) const;
    // FIX5-D2: an entry authorises its device only while it is ACTIVE and above every revocation floor. A lifecycle
    // install raises the floors (RAM, at once) before the entry changes; until then, and when the entry's commit failed,
    // the floors alone refuse the device - for sessions, routes, groups, renewals and what the Host is shown.
    [[nodiscard]] bool authorizes(const Entry &e) const;
    [[nodiscard]] const Entry *authorized(const DeviceId &d) const; // the entry of `d` if it authorises it, else null
    // What the entry means now (the Host's node view): an ACTIVE entry below a floor reads as Blocked.
    [[nodiscard]] EntryState effective(const Entry &e) const;
    // SEC-D2: can any admission be decided? Busy until the ledger is loaded, RecoveryRequired once it is lost.
    [[nodiscard]] Status admission() const {
        return failed_ || retired_ ? Status::RecoveryRequired : (loaded_ ? Status::Ok : Status::Busy);
    }
    void session_up(const MacAddr &mac, const DeviceId &peer, const Sha256Digest &peer_dc_hash, MonoTime now);
    void discovery(const MacAddr &src, const wire::BootstrapCarrier &c, MonoTime now);
    void join_control(const link::RxInfo &info, ByteView plain, MonoTime now);
    [[nodiscard]] bool link_control(const link::RxInfo &info, ByteView plain, MonoTime now);

    // ---- commands ----
    void set_join_mode(JoinMode m) { mode_ = m; } // bench/meshsim: RAM only (the product path is set_policy_mode)
    [[nodiscard]] JoinMode join_mode() const { return mode_; }
    // FIX8-D12 (lm_policy_set): the join mode as part of the root's policy. The change is committed
    // (store::rec::policy) and only then applied and reported (OPERATION `op`). Busy while one is being committed; RecoveryRequired once a
    // commit's result was unknown (the stored record decides at the next start; until then the root is CLOSED).
    [[nodiscard]] Status set_policy_mode(JoinMode m, uint64_t op, MonoTime now);
    // The ledger's share of the policy revision: the join-mode changes committed so far (lm_policy_get adds the
    // coordinator's channel changes to it; one revision, compare-and-set on the sum).
    [[nodiscard]] uint64_t policy_changes() const { return policy_count_; }
    [[nodiscard]] bool policy_in_doubt() const { return policy_doubt_; }
    // FIX8-D10: the group registry (root::Groups) has a change to commit (store::rec::root_groups): maintenance.
    void want_groups_commit(MonoTime now);
    // Signed ExpectedSet page (fleet, or the delegated root with the approve permission): verified on the
    // worker, then each entry is one commit. Completion: LM_EVENT_OPERATION with the returned id.
    [[nodiscard]] Status install_expected(ByteView signed_cose, MonoTime now, uint64_t &operation);
    // Approves or refuses a pending request (external mode). NotFound: no such pending request.
    [[nodiscard]] Status decide(const JoinDecision &d, MonoTime now);

    // ---- observability (tests, diagnostics) ----
    enum class TxnState : uint8_t {
        Free,
        Session,    // JOIN_ONLY session up, waiting for the JoinRequest
        Verifying,  // ticket check on the worker
        Pending,    // waiting for the operator's decision (external mode)
        Signing,    // MemberCredential signature on the worker
        Preparing,  // committing the PREPARED entry
        PrepareOut, // JoinPrepare sent, waiting for JoinStored
        Activating, // committing the ACTIVE entry
        CommitOut,  // JoinCommit sent, waiting for JoinActive
        Confirming, // committing the confirmed flag
        Linger,     // refusal / final ack sent: the session ends shortly
    };
    [[nodiscard]] bool ready() const { return loaded_; }
    [[nodiscard]] bool failed() const { return failed_; }
    [[nodiscard]] bool job_pending() const { return job_in_flight_; } // lm_destroy waits for the worker
    [[nodiscard]] const Entry *find(const DeviceId &d) const;
    [[nodiscard]] const Entry &entry(std::size_t slot) const { return entries_[slot]; }
    [[nodiscard]] std::size_t count(EntryState s) const;
    [[nodiscard]] uint64_t expected_revision() const { return man_.expected_revision; }
    [[nodiscard]] const Manifest &manifest() const { return man_; }
    [[nodiscard]] TxnState txn_state(std::size_t i) const { return txns_[i].state; }
    // [S13] i < k_join_txns; false unless that transaction waits for the operator.
    [[nodiscard]] bool pending_join(std::size_t i, PendingJoin &out) const;

    // ---- [S18] lifecycle (lifecycle.cpp) ----
    // A member's READY names the lease of its credential (a claim about itself, over its end session). Near the
    // end of the lease (k_renew_before) or in another term the root signs the same credential with a fresh lease
    // and sends it back over the end session. Only an ACTIVE entry of exactly this device above every floor: a
    // departed, revoked or unknown device is never renewed, so its credential dies with its lease (docs/06 §7).
    void renew_due(const DeviceId &device, uint32_t term, uint64_t lease_ms, MonoTime now);
    // A signed lifecycle object for this root (lm_install_control): RevokeObject (11: floors raised, the entry
    // blocked, the device's sessions closed after a signed notice to it), AssignmentTicket (3: a member of this
    // domain moved to another one: its entry is left and its generations floored, the reconciliation of docs/07 §8),
    // CommissioningWindow (30) or RootHandover (31). Verified on the worker; completion is an OPERATION event.
    [[nodiscard]] Status install_lifecycle(uint8_t type, ByteView signed_cose, MonoTime now, uint64_t &operation);
    // A commissioning window admits new devices now (docs/21 §2): of this term, begun, not expired, not full.
    [[nodiscard]] bool window_open(MonoTime now) const;
    // RootHandover (31) named this root the old one: it acts as root no more (admits and renews nobody). FIX5-D1: from
    // the moment the verified object names it, before (and whatever) the commit that makes it survive a restart.
    [[nodiscard]] bool retired() const { return retired_; }
    struct Stats {
        uint64_t requests = 0;
        uint64_t refused = 0;
        uint64_t prepared = 0;
        uint64_t activated = 0;
        uint64_t confirmed = 0;
        uint64_t aborted = 0;
        uint64_t left = 0;
        uint64_t conflicts = 0;
        uint64_t busy_drops = 0;
        uint64_t renewals = 0;      // [S18] renewed credentials handed to the control lane
        uint64_t renew_deferred = 0; // [S18] worker, record memory or control lane busy: tried again
        uint64_t revoked = 0;        // [S18] entries blocked by a RevokeObject
        uint64_t reconciled = 0;     // [S18] members that moved away (a transfer ticket installed here)
        uint64_t window_admitted = 0; // [S18] reservations made under a commissioning window
        uint64_t floored = 0;         // [FIX5] entries whose stricter RAM state was made durable by maintenance
        uint64_t floored_failed = 0;  // [FIX5] ... commits of those that failed (bounded retry)
        uint64_t covers_evicted = 0;  // [FIX8] floor-table copies of a departed entry dropped for an unlisted device
    };
    [[nodiscard]] const Stats &stats() const { return stats_; }

  private:
    struct TicketInfo {
        uint64_t new_generation = 0;
        uint8_t mode = 0;
        Sha256Digest grant{}; // SHA-256 of the ticket COSE
        // [S18] 0: an initial assignment; 1: a transfer from another domain (docs/07 §8); 2: the re-issue of this
        // ledger's own member under a RootHandover (the object in the ticket field is that handover).
        uint8_t kind = 0;
    };
    struct Txn {
        member::JoinPipe pipe;
        TxnState state = TxnState::Free;
        DeviceId device;
        MacAddr mac;
        Sha256Digest dc_hash{};
        RequestId request;
        Sha256Digest content{};
        Sha256Digest prepare_hash{};
        TicketInfo ticket;
        ByteView dc;            // views into the credential buffer (valid while this txn holds it)
        ByteView ticket_cose;
        uint16_t slot = 0;      // ledger slot of this device
        uint8_t role = 0;
        // Waiting for the shared memory: 1 start_prepare, 2 answer_repeat; [P4] for the record memory alone:
        // 3 commit PREPARED, 4 commit ACTIVE, 5 commit confirmed.
        uint8_t retry_kind_ = 0;
        bool windowed = false;   // [S18] admitted by the commissioning window, not by the join mode
        bool resend = false;     // answers a repeated request: no new reservation
        bool confirmed_done = false;
        uint64_t membership = 0;
        uint64_t device_generation = 0; // the record generation the device reported (echoed back)
        std::size_t cose_len = 0;   // MemberCredential COSE staged at scratch tail
        std::size_t obj_len = 0;    // JoinPrepare object at scratch head
        std::size_t staged_len = 0; // small object in the pipe's staging area
        MonoTime deadline = MonoTime::never();
        MonoTime retry_at = MonoTime::never();
    };
    enum class Step : uint8_t {
        None,
        LoadAll,
        VerifyTicket,
        SignMember,
        CommitPrepared,
        CommitActive,
        CommitConfirmed,
        ResendLoad,
        CommitAborted,
        ConfirmLoad,
        ConfirmCommit,
        CommitLeft,
        CommitFloors,
        VerifyExpected,
        CommitExpectedHeader, // the page is marked pending (progress durable before any entry changes)
        CommitExpectedEntry,
        CommitExpectedDone,   // the page is marked received
        CommitManifest,
        RenewLoad, // [S18] the entry record: the credential the renewal repeats
        RenewSign,
        LcVerify,  // [S18] a lifecycle object on the worker
        LcFloors,  // [S18] revocation floors committed
        LcEntry,   // [S18] the entry blocked / left
        LcRetire,  // [S18] the RootHandover that retires this root, committed
        LcRetireCheck, // [FIX5-D1] ... read again after a failed commit (it may have reached the Flash)
        LcWindow,  // [S18] a new commissioning window's budget record, committed
        WindowReserve, // [S18] a windowed join's reservation counted durably before its entry commit
        CommitDirty,   // [FIX8-D1] maintenance: an entry whose (stricter) RAM state is ahead of its record
        CommitGroups,  // [FIX8-D10] the group registry
        CommitPolicy,  // [FIX8-D12] the join mode
    };

    struct VerifyArgs { // copied at submit: the worker never reads owner-mutable state
        member::TrustAnchor trust;
        member::RootDelegation delegation;
        Sha256Digest delegation_hash{};
        DeviceId device;
        Sha256Digest dc_hash{};
        ByteView ticket_cose;
        std::array<uint8_t, 16> nonce{}; // [S18] the JoinRequest's: a mode-0 ticket must name it (SEC-D4a)
        RootTerm term;                   // [S18] this root's term: a RootHandover must name it
        TicketInfo out;
    };
    struct SignArgs {
        sec::KeyHandle key;
        member::MemberCredential mc;
        member::Envelope env;
        MutByteView out; // scratch tail
        std::size_t len = 0;
    };

    // job plumbing (one ledger job at a time)
    // One ledger job at a time. `owner` (a transaction index, -2 maintenance) becomes job_txn_ only once the job
    // exists: a refused submit never re-points the completion of the job that is running (ARCH2 fix).
    [[nodiscard]] Status submit(Step step, JobClass cls, port::JobFn fn, void *arg, int owner);
    [[nodiscard]] Status commit_entry(Step step, std::size_t slot, EntryState state, bool confirmed,
                                      ByteView cose, int txn);
    static Status load_all_job(port::JobEnv &env, void *arg);
    static Status verify_ticket_job(port::JobEnv &env, void *arg);
    static Status sign_job(port::JobEnv &env, void *arg);
    void step_done(Step step, Status s, MonoTime now);
    void handle_step(Step step, Status s, MonoTime now);

    // shared memory
    [[nodiscard]] bool acquire(int txn);
    void release(int txn);
    void return_memory();
    [[nodiscard]] bool hold_record(); // [P4] the node's record memory, for the holder's next record job
    void give_back_record();
    [[nodiscard]] bool record_or_retry(Txn &t, uint8_t kind, MonoTime now);
    [[nodiscard]] MutByteView scratch() const { return scratch_; }

    // transactions
    [[nodiscard]] Txn *txn_by_device(const DeviceId &d);
    [[nodiscard]] int txn_index(const Txn *t) const { return static_cast<int>(t - txns_.data()); }
    [[nodiscard]] Txn *txn_by_slot(std::size_t slot);
    void repeat_last(Txn &t, MonoTime now);
    void on_request(Txn &t, ByteView data, const member::JoinObjectHeader &h, MonoTime now);
    void verified(Txn &t, Status s, MonoTime now);
    void decide_policy(Txn &t, MonoTime now);
    void start_prepare(Txn &t, MonoTime now);
    void prepare_signed(Txn &t, Status s, MonoTime now);
    void commit_prepared(Txn &t, MonoTime now);
    void window_reserved(Txn &t, Status s, MonoTime now); // [S18]
    // [S18] rec::commissioning_window := `r` (window_stage_ until the commit is durable).
    [[nodiscard]] Status commit_window(Step step, const WindowRecord &r, int holder);
    void prepare_committed(Txn &t, Status s, MonoTime now);
    void send_prepare(Txn &t, MonoTime now);
    void on_stored(Txn &t, ByteView data, const member::JoinObjectHeader &h, MonoTime now);
    void commit_active(Txn &t, MonoTime now);
    void active_committed(Txn &t, Status s, MonoTime now);
    void on_active(Txn &t, ByteView data, const member::JoinObjectHeader &h, MonoTime now);
    void commit_confirmed(Txn &t, MonoTime now);
    void confirmed_committed(Txn &t, Status s, MonoTime now);
    void answer_repeat(Txn &t, const Entry &e, MonoTime now);
    void resend_loaded(Txn &t, Status s, MonoTime now);
    void refuse(Txn &t, Status why, MonoTime now);
    void stage_ack(Txn &t, uint8_t type, const member::JoinAckData &a, MonoTime now);
    void stage_commit(Txn &t, MonoTime now);
    void stage_commit_data(Txn &t, const member::JoinCommitData &c, MonoTime now);
    void end_txn(Txn &t, bool close_session = true); // false: the device's new session is up, only this txn ends
    void retry_txn(Txn &t, MonoTime now);
    // [FIX8-D2] May this transaction still get what it asks for? At every approval (decide, retry, preapproved) and
    // before the JoinCommit signature leaves the root: a revocation, a block or the join mode may have changed.
    [[nodiscard]] Status still_allowed(const Txn &t) const;
    // [FIX8-D4] The first membership generation `device` may get: above its entry's last one and its floor.
    [[nodiscard]] uint64_t next_membership(const DeviceId &device, const Entry *e) const;
    // A slot another device may take: departed, its floor kept in the table, named by no group (FIX8-D9).
    [[nodiscard]] bool reusable(std::size_t slot) const;
    [[nodiscard]] Status pick_slot(const DeviceId &device, std::size_t &slot) const;
    void abort_expired(MonoTime now);
    void maintenance(MonoTime now);
    void leave_committed(Status s, MonoTime now);
    // A member is gone from the ledger (left): its sessions end and the tree forgets it at once.
    void forget_member(const DeviceId &device, ShortAddr address);
    // An entry record now exists for `slot`: the manifest must say so (committed by maintenance).
    void mark_used(std::size_t slot);
    // `e` is now the durable entry of `slot`. When the slot changes owner (the ledger reused the address of a device
    // that left), nothing learned about the old owner may route on (review finding 20).
    void set_entry(std::size_t slot, const Entry &e);
    [[nodiscard]] Status commit_manifest(const Manifest &m, Step step);
    [[nodiscard]] Status commit_floors(Step step);
    // The common start of a signed object's install (holder -2): refusals, the object in the lent scratch, the trust
    // the verify job checks it against. `other` = another install of that kind is running.
    [[nodiscard]] Status begin_install(ByteView cose, std::size_t max_bytes, bool other);
    // SEC-D7: may this verified page be applied? `applied` = it is applied already (the same bytes again).
    [[nodiscard]] Status expected_admit(bool &applied);
    [[nodiscard]] bool expected_room() const;
    void expected_step_done(Step step, Status s, MonoTime now);
    void expected_next(MonoTime now);
    void expected_finish(Status s);
    void confirm_loaded(Status s, MonoTime now);
    void confirm_done(MonoTime now);
    // [S18] lifecycle.cpp
    void start_renew(MonoTime now);
    void renew_step(Step step, Status s, MonoTime now);
    static Status lc_verify_job(port::JobEnv &env, void *arg);
    void lc_step(Step step, Status s, MonoTime now);
    void lc_verified(MonoTime now);
    void lc_listed(std::size_t slot, uint64_t af, uint64_t mf, MonoTime now); // [FIX8-D1]
    void lc_unlisted(const DeviceId &device, uint64_t af, uint64_t mf, MonoTime now);
    [[nodiscard]] bool evict_cover();
    void lc_finish(Status s, MonoTime now);
    void stop_admitting(MonoTime now);
    void retire(MonoTime now);                              // [FIX5-D1]
    void retire_step(Step step, Status s, MonoTime now);
    void retire_check(MonoTime now);
    void lc_entry_failed(MonoTime now);                     // [FIX5-D2, FIX8-D1]
    void mark_dirty(std::size_t slot, MonoTime now);
    // [FIX8-D1] Every entry commit ends here: a failed one leaves the slot's record in doubt (never evicted from nor
    // reused while so), a successful one clears it (RAM and the record agree again: every path writes RAM's entry).
    void entry_written(std::size_t slot, bool ok);
    void cover(std::size_t slot, MonoTime now); // [FIX8-D1] best-effort copy of a departed entry's floor in the table
    void block_below_floors(MonoTime now);
    [[nodiscard]] bool start_dirty(MonoTime now);
    void dirty_done(Status s, MonoTime now);
    void groups_done(Status s);                              // [FIX8-D10]
    void policy_done(Status s);                              // [FIX8-D12]
    void recon_retry(MonoTime now);
    void send_echo(MonoTime now);
    static Status verify_expected_job(port::JobEnv &env, void *arg);
    [[nodiscard]] uint32_t hint() const;
    [[nodiscard]] Entry *find_mut(const DeviceId &d);

    Engine &engine_;
    Stats stats_;
    JoinMode mode_ = JoinMode::External;
    bool loaded_ = false;
    bool failed_ = false;
    Manifest man_;             // RAM copy of the durable manifest (used bits may run ahead: man_dirty_)
    bool man_dirty_ = false;   // a used bit or the expected-set progress is not durable yet
    DomainId load_domain_;     // the delegation's domain, copied for the load job
    std::array<Entry, k_ledger_slots> entries_{};
    std::array<Txn, k_join_txns> txns_;

    // borrowed memory (holder: txn index, -1 none, -2 a maintenance operation)
    MutByteView scratch_;
    store::RecordJob *rec_ = nullptr;
    int holder_ = -1;

    // the one worker job
    Step step_ = Step::None;
    Entry job_entry_;        // what RAM becomes when the entry commit in flight is durable
    int orphan_release_ = -1;
    bool load_pending_ = false;
    Status groups_load_ = Status::NotFound; // [FIX8-D10] the registry record as the load job found it (payload in rec_)
    Status load_policy_ = Status::NotFound; // [FIX8-D12] ... and the policy record (applied by the owner at completion)
    JoinMode load_mode_ = JoinMode::External;
    uint64_t load_count_ = 0;
    Handle job_slot_;
    uint32_t job_gen_ = 0;
    bool job_in_flight_ = false;
    bool cancelled_ = false;
    int job_txn_ = -1;
    std::size_t job_slot_index_ = 0;
    VerifyArgs vargs_;
    SignArgs sargs_;
    member::ExpectedSet exp_;
    std::size_t exp_next_ = 0;
    uint64_t exp_op_ = 0;
    uint64_t exp_revision_ = 0;
    std::array<uint8_t, 8> exp_digest_{}; // of the page being installed (verify job)
    Manifest exp_man_;                    // the manifest the install commits next
    bool exp_active_ = false;
    // maintenance: leaves waiting for the record memory, one bit per ledger slot (FIX8-D3: several at once)
    uint64_t leave_mask_ = 0;
    // A device's JoinActive over an ordinary link (durable retry of the final acknowledgement)
    struct Confirm {
        DeviceId device;
        RequestId request;
        Sha256Digest hash{};
        uint64_t value = 0;
        std::size_t slot = 0;
    };
    Confirm confirm_;
    bool confirm_pending_ = false;
    uint64_t renew_mask_ = 0; // [S18] ledger slots whose credential is to be renewed (one at a time)
    // [S18] the one lifecycle install in progress (verify job output, then the commits it makes)
    // The decoded lifecycle object: one install at a time, so one of them (the verify job starts its lifetime).
    union LcObject {
        member::RevokeObject revoke;
        member::AssignmentTicket ticket;
        member::CommissioningWindow window;
        member::RootHandover handover;
        LcObject() : revoke() {}
    };
    struct Lifecycle {
        bool active = false;
        uint8_t type = 0;
        uint64_t op = 0;
        std::size_t len = 0; // the object, at the head of the shared credential buffer
        LcObject obj;
        std::size_t slot = 0;
        EntryState to = EntryState::Free; // the entry state the install commits (Blocked / Left)
        bool was_active = false;          // [FIX8-D1] the install took an ACTIVE member's authorisation
        uint8_t checks = 0;                        // [FIX5-D1] reads of the retirement record after a failed commit
        MonoTime retry_at = MonoTime::never();     // ... the next one (the record memory is given back meanwhile)
    };
    Lifecycle lc_;
    member::CommissioningWindow window_; // RAM only: a root restart ends it (its times are of this boot's clock)
    bool window_set_ = false;
    WindowRecord window_rec_;   // [FIX5-D6] rec::commissioning_window as committed (loaded at boot)
    WindowRecord window_stage_; // ... what the window commit in flight writes (window_rec_ once it is durable)
    // [FIX5-D2, FIX8-D1] Entries whose RAM state is ahead of their record (bit = slot): a revocation or reconciliation
    // changed RAM first (the entry refuses at once) and its commit failed, or the boot found an ACTIVE entry below a
    // table floor. Written as they are in RAM; bounded: after k_recon_tries failures in a row this boot stops trying
    // (RAM refuses meanwhile; the next boot or install decides again).
    uint64_t dirty_ = 0;
    // Slots whose record may differ from RAM (a failed entry commit of any path; dirty_ slots too). What RAM says of such
    // a slot is not known to be durable: its floor is not counted as kept (evict_cover) and it is not reused (reusable).
    uint64_t doubt_ = 0;
    bool floors_dirty_ = false; // the RAM floors may be ahead of the revocation_floors record (a failed floors commit)
    uint8_t recon_fails_ = 0;
    bool retired_ = false;
    DeviceId notice_device_; // a revoked member whose sessions end once its notice had its chance
    ShortAddr notice_addr_;
    MonoTime notice_until_ = MonoTime::never();
    std::size_t abort_slot_ = 0;
    bool abort_pending_ = false;
    MonoTime maint_retry_ = MonoTime::never();
    MonoTime last_offer_ = MonoTime{0};
    bool groups_pending_ = false; // [FIX8-D10] the registry waits for its commit
    // [FIX8-D12] store::rec::policy: the join mode and the number of committed changes (the policy revision's share)
    uint64_t policy_count_ = 0;
    JoinMode policy_stage_ = JoinMode::External;
    uint64_t policy_op_ = 0;
    bool policy_pending_ = false;
    bool policy_doubt_ = false;
};

// Leaf/relay builds carry no root code (docs/02 §4): the Engine holds this empty stand-in instead, so
// nothing of the ledger (RAM, Flash) exists there.
struct NoLedger {
    explicit NoLedger(Engine &) {}
    void on_identity_ready(MonoTime) {}
    void on_job_done(Handle, Status, MonoTime) {}
    void on_tx_outcome(const TxOutcome &, MonoTime) {}
    void on_timer(MonoTime) {}
    [[nodiscard]] MonoTime deadline() const { return MonoTime::never(); }
    void stop() {}
    [[nodiscard]] bool job_pending() const { return false; }
    [[nodiscard]] bool responder_open() const { return false; }
    [[nodiscard]] bool link_admit(const DeviceId &, const member::MemberCredential &) const { return true; }
    [[nodiscard]] Status admission() const { return Status::Ok; }
    void session_up(const MacAddr &, const DeviceId &, const Sha256Digest &, MonoTime) {}
    void discovery(const MacAddr &, const wire::BootstrapCarrier &, MonoTime) {}
    void join_control(const link::RxInfo &, ByteView, MonoTime) {}
    [[nodiscard]] bool link_control(const link::RxInfo &, ByteView, MonoTime) { return false; }
    void set_join_mode(JoinMode) {}
    [[nodiscard]] JoinMode join_mode() const { return JoinMode::Closed; }
    [[nodiscard]] Status set_policy_mode(JoinMode, uint64_t, MonoTime) { return Status::Unsupported; }
    [[nodiscard]] uint64_t policy_changes() const { return 0; }
    [[nodiscard]] bool policy_in_doubt() const { return false; }
    [[nodiscard]] Status install_expected(ByteView, MonoTime, uint64_t &) { return Status::Unsupported; }
    [[nodiscard]] Status install_lifecycle(uint8_t, ByteView, MonoTime, uint64_t &) { return Status::Unsupported; }
    void renew_due(const DeviceId &, uint32_t, uint64_t, MonoTime) {}
    [[nodiscard]] bool retired() const { return false; }
    [[nodiscard]] Status decide(const JoinDecision &, MonoTime) { return Status::Unsupported; }
    [[nodiscard]] bool pending_join(std::size_t, PendingJoin &) const { return false; }
};

using LedgerType = std::conditional_t<k_root_capable, Ledger, NoLedger>;

} // namespace lm::root
