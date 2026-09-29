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
inline constexpr Duration k_member_lease = Duration::from_s(15 * 60); // docs/06 §7 (renewal: mesh slice)

enum class EntryState : uint8_t { Free = 0, Expected = 1, Prepared = 2, Active = 3, Left = 4, Aborted = 5, Blocked = 6 };
enum class JoinMode : uint8_t { Closed = 0, External = 1, Preapproved = 2 };

struct Entry {
    DeviceId device;
    Sha256Digest hash{};      // Expected: SHA-256 of the granting ticket; else SHA-256 of the JoinRequest content
    RequestId request;        // the request that reserved / activated it
    uint64_t assignment = 0;  // Expected: the assignment generation to be granted; else the one issued
    uint64_t membership = 0;  // the last membership generation issued to this device (never reused)
    ShortAddr address;        // 2 + slot: the slot is the address
    EntryState state = EntryState::Free;
    bool confirmed = false;   // Active: the device's own JOIN_ACTIVE evidence was recorded
    bool recovered = false;   // Prepared and read at boot: its reservation deadline is unknown
    MonoTime reserved_until = MonoTime::never(); // RAM only
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
    [[nodiscard]] bool link_admit(const DeviceId &device, const member::MemberCredential &mc) const;
    void session_up(const MacAddr &mac, const DeviceId &peer, const Sha256Digest &peer_dc_hash, MonoTime now);
    void discovery(const MacAddr &src, const wire::BootstrapCarrier &c, MonoTime now);
    void join_control(const link::RxInfo &info, ByteView plain, MonoTime now);
    [[nodiscard]] bool link_control(const link::RxInfo &info, ByteView plain, MonoTime now);

    // ---- commands ----
    void set_join_mode(JoinMode m) { mode_ = m; }
    [[nodiscard]] JoinMode join_mode() const { return mode_; }
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
    [[nodiscard]] bool job_pending() const { return job_in_flight_; } // lm_destroy waits for the worker
    [[nodiscard]] const Entry *find(const DeviceId &d) const;
    [[nodiscard]] const Entry &entry(std::size_t slot) const { return entries_[slot]; }
    [[nodiscard]] std::size_t count(EntryState s) const;
    [[nodiscard]] uint64_t expected_revision() const { return expected_revision_; }
    [[nodiscard]] TxnState txn_state(std::size_t i) const { return txns_[i].state; }
    // [S13] i < k_join_txns; false unless that transaction waits for the operator.
    [[nodiscard]] bool pending_join(std::size_t i, PendingJoin &out) const;
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
    };
    [[nodiscard]] const Stats &stats() const { return stats_; }

  private:
    struct TicketInfo {
        uint64_t new_generation = 0;
        uint8_t mode = 0;
        Sha256Digest grant{}; // SHA-256 of the ticket COSE
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
        uint8_t retry_kind_ = 0; // 1: start_prepare, 2: answer_repeat, waiting for the shared memory
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
        CommitExpectedHeader,
        CommitExpectedEntry,
    };

    struct VerifyArgs { // copied at submit: the worker never reads owner-mutable state
        member::TrustAnchor trust;
        member::RootDelegation delegation;
        Sha256Digest delegation_hash{};
        DeviceId device;
        Sha256Digest dc_hash{};
        ByteView ticket_cose;
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
    [[nodiscard]] Status submit(Step step, JobClass cls, port::JobFn fn, void *arg);
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
    void prepare_committed(Txn &t, Status s, MonoTime now);
    void send_prepare(Txn &t, MonoTime now);
    void on_stored(Txn &t, ByteView data, const member::JoinObjectHeader &h, MonoTime now);
    void active_committed(Txn &t, Status s, MonoTime now);
    void on_active(Txn &t, ByteView data, const member::JoinObjectHeader &h, MonoTime now);
    void confirmed_committed(Txn &t, Status s, MonoTime now);
    void answer_repeat(Txn &t, const Entry &e, MonoTime now);
    void resend_loaded(Txn &t, Status s, MonoTime now);
    void refuse(Txn &t, Status why, MonoTime now);
    void stage_ack(Txn &t, uint8_t type, const member::JoinAckData &a, MonoTime now);
    void end_txn(Txn &t);
    void retry_txn(Txn &t, MonoTime now);
    [[nodiscard]] Status pick_slot(const DeviceId &device, std::size_t &slot) const;
    void abort_expired(MonoTime now);
    void maintenance(MonoTime now);
    void leave_committed(Status s, MonoTime now);
    void expected_step_done(Step step, Status s, MonoTime now);
    void expected_next(MonoTime now);
    void expected_finish(Status s);
    void confirm_loaded(Status s, MonoTime now);
    void confirm_done(MonoTime now);
    void send_echo(MonoTime now);
    static Status verify_expected_job(port::JobEnv &env, void *arg);
    [[nodiscard]] uint32_t hint() const;
    [[nodiscard]] Entry *find_mut(const DeviceId &d);

    Engine &engine_;
    Stats stats_;
    JoinMode mode_ = JoinMode::External;
    bool loaded_ = false;
    bool failed_ = false;
    uint64_t expected_revision_ = 0;
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
    std::size_t leave_slot_ = 0;
    Handle job_slot_;
    uint32_t job_gen_ = 0;
    bool job_in_flight_ = false;
    bool cancelled_ = false;
    int job_txn_ = -1;
    std::size_t job_slot_index_ = 0;
    EntryState job_state_ = EntryState::Free;
    bool job_confirmed_ = false;
    VerifyArgs vargs_;
    SignArgs sargs_;
    member::ExpectedSet exp_;
    std::size_t exp_next_ = 0;
    uint64_t exp_op_ = 0;
    uint64_t exp_revision_ = 0;
    bool exp_active_ = false;
    Status exp_result_ = Status::Ok;
    // maintenance: a leave/abort waiting for the record memory
    bool leave_pending_ = false;
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
    std::size_t abort_slot_ = 0;
    bool abort_pending_ = false;
    MonoTime maint_retry_ = MonoTime::never();
    MonoTime last_offer_ = MonoTime{0};
    uint64_t op_counter_ = 0;
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
    void session_up(const MacAddr &, const DeviceId &, const Sha256Digest &, MonoTime) {}
    void discovery(const MacAddr &, const wire::BootstrapCarrier &, MonoTime) {}
    void join_control(const link::RxInfo &, ByteView, MonoTime) {}
    [[nodiscard]] bool link_control(const link::RxInfo &, ByteView, MonoTime) { return false; }
    void set_join_mode(JoinMode) {}
    [[nodiscard]] Status install_expected(ByteView, MonoTime, uint64_t &) { return Status::Unsupported; }
    [[nodiscard]] Status decide(const JoinDecision &, MonoTime) { return Status::Unsupported; }
    [[nodiscard]] bool pending_join(std::size_t, PendingJoin &) const { return false; }
};

using LedgerType = std::conditional_t<k_root_capable, Ledger, NoLedger>;

} // namespace lm::root
