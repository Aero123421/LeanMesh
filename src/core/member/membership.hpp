// Device side of membership (docs/07): Join as a joiner (discover, JOIN_ONLY session, request,
// PREPARE -> STORED -> COMMIT -> ACTIVE), resume after boot, leave (DRAIN/IMMEDIATE), the ticket
// record and the lm_membership_get / lm_join / lm_leave / lm_get_request views. The root side is
// root::Ledger. One owner-side state machine; every public-key check and every Flash access is a
// worker job matched by (job table, slot handle) and none of them touches owner state except its
// argument (docs/IMPLEMENTATION.md §3).
//
// Persistence (each arrow is one sealed-record commit, docs/12 §4):
//   root_delegation ... PREPARED record (membership_prepared, state 1) ... membership (state 1 =
//   ACTIVE, the commit marker of the join) ... membership_prepared consumed (state 2).
// Every cut leaves exactly one allowed state: before the PREPARED commit "not a member"; after it
// PREPARED (query the root by request_id); after the membership commit ACTIVE (a stale PREPARED
// record is ignored because ACTIVE is authoritative); leave writes one tombstone (state 3).
//
// Borrowed memory (no per-feature buffers, docs/IMPLEMENTATION.md §13): the credential buffer of the
// link exchange holds the JoinRequest/JoinPrepare object; the record job memory of LocalIdentity
// carries every Flash step. Both are held from the session until the join ends.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/ids.hpp"
#include "core/jobs.hpp"
#include "core/link/exchange.hpp"
#include "core/member/credentials.hpp"
#include "core/member/discovery.hpp"
#include "core/member/join.hpp"
#include "core/member/join_wire.hpp"
#include "core/pool.hpp"
#include "core/time.hpp"
#include "leanmesh.h"
#include "store/record.hpp"

namespace lm {
class Engine;
}

namespace lm::member {

// Record id of this slice (decision S8-D5; folded into store::rec, 0x40 collided with the paired
// Host record of S10-D2).
inline constexpr uint16_t k_rec_assignment_ticket = store::rec::assignment_ticket;
inline constexpr std::size_t k_prepared_head = 16 + 16 + 32; // PREPARED record: request | nonce | prepare hash | credential
inline constexpr uint8_t k_prepared_state = 1;            // membership_prepared: PREPARED
inline constexpr uint8_t k_prepared_consumed = 2;         // membership_prepared: finished or aborted
inline constexpr uint8_t k_prepared_activated = 4;        // ACTIVE committed, the root's acknowledgement still owed

inline constexpr uint32_t k_tag_join = 0x4A4E0000; // "JN": TX completions of the device's join pipe
inline constexpr uint32_t k_tag_leave = 0x4A4C0000; // "JL": the leave notice
inline constexpr uint32_t k_tag_hello = 0x4A480000; // "JH": the discovery hello (broadcast)
inline constexpr uint32_t k_tag_confirm = 0x4A4B0000; // "JK": JoinActive over an ordinary link (durable retry)
// Every TX tag of the join/leave/discovery traffic lies in this range (upper 16 bits 0x4A48..0x4A55).
[[nodiscard]] constexpr bool is_join_tag(uint32_t tag) {
    const uint32_t hi = tag >> 16U;
    return hi >= 0x4A48U && hi <= 0x4A55U;
}
struct LeaveArgs {
    uint32_t mode = 0;
    uint32_t deadline_ms = 0;
};
// Operation ids of join/leave/install carry this bit so they cannot collide with message operations.
inline constexpr uint64_t k_op_tag = 1ULL << 62;

// Evidence bits reported by lm_get_request (docs/21 §10). They are separate facts and never imply
// each other: `requested` says the device asked, `root_stored` that the root committed PREPARED
// (device saw JoinPrepare), `device_stored` that the device read its PREPARED record back,
// `device_active` that it committed ACTIVE, `root_confirmed` that the root acknowledged that.
enum JoinEvidence : uint32_t {
    kEvRequested = 1U << 0,
    kEvRootStored = 1U << 1,
    kEvDeviceStored = 1U << 2,
    kEvDeviceActive = 1U << 3,
    kEvRootConfirmed = 1U << 4,
};

enum class JoinPhase : uint8_t {
    Idle,
    Discover,          // hello broadcast, waiting for an offer
    Connect,           // JOIN_ONLY handshake running
    PersistDelegation, // Flash: root_delegation
    LoadTicket,        // Flash: ticket record
    RequestOut,        // JoinRequest sent, waiting for JoinPrepare / JoinCommit / refusal
    Verify,            // JoinPrepare checked (signature withheld, SEC-D1), waiting for the record memory
    PersistPrepared,   // Flash: membership_prepared
    StoredOut,         // JoinStored sent, waiting for JoinCommit
    Activate,          // Flash chain: load prepared -> verify the completed credential -> commit membership
    ActiveOut,         // ACTIVE; JoinActive sent, waiting for the root's final ack
};

// Hooks the delivery/mesh slices install to make DRAIN meaningful. Without them nothing is pending
// and nothing blocks a leave.
struct MembershipHooks {
    void *ctx = nullptr;
    // Every pending operation settled and (relay) every child reachable elsewhere?
    bool (*drained)(void *ctx) = nullptr;
    // New sends are refused while true (leave in progress).
    void (*refuse_sends)(void *ctx, bool refuse) = nullptr;
    // IMMEDIATE leave / committed leave: pending work becomes INDETERMINATE / NOT_SENT.
    void (*settle_pending)(void *ctx) = nullptr;
};

struct JoinArgs {
    RequestId request;
    uint32_t mode = LM_JOIN_NEW;
    uint32_t search_budget_ms = 0; // 0: the default (30 s)
    DomainId target;               // with `constrain`: only this domain's root is acceptable
    bool constrain = false;
};

class Membership {
  public:
    explicit Membership(Engine &engine);
    Membership(const Membership &) = delete;
    Membership &operator=(const Membership &) = delete;

    // ---- Engine wiring ----
    void on_identity_ready(MonoTime now);
    void on_job_done(Handle slot, Status s, MonoTime now);
    void on_tx_outcome(const TxOutcome &o, MonoTime now);
    void on_timer(MonoTime now);
    [[nodiscard]] MonoTime deadline() const;
    void stop();
    // Trampolines for link::JoinHooks (the Engine routes them by role).
    void session_up(bool initiator, const MacAddr &mac, const DeviceId &peer, ByteView bundle, MonoTime now);
    void exchange_failed(Status why, MonoTime now);
    void discovery(const MacAddr &src, const wire::BootstrapCarrier &c, uint32_t domain_hint, MonoTime now);
    void join_control(const link::RxInfo &info, ByteView plain, MonoTime now);
    void link_up(const DeviceId &peer, uint8_t role, MonoTime now);
    [[nodiscard]] bool link_control(const link::RxInfo &info, ByteView plain, MonoTime now);

    // ---- commands (owner thread) ----
    [[nodiscard]] Status join(const JoinArgs &args, MonoTime now, uint64_t &operation);
    [[nodiscard]] Status leave(uint8_t mode, uint32_t deadline_ms, MonoTime now, uint64_t &operation);
    [[nodiscard]] Status install_ticket(ByteView signed_cose, MonoTime now, uint64_t &operation);
    void get_membership(lm_membership_t &out, MonoTime now) const;
    [[nodiscard]] Status get_request(const RequestId &id, lm_operation_t &out, MonoTime now) const;
    void set_hooks(const MembershipHooks &h) { hooks_ = h; }

    // ---- [S18] lifecycle (lifecycle.cpp) ----
    // A signed lifecycle object the root sent over the end session with it (the engine's control sink): a renewed
    // MemberCredential. Checked against the live credential (every field but the lease equal, the lease later),
    // verified on the worker, committed, then live; every link session is then made again so that each neighbour
    // holds the new lease. Anything else, or no room right now, is dropped: the root offers it again.
    void on_lifecycle_object(const DeviceId &origin, ByteView cose, MonoTime now);
    // SEC-D4a / S18: the nonce a mode-0 AssignmentTicket must name (docs/07 §8 transfer_nonce16). One outstanding
    // nonce, RAM only: made on the first call, the same until a join made ACTIVE with it, lost with a restart (a
    // ticket for it is then refused: never a replayed or stale grant).
    [[nodiscard]] Status transfer_nonce(std::array<uint8_t, 16> &out);
    // A committed transfer/handover is switching this device to its new root (no new Link/End sessions meanwhile).
    [[nodiscard]] bool switching() const { return switch_ && phase_ == JoinPhase::Activate; }

    // ---- observability ----
    [[nodiscard]] JoinPhase phase() const { return phase_; }
    [[nodiscard]] bool leaving() const { return leave_ != LeavePhase::Idle; }
    [[nodiscard]] bool prepared_record() const { return have_prepared_; }
    // A worker job still runs on this module's memory (also after stop(): lm_destroy must wait).
    [[nodiscard]] bool job_pending() const { return job_in_flight_; }
    [[nodiscard]] bool confirm_pending() const { return confirm_pending_; } // ACTIVE durable, root ack owed
    [[nodiscard]] const RequestId &request_id() const { return req_.id; }
    [[nodiscard]] const std::array<uint8_t, 16> &hello_nonce() const { return hello_nonce_; } // bench: a forged offer needs it
    [[nodiscard]] uint32_t evidence() const { return req_.evidence; }
    [[nodiscard]] Status reason() const { return req_.reason; }
    [[nodiscard]] const JoinPipe &pipe() const { return pipe_; }
    struct Stats {
        uint64_t joins_started = 0;
        uint64_t joins_active = 0;
        uint64_t refusals = 0;
        uint64_t offers_seen = 0;
        uint64_t stale_job_completions = 0;
        uint64_t scratch_busy = 0;
        uint64_t renewals = 0;       // [S18] renewed credentials made live
        uint64_t renew_dropped = 0;  // [S18] not taken (busy, refused, not newer): the root sends it again
    };
    [[nodiscard]] const Stats &stats() const { return stats_; }

  private:
    enum class Step : uint8_t {
        None,
        BootLoadPrepared,
        CommitDelegation,
        LoadTicket,
        CommitPrepared,
        ActivateLoad,
        ActivateCommit,
        ActivateMark,   // membership_prepared -> ACTIVATED (root acknowledgement still owed)
        ConfirmConsume, // membership_prepared -> CONSUMED once the root acknowledged
        VerifyActivation, // worker: the credential completed by JoinCommit's signature (SEC-D1)
        ConsumePrepared, // refusal or leave of a PREPARED join
        InstallTicket,
        LeaveCommit,
        RenewVerify, // [S18] worker: the renewed credential under the delegation
        RenewCommit, // [S18] membership record := the renewed credential
        RevokeVerify,  // [S18] worker: the root's RevokeObject for this device
        CommitPending, // [S18] pending_delegation := the new root's delegation (transfer/handover)
        SwitchLoad,    // [S18] after the ACTIVE commit: the pending delegation ...
        SwitchCommit,  // [S18] ... becomes root_delegation
        SwitchPeek,    // [S18] the installed object says where a member's switch looks (its target domain)
    };
    enum class LeavePhase : uint8_t { Idle, Draining, Notifying, Committing };

    struct Request {
        RequestId id;
        std::array<uint8_t, 16> nonce{};
        Sha256Digest prepare_hash{};
        uint64_t membership = 0;
        uint64_t assignment = 0; // the ticket's new generation
        uint64_t prepared_generation = 0;
        MemberCredential mc;
        std::array<uint8_t, k_signature_bytes> signature{}; // from JoinCommit: completes the PREPARED credential
        uint32_t reservation_ms = 0;
        uint32_t evidence = 0;
        Status reason = Status::Ok;
        uint32_t outcome = LM_OUTCOME_PENDING;
        uint64_t operation = 0;
        bool known = false;
    };

    // flash / worker plumbing
    [[nodiscard]] Status start_flash(Step step, store::RecordJob::Op op, uint16_t id, uint8_t state,
                                     std::size_t payload_len, MonoTime now);
    [[nodiscard]] Status start_verify(Step step);
    static Status verify_job(port::JobEnv &env, void *arg);
    void flash_done(Step step, Status s, MonoTime now);

    // join steps
    void begin_discovery(MonoTime now);
    void choose_offer(MonoTime now);
    void apply_pacing(uint8_t depth);
    void not_expected(MonoTime now);
    void send_hello(MonoTime now);
    void try_connect(MonoTime now);
    void request_ready(MonoTime now);   // ticket loaded: build and send JoinRequest
    void on_prepare(ByteView data, MonoTime now);
    void on_commit(ByteView data, MonoTime now);
    void on_active_echo(ByteView data, MonoTime now);
    void prepared_verified(MonoTime now);
    void activate(MonoTime now);
    void activate_loaded(Status s, MonoTime now);
    void activate_commit(MonoTime now);
    void active_out(MonoTime now);
    void send_stored(MonoTime now);
    void stage_ack(uint8_t type, const JoinAckData &a, MonoTime now);
    void repeat_last(MonoTime now);
    void finish_join(Status why, uint32_t outcome, MonoTime now);
    void release_join();               // scratch, record memory, session, pipe
    void fail_and_consume(Status why, MonoTime now);
    void pipe_failed(Status why, MonoTime now);
    void retry_work(MonoTime now);
    void emit_state(uint32_t reason);
    [[nodiscard]] bool lend_scratch_only();
    [[nodiscard]] bool lend_record_only();
    [[nodiscard]] bool lend_record_or_retry(MonoTime now);
    [[nodiscard]] uint32_t hint() const;
    [[nodiscard]] Status parse_prepared_record(const store::RecordJob &rec);
    void install_done(Status s, MonoTime now);
    // [S18] lifecycle.cpp
    void renew_step(Step step, Status s, MonoTime now);
    void renew_adopt(MonoTime now);
    [[nodiscard]] Status check_request_object(ByteView obj, uint64_t &assignment);
    void wrong_root(MonoTime now);
    void leave_old_domain();
    void switch_done(MonoTime now);
    void mark_activated(MonoTime now);
    void on_revoke_notice(ByteView cose, MonoTime now);
    void revoke_verified(Status s, MonoTime now);
    void send_confirm(MonoTime now);
    void parse_activated_record(const store::RecordJob &rec);
    void resume_switch(const store::RecordJob &rec);
    void switch_peeked(Status s, MonoTime now);

    // leave
    void leave_timer(MonoTime now);
    void leave_notify(MonoTime now);
    void leave_tx_done(const TxOutcome &o, MonoTime now);
    void leave_commit(MonoTime now);
    void leave_flash_done(Step step, Status s, MonoTime now);
    void leave_finish(Status why, uint32_t outcome, MonoTime now);

    Engine &engine_;
    JoinPipe pipe_;
    MembershipHooks hooks_;
    Stats stats_;

    JoinPhase phase_ = JoinPhase::Idle;
    Request req_;
    link::JoinPeerOut peer_;               // the root's delegation, written by the exchange's verify job
    bool have_prepared_ = false;     // a PREPARED record is durable
    bool resume_ = false;            // boot found a PREPARED record: query, no human involvement
    DomainId target_;                // lm_join_request_t.target_domain when constrain_target
    bool constrain_ = false;
    bool link_resume_ = false;       // RESUME of an ACTIVE member: an ordinary link session, no join
    bool retry_consume_ = false;
    bool confirm_pending_ = false;   // ACTIVE is durable but the root's acknowledgement is not (LC06)
    bool confirm_consume_ = false;   // the root acknowledged; the PREPARED record still has to be consumed
    uint8_t confirm_attempts_ = 0;
    MonoTime confirm_at_ = MonoTime::never();
    ShortAddr prep_address_;         // JoinPrepare fields the verified credential must repeat
    uint32_t prep_term_ = 0;
    std::size_t staged_len_ = 0;     // the small object in the pipe's staging area (JoinStored/Active)
    uint64_t activated_generation_ = 0;
    MonoTime state_since_;

    // discovery
    std::array<uint8_t, 16> hello_nonce_{};
    MacAddr cand_;
    bool have_cand_ = false;
    Discovery disc_;                          // [S11] listen-first timing, budgets, NOT_EXPECTED hold
    struct Offer {                            // up to three offers of one search (docs/07 §3: candidates 3)
        bool used = false, tried = false;
        MacAddr mac;
        uint8_t depth = 0;                    // 0: the root itself
        uint32_t revision = 0;                // its expected-list revision hint
    };
    std::array<Offer, 3> offers_{};
    MonoTime collect_until_ = MonoTime::never(); // a shallower offer may still arrive
    uint32_t cand_revision_ = 0;
    bool budget_default_ = true;              // lm_join without an explicit search budget
    uint8_t not_expected_ = 0;                // consecutive NOT_EXPECTED refusals (hold 10 s, 20 s ... 60 s)
    MonoTime search_deadline_ = MonoTime::never();
    MonoTime retry_at_ = MonoTime::never();   // busy scratch / rate gate / radio: try again then
    MonoTime request_deadline_ = MonoTime::never();
    MonoTime prepared_until_ = MonoTime::never();
    MonoTime final_wait_until_ = MonoTime::never();

    // borrowed memory
    MutByteView scratch_;            // exchange credential buffer (JoinRequest / JoinPrepare)
    store::RecordJob *rec_ = nullptr;
    bool rec_mine_ = false;

    // worker job bookkeeping (zombie rule: memory stays reserved until the completion is polled)
    Step step_ = Step::None;
    Handle job_slot_;
    uint32_t job_gen_ = 0;
    bool job_in_flight_ = false;
    bool cancelled_ = false;
    ByteView verify_input_;          // PREPARE: the withheld credential in scratch_; activation: the completed one in rec_
    uint64_t op_counter_ = 0;
    uint64_t install_op_ = 0;
    bool boot_failed_ = false;       // reading the PREPARED record failed: unknown state, refuse to join
    bool renew_adopt_ = false;       // [S18] a renewed credential is durable and waits for an idle exchange
    bool switch_ = false;            // [S18] this join moves an ACTIVE member to another root (transfer/handover)
    bool handover_ = false;          // [S18] ... to its own domain's new root (the object is a RootHandover)
    DomainId switch_domain_;         // [S18] the domain whose root that switch asks (offers of others are skipped)
    std::array<uint8_t, 16> nonce_{}; // [S18] the outstanding mode-0 nonce
    bool nonce_valid_ = false;
    bool revoked_ = false;            // [S18] the running leave is the erasure a revocation notice asked for
    uint64_t revoke_af_ = 0;          // [S18] ... and the floors it named (assignment, membership)
    uint64_t revoke_mf_ = 0;
    uint64_t leave_assignment_ = 0;  // this device's generations, for the floors written on leave
    uint64_t leave_membership_ = 0;
    MonoTime poll_at_ = MonoTime::never(); // RESUME of a member: waits for the link session

    // leave
    LeavePhase leave_ = LeavePhase::Idle;
    uint8_t leave_mode_ = 0;
    uint64_t leave_op_ = 0;
    MonoTime leave_deadline_ = MonoTime::never();
    MonoTime leave_tx_wait_ = MonoTime::never();
    uint8_t leave_attempts_ = 0;
    bool leave_tx_inflight_ = false;
    bool leave_prepared_only_ = false;
};

} // namespace lm::member
