// Power (S16, docs/20, 22): the three power modes in one engine.
//   ALWAYS_RX    the radio stays on; a relay or the root can only be this.
//   WINDOWED_RX  the engine cycles by itself: light sleep (radio off, RAM kept) -> wake -> authenticated
//                POWER poll to the parent -> receive window -> light sleep. Same wire, same sessions.
//   REPORT_ONLY  the application decides when to sleep (prepare -> ticket -> enter) and what wakes it; the
//                SDK runs one bounded episode per wake and polls the parent once.
// One episode budget (`ep_end_`) is set at wake/boot and every subsystem is measured against it (send
// admission, search, handshakes): retries, repairs and channel searches never re-grant it.
//
// Parents (relay/root): a sleepy child is a `Child` entry that only exists because it sent an authenticated
// poll. Frames for it are ordinary TX-pool frames that are *parked* (not handed to the radio) while the child
// is asleep: the mailbox is the pool (P9), its caps are admission checks, its expiry is `hold_until`. Parked
// frames are RAM only: a HOP_ACK for them is HOP_ACCEPTED, never a durable receipt (docs/20 §5).
//
// Sleep is not RF loss: parked frames spend no link attempts, waiting timers do not run into a sleep gap, the
// mesh forgets no silence (Mesh::on_wake), and every timer that measures *waiting* is shifted by the gap
// while every *lifetime* (keys, leases, deadlines) keeps running.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/command.hpp"
#include "core/link/link_layer.hpp"
#include "core/pool.hpp"
#include "core/power/policy.hpp"
#include "core/power/power_wire.hpp"
#include "core/ports.hpp"
#include "core/time.hpp"
#include "gen/power_policy.hpp"

namespace lm {
class Engine;
namespace store {
struct RecordJob;
}
} // namespace lm

namespace lm::power {

// Reasons in LM_EVENT_POWER events and lm_power_snapshot_t.wake_reason / last_reason.
enum Reason : uint32_t {
    kNone = 0,
    kColdBoot = 1,
    kTimer = 2,
    kExternal = 3,
    kWindow = 4,
    kEpisodeBudgetEnd = 5, // the episode's budget is used up: sleep now
    kWakeDenied = 6,       // extra-wake quota used up: the radio stays off
    kOfflineBudget = 7,    // this hour's radio time for searching is used up
    kSleepEntered = 8,
    kSleepAborted = 9,
    kOverrun = 10,         // the node did not go to sleep within reserve + overrun limit
    kSearchBudgetEnd = 11, // the episode's search budget is used up: no parent yet, sleep now
    kWindowClosed = 12,    // the receive window after the poll is over
    kOpDone = 13,          // a policy set / sleep prepare finished (the operation event has the status)
    kOpFailed = 14,
    kReportRx = 15,        // (root) a member reported its schedule: the Host reads it
};

// lm_power_snapshot_t.validity_bits: what this build actually knows. cpu_active_us and energy are absent.
namespace valid {
inline constexpr uint64_t state = 1U << 0;
inline constexpr uint64_t radio_on_us = 1U << 1;
inline constexpr uint64_t handshakes = 1U << 2;
inline constexpr uint64_t flash_commits = 1U << 3;
inline constexpr uint64_t budgets = 1U << 4;
inline constexpr uint64_t next_wake = 1U << 5;
} // namespace valid

inline constexpr uint64_t k_op_power = 1ULL << 60; // operation ids of policy set / sleep prepare
inline constexpr uint32_t k_tag_power = 0x50570000; // "PW": POWER frames on the air

// Per-child (parent side) and per-member (root side) tables are compiled out of builds that cannot be a
// relay or the root: a leaf image keeps neither.
inline constexpr std::size_t k_children = k_build_max_role >= Role::Relay ? k_build_limits.neighbors / 2 : 0;
inline constexpr std::size_t k_members = k_root_capable ? k_build_limits.members : 0;

struct SleepRequest { // lm_sleep_request_t without the ABI header
    uint8_t kind = LM_SLEEP_DEEP, sources = LM_WAKE_TIMER, pending = 0;
    uint32_t budget_ms = 0;
    uint64_t sleep_ms = 0;
};
struct PolicySetRequest {
    Policy policy;
    uint64_t expected = 0;
};

struct Stats {
    uint64_t episodes = 0, sleeps = 0, polls = 0, grants = 0, missed_windows = 0, overruns = 0;
    uint64_t wake_denied = 0, ticket_stale = 0, sessions_kept = 0, sessions_dropped = 0;
    uint64_t parked_expired = 0, polls_served = 0, polls_refused = 0, flash_commits = 0, reports_sent = 0;
    uint64_t reports_rx = 0;
};

class Power {
  public:
    enum class State : uint8_t { Running = LM_POWER_RUNNING, Quiescing = LM_POWER_QUIESCING,
                                 SleepReady = LM_POWER_SLEEP_READY, Sleeping = LM_POWER_SLEEPING,
                                 Waking = LM_POWER_WAKING, BudgetBlocked = LM_POWER_BUDGET_BLOCKED,
                                 Fault = LM_POWER_FAULT };

    explicit Power(Engine &engine) : engine_(engine) {}
    Power(const Power &) = delete;
    Power &operator=(const Power &) = delete;

    // ---- Engine wiring ----
    void on_start(MonoTime now);            // lm_start: boot facts and budgets
    void on_identity_ready(MonoTime now);   // load the policy record
    void on_job_done(Handle slot, Status s, MonoTime now);
    [[nodiscard]] bool job_pending() const { return policy_job_; }
    void stop();
    // The radio is off and the owner has nothing to do but wait for its wake (a sleep, or a wake the budget denied).
    [[nodiscard]] bool asleep() const;
    MonoTime step_asleep(MonoTime now);
    void after_step(MonoTime now);          // end of every step: prepare progress, accounting, locks
    void on_timer(MonoTime now);
    [[nodiscard]] MonoTime deadline() const;
    [[nodiscard]] Reply execute(const Command &cmd, MonoTime now);
    void on_frame(const link::RxInfo &info, ByteView plain, MonoTime now); // frame kind POWER
    // An authenticated DATA frame arrived: a sleep ticket in hand is stale, and the receive window is not over.
    void note_rx(MonoTime now);
    // We sent a frame of our own (device side): its answer can come within the receive window that follows it.
    void note_uplink(MonoTime now);
    // A neighbour sent us an authenticated frame (parent side): if it is a sleepy child it is awake, and stays so
    // for the window it announced, counted from this frame.
    void on_child_frame(const MacAddr &mac, MonoTime now);
    // The platform woke the CPU (interrupt, or the port returned from a blocking light sleep).
    void wake(const port::WakeInfo &info, MonoTime now);
    void on_parent_ready(MonoTime now);     // the mesh has an approved parent: the poll of the episode
    [[nodiscard]] Reply get_operation(uint64_t id, lm_operation_t &out) const;

    // ---- hooks other modules call ----
    [[nodiscard]] Status admit_send(const DeviceId &dest, uint64_t expires_root_ms, MonoTime now);
    [[nodiscard]] bool search_allowed(MonoTime now);
    [[nodiscard]] bool handshake_allowed(MonoTime now) const;
    // parent side
    [[nodiscard]] bool deliverable(const MacAddr &mac, MonoTime now, bool first_send) const;
    void note_handoff(const MacAddr &mac);
    [[nodiscard]] bool mailbox_admit(const MacAddr &mac, MonoTime now);
    [[nodiscard]] bool child_known(const MacAddr &mac, MonoTime now) const;
    [[nodiscard]] bool child_asleep(const MacAddr &mac, MonoTime now) const;
    // root side
    void on_report(const DeviceId &peer, ShortAddr addr, ByteView body, MonoTime now);
    [[nodiscard]] uint32_t lease_ms_for(ShortAddr addr, MonoTime now) const;
    // Does the root hold a fresh schedule report that says `dest` sleeps? (Waits for it instead of giving up.)
    [[nodiscard]] bool sleepy_target(const DeviceId &dest, MonoTime now) const;
    // WAIT_WAKE (root origin): how long until the earliest possible wake of `dest`; zero when awake or unknown.
    [[nodiscard]] Duration wait_for_wake(const DeviceId &dest, MonoTime now) const;
    [[nodiscard]] bool member_power(ShortAddr addr, MemberPower &out) const;
    // The root's wake estimate for a member, on the root clock (ms). quality per k_quality_*.
    [[nodiscard]] uint8_t next_wake(ShortAddr addr, uint64_t now_ms, uint64_t &earliest_ms, uint64_t &latest_ms) const;

    // ---- observation ----
    [[nodiscard]] State state() const { return st_; }
    [[nodiscard]] const Policy &policy() const { return policy_; }
    [[nodiscard]] const Stats &stats() const { return stats_; }
    [[nodiscard]] SessionPath last_session_path() const { return last_path_; }
    [[nodiscard]] int64_t last_sleep_life_ms() const { return sl_life_ms_; } // min(authorization, key) at entry
    [[nodiscard]] uint64_t radio_on_us(MonoTime now);
    // The episode's poll is over (granted, or given up): the receive window has been served.
    [[nodiscard]] bool poll_done() const { return !poll_.want || poll_.granted; }
    [[nodiscard]] MonoTime episode_end() const { return ep_end_; }
    [[nodiscard]] uint32_t offline_remaining_ms(MonoTime now);
    [[nodiscard]] uint64_t slept_ms(MonoTime now) const { return st_ == State::Sleeping ? static_cast<uint64_t>((now - slept_at_).to_ms()) : 0U; }
    void fill_snapshot(lm_power_snapshot_t &out, MonoTime now);

  private:
    struct Ticket {
        uint64_t id = 0, gen = 0, membership = 0;
        MonoTime expires = MonoTime::never();
        bool valid = false, taken = false;
    };
    struct OpRec {
        uint64_t id = 0;
        bool final = false;
        Status result = Status::Ok;
        uint64_t accepted_ms = 0, last_ms = 0;
    };
    struct Child { // a sleepy neighbour that polled (parent side)
        bool used = false, grant_due = false;
        MacAddr mac;
        uint16_t credit_left = 0, credit_req = 0, granted = 0, window_ms = 0;
        uint32_t interval_ms = 0;
        uint64_t nonce = 0;
        MonoTime first_poll = MonoTime::never(), last_poll = MonoTime::never(), awake_until = MonoTime{},
                 hold_until = MonoTime::never(), grant_at = MonoTime::never();
    };
    struct Poll { // this device's poll of the episode
        uint64_t nonce = 0;
        MonoTime first = MonoTime::never(), retry = MonoTime::never();
        uint8_t attempts = 0;
        uint16_t credit = 0, window_ms = 0, pending_more = 0;
        bool granted = false, want = false;
    };
    // Leaky buckets in microseconds: they drain at limit/window, so a boot that starts "empty" refills with
    // observed time and a rate limit never needs a calendar (docs/20 §8).
    struct Budgets {
        uint64_t offline_us = 0, extra_us = 0, extra_wakes_micro = 0;
        uint8_t cursor = 0, fail_streak = 0;
    };

    [[nodiscard]] bool sleepy_mode() const { return policy_.mode != k_always_rx; }
    void begin_episode(uint32_t reason, MonoTime now);
    void end_of_budget(MonoTime now);
    void emit(uint32_t reason, uint64_t operation = 0);
    [[nodiscard]] OpRec new_op(MonoTime now);
    void finish_op(OpRec &r, Status s, MonoTime now);
    // commands
    [[nodiscard]] Reply policy_set(const Command &cmd, MonoTime now);
    [[nodiscard]] Reply prepare(const SleepRequest &req, MonoTime now);
    [[nodiscard]] Reply ticket_get(uint64_t op, lm_sleep_ticket_t &out, MonoTime now);
    [[nodiscard]] Reply enter(const lm_sleep_ticket_t &t, MonoTime now);
    [[nodiscard]] Reply sleep_abort(uint64_t op, MonoTime now);
    void progress_prepare(MonoTime now);
    [[nodiscard]] bool quiet_now() const; // nothing in flight that a sleep would cut
    [[nodiscard]] Status begin_sleep(const SleepRequest &req, bool automatic, MonoTime now);
    void windowed_timer(MonoTime now);
    void drop_sessions();
    // poll/grant (power_link.cpp)
    void send_poll(MonoTime now);
    void poll_timer(MonoTime now);
    [[nodiscard]] bool continue_poll(MonoTime now);
    void on_poll(const link::RxInfo &info, const wire::PowerPoll &p, MonoTime now);
    void on_grant(const wire::PowerGrant &g, MonoTime now);
    [[nodiscard]] bool send_grant(Child &c, uint32_t ttl_ms, uint32_t reason, MonoTime now);
    void flush_grants(MonoTime now);
    // Awake now: inside the announced window, or in a link session newer than its last poll (it has just come back
    // and is still setting itself up: it cannot poll before that, and everything it needs must reach it).
    [[nodiscard]] bool child_awake(const Child &c, MonoTime now) const;
    [[nodiscard]] Child *find_child(const MacAddr &mac, MonoTime now);
    [[nodiscard]] const Child *find_child(const MacAddr &mac, MonoTime now) const;
    void expire_mailboxes(MonoTime now);
    // budgets
    void advance_budgets(MonoTime now);
    void clamp_budgets();
    void account_radio(MonoTime now);
    [[nodiscard]] bool offline() const;
    [[nodiscard]] MonoTime search_due() const;
    void save_retained();
    void load_retained(const port::WakeInfo &w);
    void set_locks();
    void send_report(MonoTime now);
    [[nodiscard]] Status root_check_target(const DeviceId &dest, uint64_t expires_root_ms, MonoTime now) const;

    Engine &engine_;
    Policy policy_ = gen::power_policy::k_always_rx;
    Stats stats_;
    State st_ = State::Running;
    bool loaded_ = false;
    bool policy_job_ = false, zombie_ = false;
    store::RecordJob *rec_ = nullptr; // the identity's record memory while a policy job owns it
    OpRec policy_op_, prep_op_;
    uint64_t op_counter_ = 0;
    // episode
    MonoTime ep_start_ = MonoTime::never(), ep_end_ = MonoTime::never(), overrun_at_ = MonoTime::never();
    uint32_t wake_reason_ = kNone, last_reason_ = kNone;
    bool ep_over_ = false, ep_extra_ = false, search_ended_ = false, window_closed_ = false;
    // sleep
    MonoTime wake_at_ = MonoTime::never(), slept_at_;
    SleepRequest cur_;
    port::WakeInfo pending_wake_;
    bool auto_ = false; // WINDOWED cycle: the app tasks keep running, only the radio sleeps
    uint8_t lock_mask_ = 0;
    int64_t sl_auth_ms_ = 0, sl_key_ms_ = 0, sl_life_ms_ = 0;
    SessionPath last_path_ = SessionPath::FreshEdhoc;
    // the ticket race
    uint64_t state_gen_ = 1, ticket_seq_ = 0;
    Ticket ticket_;
    bool prep_active_ = false;
    State prep_from_ = State::Running;
    SleepRequest prep_req_;
    MonoTime prep_limit_ = MonoTime::never();
    uint64_t prep_gen_ = 0;
    // window and poll (device side)
    MonoTime window_end_ = MonoTime::never(), next_window_ = MonoTime::never(), cont_start_ = MonoTime::never();
    Poll poll_;
    MacAddr poll_mac_; // the neighbour the last poll went to
    // budgets and accounting
    Budgets bud_;
    MonoTime bud_at_;
    MonoTime search_next_{};                   // offline backoff: no search before this (0: none)
    uint64_t radio_on_us_ = 0;
    MonoTime acct_at_ = MonoTime::never();
    bool acct_offline_ = false;
    bool boot_grant_ = false;
    uint32_t search_used_ms_ = 0;
    // tables
    std::array<Child, k_children> children_{};
    std::array<MemberPower, k_members> members_{};
};

} // namespace lm::power
