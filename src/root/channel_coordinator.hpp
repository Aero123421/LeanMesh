// The root's channel coordinator (docs/05, IMPLEMENTATION.md S17): the only issuer of channel plans.
//
//   MONITOR -> SURVEY -> PREPARING -> COMMITTED -> SWITCHING -> SETTLING -> MONITOR
//   failure: ABORTED (before the commit) or RECOVERING (after it: stragglers are followed, never undone)
//
// What starts it: two independent parent links reporting > 10 % RF loss over the degradation window (one bad link
// is the route module's job, C02), or an operator RECALCULATE. What stops it: freeze (no new plan; a plan in
// PREPARING is aborted, a COMMITTED one runs to its end), cooldown, the daily limit, a survey that cannot be done
// without stranding a child (no maintenance gap), a clock the plan cannot trust.
//
// Evidence is kept apart per member: READY (prepared, durable), STORED (COMMIT durable), APPLIED (on the new
// channel, told by the member itself). "unreachable" = required and never confirmed STORED; there is no single
// success flag. The root drives everything by repeating its request until the member's receipt answers (members
// are idempotent); receipts are never guessed. The root is also a participant: its own PREPARE/COMMIT go through
// the same channel::Channel code as everybody's. Sets are bit masks by address - 2 (at most 64). Owner thread only.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "core/channel/channel.hpp"
#include "core/channel/score.hpp"
#include "core/command.hpp"
#include "core/delivery/route_spec.hpp"
#include "core/profile.hpp"
#include "core/time.hpp"

namespace lm {
class Engine;
}

namespace lm::root {

enum class CState : uint8_t { Monitor, Survey, Preparing, Committed, Switching, Settling, Aborted, Recovering };
// Why the coordinator is where it is / what the last evaluation concluded (the RETAINED family are decisions).
enum class Why : uint8_t {
    None, Moved, RetainedNoData, RetainedWorse, RetainedSmall, SingleLink, GapNeeded, CriticalAsleep, Frozen, Cooldown,
    DailyLimit, NoCandidates, PrepareTimeout, Refused, TimeUncertain, SurveyFailed, NoMembers,
};

class Coordinator {
  public:
    explicit Coordinator(Engine &engine) : engine_(engine) {}
    Coordinator(const Coordinator &) = delete;
    Coordinator &operator=(const Coordinator &) = delete;

    // ---- Engine / Channel wiring ----
    void stop();
    void on_timer(MonoTime now);
    [[nodiscard]] MonoTime deadline() const;
    void on_record(const DeviceId &peer, const delivery::PathSpec &reply, ByteView body, MonoTime now);
    void on_local_receipt(const channel::Receipt &r, MonoTime now);
    void on_local_survey(const channel::SurveyResult &r, MonoTime now);
    void on_local_switch(MonoTime now);
    void on_loaded(MonoTime now);
    void save(Writer &w) const;
    // `committed`: the channel record was COMMITTED when the power went: that plan is followed to its end.
    void restore(Reader &r, const channel::Plan *committed);

    // ---- commands ----
    // lm_channel_request: 0 auto (unfreeze), 1 freeze, 2 recalculate. Conflict = stale policy revision.
    [[nodiscard]] Reply request(uint32_t action, uint64_t expected_revision, MonoTime now);
    [[nodiscard]] Status rollback(MonoTime now); // a new plan back to the previous channel, higher epoch (docs/05 §8)
    [[nodiscard]] Status plan_to(uint8_t channel, MonoTime now); // operator override / bench: no survey, same rules
    void set_maintenance_gap(bool on) { gap_ = on; }
    void allow_deferred(bool on) { defer_ok_ = on; }
    void set_sleepy(ShortAddr a, bool on) { flag(sleepy_, a, on); }
    void set_critical(ShortAddr a, bool on) { flag(critical_, a, on); }
    void set_max_clock_error(uint32_t ms) { max_err_ms_ = ms; } // policy range 50..10000 ms (docs/05 §9)
    // Bench only (meshsim in real time): the switch is at start + prepare timeout + lead.
    void set_timing(uint32_t prepare_timeout_ms, uint32_t commit_lead_ms) {
        prepare_timeout_ms_ = prepare_timeout_ms;
        commit_lead_ms_ = commit_lead_ms;
    }

    // ---- observation ----
    struct View {
        CState state = CState::Monitor;
        Why why = Why::None;
        uint8_t current = 0;
        uint32_t epoch = 0;
        bool frozen = false;
        uint64_t policy_revision = 0;
        std::array<uint8_t, 16> plan_id{};
        uint64_t required = 0, ready = 0, stored = 0, applied = 0, unreachable = 0, deferred = 0;
    };
    [[nodiscard]] View view() const;
    [[nodiscard]] CState state() const { return state_; }
    [[nodiscard]] Why why() const { return why_; }
    [[nodiscard]] const channel::Plan &plan() const { return plan_; }
    [[nodiscard]] Status last_refusal() const { return last_refusal_; }
    struct Stats {
        uint32_t plans = 0, commits = 0, aborts = 0, surveys = 0, visits = 0, degraded = 0;
    };
    [[nodiscard]] const Stats &stats() const { return stats_; }
    // The last survey: samples[pair][0 = home, 1.. = candidates], the channels behind the columns.
    [[nodiscard]] const std::array<channel::Row, channel::k_max_pairs> &samples() const { return res_; }
    [[nodiscard]] unsigned pairs() const { return n_pairs_; }
    [[nodiscard]] unsigned candidates() const { return n_cands_; }
    [[nodiscard]] uint8_t candidate_channel(unsigned i) const { return cand_ch_[i]; }
    [[nodiscard]] Status survey_reason() const { return survey_reason_; }

  private:
    enum class Vs : uint8_t { Idle, Listen, Probe, Gap };

    [[nodiscard]] static uint64_t bit(uint16_t addr) { return 1ULL << (addr - 2U); }
    static void flag(uint64_t &mask, ShortAddr a, bool on) {
        if (a.value() >= 2 && a.value() < 66) {
            mask = on ? (mask | bit(a.value())) : (mask & ~bit(a.value()));
        }
    }

    // the tree (admitted members) plus the end session / ledger for identities
    [[nodiscard]] bool attached(uint16_t addr, MonoTime now) const;
    [[nodiscard]] unsigned children_of(uint16_t addr, MonoTime now) const;
    [[nodiscard]] bool device_at(uint16_t addr, DeviceId &out) const;
    [[nodiscard]] bool member_of(const DeviceId &peer, uint16_t &addr) const;
    [[nodiscard]] Status send_to(uint16_t addr, ByteView rec, MonoTime now);
    template <class M> Status send_to(uint16_t addr, const M &m, MonoTime now) {
        std::array<uint8_t, channel::k_max_record> buf{};
        std::size_t len = 0;
        const Status st = encode(m, MutByteView{buf}, len);
        return st == Status::Ok ? send_to(addr, ByteView{buf.data(), len}, now) : st;
    }

    // plan
    [[nodiscard]] Status begin_plan(uint8_t new_ch, MonoTime now);
    void plan_tick(MonoTime now);
    void send_round(channel::Phase phase, uint64_t missing, MonoTime now);
    void abort_plan(Why why, MonoTime now);
    void finish_settle(MonoTime now);
    void apply(bool self, uint16_t addr, const channel::Receipt &r, MonoTime now);
    void set_state(CState s, Why why);
    void changed(MonoTime now);

    // survey
    void start_survey(MonoTime now);
    void survey_tick(MonoTime now);
    void send_survey(channel::Side role, MonoTime now);
    void retry_visit(MonoTime now, Duration delay);
    void next_visit(MonoTime now);
    void end_survey(MonoTime now);
    void on_survey_result(uint16_t addr, const channel::SurveyResult &r, MonoTime now);
    void note_degraded(uint16_t addr, MonoTime now);
    [[nodiscard]] bool may_start(bool operator_override, MonoTime now);

    Engine &engine_;
    CState state_ = CState::Monitor;
    Why why_ = Why::None;
    bool frozen_ = false;
    bool gap_ = false;      // maintenance_gap permitted: the survey may take relays off their channel briefly
    bool defer_ok_ = false; // the operator explicitly accepts critical receivers being deferred
    uint32_t prepare_timeout_ms_ = static_cast<uint32_t>(gen::defaults::channel::prepare_timeout_ms);
    uint32_t commit_lead_ms_ = static_cast<uint32_t>(gen::defaults::channel::commit_lead_ms);
    uint32_t max_err_ms_ = static_cast<uint32_t>(gen::defaults::channel::max_clock_error_ms);
    uint64_t policy_rev_ = 0;
    uint64_t sleepy_ = 0, critical_ = 0;
    Stats stats_;

    // the plan in flight or the last one
    channel::Plan plan_;
    uint64_t required_ = 0, ready_ = 0, stored_ = 0, applied_ = 0, deferred_ = 0;
    uint8_t self_ev_ = 0; // the root's own evidence (0 none, 1 ready, 2 stored, 3 applied)
    uint8_t cursor_ = 0;
    uint8_t rollback_to_ = 0; // the channel before the last committed plan
    bool aborted_local_ = false;
    Status last_refusal_ = Status::Ok;
    MonoTime plan_start_{}, tick_at_ = MonoTime::never(), switched_at_ = MonoTime::never();

    // pacing limits (seconds of this boot: the windows start again at a restart)
    MonoTime cool_until_{};
    std::array<uint32_t, 4> changes_{};
    uint8_t n_changes_ = 0;
    struct Deg {
        uint16_t addr = 0;
        uint32_t at_s = 0;
    };
    std::array<Deg, 4> deg_{};

    // the survey in flight
    struct Pair {
        uint16_t child = 0, parent = 0;
    };
    std::array<Pair, channel::k_max_pairs> pairs_{};
    std::array<channel::Row, channel::k_max_pairs> res_{};
    std::array<uint8_t, channel::k_max_cands> cand_ch_{};
    uint8_t n_pairs_ = 0, n_cands_ = 0, visit_ = 0; // visit_: pair-major, column 0 of each pair is the home baseline
    uint8_t vs_tries_ = 0;                          // attempts of this visit (a late ack, a wide clock bound, a lost answer)
    uint8_t pass_ = 0;                              // 1: the second pass repeats only the visits that gave no data
    Vs vs_ = Vs::Idle;
    uint16_t sid_ = 0;
    uint64_t vs_start_ms_ = 0;
    MonoTime vs_at_ = MonoTime::never(), survey_end_ = MonoTime::never();
    Status survey_reason_ = Status::Ok;
};

// Leaf/relay builds carry no coordinator (docs/02 §4).
struct NoCoordinator {
    explicit NoCoordinator(Engine &) {}
    void stop() {}
    void on_timer(MonoTime) {}
    [[nodiscard]] MonoTime deadline() const { return MonoTime::never(); }
    void on_record(const DeviceId &, const delivery::PathSpec &, ByteView, MonoTime) {}
    void on_local_receipt(const channel::Receipt &, MonoTime) {}
    void on_local_survey(const channel::SurveyResult &, MonoTime) {}
    void on_local_switch(MonoTime) {}
    void on_loaded(MonoTime) {}
    void save(Writer &) const {}
    void restore(Reader &, const channel::Plan *) {}
    [[nodiscard]] Reply request(uint32_t, uint64_t, MonoTime) { return Reply{Status::Unsupported, 0, 0}; }
};

using CoordinatorType = std::conditional_t<k_root_capable, Coordinator, NoCoordinator>;

} // namespace lm::root
