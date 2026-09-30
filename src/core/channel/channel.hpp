// The channel module of every node (docs/05, IMPLEMENTATION.md S17). One state machine, three jobs:
//
//   time      TIME_REQ/RESP with the root: the root clock as an interval (RTT-wide, drift-widened by the
//             delivery module), fed to Delivery::set_root_time. The root is its own time base.
//   plan      the participant side of PREPARE / COMMIT / ABORT: validate, persist (PREPARED / COMMITTED are
//             durable before the receipt goes out), guard, switch at the root time, persist the new current
//             channel. A committed plan is never undone by the node (no lone rollback). After a power cut:
//             PREPARED -> old channel, COMMITTED -> target channel, whatever the clock says.
//   recover   a node that lost its parent for k_scan_after searches: stored channel, pending target, then the
//             allowed set, 200 ms per channel, two laps, backoff 1..60 s. It only tunes the radio; nothing
//             is persisted before the root has told it (authenticated) what the epoch is.
//
// Plus the two small node parts of the survey (a paired visit: one side listens on the candidate channel,
// the other sends MAC-acked probes to it) and the degradation window that tells the root when the parent
// link keeps losing frames. The root's planner is root::Coordinator; the root also runs this module as one
// participant. No timer of its own while nothing is due (every deadline is a real one). Owner thread only.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/channel/wire.hpp"
#include "core/delivery/route_spec.hpp"
#include "core/pool.hpp"
#include "core/radio/tx_manager.hpp"
#include "core/time.hpp"
#include "gen/defaults.hpp"
#include "store/record.hpp"

namespace lm {
class Engine;
}

namespace lm::channel {

inline constexpr uint32_t k_tag_channel = 0x43480000; // "CH": survey probes
inline constexpr uint8_t k_max_probes = 8;
inline constexpr Duration k_time_refresh = Duration::from_s(300); // drift widens the interval 1 ms per second (2 x 500 ppm)
inline constexpr Duration k_scan_after = Duration::from_s(12); // no parent this long: search other channels
inline constexpr Duration k_dwell = Duration::from_ms(200);    // docs/05 §7 / docs/20 §8
inline constexpr unsigned k_scan_laps = 2;
inline constexpr Duration k_backoff_min = Duration::from_s(1);
inline constexpr Duration k_backoff_max = Duration::from_s(60);
inline constexpr uint32_t k_drain_ms = 1000;      // guard = 2 * max error + drain + 500 ms (docs/05 §5)
inline constexpr uint32_t k_store_margin_ms = 2000; // a PREPARE whose switch is nearer than guard + this is refused
inline constexpr uint16_t k_survey_tol_max_ms = 100;

// Observation only (diagnostics, tests).
enum class Mode : uint8_t { Normal, Prepared, Committed, Searching };

// Reasons carried in LM_EVENT_CHANNEL (`reason` = Mode << 8 | detail).
struct Stats { // counters of this boot (diagnostics, tests)
    uint32_t time_updates = 0;
    uint32_t prepared = 0, committed = 0, switched = 0, refused = 0;
    uint32_t scans = 0, scan_dwells = 0;
    uint32_t degraded_sent = 0;
    uint32_t surveys = 0;
};

class Channel {
  public:
    explicit Channel(Engine &engine) : engine_(engine) {}
    Channel(const Channel &) = delete;
    Channel &operator=(const Channel &) = delete;

    // ---- Engine wiring ----
    void on_identity_ready(MonoTime now);
    void on_job_done(Handle slot, Status s, MonoTime now);
    void on_timer(MonoTime now);
    [[nodiscard]] MonoTime deadline() const;
    void on_tx_outcome(const TxOutcome &o, MonoTime now);
    void stop();
    [[nodiscard]] bool job_pending() const { return job_ != Job::None || cancelled_; }
    // A CONTROL end record with a channel opcode (Mesh::on_control routes here).
    void on_record(const DeviceId &peer, const delivery::PathSpec &reply, ByteView body, MonoTime now);
    // Bench switch, like Mesh::set_enabled: sim nodes of other slices run without it.
    void set_enabled(bool on) {
        enabled_ = on;
        loaded_ = !on;
    }
    [[nodiscard]] bool enabled() const { return enabled_; }
    // The mesh must not start (beacons, hellos) before the stored channel is applied (docs/05 §7).
    [[nodiscard]] bool holds_mesh() const { return enabled_ && !loaded_; }

    // ---- hooks from the mesh module ----
    void on_ready(MonoTime now); // an approved path with a lease exists (again)
    void on_lost(MonoTime now);  // the path is gone
    void on_term(MonoTime now);  // ARCH2-D1: the node follows a newer root term (a committed plan of the old one switches)
    void on_link_sample(bool ok, MonoTime now); // one RF attempt towards the parent
    // Planned off-channel time (guard of a switch, survey visit): failures in it are not RF loss.
    [[nodiscard]] bool planned_gap(MonoTime now) const { return now < gap_end_; }

    // ---- root: the coordinator drives the local participant ----
    [[nodiscard]] Status local_plan(const PlanRec &rec, MonoTime now);
    [[nodiscard]] Status local_survey(const Survey &s, MonoTime now);
    void persist_now(MonoTime now) { dirty_ = true; kick(now); } // coordinator state changed

    // ---- observation ----
    [[nodiscard]] Mode mode() const;
    [[nodiscard]] uint8_t current() const { return cur_; }
    [[nodiscard]] ChannelEpoch epoch() const { return epoch_; }
    [[nodiscard]] bool have_plan() const { return phase_ != Ph::Idle; }
    [[nodiscard]] bool committed() const { return phase_ == Ph::Committed; }
    // A plan that is prepared or committed but not yet switched, or the write of one in progress: the node has
    // promised to be on the air and must not sleep (FIX3-D5).
    [[nodiscard]] bool unsettled() const { return phase_ != Ph::Idle || job_ != Job::None; }
    [[nodiscard]] const Plan &plan() const { return plan_; }
    [[nodiscard]] bool loaded() const { return loaded_; }
    [[nodiscard]] const Stats &stats() const { return stats_; }
    [[nodiscard]] uint64_t clock_width_ms(MonoTime now); // bound width, UINT64_MAX when unknown
    // Battery nodes: bounded search per wake episode (0 = unlimited, always-on nodes).
    void set_scan_limit(uint8_t attempts) { scan_limit_ = attempts; }
    // A new wake episode: the search may run again (at once when the node has no parent).
    void rearm_scan(MonoTime now) {
        scan_tries_ = 0;
        sc_backoff_ = k_backoff_min;
        on_lost(now);
    }
    [[nodiscard]] uint8_t scan_tries() const { return scan_tries_; }

  private:
    enum class Ph : uint8_t { Idle = 0, Prepared = 1, Committed = 2 };
    enum class Job : uint8_t { None, Load, Persist };
    enum class After : uint8_t { None, Prepared, Stored, Applied };
    enum class Sw : uint8_t { None, Hold, Switch, Release };
    enum class Sv : uint8_t { None, Wait, Prep, Away };

    [[nodiscard]] bool is_root() const;
    [[nodiscard]] RootTerm term() const;
    [[nodiscard]] uint16_t allowed_mask() const;
    [[nodiscard]] uint16_t jitter(uint16_t modulus);
    [[nodiscard]] MonoTime reach(uint64_t root_ms, MonoTime now); // local time the estimate reaches root_ms
    [[nodiscard]] Status to_root(ByteView rec, MonoTime now);
    void notify(uint32_t detail);

    // persistence (one job at a time, the identity's lent record memory)
    void kick(MonoTime now);
    // Load, or Persist of the record (version | phase | current channel | epoch | plan | root extras) with `phase`
    // and `plan` next to the live channel and epoch.
    [[nodiscard]] Status begin_job(Job kind, Ph phase, const Plan &plan, After after, MonoTime now);
    [[nodiscard]] bool adopt_record(Reader &rd);
    void loaded_ok(Status s, MonoTime now);
    void persisted(Status s, MonoTime now);

    // plan (participant)
    [[nodiscard]] static bool same_plan(const Plan &a, const Plan &b);
    void on_plan(const PlanRec &rec, bool local, MonoTime now);
    void prepare(const Plan &p, bool local, MonoTime now);
    void commit(const Plan &p, bool local, MonoTime now);
    void reply(const Plan &p, Evidence ev, Status why, bool local, MonoTime now);
    void arm_switch(MonoTime now);
    void switch_step(MonoTime now);
    void apply_target(MonoTime now);
    [[nodiscard]] Status set_radio(uint8_t channel);

    // time
    void on_time_resp(const TimeResp &r, MonoTime now);
    void time_step(MonoTime now);

    // recovery scan
    void scan_step(MonoTime now);
    void scan_end(MonoTime now);
    [[nodiscard]] unsigned scan_list(std::array<uint8_t, 14> &out) const;

    // survey (participant)
    void on_survey(const Survey &s, bool local, MonoTime now);
    void survey_step(MonoTime now);
    void probe_next(MonoTime now);
    void survey_finish(MonoTime now);
    void answer(const SurveyResult &r, bool local, MonoTime now);
    void anchor_root(MonoTime now); // the root's clock is its own interval of zero width
    template <class M> [[nodiscard]] Status send(const M &m, MonoTime now) { // one record to the root
        std::array<uint8_t, k_max_record> buf{};
        std::size_t len = 0;
        const Status st = encode(m, MutByteView{buf}, len);
        return st == Status::Ok ? to_root(ByteView{buf.data(), len}, now) : st;
    }

    Engine &engine_;
    bool enabled_ = true;
    bool loaded_ = false;
    bool faulted_ = false; // the record could not be read: no plan is accepted (fail closed)
    bool dirty_ = false;
    Stats stats_;

    // persisted state
    Ph phase_ = Ph::Idle;
    uint8_t cur_ = 0;
    ChannelEpoch epoch_;
    Plan plan_;

    // job
    Job job_ = Job::None;
    After after_ = After::None;
    bool after_local_ = false;
    bool cancelled_ = false;
    Handle job_slot_;
    uint32_t job_gen_ = 0;
    store::RecordJob *rec_ = nullptr;
    MonoTime retry_at_ = MonoTime::never(); // no record memory / job slot right now

    // guard + switch
    Sw sw_ = Sw::None;
    MonoTime switch_at_ = MonoTime::never(); // local instant of the switch
    MonoTime sw_at_ = MonoTime::never();
    uint8_t sw_tries_ = 0;
    MonoTime gap_end_{};

    // time
    MonoTime time_at_ = MonoTime::never();
    MonoTime t1_{};
    std::array<uint8_t, 8> nonce_{};
    bool time_wait_ = false;
    uint8_t time_tries_ = 0;
    bool state_sent_ = false;

    // recovery scan
    enum class Sc : uint8_t { Idle, Armed, Dwell, Backoff };
    Sc sc_ = Sc::Idle;
    MonoTime sc_at_ = MonoTime::never();
    MonoTime dwell_start_{};
    bool dwell_open_ = false;
    uint8_t sc_index_ = 0;
    uint8_t sc_lap_ = 0;
    Duration sc_backoff_ = k_backoff_min;
    uint8_t scan_tries_ = 0;
    uint8_t scan_limit_ = 0;

    // degradation window (parent link)
    MonoTime win_end_ = MonoTime::never();
    uint16_t win_attempts_ = 0, win_fails_ = 0;

    // survey participant: one visit at a time
    Sv sv_ = Sv::None;
    bool sv_visit_ = false; // the node leaves its channel (else: a baseline probe on the home channel, no clock needed)
    Survey svq_;
    MonoTime sv_at_ = MonoTime::never();
    MonoTime probe_sent_{};
    uint8_t probes_done_ = 0, probes_ok_ = 0, probes_fail_ = 0;
    bool probe_out_ = false;
    std::array<uint8_t, k_max_probes> probe_ms_{}; // TX-done latency of the acknowledged probes, ms (clamped)
    SurveyResult result_;
    uint8_t sv_home_ = 0;
};

} // namespace lm::channel
