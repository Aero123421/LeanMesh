#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

// Presence (occupancy) detector for the display board, 9/27 version.
//
// Design: docs/redesign/03-judgment-and-recovery.md section 2.
// Initial values: docs/redesign/impl/plan-site.md section 4.10. Every number
// is provisional and is to be tuned with recordings (firmware/tools/
// record_presence.py, then `program --replay` in firmware/native-test).
// NOT verified on hardware.
//
// Fed one VL53L1X result at a time. No heap, no I/O, no NVS, no floating
// point. The caller owns time, persistence and messages. Not thread-safe:
// exactly one task owns a Detector.
//
// Evidence of one sample:
//   near        valid and at least 150 mm closer than the background
//   background  valid and within background ± max(4 × noise, 25 mm)
//   none        everything else: invalid status, outside 100..4000 mm,
//               farther than the band, or between the band and "near".
//               "none" is never evidence of an empty room.
// Decisions (9/27 field fix, after the 9/22 test showed late and unstable
// detection): a switch counts only near and background readings newer
// than the last switch and than 1 s. Invalid readings and valid readings
// that match neither class are neutral: they neither count nor break the
// count (a seated person returns invalid bursts).
//   vacant -> occupied   at least 8 near among the newest 11 near/
//                        background readings (8 / 70%). Clean: 0.28 s
//                        after the first near reading; a blockage shorter
//                        than that (a hand, the door) is ignored.
//   occupied -> vacant   at least 10 background among the newest 12
//                        (10 / 80%). Clean: 0.36 s. Stricter than entry:
//                        a wrong "vacant" is the harmful error.
//                        1-2 outliers of either kind never switch and do
//                        not undo a real switch in progress.
//   gate                 a switch also needs ≥8 samples in the last 0.5 s
//                        (the sensor runs at the planned rate).
//   unknown (yellow)     over the last 1 s (only after the last switch, so
//                        a fresh entry/exit does not flash yellow):
//                        vacant   — background below 50% of ALL samples
//                                   ("none" never supports empty);
//                        occupied — near below 50% of the valid samples,
//                                   or fewer than 20% of samples valid.
//                        held() keeps the last certain state; the body
//                        stays.
//   fault (red)          unknown for 10 s; no sample at all for
//                        no_sample_fault_ms; a requested learning not
//                        finished in 60 s.
// The entry, exit and yellow numbers are Config fields and can be changed
// at run time (set_config; the display's `#presence set`), never saved.
// Clearing (contract v1 section 3, K1b): a latched fault stays until its
// own clear condition — a passing doubt, a state switch or a new learn
// request never clears it. Sensor faults (no sample, presence_lost)
// clear after a valid-sample rate of at least 90% for 3 minutes
// straight; background_changed and a failed learning clear when a
// relearn succeeds. begin() and a new generation drop every latch; the
// caller keeps them across a reboot with latch_state()/restore_latches()
// (FW1c): NVS holds the export, restored faults still wait for their own
// clear conditions.
// Learning happens only on request (learn()). It needs 3 s of samples with
// ≥90% valid and a p10..p90 width ≤ max(40 mm, background / 25). It retries
// on a sliding window until 60 s, then fails.
// Start-up: a stored background of the current generation is compared with
// the first readings: background → vacant, near → occupied, neither for
// 10 s → fault (background_changed when most readings are valid but match
// neither, presence_lost when the sensor mostly cannot measure).
// Optional slow background tracking (off by default, plan 1.2 "余力枠"):
// only while vacant with ≥90% background over the last 0.5 s, time constant
// 3 min, at most ±50 mm from the learned/stored value.

namespace kguard::field::presence_v2 {

// Samples kept for the windows. 128 covers the 3 s learning window up to
// ~42 samples/s; the plan runs the sensor at 25 samples/s.
constexpr size_t kSampleCapacity = 128;
// Longest entry/exit stretch a config may ask for (fits the buffer at the
// planned 25 samples/s).
constexpr uint16_t kMaxSwitchWindowMs = 3000;
// Unacknowledged entry/exit transitions (plan 4.2 `tr`: up to 16).
constexpr size_t kTransitionCapacity = 16;
// Sensor-fault recovery (contract v1 section 3, K1b): 180 consecutive
// 1 s windows (3 minutes), each with at least min_decision_samples
// samples and a valid-sample rate of at least 90%. A window that cannot
// support a decision cannot prove recovery, so it fails the streak.
constexpr uint32_t kRecoverWindowMs = 1000;
constexpr uint32_t kRecoverGoodWindows = 180;
constexpr uint8_t kRecoverValidPercent = 90;

// Wire names below are the strings of plan 4.2 (`occ`, `st`, `tr`).
enum class Occupancy : uint8_t { Unknown, Vacant, Occupied };
enum class Bar : uint8_t { Green, Yellow, Red };
enum class Fault : uint8_t {
    None,
    TofNoResponse,
    PresenceLost,
    LearnTimeout,
    BackgroundChanged,
};
enum class LearnState : uint8_t { Idle, Running, Done, Failed };
enum class Evidence : uint8_t { None, Near, Background };
enum class TransitionKind : uint8_t { In, Out };

const char* occupancy_name(Occupancy value);        // unknown vacant occupied
const char* bar_name(Bar value);                    // green yellow red
const char* fault_name(Fault value);                // none tof_no_response ...
const char* learn_state_name(LearnState value);     // idle running done failed
const char* transition_name(TransitionKind value);  // in out

struct Config {
    uint16_t min_valid_mm = 100;
    uint16_t max_valid_mm = 4000;
    uint16_t near_delta_mm = 150;
    uint16_t band_min_mm = 25;
    uint8_t band_noise_multiplier = 4;
    // Sample-rate gate: a switch needs this many samples in this window.
    uint16_t decision_window_ms = 500;
    uint8_t min_decision_samples = 8;
    // Entry: at least entry_samples near readings among the newest
    // entry_samples * 100 / entry_percent near/background readings newer
    // than entry_window_ms and than the last switch. Exit likewise with
    // background readings.
    uint8_t entry_samples = 8;
    uint8_t entry_percent = 70;
    uint16_t entry_window_ms = 1000;
    uint8_t exit_samples = 10;
    uint8_t exit_percent = 80;
    uint16_t exit_window_ms = 1000;
    uint16_t doubt_window_ms = 1000;
    uint8_t support_percent = 50;
    // While occupied, doubt also when fewer than this share of the samples
    // in the doubt window are valid (the sensor stopped seeing anything).
    uint8_t occupied_valid_percent = 20;
    uint32_t doubt_fault_ms = 10000;
    uint32_t no_sample_fault_ms = 1000;
    // Samples right after begin() are ignored while the sensor settles.
    uint32_t settle_ms = 1000;
    uint16_t learn_window_ms = 3000;
    uint8_t learn_valid_percent = 90;
    uint16_t learn_width_min_mm = 40;
    uint16_t learn_width_divisor = 25;
    uint32_t learn_timeout_ms = 60000;
    bool track_background = false;
    uint32_t track_time_constant_ms = 180000;
    uint16_t track_limit_mm = 50;
    uint8_t track_background_percent = 90;

    bool valid() const;
    // Learning needs as many samples per second as a decision window does.
    size_t min_learn_samples() const;
};

// What the display keeps in NVS (plan 4.5 `kgd2/bg`). distance_mm == 0
// means "no background" (the body shows 準備中).
struct Background {
    uint32_t generation = 0;
    uint16_t distance_mm = 0;
    uint16_t noise_mm = 0;
    uint32_t learn_no = 0;  // the learn request this background answers
};

struct Transition {
    uint32_t n = 0;  // 1, 2, ... per Detector (= per boot); a gap = lost
    TransitionKind kind = TransitionKind::In;
    uint64_t at_ms = 0;  // detector clock when the change was decided
};

// Latched faults across a reboot (FW1c): what NVS keeps in kgd2/latch so a
// power cut never clears a fault early. Only the fault latches are
// restored; the recovery streak restarts (FW1d-4). Trivially copyable,
// stored as one blob with a schema word.
struct LatchState {
    uint32_t generation = 0;  // detector generation the latches belong to
    uint8_t no_response = 0;  // no-sample latch (sensor cause)
    // The doubt latch as a Fault code: None, PresenceLost (sensor cause)
    // or BackgroundChanged. Anything else fails closed to PresenceLost.
    uint8_t doubt_fault = 0;
    uint8_t learn_fault = 0;  // failed-learning latch
    uint8_t reserved = 0;
    // Unused since FW1d-4 (kept for the NVS blob shape): the recovery
    // streak never survives a reboot — the export always writes 0 and
    // the restore ignores it — so a restored sensor fault waits out the
    // full 3 minutes again.
    uint32_t recover_good = 0;
};

static_assert(
    std::is_trivially_copyable<LatchState>::value,
    "LatchState is stored as raw bytes");

inline bool operator==(const LatchState& a, const LatchState& b) {
    return a.generation == b.generation && a.no_response == b.no_response &&
        a.doubt_fault == b.doubt_fault && a.learn_fault == b.learn_fault &&
        a.recover_good == b.recover_good;
}

inline bool operator!=(const LatchState& a, const LatchState& b) {
    return !(a == b);
}

class Detector {
public:
    // An invalid config fails closed: never leaves unknown, bar red.
    explicit Detector(const Config& config = Config{});

    // Call once per boot when ranging has started. `stored` may be null; a
    // background of another generation is ignored (plan 4.5).
    void begin(uint64_t now_ms, uint32_t generation, const Background* stored);

    // One ranging result. `range_status` is VL53L1X::RangeStatus (0 =
    // RangeValid); pass a non-zero status for a timed-out read. Samples with
    // a clock older than the last call are ignored.
    void update(uint64_t now_ms, uint16_t distance_mm, uint8_t range_status);

    // Advance timers without a sample. Call at least every 100 ms, also when
    // the sensor produces nothing (that is how "no response" is detected).
    void tick(uint64_t now_ms);

    // Learn the empty room for request `request_no` (view `rl`). Starts only
    // if request_no is newer than the last handled request and than a
    // running one; a repeated number never learns twice. Returns true when
    // a run started. A failed run also consumes its number. Starting a run
    // never clears a latched fault — only a success does (K1b).
    bool learn(uint64_t now_ms, uint32_t request_no);

    // The assignment generation changed: forget the background and the
    // learn number, back to "no background". Transition numbering goes on.
    void set_generation(uint64_t now_ms, uint32_t generation);

    // Exports the latched faults for NVS (FW1c). The sensing task saves
    // the export whenever it changes; a failed save is fault storage.
    // The recovery streak is not exported (FW1d-4).
    LatchState latch_state() const;
    // Restores fault latches exported before a reboot: call once after
    // begin() with the stored state. A generation mismatch restores
    // nothing; unknown codes fail closed (sensor cause). The recovery
    // streak always restarts: restored faults still wait for their own
    // clear conditions, a sensor fault for the full 3 minutes again.
    void restore_latches(uint64_t now_ms, const LatchState& saved);

    // Field tuning (the display's `#presence set`): replaces the decision
    // numbers at run time. An invalid config is refused and the old one
    // kept (returns false). Samples already held are re-classified with
    // the new thresholds; the state, the background, the queue and every
    // latch stay. Nothing is persisted: a reboot starts from the defaults.
    bool set_config(const Config& config);
    const Config& config() const { return config_; }

    // occ: vacant / occupied, or unknown while doubtful, learning, without a
    // background or without samples.
    Occupancy state() const;
    // Last certain state (the body while unknown). Unknown until the first
    // decision after boot or after the background was dropped.
    Occupancy held() const { return held_; }
    Bar bar() const;  // red if fault() != None, yellow if state() unknown
    // The primary latched fault (silence, then failed learning, then the
    // doubt latch). Simultaneous causes need the per-cause latches below.
    Fault fault() const;
    // Per-cause latches for the st report, which keeps every cause
    // (contract v1 section 3, K1b): the coarse "sensor" (silence,
    // presence_lost, an invalid config), "background_changed", and
    // "learn_timeout" (a failed run, kept across retries until one
    // succeeds).
    bool sensor_fault() const;
    bool background_fault() const;
    bool learn_fault() const;
    LearnState learn_state() const { return learn_state_; }
    uint32_t learn_done_no() const { return learn_done_no_; }  // st rl_done
    bool has_background() const { return background_.distance_mm != 0; }
    // Current background (tracked value when tracking is on) for NVS.
    Background background() const { return background_; }
    Evidence last_evidence() const { return last_evidence_; }
    // Whether the last sample passed the validity rule (status and range);
    // with last_evidence() None it tells "invalid" from "neither class".
    bool last_valid() const { return last_valid_; }
    // Half-width of the background band in use (mm); 0 without background.
    uint16_t band_mm() const { return band_mm_; }
    // Every class in the trailing window_ms (diagnostics: `#presence show`).
    struct Breakdown {
        size_t total = 0;
        size_t near = 0;
        size_t background = 0;
        size_t mismatch = 0;  // valid but neither near nor background
        size_t invalid = 0;
    };
    Breakdown breakdown(uint64_t now_ms, uint64_t window_ms) const;
    // Samples the detector holds in the trailing decision window ending
    // at now_ms — the same count decide() gates on (total >=
    // min_decision_samples). Exposed so the save-offload test checks the
    // detector's own accounting instead of re-counting feeds.
    struct WindowCounts {
        size_t total = 0;
        size_t near = 0;
        size_t background = 0;
    };
    WindowCounts decision_window_counts(uint64_t now_ms) const;
    bool config_ok() const { return config_ok_; }

    // Entry/exit queue for `tr`. Oldest first. When full, the oldest is
    // dropped and dropped() counts it; the receiver sees the gap in `n`.
    // Only observed changes are queued: the start-up comparison and
    // set_generation() never invent an entry time. A successful learning
    // while held() was occupied closes that visit with an "out".
    size_t pending() const { return transition_count_; }
    const Transition* transition(size_t index) const;
    void ack(uint32_t n);  // cumulative: removes every transition <= n
    uint32_t dropped() const { return dropped_; }
    static uint32_t ago_ms(const Transition& transition, uint64_t now_ms);

private:
    struct Sample {
        uint32_t t_ms = 0;  // low 32 bits; the buffer never spans a 1 s gap
        uint16_t distance_mm = 0;
        bool valid = false;
        Evidence evidence = Evidence::None;
    };
    struct Counts {
        size_t total = 0;
        size_t near = 0;
        size_t background = 0;
        size_t mismatch = 0;  // valid but neither near nor background
    };

    Evidence classify(bool valid, uint16_t distance_mm) const;
    Counts count(uint64_t now_ms, uint64_t window_ms) const;
    bool recent_stretch(
        uint64_t now_ms, Evidence want, Evidence against, uint8_t need,
        uint8_t percent, uint16_t window_ms) const;
    void update_band();
    void reclassify();
    void push(uint64_t now_ms, uint16_t distance_mm, bool valid, Evidence evidence);
    void set_background(const Background& background);
    void restart_evidence(uint64_t now_ms);
    void decide(uint64_t now_ms);
    void evaluate_doubt(uint64_t now_ms);
    void evaluate_learning(uint64_t now_ms);
    void track(uint64_t now_ms, uint64_t step_ms, uint16_t distance_mm, Evidence evidence);
    void change(uint64_t now_ms, Occupancy next, bool record);
    void emit(TransitionKind kind, uint64_t now_ms);
    Fault doubt_fault_code(uint64_t now_ms) const;
    bool sensor_latched() const;
    void sensor_recover_reset(uint64_t now_ms);
    void note_sample_for_recovery(uint64_t now_ms, bool valid);
    void roll_recovery(uint64_t now_ms);
    void clear_sensor_fault();

    Config config_;
    bool config_ok_ = true;
    bool begun_ = false;
    uint64_t now_ms_ = 0;
    uint64_t begin_ms_ = 0;
    bool have_sample_ = false;
    uint64_t last_sample_ms_ = 0;
    bool no_response_ = false;

    std::array<Sample, kSampleCapacity> samples_{};
    size_t sample_next_ = 0;
    size_t sample_count_ = 0;
    Evidence last_evidence_ = Evidence::None;
    bool last_valid_ = false;

    uint32_t generation_ = 0;
    Background background_{};
    uint16_t band_mm_ = 0;
    uint16_t anchor_mm_ = 0;  // learned/stored value; tracking cap centre
    int64_t track_fp_ = 0;    // tracked background, mm << 16

    Occupancy held_ = Occupancy::Unknown;
    // Doubt uses only samples after fresh_since_ms_ (last state change or
    // evidence restart). fresh_supported_ says whether that start itself was
    // backed by evidence (a decision) rather than a buffer restart.
    uint64_t fresh_since_ms_ = 0;
    bool fresh_supported_ = false;
    bool doubt_ = false;
    uint64_t doubt_since_ms_ = 0;
    // Latched when doubt reaches 10 s. A sensor word (PresenceLost) clears
    // by the 3-minute recovery below; BackgroundChanged clears when a
    // relearn succeeds. Never cleared by a passing doubt, a state switch,
    // a new learn request, or a sample gap (K1b).
    Fault doubt_fault_ = Fault::None;

    LearnState learn_state_ = LearnState::Idle;
    uint32_t learn_no_ = 0;
    uint32_t learn_done_no_ = 0;
    uint64_t learn_started_ms_ = 0;
    // A learn run failed; cleared when a run succeeds (kept across
    // retries, alongside any doubt latch).
    bool learn_fault_ = false;

    // Sensor-fault recovery streak, meaningful only while sensor_latched():
    // the open 1 s bucket starting at recover_window_ms_ and the count of
    // consecutive passing buckets before it.
    uint64_t recover_window_ms_ = 0;
    uint32_t recover_valid_ = 0;
    uint32_t recover_total_ = 0;
    uint32_t recover_good_ = 0;

    std::array<Transition, kTransitionCapacity> transitions_{};
    size_t transition_head_ = 0;
    size_t transition_count_ = 0;
    uint32_t next_n_ = 1;
    uint32_t dropped_ = 0;
};

}  // namespace kguard::field::presence_v2
