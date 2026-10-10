#include <kguard_field/presence_v2.hpp>

#include <algorithm>

#include <kguard_field/tof_validity.hpp>

namespace kguard::field::presence_v2 {
namespace {

bool percent_at_least(size_t part, size_t total, uint8_t percent) {
    return part * 100u >= total * percent;
}

uint16_t difference(uint16_t a, uint16_t b) {
    return a > b ? static_cast<uint16_t>(a - b) : static_cast<uint16_t>(b - a);
}

template <size_t Capacity>
uint16_t median_of_sorted(const std::array<uint16_t, Capacity>& values, size_t count) {
    if (count == 0) {
        return 0;
    }
    return static_cast<uint16_t>(
        (static_cast<uint32_t>(values[(count - 1) / 2]) +
         static_cast<uint32_t>(values[count / 2])) /
        2u);
}

}  // namespace

const char* occupancy_name(Occupancy value) {
    switch (value) {
        case Occupancy::Vacant:
            return "vacant";
        case Occupancy::Occupied:
            return "occupied";
        default:
            return "unknown";
    }
}

const char* bar_name(Bar value) {
    switch (value) {
        case Bar::Green:
            return "green";
        case Bar::Yellow:
            return "yellow";
        default:
            return "red";
    }
}

const char* fault_name(Fault value) {
    switch (value) {
        case Fault::None:
            return "none";
        case Fault::TofNoResponse:
            return "tof_no_response";
        case Fault::LearnTimeout:
            return "learn_timeout";
        case Fault::BackgroundChanged:
            return "background_changed";
        default:
            return "presence_lost";
    }
}

const char* learn_state_name(LearnState value) {
    switch (value) {
        case LearnState::Idle:
            return "idle";
        case LearnState::Running:
            return "running";
        case LearnState::Done:
            return "done";
        default:
            return "failed";
    }
}

const char* transition_name(TransitionKind value) {
    return value == TransitionKind::In ? "in" : "out";
}

size_t Config::min_learn_samples() const {
    if (decision_window_ms == 0) {
        return 0;
    }
    return static_cast<size_t>(min_decision_samples) * learn_window_ms /
        decision_window_ms;
}

bool Config::valid() const {
    // The band floor stays below the near threshold, so a reading can never
    // be a person and the empty room at once by the floor alone.
    const bool ranges = min_valid_mm > 0 && min_valid_mm < max_valid_mm &&
        near_delta_mm > 0 && band_noise_multiplier > 0 &&
        band_min_mm < near_delta_mm;
    // entry + exit > 100 keeps both switches from holding on one stretch.
    const bool decisions = decision_window_ms > 0 && min_decision_samples > 0 &&
        min_decision_samples <= kSampleCapacity && entry_percent > 0 &&
        entry_percent <= 100 && exit_percent > 0 && exit_percent <= 100 &&
        entry_percent + exit_percent > 100;
    // At least 3 readings per switch: 1-2 outliers must never switch.
    const bool switches = entry_samples >= 3 && entry_samples <= kSampleCapacity &&
        exit_samples >= 3 && exit_samples <= kSampleCapacity &&
        entry_window_ms > 0 && entry_window_ms <= kMaxSwitchWindowMs &&
        exit_window_ms > 0 && exit_window_ms <= kMaxSwitchWindowMs;
    const bool doubt = support_percent > 0 && support_percent <= 100 &&
        occupied_valid_percent <= 100 &&
        doubt_window_ms >= decision_window_ms && doubt_fault_ms > 0 &&
        no_sample_fault_ms > 0;
    const bool learning = learn_window_ms >= decision_window_ms &&
        learn_valid_percent > 0 && learn_valid_percent <= 100 &&
        learn_width_divisor > 0 && learn_timeout_ms >= learn_window_ms &&
        min_learn_samples() <= kSampleCapacity;
    const bool tracking = track_time_constant_ms > 0 &&
        track_background_percent > 0 && track_background_percent <= 100;
    return ranges && decisions && switches && doubt && learning && tracking;
}

Detector::Detector(const Config& config)
    : config_(config), config_ok_(config.valid()) {}

bool Detector::set_config(const Config& config) {
    if (!config.valid()) {
        return false;
    }
    config_ = config;
    config_ok_ = true;
    update_band();
    reclassify();
    return true;
}

void Detector::begin(uint64_t now_ms, uint32_t generation, const Background* stored) {
    begun_ = true;
    now_ms_ = begin_ms_ = now_ms;
    have_sample_ = false;
    no_response_ = false;
    generation_ = generation;
    background_ = Background{};
    band_mm_ = anchor_mm_ = 0;
    track_fp_ = 0;
    held_ = Occupancy::Unknown;
    learn_state_ = LearnState::Idle;
    learn_no_ = learn_done_no_ = 0;
    restart_evidence(now_ms);
    // A fresh boot drops every latch (restart_evidence keeps them: only
    // begin, a new generation, and the clear conditions reset them).
    doubt_fault_ = Fault::None;
    learn_fault_ = false;
    sensor_recover_reset(now_ms);
    if (stored != nullptr && stored->generation == generation &&
        stored->distance_mm >= config_.min_valid_mm + config_.near_delta_mm &&
        stored->distance_mm <= config_.max_valid_mm) {
        set_background(*stored);
        learn_done_no_ = stored->learn_no;
    }
}

void Detector::update(uint64_t now_ms, uint16_t distance_mm, uint8_t range_status) {
    if (!begun_ || !config_ok_ || now_ms < now_ms_) {
        return;
    }
    tick(now_ms);
    const uint64_t step_ms = have_sample_ ? now_ms - last_sample_ms_ : 0;
    have_sample_ = true;
    last_sample_ms_ = now_ms;
    if (now_ms - begin_ms_ < config_.settle_ms) {
        return;
    }
    const bool valid = tof_sample_valid(
                           TofModel::Tof400c, range_status, distance_mm, true, false) &&
        distance_mm >= config_.min_valid_mm && distance_mm <= config_.max_valid_mm;
    // Recovery counts every sample's validity, also while learning. A
    // single answered sample never clears a sensor fault (K1b): only the
    // 3-minute streak in roll_recovery does.
    note_sample_for_recovery(now_ms, valid);
    const Evidence evidence = classify(valid, distance_mm);
    push(now_ms, distance_mm, valid, evidence);
    last_evidence_ = evidence;
    last_valid_ = valid;
    if (learn_state_ == LearnState::Running) {
        // The body is frozen while learning (3章 2.5): no switch, no doubt.
        evaluate_learning(now_ms);
        return;
    }
    if (!has_background()) {
        return;
    }
    if (config_.track_background) {
        track(now_ms, step_ms, distance_mm, evidence);
    }
    decide(now_ms);
}

void Detector::tick(uint64_t now_ms) {
    if (!begun_ || !config_ok_ || now_ms < now_ms_) {
        return;
    }
    now_ms_ = now_ms;
    const uint64_t last = have_sample_ ? last_sample_ms_ : begin_ms_;
    if (!no_response_ && now_ms - last >= config_.no_sample_fault_ms) {
        no_response_ = true;
        sensor_recover_reset(now_ms);
        restart_evidence(now_ms);
    }
    if (learn_state_ == LearnState::Running &&
        now_ms - learn_started_ms_ >= config_.learn_timeout_ms) {
        // Keep the old background (if any) and go on detecting with it.
        // The failure — and any latched background fault — stays until a
        // relearn succeeds (K1b).
        learn_state_ = LearnState::Failed;
        learn_done_no_ = learn_no_;
        learn_fault_ = true;
        fresh_since_ms_ = now_ms;
        fresh_supported_ = false;
        doubt_ = false;
    }
    if (doubt_ && doubt_fault_ == Fault::None &&
        now_ms - doubt_since_ms_ >= config_.doubt_fault_ms) {
        doubt_fault_ = doubt_fault_code(now_ms);
        if (doubt_fault_ == Fault::PresenceLost) {
            sensor_recover_reset(now_ms);
        }
    }
    // Silence also closes recovery buckets: an empty second breaks the
    // 3-minute streak.
    roll_recovery(now_ms);
}

bool Detector::learn(uint64_t now_ms, uint32_t request_no) {
    if (!begun_ || !config_ok_ || now_ms < now_ms_ || request_no <= learn_done_no_ ||
        (learn_state_ == LearnState::Running && request_no <= learn_no_)) {
        return false;
    }
    tick(now_ms);
    learn_no_ = request_no;
    learn_state_ = LearnState::Running;
    learn_started_ms_ = now_ms;
    // Latched faults stay while the run is in flight: only its success
    // clears them (K1b).
    return true;
}

LatchState Detector::latch_state() const {
    LatchState saved;
    saved.generation = generation_;
    saved.no_response = no_response_ ? 1 : 0;
    saved.doubt_fault = static_cast<uint8_t>(doubt_fault_);
    saved.learn_fault = learn_fault_ ? 1 : 0;
    // The recovery streak never survives a reboot (FW1d-4): restored
    // sensor faults wait out the full 3 minutes again, so the export
    // carries no streak. (The field stays for the NVS blob shape.)
    saved.recover_good = 0;
    return saved;
}

void Detector::restore_latches(uint64_t now_ms, const LatchState& saved) {
    if (!begun_ || !config_ok_ || saved.generation != generation_) {
        return;
    }
    const uint64_t at_ms = now_ms < now_ms_ ? now_ms_ : now_ms;
    no_response_ = saved.no_response != 0;
    switch (static_cast<Fault>(saved.doubt_fault)) {
        case Fault::None:
        case Fault::PresenceLost:
        case Fault::BackgroundChanged:
            doubt_fault_ = static_cast<Fault>(saved.doubt_fault);
            break;
        default:
            // A code this firmware never wrote: fail closed to the sensor
            // cause (red with a blackout until the 3-minute recovery).
            doubt_fault_ = Fault::PresenceLost;
            break;
    }
    learn_fault_ = saved.learn_fault != 0;
    // Only the fault latches are restored; the recovery streak restarts
    // (FW1d-4): a restored sensor fault waits out the full 3 minutes
    // again. saved.recover_good is ignored — an older NVS blob may still
    // carry it. The open window restarts once the fresh boot's settle
    // ends (settle samples are ignored, so starting the window at the
    // restore would fail it at once). The blackout itself proves nothing.
    const uint64_t window_ms = at_ms > begin_ms_ + config_.settle_ms
        ? at_ms
        : begin_ms_ + config_.settle_ms;
    sensor_recover_reset(window_ms);
}

void Detector::set_generation(uint64_t now_ms, uint32_t generation) {
    if (!begun_ || generation == generation_) {
        return;
    }
    generation_ = generation;
    background_ = Background{};
    band_mm_ = anchor_mm_ = 0;
    track_fp_ = 0;
    held_ = Occupancy::Unknown;
    learn_state_ = LearnState::Idle;
    learn_no_ = learn_done_no_ = 0;
    const uint64_t at_ms = now_ms < now_ms_ ? now_ms_ : now_ms;
    restart_evidence(at_ms);
    // A new assignment drops every latch with the old background.
    doubt_fault_ = Fault::None;
    learn_fault_ = false;
    no_response_ = false;
    sensor_recover_reset(at_ms);
}

Occupancy Detector::state() const {
    if (!begun_ || !config_ok_ || no_response_ || doubt_ ||
        learn_state_ == LearnState::Running) {
        return Occupancy::Unknown;
    }
    return held_;
}

Bar Detector::bar() const {
    if (fault() != Fault::None) {
        return Bar::Red;
    }
    return state() == Occupancy::Unknown ? Bar::Yellow : Bar::Green;
}

Fault Detector::fault() const {
    if (!config_ok_) {
        return Fault::PresenceLost;
    }
    if (no_response_) {
        return Fault::TofNoResponse;
    }
    // learn_fault_ (not the Failed state): a retry in flight after a
    // failure still reports learn_timeout until it succeeds.
    if (learn_fault_) {
        return Fault::LearnTimeout;
    }
    return doubt_fault_;
}

bool Detector::sensor_fault() const {
    return !config_ok_ || sensor_latched();
}

bool Detector::background_fault() const {
    return doubt_fault_ == Fault::BackgroundChanged;
}

bool Detector::learn_fault() const {
    return learn_fault_;
}

bool Detector::sensor_latched() const {
    return no_response_ || doubt_fault_ == Fault::PresenceLost;
}

void Detector::sensor_recover_reset(uint64_t now_ms) {
    recover_window_ms_ = now_ms;
    recover_valid_ = 0;
    recover_total_ = 0;
    recover_good_ = 0;
}

void Detector::note_sample_for_recovery(uint64_t now_ms, bool valid) {
    if (!sensor_latched()) {
        return;
    }
    roll_recovery(now_ms);
    if (!sensor_latched()) {
        // Rolling just cleared the fault; this sample belongs to healthy
        // detection, not to a new streak.
        return;
    }
    ++recover_total_;
    if (valid) {
        ++recover_valid_;
    }
}

void Detector::roll_recovery(uint64_t now_ms) {
    while (sensor_latched() &&
        now_ms >= recover_window_ms_ + kRecoverWindowMs) {
        const bool pass = recover_total_ >= config_.min_decision_samples &&
            percent_at_least(
                recover_valid_, recover_total_, kRecoverValidPercent);
        recover_good_ = pass ? recover_good_ + 1 : 0;
        recover_valid_ = 0;
        recover_total_ = 0;
        recover_window_ms_ += kRecoverWindowMs;
        if (recover_good_ >= kRecoverGoodWindows) {
            clear_sensor_fault();
        }
    }
}

void Detector::clear_sensor_fault() {
    no_response_ = false;
    if (doubt_fault_ == Fault::PresenceLost) {
        doubt_fault_ = Fault::None;
    }
    // A background latch is a different cause with its own clear
    // condition (relearn success): it survives the sensor recovery.
    sensor_recover_reset(now_ms_);
}

const Transition* Detector::transition(size_t index) const {
    if (index >= transition_count_) {
        return nullptr;
    }
    return &transitions_[(transition_head_ + index) % kTransitionCapacity];
}

void Detector::ack(uint32_t n) {
    while (transition_count_ > 0 && transitions_[transition_head_].n <= n) {
        transition_head_ = (transition_head_ + 1) % kTransitionCapacity;
        --transition_count_;
    }
}

uint32_t Detector::ago_ms(const Transition& transition, uint64_t now_ms) {
    if (now_ms <= transition.at_ms) {
        return 0;
    }
    const uint64_t ago = now_ms - transition.at_ms;
    return ago > UINT32_MAX ? UINT32_MAX : static_cast<uint32_t>(ago);
}

Evidence Detector::classify(bool valid, uint16_t distance_mm) const {
    if (!valid || !has_background()) {
        return Evidence::None;
    }
    const uint16_t background = background_.distance_mm;
    // Checked first: with a noisy background the band may reach the near
    // threshold; a clearly nearer reading still counts as a person.
    if (static_cast<uint32_t>(distance_mm) + config_.near_delta_mm <= background) {
        return Evidence::Near;
    }
    if (difference(distance_mm, background) <= band_mm_) {
        return Evidence::Background;
    }
    return Evidence::None;
}

Detector::WindowCounts Detector::decision_window_counts(uint64_t now_ms) const {
    const Counts window = count(now_ms, config_.decision_window_ms);
    WindowCounts out;
    out.total = window.total;
    out.near = window.near;
    out.background = window.background;
    return out;
}

Detector::Breakdown Detector::breakdown(uint64_t now_ms, uint64_t window_ms) const {
    const Counts counts = count(now_ms, window_ms);
    Breakdown out;
    out.total = counts.total;
    out.near = counts.near;
    out.background = counts.background;
    out.mismatch = counts.mismatch;
    out.invalid = counts.total - counts.near - counts.background - counts.mismatch;
    return out;
}

// Whether, among the newest N * 100 / percent near/background readings
// (N = need), at least N are `want`: by default entry 8 of 11 (70%), exit
// 10 of 12 (80%). Only readings newer than window_ms and than the last switch
// (fresh_since_ms_) count: evidence for a switch is never older than the
// switch before it. Other readings (invalid, or valid but neither class)
// are neutral: they neither count nor take a place in the N * 100 /
// percent. A fixed count instead of the best-looking stretch keeps a
// steady 70/30 background/near mix (a person partly out of view) from
// ever proving an exit.
bool Detector::recent_stretch(
    uint64_t now_ms, Evidence want, Evidence against, uint8_t need,
    uint8_t percent, uint16_t window_ms) const {
    const uint64_t since = now_ms - fresh_since_ms_;
    const uint64_t limit = since < window_ms ? since : window_ms;
    const size_t places = static_cast<size_t>(need) * 100u / percent;
    const uint32_t now32 = static_cast<uint32_t>(now_ms);
    size_t support = 0;
    size_t seen = 0;
    for (size_t index = 0; index < sample_count_ && seen < places; ++index) {
        const Sample& sample =
            samples_[(sample_next_ + kSampleCapacity - 1 - index) % kSampleCapacity];
        if (static_cast<uint32_t>(now32 - sample.t_ms) >= limit) {
            break;
        }
        if (sample.evidence == want) {
            ++support;
            ++seen;
            if (support >= need) {
                return true;
            }
        } else if (sample.evidence == against) {
            ++seen;
        }
    }
    return false;
}

Detector::Counts Detector::count(uint64_t now_ms, uint64_t window_ms) const {
    Counts counts;
    const uint32_t now32 = static_cast<uint32_t>(now_ms);
    for (size_t index = 0; index < sample_count_; ++index) {
        const Sample& sample =
            samples_[(sample_next_ + kSampleCapacity - 1 - index) % kSampleCapacity];
        if (static_cast<uint32_t>(now32 - sample.t_ms) >= window_ms) {
            break;
        }
        ++counts.total;
        if (sample.evidence == Evidence::Near) {
            ++counts.near;
        } else if (sample.evidence == Evidence::Background) {
            ++counts.background;
        } else if (sample.valid) {
            ++counts.mismatch;
        }
    }
    return counts;
}

void Detector::push(uint64_t now_ms, uint16_t distance_mm, bool valid, Evidence evidence) {
    samples_[sample_next_] = Sample{
        static_cast<uint32_t>(now_ms), distance_mm, valid, evidence};
    sample_next_ = (sample_next_ + 1) % kSampleCapacity;
    if (sample_count_ < kSampleCapacity) {
        ++sample_count_;
    }
}

void Detector::set_background(const Background& background) {
    background_ = background;
    background_.generation = generation_;
    update_band();
    anchor_mm_ = background.distance_mm;
    track_fp_ = static_cast<int64_t>(background.distance_mm) << 16;
}

void Detector::update_band() {
    if (!has_background()) {
        band_mm_ = 0;
        return;
    }
    const uint32_t band = static_cast<uint32_t>(background_.noise_mm) *
        config_.band_noise_multiplier;
    band_mm_ = band > config_.band_min_mm
        ? static_cast<uint16_t>(band > UINT16_MAX ? UINT16_MAX : band)
        : config_.band_min_mm;
}

void Detector::reclassify() {
    for (size_t index = 0; index < sample_count_; ++index) {
        Sample& sample = samples_[index];
        sample.evidence = classify(sample.valid, sample.distance_mm);
    }
}

void Detector::restart_evidence(uint64_t now_ms) {
    sample_count_ = 0;
    sample_next_ = 0;
    last_evidence_ = Evidence::None;
    last_valid_ = false;
    fresh_since_ms_ = now_ms;
    fresh_supported_ = false;
    doubt_ = false;
    // Latched faults are kept on purpose: only the clear conditions (or
    // begin / a new generation) reset them.
}

void Detector::decide(uint64_t now_ms) {
    const Counts window = count(now_ms, config_.decision_window_ms);
    const bool enough = window.total >= config_.min_decision_samples;
    const bool entry = enough &&
        recent_stretch(now_ms, Evidence::Near, Evidence::Background,
                       config_.entry_samples, config_.entry_percent,
                       config_.entry_window_ms);
    const bool exit = enough &&
        recent_stretch(now_ms, Evidence::Background, Evidence::Near,
                       config_.exit_samples, config_.exit_percent,
                       config_.exit_window_ms);
    switch (held_) {
        case Occupancy::Unknown:
            // Start-up comparison with the stored background (3章 2.5).
            if (exit) {
                change(now_ms, Occupancy::Vacant, false);
            } else if (entry) {
                change(now_ms, Occupancy::Occupied, false);
            } else if (!doubt_) {
                doubt_ = true;
                doubt_since_ms_ = now_ms;
            }
            return;
        case Occupancy::Vacant:
            if (entry) {
                change(now_ms, Occupancy::Occupied, true);
                return;
            }
            break;
        case Occupancy::Occupied:
            if (exit) {
                change(now_ms, Occupancy::Vacant, true);
                return;
            }
            break;
    }
    evaluate_doubt(now_ms);
}

void Detector::evaluate_doubt(uint64_t now_ms) {
    const uint64_t since = now_ms - fresh_since_ms_;
    const uint64_t window_ms =
        since < config_.doubt_window_ms ? since : config_.doubt_window_ms;
    const Counts counts = count(now_ms, window_ms);
    bool doubt = false;
    if (counts.total < config_.min_decision_samples) {
        // Right after a decision the new state was just proven; too few
        // samples since then is not doubt. Anything else (a full second, or
        // a restart after the sensor stopped) with this little evidence is.
        doubt = !(fresh_supported_ && window_ms < config_.doubt_window_ms);
    } else if (held_ == Occupancy::Vacant) {
        // Only background supports an empty room: invalid readings count
        // against it ("none" is never evidence of empty).
        doubt = !percent_at_least(
            counts.background, counts.total, config_.support_percent);
    } else {
        // A seated person often returns invalid bursts (9/22 site data):
        // invalid readings neither support nor contradict occupied. Doubt
        // when the valid readings are mostly not a person, or when almost
        // nothing valid comes back.
        const size_t valid = counts.near + counts.background + counts.mismatch;
        doubt = !percent_at_least(valid, counts.total, config_.occupied_valid_percent) ||
            valid == 0 ||
            !percent_at_least(counts.near, valid, config_.support_percent);
    }
    if (!doubt) {
        // Yellow follows the evidence, but a latched fault stays until
        // its own clear condition (K1b).
        doubt_ = false;
    } else if (!doubt_) {
        doubt_ = true;
        doubt_since_ms_ = now_ms;
    }
}

void Detector::evaluate_learning(uint64_t now_ms) {
    if (now_ms - learn_started_ms_ < config_.learn_window_ms) {
        return;
    }
    // Every sample in the window is newer than the request, because the
    // window is not longer than the time since the request.
    std::array<uint16_t, kSampleCapacity> values{};
    size_t total = 0;
    size_t valid = 0;
    const uint32_t now32 = static_cast<uint32_t>(now_ms);
    for (size_t index = 0; index < sample_count_; ++index) {
        const Sample& sample =
            samples_[(sample_next_ + kSampleCapacity - 1 - index) % kSampleCapacity];
        if (static_cast<uint32_t>(now32 - sample.t_ms) >= config_.learn_window_ms) {
            break;
        }
        ++total;
        if (sample.valid) {
            values[valid++] = sample.distance_mm;
        }
    }
    if (total < config_.min_learn_samples() ||
        !percent_at_least(valid, total, config_.learn_valid_percent) || valid == 0) {
        return;
    }
    std::sort(values.begin(), values.begin() + valid);
    const uint16_t p10 = values[valid / 10];
    const uint16_t p90 = values[valid - 1 - valid / 10];
    const uint16_t median = median_of_sorted(values, valid);
    const uint16_t allowed_width =
        std::max<uint16_t>(config_.learn_width_min_mm, median / config_.learn_width_divisor);
    if (p90 - p10 > allowed_width) {
        return;
    }
    // A background nearer than 250 mm leaves no room for "near" above the
    // 100 mm floor: a person could never be seen. Keep trying (then fail).
    if (median < config_.min_valid_mm + config_.near_delta_mm) {
        return;
    }
    for (size_t index = 0; index < valid; ++index) {
        values[index] = difference(values[index], median);
    }
    std::sort(values.begin(), values.begin() + valid);
    const uint16_t noise = std::max<uint16_t>(median_of_sorted(values, valid), 1);

    Background learned;
    learned.distance_mm = median;
    learned.noise_mm = noise;
    learned.learn_no = learn_no_;
    set_background(learned);
    learn_state_ = LearnState::Done;
    learn_done_no_ = learn_no_;
    // Relearn success clears the background and learning latches. A
    // sensor latch (no sample, presence_lost) has its own clear
    // condition and survives this.
    learn_fault_ = false;
    if (doubt_fault_ == Fault::BackgroundChanged) {
        doubt_fault_ = Fault::None;
    }
    reclassify();
    // A person confirmed the room empty and the readings agree. If the body
    // said occupied, this closes that visit with an exit.
    change(now_ms, Occupancy::Vacant, true);
}

void Detector::track(
    uint64_t now_ms, uint64_t step_ms, uint16_t distance_mm, Evidence evidence) {
    if (held_ != Occupancy::Vacant || doubt_ || evidence != Evidence::Background) {
        return;
    }
    const Counts window = count(now_ms, config_.decision_window_ms);
    if (window.total < config_.min_decision_samples ||
        !percent_at_least(window.background, window.total, config_.track_background_percent)) {
        return;
    }
    if (step_ms > config_.decision_window_ms) {
        step_ms = config_.decision_window_ms;
    }
    const int64_t target = static_cast<int64_t>(distance_mm) << 16;
    track_fp_ += (target - track_fp_) * static_cast<int64_t>(step_ms) /
        static_cast<int64_t>(config_.track_time_constant_ms);
    // Beyond the cap the readings leave the band and the doubt rules take
    // over (yellow, then background_changed), like at start-up.
    const int64_t low = static_cast<int64_t>(anchor_mm_ > config_.track_limit_mm
                                                 ? anchor_mm_ - config_.track_limit_mm
                                                 : 0)
        << 16;
    const int64_t high =
        static_cast<int64_t>(anchor_mm_ + config_.track_limit_mm) << 16;
    track_fp_ = std::min(std::max(track_fp_, low), high);
    background_.distance_mm = static_cast<uint16_t>((track_fp_ + (1 << 15)) >> 16);
}

void Detector::change(uint64_t now_ms, Occupancy next, bool record) {
    const Occupancy previous = held_;
    held_ = next;
    fresh_since_ms_ = now_ms;
    fresh_supported_ = true;
    doubt_ = false;
    // A state switch never clears a latched fault (K1b): the visit
    // genuinely changed, and the fault still waits for its own clear
    // condition.
    if (record && previous != Occupancy::Unknown && previous != next) {
        emit(next == Occupancy::Occupied ? TransitionKind::In : TransitionKind::Out, now_ms);
    }
}

void Detector::emit(TransitionKind kind, uint64_t now_ms) {
    if (transition_count_ == kTransitionCapacity) {
        // Never stop deciding because nobody acknowledged (3章 2.7).
        transition_head_ = (transition_head_ + 1) % kTransitionCapacity;
        --transition_count_;
        ++dropped_;
    }
    transitions_[(transition_head_ + transition_count_) % kTransitionCapacity] =
        Transition{next_n_++, kind, now_ms};
    ++transition_count_;
}

Fault Detector::doubt_fault_code(uint64_t now_ms) const {
    if (held_ == Occupancy::Occupied) {
        return Fault::PresenceLost;
    }
    // Vacant or at start-up: readings that are valid but match neither the
    // background nor a person mean the scene changed (an object, a moved
    // sensor). Mostly invalid readings mean the sensor cannot see.
    const Counts counts = count(now_ms, config_.doubt_window_ms);
    return counts.total > 0 && counts.mismatch * 2 >= counts.total
        ? Fault::BackgroundChanged
        : Fault::PresenceLost;
}

}  // namespace kguard::field::presence_v2
