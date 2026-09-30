#include "core/route/score.hpp"

#include <algorithm>

namespace lm::route {

namespace {
int32_t ewma(int32_t p, int32_t sample) { return p + (sample - p) / 8; }
} // namespace

void LinkQuality::record_attempt(bool success) {
    success_q16 = ewma(success_q16, success ? k_q16_one : 0);
    if (samples != UINT16_MAX) {
        ++samples;
    }
}

void LinkQuality::record_queue_ms(uint32_t sample_ms) {
    const int32_t s = static_cast<int32_t>(std::min(sample_ms, k_queue_ms_max));
    queue_ms = static_cast<uint16_t>(std::clamp<int32_t>(ewma(queue_ms, s), 0, 500));
}

uint32_t LinkQuality::etx_q8() const {
    const int64_t p = std::max<int64_t>(success_q16, 4096);
    const int64_t etx = (256LL * k_q16_one) / p;
    return static_cast<uint32_t>(std::clamp<int64_t>(etx, k_etx_min_q8, k_etx_max_q8));
}

void Instability::note_change(MonoTime now) {
    // Decay first so an old level does not stack on a fresh change.
    level = static_cast<uint8_t>(std::min<uint32_t>(penalty(now) / k_penalty_step + 1U,
                                                   k_penalty_max / k_penalty_step));
    stamp = now;
}

uint32_t Instability::penalty(MonoTime now) const {
    if (level == 0) {
        return 0;
    }
    const int64_t steps = (now - stamp).us / k_instability_window_us;
    const int64_t left = std::max<int64_t>(0, static_cast<int64_t>(level) - steps);
    return static_cast<uint32_t>(left) * k_penalty_step;
}

uint32_t parent_score(uint32_t depth, const LinkQuality &q, uint32_t penalty) {
    return 256U * depth + q.etx_q8() - 256U + q.queue_ms + penalty;
}

int pick_best(const Candidate *c, std::size_t n) {
    int best = -1;
    uint32_t best_score = 0;
    for (std::size_t i = 0; i < n; ++i) {
        if (!c[i].quality.known()) {
            continue;
        }
        const uint32_t s = parent_score(c[i].depth, c[i].quality, c[i].penalty);
        if (best < 0 || s < best_score ||
            (s == best_score && c[i].id < c[static_cast<std::size_t>(best)].id)) {
            best = static_cast<int>(i);
            best_score = s;
        }
    }
    return best;
}

bool should_switch(uint32_t current_score, uint32_t best_score, Duration held, bool current_dead) {
    if (current_dead) {
        return true;
    }
    if (held < Duration::from_ms(gen::defaults::routing::parent_hold_ms)) {
        return false;
    }
    const uint64_t keep = 100U - gen::defaults::routing::improvement_percent;
    return static_cast<uint64_t>(best_score) * 100U <= static_cast<uint64_t>(current_score) * keep;
}

} // namespace lm::route
