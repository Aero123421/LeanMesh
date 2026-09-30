// Integer parent score and link quality (docs/04 §6 "整数scoreの固定式"). Initial policy; a change
// after measurement needs a revision and a comparison result. Only RF-attributable attempts feed
// the estimator: BUSY, planned sleep and local shortage are never samples (call sites decide).
#pragma once

#include <array>
#include <cstdint>

#include "core/ids.hpp"
#include "core/time.hpp"
#include "gen/defaults.hpp"

namespace lm::route {

inline constexpr int32_t k_q16_one = 65536;
inline constexpr uint32_t k_etx_min_q8 = 256;
inline constexpr uint32_t k_etx_max_q8 = 4096;
inline constexpr uint32_t k_queue_ms_max = 500;
inline constexpr uint32_t k_penalty_step = 128;
inline constexpr uint32_t k_penalty_max = 512;
inline constexpr int64_t k_instability_window_us = 30'000'000;

// Per neighbour, 8 bytes. `samples` distinguishes "never probed" from a measured link.
struct LinkQuality {
    int32_t success_q16 = k_q16_one;
    uint16_t queue_ms = 0;
    uint16_t samples = 0; // saturating count of RF attempts; 0 = unknown candidate

    // p += (sample - p) / 8 with signed intermediate (sample = 65536 on success, 0 on failure).
    void record_attempt(bool success);
    // Same alpha, clipped to 0..500 ms.
    void record_queue_ms(uint32_t sample_ms);
    [[nodiscard]] bool known() const { return samples != 0; }
    [[nodiscard]] uint32_t etx_q8() const;
};

// Parent changes involving this neighbour within the last 30 s: +128 each, max 512, one step of
// decay per elapsed 30 s (docs/04 §6).
struct Instability {
    uint8_t level = 0;
    MonoTime stamp{};

    void note_change(MonoTime now);
    [[nodiscard]] uint32_t penalty(MonoTime now) const;
};

// score = 256*depth + ETX_Q8 - 256 + queue_ms + penalty. `depth` is the depth this node would
// have below the candidate (candidate root_depth + 1); it is the same term for every candidate
// of one comparison and only matters against the current parent.
[[nodiscard]] uint32_t parent_score(uint32_t depth, const LinkQuality &q, uint32_t penalty);

struct Candidate {
    DeviceId id{};
    uint8_t depth = 0; // resulting own depth
    LinkQuality quality{};
    uint32_t penalty = 0;
};

// Lowest score among candidates whose link was measured (unknown ones need a PROBE first and are
// never chosen); ties resolved by the lexicographically smaller full DeviceId. Returns the index
// or -1. Bounded linear scan over at most 16 neighbours.
[[nodiscard]] int pick_best(const Candidate *c, std::size_t n);

// Improvement rule: dead link switches at once; otherwise the current parent must have been held
// for parent_hold_ms and the best score must be at least improvement_percent lower.
[[nodiscard]] bool should_switch(uint32_t current_score, uint32_t best_score, Duration held,
                                 bool current_dead);

} // namespace lm::route
