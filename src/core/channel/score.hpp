// Candidate scoring and the migration decision (docs/05 §3, §9). Pure functions on integer samples.
//   loss_q16     = failed probes / probes * 65536 (RF attempts only: a probe the radio did not accept is no sample)
//   service_q16  = min(median service / home baseline, 4) / 4 * 65536
//   queue_q16    = min(queue median, 500 ms) / 500 * 65536   (a probe leaves an idle queue: 0 here, S17-D6)
//   score        = (5 * loss + 3 * service + 2 * queue) / 10
// A candidate is chosen only when EVERY measured pair is comparable, the worst pair is not worse than at
// home, and the summed cost improves by >= 25 % (defaults.json). Failures of a candidate are never dropped
// from its sample, and a pair without enough probes makes the candidate not comparable (never "good").
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

namespace lm::channel {

inline constexpr uint32_t k_q16 = 65536;
inline constexpr unsigned k_min_probes = 4; // below this a sample says nothing
inline constexpr std::size_t k_max_pairs = 4;
inline constexpr std::size_t k_max_cands = 3;

struct Sample {
    uint8_t ok = 0, fail = 0;
    uint16_t svc_ms = 0; // median TX-done latency of the acknowledged probes
};
using Row = std::array<Sample, 1 + k_max_cands>; // [0] = home baseline, [1..] = candidates

[[nodiscard]] constexpr bool usable(const Sample &s) { return static_cast<unsigned>(s.ok) + s.fail >= k_min_probes; }

[[nodiscard]] constexpr uint32_t score_q16(const Sample &s, uint16_t base_svc_ms) {
    const uint32_t n = static_cast<uint32_t>(s.ok) + s.fail;
    const uint32_t loss = n == 0 ? k_q16 : static_cast<uint32_t>((uint64_t{s.fail} << 16U) / n);
    // No acknowledged probe at all: the worst service class. base 0 cannot happen for usable pairs.
    const uint64_t ratio = (s.ok == 0 || base_svc_ms == 0) ? uint64_t{4} * k_q16 : (uint64_t{s.svc_ms} << 16U) / base_svc_ms;
    const uint32_t svc = static_cast<uint32_t>(std::min<uint64_t>(ratio, uint64_t{4} * k_q16) / 4U);
    return (5U * loss + 3U * svc + 2U * 0U) / 10U;
}

enum class Verdict : uint8_t { Move, NoData, Worse, Small };
struct Choice {
    Verdict verdict = Verdict::NoData;
    uint8_t index = 0; // 1.. = column of the chosen candidate
};

[[nodiscard]] constexpr Choice decide(const Row *rows, std::size_t pairs, std::size_t cands, unsigned min_improve_percent) {
    Choice best;
    bool any_comparable = false, any_worst_ok = false;
    uint64_t best_sum = 0;
    for (std::size_t c = 1; c <= cands; ++c) {
        bool ok = pairs > 0;
        uint32_t worst_home = 0, worst_cand = 0;
        uint64_t sum_home = 0, sum_cand = 0;
        for (std::size_t p = 0; p < pairs && ok; ++p) {
            ok = usable(rows[p][0]) && usable(rows[p][c]) && rows[p][0].ok != 0;
            if (ok) {
                const uint32_t h = score_q16(rows[p][0], rows[p][0].svc_ms);
                const uint32_t k = score_q16(rows[p][c], rows[p][0].svc_ms);
                worst_home = std::max(worst_home, h);
                worst_cand = std::max(worst_cand, k);
                sum_home += h;
                sum_cand += k;
            }
        }
        if (!ok) {
            continue;
        }
        any_comparable = true;
        if (worst_cand > worst_home) {
            continue;
        }
        any_worst_ok = true;
        if (sum_cand * 100U > sum_home * (100U - min_improve_percent)) {
            continue;
        }
        if (best.verdict != Verdict::Move || sum_cand < best_sum) {
            best = Choice{Verdict::Move, static_cast<uint8_t>(c)};
            best_sum = sum_cand;
        }
    }
    if (best.verdict != Verdict::Move) {
        best.verdict = !any_comparable ? Verdict::NoData : (!any_worst_ok ? Verdict::Worse : Verdict::Small);
    }
    return best;
}

} // namespace lm::channel
