// Power-cut matrix driver (S20, docs/12 §4, docs/18 §2): ONE harness for every store-cut sweep of the native tests.
// A scenario supplies a function that builds its own network, arms a cut at mutating store call `k` of a target node in
// a given mode, runs the operation, restarts the node, asserts that only allowed states exist, lets the network settle
// and reports whether it converged. The driver walks k = 0.. until a run has fewer store calls than k (the sweep of
// that node/mode is complete), fails loudly with scenario/node/mode/k (the minimal counterexample of a sweep is its
// smallest failing k) and prints one `[matrix]` row per (scenario, node, mode) for the release records.
// Sim store only: this is a model of Flash commits, never a measurement of a real power loss (docs/18 §4).
#pragma once

#include <cstdio>
#include <string>
#include <utility>
#include <vector>

#include "lmtest.hpp"
#include "port/sim/sim_store.hpp"

namespace lmtest {

struct CutRun {
    bool fired = false;     // the armed cut hit a store call (false: the run had fewer calls than k)
    bool ok = false;        // only allowed states, and the network settled
    bool converged = false; // it ended in the operation's target state (some cuts legitimately roll back)
    std::string why;        // what was wrong when !ok
};

struct CutTarget {
    unsigned node;
    const char *label;
};

struct CutTotals {
    unsigned points = 0;
    unsigned converged = 0;
    unsigned truncated = 0; // sweeps that stopped at max_k with the cut still firing (FIX11-D10): not a complete sweep
};

inline const char *cut_mode_name(lm::sim::CutMode m) {
    return m == lm::sim::CutMode::Before ? "before" : (m == lm::sim::CutMode::Torn ? "torn" : "after");
}

// run(node, k, mode) -> CutRun. `modes` defaults to before / torn / after.
template <class Fn>
CutTotals cut_matrix(const char *scenario, const std::vector<CutTarget> &targets, Fn run, uint64_t first_k = 0,
                     uint64_t max_k = 40,
                     const std::vector<lm::sim::CutMode> &modes = {lm::sim::CutMode::Before, lm::sim::CutMode::Torn,
                                                                    lm::sim::CutMode::After}) {
    CutTotals total;
    for (const CutTarget &t : targets) {
        for (const lm::sim::CutMode mode : modes) {
            unsigned points = 0;
            unsigned conv = 0;
            bool complete = false;
            for (uint64_t k = first_k; k < max_k; ++k) {
                const CutRun r = run(t.node, k, mode);
                if (!r.ok) {
                    std::fprintf(stderr, "  MATRIX FAIL scenario=%s node=%s mode=%s k=%llu: %s\n", scenario, t.label,
                                 cut_mode_name(mode), static_cast<unsigned long long>(k), r.why.c_str());
                }
                LM_CHECK(r.ok);
                if (!r.fired) {
                    complete = true; // fewer store calls than k in this scenario: the sweep of this node/mode is complete
                    break;
                }
                ++points;
                conv += r.converged ? 1 : 0;
            }
            std::printf("  [matrix] %-28s node %-10s %-6s: %2u cut points, %2u converged on the target state%s\n", scenario,
                        t.label, cut_mode_name(mode), points, conv,
                        complete ? "" : "  ** TRUNCATED: the store calls did not end before k reached the limit, the sweep is NOT complete **");
            total.truncated += complete ? 0 : 1;
            total.points += points;
            total.converged += conv;
        }
    }
    std::printf("  [matrix] %-28s total: %u cut points, %u converged, %u truncated sweeps\n", scenario, total.points,
                total.converged, total.truncated);
    return total;
}

} // namespace lmtest
