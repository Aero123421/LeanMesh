// Power policy and the pure decisions of docs/20 (no state, no I/O). These are the functions the
// executable spec scripts/power_contract.py describes; the engine (power.cpp) calls them with its
// own state, and the tests replay tests/power_golden.json through the engine, not only through these.
#pragma once

#include <cstdint>

#include "core/ids.hpp"
#include "core/profile.hpp"
#include "core/status.hpp"
#include "leanmesh.h"

namespace lm::power {

inline constexpr uint8_t k_always_rx = LM_POWER_ALWAYS_RX;
inline constexpr uint8_t k_windowed_rx = LM_POWER_WINDOWED_RX;
inline constexpr uint8_t k_report_only = LM_POWER_REPORT_ONLY;

// config/power.schema.json. Field order = the generated initialisers (gen/power_policy.hpp).
struct Policy {
    uint64_t revision = 1;
    uint8_t mode = k_always_rx;
    uint8_t pending = LM_PENDING_REQUIRE_SETTLED;
    uint32_t wake_interval_ms = 0;
    uint32_t rx_window_ms = 0;
    uint32_t max_rx_window_ms = 0;
    uint32_t awake_budget_ms = 15000;
    uint32_t shutdown_reserve_ms = 500;
    uint32_t search_budget_ms = 1000;
    uint32_t guard_ms = 20;
    uint32_t retry_min_ms = 60000;
    uint32_t retry_max_ms = 3600000;
    uint32_t offline_radio_ms_per_hour = 60000;
    uint32_t extra_wakes_per_day = 32;
    uint32_t extra_radio_ms_per_day = 120000;
    uint32_t shutdown_overrun_ms = 2000;
    uint32_t mailbox_child = 2;
    uint32_t mailbox_total = 16;
};
using PolicyInit = Policy;

// JSON schema ranges plus the cross-field rules of chapter 20 (Python: validate_policy). RoleNotAllowed:
// a relay or root may only be ALWAYS_RX. InvalidArgument: any other violation.
[[nodiscard]] Status validate(const Policy &p, Role role);

// docs/20 §2: no job may start unless it and the shutdown reserve still fit into the episode.
[[nodiscard]] constexpr bool can_start_work(const Policy &p, uint64_t elapsed_ms, uint64_t estimated_ms) {
    return elapsed_ms + estimated_ms + p.shutdown_reserve_ms <= p.awake_budget_ms;
}

// docs/20 §4: guard for a window predicted after `elapsed_ms`; both clocks' drift counts.
[[nodiscard]] constexpr uint64_t required_guard_ms(uint64_t elapsed_ms, uint32_t local_ppm, uint32_t peer_ppm,
                                                   uint32_t timestamp_error_ms, uint32_t wakeup_error_ms) {
    const uint64_t ppm = uint64_t{local_ppm} + peer_ppm;
    return (elapsed_ms * ppm + 999999U) / 1000000U + timestamp_error_ms + wakeup_error_ms;
}

// docs/20 §7. Only a wake that kept the RAM may reuse a session; everything else is a fresh EDHOC.
// RTC secure resume does not exist (implemented=false): there is no third answer.
enum class Wake : uint8_t { Cold, LightWake, ModemWindow, DeepWake };
enum class SessionPath : uint8_t { RamReuse, FreshEdhoc };
struct ResumeFacts {
    Wake cause = Wake::Cold;
    bool complete_ram_state = false;
    bool peer_session_valid = false;
    bool elapsed_known = false;       // elapsed_upper_ms is a proven upper bound
    uint64_t elapsed_upper_ms = 0;
    int64_t authorization_remaining_ms = 0; // at sleep entry; negative or unknown = 0
    int64_t key_remaining_ms = 0;
};
[[nodiscard]] constexpr SessionPath session_path(const ResumeFacts &f) {
    if (f.cause != Wake::LightWake && f.cause != Wake::ModemWindow) {
        return SessionPath::FreshEdhoc;
    }
    if (!f.complete_ram_state || !f.peer_session_valid || !f.elapsed_known) {
        return SessionPath::FreshEdhoc;
    }
    const int64_t life = f.authorization_remaining_ms < f.key_remaining_ms ? f.authorization_remaining_ms
                                                                            : f.key_remaining_ms;
    return life > 0 && f.elapsed_upper_ms < static_cast<uint64_t>(life) ? SessionPath::RamReuse
                                                                        : SessionPath::FreshEdhoc;
}

// docs/22 §5 for one target. `next_wake_earliest_ms`: the target's next wake as an interval start on the
// origin's clock (unknown = !known). Times are on one clock (root ms).
enum class Target : uint8_t { Rejected, Expired, Indeterminate, DeadlineUnreachable, Ready, WaitWake };
struct TargetFacts {
    uint64_t now_ms = 0;
    bool has_deadline = false;
    uint64_t deadline_ms = 0;
    bool wake_known = false;
    uint64_t next_wake_earliest_ms = 0;
    bool awake = false;
    bool previously_sent = false;
    bool generation_matches = true;
};
[[nodiscard]] constexpr Target target_wait(const TargetFacts &t) {
    if (!t.generation_matches) {
        return Target::Rejected;
    }
    if (t.has_deadline && t.now_ms >= t.deadline_ms) {
        return t.previously_sent ? Target::Indeterminate : Target::Expired;
    }
    if (t.awake) {
        return Target::Ready;
    }
    if (t.has_deadline && t.wake_known && t.next_wake_earliest_ms >= t.deadline_ms) {
        return t.previously_sent ? Target::Indeterminate : Target::DeadlineUnreachable;
    }
    return Target::WaitWake;
}

} // namespace lm::power
