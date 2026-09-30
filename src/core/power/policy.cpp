#include "core/power/policy.hpp"

namespace lm::power {
namespace {
constexpr bool in(uint32_t v, uint32_t lo, uint32_t hi) { return v >= lo && v <= hi; }
} // namespace

Status validate(const Policy &p, Role role) {
    if (p.revision > k_u63_max || p.mode > k_report_only || p.pending > LM_PENDING_SAVE_AND_SLEEP) {
        return Status::InvalidArgument;
    }
    if (role != Role::Leaf && p.mode != k_always_rx) {
        return Status::RoleNotAllowed; // relays and the root keep the radio on (docs/20 §1)
    }
    // config/power.schema.json ranges
    if (p.wake_interval_ms > 86400000U || p.rx_window_ms > 60000U || p.max_rx_window_ms > 65535U ||
        !in(p.awake_budget_ms, 100, 300000) || !in(p.shutdown_reserve_ms, 50, 10000) ||
        p.search_budget_ms > 300000U || !in(p.guard_ms, 1, 1000) || !in(p.retry_min_ms, 1000, 3600000) ||
        !in(p.retry_max_ms, 1000, 86400000) || !in(p.offline_radio_ms_per_hour, 1000, 3600000) ||
        p.extra_wakes_per_day > 1024U || p.extra_radio_ms_per_day > 3600000U ||
        !in(p.shutdown_overrun_ms, 100, 10000) || p.mailbox_child > 4U || p.mailbox_total > 64U) {
        return Status::InvalidArgument;
    }
    // cross-field rules (scripts/power_contract.py validate_policy)
    if (p.shutdown_reserve_ms >= p.awake_budget_ms ||
        p.search_budget_ms > p.awake_budget_ms - p.shutdown_reserve_ms || p.retry_min_ms > p.retry_max_ms ||
        p.mailbox_child > p.mailbox_total) {
        return Status::InvalidArgument;
    }
    if (p.mode == k_always_rx) {
        return (p.wake_interval_ms | p.rx_window_ms | p.max_rx_window_ms) != 0 ? Status::InvalidArgument : Status::Ok;
    }
    if (!(2 * p.guard_ms < p.rx_window_ms && p.rx_window_ms <= p.max_rx_window_ms) ||
        p.max_rx_window_ms > p.awake_budget_ms - p.shutdown_reserve_ms ||
        (p.mode == k_windowed_rx && p.wake_interval_ms <= p.max_rx_window_ms + 2 * p.guard_ms)) {
        return Status::InvalidArgument;
    }
    return Status::Ok;
}

} // namespace lm::power
