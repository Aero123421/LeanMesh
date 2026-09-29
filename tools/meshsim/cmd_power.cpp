// meshsim commands of the power slice (S16). Bench only: sleep here is a protocol state; nothing is measured.
//   power <node>                          snapshot of lm_power_get plus the module's counters
//   power-set <node> <always|windowed|report>   the reference policy (config/power.*.json) via lm_power_policy_set
//   sleep <node> <light|deep> <ms> [ext]  prepare -> ticket -> enter (SAVE_AND_SLEEP); `ext` = GPIO wake only
//   wake <node>                           an external wake source fires
#include <cinttypes>
#include <cstdio>
#include <string>

#include "control.hpp"
#include "gen/power_policy.hpp"
#include "port/sim/sim_node.hpp"

namespace meshsim {
namespace {

lm_context_t *ctx_of(Sim &sim, const Args &a, uint16_t &i) {
    if (a.size() < 2 || !parse_node(sim, a[1], i) || sim.world.node(i).ctx() == nullptr) {
        return nullptr;
    }
    return sim.world.node(i).ctx();
}

} // namespace

std::string cmd_power(Sim &sim, const Args &a) {
    uint16_t i = 0;
    lm_context_t *c = ctx_of(sim, a, i);
    if (c == nullptr || a.size() != 2) {
        return error("usage: power <node> (node must be powered)");
    }
    lm_power_snapshot_t s{};
    s.struct_size = sizeof(s);
    s.abi_version = LM_ABI_VERSION;
    if (lm_power_get(c, &s) != LM_STATUS_OK) {
        return error("lm_power_get failed");
    }
    const lm::power::Stats &st = c->engine.power().stats();
    char buf[640];
    std::snprintf(buf, sizeof buf,
                  "{\"ok\":true,\"mode\":%u,\"state\":%u,\"policy_revision\":%" PRIu64 ",\"radio_on_us\":%" PRIu64
                  ",\"episodes\":%" PRIu64 ",\"polls\":%" PRIu64 ",\"grants\":%" PRIu64 ",\"missed_windows\":%" PRIu64
                  ",\"wake_denied\":%" PRIu64 ",\"offline_budget_remaining_ms\":%u,\"remaining_awake_ms\":%u,"
                  "\"asleep\":%s,\"polls_served\":%" PRIu64 ",\"parked_expired\":%" PRIu64 "}",
                  s.mode, s.state, s.policy_revision, s.radio_on_us, s.episode_count, s.polls, st.grants,
                  s.missed_windows, st.wake_denied, s.offline_budget_remaining_ms, s.remaining_awake_ms,
                  c->engine.radio_state() == lm::RadioState::Asleep ? "true" : "false", st.polls_served, st.parked_expired);
    return buf;
}

std::string cmd_power_set(Sim &sim, const Args &a) {
    uint16_t i = 0;
    lm_context_t *c = ctx_of(sim, a, i);
    if (c == nullptr || a.size() != 3 || (a[2] != "always" && a[2] != "windowed" && a[2] != "report")) {
        return error("usage: power-set <node> <always|windowed|report>");
    }
    const lm::power::Policy &ref = a[2] == "always" ? lm::gen::power_policy::k_always_rx
                                   : (a[2] == "windowed" ? lm::gen::power_policy::k_windowed_rx : lm::gen::power_policy::k_report_only);
    lm_power_policy_t cur{};
    cur.struct_size = sizeof(cur);
    cur.abi_version = LM_ABI_VERSION;
    if (lm_power_policy_get(c, &cur) != LM_STATUS_OK) {
        return error("lm_power_policy_get failed");
    }
    lm_power_policy_t p{};
    p.struct_size = sizeof(p);
    p.abi_version = LM_ABI_VERSION;
    p.revision = cur.revision + 1;
    p.mode = ref.mode;
    p.pending_policy = ref.pending;
    p.wake_interval_ms = ref.wake_interval_ms;
    p.rx_window_ms = ref.rx_window_ms;
    p.max_rx_window_ms = ref.max_rx_window_ms;
    p.awake_budget_ms = ref.awake_budget_ms;
    p.shutdown_reserve_ms = ref.shutdown_reserve_ms;
    p.search_budget_ms = ref.search_budget_ms;
    p.guard_ms = ref.guard_ms;
    p.retry_min_ms = ref.retry_min_ms;
    p.retry_max_ms = ref.retry_max_ms;
    p.offline_radio_ms_per_hour = ref.offline_radio_ms_per_hour;
    p.extra_event_wakes_per_day = ref.extra_wakes_per_day;
    p.extra_event_radio_ms_per_day = ref.extra_radio_ms_per_day;
    p.shutdown_overrun_limit_ms = ref.shutdown_overrun_ms;
    p.mailbox_frames_per_child = ref.mailbox_child;
    p.mailbox_frames_total = ref.mailbox_total;
    lm_operation_id_t op = 0;
    const lm_status_t st = lm_power_policy_set(c, &p, cur.revision, &op);
    sim.world.node(i).notify();
    return "{\"ok\":true,\"status\":\"" + std::string(lm::status_name(static_cast<lm::Status>(st))) + "\",\"operation\":" +
           std::to_string(op) + "}";
}

std::string cmd_sleep(Sim &sim, const Args &a) {
    uint16_t i = 0;
    uint64_t ms = 0;
    lm_context_t *c = ctx_of(sim, a, i);
    if (c == nullptr || (a.size() != 4 && a.size() != 5) || (a[2] != "light" && a[2] != "deep") || !parse_u64(a[3], ms) ||
        (a.size() == 5 && a[4] != "ext")) {
        return error("usage: sleep <node> <light|deep> <ms> [ext]");
    }
    lm_sleep_request_t r{};
    r.struct_size = sizeof(r);
    r.abi_version = LM_ABI_VERSION;
    r.sleep_kind = a[2] == "deep" ? LM_SLEEP_DEEP : LM_SLEEP_LIGHT;
    r.wake_source_mask = a.size() == 5 ? LM_WAKE_EXTERNAL : LM_WAKE_TIMER;
    r.awake_budget_ms = 3000;
    r.pending_policy = LM_PENDING_SAVE_AND_SLEEP;
    r.requested_sleep_ms = a.size() == 5 ? 0 : ms;
    lm_operation_id_t op = 0;
    lm_status_t st = lm_sleep_prepare_ex(c, &r, &op);
    if (st != LM_STATUS_OK) {
        return "{\"ok\":true,\"status\":\"" + std::string(lm::status_name(static_cast<lm::Status>(st))) + "\",\"stage\":\"prepare\"}";
    }
    lm_sleep_ticket_t t{};
    for (unsigned k = 0; k < 1000; ++k) { // the prepare finishes in virtual milliseconds
        sim.world.run_until(sim.world.now_us() + 5000);
        st = lm_sleep_ticket_get(c, op, &t);
        if (st != LM_STATUS_BUSY) {
            break;
        }
    }
    if (st == LM_STATUS_OK) {
        st = lm_sleep_enter(c, &t);
        sim.world.node(i).notify();
    }
    return "{\"ok\":true,\"status\":\"" + std::string(lm::status_name(static_cast<lm::Status>(st))) + "\"}";
}

std::string cmd_wake(Sim &sim, const Args &a) {
    uint16_t i = 0;
    if (a.size() != 2 || !parse_node(sim, a[1], i)) {
        return error("usage: wake <node>");
    }
    sim.world.node(i).wake_external();
    return "{\"ok\":true}";
}

} // namespace meshsim
