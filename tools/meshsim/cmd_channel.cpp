// meshsim commands of the channel slice (S17): the state of the channel module and of the root's coordinator, plans,
// rollback, the operator switches, and the interference model of the simulated medium. Bench only.
//   channel status <node>                  module state; on node 0 also the coordinator (state, why, sets by address)
//   channel plan <ch> | rollback           an operator plan to <ch> / back to the previous channel (higher epoch)
//   channel request <0|1|2> <rev>          lm_channel_request on node 0: auto, freeze, recalculate
//   channel mark <addr> sleepy|critical <on|off>, channel gap <on|off>, channel defer <on|off>
//   channel timing <prepare_ms> <lead_ms>, channel max-error <ms>      bench knobs of the coordinator
//   channel noise <node|-1> <ch|0> <permille>, channel noise-clear     extra loss at a node on a channel
#include <cstdio>
#include <string>

#include "control.hpp"
#include "port/sim/sim_node.hpp"

namespace meshsim {
namespace {

const char *state_name(lm::root::CState s) {
    static const char *const k[] = {"MONITOR", "SURVEY", "PREPARING", "COMMITTED", "SWITCHING", "SETTLING", "ABORTED", "RECOVERING"};
    return k[static_cast<unsigned>(s)];
}

std::string addrs(uint64_t mask) {
    std::string out = "[";
    for (unsigned slot = 0; slot < 64; ++slot) {
        if (((mask >> slot) & 1U) != 0) {
            out += (out.size() > 1 ? "," : "") + std::to_string(2 + slot);
        }
    }
    return out + "]";
}

std::string hex(const std::array<uint8_t, 16> &b) {
    char buf[33];
    for (unsigned i = 0; i < 16; ++i) {
        std::snprintf(buf + 2 * i, 3, "%02x", b[i]);
    }
    return buf;
}

std::string field(const char *name, uint64_t v) { return std::string(",\"") + name + "\":" + std::to_string(v); }
std::string field(const char *name, const std::string &v) { return std::string(",\"") + name + "\":" + v; }

std::string status(Sim &sim, const Args &a) {
    uint16_t i = 0;
    if (a.size() != 3 || !parse_node(sim, a[2], i)) {
        return error("usage: channel status <node>");
    }
    lm::sim::SimNode &n = sim.world.node(i);
    if (n.ctx() == nullptr) {
        return error("node is not powered");
    }
    lm::Engine &e = n.ctx()->engine;
    lm::channel::Channel &c = e.chan();
    static const char *const k_mode[] = {"normal", "prepared", "committed", "searching"};
    const uint64_t w = c.clock_width_ms(n.clock.now());
    const lm::channel::Stats &s = c.stats();
    std::string out = "{\"ok\":true,\"mode\":\"" + std::string(k_mode[static_cast<unsigned>(c.mode())]) + "\"";
    out += field("loaded", c.loaded() ? "true" : "false") + field("radio", e.channel()) + field("current", c.current());
    out += field("epoch", c.epoch().value()) + field("clock_width_ms", w == UINT64_MAX ? "null" : std::to_string(w));
    out += field("time_updates", s.time_updates) + field("prepared", s.prepared) + field("committed", s.committed);
    out += field("switched", s.switched) + field("refused", s.refused) + field("scans", s.scans);
    out += field("scan_dwells", s.scan_dwells) + field("degraded_sent", s.degraded_sent) + field("surveys", s.surveys);
    if (i == 0) {
        const lm::root::Coordinator::View v = e.coordinator().view();
        const lm::root::Coordinator::Stats &cs = e.coordinator().stats();
        out += ",\"coordinator\":{\"state\":\"" + std::string(state_name(v.state)) + "\"";
        out += field("why", static_cast<unsigned>(v.why)) + field("frozen", v.frozen ? "true" : "false");
        out += field("policy_revision", v.policy_revision) + field("plan_id", "\"" + hex(v.plan_id) + "\"");
        out += field("plans", cs.plans) + field("commits", cs.commits) + field("aborts", cs.aborts);
        out += field("surveys", cs.surveys) + field("visits", cs.visits) + field("degraded", cs.degraded);
        out += field("epoch", v.epoch) + field("current", v.current) + field("required", addrs(v.required));
        out += field("ready", addrs(v.ready)) + field("stored", addrs(v.stored)) + field("applied", addrs(v.applied));
        out += field("unreachable", addrs(v.unreachable)) + field("deferred", addrs(v.deferred)) + "}";
    }
    return out + "}";
}

} // namespace

std::string cmd_channel(Sim &sim, const Args &a) {
    if (a.size() < 2) {
        return error("usage: channel status|plan|rollback|request|mark|gap|defer|timing|max-error|noise|noise-clear ...");
    }
    if (a[1] == "status") {
        return status(sim, a);
    }
    lm::sim::SimNode &root = sim.world.node(0);
    if (a[1] == "noise" && a.size() == 5) {
        uint64_t ch = 0, permille = 0;
        const bool all = a[2] == "-1";
        uint16_t node = 0;
        if ((!all && !parse_node(sim, a[2], node)) || !parse_u64(a[3], ch) || !parse_u64(a[4], permille) || ch > 13 || permille > 1000) {
            return error("usage: channel noise <node|-1> <channel|0> <permille>");
        }
        sim.world.set_noise(all ? -1 : node, static_cast<uint8_t>(ch), static_cast<uint16_t>(permille));
        return "{\"ok\":true}";
    }
    if (a[1] == "noise-clear") {
        sim.world.clear_noise();
        return "{\"ok\":true}";
    }
    if (root.ctx() == nullptr) {
        return error("the root is not powered");
    }
    lm::root::CoordinatorType &co = root.ctx()->engine.coordinator();
    const lm::MonoTime now = root.clock.now();
    uint64_t x = 0, y = 0;
    lm::Status st = lm::Status::Ok;
    if (a[1] == "plan" && a.size() == 3 && parse_u64(a[2], x)) {
        st = co.plan_to(static_cast<uint8_t>(x), now);
    } else if (a[1] == "rollback" && a.size() == 2) {
        st = co.rollback(now);
    } else if (a[1] == "request" && a.size() == 4 && parse_u64(a[2], x) && parse_u64(a[3], y)) {
        lm_operation_id_t op = 0;
        st = static_cast<lm::Status>(lm_channel_request(root.ctx(), static_cast<uint32_t>(x), y, &op));
    } else if (a[1] == "mark" && a.size() == 5 && parse_u64(a[2], x)) {
        const bool on = a[4] == "on";
        if (a[3] == "sleepy") {
            co.set_sleepy(lm::ShortAddr{static_cast<uint16_t>(x)}, on);
        } else if (a[3] == "critical") {
            co.set_critical(lm::ShortAddr{static_cast<uint16_t>(x)}, on);
        } else {
            return error("usage: channel mark <addr> sleepy|critical <on|off>");
        }
    } else if (a[1] == "gap" && a.size() == 3) {
        co.set_maintenance_gap(a[2] == "on");
    } else if (a[1] == "defer" && a.size() == 3) {
        co.allow_deferred(a[2] == "on");
    } else if (a[1] == "timing" && a.size() == 4 && parse_u64(a[2], x) && parse_u64(a[3], y)) {
        co.set_timing(static_cast<uint32_t>(x), static_cast<uint32_t>(y));
    } else if (a[1] == "max-error" && a.size() == 3 && parse_u64(a[2], x)) {
        co.set_max_clock_error(static_cast<uint32_t>(x));
    } else {
        return error("bad channel command");
    }
    root.notify();
    return std::string("{\"ok\":true,\"status\":\"") + lm::status_name(st) + "\"}";
}

} // namespace meshsim
