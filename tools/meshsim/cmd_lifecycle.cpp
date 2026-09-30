// meshsim commands of the lifecycle slice (S18): signed lifecycle objects of the TEST-ONLY fleet issuer, handed to
// the caller (a Host E2E test submits them through POST /v1/control like an operator's signing service would).
// Nothing is installed here. Bench only.
#include <cinttypes>
#include <cstdio>
#include <string>

#include "control.hpp"
#include "core/member/credentials.hpp"
#include "fleet.hpp"
#include "port/sim/sim_node.hpp"

namespace meshsim {
namespace {

std::string hex(const lm::fleet::Bytes &v) {
    static const char *const k = "0123456789abcdef";
    std::string s;
    for (uint8_t b : v) {
        s += k[b >> 4U];
        s += k[b & 15U];
    }
    return s;
}

// <node> of a booted node, or 64 hex digits of any DeviceId (a device the simulation does not run).
bool parse_device(Sim &sim, const std::string &s, lm::DeviceId &out) {
    uint16_t i = 0;
    if (s.size() == 64) {
        for (std::size_t k = 0; k < 32; ++k) {
            unsigned v = 0;
            if (std::sscanf(s.c_str() + 2 * k, "%2x", &v) != 1) {
                return false;
            }
            out.bytes[k] = static_cast<uint8_t>(v);
        }
        return true;
    }
    if (!parse_node(sim, s, i) || sim.world.node(i).ctx() == nullptr) {
        return false;
    }
    out = sim.world.node(i).ctx()->engine.identity().self();
    return true;
}

std::string object_json(uint32_t type, const lm::fleet::Bytes &cose) {
    return "{\"ok\":true,\"type\":" + std::to_string(type) + ",\"cose\":\"" + hex(cose) + "\"}";
}

} // namespace

// lc-object revoke <node|device hex> <assignment floor> <membership floor> [fleet|root]
// lc-object window <expected revision> <span ms> <max new members> [allowed roles]   (the root's term, from its now;
//                                                                                     policy revision = expected revision)
std::string cmd_lc_object(Sim &sim, const Args &a) {
    lm::fleet::Network &net = fleet_network(sim);
    if (a.size() >= 5 && a.size() <= 6 && a[1] == "revoke") {
        lm::DeviceId device;
        uint64_t af = 0;
        uint64_t mf = 0;
        if (!parse_device(sim, a[2], device) || !parse_u64(a[3], af) || !parse_u64(a[4], mf) ||
            (a.size() == 6 && a[5] != "fleet" && a[5] != "root")) {
            return error("usage: lc-object revoke <node|device hex> <assignment floor> <membership floor> [fleet|root]");
        }
        const bool by_root = a.size() == 6 && a[5] == "root";
        return object_json(lm::member::k_type_revoke, by_root ? lm::fleet::issue_root_revoke(net.root, net.domain, device, af, mf)
                                                              : net.fleet.revoke(device, af, mf));
    }
    if (a.size() >= 5 && a.size() <= 6 && a[1] == "window" && sim.world.node(0).ctx() != nullptr) {
        uint64_t revision = 0;
        uint64_t span = 0;
        uint64_t max = 0;
        uint64_t roles = 3;
        if (!parse_u64(a[2], revision) || !parse_u64(a[3], span) || !parse_u64(a[4], max) || max == 0 || max > 64 ||
            (a.size() == 6 && !parse_u64(a[5], roles))) {
            return error("usage: lc-object window <expected revision> <span ms> <max 1..64> [allowed roles]");
        }
        lm::member::CommissioningWindow w;
        w.id[0] = static_cast<uint8_t>(revision);
        w.id[1] = static_cast<uint8_t>(max);
        w.id[2] = static_cast<uint8_t>(span >> 8U);
        w.term = sim.world.node(0).ctx()->engine.identity().term(); // a window is root time of one term (ARCH2-D1)
        w.expected_revision = revision;
        w.not_before_ms = sim.world.node(0).clock.now().to_ms(); // the root is the time base of its term
        w.expires_ms = w.not_before_ms + span;
        w.max_new_members = static_cast<uint8_t>(max);
        w.allowed_roles = static_cast<uint8_t>(roles);
        w.policy_revision = revision;
        return object_json(lm::member::k_type_commissioning_window, net.fleet.window(net.domain, w));
    }
    return error("usage: lc-object revoke ... | lc-object window ... (see cmd_lifecycle.cpp)");
}

// job-latency <node> <us>: every job of the node's worker takes this long (virtual execution time) from now on; the
// default is 2000. A slow worker keeps a root's one signed-object install running long enough for a Host request to
// meet it (a BUSY refusal on purpose, FIX5 E2E).
std::string cmd_job_latency(Sim &sim, const Args &a) {
    uint16_t i = 0;
    uint64_t us = 0;
    if (a.size() != 3 || !parse_node(sim, a[1], i) || !parse_u64(a[2], us) || us == 0 || us > 60'000'000) {
        return error("usage: job-latency <node> <1..60000000 us>");
    }
    sim.world.node(i).jobs.latency_us = static_cast<uint32_t>(us);
    return "{\"ok\":true}";
}

} // namespace meshsim
