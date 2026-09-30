// meshsim command of the diagnostics slice (S19).
//   diag <node> [heap <bytes>]   lm_diagnostics_get + lm_get_capabilities of a powered node, with the validity bits and
//                                the engine's step count (a query must not change it). `heap` sets a bench value on
//                                the node's SimHealth so a test can see a platform fact appear (sim has no heap).
#include <array>
#include <cinttypes>
#include <cstdio>
#include <string>

#include "control.hpp"
#include "core/diag/diag.hpp"
#include "port/sim/sim_node.hpp"

namespace meshsim {

std::string cmd_diag(Sim &sim, const Args &a) {
    uint16_t i = 0;
    if (a.size() < 2 || !parse_node(sim, a[1], i) || sim.world.node(i).ctx() == nullptr) {
        return error("usage: diag <node> [heap <bytes>] (node must be powered)");
    }
    lm::sim::SimNode &n = sim.world.node(i);
    if (a.size() == 4 && a[2] == "heap") {
        uint64_t v = 0;
        if (!parse_u64(a[3], v)) {
            return error("heap <bytes>");
        }
        n.health.extra.heap_valid = true;
        n.health.extra.min_heap_bytes = static_cast<uint32_t>(v);
    }
    lm_context_t *c = n.ctx();
    const uint64_t steps = c->engine.stats().steps;
    lm_diagnostics_t d{};
    d.struct_size = sizeof(d);
    d.abi_version = LM_ABI_VERSION;
    lm_capabilities_t caps{};
    caps.struct_size = sizeof(caps);
    caps.abi_version = LM_ABI_VERSION;
    if (lm_diagnostics_get(c, &d) != LM_STATUS_OK || lm_get_capabilities(c, &caps) != LM_STATUS_OK) {
        return error("lm_diagnostics_get failed");
    }
    std::string feats;
    std::array<lm::diag::Feature, lm::diag::k_max_features> rows{};
    const std::size_t rn = lm::diag::features(caps, rows);
    for (std::size_t k = 0; k < rn; ++k) {
        char f[160];
        std::snprintf(f, sizeof f, "%s{\"name\":\"%s\",\"built\":%s,\"implemented\":%s,\"enabled\":%s,\"qualified\":%s}",
                      k == 0 ? "" : ",", rows[k].name, rows[k].built ? "true" : "false",
                      rows[k].implemented ? "true" : "false", rows[k].enabled ? "true" : "false",
                      rows[k].qualified ? "true" : "false");
        feats += f;
    }
    char buf[2400];
    std::snprintf(buf, sizeof buf,
                  "{\"ok\":true,\"validity\":%" PRIu64 ",\"root_term\":%u,\"channel_epoch\":%u,\"current_channel\":%u,"
                  "\"pending_channel\":%u,\"regular_peers\":%u,\"transient_peers\":%u,\"tx_depth\":%u,\"rx_depth\":%u,"
                  "\"tx_frames\":%" PRIu64 ",\"rx_frames\":%" PRIu64 ",\"link_retries\":%" PRIu64 ",\"rf_failures\":%" PRIu64
                  ",\"local_busy\":%" PRIu64 ",\"owner_cpu_us\":%" PRIu64 ",\"interval_us\":%" PRIu64
                  ",\"last_reset_reason\":%" PRIu64 ",\"min_heap_bytes\":%u,\"stack_free_bytes\":%u,\"steps\":%" PRIu64
                  ",\"build_bits\":%" PRIu64 ",\"implemented_bits\":%" PRIu64 ",\"qualified_bits\":%" PRIu64
                  ",\"enabled_bits\":%" PRIu64 ",\"features\":[%s]}",
                  d.validity_bits, d.root_term, d.channel_epoch, d.current_channel, d.pending_channel, d.regular_peers,
                  d.transient_peers, d.tx_depth, d.rx_depth, d.tx_frames, d.rx_frames, d.link_retries, d.rf_failures,
                  d.local_busy, d.owner_cpu_us, d.interval_us, d.last_reset_reason, d.min_heap_bytes, d.stack_free_bytes,
                  steps, caps.build_bits, caps.implemented_bits, caps.qualified_bits, caps.enabled_bits, feats.c_str());
    return buf;
}

} // namespace meshsim
