// meshsim command of the mesh slice (S11): the state of a node's mesh module. Bench only.
#include <cinttypes>
#include <cstdio>
#include <string>

#include "control.hpp"
#include "port/sim/sim_node.hpp"

namespace meshsim {

std::string cmd_mesh(Sim &sim, const Args &a) {
    uint16_t i = 0;
    if (a.size() != 2 || !parse_node(sim, a[1], i)) {
        return error("usage: mesh <node>");
    }
    lm::sim::SimNode &n = sim.world.node(i);
    if (n.ctx() == nullptr) {
        return error("node is not powered");
    }
    lm::Engine &e = n.ctx()->engine;
    const lm::route::Mesh &m = e.mesh();
    static const char *const k_state[] = {"off", "listen", "search", "attach", "ready", "root"};
    std::string path = "[";
    for (unsigned k = 0; k < m.path_size(); ++k) {
        path += (k != 0 ? "," : "") + std::to_string(m.path()[k]);
    }
    path += "]";
    const lm::route::Mesh::Stats &s = m.stats();
    char buf[640];
    std::snprintf(buf, sizeof buf,
                  "{\"ok\":true,\"state\":\"%s\",\"parent\":%u,\"depth\":%u,\"path\":%s,\"repairing\":%s,"
                  "\"beacons_tx\":%" PRIu64 ",\"beacons_rx\":%" PRIu64 ",\"probes_tx\":%" PRIu64
                  ",\"registers\":%" PRIu64 ",\"leases\":%" PRIu64 ",\"queries\":%" PRIu64 ",\"suspects\":%" PRIu64
                  ",\"attach_failed\":%" PRIu64 ",\"last_repair_ms\":%" PRIu64 ",\"proxy_entries\":%zu}",
                  k_state[static_cast<unsigned>(m.state())], m.parent_addr().value(), m.depth(), path.c_str(),
                  m.repairing() ? "true" : "false", s.beacons_tx, s.beacons_rx, s.probes_tx, s.registers, s.leases,
                  s.queries, s.suspects, s.attach_failed, s.last_repair_ms, e.proxy().entries());
    return buf;
}

} // namespace meshsim
