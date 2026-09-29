// Root side of the mesh control plane (docs/04 §3, §5, §7): answers REGISTER / READY / QUERY of the
// members over their end sessions, owns the approved tree (root::Topology) and derives every path the
// root sends on from it. The tree holds routing state only; who a member is comes from the ledger entry
// of the same short address (decision S11-D9, ADR-002 P6: no second DeviceId table, no 64 cached
// paths on the root). One request at a time is validated against the current tree, so a burst of
// concurrent parent choices can never put a cycle into it. Owner thread only; nothing here blocks.
//
// A moved subtree is told: when READY applies a link that changes the paths of descendants, the root
// pushes each descendant its new path (one unsolicited LEASE at a time, paced), so nodes below a repaired
// relay reach the root again without waiting for their own lease renewal.
#pragma once

#include <cstdint>
#include <type_traits>

#include "core/delivery/route_spec.hpp"
#include "core/profile.hpp"
#include "core/route/mesh_wire.hpp"
#include "core/time.hpp"
#include "root/topology.hpp"

namespace lm {
class Engine;
}

namespace lm::root {

class Routes {
  public:
    explicit Routes(Engine &engine) : engine_(engine) {}
    Routes(const Routes &) = delete;
    Routes &operator=(const Routes &) = delete;

    void stop();
    // A mesh record of the end session with `peer`; `reply` is the reverse of the route it came along.
    void on_control(const DeviceId &peer, const delivery::PathSpec &reply, ByteView body, MonoTime now);
    void on_timer(MonoTime now);
    [[nodiscard]] MonoTime deadline() const;

    // Root -> member path from the tree (member must be Active in the ledger and in the tree).
    [[nodiscard]] bool path_to(const DeviceId &dest, delivery::PathSpec &out, MonoTime now);
    [[nodiscard]] bool path_to_addr(ShortAddr dest, delivery::PathSpec &out, MonoTime now);

    [[nodiscard]] const Topology &topology() const { return topo_; }
    struct Stats {
        uint64_t registers = 0, grants = 0, refused = 0, readies = 0, queries = 0, pushes = 0;
    };
    [[nodiscard]] const Stats &stats() const { return stats_; }

  private:
    void sync(MonoTime now);
    [[nodiscard]] bool identify(const DeviceId &dev, ShortAddr &addr, uint32_t &gen);
    void on_register(const DeviceId &peer, ShortAddr addr, uint32_t gen, const delivery::PathSpec &reply,
                     ByteView body, MonoTime now);
    void on_ready(const DeviceId &peer, ShortAddr addr, const delivery::PathSpec &reply, ByteView body, MonoTime now);
    void on_query(const DeviceId &peer, const delivery::PathSpec &reply, ByteView body, MonoTime now);
    void send_lease(const DeviceId &peer, const delivery::PathSpec &route, route::LeaseRec &l, MonoTime now);
    void push_next(MonoTime now);
    [[nodiscard]] uint64_t ms(MonoTime now) const { return now.to_ms(); }

    Engine &engine_;
    Topology topo_{ShortAddr{1}, RootTerm{1}};
    bool inited_ = false;
    Stats stats_;
    uint64_t push_mask_ = 0; // ledger slot (address - 2) of every member whose path changed
    MonoTime push_at_ = MonoTime::never();
};

// Leaf/relay builds carry no tree (docs/02 §4).
struct NoRoutes {
    explicit NoRoutes(Engine &) {}
    void stop() {}
    void on_control(const DeviceId &, const delivery::PathSpec &, ByteView, MonoTime) {}
    void on_timer(MonoTime) {}
    [[nodiscard]] MonoTime deadline() const { return MonoTime::never(); }
    [[nodiscard]] bool path_to(const DeviceId &, delivery::PathSpec &, MonoTime) { return false; }
    [[nodiscard]] bool path_to_addr(ShortAddr, delivery::PathSpec &, MonoTime) { return false; }
};

using RoutesType = std::conditional_t<k_root_capable, Routes, NoRoutes>;

} // namespace lm::root
