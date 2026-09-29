// One simulated device: the real core (lm_context + Engine) wired to sim ports.
// power_cut() drops all RAM state (context, rings, in-flight jobs) and keeps the SimStore, like a
// real brown-out; boot() constructs a fresh context from the same workspace.
#pragma once

#include <cstdint>
#include <memory>

#include "capi/context.hpp"
#include "core/profile.hpp"
#include "port/sim/sim_ports.hpp"
#include "port/sim/sim_store.hpp"

namespace lm::sim {

class World;

struct NodeOptions {
    Role role = Role::Leaf;
    int32_t clock_drift_ppm = 0;
    StoreGeometry store;
    bool object_transfer_enabled = false;
};

// Counters the simulator itself observes (not device diagnostics).
struct SerialCounters {
    uint64_t rx_bytes = 0; // bytes the host wrote to this node's serial port
    uint64_t tx_bytes = 0;
};

class SimNode {
  public:
    SimNode(World &world, uint16_t index, const MacAddr &mac, const NodeOptions &opts);
    ~SimNode();
    SimNode(const SimNode &) = delete;
    SimNode &operator=(const SimNode &) = delete;

    [[nodiscard]] Status boot();
    void power_cut();
    [[nodiscard]] bool powered() const { return ctx_ != nullptr; }
    // Monotone count of power cycles; pending radio/job events of an older epoch are discarded.
    [[nodiscard]] uint32_t epoch() const { return epoch_; }

    // World callback for a Wake event scheduled at `at_us`; stale (superseded) wakes are ignored.
    void on_wake_event(uint64_t at_us);
    // Asks the world to run the owner as soon as possible (after RX, job done, command).
    void notify();

    [[nodiscard]] uint16_t index() const { return index_; }
    [[nodiscard]] const NodeOptions &options() const { return opts_; }
    [[nodiscard]] lm_context_t *ctx() { return ctx_; }
    [[nodiscard]] const Engine *engine() const { return ctx_ != nullptr ? &ctx_->engine : nullptr; }

    SimClock clock;
    SimRadio radio;
    SimJobs jobs;
    SimStore store;
    DirectOwnerCall owner_call;
    SerialCounters serial;

  private:
    World &world_;
    uint16_t index_;
    NodeOptions opts_;
    uint32_t epoch_ = 0;
    std::unique_ptr<uint8_t[]> workspace_;
    std::size_t workspace_bytes_ = 0;
    lm_context_t *ctx_ = nullptr;
    void request_wake(uint64_t world_at_us);

    uint64_t scheduled_wake_us_ = UINT64_MAX; // earliest pending Wake event
};

} // namespace lm::sim
