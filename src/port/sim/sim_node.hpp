// One simulated device: the real core (lm_context + Engine) wired to sim ports.
// power_cut() drops all RAM state (context, rings, in-flight jobs) and keeps the SimStore, like a
// real brown-out; boot() constructs a fresh context from the same workspace.
#pragma once

#include <cstdint>
#include <memory>

#include "capi/context.hpp"
#include "core/profile.hpp"
#include "port/sim/sim_health.hpp"
#include "port/sim/sim_pm.hpp"
#include "port/sim/sim_ports.hpp"
#include "port/sim/sim_store.hpp"

namespace lm::sim {

class World;

// SIMULATION ONLY: an "approved" profile without any compliance record. Firmware refuses to start
// the radio until a real deployment approval exists (Kconfig, docs/03 §3).
inline port::RfProfile sim_rf_profile(uint8_t channel = 6) {
    port::RfProfile p;
    p.deployment_approved = true;
    p.channel = channel;
    p.allowed_channels_mask = static_cast<uint16_t>((1U << 1) | (1U << 6) | (1U << 11));
    return p;
}

struct NodeOptions {
    Role role = Role::Leaf;
    port::RfProfile rf = sim_rf_profile();
    int32_t clock_drift_ppm = 0;
    StoreGeometry store;
    bool object_transfer_enabled = false;
    // The mesh module (parent search, registration) runs by itself. Off for the tests of the slices that
    // open sessions and install routes by hand (link, join, delivery, serial); mesh tests turn it on.
    bool mesh = false;
    // [S16] The node has a sleep port (SimPm). Off: Ports::pm is null, as on a build without one.
    bool power_port = true;
    // The channel module (clock, plans, recovery scan, survey) runs. Off for the tests of earlier slices, which
    // give their nodes a root clock by hand and never change the channel.
    bool channel = false;
    // [S19] The node has a Health port (SimHealth). Off: Ports::health is null and the driver facts are unknown.
    bool health_port = true;
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
    // [S16] A deep-sleeping node's firmware starts again (app main: lm_init + lm_start) at its wake time.
    void on_boot_event(uint64_t at_us);
    // [S16] An external wake source fires (GPIO): a light sleeper wakes in place, a deep sleeper reboots now.
    void wake_external();
    [[nodiscard]] bool deep_sleeping() const { return deep_boot_at_us_ != UINT64_MAX; }
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
    SimPm pm{*this};
    SimHealth health{radio};
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
    uint64_t deep_boot_at_us_ = UINT64_MAX;   // [S16] the pending Boot event of a deep sleeper
    uint64_t deep_slept_at_us_ = 0;
    uint8_t deep_sources_ = 0;
    void go_deep();
};

} // namespace lm::sim
