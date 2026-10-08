// Simulated Health port (S19). SIMULATION ONLY. The simulator knows what it models: the reset cause of a boot
// (power-on: every boot in the sim follows a start or a power cut) and the depth/drops of its callback ring. It
// has no heap, no task stacks and no CPU time, so those stay UNKNOWN unless a test sets `override_facts` to
// prove the mapping of a platform that has them. A sim value is never a device measurement.
#pragma once

#include "core/diag/health.hpp"
#include "port/sim/sim_ports.hpp"

namespace lm::sim {

class SimHealth final : public port::Health {
  public:
    explicit SimHealth(const SimRadio &radio) : radio_(radio) {}
    port::HealthFacts read() override {
        port::HealthFacts f = extra; // explicit test facts only; defaults are unknown
        f.reset_valid = true;
        f.reset = port::ResetReason::PowerOn;
        f.rx_ring_valid = true;
        f.rx_ring_depth = radio_.rx_depth();
        f.rx_ring_dropped = radio_.rx_dropped();
        ++reads;
        return f;
    }
    // Test bench: values a platform with those sensors would report.
    port::HealthFacts extra;
    uint64_t reads = 0;

  private:
    const SimRadio &radio_;
};

} // namespace lm::sim
