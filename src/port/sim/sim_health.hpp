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
        port::HealthFacts f;
        f.reset_valid = true;
        f.reset = port::ResetReason::PowerOn;
        f.rx_ring_valid = true;
        f.rx_ring_depth = radio_.rx_depth();
        f.rx_ring_dropped = radio_.rx_dropped();
        if (extra.heap_valid) {
            f.heap_valid = true;
            f.min_heap_bytes = extra.min_heap_bytes;
        }
        if (extra.stack_valid) {
            f.stack_valid = true;
            f.stack_free_bytes = extra.stack_free_bytes;
        }
        if (extra.cpu_valid) {
            f.cpu_valid = true;
            f.owner_cpu_us = extra.owner_cpu_us;
        }
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
