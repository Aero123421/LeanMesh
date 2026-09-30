// Simulation of the power-management port (S16): PM locks as a recorded level, sleep entry, and the facts a wake
// reports. SIMULATION ONLY: no energy is modelled here, the only quantities are the virtual times a node spends
// awake and the lock transitions. Fault-injection fields let a test produce the golden wake cases
// (RAM incomplete, elapsed time unknown) without touching the core.
#pragma once

#include <array>
#include <cstdint>

#include "core/ports.hpp"

namespace lm::sim {

class SimNode;

class SimPm final : public port::Pm {
  public:
    explicit SimPm(SimNode &node) : node_(node) {}

    [[nodiscard]] uint8_t set_locks(uint8_t mask) override;
    port::WakeInfo boot_info() override;
    void retain(ByteView state) override;
    [[nodiscard]] port::SleepStart sleep(uint8_t kind, uint8_t sources, uint64_t duration_ms, port::WakeInfo &woke) override;

    // ---- bench ----
    bool supported = true;        // false: sleep() answers Unsupported (a port without the capability)
    bool ram_complete = true;     // reported by a light wake
    bool elapsed_known = true;    // reported by a light/deep wake (false: RTC continuity unknown)
    uint8_t take_fail = 0;        // lock bits whose acquire fails (the level does not change)
    uint8_t drop_fail = 0;        // lock bits whose release fails (the bit stays held)
    [[nodiscard]] uint8_t locks() const { return mask_; }
    [[nodiscard]] uint64_t acquired(unsigned bit) const { return acquired_[bit]; }
    [[nodiscard]] uint64_t released(unsigned bit) const { return released_[bit]; }
    [[nodiscard]] bool leaked() const { return mask_ != 0; }
    [[nodiscard]] uint64_t set_calls() const { return set_calls_; }
    [[nodiscard]] uint64_t sleep_calls() const { return sleep_calls_; } // sleeps the owner actually started
    void clear_retained() { retained_len_ = 0; } // a power-on reset: RTC memory is gone
    // Deep sleep (the node's RAM goes with it; the SimNode powers it off and boots it at the wake).
    [[nodiscard]] bool deep_requested() const { return deep_; }
    [[nodiscard]] uint64_t deep_wake_after_ms() const { return deep_ms_; }
    [[nodiscard]] uint8_t deep_sources() const { return deep_sources_; }
    void deep_taken() { deep_ = false; }
    // The next boot() is a deep-sleep wake with these facts (consumed by boot_info()).
    void prepare_deep_boot(uint8_t source, uint64_t elapsed_ms);

  private:
    SimNode &node_;
    uint8_t mask_ = 0;
    std::array<uint64_t, 4> acquired_{}, released_{};
    uint64_t set_calls_ = 0, sleep_calls_ = 0;
    std::array<uint8_t, 32> retained_{};
    uint8_t retained_len_ = 0;
    bool deep_ = false;
    uint64_t deep_ms_ = 0;
    uint8_t deep_sources_ = 0;
    port::WakeInfo boot_;
};

} // namespace lm::sim
