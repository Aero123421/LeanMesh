// Health port (S19): what only the platform/driver knows (docs/10 §6, docs/16, T19). Optional
// (Ports::health may be null, as on a build without it); every field carries its own validity, so a
// fact the port cannot give is UNKNOWN and never 0. Owner thread only; the reads are cheap and are made
// only when the application asks for the diagnostics - nothing polls this port.
#pragma once

#include <cstdint>

namespace lm::port {

// Reset causes, port-neutral (the IDF port maps esp_reset_reason_t onto these).
enum class ResetReason : uint8_t {
    Unknown = 0, PowerOn = 1, Software = 2, Panic = 3, Watchdog = 4, Brownout = 5, DeepSleepWake = 6, External = 7,
};

struct HealthFacts {
    bool reset_valid = false;
    ResetReason reset = ResetReason::Unknown;
    bool heap_valid = false;
    uint32_t min_heap_bytes = 0;   // minimum free heap since boot (all of the SoC's heap, not the SDK's)
    bool stack_valid = false;
    uint32_t stack_free_bytes = 0; // least stack ever free over the SDK's tasks (high-water mark)
    bool cpu_valid = false;
    uint64_t owner_cpu_us = 0;     // time the owner spent inside step()/commands; includes preemption
    bool rx_ring_valid = false;
    uint32_t rx_ring_depth = 0;    // driver callback ring now
    uint32_t rx_ring_dropped = 0;  // frames the callback could not enqueue since boot
    bool radio_recovery_valid = false;
    uint32_t radio_recovery_uptime_ms = 0, radio_recovery_reason = 0, radio_recovery_status = 0;
    uint32_t radio_recovery_attempts = 0, radio_recovery_tx = 0, radio_recovery_rx = 0;
    uint32_t radio_recovery_previous_boot = 0;
};

class Health {
  public:
    virtual HealthFacts read() = 0;

  protected:
    ~Health() = default;
};

} // namespace lm::port
