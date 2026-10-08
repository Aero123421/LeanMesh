#include "port/idf/idf_health.hpp"

#include <algorithm>

#include "esp_heap_caps.h"
#include "esp_system.h"
#include "leanmesh_idf.h"

namespace lm::idf {

namespace {

port::ResetReason map_reset(esp_reset_reason_t r) {
    switch (r) {
    case ESP_RST_POWERON:
        return port::ResetReason::PowerOn;
    case ESP_RST_SW:
        return port::ResetReason::Software;
    case ESP_RST_PANIC:
    case ESP_RST_CPU_LOCKUP: // double exception
        return port::ResetReason::Panic;
    case ESP_RST_INT_WDT:
    case ESP_RST_TASK_WDT:
    case ESP_RST_WDT:
        return port::ResetReason::Watchdog;
    case ESP_RST_BROWNOUT:
    case ESP_RST_PWR_GLITCH:
        return port::ResetReason::Brownout;
    case ESP_RST_DEEPSLEEP:
        return port::ResetReason::DeepSleepWake;
    case ESP_RST_EXT:
    case ESP_RST_USB:  // the USB-Serial/JTAG reset a connected PC triggers (S3/C3/C5/C6, HIL 2026-10-03)
    case ESP_RST_JTAG:
        return port::ResetReason::External;
    default:
        return port::ResetReason::Unknown; // ESP_RST_UNKNOWN and causes this map does not name
    }
}

} // namespace

port::HealthFacts IdfHealth::read() {
    port::HealthFacts f;
    const esp_reset_reason_t rr = esp_reset_reason();
    f.reset_valid = rr != ESP_RST_UNKNOWN;
    f.reset = map_reset(rr);
    f.heap_valid = true;
    f.min_heap_bytes = static_cast<uint32_t>(esp_get_minimum_free_heap_size());
    if (owner_.task() != nullptr && jobs_.task() != nullptr) {
        // IDF's FreeRTOS reports the high-water mark in bytes.
        f.stack_valid = true;
        f.stack_free_bytes = std::min(static_cast<uint32_t>(uxTaskGetStackHighWaterMark(owner_.task())),
                                      static_cast<uint32_t>(uxTaskGetStackHighWaterMark(jobs_.task())));
    }
    // owner busy_us is wall elapsed (including synchronous sleep/preemption), not CPU time.
    f.cpu_valid = false;
    f.rx_ring_valid = true;
    f.rx_ring_depth = radio_.rx_depth();
    f.rx_ring_dropped = radio_.rx_dropped();
    lm_idf_recovery_t recovery{};
    f.radio_recovery_valid = lm_idf_last_radio_recovery(&recovery);
    if (f.radio_recovery_valid) {
        f.radio_recovery_uptime_ms = recovery.uptime_ms;
        f.radio_recovery_reason = recovery.reason;
        f.radio_recovery_status = recovery.status;
        f.radio_recovery_attempts = recovery.attempts;
        f.radio_recovery_tx = recovery.tx_frames;
        f.radio_recovery_rx = recovery.rx_frames;
        f.radio_recovery_previous_boot = recovery.previous_boot;
    }
    return f;
}

} // namespace lm::idf
