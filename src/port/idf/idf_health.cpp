#include "port/idf/idf_health.hpp"

#include <algorithm>

#include "esp_heap_caps.h"
#include "esp_system.h"

namespace lm::idf {

namespace {

port::ResetReason map_reset(esp_reset_reason_t r) {
    switch (r) {
    case ESP_RST_POWERON:
        return port::ResetReason::PowerOn;
    case ESP_RST_SW:
        return port::ResetReason::Software;
    case ESP_RST_PANIC:
        return port::ResetReason::Panic;
    case ESP_RST_INT_WDT:
    case ESP_RST_TASK_WDT:
    case ESP_RST_WDT:
        return port::ResetReason::Watchdog;
    case ESP_RST_BROWNOUT:
        return port::ResetReason::Brownout;
    case ESP_RST_DEEPSLEEP:
        return port::ResetReason::DeepSleepWake;
    case ESP_RST_EXT:
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
    f.cpu_valid = true;
    f.owner_cpu_us = owner_.busy_us();
    f.rx_ring_valid = true;
    f.rx_ring_depth = radio_.rx_depth();
    f.rx_ring_dropped = radio_.rx_dropped();
    return f;
}

} // namespace lm::idf
