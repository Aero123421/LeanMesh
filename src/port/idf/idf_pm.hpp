// ESP-IDF power-management port (S16): PM locks as a level, light/deep sleep entry, the facts of a wake and the
// few bytes that must survive a deep sleep (RTC memory). Owner thread only.
//
// Not verified on hardware: whether esp_light_sleep_start() with the Wi-Fi driver stopped reaches the power the board
// needs, what the wake costs, and whether the RTC counter stays continuous across a deep sleep on every SoC are
// board questions (docs/20 §3, §11, docs/23). "Returned ESP_OK" is not a power result.
#pragma once

#include "core/ports.hpp"
#include "esp_pm.h"

namespace lm::idf {

class IdfPm final : public port::Pm {
  public:
    [[nodiscard]] uint8_t set_locks(uint8_t mask) override;
    port::WakeInfo boot_info() override;
    void retain(ByteView state) override;
    [[nodiscard]] port::SleepStart sleep(uint8_t kind, uint8_t sources, uint64_t duration_ms, port::WakeInfo &woke) override;
    [[nodiscard]] bool may_sleep(uint8_t kind) override; // lm_idf_sleep_veto() of the application, if it has one

    // Locks that could not be created or taken (a build without CONFIG_PM_ENABLE takes none): diagnostics.
    [[nodiscard]] uint32_t lock_failures() const { return failures_; }

  private:
    static constexpr unsigned k_locks = 4; // port::pm_lock::{episode, crypto, flash, radio}
    esp_pm_lock_handle_t handle_[k_locks] = {};
    uint8_t held_ = 0;
    uint32_t failures_ = 0;
};

} // namespace lm::idf
