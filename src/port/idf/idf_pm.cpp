#include "port/idf/idf_pm.hpp"

#include <cstddef>
#include <cstring>

#include "esp_attr.h"
#include "esp_rtc_time.h"
#include "esp_sleep.h"
#include "esp_system.h"
#include "sdkconfig.h"

namespace lm::idf {
namespace {

// RTC memory that a deep sleep keeps (a power-on reset does not: the magic and checksum then fail).
struct Retained {
    uint32_t magic;
    uint64_t slept_at_rtc_us;
    uint8_t len;
    uint8_t bytes[32];
    uint32_t check;
};
RTC_NOINIT_ATTR Retained g_rtc;
constexpr uint32_t k_magic = 0x4C4D5052; // "LMPR"

uint32_t check_of(const Retained &r) {
    uint32_t c = 0x811C9DC5U; // FNV-1a over the fields, not a security measure: it only tells garbage from state
    const auto *p = reinterpret_cast<const uint8_t *>(&r);
    for (std::size_t i = 0; i < offsetof(Retained, check); ++i) {
        c = (c ^ p[i]) * 16777619U;
    }
    return c;
}

#if CONFIG_PM_ENABLE
esp_pm_lock_type_t type_of(unsigned bit) {
    // The Wi-Fi driver holds its own locks while it runs; ours keep the CPU out of light sleep while an episode,
    // a Flash job or a frame is on, and at full speed for the public-key jobs.
    return bit == 1 ? ESP_PM_CPU_FREQ_MAX : ESP_PM_NO_LIGHT_SLEEP;
}
#endif

} // namespace

uint8_t IdfPm::set_locks(uint8_t mask) {
#if CONFIG_PM_ENABLE
    for (unsigned b = 0; b < k_locks; ++b) {
        const bool want = ((mask >> b) & 1U) != 0;
        const bool have = ((held_ >> b) & 1U) != 0;
        if (want == have) {
            continue;
        }
        if (want) {
            if (handle_[b] == nullptr &&
                esp_pm_lock_create(type_of(b), 0, "leanmesh", &handle_[b]) != ESP_OK) {
                ++failures_;
                continue;
            }
            if (esp_pm_lock_acquire(handle_[b]) == ESP_OK) {
                held_ = static_cast<uint8_t>(held_ | (1U << b));
            } else {
                ++failures_;
            }
        } else if (esp_pm_lock_release(handle_[b]) == ESP_OK) {
            held_ = static_cast<uint8_t>(held_ & ~(1U << b));
        } else {
            ++failures_; // a release that failed leaves the bit held: the next set_locks() tries it again
        }
    }
    return held_;
#else
    return mask; // no power management in this build: there is nothing to hold, so nothing can be missing
#endif
}

port::WakeInfo IdfPm::boot_info() {
    port::WakeInfo w;
    switch (esp_reset_reason()) {
    case ESP_RST_DEEPSLEEP:
        w.cause = port::ResetCause::DeepWake;
        break;
    case ESP_RST_BROWNOUT:
        w.cause = port::ResetCause::Brownout;
        break;
    case ESP_RST_INT_WDT:
    case ESP_RST_TASK_WDT:
    case ESP_RST_WDT:
        w.cause = port::ResetCause::Watchdog;
        break;
    default:
        w.cause = port::ResetCause::Cold;
        break;
    }
    if (w.cause == port::ResetCause::DeepWake) {
        switch (esp_sleep_get_wakeup_cause()) {
        case ESP_SLEEP_WAKEUP_TIMER:
            w.source = LM_WAKE_TIMER;
            break;
        case ESP_SLEEP_WAKEUP_UNDEFINED:
            break;
        default:
            w.source = LM_WAKE_EXTERNAL; // GPIO/EXT0/EXT1/ULP: whatever the application armed
            break;
        }
        if (g_rtc.magic == k_magic && g_rtc.check == check_of(g_rtc) && g_rtc.len <= sizeof(w.retained)) {
            std::memcpy(w.retained.data(), g_rtc.bytes, g_rtc.len);
            w.retained_len = g_rtc.len;
            const uint64_t now = esp_rtc_get_time_us();
            if (now >= g_rtc.slept_at_rtc_us) { // the RTC counter went on across the sleep
                w.elapsed_known = true;
                w.elapsed_upper_ms = (now - g_rtc.slept_at_rtc_us + 999U) / 1000U + 1U;
            }
        }
    }
    std::memset(&g_rtc, 0, sizeof(g_rtc)); // consumed: a later reset without a sleep is not a continuation
    return w;
}

void IdfPm::retain(ByteView state) {
    g_rtc.len = static_cast<uint8_t>(state.size() < sizeof(g_rtc.bytes) ? state.size() : sizeof(g_rtc.bytes));
    std::memcpy(g_rtc.bytes, state.data(), g_rtc.len);
    g_rtc.magic = k_magic;
    g_rtc.check = check_of(g_rtc);
}

// leanmesh_idf.h: optional; an application that does not define it never holds a sleep back.
extern "C" bool lm_idf_sleep_veto(uint8_t sleep_kind) __attribute__((weak));

bool IdfPm::may_sleep(uint8_t kind) { return lm_idf_sleep_veto == nullptr || !lm_idf_sleep_veto(kind); }

port::SleepStart IdfPm::sleep(uint8_t kind, uint8_t sources, uint64_t duration_ms, port::WakeInfo &woke) {
    if ((sources & LM_WAKE_TIMER) != 0 && duration_ms != 0) {
        if (esp_sleep_enable_timer_wakeup(duration_ms * 1000ULL) != ESP_OK) {
            return port::SleepStart::Unsupported;
        }
    } else {
        (void)esp_sleep_disable_wakeup_source(ESP_SLEEP_WAKEUP_TIMER); // GPIO wake sources stay as the board armed them
    }
    const uint64_t before = esp_rtc_get_time_us();
    if (kind == LM_SLEEP_DEEP) {
        g_rtc.slept_at_rtc_us = before;
        g_rtc.check = check_of(g_rtc);
        esp_deep_sleep_start(); // does not return
    }
    const esp_err_t e = esp_light_sleep_start();
    if (e == ESP_ERR_SLEEP_REJECT || e == ESP_ERR_INVALID_STATE) {
        return port::SleepStart::Unsupported; // the platform refused: the owner brings the radio back
    }
    woke = port::WakeInfo{};
    woke.cause = port::ResetCause::LightWake;
    woke.source = esp_sleep_get_wakeup_cause() == ESP_SLEEP_WAKEUP_TIMER ? LM_WAKE_TIMER : LM_WAKE_EXTERNAL;
    woke.ram_complete = e == ESP_OK;
    const uint64_t after = esp_rtc_get_time_us();
    woke.elapsed_known = after >= before;
    woke.elapsed_upper_ms = woke.elapsed_known ? (after - before + 999U) / 1000U + 1U : 0U;
    return port::SleepStart::Woke;
}

} // namespace lm::idf
