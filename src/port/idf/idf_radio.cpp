#include "port/idf/idf_radio.hpp"

#include <cstring>

#include "esp_event.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_now.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_attr.h"
#include "esp_wifi.h"
#include "leanmesh_idf.h"
#include "port/idf/idf_owner.hpp"
#include "soc/soc_caps.h"

namespace lm::idf {

namespace {

IdfRadio *g_radio = nullptr; // the one driver instance; set before the callbacks are registered

// Radio facts for lm_idf_radio_stats (field diagnostics). Counters only: the send callback updates two of them with
// plain atomic arithmetic (no logging, no formatting).
std::atomic<uint32_t> g_tx_done_max_ms{0};
std::atomic<uint32_t> g_tx_late{0};
std::atomic<uint32_t> g_tx_stall_waits{0};

// Why the previous boot ended, if the SDK itself restarted it: RTC memory that survives a software reset but not a
// power loss (then the reset reason says power-on). The magic tells a written record from power-on garbage.
constexpr uint32_t k_restart_magic = 0x4C4D5232U; // "LMR2": includes the recovery record
struct RestartRecord {
    uint32_t magic;
    uint32_t cause;
    uint32_t uptime_ms;
    uint32_t detail;
    lm_idf_recovery_t recovery;
};
portMUX_TYPE g_recovery_lock = portMUX_INITIALIZER_UNLOCKED;
lm_idf_recovery_t g_recovery{};
RTC_NOINIT_ATTR RestartRecord g_restart_rec;
RestartRecord g_restart_seen{};   // the previous boot's record, taken once at the first read
bool g_restart_taken = false;

void take_restart_record() {
    portENTER_CRITICAL(&g_recovery_lock);
    if (g_restart_taken) {
        portEXIT_CRITICAL(&g_recovery_lock);
        return;
    }
    g_restart_taken = true;
    if (g_restart_rec.magic == k_restart_magic) {
        g_restart_seen = g_restart_rec;
        g_restart_seen.recovery.previous_boot = true;
        g_recovery = g_restart_seen.recovery;
    }
    g_restart_rec.magic = 0; // a later restart that is not the SDK's (panic, power) never shows an old cause
    portEXIT_CRITICAL(&g_recovery_lock);
}

[[noreturn]] void controlled_restart(uint32_t cause, uint32_t detail) {
    take_restart_record();
    portENTER_CRITICAL(&g_recovery_lock);
    g_restart_rec.cause = cause;
    g_restart_rec.uptime_ms = static_cast<uint32_t>(esp_timer_get_time() / 1000);
    g_restart_rec.detail = detail;
    g_restart_rec.recovery = g_recovery;
    g_restart_rec.magic = k_restart_magic;
    portEXIT_CRITICAL(&g_recovery_lock);
    esp_restart();
}

// Callback trampolines: no logging, no formatting, no allocation (docs/15 §2).
void recv_cb(const esp_now_recv_info_t *info, const uint8_t *data, int len) {
    if (g_radio != nullptr && info != nullptr && info->rx_ctrl != nullptr) {
        g_radio->on_recv(info->src_addr, info->des_addr, info->rx_ctrl->rssi, data, len);
    }
}

void send_cb(const esp_now_send_info_t *, esp_now_send_status_t status) {
    if (g_radio != nullptr) {
        g_radio->on_sent(status == ESP_NOW_SEND_SUCCESS);
    }
}

MonoTime now_mono() { return MonoTime{static_cast<uint64_t>(esp_timer_get_time())}; }

MacAddr to_mac(const uint8_t *b) {
    MacAddr m;
    std::memcpy(m.bytes.data(), b, m.bytes.size());
    return m;
}

Status map_send_error(esp_err_t e) {
    switch (e) {
    case ESP_ERR_ESPNOW_NO_MEM:
        return Status::NoCapacity; // NO_MEM: local shortage
    case ESP_ERR_ESPNOW_NOT_FOUND:
    case ESP_ERR_ESPNOW_ARG:
        return Status::InvalidArgument;
    default:
        return Status::Busy; // internal/if errors: local, retryable, not an RF sample
    }
}

} // namespace

Status IdfRadio::init_wifi() {
    if (wifi_inited_) {
        return Status::Ok;
    }
    // Both calls report INVALID_STATE when the application already did them: that is fine.
    esp_err_t e = esp_netif_init();
    if (e != ESP_OK) {
        return Status::RecoveryRequired;
    }
    e = esp_event_loop_create_default();
    if (e != ESP_OK && e != ESP_ERR_INVALID_STATE) {
        return Status::RecoveryRequired;
    }
    wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
    if (esp_wifi_init(&init) != ESP_OK || esp_wifi_set_storage(WIFI_STORAGE_RAM) != ESP_OK ||
        esp_wifi_set_mode(WIFI_MODE_STA) != ESP_OK) {
        return Status::RecoveryRequired;
    }
#if SOC_WIFI_SUPPORT_5G
    // C5: the LR mode lives on 2.4 GHz only; never leave the band on AUTO.
    if (esp_wifi_set_band_mode(WIFI_BAND_MODE_2G_ONLY) != ESP_OK) {
        return Status::RecoveryRequired;
    }
#endif
    wifi_inited_ = true;
    return Status::Ok;
}

// Every start after a radio-off period sets the profile again: nothing is assumed to have survived esp_wifi_stop.
Status IdfRadio::start_wifi(const port::RfProfile &profile) {
    LM_TRY(init_wifi());
    if (wifi_running_) {
        return Status::Ok;
    }
    // Allowed channel window from the deployment profile (contiguous range covering the mask).
    uint8_t lo = 14;
    uint8_t hi = 0;
    for (uint8_t c = 1; c <= 13; ++c) {
        if ((profile.allowed_channels_mask & (1U << c)) != 0) {
            lo = lo < c ? lo : c;
            hi = c;
        }
    }
    wifi_country_t country{};
    country.cc[0] = profile.country[0];
    country.cc[1] = profile.country[1];
    country.cc[2] = '\0';
    country.schan = lo;
    country.nchan = static_cast<uint8_t>(hi - lo + 1);
    country.max_tx_power = static_cast<int8_t>(profile.tx_power_qdbm / 4);
    country.policy = WIFI_COUNTRY_POLICY_MANUAL;
    if (esp_wifi_set_country(&country) != ESP_OK ||
        esp_wifi_set_bandwidth(WIFI_IF_STA, WIFI_BW20) != ESP_OK ||
        esp_wifi_set_protocol(WIFI_IF_STA, WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G |
                                               WIFI_PROTOCOL_11N | WIFI_PROTOCOL_LR) != ESP_OK ||
        esp_wifi_start() != ESP_OK) {
        return Status::RecoveryRequired;
    }
    wifi_running_ = true;
    // Power save off, read back (the STA default is MIN_MODEM): a radio that is on is on for ESP-NOW.
    wifi_ps_type_t ps = WIFI_PS_MAX_MODEM;
    if (esp_wifi_set_ps(WIFI_PS_NONE) != ESP_OK || esp_wifi_get_ps(&ps) != ESP_OK || ps != WIFI_PS_NONE) {
        return Status::RecoveryRequired;
    }
    return Status::Ok;
}

Status IdfRadio::apply_channel_and_power(uint8_t channel, int16_t tx_qdbm) {
    if (esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE) != ESP_OK ||
        esp_wifi_set_max_tx_power(static_cast<int8_t>(tx_qdbm)) != ESP_OK) {
        return Status::RecoveryRequired;
    }
    uint8_t applied = 0;
    wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;
    int8_t power = 0;
    // Readback: what the driver runs is what the profile allows, not what was requested.
    if (esp_wifi_get_channel(&applied, &second) != ESP_OK || applied != channel ||
        second != WIFI_SECOND_CHAN_NONE || esp_wifi_get_max_tx_power(&power) != ESP_OK ||
        power > tx_qdbm) {
        return Status::RecoveryRequired;
    }
    return Status::Ok;
}

Status IdfRadio::start(const port::RfProfile &profile) {
    if (!profile.deployment_approved) {
        return Status::RfProfileUnapproved;
    }
    if (profile.channel < 1 || profile.channel > 13 ||
        (profile.allowed_channels_mask & (1U << profile.channel)) == 0 ||
        profile.tx_power_qdbm < 8 || profile.tx_power_qdbm > 84 || profile.country[0] == '\0') {
        return Status::InvalidArgument;
    }
    if (now_ready_) {
        return Status::Conflict; // stop() first
    }
    LM_TRY(start_wifi(profile));
    LM_TRY(apply_channel_and_power(profile.channel, profile.tx_power_qdbm));
    allowed_mask_ = profile.allowed_channels_mask;
    tx_power_qdbm_ = profile.tx_power_qdbm;
    ++generation_; // fresh driver instance: an older completion can never match
    in_flight_.store(false);
    g_radio = this;
    if (esp_now_init() != ESP_OK) {
        return Status::RecoveryRequired;
    }
    if (esp_now_register_recv_cb(recv_cb) != ESP_OK || esp_now_register_send_cb(send_cb) != ESP_OK) {
        // A failed deinit leaves ESP-NOW up: remember it so stop() retries and destroy is refused.
        now_ready_ = esp_now_deinit() != ESP_OK;
        return Status::RecoveryRequired;
    }
    rx_held_.store(false);
    now_ready_ = true;
    return Status::Ok;
}

Status IdfRadio::stop() {
    if (!now_ready_ && !wifi_running_) {
        return Status::Ok;
    }
    if (now_ready_) {
        const uint64_t started = tx_started_us_.load();
        const bool overdue = in_flight_.load() && static_cast<uint64_t>(esp_timer_get_time()) - started >=
                                                      static_cast<uint64_t>(TxManager::k_watchdog.us);
        if (overdue) {
            // A late completion still proves the drain: wait for it, bounded (a recovery path, not a poll).
            g_tx_stall_waits.fetch_add(1);
            const uint64_t limit = started + static_cast<uint64_t>(TxManager::k_watchdog.us + k_drain_wait.us);
            const TickType_t pause = pdMS_TO_TICKS(5) > 0 ? pdMS_TO_TICKS(5) : 1; // HZ=100: 5 ms is 0 ticks (a spin)
            while (in_flight_.load() && static_cast<uint64_t>(esp_timer_get_time()) < limit) {
                vTaskDelay(pause);
            }
            if (in_flight_.load()) { // callback drain cannot be proven: controlled reboot (docs/03 §4)
                controlled_restart(LM_IDF_RESTART_RADIO_STALL,
                                   static_cast<uint32_t>((static_cast<uint64_t>(esp_timer_get_time()) - started) / 1000));
            }
        }
        // Only a successful deinit proves the callbacks are gone. On failure the port stays "ready"
        // (callbacks possibly live) so a second stop() retries instead of reporting success, and the
        // engine refuses lm_destroy (FIX1-D5).
        if (esp_now_deinit() != ESP_OK) {
            return Status::RecoveryRequired;
        }
        now_ready_ = false;
        // Anything still queued is discarded by the generation check.
        port::RadioRx rx;
        while (rx_ring_.pop(rx)) {
        }
    }
    // The radio is off only when the Wi-Fi driver is stopped as well (FIX10-D10): a failure keeps `wifi_running_`,
    // reports the failure and lets the next stop() try again; the owner does not count the time as radio-off.
    if (wifi_running_) {
        if (esp_wifi_stop() != ESP_OK) {
            return Status::RecoveryRequired;
        }
        wifi_running_ = false;
    }
    in_flight_.store(false); // (no callback can follow a stopped driver)
    return Status::Ok;
}

Status IdfRadio::set_channel(uint8_t channel) {
    if (!now_ready_ || channel < 1 || channel > 13 || (allowed_mask_ & (1U << channel)) == 0) {
        return Status::InvalidArgument;
    }
    return apply_channel_and_power(channel, tx_power_qdbm_);
}

Status IdfRadio::add_peer(const MacAddr &mac) {
    if (!now_ready_) {
        return Status::Conflict;
    }
    esp_now_peer_info_t peer{};
    std::memcpy(peer.peer_addr, mac.bytes.data(), mac.bytes.size());
    peer.channel = 0; // follow the current channel
    peer.ifidx = WIFI_IF_STA;
    peer.encrypt = false; // link AEAD is done in software (docs/03 §2)
    const esp_err_t e = esp_now_add_peer(&peer);
    if (e == ESP_ERR_ESPNOW_FULL || e == ESP_ERR_ESPNOW_NO_MEM) {
        return Status::NoCapacity;
    }
    if (e != ESP_OK && e != ESP_ERR_ESPNOW_EXIST) {
        return Status::RecoveryRequired;
    }
    esp_now_rate_config_t rate{};
    rate.phymode = WIFI_PHY_MODE_LR;
    rate.rate = WIFI_PHY_RATE_LORA_250K;
    if (esp_now_set_peer_rate_config(mac.bytes.data(), &rate) != ESP_OK) {
        (void)esp_now_del_peer(mac.bytes.data());
        return Status::RecoveryRequired; // never fall back to 1 Mbit/s silently
    }
    return Status::Ok;
}

Status IdfRadio::remove_peer(const MacAddr &mac) {
    const esp_err_t e = esp_now_del_peer(mac.bytes.data());
    if (e == ESP_OK) {
        return Status::Ok;
    }
    return e == ESP_ERR_ESPNOW_NOT_FOUND ? Status::NotFound : Status::RecoveryRequired;
}

Status IdfRadio::transmit(const MacAddr &dst, ByteView frame, port::TxToken token) {
    if (!now_ready_ || frame.empty() || frame.size() > port::k_max_frame_bytes) {
        return Status::InvalidArgument;
    }
    bool expected = false;
    if (!in_flight_.compare_exchange_strong(expected, true)) {
        return Status::Busy;
    }
    pending_token_ = token;
    tx_started_us_.store(static_cast<uint64_t>(esp_timer_get_time()));
    const esp_err_t e = esp_now_send(dst.bytes.data(), frame.data(), frame.size());
    if (e != ESP_OK) {
        in_flight_.store(false); // no callback will follow
        return map_send_error(e);
    }
    return Status::Ok;
}

bool IdfRadio::poll(port::RadioEvent &out) {
    if (done_ring_.pop(out.done)) {
        out.kind = port::RadioEvent::Kind::TxDone;
        return true;
    }
    if (rx_ring_.pop(out.rx)) {
        out.kind = port::RadioEvent::Kind::Rx;
        return true;
    }
    return false;
}

void IdfRadio::hold_rx() {
    rx_held_.store(true);
    // The callback increments rx_in_cb_ before it reads rx_held_ (both seq_cst): once the count is 0
    // here, every later callback sees the hold and every earlier one has finished its push. The
    // callback body is a bounded copy, so this wait is short; the tick bound only guards a stuck driver.
    for (int ticks = 0; rx_in_cb_.load() != 0 && ticks < 100; ++ticks) {
        vTaskDelay(1);
    }
}

void IdfRadio::on_recv(const uint8_t *src, const uint8_t *dst, int8_t rssi, const uint8_t *data,
                       int len) {
    rx_in_cb_.fetch_add(1);
    struct Leave {
        std::atomic<uint8_t> &n;
        ~Leave() { n.fetch_sub(1); }
    } leave{rx_in_cb_};
    if (rx_held_.load() || len <= 0 || static_cast<std::size_t>(len) > port::k_max_frame_bytes) {
        return; // held for the sleep entry (never acknowledged: the sender repeats it), or not a frame this SDK can have produced (250 B self-limit)
    }
    port::RadioRx rx;
    rx.src = to_mac(src);
    rx.broadcast = to_mac(dst).is_broadcast();
    rx.rssi_valid = true;
    rx.rssi_dbm = rssi;
    rx.at = now_mono();
    rx.len = static_cast<uint8_t>(len);
    std::memcpy(rx.bytes.data(), data, static_cast<std::size_t>(len));
    if (rx_ring_.push(rx)) { // overflow is counted by the ring, never blocks the driver
        owner_.notify();
    }
}

void IdfRadio::on_sent(bool success) {
    if (!in_flight_.load()) {
        return; // no TX of this driver instance is waiting: ignore
    }
    port::RadioTxDone done;
    done.token = pending_token_;
    done.result = success ? port::TxResult::MacAcked : port::TxResult::MacFailed;
    done.at = now_mono();
    const auto took_ms = static_cast<uint32_t>((done.at.us - tx_started_us_.load()) / 1000);
    for (uint32_t seen = g_tx_done_max_ms.load(); took_ms > seen && !g_tx_done_max_ms.compare_exchange_weak(seen, took_ms);) {
    }
    if (took_ms >= k_tx_slow_ms) {
        g_tx_late.fetch_add(1);
    }
    in_flight_.store(false);
    (void)done_ring_.push(done);
    owner_.notify();
}

} // namespace lm::idf

extern "C" bool lm_idf_last_restart(lm_idf_restart_t *out) {
    lm::idf::take_restart_record();
    if (out == nullptr || lm::idf::g_restart_seen.magic != lm::idf::k_restart_magic) {
        return false;
    }
    out->cause = lm::idf::g_restart_seen.cause;
    out->uptime_ms = lm::idf::g_restart_seen.uptime_ms;
    out->detail = lm::idf::g_restart_seen.detail;
    out->recovery = lm::idf::g_restart_seen.recovery;
    return true;
}

extern "C" void lm_idf_record_radio_recovery(uint32_t reason, lm_status_t status, uint64_t tx, uint64_t rx) {
    using namespace lm::idf;
    take_restart_record();
    portENTER_CRITICAL(&g_recovery_lock);
    g_recovery = lm_idf_recovery_t{static_cast<uint32_t>(esp_timer_get_time() / 1000), reason,
                                  static_cast<uint32_t>(status), g_recovery.attempts == UINT32_MAX ? UINT32_MAX : g_recovery.attempts + 1,
                                  static_cast<uint32_t>(tx), static_cast<uint32_t>(rx), false};
    portEXIT_CRITICAL(&g_recovery_lock);
}

extern "C" void lm_idf_finish_radio_recovery(lm_status_t status) {
    using namespace lm::idf;
    portENTER_CRITICAL(&g_recovery_lock);
    g_recovery.status = static_cast<uint32_t>(status);
    portEXIT_CRITICAL(&g_recovery_lock);
}

extern "C" bool lm_idf_last_radio_recovery(lm_idf_recovery_t *out) {
    using namespace lm::idf;
    if (out == nullptr) return false;
    take_restart_record();
    portENTER_CRITICAL(&g_recovery_lock);
    *out = g_recovery;
    portEXIT_CRITICAL(&g_recovery_lock);
    return out->attempts != 0;
}

extern "C" void lm_idf_restart_radio_recovery(void) {
    lm_idf_recovery_t recovery{};
    (void)lm_idf_last_radio_recovery(&recovery);
    lm::idf::controlled_restart(LM_IDF_RESTART_RADIO_RECOVERY, recovery.reason);
}

extern "C" void lm_idf_radio_stats(lm_idf_radio_stats_t *out) {
    if (out == nullptr) {
        return;
    }
    out->tx_done_max_ms = lm::idf::g_tx_done_max_ms.load();
    out->tx_late = lm::idf::g_tx_late.load();
    out->tx_stall_waits = lm::idf::g_tx_stall_waits.load();
}
