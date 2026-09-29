#include "port/idf/idf_radio.hpp"

#include <cstring>

#include "esp_event.h"
#include "esp_now.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "port/idf/idf_owner.hpp"
#include "soc/soc_caps.h"

namespace lm::idf {

namespace {

IdfRadio *g_radio = nullptr; // the one driver instance; set before the callbacks are registered

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

Status IdfRadio::bring_up_wifi(const port::RfProfile &profile) {
    if (wifi_ready_) {
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
    wifi_ready_ = true;
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
    LM_TRY(bring_up_wifi(profile));
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
        (void)esp_now_deinit();
        return Status::RecoveryRequired;
    }
    now_ready_ = true;
    return Status::Ok;
}

Status IdfRadio::stop() {
    if (!now_ready_) {
        return Status::Ok;
    }
    const bool overdue =
        in_flight_.load() && static_cast<uint64_t>(esp_timer_get_time()) - tx_started_us_ >=
                                 static_cast<uint64_t>(TxManager::k_watchdog.us);
    if (overdue) {
        esp_restart(); // callback drain cannot be proven: controlled reboot (docs/03 §4)
    }
    now_ready_ = false;
    const esp_err_t e = esp_now_deinit();
    // Callbacks stop with deinit; anything still queued is discarded by the generation check.
    port::RadioRx rx;
    while (rx_ring_.pop(rx)) {
    }
    return e == ESP_OK ? Status::Ok : Status::RecoveryRequired;
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
    tx_started_us_ = static_cast<uint64_t>(esp_timer_get_time());
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

void IdfRadio::on_recv(const uint8_t *src, const uint8_t *dst, int8_t rssi, const uint8_t *data,
                       int len) {
    if (len <= 0 || static_cast<std::size_t>(len) > port::k_max_frame_bytes) {
        return; // not a frame this SDK can have produced (250 B self-limit)
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
    in_flight_.store(false);
    (void)done_ring_.push(done);
    owner_.notify();
}

} // namespace lm::idf
