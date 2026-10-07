// ESP-IDF Radio port: ESP-NOW over Wi-Fi STA without an AP, LR 250 kbit/s on every peer (docs/03).
//
// Init order (docs/03 §3): netif/event loop -> Wi-Fi init (RAM storage, once) -> STA -> country, HT20,
// protocol incl. LR -> Wi-Fi start -> channel + tx power with readback -> ESP-NOW init -> callbacks.
// stop() is the reverse: ESP-NOW deinit, then esp_wifi_stop - only then is the radio off (FIX10-D10); the next start()
// applies country, bandwidth, protocol, channel and power again and the owner re-registers the peers.
// Peers get the LR250 rate config right after registration; a peer that cannot be switched to LR is
// removed again and reported (no silent fall-back to 1 Mbit/s).
//
// Driver callbacks (Wi-Fi task) only copy into fixed rings and notify the owner. RX frames and the
// single TX completion use separate rings, so RX overload can never lose the TX-done.
//
// One driver instance per device. The owner watchdog (TxManager::k_watchdog, 3000 ms) lies beyond every completion
// the driver was seen to deliver (slowest 1.02-1.06 s, HIL 2026-10-04; a 1000 ms watchdog restarted healthy radios
// in a chain through the mesh). stop() with a TX whose callback is overdue first waits up to k_drain_wait more for
// that callback: its arrival proves the drain; only when it never comes does the port do the controlled reboot,
// the specified fall-back when the driver cannot be drained (docs/03 §4), and it records why in RTC memory
// (lm_idf_last_restart). Fresh session after boot. The Wi-Fi power save is off (ESP-NOW must hear and send
// at any time: an always-on node is ALWAYS_RX, a sleeping one stops the radio instead).
#pragma once

#include <atomic>

#include "core/engine.hpp"
#include "core/ports.hpp"
#include "core/profile.hpp"
#include "core/ring.hpp"


namespace lm::idf {

class IdfOwner;

class IdfRadio final : public port::Radio {
  public:
    void hold_rx() override;
    void release_rx() override { rx_held_.store(false); }
    // RX ring: profile rx_frames plus two (leaf 10, relay 14, root 26 frames).
    static constexpr std::size_t k_rx_ring = k_build_limits.rx_frames + 2;

    explicit IdfRadio(IdfOwner &owner) : owner_(owner) {}

    [[nodiscard]] Status start(const port::RfProfile &profile) override;
    [[nodiscard]] Status stop() override;
    [[nodiscard]] Status set_channel(uint8_t channel) override;
    [[nodiscard]] Status add_peer(const MacAddr &mac) override;
    [[nodiscard]] Status remove_peer(const MacAddr &mac) override;
    [[nodiscard]] Status transmit(const MacAddr &dst, ByteView frame, port::TxToken token) override;
    [[nodiscard]] bool poll(port::RadioEvent &out) override;
    [[nodiscard]] uint32_t driver_generation() const override { return generation_; }

    // A late TX completion is waited for this long after the watchdog before the controlled reboot.
    static constexpr Duration k_drain_wait = Duration::from_ms(2000);
    // Field diagnostics only (lm_idf_radio_stats tx_late): a completion at least this slow. Fixed, apart from the
    // watchdog, so the field log keeps showing the ~1.05 s completions that once tripped the old 1000 ms watchdog.
    static constexpr uint32_t k_tx_slow_ms = 1000;

    [[nodiscard]] uint32_t rx_dropped() const { return rx_ring_.dropped(); }
    [[nodiscard]] uint32_t rx_depth() const { return rx_ring_.depth(); } // [S19]

    // Driver callback bodies (public for the C trampolines in idf_radio.cpp only).
    void on_recv(const uint8_t *src, const uint8_t *dst, int8_t rssi, const uint8_t *data, int len);
    void on_sent(bool success);

  private:
    [[nodiscard]] Status init_wifi();                                     // once: driver init, RAM storage, STA, band
    [[nodiscard]] Status start_wifi(const port::RfProfile &profile);      // every start: country, HT20, protocol incl. LR, start
    [[nodiscard]] Status apply_channel_and_power(uint8_t channel, int16_t tx_qdbm);

    IdfOwner &owner_;
    bool wifi_inited_ = false;  // esp_wifi_init done (kept across radio-off periods)
    bool wifi_running_ = false; // esp_wifi_start done and not yet stopped: only false means the radio is really off
    bool now_ready_ = false;
    uint16_t allowed_mask_ = 0;
    int16_t tx_power_qdbm_ = 0;
    uint32_t generation_ = 0;
    std::atomic<bool> in_flight_{false};
    std::atomic<bool> rx_held_{false}; // sleep entry: the recv callback queues nothing more (FIX13-D3)
    // Callbacks between entry and return. hold_rx() waits for it to reach 0, so a callback that passed
    // the rx_held_ check before the hold was set has pushed its frame before the owner's final poll.
    std::atomic<uint8_t> rx_in_cb_{0};
    port::TxToken pending_token_;
    std::atomic<uint64_t> tx_started_us_{0}; // (read by the send callback for the completion time)
    SpscRing<port::RadioRx, k_rx_ring> rx_ring_;
    SpscRing<port::RadioTxDone, 2> done_ring_;
};

} // namespace lm::idf
