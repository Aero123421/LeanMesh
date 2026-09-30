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
// One driver instance per device. stop() with a TX whose callback is overdue (>= the 1000 ms owner
// watchdog) cannot prove the old callback is gone; then the port does a controlled reboot, which is
// the specified fall-back when the driver cannot be drained (docs/03 §4). Fresh session after boot.
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
    void hold_rx() override { rx_held_.store(true); }
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
    port::TxToken pending_token_;
    uint64_t tx_started_us_ = 0;
    SpscRing<port::RadioRx, k_rx_ring> rx_ring_;
    SpscRing<port::RadioTxDone, 2> done_ring_;
};

} // namespace lm::idf
