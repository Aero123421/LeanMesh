// Simulation implementations of the Clock, Radio and Jobs ports plus the direct owner call.
// Each SimNode owns one instance of each. They obey the same contracts as the IDF ports
// (non-blocking, bounded, one TX in flight, local errors distinct from RF failures).
#pragma once

#include <array>
#include <cstdint>

#include "core/command.hpp"
#include "core/ports.hpp"
#include "core/ring.hpp"

namespace lm::sim {

class World;
class SimNode;

class SimClock final : public port::Clock {
  public:
    SimClock(const World &world, int32_t drift_ppm) : world_(world), drift_ppm_(drift_ppm) {}
    [[nodiscard]] MonoTime now() const override;
    // Local monotonic time restarts at 0 on every boot (power cycle).
    void on_boot(uint64_t world_us) { boot_world_us_ = world_us; }

  private:
    const World &world_;
    int32_t drift_ppm_;
    uint64_t boot_world_us_ = 0;
};

class SimRadio final : public port::Radio {
  public:
    static constexpr std::size_t k_rx_ring = 16;
    static constexpr std::size_t k_max_peers = 20; // 16 regular + 3 transient + 1 broadcast

    SimRadio(World &world, uint16_t node, const MacAddr &mac)
        : world_(world), node_(node), mac_(mac) {}

    [[nodiscard]] Status start(const port::RfProfile &profile) override;
    [[nodiscard]] Status stop() override;
    [[nodiscard]] Status set_channel(uint8_t channel) override;
    [[nodiscard]] Status add_peer(const MacAddr &mac) override;
    [[nodiscard]] Status remove_peer(const MacAddr &mac) override;
    [[nodiscard]] Status transmit(const MacAddr &dst, ByteView frame, port::TxToken token) override;
    [[nodiscard]] bool poll(port::RadioEvent &out) override;
    [[nodiscard]] uint32_t driver_generation() const override { return driver_generation_; }

    // --- world side ---
    [[nodiscard]] const MacAddr &mac() const { return mac_; }
    [[nodiscard]] bool receiving() const { return on_; }
    [[nodiscard]] uint8_t channel() const { return channel_; }
    void deliver(const port::RadioEvent &ev); // RX or TX-done from the medium
    void power_cut();
    [[nodiscard]] uint32_t rx_dropped() const { return ring_.dropped(); }
    [[nodiscard]] std::size_t peer_count() const { return peer_count_; }
    [[nodiscard]] std::size_t peak_peer_count() const { return peak_peers_; }
    [[nodiscard]] uint32_t tx_done_dropped() const { return done_ring_.dropped(); }

    // --- fault injection (test bench only) ---
    // Extra delay before this node's TX-done callback (models a slow Wi-Fi task, docs/03 §4).
    uint32_t tx_callback_delay_us = 0;
    // The next `tx_fault_count` transmit() calls fail locally with `tx_fault` (Busy = driver BUSY,
    // NoCapacity = NO_MEM). No frame leaves the node and no TX-done follows: never RF loss.
    Status tx_fault = Status::Busy;
    uint32_t tx_fault_count = 0;
    // The next `start_fault_count` start() calls fail (driver re-initialisation problems).
    uint32_t start_fault_count = 0;
    // The next `stop_fault_count` stop() calls fail and leave the driver running (esp_now_deinit
    // error): callbacks may still be live.
    uint32_t stop_fault_count = 0;

  private:
    [[nodiscard]] bool has_peer(const MacAddr &mac) const;

    World &world_;
    uint16_t node_;
    MacAddr mac_;
    bool on_ = false;
    bool tx_in_flight_ = false;
    uint8_t channel_ = 0;
    uint16_t allowed_mask_ = 0;
    uint32_t driver_generation_ = 1;
    std::array<MacAddr, k_max_peers> peers_{};
    std::size_t peer_count_ = 0;
    std::size_t peak_peers_ = 0;
    // Like the IDF port: RX frames and the (single) TX completion travel in separate rings so a
    // burst of RX can never push the TX-done out.
    SpscRing<port::RadioRx, k_rx_ring> ring_;
    SpscRing<port::RadioTxDone, 2> done_ring_;
};

class SimJobs final : public port::Jobs {
  public:
    static constexpr std::size_t k_queue = 4;

    SimJobs(World &world, uint16_t node, uint64_t seed)
        : world_(world), node_(node), rng_state_(seed | 1U) {}

    [[nodiscard]] Status submit(uint16_t table_index, uint32_t job_id, port::JobFn fn,
                                void *arg) override;
    [[nodiscard]] bool poll(port::JobCompletion &out) override;
    void random(MutByteView out) override;

    // --- world side ---
    void complete(const port::JobCompletion &c);
    void power_cut();
    void set_epoch(uint32_t epoch) { epoch_ = epoch; }
    // Virtual execution time of every job (models worker latency; late-completion tests raise it).
    uint32_t latency_us = 2000;

  private:
    World &world_;
    uint16_t node_;
    uint64_t rng_state_;
    uint32_t epoch_ = 0;
    std::size_t queued_ = 0;
    BoundedQueue<port::JobCompletion, k_queue> done_;
};

// Runs commands directly on the simulation thread (which is the node's owner thread).
class DirectOwnerCall final : public OwnerCall {
  public:
    explicit DirectOwnerCall(SimNode &node) : node_(node) {}
    [[nodiscard]] Reply call(const Command &cmd) override;

  private:
    SimNode &node_;
};

} // namespace lm::sim
