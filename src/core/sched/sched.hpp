// Transmit scheduler (docs/08 §8): which class may put its next frame on the air, and what a frame
// costs. Owner thread only; pure state, no queue of its own (the queued frames are TX-pool frames
// that carry a class tag, radio/tx_pool.hpp).
//
//   DRR       four classes, quantum = weight * k_quantum_us of airtime, weights 4:8:4:1
//             (CONTROL, URGENT, NORMAL, BULK; config/defaults.json scheduler.drr_weights).
//   reserve   CONTROL is entitled to 20 % of every 100 ms window (20 ms of airtime): until it has used
//             that much of the window, a ready control frame goes next whatever the bucket says, and
//             after two URGENT frames in a row a ready control frame is looked at before a third
//             (S14-D2). Beyond the entitlement CONTROL competes like the other classes.
//   tokens    one airtime bucket for everything that is sent (data, control, retries, HOP_ACKs):
//             refill 300 ms/s, burst 600 ms. URGENT and CONTROL may borrow up to the urgent debt
//             (100 ms, repaid by the refill). Sending is never gated for a HOP_ACK (it frees the
//             sender's buffer) or for the control reserve: they are charged, so the debt shows.
//
// The airtime of a frame is an estimate (PHY bits at the assumed rate plus a per-frame overhead);
// the overhead constants are unmeasured defaults until the RF qualification measures them.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/time.hpp"
#include "core/wire/frame.hpp"
#include "gen/defaults.hpp"

namespace lm::sched {

// Index order = the order of config drr_weights.
enum class Class : uint8_t { Control = 0, Urgent = 1, Normal = 2, Bulk = 3 };
inline constexpr std::size_t k_classes = 4;

[[nodiscard]] constexpr Class class_of(wire::Priority p) {
    switch (p) {
    case wire::Priority::Control:
        return Class::Control;
    case wire::Priority::Urgent:
        return Class::Urgent;
    case wire::Priority::Normal:
        return Class::Normal;
    case wire::Priority::Bulk:
        return Class::Bulk;
    }
    return Class::Normal;
}

// Airtime estimate: (frame + 802.11/ESP-NOW overhead) at 250 kbit/s plus preamble/SIFS/MAC-ACK.
inline constexpr int64_t k_phy_us_per_byte = 32;   // 8 bit / 250 kbit/s
inline constexpr int64_t k_frame_overhead_bytes = 43;
inline constexpr int64_t k_mac_overhead_us = 600;
[[nodiscard]] constexpr int64_t airtime_us(std::size_t frame_bytes) {
    return (static_cast<int64_t>(frame_bytes) + k_frame_overhead_bytes) * k_phy_us_per_byte + k_mac_overhead_us;
}

inline constexpr int64_t k_quantum_us = 2500;
inline constexpr int64_t k_window_us = 100'000;
inline constexpr int64_t k_reserve_percent = 20;
inline constexpr unsigned k_urgent_run = 2;
inline constexpr int64_t k_burst_us = static_cast<int64_t>(gen::defaults::scheduler::airtime_burst_ms) * 1000;
inline constexpr int64_t k_urgent_debt_us = static_cast<int64_t>(gen::defaults::scheduler::urgent_debt_ms) * 1000;
inline constexpr int64_t k_rate_ms_per_s = static_cast<int64_t>(gen::defaults::scheduler::airtime_ms_per_second);

struct ClassStats {
    uint32_t frames = 0;
    uint32_t refused = 0; // admission refusals of this class (TX pool or operation slots)
    uint64_t airtime_us = 0;
};

struct Stats {
    std::array<ClassStats, k_classes> cls{};
    uint32_t reserve_picks = 0;   // CONTROL taken ahead of the DRR order (20 % window entitlement)
    uint32_t urgent_yields = 0;   // CONTROL looked at after two URGENT frames in a row
    uint32_t token_waits = 0;     // a ready frame waited for airtime tokens
    uint64_t ack_charged_us = 0;  // HOP_ACK/handshake airtime charged without gating
};

class Scheduler {
  public:
    // `head_bytes[c]` = length of the oldest ready frame of class c (0: none). True: `out` may
    // send now (call charge() when it did). False: nothing may go before `wake` (never() when no
    // class has a ready frame).
    [[nodiscard]] bool pick(const std::array<uint16_t, k_classes> &head_bytes, MonoTime now, Class &out,
                            MonoTime &wake);
    // A frame of `bytes` went to the radio: every transmission of the node is charged to the token
    // bucket. `queued` = it came out of pick() (counts in the 100 ms window entitlement and the DRR
    // deficit); HOP_ACKs and handshake frames are charged with queued = false (never gated).
    void charge(Class c, std::size_t bytes, MonoTime now, bool queued);
    void note_refused(Class c) { ++stats_.cls[static_cast<std::size_t>(c)].refused; }
    // [S17] Planned off-channel time (channel switch guard, survey visit): no frame of a data class is
    // picked before `t`; CONTROL keeps flowing. The queued frames wait, they are not lost or aborted.
    void hold_until(MonoTime t) { hold_until_ = t; }
    [[nodiscard]] const Stats &stats() const { return stats_; }
    [[nodiscard]] int64_t tokens_us(MonoTime now);

  private:
    void refill(MonoTime now);
    void roll_window(MonoTime now);
    [[nodiscard]] bool allowed(Class c, int64_t cost) const;
    [[nodiscard]] bool control_due() const { return win_ctrl_us_ < k_window_us * k_reserve_percent / 100; }

    Stats stats_;
    MonoTime hold_until_{};
    std::array<int32_t, k_classes> deficit_{};
    int64_t tokens_ = k_burst_us;
    MonoTime tokens_at_;
    MonoTime win_start_;
    int32_t win_ctrl_us_ = 0; // airtime CONTROL used in this window
    uint8_t rr_ = 0;
    uint8_t urgent_run_ = 0;
    Class last_ = Class::Control; // class of the last DRR pick whose frame is not charged yet
    bool drr_pending_ = false;
};

} // namespace lm::sched
