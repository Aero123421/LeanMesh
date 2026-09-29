// One-hop reliability of routed frames (docs/08 §6, docs/09 §7): the TX frame pool, link retry with
// RTO, HOP_ACK matching and HOP_ACK generation. Owner thread only.
//
// A frame is sealed once (one link counter) and every retry sends the very same bytes, so a nonce
// is never reused for different content. The driver TX callback and the HOP_ACK are separate
// facts: an ACK that arrives before the callback is kept and applied when the callback comes
// (D10). Only a MAC failure counts as an RF-loss sample; Busy from the radio, a busy peer
// (HOP_ACK BUSY) and pool shortage are local/remote-capacity conditions: they defer a frame but
// never consume one of its three link attempts. Before the first send and before every retry the
// owner of the frame is asked whether the frame may still go out (deadline, cancel).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/link/seal.hpp"
#include "core/pool.hpp"
#include "core/profile.hpp"
#include "core/radio/tx_manager.hpp"
#include "core/ring.hpp"
#include "core/delivery/types.hpp"

namespace lm {
class Engine;
}
namespace lm::link {
class LinkLayer;
}

namespace lm::delivery {

enum class OwnerKind : uint8_t { None, Out, Receipt, Forward, Exchange };
enum class HopEnd : uint8_t {
    Accepted, // the next hop reserved a buffer
    Rejected, // the next hop refused (no route/session/capacity to forward)
    Failed,   // 3 attempts without HOP_ACK, or too many BUSY deferrals
    Aborted,  // the owner withdrew the frame before/at a retry (deadline, cancel)
};

struct TxFrame {
    enum class St : uint8_t { Reserved, Ready, OnAir, WaitAck };
    St st = St::Reserved;
    OwnerKind kind = OwnerKind::None;
    Handle owner;
    link::SealedFrame frame;
    MacAddr mac;
    uint16_t air_seq = 0;
    uint8_t attempts = 0;    // physical handoffs so far
    uint8_t busy_defers = 0; // HOP_ACK BUSY answers
    bool abandoned = false;  // no more retransmissions (cancel after the frame left)
    bool left = false;       // handed to the radio at least once (it may have arrived)
    bool after_busy = false; // the next handoff repeats a frame the peer deferred (not an attempt)
    uint32_t order = 0;      // FIFO among ready frames
    MonoTime not_before;
    MonoTime rto_at = MonoTime::never();
    MonoTime handoff_at;
};

// What the owner of a finished frame needs to know (the frame's bytes are not copied around).
struct FrameDone {
    OwnerKind kind = OwnerKind::None;
    Handle owner;
    MacAddr mac;
    uint8_t attempts = 0;
    bool left = false; // handed to the radio at least once
    uint64_t counter = 0;
};

struct HopStats {
    uint64_t frames = 0;         // handoffs to the radio (first sends and retransmissions)
    uint64_t retransmits = 0;    // repeats after a missing HOP_ACK (each used one of the 3 attempts)
    uint64_t busy_resends = 0;   // repeats after the peer said BUSY (no attempt used)
    uint64_t rf_failed = 0;      // MacFailed samples (the only RF-loss evidence)
    uint64_t tx_unknown = 0;     // driver result unknown: neither loss nor success
    uint64_t local_busy = 0;     // radio Busy/isolated at handoff: local, never loss
    uint64_t ack_busy = 0;       // peer answered BUSY (its capacity, not RF loss)
    uint64_t ack_rejected = 0;
    uint64_t early_acks = 0;     // HOP_ACK seen before the TX callback (D10)
    uint64_t ack_unmatched = 0;
    uint64_t aborted = 0;        // withdrawn by the owner at (re)send time
    uint64_t acks_sent = 0;
    uint64_t acks_dropped = 0;   // ACK queue full: the sender retries (never a silent accept)
};

class HopTx {
  public:
    static constexpr std::size_t k_frames = k_build_limits.tx_frames;
    static constexpr std::size_t k_acks = 4;
    static constexpr uint8_t k_max_busy_defers = 16;
    static constexpr uint32_t k_tag_frame = 0x44540000; // "DT"
    static constexpr uint32_t k_tag_ack = 0x44410000;   // "DA"
    [[nodiscard]] static bool is_hop_tag(uint32_t tag) {
        return (tag & 0xFFFF0000U) == k_tag_frame || (tag & 0xFFFF0000U) == k_tag_ack;
    }

    struct Hooks {
        void *ctx = nullptr;
        // Ok = go ahead. Anything else withdraws the frame (reported as Aborted).
        Status (*may_send)(void *ctx, const TxFrame &f, MonoTime now) = nullptr;
        void (*done)(void *ctx, const FrameDone &f, HopEnd end, MonoTime now) = nullptr;
    };

    HopTx(Engine &engine, link::LinkLayer &link) : engine_(engine), link_(link) {}
    void set_hooks(const Hooks &h) { hooks_ = h; }

    // Reserves a pool entry to seal into (Reserved: never sent until submit()). None = full.
    [[nodiscard]] TxFrame *reserve(Handle &h);
    void release(Handle h) { (void)frames_.release(h); }
    // The frame in `h` is sealed: queue it for `mac` and try to send.
    void submit(Handle h, OwnerKind kind, Handle owner, const MacAddr &mac, MonoTime now);
    [[nodiscard]] std::size_t free_frames() const { return k_frames - frames_.in_use(); }

    // HOP_ACK for a DATA frame received from `peer` (answered under that peer's link session).
    void queue_ack(const MacAddr &mac, const DeviceId &peer, uint64_t counter, wire::HopAckStatus st,
                   uint16_t retry_after_ms, MonoTime now);
    // A decoded HOP_ACK that arrived from `src`. False: it matches no frame of ours.
    bool on_ack(const MacAddr &src, const wire::HopAck &ack, MonoTime now);
    void on_tx_outcome(const TxOutcome &o, MonoTime now);
    void on_timer(MonoTime now);
    [[nodiscard]] MonoTime deadline() const;
    void pump(MonoTime now);

    // True when a frame of this owner was handed to the radio at least once (it may have left).
    [[nodiscard]] bool has_left(OwnerKind kind, Handle owner) const;
    // Removes the owner's frames that never left; the ones that did stop being retransmitted and
    // are dropped when they are acknowledged or time out. Returns true when nothing had left.
    bool withdraw(OwnerKind kind, Handle owner);
    void clear();

    [[nodiscard]] const HopStats &stats() const { return stats_; }
    [[nodiscard]] Duration rto() const { return rto_; }
    [[nodiscard]] std::size_t in_use() const { return frames_.in_use(); }

  private:
    struct PendingAck {
        MacAddr mac;
        DeviceId peer;
        uint64_t counter = 0;
        wire::HopAckStatus status = wire::HopAckStatus::Accepted;
        uint16_t retry_after_ms = 0;
    };

    [[nodiscard]] Duration rto_for(uint8_t attempts) const;
    void finish(Handle h, TxFrame &f, HopEnd end, MonoTime now);
    void apply_ack(Handle h, TxFrame &f, wire::HopAckStatus st, uint16_t retry_after_ms, MonoTime now);
    void pump_once(MonoTime now, bool &sent, bool &progress);
    void rtt_sample(Duration r);

    Engine &engine_;
    link::LinkLayer &link_;
    Hooks hooks_;
    Pool<TxFrame, k_frames> frames_;
    BoundedQueue<PendingAck, k_acks> acks_;
    link::SealedFrame ack_buf_; // the HOP_ACK being sealed (keeps 264 B off the owner stack)
    HopStats stats_;
    Duration rto_ = Duration::from_ms(static_cast<int64_t>(gen::defaults::delivery::rto_initial_ms));
    int64_t srtt_us_ = 0;
    int64_t rttvar_us_ = 0;
    bool rtt_valid_ = false;
    uint32_t order_ = 0;
    uint16_t air_seq_ = 0;
    uint16_t ack_seq_ = 0;
    MonoTime retry_at_ = MonoTime::never();
    MonoTime now_;
    bool in_pump_ = false;
    bool pump_again_ = false;
};

} // namespace lm::delivery
