// The node's one frame pool (P9, ADR-002). A slot holds one RF frame (<= 250 B) plus 32 B of
// scheduling metadata (P7). It is used three ways, always through a generation handle:
//   queued frame  reserve(): sealed once, then owned by HopTx (link retry, HOP_ACK) until it ends.
//                 Its class tag is the scheduler's queue: there is no second queue.
//   borrowed      borrow(): plain memory a module needs for a while (the HOP_ACK seal buffer, the
//                 delivery build scratch, the exchange's staged object, the join pipe's staging,
//                 later the power mailboxes). Never sent, never scheduled; the borrower releases it.
// Admission (S14-D4): a class may take a slot only while fewer than limit(class) slots are in use, so
// BULK cannot fill the pool, CONTROL always finds room, and the last slot is left to a HOP_ACK seal
// buffer or another borrower (two full pools waiting for each other's ACKs cannot deadlock); a single
// next hop holds at most three quarters of the slots so one dead peer cannot pin the pool.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/codec.hpp"
#include "core/ids.hpp"
#include "core/pool.hpp"
#include "core/profile.hpp"
#include "core/sched/sched.hpp"
#include "core/time.hpp"
#include "core/wire/frame.hpp"

namespace lm {

// One RF frame: the link counter (nonce) of a sealed frame is read from its header.
struct FrameBuf {
    std::array<uint8_t, wire::k_max_frame_bytes> bytes{};
    uint16_t len = 0;
    [[nodiscard]] ByteView view() const { return ByteView{bytes.data(), len}; }
    [[nodiscard]] uint64_t counter() const {
        if (len < wire::k_link_header_bytes) {
            return 0;
        }
        Reader r{ByteView{bytes.data() + wire::layout::link::link_counter_offset, 8}};
        return r.u64be();
    }
};

enum class OwnerKind : uint8_t { None, Out, Receipt, Forward, Exchange, Borrowed, Mesh, Tunnel }; // [S11] Mesh: control record; Tunnel: join proxy chunk

struct TxFrame {
    enum class St : uint8_t { Reserved, Ready, OnAir, WaitAck };
    enum Flag : uint8_t {
        Abandoned = 1, // no more retransmissions (cancel after the frame left)
        Left = 2,      // handed to the radio at least once (it may have arrived)
        AfterBusy = 4, // the next handoff repeats a frame the peer deferred (not an attempt)
    };
    // ---- 32 B of metadata ----
    MonoTime at = MonoTime::never(); // Ready: not before; WaitAck: RTO expiry; else never
    uint32_t owner_gen = 0;
    MacAddr mac;
    uint16_t owner_index = 0;
    uint16_t air_seq = 0;
    uint16_t order = 0;       // FIFO among ready frames (wrap-safe compare)
    uint16_t handoff_ms = 0;  // low 16 bits of the handoff time in ms: RTT samples only
    St st = St::Reserved;
    OwnerKind kind = OwnerKind::None;
    sched::Class cls = sched::Class::Normal;
    uint8_t attempts = 0;     // physical handoffs so far
    uint8_t busy_defers = 0;  // HOP_ACK BUSY answers
    uint8_t flags = 0;
    // ---- 12 B: the end record's deadline of a FORWARDED frame (FIX4-D1). The relay cannot open the record, so it
    // keeps the authenticated header's expiry and the route's term beside the sealed bytes and checks them before
    // every hand-off and retry; the bytes themselves are never re-encrypted. 0 = no deadline.
    uint64_t expires_root_ms = 0;
    uint32_t term = 0;
    FrameBuf frame;

    [[nodiscard]] Handle owner() const { return Handle{owner_index, owner_gen}; }
    void set_owner(Handle h) {
        owner_index = h.index;
        owner_gen = h.generation;
    }
    [[nodiscard]] bool has(Flag f) const { return (flags & f) != 0; }
    void set(Flag f, bool on = true) { flags = static_cast<uint8_t>(on ? (flags | f) : (flags & ~f)); }
};
static_assert(offsetof(TxFrame, frame) == 44, "TX frame metadata is 32 bytes (P7) + the 12 B forward deadline (FIX4-D1)");

class TxPool {
  public:
    static constexpr std::size_t k_frames = k_build_limits.tx_frames;
    static_assert(k_frames >= 4, "profile tx_frames");

    // In-use slots below which a class may still take one.
    [[nodiscard]] static constexpr std::size_t limit(sched::Class c) {
        switch (c) {
        case sched::Class::Bulk:
            return k_frames / 2;
        case sched::Class::Normal:
            return k_frames * 5 / 8;
        case sched::Class::Urgent:
            return k_frames - 2;
        case sched::Class::Control:
            break;
        }
        return k_frames - 1;
    }
    static constexpr std::size_t k_peer_max = k_frames * 3 / 4;

    // A queued frame of class `c` for next hop `mac`. nullptr: refused (class limit, per-peer cap or
    // pool full): a local shortage, never RF loss.
    [[nodiscard]] TxFrame *reserve(Handle &h, sched::Class c, const MacAddr &mac) {
        if (c != sched::Class::Control) {
            std::size_t same = 0;
            frames_.for_each([&](Handle, TxFrame &f) { same += (f.kind != OwnerKind::Borrowed && f.mac == mac) ? 1U : 0U; });
            if (same >= k_peer_max) {
                return nullptr;
            }
        }
        if (frames_.in_use() >= limit(c)) {
            return nullptr;
        }
        return take(h, OwnerKind::None, c, mac);
    }
    // Plain memory for a module; the caller releases it. nullptr only when every slot is in use.
    [[nodiscard]] TxFrame *borrow(Handle &h) { return take(h, OwnerKind::Borrowed, sched::Class::Control, MacAddr{}); }
    bool release(Handle h) { return frames_.release(h); }
    [[nodiscard]] TxFrame *get(Handle h) { return frames_.get(h); }
    [[nodiscard]] Pool<TxFrame, k_frames> &slots() { return frames_; }
    [[nodiscard]] const Pool<TxFrame, k_frames> &slots() const { return frames_; }
    [[nodiscard]] std::size_t in_use() const { return frames_.in_use(); }
    // Node stop: every owner has released its frames; whatever is left is a leak and is reclaimed.
    void clear() {
        for (std::size_t i = 0; i < k_frames; ++i) {
            (void)frames_.release(frames_.handle_at(i));
        }
    }

  private:
    [[nodiscard]] TxFrame *take(Handle &h, OwnerKind kind, sched::Class c, const MacAddr &mac) {
        h = frames_.acquire();
        TxFrame *f = h.is_none() ? nullptr : frames_.get(h);
        if (f != nullptr) {
            f->kind = kind;
            f->cls = c;
            f->mac = mac;
            f->expires_root_ms = 0;
            f->term = 0;
        }
        return f;
    }
    Pool<TxFrame, k_frames> frames_;
};

// A pool frame borrowed for the lifetime of the object (RAII). Empty when the pool had no room.
class Lease {
  public:
    Lease() = default;
    explicit Lease(TxPool &pool) : pool_(&pool), f_(pool.borrow(h_)) {}
    Lease(const Lease &) = delete;
    Lease &operator=(const Lease &) = delete;
    ~Lease() {
        if (f_ != nullptr) {
            (void)pool_->release(h_);
        }
    }
    [[nodiscard]] bool ok() const { return f_ != nullptr; }
    [[nodiscard]] FrameBuf &buf() { return f_->frame; }
    [[nodiscard]] uint8_t *data() { return f_->frame.bytes.data(); }
    [[nodiscard]] static constexpr std::size_t size() { return wire::k_max_frame_bytes; }

  private:
    TxPool *pool_ = nullptr;
    Handle h_;
    TxFrame *f_ = nullptr;
};

} // namespace lm
