// Fragmentation and reassembly of end records (docs/09 §6): messages above one frame (up to 512 B),
// the optional 4096 B object, control objects and receipts that do not fit a frame. One mechanism:
// FRAGMENT records (kind 3) in 16 B quanta, answered by TRANSFER_BITMAP records (kind 5). The state
// is plain data owned by Delivery (`FragState`); the behaviour is `Delivery::on_end_fragment` and
// friends in fragment.cpp.
//
//   receiver  a bounded set of slots keyed by (end session, MessageId). Payloads live in the
//             message pool (small class), the one control buffer (receipts and control objects) or
//             the object buffer (only in builds with LM_OBJECT_TRANSFER). A slot is Free or
//             Filling; a full transfer is dispatched once and the slot is freed at once.
//   origin    the Active of the message: `acked` bitmap, a cursor, at most k_frag_window
//             unconfirmed fragments; a repeated round resends the first missing fragment.
//   receipts  fragments of a RECEIPT are sent once, without a bitmap: the origin's next E2E round
//             makes the destination send the newest receipt again (S12-D4).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/delivery/types.hpp"
#include "core/pool.hpp"
#include "core/profile.hpp"
#include "core/time.hpp"
#include "core/wire/transfer.hpp"

#ifndef LM_OBJECT_TRANSFER
#define LM_OBJECT_TRANSFER 0
#endif

namespace lm::delivery {

// The 4 KiB object lane exists only when the build asks for it (docs/09 §6 "optional object").
inline constexpr bool k_object_capable = LM_OBJECT_TRANSFER != 0;
inline constexpr std::size_t k_object_bytes = k_object_capable ? gen::limits::object_bytes : 0;
inline constexpr std::size_t k_control_bytes = 1024; // one control page (docs/09 §6 "1ページ1024B")
inline constexpr unsigned k_frag_window = static_cast<unsigned>(gen::defaults::delivery::fragment_window);
inline constexpr std::size_t k_small_slots = k_build_limits.small_reassembly;
inline constexpr std::size_t k_frag_slots = k_small_slots + 1 + (k_object_capable ? 1 : 0);
// Bitmap bytes needed by the largest transfer this build carries (1 KiB control = 8 B, object 32 B).
inline constexpr std::size_t k_bitmap_bytes = k_object_capable ? wire::k_bitmap_bytes : 8;
inline constexpr std::size_t k_control_done = 4; // control objects remembered after dispatch (dedup)
// A receipt with a 32 B result is at most 1 + 17 + 34 + 1 + 5 + 5 + 34 B of CBOR.
inline constexpr std::size_t k_receipt_max = 100;

// Where a message payload lives.
enum class Lane : uint8_t { Pool = 0, Control = 1, Object = 2 };

struct RxSlot {
    enum class St : uint8_t { Free, Filling };
    St st = St::Free;
    wire::ObjectClass cls = wire::ObjectClass::Small;
    wire::RecordKind kind = wire::RecordKind::Data;
    uint8_t flags = 0;   // end-header flags of the first fragment
    uint8_t unacked = 0; // new fragments since the last bitmap went out
    uint16_t total = 0;
    uint16_t port = 0;
    uint32_t sid = 0;    // the end session that owns it (our rx_sid) ...
    uint32_t epoch = 0;  // ... and which installation of it (a new session drops its transfers)
    uint32_t term = 0;
    uint32_t last_use = 0;
    uint64_t expires = 0;
    MonoTime until = MonoTime::never(); // never extended by later fragments
    std::array<uint8_t, 16> mid{};
    Sha256Digest hash{};
    Handle msg; // Pool lane only
    std::array<uint8_t, 8> have{};
};

// A dispatched control object (never dispatched twice). FIX4-D4: keyed by (origin, its assignment generation,
// MessageId, full hash) and kept until its own deadline passes (or its root term is over); a full table answers
// BUSY, it never evicts a live entry.
struct ControlDone {
    bool used = false;
    uint32_t term = 0;
    uint64_t assignment = 0;
    uint64_t expires = 0;
    DeviceId origin;
    std::array<uint8_t, 16> mid{};
    Sha256Digest hash{};
};

struct FragStats {
    uint64_t rx = 0;        // fragments accepted (new bytes)
    uint64_t rx_dup = 0;    // fragments that carried nothing new (answered with the bitmap)
    uint64_t rx_conflict = 0; // same offset, other bytes / other metadata: transfer discarded
    uint64_t rx_busy = 0;   // no slot / no buffer: BUSY, the sender waits
    uint64_t rx_refused = 0; // refused with a receipt (deadline, capacity, unsupported)
    uint64_t rx_expired = 0; // slots freed by their timeout
    uint64_t completed = 0; // transfers dispatched
    uint64_t tx = 0;        // fragments sealed by this node (messages, control objects, receipts)
    uint64_t bitmap_tx = 0;
    uint64_t bitmap_rx = 0;
    uint64_t control_rx = 0; // control objects dispatched
};

struct FragState {
    std::array<RxSlot, k_frag_slots> slots{};
    std::array<uint8_t, k_control_bytes> ctl_buf{};
    std::array<uint8_t, k_object_bytes> obj_buf{};
    std::array<uint8_t, k_object_bytes != 0 ? 32 : 1> obj_have{}; // the object slot's bitmap
    std::array<ControlDone, k_control_done> done{};
    std::array<uint8_t, k_receipt_max> receipt{}; // the receipt being cut into fragments (TX scratch is reused per frame)
    bool ctl_tx = false;   // the control buffer holds an outgoing control object
    bool obj_tx = false;   // the object buffer holds an outgoing object
    bool obj_held = false; // the object buffer holds a received object until the application takes it
    uint32_t tick = 0;
    // What the application-visible control sink gets (control objects that complete here).
    void *sink_ctx = nullptr;
    void (*sink)(void *ctx, const DeviceId &origin, const std::array<uint8_t, 16> &mid, ByteView payload,
                 MonoTime now) = nullptr;
    FragStats stats{};

    // In place: the state is several KiB, never built as a temporary on the owner stack.
    void reset() {
        for (RxSlot &s : slots) {
            s = RxSlot{};
        }
        for (ControlDone &d : done) {
            d = ControlDone{};
        }
        ctl_tx = obj_tx = obj_held = false;
    }
};

[[nodiscard]] inline bool bit_get(const uint8_t *bm, unsigned q) { return ((bm[q / 8U] >> (q % 8U)) & 1U) != 0; }
inline void bit_set(uint8_t *bm, unsigned q) { bm[q / 8U] = static_cast<uint8_t>(bm[q / 8U] | (1U << (q % 8U))); }
[[nodiscard]] inline unsigned quanta_of(std::size_t total) {
    return static_cast<unsigned>((total + wire::k_fragment_quantum - 1U) / wire::k_fragment_quantum);
}

// The control-object sink: called once per complete, authenticated control object.
using ControlSink = void (*)(void *ctx, const DeviceId &origin, const std::array<uint8_t, 16> &mid,
                             ByteView payload, MonoTime now);

// A control object to send to `dest` (S12; S15 groups and the policy/expected pages use it).
struct ControlSendRequest {
    DeviceId dest;
    uint32_t root_term = 0;
    uint64_t expires_root_ms = 0;
};

} // namespace lm::delivery
