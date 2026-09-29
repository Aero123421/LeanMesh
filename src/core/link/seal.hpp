// Sealing and opening of one link frame under a session (docs/09 §2):
//   frame = header24 || AES-GCM(key, prefix || counter, body, AAD = header24 || ctx_hash) || tag16
// Owner-side and symmetric only (one short AEAD call). Authorisation decisions stay with the
// caller: open_frame() never advances the replay window (LinkLayer calls accept() after its own
// checks, docs/06 §6).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/link/neighbors.hpp"
#include "core/wire/frame.hpp"

namespace lm::link {

// One ready-to-transmit frame. A retransmission sends these very bytes: the counter (nonce) of
// a sealed frame is never reused for a different ciphertext (docs/06 §6).
struct SealedFrame {
    std::array<uint8_t, wire::k_max_frame_bytes> bytes{};
    uint16_t len = 0;
    uint64_t counter = 0;
    [[nodiscard]] ByteView view() const { return ByteView{bytes.data(), len}; }
};

// `header_sid` is what goes into the link header: the peer-assigned SID for normal frames, the
// sender's own reserved SID for the two SESSION_BIND frames (docs/IMPLEMENTATION.md S5-D3).
// Consumes one counter even when sealing fails. The produced frame is re-decoded, so a frame the
// receiver's strict decoder would reject (wrong HOP_ACK length ...) is never emitted.
[[nodiscard]] Status seal_frame(SessionKeys &k, wire::FrameKind kind, uint32_t domain_hint,
                                uint32_t header_sid, ByteView plain, SealedFrame &out);

struct Opened {
    std::array<uint8_t, wire::k_max_frame_bytes> plain{};
    std::size_t len = 0;
    sec::ReplayVerdict verdict = sec::ReplayVerdict::Fresh;
    [[nodiscard]] ByteView view() const { return ByteView{plain.data(), len}; }
};

// Ok: fresh and authentic. Replay: verdict Duplicate (authentic, plaintext valid) or TooOld.
// AuthRejected: tag mismatch. The window is untouched in every case.
[[nodiscard]] Status open_frame(SessionKeys &k, const wire::LinkHeader &h, ByteView frame,
                                Opened &out);

[[nodiscard]] inline uint32_t domain_hint_of(const DomainId &d) {
    return (uint32_t{d.bytes[0]} << 24U) | (uint32_t{d.bytes[1]} << 16U) |
           (uint32_t{d.bytes[2]} << 8U) | uint32_t{d.bytes[3]};
}

} // namespace lm::link
