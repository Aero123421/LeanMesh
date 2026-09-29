// Delivery vocabulary shared by the end-to-end modules (docs/08). Evidence, phase and outcome are
// separate facts: accepted, persisted, sent, HOP_ACCEPTED, END_RECEIVED and APP_APPLIED are never
// inferred from one another (AGENTS.md).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/ids.hpp"
#include "core/status.hpp"
#include "core/time.hpp"
#include "core/wire/frame.hpp"
#include "gen/defaults.hpp"
#include "gen/registry.hpp"
#include "leanmesh.h"

namespace lm::delivery {

inline constexpr std::size_t k_msg_bytes = gen::limits::small_message_bytes; // 512
inline constexpr std::size_t k_result_bytes = LM_MAX_APP_RESULT_BYTES;      // 32
// Reserved end_sid of the unauthenticated end-handshake carrier (S9-D2). No session gets it.
inline constexpr uint32_t k_handshake_sid = 0xFFFFFFFFU;

inline constexpr uint8_t k_link_attempts = static_cast<uint8_t>(gen::defaults::delivery::link_attempts);
inline constexpr uint8_t k_e2e_rounds = static_cast<uint8_t>(gen::defaults::delivery::e2e_rounds);

// lm_operation_t.evidence_bits (S9-D5): what was actually observed. Bits are only ever added.
namespace ev {
inline constexpr uint32_t accepted = 1U << 0;      // the API accepted the request (RAM only)
inline constexpr uint32_t persisted = 1U << 1;     // origin journal commit
inline constexpr uint32_t sent = 1U << 2;          // handed to the radio at least once (may have left)
inline constexpr uint32_t hop_accepted = 1U << 3;  // the first hop reserved a buffer (HOP_ACK)
inline constexpr uint32_t end_received = 1U << 4;  // destination receipt: stored as declared
inline constexpr uint32_t app_pending = 1U << 5;   // destination application acknowledged, no result yet
inline constexpr uint32_t app_applied = 1U << 6;   // APP_APPLIED by the destination application
inline constexpr uint32_t app_rejected = 1U << 7;  // the destination application refused it
inline constexpr uint32_t refused = 1U << 8;       // the destination network layer refused it
} // namespace ev

// lm_operation_t.phase (matches the Host operation states).
enum class Phase : uint8_t { Pending = 0, Sending = 1, WaitingReceipt = 2, Final = 3 };

// delivery-receipt `evidence` (control.cddl 0..6, S9-D5).
enum class ReceiptEv : uint8_t {
    EndReceived = 0,
    AppApplied = 1,
    AppRejected = 2,
    Refused = 3,      // reason carries the Status
    Expired = 4,
    Indeterminate = 5, // reserved: the destination cannot tell
    AppPending = 6,
};

// Fields of intent_hash (docs/08 §2). expires == 0 forces the effective root term to 0.
struct IntentFields {
    DeviceId origin;
    DeviceId target;
    DomainId domain;
    uint16_t app_port = 0;
    uint8_t delivery = 0; // LM_BEST_EFFORT/RECEIVED/APPLIED
    uint8_t storage = 0;  // LM_VOLATILE/LM_DURABLE
    uint8_t priority = 0;
    uint32_t root_term = 0; // term the message was sent under
    uint64_t expires_root_ms = 0;
    ByteView payload;
};
// SHA-256 over deterministic CBOR [origin, target, domain, port, delivery, storage, priority,
// effective_root_term, expires_root_ms, payload]. NoCapacity when the payload exceeds one frame
// (S12 extends it to reassembled messages).
[[nodiscard]] Status intent_hash(const IntentFields &f, Sha256Digest &out);

// delivery-receipt (control.cddl 25) as carried in a RECEIPT end record.
struct Receipt {
    std::array<uint8_t, 16> message_id{};
    Sha256Digest intent_hash{};
    ReceiptEv evidence = ReceiptEv::EndReceived;
    uint32_t reason = 0;
    uint32_t sequence = 0;
    std::array<uint8_t, k_result_bytes> result{};
    uint8_t result_len = 0;
};
[[nodiscard]] Status encode_receipt(const Receipt &r, MutByteView out, std::size_t &len);
[[nodiscard]] Status decode_receipt(ByteView in, Receipt &out);

// Time one end-to-end round (frame out, receipt back) may take over `hops` hops before the origin
// repeats it: queue budget + 2 * hops * per-hop allowance (docs/08 §6). The numbers are unmeasured
// defaults (S9-D9); hardware qualification replaces them with link p95 values.
[[nodiscard]] constexpr Duration round_timeout(unsigned hops) {
    return Duration::from_ms(600 + 240 * static_cast<int64_t>(hops));
}

[[nodiscard]] inline MessageId to_message_id(const std::array<uint8_t, 16> &b) {
    MessageId m;
    for (unsigned i = 0; i < 8; ++i) {
        m.incarnation = (m.incarnation << 8U) | b[i];
        m.sequence = (m.sequence << 8U) | b[8 + i];
    }
    return m;
}

[[nodiscard]] inline std::array<uint8_t, 16> to_bytes(const MessageId &m) {
    std::array<uint8_t, 16> b{};
    for (unsigned i = 0; i < 8; ++i) {
        b[i] = static_cast<uint8_t>(m.incarnation >> (56U - 8U * i));
        b[8 + i] = static_cast<uint8_t>(m.sequence >> (56U - 8U * i));
    }
    return b;
}

} // namespace lm::delivery
