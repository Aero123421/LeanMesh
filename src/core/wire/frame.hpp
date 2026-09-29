// RF frame codecs: link envelope, routed body, end record header, HOP_ACK (docs/09 §2-§5, §7).
// Pure functions over byte views: no crypto, no state, no allocation. A decoder checks the
// structure the wire contract fixes (lengths, reserved bits, ranges, simple path); it does not
// decide authorization or freshness. Failures: Unsupported for a wire version/kind this build
// does not define, BadFrame for every other malformation.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/status.hpp"
#include "gen/registry.hpp"

namespace lm::wire {

using gen::FrameKind;
using gen::RecordKind;

namespace layout = gen::layout;
inline constexpr std::size_t k_link_header_bytes = layout::link::bytes;   // 24
inline constexpr std::size_t k_route_header_bytes = layout::route::bytes; // 16
inline constexpr std::size_t k_end_header_bytes = layout::end::bytes;     // 42
inline constexpr std::size_t k_tag_bytes = gen::aead::tag_bytes;          // 16
inline constexpr std::size_t k_max_frame_bytes = gen::limits::rf_body_bytes;
inline constexpr std::size_t k_max_path = gen::limits::path_hops;
inline constexpr std::size_t k_hop_ack_body_bytes = 12;
inline constexpr std::size_t k_link_aad_bytes = k_link_header_bytes + 32;
inline constexpr std::size_t k_end_aad_bytes = 7 + 32 + 4 + k_end_header_bytes;
inline constexpr uint16_t k_addr_broadcast = 0xFFFF;

// docs/09 §5: 250 - 24 - 16 - 16 - 2N - 42 - 16 = 136 - 2N. Zero when hops is outside 1..40.
[[nodiscard]] constexpr std::size_t data_capacity(std::size_t hops) {
    constexpr std::size_t fixed = k_max_frame_bytes - k_link_header_bytes - k_tag_bytes -
                                  k_route_header_bytes - k_end_header_bytes - k_tag_bytes;
    return (hops >= 1 && hops <= k_max_path && 2 * hops <= fixed) ? fixed - 2 * hops : 0;
}

static_assert(data_capacity(1) == 134 && data_capacity(20) == 96 && data_capacity(40) == 56,
              "docs/09 §5 payload accounting");

// ---- link envelope (24 B) ----
struct LinkHeader {
    FrameKind kind = FrameKind::Data;
    uint32_t domain_hint = 0;
    uint32_t link_sid = 0;
    uint64_t link_counter = 0;
    uint16_t body_length = 0; // ciphertext length, tag excluded
    bool encrypted = true;
};

// Whole RF frame -> header plus `payload` (ciphertext||tag when encrypted, else the plain body).
// Encrypted: DATA/HOP_ACK/ROUTE/CONTROL/POWER always, EDHOC when link_sid != 0; SID-0 frames
// (DISCOVERY, JOIN_PROXY, EDHOC bootstrap) are never encrypted (docs/09 §2).
[[nodiscard]] Status decode_link_frame(ByteView frame, LinkHeader &h, ByteView &payload);
[[nodiscard]] Status encode_link_header(const LinkHeader &h, MutByteView out);
// AAD = prefix24 || ctx_hash32.
[[nodiscard]] Status build_link_aad(ByteView prefix24, ByteView ctx_hash32,
                                    std::array<uint8_t, k_link_aad_bytes> &out);

// ---- routed body (route_header16 || path[2N] || end_record) ----
struct RouteHeader {
    uint16_t origin = 0;
    uint16_t final = 0;
    uint8_t path_len = 0;
    uint8_t next_index = 0;
    uint8_t budget = 0;
    uint32_t root_term = 0;
    uint32_t path_revision = 0;
    std::array<uint16_t, gen::limits::path_hops> path{};
};

// docs/04 §4: every address non-zero and not broadcast, none equal to origin, no duplicates.
[[nodiscard]] Status validate_simple_path(uint16_t origin, const uint16_t *path, std::size_t n);
// Also requires 1 <= path_len <= 40, next_index < path_len, budget == path_len - next_index,
// final == last path entry, reserved == 0 and room for an end record. `end_record` aliases plain.
[[nodiscard]] Status decode_route(ByteView plain, RouteHeader &h, ByteView &end_record);
[[nodiscard]] Status encode_route(const RouteHeader &h, MutByteView out, std::size_t &len);

// ---- end record header (42 B) ----
enum class Delivery : uint8_t { BestEffort = 0, Received = 1, Applied = 2 };
enum class Priority : uint8_t { Bulk = 0, Normal = 1, Urgent = 2, Control = 3 };

struct EndHeader {
    uint32_t end_sid = 0;
    uint64_t end_counter = 0;
    std::array<uint8_t, 16> message_id{};
    uint16_t app_port = 0;
    RecordKind record_kind = RecordKind::Data;
    uint8_t flags = 0;
    uint64_t expires_root_ms = 0;
    uint16_t plaintext_length = 0;

    [[nodiscard]] Delivery delivery() const { return static_cast<Delivery>(flags & 3U); }
    [[nodiscard]] Priority priority() const { return static_cast<Priority>((flags >> 2U) & 3U); }
    [[nodiscard]] bool durable() const { return (flags & 0x10U) != 0; }
};

[[nodiscard]] constexpr uint8_t make_end_flags(Delivery d, Priority p, bool durable) {
    return static_cast<uint8_t>(static_cast<uint8_t>(d) | (static_cast<uint8_t>(p) << 2U) |
                                (durable ? 0x10U : 0U));
}

// record = header42 || ciphertext(plaintext_length) || tag16, exact length.
// `sealed` = ciphertext||tag. DATA needs app_port 1..65534; 0 (SDK control) is for other kinds;
// 65535 is reserved. Kind 5 (bitmap) must carry exactly 35 plaintext bytes.
[[nodiscard]] Status decode_end_record(ByteView record, EndHeader &h, ByteView &sealed);
[[nodiscard]] Status encode_end_header(const EndHeader &h, MutByteView out);
// AAD = "LM1-END" || ctx_hash32 || u32be(root_term) || header42.
[[nodiscard]] Status build_end_aad(ByteView ctx_hash32, uint32_t root_term, ByteView header42,
                                   std::array<uint8_t, k_end_aad_bytes> &out);

// ---- HOP_ACK (link plaintext 12 B; frame 52 B) ----
enum class HopAckStatus : uint8_t { Accepted = 0, Busy = 1, Rejected = 2 };
struct HopAck {
    uint64_t acked_link_counter = 0;
    HopAckStatus status = HopAckStatus::Accepted;
    uint8_t credit = 0;
    uint16_t retry_after_ms = 0;
};
[[nodiscard]] Status decode_hop_ack(ByteView plain, HopAck &out);
[[nodiscard]] Status encode_hop_ack(const HopAck &a, MutByteView out, std::size_t &len);

} // namespace lm::wire
