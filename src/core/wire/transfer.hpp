// Fragment prefix, transfer bitmap and bootstrap carrier layouts (docs/09 §6, §8).
// Codecs only: reassembly slots, timeouts and reservation belong to the delivery slice.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/status.hpp"
#include "core/wire/frame.hpp"

namespace lm::wire {

inline constexpr std::size_t k_fragment_prefix_bytes = gen::limits::fragment_prefix_bytes; // 40
inline constexpr std::size_t k_fragment_quantum = gen::limits::fragment_quantum;           // 16
inline constexpr std::size_t k_bitmap_bytes = gen::limits::fragment_bitmap_bytes;          // 32
inline constexpr std::size_t k_transfer_bitmap_body = 35;
inline constexpr std::size_t k_bootstrap_header_bytes = 23;
inline constexpr std::size_t k_bootstrap_max_body = 160;
inline constexpr std::size_t k_bootstrap_max_total = 1024;

// Bytes of fragment data one frame carries over `hops` hops, a multiple of 16 (1 hop 80,
// 20 hops 48, 40 hops 16). Zero outside 1..40 hops.
[[nodiscard]] constexpr std::size_t fragment_chunk(std::size_t hops) {
    const std::size_t cap = data_capacity(hops);
    return cap <= k_fragment_prefix_bytes
               ? 0
               : (cap - k_fragment_prefix_bytes) / k_fragment_quantum * k_fragment_quantum;
}
// Largest fragment data any frame can carry (1 hop, unrounded): last fragments may be shorter.
inline constexpr std::size_t k_fragment_max_bytes = data_capacity(1) - k_fragment_prefix_bytes;

static_assert(fragment_chunk(1) == 80 && fragment_chunk(20) == 48 && fragment_chunk(40) == 16,
              "docs/09 §6 chunk sizes");

enum class ObjectClass : uint8_t { Small = 0, Object = 1, Control = 2 };

struct FragmentPrefix {
    uint16_t total_len = 0;
    uint16_t offset = 0;
    uint16_t fragment_len = 0;
    RecordKind original_kind = RecordKind::Data; // DATA, RECEIPT or CONTROL only
    ObjectClass object_class = ObjectClass::Small;
    std::array<uint8_t, 32> intent_hash{};
};

// Record plaintext = prefix40 || fragment bytes. total 1..4096 (Small: <= 512); offset and every
// non-final fragment length are multiples of 16; offset+len <= total; len == bytes present.
[[nodiscard]] Status decode_fragment(ByteView plain, FragmentPrefix &out, ByteView &bytes);
[[nodiscard]] Status encode_fragment_prefix(const FragmentPrefix &p, MutByteView out);

// Record kind 5 body: base_offset u16 (must be 0), bitmap32, credit u8. Bit i of byte j (bit0
// first) is the fragment at offset 16*(8*j + i).
struct TransferBitmap {
    uint16_t base_offset = 0;
    std::array<uint8_t, gen::limits::fragment_bitmap_bytes> bitmap{};
    uint8_t credit = 0;
};
[[nodiscard]] Status decode_transfer_bitmap(ByteView plain, TransferBitmap &out);
[[nodiscard]] Status encode_transfer_bitmap(const TransferBitmap &b, MutByteView out);
[[nodiscard]] bool bitmap_test(const TransferBitmap &b, uint16_t offset);
void bitmap_set(TransferBitmap &b, uint16_t offset);

// Bootstrap carrier (kinds EDHOC / JOIN_PROXY at SID 0): exchange_id16, object_kind u8,
// total u16, offset u16, length u16, body. total 1..1024, body 1..160, offset+length <= total.
struct BootstrapCarrier {
    std::array<uint8_t, 16> exchange_id{};
    uint8_t object_kind = 0;
    uint16_t total = 0;
    uint16_t offset = 0;
    ByteView body; // aliases the input (decode) or the caller (encode)
};
[[nodiscard]] Status decode_bootstrap(ByteView plain, BootstrapCarrier &out);
[[nodiscard]] Status encode_bootstrap(const BootstrapCarrier &c, MutByteView out, std::size_t &len);

} // namespace lm::wire
