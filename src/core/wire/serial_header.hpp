// Serial record layout after COBS decoding (docs/09 §9, docs/19 §3, protocol/serial.cddl):
//   header18 (magic "LS", version 1, kind, session_id u32, counter u64, payload_len u16)
//   || payload[payload_len] (|| AEAD tag16 for authenticated kinds) || CRC32 u32be.
// HELLO and EDHOC are the only unauthenticated kinds (payload <= 1024, no tag); all others carry
// the USB record AEAD tag. payload_len counts plaintext bytes, so the decoded maximum is
// 18 + 8192 + 16 + 4 = 8230. The CRC (ISO-HDLC/zlib polynomial) covers everything before it and
// detects corruption only; it is no substitute for the AEAD. COBS framing belongs to the serial
// transport slice.
#pragma once

#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/status.hpp"
#include "gen/registry.hpp"

namespace lm::wire {

using gen::SerialKind;

inline constexpr std::size_t k_serial_header_bytes = 18;
inline constexpr std::size_t k_serial_crc_bytes = 4;
inline constexpr std::size_t k_serial_unauth_payload_max = 1024;

struct SerialHeader {
    SerialKind kind = SerialKind::Hello;
    uint32_t session_id = 0;
    uint64_t counter = 0;
    uint16_t payload_len = 0;
};

[[nodiscard]] constexpr bool serial_kind_authenticated(SerialKind k) {
    return k != SerialKind::Hello && k != SerialKind::Edhoc;
}

[[nodiscard]] uint32_t crc32_iso_hdlc(ByteView data);

// `body` = payload (|| tag). Unsupported for an unknown version/kind, BadFrame otherwise
// (CRC mismatch, length rule, size cap).
[[nodiscard]] Status decode_serial_frame(ByteView decoded, SerialHeader &h, ByteView &body);
// `body` must already include the tag for authenticated kinds.
[[nodiscard]] Status encode_serial_frame(const SerialHeader &h, ByteView body, MutByteView out,
                                         std::size_t &len);

} // namespace lm::wire
