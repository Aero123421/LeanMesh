#include "core/wire/serial_header.hpp"

#include "core/codec.hpp"
#include "core/wire/frame.hpp"

namespace lm::wire {
namespace {

constexpr uint8_t k_version = 1;

std::size_t tag_len(SerialKind k) { return serial_kind_authenticated(k) ? k_tag_bytes : 0; }

} // namespace

uint32_t crc32_iso_hdlc(ByteView data) {
    uint32_t crc = 0xFFFFFFFFU;
    for (const uint8_t b : data) {
        crc ^= b;
        for (int i = 0; i < 8; ++i) {
            crc = (crc >> 1U) ^ ((crc & 1U) != 0 ? 0xEDB88320U : 0U);
        }
    }
    return ~crc;
}

Status decode_serial_frame(ByteView decoded, SerialHeader &out, ByteView &body) {
    if (decoded.size() < k_serial_header_bytes + k_serial_crc_bytes ||
        decoded.size() > gen::limits::serial_decoded_bytes) {
        return Status::BadFrame;
    }
    const std::size_t covered = decoded.size() - k_serial_crc_bytes;
    Reader r{decoded};
    const uint8_t m0 = r.u8();
    const uint8_t m1 = r.u8();
    const uint8_t version = r.u8();
    const uint8_t kind = r.u8();
    SerialHeader h;
    h.session_id = r.u32be();
    h.counter = r.u64be();
    h.payload_len = r.u16be();
    if (m0 != 'L' || m1 != 'S') {
        return Status::BadFrame;
    }
    if (version != k_version || kind < 1 || kind > 7) {
        return Status::Unsupported;
    }
    h.kind = static_cast<SerialKind>(kind);
    const bool unauth_too_big =
        !serial_kind_authenticated(h.kind) && h.payload_len > k_serial_unauth_payload_max;
    const std::size_t expected =
        k_serial_header_bytes + std::size_t{h.payload_len} + tag_len(h.kind) + k_serial_crc_bytes;
    if (unauth_too_big || h.payload_len > gen::limits::serial_payload_bytes ||
        decoded.size() != expected) {
        return Status::BadFrame;
    }
    Reader crc{decoded.from(covered)};
    if (crc32_iso_hdlc(decoded.first(covered)) != crc.u32be()) {
        return Status::BadFrame;
    }
    body = decoded.subspan(k_serial_header_bytes, covered - k_serial_header_bytes);
    out = h;
    return Status::Ok;
}

Status encode_serial_frame(const SerialHeader &h, ByteView body, MutByteView out,
                           std::size_t &len) {
    if (body.size() != std::size_t{h.payload_len} + tag_len(h.kind)) {
        return Status::InvalidArgument;
    }
    Writer w{out};
    w.u8('L');
    w.u8('S');
    w.u8(k_version);
    w.u8(static_cast<uint8_t>(h.kind));
    w.u32be(h.session_id);
    w.u64be(h.counter);
    w.u16be(h.payload_len);
    w.bytes(body);
    LM_TRY(w.finish());
    w.u32be(crc32_iso_hdlc(w.written()));
    len = w.size();
    return w.finish();
}

} // namespace lm::wire
