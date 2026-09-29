#include "core/wire/frame.hpp"

#include <algorithm>

#include "core/codec.hpp"

namespace lm::wire {
namespace {

constexpr uint8_t k_magic0 = 'L';
constexpr uint8_t k_magic1 = 'M';
constexpr uint8_t k_wire_version = 1;
constexpr uint8_t k_flag_encrypted = 1;
constexpr uint8_t k_end_flags_reserved = 0xE0;
constexpr std::size_t k_bitmap_record_bytes = 35;
constexpr uint8_t k_end_aad_tag[7] = {'L', 'M', '1', '-', 'E', 'N', 'D'};

bool kind_known(uint8_t k) { return k >= 1 && k <= 8; }

// Sessionless kinds are plain and SID 0; session kinds are encrypted with a non-zero SID. EDHOC is
// both: bootstrap (SID 0) plain, post-handshake records (SESSION_BIND) under the link key.
bool session_shape_ok(FrameKind k, uint32_t sid, bool encrypted) {
    switch (k) {
    case FrameKind::Discovery:
    case FrameKind::JoinProxy:
        return sid == 0 && !encrypted;
    case FrameKind::Edhoc:
        return encrypted == (sid != 0);
    default:
        return sid != 0 && encrypted;
    }
}

bool body_length_ok(FrameKind k, uint16_t n) {
    switch (k) {
    case FrameKind::HopAck:
        return n == k_hop_ack_body_bytes;
    case FrameKind::Power:
        return n == layout::power_poll_bytes || n == layout::power_grant_bytes;
    case FrameKind::Data: // route + 1 path entry + end header + end tag
        return n >= k_route_header_bytes + 2 + k_end_header_bytes + k_tag_bytes;
    default:
        return n >= 1;
    }
}

} // namespace

Status decode_link_frame(ByteView frame, LinkHeader &out, ByteView &payload) {
    if (frame.size() < k_link_header_bytes || frame.size() > k_max_frame_bytes) {
        return Status::BadFrame;
    }
    Reader r{frame};
    const uint8_t m0 = r.u8();
    const uint8_t m1 = r.u8();
    const uint8_t version = r.u8();
    const uint8_t kind = r.u8();
    LinkHeader h;
    h.domain_hint = r.u32be();
    h.link_sid = r.u32be();
    h.link_counter = r.u64be();
    h.body_length = r.u16be();
    const uint8_t flags = r.u8();
    const uint8_t reserved = r.u8();
    if (m0 != k_magic0 || m1 != k_magic1) {
        return Status::BadFrame;
    }
    if (version != k_wire_version || !kind_known(kind)) {
        return Status::Unsupported;
    }
    h.kind = static_cast<FrameKind>(kind);
    h.encrypted = (flags & k_flag_encrypted) != 0;
    if ((flags & ~k_flag_encrypted) != 0 || reserved != 0) {
        return Status::BadFrame;
    }
    if (!session_shape_ok(h.kind, h.link_sid, h.encrypted) ||
        (h.encrypted && h.link_counter == 0)) {
        return Status::BadFrame;
    }
    if (frame.size() != k_link_header_bytes + h.body_length + (h.encrypted ? k_tag_bytes : 0) ||
        !body_length_ok(h.kind, h.body_length)) {
        return Status::BadFrame;
    }
    payload = frame.from(k_link_header_bytes);
    out = h;
    return Status::Ok;
}

Status encode_link_header(const LinkHeader &h, MutByteView out) {
    Writer w{out};
    w.u8(k_magic0);
    w.u8(k_magic1);
    w.u8(k_wire_version);
    w.u8(static_cast<uint8_t>(h.kind));
    w.u32be(h.domain_hint);
    w.u32be(h.link_sid);
    w.u64be(h.link_counter);
    w.u16be(h.body_length);
    w.u8(h.encrypted ? k_flag_encrypted : 0);
    w.u8(0);
    return w.finish();
}

Status build_link_aad(ByteView prefix24, ByteView ctx_hash32,
                      std::array<uint8_t, k_link_aad_bytes> &out) {
    if (prefix24.size() != k_link_header_bytes || ctx_hash32.size() != 32) {
        return Status::InvalidArgument;
    }
    Writer w{MutByteView{out}};
    w.bytes(prefix24);
    w.bytes(ctx_hash32);
    return w.finish();
}

Status validate_simple_path(uint16_t origin, const uint16_t *path, std::size_t n) {
    if (origin == 0 || origin == k_addr_broadcast) {
        return Status::BadFrame;
    }
    for (std::size_t i = 0; i < n; ++i) {
        if (path[i] == 0 || path[i] == k_addr_broadcast || path[i] == origin) {
            return Status::BadFrame;
        }
        for (std::size_t j = 0; j < i; ++j) {
            if (path[j] == path[i]) {
                return Status::BadFrame;
            }
        }
    }
    return Status::Ok;
}

Status decode_route(ByteView plain, RouteHeader &out, ByteView &end_record) {
    Reader r{plain};
    RouteHeader h;
    h.origin = r.u16be();
    h.final = r.u16be();
    h.path_len = r.u8();
    h.next_index = r.u8();
    h.budget = r.u8();
    const uint8_t reserved = r.u8();
    h.root_term = r.u32be();
    h.path_revision = r.u32be();
    if (!r.ok() || reserved != 0 || h.path_len < 1 || h.path_len > k_max_path ||
        h.next_index >= h.path_len || h.budget != h.path_len - h.next_index) {
        return Status::BadFrame;
    }
    for (std::size_t i = 0; i < h.path_len; ++i) {
        h.path[i] = r.u16be();
    }
    if (!r.ok() || r.remaining() < k_end_header_bytes + k_tag_bytes ||
        h.final != h.path[h.path_len - 1]) {
        return Status::BadFrame;
    }
    LM_TRY(validate_simple_path(h.origin, h.path.data(), h.path_len));
    end_record = plain.from(r.position());
    out = h;
    return Status::Ok;
}

Status encode_route(const RouteHeader &h, MutByteView out, std::size_t &len) {
    if (h.path_len < 1 || h.path_len > k_max_path) {
        return Status::InvalidArgument;
    }
    Writer w{out};
    w.u16be(h.origin);
    w.u16be(h.final);
    w.u8(h.path_len);
    w.u8(h.next_index);
    w.u8(h.budget);
    w.u8(0);
    w.u32be(h.root_term);
    w.u32be(h.path_revision);
    for (std::size_t i = 0; i < h.path_len; ++i) {
        w.u16be(h.path[i]);
    }
    len = w.size();
    return w.finish();
}

Status decode_end_record(ByteView record, EndHeader &out, ByteView &sealed) {
    Reader r{record};
    EndHeader h;
    h.end_sid = r.u32be();
    h.end_counter = r.u64be();
    r.copy_to(h.message_id);
    h.app_port = r.u16be();
    const uint8_t kind = r.u8();
    h.flags = r.u8();
    h.expires_root_ms = r.u64be();
    h.plaintext_length = r.u16be();
    if (!r.ok() || h.end_sid == 0 || h.end_counter == 0 || kind < 1 || kind > 5 ||
        (h.flags & k_end_flags_reserved) != 0 || h.delivery() > Delivery::Applied ||
        h.app_port == k_addr_broadcast) {
        return Status::BadFrame;
    }
    h.record_kind = static_cast<RecordKind>(kind);
    if ((h.record_kind == RecordKind::Data && h.app_port == 0) ||
        (h.record_kind == RecordKind::TransferBitmap &&
         h.plaintext_length != k_bitmap_record_bytes) ||
        r.remaining() != std::size_t{h.plaintext_length} + k_tag_bytes) {
        return Status::BadFrame;
    }
    sealed = record.from(k_end_header_bytes);
    out = h;
    return Status::Ok;
}

Status encode_end_header(const EndHeader &h, MutByteView out) {
    Writer w{out};
    w.u32be(h.end_sid);
    w.u64be(h.end_counter);
    w.bytes(ByteView{h.message_id});
    w.u16be(h.app_port);
    w.u8(static_cast<uint8_t>(h.record_kind));
    w.u8(h.flags);
    w.u64be(h.expires_root_ms);
    w.u16be(h.plaintext_length);
    return w.finish();
}

Status build_end_aad(ByteView ctx_hash32, uint32_t root_term, ByteView header42,
                     std::array<uint8_t, k_end_aad_bytes> &out) {
    if (ctx_hash32.size() != 32 || header42.size() != k_end_header_bytes) {
        return Status::InvalidArgument;
    }
    Writer w{MutByteView{out}};
    w.bytes(ByteView{k_end_aad_tag, sizeof k_end_aad_tag});
    w.bytes(ctx_hash32);
    w.u32be(root_term);
    w.bytes(header42);
    return w.finish();
}

Status decode_hop_ack(ByteView plain, HopAck &out) {
    Reader r{plain};
    HopAck a;
    a.acked_link_counter = r.u64be();
    const uint8_t status = r.u8();
    a.credit = r.u8();
    a.retry_after_ms = r.u16be();
    if (!r.ok() || r.finish() != Status::Ok || a.acked_link_counter == 0 || status > 2) {
        return Status::BadFrame;
    }
    a.status = static_cast<HopAckStatus>(status);
    out = a;
    return Status::Ok;
}

Status encode_hop_ack(const HopAck &a, MutByteView out, std::size_t &len) {
    Writer w{out};
    w.u64be(a.acked_link_counter);
    w.u8(static_cast<uint8_t>(a.status));
    w.u8(a.credit);
    w.u16be(a.retry_after_ms);
    len = w.size();
    return w.finish();
}

} // namespace lm::wire
