#include "core/wire/transfer.hpp"

#include "core/codec.hpp"

namespace lm::wire {

Status decode_fragment(ByteView plain, FragmentPrefix &out, ByteView &bytes) {
    Reader r{plain};
    FragmentPrefix p;
    p.total_len = r.u16be();
    p.offset = r.u16be();
    p.fragment_len = r.u16be();
    const uint8_t kind = r.u8();
    const uint8_t cls = r.u8();
    r.copy_to(p.intent_hash);
    if (!r.ok()) {
        return Status::BadFrame;
    }
    const bool kind_ok = kind == static_cast<uint8_t>(RecordKind::Data) ||
                         kind == static_cast<uint8_t>(RecordKind::Receipt) ||
                         kind == static_cast<uint8_t>(RecordKind::Control);
    if (!kind_ok || cls > 2) {
        return Status::BadFrame;
    }
    p.original_kind = static_cast<RecordKind>(kind);
    p.object_class = static_cast<ObjectClass>(cls);
    const std::size_t end = std::size_t{p.offset} + p.fragment_len;
    const std::size_t small_max = gen::limits::small_message_bytes;
    if (p.total_len == 0 || p.total_len > gen::limits::object_bytes ||
        (p.object_class == ObjectClass::Small && p.total_len > small_max) || p.fragment_len == 0 ||
        p.fragment_len > k_fragment_max_bytes || p.offset % k_fragment_quantum != 0 ||
        end > p.total_len || (end < p.total_len && p.fragment_len % k_fragment_quantum != 0) ||
        r.remaining() != p.fragment_len) {
        return Status::BadFrame;
    }
    bytes = plain.from(k_fragment_prefix_bytes);
    out = p;
    return Status::Ok;
}

Status encode_fragment_prefix(const FragmentPrefix &p, MutByteView out) {
    Writer w{out};
    w.u16be(p.total_len);
    w.u16be(p.offset);
    w.u16be(p.fragment_len);
    w.u8(static_cast<uint8_t>(p.original_kind));
    w.u8(static_cast<uint8_t>(p.object_class));
    w.bytes(ByteView{p.intent_hash});
    return w.finish();
}

Status decode_transfer_bitmap(ByteView plain, TransferBitmap &out) {
    Reader r{plain};
    TransferBitmap b;
    b.base_offset = r.u16be();
    r.copy_to(b.bitmap);
    b.credit = r.u8();
    if (!r.ok() || r.finish() != Status::Ok || b.base_offset != 0) {
        return Status::BadFrame;
    }
    out = b;
    return Status::Ok;
}

Status encode_transfer_bitmap(const TransferBitmap &b, MutByteView out) {
    Writer w{out};
    w.u16be(b.base_offset);
    w.bytes(ByteView{b.bitmap});
    w.u8(b.credit);
    return w.finish();
}

bool bitmap_test(const TransferBitmap &b, uint16_t offset) {
    const std::size_t idx = offset / k_fragment_quantum;
    return idx < k_bitmap_bytes * 8 && ((b.bitmap[idx / 8] >> (idx % 8)) & 1U) != 0;
}

void bitmap_set(TransferBitmap &b, uint16_t offset) {
    const std::size_t idx = offset / k_fragment_quantum;
    if (idx < k_bitmap_bytes * 8) {
        b.bitmap[idx / 8] = static_cast<uint8_t>(b.bitmap[idx / 8] | (1U << (idx % 8)));
    }
}

Status decode_bootstrap(ByteView plain, BootstrapCarrier &out) {
    Reader r{plain};
    BootstrapCarrier c;
    r.copy_to(c.exchange_id);
    c.object_kind = r.u8();
    c.total = r.u16be();
    c.offset = r.u16be();
    const uint16_t length = r.u16be();
    if (!r.ok() || c.total == 0 || c.total > k_bootstrap_max_total || length == 0 ||
        length > k_bootstrap_max_body || std::size_t{c.offset} + length > c.total ||
        r.remaining() != length) {
        return Status::BadFrame;
    }
    c.body = plain.from(k_bootstrap_header_bytes);
    out = c;
    return Status::Ok;
}

Status encode_bootstrap(const BootstrapCarrier &c, MutByteView out, std::size_t &len) {
    Writer w{out};
    w.bytes(ByteView{c.exchange_id});
    w.u8(c.object_kind);
    w.u16be(c.total);
    w.u16be(c.offset);
    w.u16be(static_cast<uint16_t>(c.body.size()));
    w.bytes(c.body);
    len = w.size();
    return w.finish();
}

} // namespace lm::wire
