#include "core/link/seal.hpp"

namespace lm::link {

Status seal_frame(SessionKeys &k, wire::FrameKind kind, uint32_t domain_hint, uint32_t header_sid,
                  ByteView plain, SealedFrame &out) {
    if (plain.empty() || plain.size() + wire::k_link_header_bytes + wire::k_tag_bytes >
                             wire::k_max_frame_bytes) {
        return Status::PayloadTooLarge;
    }
    uint64_t counter = 0;
    LM_TRY(k.rec.next_counter(counter));
    wire::LinkHeader h;
    h.kind = kind;
    h.domain_hint = domain_hint;
    h.link_sid = header_sid;
    h.link_counter = counter;
    h.body_length = static_cast<uint16_t>(plain.size());
    h.encrypted = true;
    SealedFrame f;
    LM_TRY(wire::encode_link_header(h, MutByteView{f.bytes.data(), wire::k_link_header_bytes}));
    std::array<uint8_t, wire::k_link_aad_bytes> aad{};
    LM_TRY(wire::build_link_aad(ByteView{f.bytes.data(), wire::k_link_header_bytes},
                                ByteView{k.ctx_hash}, aad));
    const std::size_t total = wire::k_link_header_bytes + plain.size() + wire::k_tag_bytes;
    LM_TRY(k.rec.seal(counter, ByteView{aad}, plain,
                      MutByteView{f.bytes.data() + wire::k_link_header_bytes,
                                  total - wire::k_link_header_bytes}));
    f.len = static_cast<uint16_t>(total);
    wire::LinkHeader check;
    ByteView body;
    if (wire::decode_link_frame(f.view(), check, body) != Status::Ok) {
        return Status::InvalidArgument;
    }
    out = f;
    return Status::Ok;
}

Status open_frame(SessionKeys &k, const wire::LinkHeader &h, ByteView frame, Opened &out) {
    std::array<uint8_t, wire::k_link_aad_bytes> aad{};
    LM_TRY(wire::build_link_aad(frame.first(wire::k_link_header_bytes), ByteView{k.ctx_hash}, aad));
    const ByteView sealed = frame.from(wire::k_link_header_bytes);
    out.len = 0;
    const Status st = k.rec.open(h.link_counter, ByteView{aad}, sealed, MutByteView{out.plain},
                                 out.len, out.verdict);
    return st;
}

} // namespace lm::link
