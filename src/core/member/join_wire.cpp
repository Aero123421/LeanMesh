#include "core/member/join_wire.hpp"

#include <algorithm>

#include "core/codec.hpp"
#include "core/member/credentials.hpp"
#include "core/wire/cbor.hpp"
#include "core/wire/cbor_reader.hpp"
#include "core/wire/frame.hpp"

namespace lm::member {
namespace {

using wire::CborReader;
using wire::CborWriter;

template <std::size_t N> void rd(CborReader &r, std::array<uint8_t, N> &out) {
    const ByteView v = r.bstr(N, N);
    if (r.ok()) {
        std::copy(v.begin(), v.end(), out.begin());
    }
}

} // namespace

// ---- credential swap ----
Status join_bundle_encode(ByteView device_cose, ByteView delegation_cose, MutByteView out, std::size_t &len) {
    if (device_cose.empty() || device_cose.size() > k_max_device_cose || delegation_cose.empty() ||
        delegation_cose.size() > k_max_delegation_cose) {
        return Status::InvalidArgument;
    }
    CborWriter w{out};
    w.array(2);
    w.bytes(device_cose);
    w.bytes(delegation_cose);
    len = w.size();
    return w.finish();
}

Status join_bundle_parse(ByteView in, JoinBundle &out) {
    LM_TRY(wire::cbor_validate(in));
    CborReader r{in};
    (void)r.array(2, 2);
    const ByteView dc = r.bstr(1, k_max_device_cose);
    const ByteView del = r.bstr(1, k_max_delegation_cose);
    LM_TRY(r.finish());
    out.device_cose = dc;
    out.delegation_cose = del;
    return Status::Ok;
}

Status encode_discovery(bool offer, const std::array<uint8_t, 16> &nonce, uint32_t domain_hint,
                        MutByteView out, std::size_t &len) {
    const uint8_t version = 1;
    std::array<uint8_t, wire::k_bootstrap_header_bytes + 1> carrier{};
    std::size_t clen = 0;
    wire::BootstrapCarrier c;
    c.exchange_id = nonce;
    c.object_kind = offer ? k_obj_join_offer : k_obj_join_hello;
    c.total = 1;
    c.offset = 0;
    c.body = ByteView{&version, 1};
    LM_TRY(wire::encode_bootstrap(c, MutByteView{carrier}, clen));
    wire::LinkHeader h;
    h.kind = wire::FrameKind::JoinProxy;
    h.domain_hint = domain_hint;
    h.body_length = static_cast<uint16_t>(clen);
    h.encrypted = false;
    if (out.size() < wire::k_link_header_bytes + clen) {
        return Status::NoCapacity;
    }
    LM_TRY(wire::encode_link_header(h, out.first(wire::k_link_header_bytes)));
    std::copy_n(carrier.begin(), clen, out.begin() + wire::k_link_header_bytes);
    len = wire::k_link_header_bytes + clen;
    return Status::Ok;
}

// ---- envelope ----
Status join_object_build(const JoinObjectHeader &h, ByteView data, MutByteView out, std::size_t &len) {
    wire::ControlBody b;
    b.type = h.type;
    b.request_id = h.request.bytes;
    b.domain = h.domain.bytes;
    b.revision = h.revision;
    b.issuer = h.issuer.bytes;
    b.data = data;
    return wire::encode_control_body(b, out, len);
}

Status join_object_begin(const JoinObjectHeader &h, MutByteView out, std::size_t &len) {
    CborWriter w{out};
    w.array(7);
    w.uint(h.type);
    w.uint(wire::k_control_version);
    w.bytes(ByteView{h.request.bytes});
    w.bytes(ByteView{h.domain.bytes});
    w.uint(h.revision);
    w.bytes(h.issuer.view());
    len = w.size();
    return w.finish();
}

Status join_object_parse(ByteView plain, JoinObjectHeader &h, ByteView &data) {
    wire::ControlBody b;
    LM_TRY(wire::decode_control_body(plain, wire::ControlCarrier::Session, b));
    if (b.type < k_type_join_request || (b.type > k_type_join_active && b.type != k_type_leave_request)) {
        return Status::Unsupported;
    }
    h.type = b.type;
    h.request.bytes = b.request_id;
    h.domain.bytes = b.domain;
    h.revision = b.revision;
    h.issuer.bytes = b.issuer;
    data = b.data;
    return Status::Ok;
}

// ---- data items ----
Status encode_join_request(const JoinRequestData &d, MutByteView out, std::size_t &len) {
    CborWriter w{out};
    w.array(4);
    w.bytes(d.device_credential);
    w.bytes(d.ticket);
    w.bytes(ByteView{d.nonce});
    w.uint(d.capabilities);
    len = w.size();
    return w.finish();
}

Status decode_join_request(ByteView data, JoinRequestData &out) {
    CborReader r{data};
    JoinRequestData d;
    (void)r.array(4, 4);
    d.device_credential = r.bstr(1, 1024);
    d.ticket = r.bstr(1, 1024);
    rd(r, d.nonce);
    d.capabilities = r.uint_in(0, UINT64_MAX);
    LM_TRY(r.finish());
    out = d;
    return Status::Ok;
}

Status encode_join_prepare(const JoinPrepareData &d, MutByteView out, std::size_t &len) {
    if (d.membership > k_u63_max || d.reservation_ms == 0 || d.reservation_ms > 120000) {
        return Status::InvalidArgument;
    }
    CborWriter w{out};
    w.array(6);
    w.bytes(d.member);
    w.bytes(ByteView{d.prepare_hash});
    w.uint(d.address.value());
    w.uint(d.membership);
    w.uint(d.root_term);
    w.uint(d.reservation_ms);
    len = w.size();
    return w.finish();
}

Status decode_join_prepare(ByteView data, JoinPrepareData &out) {
    CborReader r{data};
    JoinPrepareData d;
    (void)r.array(6, 6);
    d.member = r.bstr(1, 1024);
    rd(r, d.prepare_hash);
    d.address = ShortAddr{static_cast<uint16_t>(r.uint_in(1, 65534))};
    d.membership = r.uint_in(0, k_u63_max);
    d.root_term = static_cast<uint32_t>(r.uint_in(0, 0xFFFFFFFFULL));
    d.reservation_ms = static_cast<uint32_t>(r.uint_in(1, 120000));
    LM_TRY(r.finish());
    out = d;
    return Status::Ok;
}

Status encode_join_ack(const JoinAckData &d, MutByteView out, std::size_t &len) {
    if (d.value > k_u63_max) {
        return Status::InvalidArgument;
    }
    CborWriter w{out};
    w.array(2);
    w.bytes(ByteView{d.prepare_hash});
    w.uint(d.value);
    len = w.size();
    return w.finish();
}

Status decode_join_ack(ByteView data, JoinAckData &out) {
    CborReader r{data};
    JoinAckData d;
    (void)r.array(2, 2);
    rd(r, d.prepare_hash);
    d.value = r.uint_in(0, k_u63_max);
    LM_TRY(r.finish());
    out = d;
    return Status::Ok;
}

Status encode_leave(const LeaveData &d, MutByteView out, std::size_t &len) {
    if (d.mode > 1 || d.deadline_ms > 30000) {
        return Status::InvalidArgument;
    }
    CborWriter w{out};
    w.array(3);
    w.bytes(d.device.view());
    w.uint(d.mode);
    w.uint(d.deadline_ms);
    len = w.size();
    return w.finish();
}

Status decode_leave(ByteView data, LeaveData &out) {
    CborReader r{data};
    LeaveData d;
    (void)r.array(3, 3);
    rd(r, d.device.bytes);
    d.mode = static_cast<uint8_t>(r.uint_in(0, 1));
    d.deadline_ms = static_cast<uint32_t>(r.uint_in(0, 30000));
    LM_TRY(r.finish());
    out = d;
    return Status::Ok;
}

// ---- chunks ----
Status encode_chunk(const JoinChunk &c, MutByteView out, std::size_t &len) {
    if (c.ack) {
        if (c.object_id == 0) {
            return Status::InvalidArgument;
        }
        Writer w{out};
        w.u8(c.object_id);
        w.u16be(0);
        w.u16be(0);
        len = w.size();
        return w.finish();
    }
    if (c.object_id == 0 || c.bytes.empty() || c.bytes.size() > k_join_chunk_bytes ||
        c.total == 0 || c.total > k_join_max_object || c.offset + c.bytes.size() > c.total) {
        return Status::InvalidArgument;
    }
    Writer w{out};
    w.u8(c.object_id);
    w.u16be(c.total);
    w.u16be(c.offset);
    w.bytes(c.bytes);
    len = w.size();
    return w.finish();
}

Status decode_chunk(ByteView in, JoinChunk &out) {
    Reader r{in};
    JoinChunk c;
    c.object_id = r.u8();
    c.total = r.u16be();
    c.offset = r.u16be();
    c.bytes = r.bytes(r.remaining());
    LM_TRY(r.finish());
    if (c.object_id != 0 && c.total == 0 && c.offset == 0 && c.bytes.empty()) {
        c.ack = true;
        out = c;
        return Status::Ok;
    }
    if (c.object_id == 0 || c.bytes.empty() || c.bytes.size() > k_join_chunk_bytes || c.total == 0 ||
        c.total > k_join_max_object || c.offset + c.bytes.size() > c.total) {
        return Status::BadFrame;
    }
    out = c;
    return Status::Ok;
}

} // namespace lm::member
