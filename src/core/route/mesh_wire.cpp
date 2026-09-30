#include "core/route/mesh_wire.hpp"

#include <algorithm>

#include "core/codec.hpp"
#include "core/wire/cbor.hpp"
#include "core/wire/cbor_reader.hpp"
#include "core/wire/control.hpp"

namespace lm::route {

bool path_ok(const uint16_t *p, std::size_t n) {
    if (n == 0 || n > k_max_root_path) {
        return false;
    }
    for (std::size_t i = 0; i < n; ++i) {
        if (p[i] == 0 || p[i] == 0xFFFF) {
            return false;
        }
        for (std::size_t j = 0; j < i; ++j) {
            if (p[j] == p[i]) {
                return false;
            }
        }
    }
    return true;
}

// ---- beacon ----
Status encode_beacon(const Beacon &b, uint32_t domain_hint, MutByteView out, std::size_t &len) {
    if (b.n > k_max_root_path || (b.n != 0 && !path_ok(b.path.data(), b.n))) {
        return Status::InvalidArgument;
    }
    std::array<uint8_t, 11 + 2 * k_max_root_path> body{};
    Writer w{MutByteView{body}};
    w.u8(k_beacon_version);
    w.u8(b.flags);
    w.u8(b.n == 0 ? 0 : static_cast<uint8_t>(b.n - 1)); // depth
    w.u32be(b.term);
    w.u32be(b.revision);
    for (std::size_t i = 0; i < b.n; ++i) {
        w.u16be(b.path[i]);
    }
    LM_TRY(w.finish());
    wire::LinkHeader h;
    h.kind = wire::FrameKind::Discovery;
    h.domain_hint = domain_hint;
    h.body_length = static_cast<uint16_t>(w.size());
    h.encrypted = false;
    if (out.size() < wire::k_link_header_bytes + w.size()) {
        return Status::NoCapacity;
    }
    LM_TRY(wire::encode_link_header(h, out.first(wire::k_link_header_bytes)));
    std::copy(body.begin(), body.begin() + static_cast<std::ptrdiff_t>(w.size()),
              out.begin() + wire::k_link_header_bytes);
    len = wire::k_link_header_bytes + w.size();
    return Status::Ok;
}

Status decode_beacon(ByteView body, Beacon &out) {
    Reader r{body};
    Beacon b;
    if (r.u8() != k_beacon_version) {
        return Status::Unsupported;
    }
    b.flags = r.u8();
    const uint8_t depth = r.u8();
    b.term = r.u32be();
    b.revision = r.u32be();
    const std::size_t entries = r.remaining() / 2;
    if ((b.flags & ~(k_beacon_accepting | k_beacon_solicit)) != 0 || entries > k_max_root_path ||
        r.remaining() % 2 != 0 || (entries != 0 && depth + 1U != entries)) {
        return Status::BadFrame;
    }
    b.n = static_cast<uint8_t>(entries);
    for (std::size_t i = 0; i < entries; ++i) {
        b.path[i] = r.u16be();
    }
    LM_TRY(r.finish());
    if (b.n != 0 && !path_ok(b.path.data(), b.n)) {
        return Status::BadFrame;
    }
    out = b;
    return Status::Ok;
}

// ---- probe ----
Status encode_probe(const Probe &p, const DomainId &domain, const DeviceId &issuer, MutByteView out,
                    std::size_t &len) {
    std::array<uint8_t, 64> data{};
    wire::CborWriter w{MutByteView{data}};
    w.array(6);
    w.bytes(ByteView{p.nonce});
    w.uint(p.sender);
    w.uint(p.receiver);
    w.boolean(p.reply);
    w.uint(p.credit);
    w.uint(p.membership);
    LM_TRY(w.finish());
    wire::ControlBody b;
    b.type = 16;
    b.request_id = p.nonce;
    b.domain = domain.bytes;
    b.issuer = issuer.bytes;
    b.data = w.written();
    return wire::encode_control_body(b, out, len);
}

Status decode_probe(ByteView plain, Probe &out, DeviceId &issuer) {
    wire::ControlBody b;
    LM_TRY(wire::decode_control_body(plain, wire::ControlCarrier::Session, b));
    if (b.type != 16) {
        return Status::Unsupported;
    }
    wire::CborReader r{b.data};
    Probe p;
    (void)r.array(6, 6);
    const ByteView nonce = r.bstr(16, 16);
    p.sender = static_cast<uint16_t>(r.uint_in(1, 0xFFFE));
    p.receiver = static_cast<uint16_t>(r.uint_in(1, 0xFFFE));
    p.reply = r.boolean();
    p.credit = static_cast<uint8_t>(r.uint_in(0, 255));
    p.membership = r.uint_in(0, k_u63_max);
    LM_TRY(r.finish());
    std::copy(nonce.begin(), nonce.end(), p.nonce.begin());
    out = p;
    issuer.bytes = b.issuer;
    return Status::Ok;
}

// ---- mesh records ----
namespace {

// One field list per record (core/codec.hpp): it writes and reads the same layout.
template <class F> void io(F &f, Register &m) {
    f.is(Op::Register);
    f.u32(m.sequence);
    f.u16(m.parent);
    f.u32(m.parent_revision);
    f.u32(m.term);
}
template <class F> void io(F &f, Ready &m) {
    f.is(Op::Ready);
    f.u32(m.term);
    f.u32(m.revision);
    f.u64(m.credential_lease_ms);
}
template <class F> void io(F &f, LeaseRec &m) {
    f.is(Op::Lease);
    f.flag_en(m.push, m.status); // push and status share a byte
    f.u32(m.term);
    f.u32(m.revision);
    f.u32(m.lease_ms);
    f.u32(m.expected_revision);
    f.list(m.n, m.path);
}
template <class F> void io(F &f, Query &m) {
    f.is(Op::Query);
    f.u8(m.qid);
    f.raw(m.dest.bytes);
    f.u32(m.known_revision);
}
template <class F> void io(F &f, Answer &m) {
    f.is(Op::Answer);
    f.u8(m.qid);
    f.en(m.status);
    f.u16(m.dest);
    f.u32(m.revision);
    f.list(m.n, m.path);
}

// A path of at least `min` entries (0 allowed only when min is 0), simple.
bool path_min(uint8_t n, const std::array<uint16_t, k_max_root_path> &p, std::size_t min) {
    return n >= min && (n == 0 || path_ok(p.data(), n));
}
bool valid(const Register &m) { return is_valid_short_addr(ShortAddr{m.parent}); }
bool valid(const Ready &) { return true; }
bool valid(const LeaseRec &m) { return path_min(m.n, m.path, m.status == Status::Ok ? 2 : 0); }
bool valid(const Query &m) { return !m.dest.is_zero(); }
bool valid(const Answer &m) { return path_min(m.n, m.path, m.status == Status::Ok ? 1 : 0); }

} // namespace

template <class M> Status encode(const M &m, MutByteView out, std::size_t &len) {
    return put_record(m, out, len, [](auto &f, auto &r) { io(f, r); });
}

template <class M> Status decode(ByteView body, M &out) {
    M m;
    if (get_record(body, m, [](auto &f, auto &r) { io(f, r); }) != Status::Ok || !valid(m)) {
        return Status::BadFrame;
    }
    out = m;
    return Status::Ok;
}

#define LM_MESH_RECORD(T) \
    template Status encode<T>(const T &, MutByteView, std::size_t &); \
    template Status decode<T>(ByteView, T &);
LM_MESH_RECORD(Register)
LM_MESH_RECORD(Ready)
LM_MESH_RECORD(LeaseRec)
LM_MESH_RECORD(Query)
LM_MESH_RECORD(Answer)
#undef LM_MESH_RECORD

bool is_mesh_record(ByteView body) {
    return !body.empty() && ((body[0] >= static_cast<uint8_t>(Op::Register) && body[0] <= static_cast<uint8_t>(Op::Answer)) ||
                             body[0] == static_cast<uint8_t>(Op::Power)); // Power: the S16 schedule report
}

} // namespace lm::route
