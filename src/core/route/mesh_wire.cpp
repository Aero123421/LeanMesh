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

namespace {

void put_path(Writer &w, const uint16_t *p, std::size_t n) {
    w.u8(static_cast<uint8_t>(n));
    for (std::size_t i = 0; i < n; ++i) {
        w.u16be(p[i]);
    }
}

// n path entries (n >= min, 0 allowed only when min is 0), simple and bounded.
bool get_path(Reader &r, uint8_t &n, std::array<uint16_t, k_max_root_path> &p, std::size_t min) {
    n = r.u8();
    if (n < min || n > k_max_root_path) {
        return false;
    }
    for (std::size_t i = 0; i < n; ++i) {
        p[i] = r.u16be();
    }
    return r.ok() && (n == 0 || path_ok(p.data(), n));
}

Status finish(const Writer &w, std::size_t &len) {
    len = w.size();
    return w.finish();
}

} // namespace

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
Status encode(const Register &m, MutByteView out, std::size_t &len) {
    Writer w{out};
    w.u8(static_cast<uint8_t>(Op::Register));
    w.u32be(m.sequence);
    w.u16be(m.parent);
    w.u32be(m.parent_revision);
    w.u32be(m.term);
    return finish(w, len);
}
Status encode(const Ready &m, MutByteView out, std::size_t &len) {
    Writer w{out};
    w.u8(static_cast<uint8_t>(Op::Ready));
    w.u32be(m.term);
    w.u32be(m.revision);
    return finish(w, len);
}
Status encode(const LeaseRec &m, MutByteView out, std::size_t &len) {
    Writer w{out};
    w.u8(static_cast<uint8_t>(Op::Lease));
    w.u8(static_cast<uint8_t>((m.push ? 0x80 : 0) | static_cast<uint8_t>(m.status)));
    w.u32be(m.term);
    w.u32be(m.revision);
    w.u32be(m.lease_ms);
    w.u32be(m.expected_revision);
    put_path(w, m.path.data(), m.n);
    return finish(w, len);
}
Status encode(const Query &m, MutByteView out, std::size_t &len) {
    Writer w{out};
    w.u8(static_cast<uint8_t>(Op::Query));
    w.u8(m.qid);
    w.bytes(m.dest.view());
    w.u32be(m.known_revision);
    return finish(w, len);
}
Status encode(const Answer &m, MutByteView out, std::size_t &len) {
    Writer w{out};
    w.u8(static_cast<uint8_t>(Op::Answer));
    w.u8(m.qid);
    w.u8(static_cast<uint8_t>(m.status));
    w.u16be(m.dest);
    w.u32be(m.revision);
    put_path(w, m.path.data(), m.n);
    return finish(w, len);
}

bool is_mesh_record(ByteView body) {
    return !body.empty() && ((body[0] >= static_cast<uint8_t>(Op::Register) && body[0] <= static_cast<uint8_t>(Op::Answer)) ||
                             body[0] == static_cast<uint8_t>(Op::Power)); // Power: the S16 schedule report
}

namespace {
bool op_is(Reader &r, Op op) { return r.u8() == static_cast<uint8_t>(op); }
} // namespace

Status decode(ByteView body, Register &out) {
    Reader r{body};
    Register m;
    const bool op = op_is(r, Op::Register);
    m.sequence = r.u32be();
    m.parent = r.u16be();
    m.parent_revision = r.u32be();
    m.term = r.u32be();
    LM_TRY(r.finish());
    if (!op || !is_valid_short_addr(ShortAddr{m.parent})) {
        return Status::BadFrame;
    }
    out = m;
    return Status::Ok;
}
Status decode(ByteView body, Ready &out) {
    Reader r{body};
    Ready m;
    const bool op = op_is(r, Op::Ready);
    m.term = r.u32be();
    m.revision = r.u32be();
    LM_TRY(r.finish());
    if (!op) {
        return Status::BadFrame;
    }
    out = m;
    return Status::Ok;
}
Status decode(ByteView body, LeaseRec &out) {
    Reader r{body};
    LeaseRec m;
    const bool op = op_is(r, Op::Lease);
    const uint8_t st = r.u8();
    m.push = (st & 0x80) != 0;
    m.status = static_cast<Status>(st & 0x7F);
    m.term = r.u32be();
    m.revision = r.u32be();
    m.lease_ms = r.u32be();
    m.expected_revision = r.u32be();
    const bool path = get_path(r, m.n, m.path, m.status == Status::Ok ? 2 : 0);
    LM_TRY(r.finish());
    if (!op || !path) {
        return Status::BadFrame;
    }
    out = m;
    return Status::Ok;
}
Status decode(ByteView body, Query &out) {
    Reader r{body};
    Query m;
    const bool op = op_is(r, Op::Query);
    m.qid = r.u8();
    r.copy_to(m.dest.bytes);
    m.known_revision = r.u32be();
    LM_TRY(r.finish());
    if (!op || m.dest.is_zero()) {
        return Status::BadFrame;
    }
    out = m;
    return Status::Ok;
}
Status decode(ByteView body, Answer &out) {
    Reader r{body};
    Answer m;
    const bool op = op_is(r, Op::Answer);
    m.qid = r.u8();
    m.status = static_cast<Status>(r.u8());
    m.dest = r.u16be();
    m.revision = r.u32be();
    const bool path = get_path(r, m.n, m.path, m.status == Status::Ok ? 1 : 0);
    LM_TRY(r.finish());
    if (!op || !path) {
        return Status::BadFrame;
    }
    out = m;
    return Status::Ok;
}

} // namespace lm::route
