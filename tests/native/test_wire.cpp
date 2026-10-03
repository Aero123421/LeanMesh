// Wire codecs (docs/09): strict CBOR vectors, golden 1/3/20/40-hop headers, every-length sweeps,
// R04 duplicate source route, control envelope and COSE structure. The C++/Python/fixture
// differential lives in host/tests/unit/test_wire_differential.py (it drives tools/lmtool).
#include <array>
#include <cstdint>
#include <vector>

#include "core/wire/cbor.hpp"
#include "core/wire/cbor_reader.hpp"
#include "core/wire/control.hpp"
#include "core/wire/frame.hpp"
#include "core/wire/power_frame.hpp"
#include "core/wire/serial_header.hpp"
#include "core/wire/transfer.hpp"
#include "gen/golden.hpp"
#include "lmtest.hpp"

using namespace lm;
using namespace lm::wire;
using Bytes = std::vector<uint8_t>;

namespace {

ByteView view(const Bytes &b) { return ByteView{b.data(), b.size()}; }
Bytes hex(const char *h) { return lmtest::from_hex(h); }

// A decoder accepts `valid` and rejects every shorter prefix and a one-byte extension. This is
// the "every length" sweep for length-exact layouts.
template <class Decode> void expect_only_exact_length(const Bytes &valid, Decode decode) {
    for (std::size_t n = 0; n < valid.size(); ++n) {
        LM_CHECK(decode(ByteView{valid.data(), n}) != Status::Ok);
    }
    LM_CHECK(decode(view(valid)) == Status::Ok);
    Bytes longer = valid;
    longer.push_back(0);
    LM_CHECK(decode(view(longer)) != Status::Ok);
}

Bytes make_route(std::initializer_list<uint16_t> path, uint16_t origin, uint16_t final_addr) {
    RouteHeader h;
    h.origin = origin;
    h.final = final_addr;
    h.path_len = static_cast<uint8_t>(path.size());
    h.budget = h.path_len;
    h.root_term = 1;
    h.path_revision = 1;
    std::size_t i = 0;
    for (const uint16_t a : path) {
        h.path[i++] = a;
    }
    Bytes out(k_route_header_bytes + 2 * k_max_path + k_end_header_bytes + k_tag_bytes, 0);
    std::size_t n = 0;
    LM_CHECK_OK(encode_route(h, MutByteView{out.data(), out.size()}, n));
    out.resize(n + k_end_header_bytes + k_tag_bytes, 0); // end record bytes are opaque to routing
    return out;
}

} // namespace

// ---- CBOR ----

LM_TEST("CBOR strict decoder accepts RFC 8949 Appendix A deterministic samples") {
    const char *ok[] = {"00",     "17",           "1818",           "1903e8",
                        "1a000f4240", "1b000000e8d4a51000", "20",   "3903e7",
                        "40",     "4401020304",   "60",             "6449455446",
                        "80",     "83010203",     "8301820203820405", "a0",
                        "a201020304", "a26161016162820203", "f4",   "f5",
                        "f6"};
    for (const char *h : ok) {
        LM_CHECK_OK(cbor_validate(view(hex(h))));
    }
}

LM_TEST("CBOR strict decoder rejects non-deterministic and unsupported encodings") {
    const char *bad[] = {
        "1800",               // non-minimal uint
        "190000",             // non-minimal 2-byte head
        "1a0000ffff",         // non-minimal 4-byte head
        "1b00000000ffffffff", // non-minimal 8-byte head
        "5800",               // non-minimal bstr length
        "9f01ff",             // indefinite array
        "5f4101ff",           // indefinite bstr
        "7f6161ff",           // indefinite tstr
        "f90000",             // float16
        "fa3f800000",         // float32
        "fb3ff0000000000000", // float64
        "f7",                 // undefined
        "f0",                 // simple(16)
        "f820",               // simple(32)
        "c074323030",         // tag 0
        "d2400000",           // tag 18: only the COSE parser strips it
        "a2010101",           // truncated map
        "a1010100",           // trailing byte after a map
        "a201020102",         // duplicate key 1
        "a202010101",         // unsorted keys 2, 1
        "a1f40100",           // key false (and trailing)
        "a1f401",             // key false: not uint/nint/bstr/tstr
        "a1810101",           // array as key
        "6180",               // lone UTF-8 continuation byte
        "62c0af",             // overlong '/'
        "63eda080",           // surrogate U+D800
        "64f4908080",         // U+110000
        "8301",               // truncated array
        "0000",               // trailing byte
        "",                   // empty
    };
    for (const char *h : bad) {
        LM_CHECK(cbor_validate(view(hex(h))) == Status::BadFrame);
    }
}

LM_TEST("CBOR nesting, array and map limits") {
    Bytes deep(k_cbor_max_depth, 0x81); // arrays at levels 0..15, leaf at level 16
    deep.push_back(0x00);
    LM_CHECK_OK(cbor_validate(view(deep)));
    Bytes too_deep(k_cbor_max_depth + 1, 0x81); // leaf at level 17
    too_deep.push_back(0x00);
    LM_CHECK(cbor_validate(view(too_deep)) == Status::BadFrame);

    Bytes arr = hex("991000"); // 4096 elements
    arr.resize(3 + 4096, 0x00);
    LM_CHECK_OK(cbor_validate(view(arr)));
    arr = hex("991001"); // 4097 elements
    arr.resize(3 + 4097, 0x00);
    LM_CHECK(cbor_validate(view(arr)) == Status::BadFrame);

    auto map_of = [](unsigned pairs) {
        Bytes m = {0xB8, static_cast<uint8_t>(pairs)};
        for (unsigned i = 0; i < pairs; ++i) {
            if (i < 24) {
                m.push_back(static_cast<uint8_t>(i));
            } else {
                m.push_back(0x18);
                m.push_back(static_cast<uint8_t>(i));
            }
            m.push_back(0x00);
        }
        return m;
    };
    LM_CHECK_OK(cbor_validate(view(map_of(128))));
    LM_CHECK(cbor_validate(view(map_of(129))) == Status::BadFrame);
}

// ---- golden frames (docs/09 §2, §5) ----

LM_TEST("golden 1/3/20/40-hop packets: link header, size and payload accounting") {
    for (const auto &f : gen::golden::k_frames) {
        const Bytes packet = hex(f.packet_hex);
        LinkHeader h;
        ByteView payload;
        LM_CHECK_OK(decode_link_frame(view(packet), h, payload));
        LM_CHECK(h.kind == FrameKind::Data);
        LM_CHECK_EQ(h.link_sid, 0x50607080u);
        LM_CHECK_EQ(h.link_counter, 1u);
        LM_CHECK_EQ(h.domain_hint, 0x10111213u);
        LM_CHECK(h.encrypted);
        LM_CHECK_EQ(h.body_length, 250u - 24u - 16u);
        LM_CHECK_EQ(payload.size(), 226u);
        LM_CHECK_EQ(data_capacity(f.hops), 136u - 2u * f.hops);
        LM_CHECK_EQ(hex(f.payload_hex).size(), data_capacity(f.hops));
        std::array<uint8_t, k_link_header_bytes> re{};
        LM_CHECK_OK(encode_link_header(h, MutByteView{re}));
        LM_CHECK(bytes_equal(ByteView{re}, view(packet).first(24)));
        // Every length 0..250: only the full packet is a frame.
        for (std::size_t n = 0; n <= 250; ++n) {
            LinkHeader x;
            ByteView p;
            const Status s = decode_link_frame(view(packet).first(n), x, p);
            LM_CHECK((s == Status::Ok) == (n == 250));
        }
    }
}

LM_TEST("link frame rules: version, kind, flags, session shape, lengths") {
    Bytes p = hex(gen::golden::k_frames[0].packet_hex);
    LinkHeader h;
    ByteView payload;
    auto with = [&](std::size_t idx, uint8_t v) {
        Bytes q = p;
        q[idx] = v;
        return decode_link_frame(view(q), h, payload);
    };
    LM_CHECK(with(0, 'X') == Status::BadFrame);      // magic
    LM_CHECK(with(2, 2) == Status::Unsupported);     // version
    LM_CHECK(with(3, 9) == Status::Unsupported);     // kind
    LM_CHECK(with(3, 0) == Status::Unsupported);
    LM_CHECK(with(22, 0) == Status::BadFrame);       // DATA must be encrypted
    LM_CHECK(with(22, 3) == Status::BadFrame);       // unknown flag bit
    LM_CHECK(with(23, 1) == Status::BadFrame);       // reserved
    {
        Bytes q = p;
        for (std::size_t i = 8; i < 12; ++i) {
            q[i] = 0;
        }
        LM_CHECK(decode_link_frame(view(q), h, payload) == Status::BadFrame); // DATA with SID 0
    }
    LM_CHECK(with(21, 0xD1) == Status::BadFrame);    // body_length mismatch
    Bytes zero_ctr = p;
    for (std::size_t i = 12; i < 20; ++i) {
        zero_ctr[i] = 0;
    }
    LM_CHECK(decode_link_frame(view(zero_ctr), h, payload) == Status::BadFrame);
    LM_CHECK(decode_link_frame(view(Bytes(251, 0)), h, payload) == Status::BadFrame);

    // SID-0 kinds are plain; an encrypted DISCOVERY is refused, so is a plain one with a SID.
    LinkHeader d;
    d.kind = FrameKind::Discovery;
    d.encrypted = false;
    d.body_length = 8;
    Bytes disc(24 + 8, 0);
    LM_CHECK_OK(encode_link_header(d, MutByteView{disc.data(), 24}));
    LM_CHECK_OK(decode_link_frame(view(disc), h, payload));
    disc[11] = 1; // link_sid = 1
    LM_CHECK(decode_link_frame(view(disc), h, payload) == Status::BadFrame);
}

// ---- R04 ----

LM_TEST("R04 duplicate source route is rejected at the codec, however valid the AEAD would be") {
    Bytes ok = make_route({3, 4, 5}, 2, 5);
    RouteHeader h;
    ByteView end;
    LM_CHECK_OK(decode_route(view(ok), h, end));
    LM_CHECK_EQ(end.size(), k_end_header_bytes + k_tag_bytes);
    LM_CHECK(decode_route(view(make_route({3, 4, 3, 5}, 2, 5)), h, end) == Status::BadFrame);
    LM_CHECK(decode_route(view(make_route({3, 4, 4}, 2, 4)), h, end) == Status::BadFrame);
    LM_CHECK(decode_route(view(make_route({2, 5}, 2, 5)), h, end) == Status::BadFrame); // origin in path
    LM_CHECK(decode_route(view(make_route({3, 0, 5}, 2, 5)), h, end) == Status::BadFrame);
    LM_CHECK(decode_route(view(make_route({3, 0xFFFF, 5}, 2, 5)), h, end) == Status::BadFrame);
    LM_CHECK(decode_route(view(make_route({3, 4, 5}, 2, 4)), h, end) == Status::BadFrame); // final
    LM_CHECK(decode_route(view(make_route({3, 4, 5}, 0, 5)), h, end) == Status::BadFrame);
    // path_len > 40, next_index >= path_len, budget != remaining hops, reserved != 0.
    Bytes v = ok;
    v[4] = 41;
    LM_CHECK(decode_route(view(v), h, end) == Status::BadFrame);
    v = ok;
    v[5] = 3;
    LM_CHECK(decode_route(view(v), h, end) == Status::BadFrame);
    v = ok;
    v[6] = 2;
    LM_CHECK(decode_route(view(v), h, end) == Status::BadFrame);
    v = ok;
    v[7] = 1;
    LM_CHECK(decode_route(view(v), h, end) == Status::BadFrame);
    // A 40-hop simple path is fine; 41 addresses of a 40-hop route are refused by path_len.
    RouteHeader long_route;
    long_route.origin = 1;
    long_route.path_len = 40;
    long_route.budget = 40;
    for (uint16_t i = 0; i < 40; ++i) {
        long_route.path[i] = static_cast<uint16_t>(i + 2);
    }
    long_route.final = 41;
    Bytes big(k_route_header_bytes + 80 + 58, 0);
    std::size_t n = 0;
    LM_CHECK_OK(encode_route(long_route, MutByteView{big.data(), big.size()}, n));
    LM_CHECK_OK(decode_route(view(big), h, end));
}

// ---- end record, HOP_ACK, fragments, bitmap, bootstrap ----

LM_TEST("end record header: exact length, flags, kinds, ports") {
    EndHeader e;
    e.end_sid = 7;
    e.end_counter = 9;
    e.app_port = 5;
    e.flags = make_end_flags(Delivery::Applied, Priority::Urgent, true);
    e.plaintext_length = 3;
    Bytes rec(k_end_header_bytes + 3 + k_tag_bytes, 0xAA);
    LM_CHECK_OK(encode_end_header(e, MutByteView{rec.data(), k_end_header_bytes}));
    EndHeader d;
    ByteView sealed;
    LM_CHECK_OK(decode_end_record(view(rec), d, sealed));
    LM_CHECK(d.delivery() == Delivery::Applied && d.priority() == Priority::Urgent && d.durable());
    LM_CHECK_EQ(sealed.size(), 19u);
    expect_only_exact_length(rec, [](ByteView b) {
        EndHeader x;
        ByteView s;
        return decode_end_record(b, x, s);
    });
    auto mutated = [&](EndHeader m) {
        Bytes r = rec;
        LM_CHECK_OK(encode_end_header(m, MutByteView{r.data(), k_end_header_bytes}));
        EndHeader x;
        ByteView s;
        return decode_end_record(view(r), x, s);
    };
    EndHeader m = e;
    m.flags = 0xE0;
    LM_CHECK(mutated(m) == Status::BadFrame);
    m = e;
    m.flags = 3;
    LM_CHECK(mutated(m) == Status::BadFrame); // delivery 3
    m = e;
    m.app_port = 0;
    LM_CHECK(mutated(m) == Status::BadFrame); // DATA needs an app port
    m.record_kind = RecordKind::Control;
    LM_CHECK(mutated(m) == Status::Ok); // port 0 is SDK control
    m.app_port = 65535;
    LM_CHECK(mutated(m) == Status::BadFrame);
    m = e;
    m.end_sid = 0;
    LM_CHECK(mutated(m) == Status::BadFrame);
    m = e;
    m.end_counter = 0;
    LM_CHECK(mutated(m) == Status::BadFrame);
    m = e;
    m.record_kind = static_cast<RecordKind>(6);
    LM_CHECK(mutated(m) == Status::BadFrame);
    m = e;
    m.record_kind = RecordKind::TransferBitmap;
    LM_CHECK(mutated(m) == Status::BadFrame); // kind 5 must be 35 plaintext bytes
}

LM_TEST("HOP_ACK plaintext and frame accounting") {
    HopAck a;
    a.acked_link_counter = 0x0102030405060708ULL;
    a.status = HopAckStatus::Busy;
    a.credit = 3;
    a.retry_after_ms = 250;
    Bytes b(12);
    std::size_t n = 0;
    LM_CHECK_OK(encode_hop_ack(a, MutByteView{b.data(), b.size()}, n));
    LM_CHECK_EQ(n, 12u);
    LM_CHECK_EQ(b[0], 1u);
    LM_CHECK_EQ(b[8], 1u);
    expect_only_exact_length(b, [](ByteView v) {
        HopAck x;
        return decode_hop_ack(v, x);
    });
    b[8] = 3;
    HopAck x;
    LM_CHECK(decode_hop_ack(view(b), x) == Status::BadFrame);
    // Frame level: HOP_ACK is 24 + 12 + 16 = 52 bytes, and no other body length.
    LinkHeader h;
    h.kind = FrameKind::HopAck;
    h.link_sid = 5;
    h.link_counter = 1;
    h.body_length = 12;
    Bytes frame(52, 0);
    LM_CHECK_OK(encode_link_header(h, MutByteView{frame.data(), 24}));
    ByteView payload;
    LinkHeader d;
    LM_CHECK_OK(decode_link_frame(view(frame), d, payload));
    h.body_length = 13;
    Bytes frame13(53, 0);
    LM_CHECK_OK(encode_link_header(h, MutByteView{frame13.data(), 24}));
    LM_CHECK(decode_link_frame(view(frame13), d, payload) == Status::BadFrame);
}

LM_TEST("fragment prefix: quanta, bounds, kinds; chunk sizes for 1/20/40 hops") {
    LM_CHECK_EQ(fragment_chunk(1), 80u);
    LM_CHECK_EQ(fragment_chunk(20), 48u);
    LM_CHECK_EQ(fragment_chunk(40), 16u);
    FragmentPrefix p;
    p.total_len = 200;
    p.offset = 80;
    p.fragment_len = 80;
    p.original_kind = RecordKind::Control;
    p.object_class = ObjectClass::Control;
    p.intent_hash.fill(0x5A);
    Bytes rec(k_fragment_prefix_bytes + 80, 1);
    LM_CHECK_OK(encode_fragment_prefix(p, MutByteView{rec.data(), k_fragment_prefix_bytes}));
    FragmentPrefix d;
    ByteView bytes;
    LM_CHECK_OK(decode_fragment(view(rec), d, bytes));
    LM_CHECK_EQ(bytes.size(), 80u);
    expect_only_exact_length(rec, [](ByteView b) {
        FragmentPrefix x;
        ByteView y;
        return decode_fragment(b, x, y);
    });
    auto with = [&](FragmentPrefix m, std::size_t body) {
        Bytes r(k_fragment_prefix_bytes + body, 1);
        LM_CHECK_OK(encode_fragment_prefix(m, MutByteView{r.data(), k_fragment_prefix_bytes}));
        FragmentPrefix x;
        ByteView y;
        return decode_fragment(view(r), x, y);
    };
    FragmentPrefix m = p;
    m.offset = 8; // not a multiple of 16
    LM_CHECK(with(m, 80) == Status::BadFrame);
    m = p;
    m.fragment_len = 72; // non-final chunk not a multiple of 16
    m.offset = 0;
    LM_CHECK(with(m, 72) == Status::BadFrame);
    m.total_len = 72; // the final chunk may be a fraction
    LM_CHECK(with(m, 72) == Status::Ok);
    m = p;
    m.original_kind = RecordKind::Fragment; // no recursive fragmentation
    LM_CHECK(with(m, 80) == Status::BadFrame);
    m = p;
    m.total_len = 4097;
    LM_CHECK(with(m, 80) == Status::BadFrame);
    m = p;
    m.total_len = 513;
    m.object_class = ObjectClass::Small;
    LM_CHECK(with(m, 80) == Status::BadFrame);
    m = p;
    m.offset = 176;
    LM_CHECK(with(m, 80) == Status::BadFrame); // beyond total
    LM_CHECK(with(p, 79) == Status::BadFrame); // length disagrees with the bytes present
}

LM_TEST("transfer bitmap: layout, bit order, base_offset") {
    TransferBitmap b;
    b.credit = 4;
    bitmap_set(b, 0);
    bitmap_set(b, 16 * 9);
    bitmap_set(b, 4095);
    LM_CHECK(bitmap_test(b, 0) && bitmap_test(b, 144) && bitmap_test(b, 4080));
    LM_CHECK(!bitmap_test(b, 16) && !bitmap_test(b, 4096));
    LM_CHECK_EQ(b.bitmap[0], 1u);
    LM_CHECK_EQ(b.bitmap[1], 2u);
    Bytes rec(k_transfer_bitmap_body);
    LM_CHECK_OK(encode_transfer_bitmap(b, MutByteView{rec.data(), rec.size()}));
    expect_only_exact_length(rec, [](ByteView v) {
        TransferBitmap x;
        return decode_transfer_bitmap(v, x);
    });
    rec[1] = 1; // base_offset must be 0
    TransferBitmap x;
    LM_CHECK(decode_transfer_bitmap(view(rec), x) == Status::BadFrame);
}

LM_TEST("bootstrap carrier: 160 B body fits an unencrypted SID-0 frame") {
    BootstrapCarrier c;
    c.exchange_id.fill(9);
    c.object_kind = 2;
    c.total = 1024;
    c.offset = 864;
    Bytes body(160, 0x42);
    c.body = view(body);
    Bytes rec(k_bootstrap_header_bytes + 160);
    std::size_t n = 0;
    LM_CHECK_OK(encode_bootstrap(c, MutByteView{rec.data(), rec.size()}, n));
    BootstrapCarrier d;
    LM_CHECK_OK(decode_bootstrap(view(rec), d));
    LM_CHECK_EQ(d.body.size(), 160u);
    LM_CHECK_EQ(24 + rec.size(), 207u);
    expect_only_exact_length(rec, [](ByteView v) {
        BootstrapCarrier x;
        return decode_bootstrap(v, x);
    });
    c.offset = 865; // offset + length > total
    LM_CHECK_OK(encode_bootstrap(c, MutByteView{rec.data(), rec.size()}, n));
    LM_CHECK(decode_bootstrap(view(rec), d) == Status::BadFrame);
    c.offset = 0;
    c.total = 1025;
    LM_CHECK_OK(encode_bootstrap(c, MutByteView{rec.data(), rec.size()}, n));
    LM_CHECK(decode_bootstrap(view(rec), d) == Status::BadFrame);
}

// ---- serial header, power ----

LM_TEST("serial record: CRC, kinds, length rules, 8230-byte ceiling") {
    SerialHeader h;
    h.kind = SerialKind::Request;
    h.session_id = 0xA1B2C3D4;
    h.counter = 42;
    h.payload_len = 8192;
    Bytes body(8192 + 16, 0x11);
    Bytes frame(8230);
    std::size_t n = 0;
    LM_CHECK_OK(encode_serial_frame(h, view(body), MutByteView{frame.data(), frame.size()}, n));
    LM_CHECK_EQ(n, gen::limits::serial_decoded_bytes);
    SerialHeader d;
    ByteView out;
    LM_CHECK_OK(decode_serial_frame(ByteView{frame.data(), n}, d, out));
    LM_CHECK_EQ(out.size(), body.size());
    LM_CHECK_EQ(crc32_iso_hdlc(view(hex("313233343536373839"))), 0xCBF43926u); // CRC-32 check value
    Bytes bad = frame;
    bad[100] ^= 1U; // CRC catches corruption
    LM_CHECK(decode_serial_frame(ByteView{bad.data(), n}, d, out) == Status::BadFrame);
    LM_CHECK(decode_serial_frame(ByteView{frame.data(), n - 1}, d, out) == Status::BadFrame);

    // HELLO/EDHOC: no tag, at most 1024 payload bytes; everything else carries a tag.
    h.kind = SerialKind::Hello;
    h.payload_len = 1025;
    Bytes big(1025);
    Bytes f2(18 + 1025 + 4);
    LM_CHECK_OK(encode_serial_frame(h, view(big), MutByteView{f2.data(), f2.size()}, n));
    LM_CHECK(decode_serial_frame(ByteView{f2.data(), n}, d, out) == Status::BadFrame);
    h.payload_len = 1024;
    Bytes ok(1024);
    LM_CHECK_OK(encode_serial_frame(h, view(ok), MutByteView{f2.data(), f2.size()}, n));
    LM_CHECK_OK(decode_serial_frame(ByteView{f2.data(), n}, d, out));
    LM_CHECK(encode_serial_frame(h, view(Bytes(1023)), MutByteView{f2.data(), f2.size()}, n) ==
             Status::InvalidArgument);
    // version and kind
    f2[2] = 2;
    LM_CHECK(decode_serial_frame(ByteView{f2.data(), n}, d, out) == Status::Unsupported);
}

LM_TEST("power poll/grant golden bytes and semantic pairing") {
    const Bytes poll = hex(gen::golden::power::poll_hex);
    const Bytes grant = hex(gen::golden::power::grant_hex);
    LM_CHECK_EQ(poll.size(), 28u);
    LM_CHECK_EQ(grant.size(), 24u);
    PowerPoll p;
    PowerGrant g;
    LM_CHECK_OK(decode_power_poll(view(poll), p));
    LM_CHECK_OK(decode_power_grant(view(grant), g));
    LM_CHECK_EQ(p.rx_credit, 2u);
    LM_CHECK_EQ(p.poll_nonce, 1u);
    LM_CHECK_EQ(p.planned_interval_ms, 5000u);
    LM_CHECK_EQ(p.window_ms, 250u);
    LM_CHECK_EQ(g.window_ttl_ms, 200u);
    LM_CHECK_EQ(g.granted_credit, 2u);
    LM_CHECK_OK(check_grant_against_poll(p, g));
    Bytes re(28);
    std::size_t n = 0;
    LM_CHECK_OK(encode_power_poll(p, MutByteView{re.data(), re.size()}, n));
    LM_CHECK(re == poll);
    re.resize(24);
    LM_CHECK_OK(encode_power_grant(g, MutByteView{re.data(), re.size()}, n));
    LM_CHECK(re == grant);
    g.granted_credit = 3;
    LM_CHECK(check_grant_against_poll(p, g) != Status::Ok);
    g.granted_credit = 2;
    g.window_ttl_ms = 251;
    LM_CHECK(check_grant_against_poll(p, g) != Status::Ok);
    g.window_ttl_ms = 200;
    g.poll_nonce = 2;
    LM_CHECK(check_grant_against_poll(p, g) != Status::Ok);
    expect_only_exact_length(poll, [](ByteView v) {
        PowerPoll x;
        return decode_power_poll(v, x);
    });
    expect_only_exact_length(grant, [](ByteView v) {
        PowerGrant x;
        return decode_power_grant(v, x);
    });
    Bytes flags = poll;
    flags[23] = 1; // flags != 0 rejected
    LM_CHECK(decode_power_poll(view(flags), p) == Status::BadFrame);
    Bytes ver = poll;
    ver[1] = 2;
    LM_CHECK(decode_power_poll(view(ver), p) == Status::Unsupported);
}

// ---- control envelope and COSE ----

LM_TEST("golden COSE_Sign1 and control-body parse; Sig_structure matches the fixture") {
    namespace c = gen::golden::cose;
    const Bytes cose = hex(c::cose_sign1_hex);
    CoseSign1 s;
    LM_CHECK_OK(decode_cose_sign1(view(cose), s));
    LM_CHECK(bytes_equal(ByteView{s.kid}, view(hex(c::device_id_hex))));
    LM_CHECK(bytes_equal(s.protected_bytes, view(hex(c::protected_hex))));
    LM_CHECK(bytes_equal(s.payload, view(hex(c::payload_hex))));
    LM_CHECK(bytes_equal(s.signature, view(hex(c::signature_raw_hex))));

    std::array<uint8_t, k_sig_prefix_max> prefix{};
    std::size_t pn = 0;
    LM_CHECK_OK(sig_structure_prefix(s.protected_bytes, s.payload.size(), MutByteView{prefix}, pn));
    Bytes tbs(prefix.begin(), prefix.begin() + static_cast<long>(pn));
    tbs.insert(tbs.end(), s.payload.begin(), s.payload.end());
    LM_CHECK(tbs == hex(c::sig_structure_hex));

    Bytes re(cose.size());
    std::size_t n = 0;
    LM_CHECK_OK(encode_cose_sign1(s.kid, s.payload, s.signature, MutByteView{re.data(), re.size()}, n));
    LM_CHECK(re == cose);

    // The payload is an AssignmentTicket (type 3): a signed type, so only the COSE carrier fits.
    ControlBody b;
    LM_CHECK_OK(decode_control_body(s.payload, ControlCarrier::Signed, b));
    LM_CHECK_EQ(b.type, 3u);
    LM_CHECK(decode_control_body(s.payload, ControlCarrier::Session, b) == Status::AuthRejected);
    Bytes rebuilt(s.payload.size());
    LM_CHECK_OK(decode_control_body(s.payload, ControlCarrier::Signed, b));
    LM_CHECK_OK(encode_control_body(b, MutByteView{rebuilt.data(), rebuilt.size()}, n));
    LM_CHECK(bytes_equal(ByteView{rebuilt.data(), n}, s.payload));

    expect_only_exact_length(cose, [](ByteView v) {
        CoseSign1 x;
        return decode_cose_sign1(v, x);
    });
    Bytes tampered = cose;
    tampered[0] = 0xD1; // wrong tag
    LM_CHECK(decode_cose_sign1(view(tampered), s) == Status::BadFrame);
    tampered = cose;
    tampered[6] = 0x21; // protected header altered (still 38 bytes): alg -2 instead of -7
    LM_CHECK(decode_cose_sign1(view(tampered), s) == Status::BadFrame);
}

LM_TEST("control types: 22..24 and undefined types rejected, session vs signed carrier") {
    // Minimal valid Probe (type 16): [16,1,id16,domain,rev,issuer,[nonce,1,2,false,0,0]].
    auto probe = [](uint8_t type, uint8_t version) {
        Bytes out(256);
        CborWriter w{MutByteView{out.data(), out.size()}};
        const std::array<uint8_t, 32> id{};
        w.array(7);
        w.uint(type);
        w.uint(version);
        w.bytes(ByteView{id.data(), 16});
        w.bytes(ByteView{id.data(), 16});
        w.uint(1);
        w.bytes(ByteView{id});
        w.array(6);
        w.bytes(ByteView{id.data(), 16});
        w.uint(1);
        w.uint(2);
        w.boolean(false);
        w.uint(0);
        w.uint(0);
        LM_CHECK_OK(w.finish());
        out.resize(w.size());
        return out;
    };
    ControlBody b;
    LM_CHECK_OK(decode_control_body(view(probe(16, 1)), ControlCarrier::Session, b));
    LM_CHECK(decode_control_body(view(probe(16, 1)), ControlCarrier::Signed, b) ==
             Status::AuthRejected);
    for (const uint8_t t : {0, 22, 23, 24, 34, 200}) {
        LM_CHECK(decode_control_body(view(probe(t, 1)), ControlCarrier::Session, b) ==
                 Status::Unsupported);
        LM_CHECK(!is_control_type_defined(t));
    }
    LM_CHECK(decode_control_body(view(probe(16, 2)), ControlCarrier::Session, b) ==
             Status::Unsupported);
    // data of another type's shape is refused even though it is valid CBOR (no cross product).
    Bytes wrong = probe(15, 1); // RouteQuery expects [id32, u32]
    LM_CHECK(decode_control_body(view(wrong), ControlCarrier::Session, b) == Status::BadFrame);
    for (uint8_t t = 1; t <= 33; ++t) {
        LM_CHECK_EQ(is_control_type_defined(t), t != 22 && t != 23 && t != 24);
    }
    for (const uint8_t t : gen::k_signed_control_types) {
        LM_CHECK(is_signed_control_type(t) && is_control_type_defined(t));
    }
}

LM_TEST_MAIN()
