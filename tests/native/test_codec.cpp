// Byte-exact golden encodings of the compact fixed-layout records (mesh records, power report/policy, POWER poll/grant,
// ledger entry/manifest, trust anchor, revocation floors, channel records). The expected bytes are built field by
// field with an independent big-endian builder (not the codec under test), so a refactor of the codecs is proven
// byte-identical; every decoder is also fed each truncation, one extra byte and out-of-range fields.
#include <cstring>
#include <vector>

#include "core/channel/wire.hpp"
#include "core/codec.hpp"
#include "core/member/records.hpp"
#include "core/power/power_wire.hpp"
#include "core/route/mesh_wire.hpp"
#include "core/wire/power_frame.hpp"
#include "lmtest.hpp"
#include "root/ledger.hpp"
#include "root/ledger_internal.hpp"
#include "security/crypto.hpp"

using namespace lm;

namespace {

using Bytes = std::vector<uint8_t>;

// Independent expected-bytes builder: network byte order, one call per field.
struct Be {
    Bytes v;
    Be &put(uint64_t x, int n) {
        for (int i = n - 1; i >= 0; --i) {
            v.push_back(static_cast<uint8_t>(x >> (8 * i)));
        }
        return *this;
    }
    Be &u8(uint64_t x) { return put(x, 1); }
    Be &u16(uint64_t x) { return put(x, 2); }
    Be &u32(uint64_t x) { return put(x, 4); }
    Be &u64(uint64_t x) { return put(x, 8); }
    template <std::size_t N> Be &raw(const std::array<uint8_t, N> &a) {
        v.insert(v.end(), a.begin(), a.end());
        return *this;
    }
};

template <std::size_t N> std::array<uint8_t, N> pattern(uint8_t seed) {
    std::array<uint8_t, N> a{};
    for (std::size_t i = 0; i < N; ++i) {
        a[i] = static_cast<uint8_t>(seed + 7 * i);
    }
    return a;
}

ByteView view(const Bytes &b) { return ByteView{b.data(), b.size()}; }

// Encodes with `enc` and compares the output with `want` byte for byte.
template <class Enc> bool encodes_to(Enc enc, const Bytes &want) {
    std::array<uint8_t, 700> buf{};
    std::size_t len = 0;
    if (enc(MutByteView{buf}, len) != Status::Ok || len != want.size()) {
        return false;
    }
    return std::memcmp(buf.data(), want.data(), len) == 0;
}

// Every strict prefix and one trailing byte are refused by `dec` (returns the decoder's Status).
template <class Dec> bool strict_length(const Bytes &good, Dec dec) {
    for (std::size_t n = 0; n < good.size(); ++n) {
        if (dec(ByteView{good.data(), n}) == Status::Ok) {
            return false;
        }
    }
    Bytes longer = good;
    longer.push_back(0);
    return dec(view(longer)) != Status::Ok;
}

} // namespace

// ---- mesh records (route/mesh_wire.cpp) ----
LM_TEST("review G02 codec golden: DRAIN control is byte-exact, bounded, and distinguishes cancel ACK") {
    route::DrainRequest q{0x01020304, 30000, 0};
    const Bytes request = Be{}.u8(0xEF).u32(q.sequence).u32(30000).u8(0).v;
    LM_CHECK(
        encodes_to([&](MutByteView o, std::size_t &l) { return route::encode(q, o, l); }, request));
    LM_CHECK(strict_length(request, [](ByteView b) {
        route::DrainRequest x;
        return route::decode(b, x);
    }));
    route::DrainRequest decoded;
    LM_CHECK_OK(route::decode(view(request), decoded));
    LM_CHECK_EQ(decoded.remaining_ms, 30000u);
    for (const Bytes &bad :
         {Be{}.u8(0xEF).u32(0).u32(30000).u8(0).v, Be{}.u8(0xEF).u32(1).u32(30001).u8(0).v,
          Be{}.u8(0xEF).u32(1).u32(30000).u8(2).v}) {
        LM_CHECK(route::decode(view(bad), decoded) == Status::BadFrame);
    }
    for (const uint8_t cancel : {uint8_t{0}, uint8_t{1}}) {
        route::DrainStatus s{q.sequence, 7, Status::Ok, cancel};
        const Bytes status = Be{}.u8(0xF0).u32(q.sequence).u32(7).u8(0).u8(cancel).v;
        LM_CHECK(encodes_to([&](MutByteView o, std::size_t &l) { return route::encode(s, o, l); },
                            status));
        route::DrainStatus decoded_status;
        LM_CHECK_OK(route::decode(view(status), decoded_status));
        LM_CHECK_EQ(decoded_status.cancel, cancel);
        LM_CHECK(strict_length(status, [](ByteView b) {
            route::DrainStatus x;
            return route::decode(b, x);
        }));
    }
    route::DrainNotice n{7, 2};
    const Bytes notice = Be{}.u8(0xF1).u32(7).u16(2).v;
    LM_CHECK(
        encodes_to([&](MutByteView o, std::size_t &l) { return route::encode(n, o, l); }, notice));
    LM_CHECK(strict_length(notice, [](ByteView b) {
        route::DrainNotice x;
        return route::decode(b, x);
    }));
}

LM_TEST("codec golden: mesh REGISTER / READY / QUERY are byte-exact and strict") {
    route::Register rg;
    rg.sequence = 0x01020304;
    rg.parent = 0x0A0B;
    rg.parent_revision = 0x11223344;
    rg.term = 7;
    const Bytes rg_bytes = Be{}.u8(0xE1).u32(0x01020304).u16(0x0A0B).u32(0x11223344).u32(7).v;
    LM_CHECK(encodes_to([&](MutByteView o, std::size_t &l) { return route::encode(rg, o, l); }, rg_bytes));
    route::Register rg2;
    LM_CHECK_OK(route::decode(view(rg_bytes), rg2));
    LM_CHECK(rg2.sequence == rg.sequence && rg2.parent == rg.parent && rg2.parent_revision == rg.parent_revision &&
             rg2.term == rg.term);
    LM_CHECK(strict_length(rg_bytes, [](ByteView b) {
        route::Register x;
        return route::decode(b, x);
    }));
    for (const uint16_t bad : {uint16_t{0}, uint16_t{0xFFFF}}) { // the parent must be a valid short address
        Bytes b = Be{}.u8(0xE1).u32(1).u16(bad).u32(1).u32(1).v;
        route::Register x;
        LM_CHECK(route::decode(view(b), x) == Status::BadFrame);
    }
    Bytes wrong_op = rg_bytes;
    wrong_op[0] = 0xE3;
    LM_CHECK(route::decode(view(wrong_op), rg2) == Status::BadFrame);

    for (const uint64_t lease : {uint64_t{0}, uint64_t{0x0102030405060708}, UINT64_MAX}) { // ARCH2-D1 meanings
        route::Ready rd;
        rd.term = 0xA1B2C3D4;
        rd.revision = 9;
        rd.credential_lease_ms = lease;
        const Bytes rd_bytes = Be{}.u8(0xE3).u32(0xA1B2C3D4).u32(9).u64(lease).v;
        LM_CHECK(encodes_to([&](MutByteView o, std::size_t &l) { return route::encode(rd, o, l); }, rd_bytes));
        route::Ready rd2;
        LM_CHECK_OK(route::decode(view(rd_bytes), rd2));
        LM_CHECK(rd2.term == rd.term && rd2.revision == rd.revision && rd2.credential_lease_ms == lease);
        LM_CHECK(strict_length(rd_bytes, [](ByteView b) {
            route::Ready x;
            return route::decode(b, x);
        }));
    }

    route::Query q;
    q.qid = 0x42;
    q.dest.bytes = pattern<32>(3);
    q.known_revision = 0x55667788;
    const Bytes q_bytes = Be{}.u8(0xE4).u8(0x42).raw(q.dest.bytes).u32(0x55667788).v;
    LM_CHECK(encodes_to([&](MutByteView o, std::size_t &l) { return route::encode(q, o, l); }, q_bytes));
    route::Query q2;
    LM_CHECK_OK(route::decode(view(q_bytes), q2));
    LM_CHECK(q2.qid == q.qid && q2.dest == q.dest && q2.known_revision == q.known_revision);
    LM_CHECK(strict_length(q_bytes, [](ByteView b) {
        route::Query x;
        return route::decode(b, x);
    }));
    const Bytes zero_dest = Be{}.u8(0xE4).u8(1).raw(std::array<uint8_t, 32>{}).u32(1).v;
    LM_CHECK(route::decode(view(zero_dest), q2) == Status::BadFrame);
}

LM_TEST("codec golden: mesh LEASE / ANSWER with paths are byte-exact; path rules refuse") {
    route::LeaseRec l;
    l.status = Status::Ok;
    l.push = true;
    l.term = 3;
    l.revision = 0x01000002;
    l.lease_ms = 180000;
    l.expected_revision = 0xDEADBEEF;
    l.n = 3;
    l.path[0] = 1;
    l.path[1] = 0x1234;
    l.path[2] = 0x0077;
    const Bytes l_bytes =
        Be{}.u8(0xE2).u8(0x80).u32(3).u32(0x01000002).u32(180000).u32(0xDEADBEEF).u8(3).u16(1).u16(0x1234).u16(0x77).v;
    LM_CHECK(encodes_to([&](MutByteView o, std::size_t &len) { return route::encode(l, o, len); }, l_bytes));
    route::LeaseRec l2;
    LM_CHECK_OK(route::decode(view(l_bytes), l2));
    LM_CHECK(l2.status == Status::Ok && l2.push && l2.term == 3 && l2.revision == l.revision && l2.lease_ms == 180000 &&
             l2.expected_revision == 0xDEADBEEF && l2.n == 3 && l2.path[0] == 1 && l2.path[1] == 0x1234 &&
             l2.path[2] == 0x77);
    LM_CHECK(strict_length(l_bytes, [](ByteView b) {
        route::LeaseRec x;
        return route::decode(b, x);
    }));
    // A refusal: status in the low 7 bits, no path.
    route::LeaseRec refused;
    refused.status = Status::NetworkMismatch;
    refused.term = 9;
    const Bytes r_bytes = Be{}.u8(0xE2).u8(static_cast<uint8_t>(Status::NetworkMismatch)).u32(9).u32(0).u32(0).u32(0).u8(0).v;
    LM_CHECK(encodes_to([&](MutByteView o, std::size_t &len) { return route::encode(refused, o, len); }, r_bytes));
    LM_CHECK_OK(route::decode(view(r_bytes), l2));
    LM_CHECK(l2.status == Status::NetworkMismatch && !l2.push && l2.n == 0 && l2.term == 9);
    // A grant needs a path of 2 or more entries; a path must be simple; at most 21 entries.
    const Bytes short_grant = Be{}.u8(0xE2).u8(0).u32(1).u32(1).u32(1).u32(1).u8(1).u16(1).v;
    LM_CHECK(route::decode(view(short_grant), l2) == Status::BadFrame);
    const Bytes dup = Be{}.u8(0xE2).u8(0).u32(1).u32(1).u32(1).u32(1).u8(2).u16(5).u16(5).v;
    LM_CHECK(route::decode(view(dup), l2) == Status::BadFrame);
    Be long_path = Be{}.u8(0xE2).u8(0).u32(1).u32(1).u32(1).u32(1).u8(22);
    for (uint16_t i = 1; i <= 22; ++i) {
        long_path.u16(i);
    }
    LM_CHECK(route::decode(view(long_path.v), l2) == Status::BadFrame);

    route::Answer a;
    a.qid = 5;
    a.status = Status::Ok;
    a.dest = 0x0102;
    a.revision = 77;
    a.n = 2;
    a.path[0] = 1;
    a.path[1] = 0x0102;
    const Bytes a_bytes = Be{}.u8(0xE5).u8(5).u8(0).u16(0x0102).u32(77).u8(2).u16(1).u16(0x0102).v;
    LM_CHECK(encodes_to([&](MutByteView o, std::size_t &len) { return route::encode(a, o, len); }, a_bytes));
    route::Answer a2;
    LM_CHECK_OK(route::decode(view(a_bytes), a2));
    LM_CHECK(a2.qid == 5 && a2.status == Status::Ok && a2.dest == 0x0102 && a2.revision == 77 && a2.n == 2 &&
             a2.path[1] == 0x0102);
    LM_CHECK(strict_length(a_bytes, [](ByteView b) {
        route::Answer x;
        return route::decode(b, x);
    }));
    const Bytes a_refused = Be{}.u8(0xE5).u8(6).u8(static_cast<uint8_t>(Status::NotFound)).u16(0).u32(0).u8(0).v;
    LM_CHECK_OK(route::decode(view(a_refused), a2));
    LM_CHECK(a2.status == Status::NotFound && a2.n == 0);
    const Bytes a_no_path = Be{}.u8(0xE5).u8(6).u8(0).u16(9).u32(0).u8(0).v; // Ok needs at least one entry
    LM_CHECK(route::decode(view(a_no_path), a2) == Status::BadFrame);
}

// ---- power report and policy record (power/power_wire.cpp) ----
LM_TEST("codec golden: power report and policy record are byte-exact; ranges and versions refuse") {
    power::Report r;
    r.mode = 2;
    r.quality = 1;
    r.kind = LM_SLEEP_DEEP;
    r.policy_revision = 0x0A0B0C0D;
    r.interval_ms = 60000;
    r.earliest_ms = 1000;
    r.latest_ms = 5000;
    const Bytes r_bytes =
        Be{}.u8(0xEE).u8(1).u8(2).u8(1).u8(LM_SLEEP_DEEP).u32(0x0A0B0C0D).u32(60000).u32(1000).u32(5000).v;
    LM_CHECK(encodes_to([&](MutByteView o, std::size_t &l) { return power::encode(r, o, l); }, r_bytes));
    power::Report r2;
    LM_CHECK_OK(power::decode(view(r_bytes), r2));
    LM_CHECK(r2.mode == 2 && r2.quality == 1 && r2.kind == LM_SLEEP_DEEP && r2.policy_revision == 0x0A0B0C0D &&
             r2.interval_ms == 60000 && r2.earliest_ms == 1000 && r2.latest_ms == 5000);
    LM_CHECK(strict_length(r_bytes, [](ByteView b) {
        power::Report x;
        return power::decode(b, x);
    }));
    const auto bad_report = [&](std::size_t at, uint8_t value) {
        Bytes b = r_bytes;
        b[at] = value;
        power::Report x;
        return power::decode(view(b), x);
    };
    LM_CHECK(bad_report(0, 0xE1) == Status::BadFrame); // opcode
    LM_CHECK(bad_report(1, 2) == Status::BadFrame);    // version
    LM_CHECK(bad_report(2, 3) == Status::BadFrame);    // mode
    LM_CHECK(bad_report(3, 3) == Status::BadFrame);    // quality
    LM_CHECK(bad_report(4, LM_SLEEP_DEEP + 1) == Status::BadFrame);
    const Bytes swapped = Be{}.u8(0xEE).u8(1).u8(0).u8(0).u8(0).u32(0).u32(0).u32(9).u32(8).v; // earliest > latest
    LM_CHECK(power::decode(view(swapped), r2) == Status::BadFrame);
    const Bytes long_interval = Be{}.u8(0xEE).u8(1).u8(0).u8(0).u8(0).u32(0).u32(86400001).u32(0).u32(0).v;
    LM_CHECK(power::decode(view(long_interval), r2) == Status::BadFrame);

    power::Policy p;
    p.revision = 0x0102030405060708;
    p.mode = 1;
    p.pending = 0;
    uint32_t k = 100;
    for (uint32_t *v : {&p.wake_interval_ms, &p.rx_window_ms, &p.max_rx_window_ms, &p.awake_budget_ms,
                        &p.shutdown_reserve_ms, &p.search_budget_ms, &p.guard_ms, &p.retry_min_ms, &p.retry_max_ms,
                        &p.offline_radio_ms_per_hour, &p.extra_wakes_per_day, &p.extra_radio_ms_per_day,
                        &p.shutdown_overrun_ms, &p.mailbox_child, &p.mailbox_total}) {
        *v = k++;
    }
    Be pb = Be{}.u8(1).u64(0x0102030405060708).u8(1).u8(0);
    for (uint32_t i = 100; i < 115; ++i) {
        pb.u32(i);
    }
    LM_CHECK_EQ(pb.v.size(), power::k_policy_record_bytes);
    LM_CHECK(encodes_to([&](MutByteView o, std::size_t &l) { return power::encode_policy(p, o, l); }, pb.v));
    power::Policy p2;
    LM_CHECK_OK(power::decode_policy(view(pb.v), p2));
    LM_CHECK(p2.revision == p.revision && p2.mode == 1 && p2.pending == 0 && p2.wake_interval_ms == 100 &&
             p2.guard_ms == 106 && p2.mailbox_total == 114);
    for (std::size_t n = 0; n < pb.v.size(); ++n) { // a sealed record that does not parse: fail closed
        LM_CHECK(power::decode_policy(ByteView{pb.v.data(), n}, p2) == Status::RecoveryRequired);
    }
    Bytes v2 = pb.v;
    v2[0] = 2;
    LM_CHECK(power::decode_policy(view(v2), p2) == Status::RecoveryRequired);
    v2 = pb.v;
    v2.push_back(0);
    LM_CHECK(power::decode_policy(view(v2), p2) == Status::RecoveryRequired);
}

// ---- POWER poll / grant (wire/power_frame.cpp): the order of refusals is part of the contract ----
LM_TEST("codec golden: POWER poll and grant are byte-exact; structure before version before ranges") {
    wire::PowerPoll p;
    p.rx_credit = 0x0102;
    p.poll_nonce = 0x1122334455667788;
    p.revision_hint = 0xA0B0C0D0;
    p.planned_interval_ms = 60000;
    p.window_ms = 500;
    const Bytes p_bytes =
        Be{}.u8(1).u8(1).u16(0x0102).u64(0x1122334455667788).u32(0xA0B0C0D0).u32(60000).u16(500).u16(0).u32(0).v;
    LM_CHECK(encodes_to([&](MutByteView o, std::size_t &l) { return wire::encode_power_poll(p, o, l); }, p_bytes));
    wire::PowerPoll p2;
    LM_CHECK_OK(wire::decode_power_poll(view(p_bytes), p2));
    LM_CHECK(p2.rx_credit == p.rx_credit && p2.poll_nonce == p.poll_nonce && p2.revision_hint == p.revision_hint &&
             p2.planned_interval_ms == 60000 && p2.window_ms == 500);
    LM_CHECK(strict_length(p_bytes, [](ByteView b) {
        wire::PowerPoll x;
        return wire::decode_power_poll(b, x);
    }));
    const auto poll_with = [&](std::size_t at, uint8_t value) {
        Bytes b = p_bytes;
        b[at] = value;
        wire::PowerPoll x;
        return wire::decode_power_poll(view(b), x);
    };
    LM_CHECK(poll_with(1, 2) == Status::Unsupported);   // version
    LM_CHECK(poll_with(0, 2) == Status::BadFrame);      // subtype
    LM_CHECK(poll_with(22, 1) == Status::BadFrame);     // flags != 0
    LM_CHECK(poll_with(27, 1) == Status::BadFrame);     // reserved != 0
    Bytes both = p_bytes; // wrong subtype and wrong version: the structural check comes first
    both[0] = 2;
    both[1] = 9;
    LM_CHECK(wire::decode_power_poll(view(both), p2) == Status::BadFrame);
    Bytes short_v2 = Bytes{p_bytes.begin(), p_bytes.end() - 1}; // too short and wrong version: BadFrame
    short_v2[1] = 9;
    LM_CHECK(wire::decode_power_poll(view(short_v2), p2) == Status::BadFrame);
    Bytes v2_range = p_bytes; // wrong version and a zero window: Unsupported first
    v2_range[1] = 9;
    v2_range[20] = 0;
    v2_range[21] = 0;
    LM_CHECK(wire::decode_power_poll(view(v2_range), p2) == Status::Unsupported);
    const Bytes zero_nonce = Be{}.u8(1).u8(1).u16(1).u64(0).u32(0).u32(1).u16(1).u16(0).u32(0).v;
    LM_CHECK(wire::decode_power_poll(view(zero_nonce), p2) == Status::BadFrame);
    const Bytes long_interval = Be{}.u8(1).u8(1).u16(1).u64(1).u32(0).u32(86400001).u16(1).u16(0).u32(0).v;
    LM_CHECK(wire::decode_power_poll(view(long_interval), p2) == Status::BadFrame);

    wire::PowerGrant g;
    g.pending_frames = 3;
    g.poll_nonce = 0x0102030405060708;
    g.window_ttl_ms = 400;
    g.granted_credit = 7;
    g.reason = 0xCAFEBABE;
    const Bytes g_bytes = Be{}.u8(2).u8(1).u16(3).u64(0x0102030405060708).u32(400).u16(7).u16(0).u32(0xCAFEBABE).v;
    LM_CHECK(encodes_to([&](MutByteView o, std::size_t &l) { return wire::encode_power_grant(g, o, l); }, g_bytes));
    wire::PowerGrant g2;
    LM_CHECK_OK(wire::decode_power_grant(view(g_bytes), g2));
    LM_CHECK(g2.pending_frames == 3 && g2.poll_nonce == g.poll_nonce && g2.window_ttl_ms == 400 &&
             g2.granted_credit == 7 && g2.reason == 0xCAFEBABE);
    LM_CHECK(strict_length(g_bytes, [](ByteView b) {
        wire::PowerGrant x;
        return wire::decode_power_grant(b, x);
    }));
    Bytes gv = g_bytes;
    gv[1] = 3;
    LM_CHECK(wire::decode_power_grant(view(gv), g2) == Status::Unsupported);
    gv = g_bytes;
    gv[19] = 1; // reserved
    LM_CHECK(wire::decode_power_grant(view(gv), g2) == Status::BadFrame);
    const Bytes ttl0 = Be{}.u8(2).u8(1).u16(0).u64(1).u32(0).u16(0).u16(0).u32(0).v;
    LM_CHECK(wire::decode_power_grant(view(ttl0), g2) == Status::BadFrame);
    const Bytes ttl_big = Be{}.u8(2).u8(1).u16(0).u64(1).u32(0x10000).u16(0).u16(0).u32(0).v;
    LM_CHECK(wire::decode_power_grant(view(ttl_big), g2) == Status::BadFrame);
}

// ---- ledger entry and manifest records (root/ledger.cpp) ----
LM_TEST("codec golden: ledger entry and manifest records are byte-exact; state, pages and version refuse") {
    root::Entry e;
    e.assignment = 0x0102030405060708;
    e.membership = 9;
    e.consumed = 0x0102030405060708;
    e.device.bytes = pattern<32>(1);
    e.request.bytes = pattern<16>(2);
    e.hash = pattern<32>(3);
    const Bytes cose{0xD2, 0x84, 0x40, 0xA0, 0x41, 0x00, 0x58, 0x40};
    const Bytes e_bytes = [&] {
        Be b = Be{}.u8(1).u64(e.assignment).u64(9).u64(e.consumed).raw(e.device.bytes).raw(e.request.bytes).raw(e.hash);
        b.v.insert(b.v.end(), cose.begin(), cose.end());
        return b.v;
    }();
    LM_CHECK_EQ(e_bytes.size(), root::detail::k_entry_head + cose.size());
    LM_CHECK(encodes_to([&](MutByteView o, std::size_t &l) { return root::detail::encode_entry(e, true, view(cose), o, l); },
                        e_bytes));
    store::RecordJob rec;
    std::copy(e_bytes.begin(), e_bytes.end(), rec.payload.begin());
    rec.payload_len = static_cast<uint32_t>(e_bytes.size());
    rec.state = static_cast<uint8_t>(root::EntryState::Active);
    root::Entry e2;
    ByteView cose2;
    LM_CHECK_OK(root::detail::decode_entry(rec, e2, cose2));
    LM_CHECK(e2.confirmed && e2.assignment == e.assignment && e2.membership == 9 && e2.consumed == e.consumed &&
             e2.device == e.device && e2.request == e.request && e2.hash == e.hash &&
             e2.state == root::EntryState::Active && cose2.size() == cose.size() &&
             std::memcmp(cose2.data(), cose.data(), cose.size()) == 0);
    rec.payload_len = static_cast<uint32_t>(root::detail::k_entry_head); // no credential: an empty tail
    LM_CHECK_OK(root::detail::decode_entry(rec, e2, cose2));
    LM_CHECK(cose2.empty());
    rec.payload_len = static_cast<uint32_t>(root::detail::k_entry_head - 1);
    LM_CHECK(root::detail::decode_entry(rec, e2, cose2) == Status::BadFrame);
    rec.payload_len = static_cast<uint32_t>(e_bytes.size());
    rec.state = static_cast<uint8_t>(root::EntryState::Blocked) + 1;
    LM_CHECK(root::detail::decode_entry(rec, e2, cose2) == Status::BadFrame);
    const Bytes unconfirmed = [&] { // a zero first byte: not confirmed
        Bytes b = e_bytes;
        b[0] = 0;
        return b;
    }();
    LM_CHECK(encodes_to([&](MutByteView o, std::size_t &l) { return root::detail::encode_entry(e, false, view(cose), o, l); },
                        unconfirmed));

    root::Manifest m;
    m.domain.bytes = pattern<16>(9);
    m.expected_revision = 0x0A0B0C0D0E0F1011;
    m.used = 0x8000000000000001;
    m.set_hash = pattern<32>(5);
    m.pages = 4;
    m.received = 0x000F;
    m.pending = 0x0010;
    for (std::size_t i = 0; i < m.digests.size(); ++i) {
        m.digests[i] = pattern<8>(static_cast<uint8_t>(i * 3));
    }
    Be mb = Be{}.u8(1).raw(m.domain.bytes).u64(m.expected_revision).u64(m.used).raw(m.set_hash).u8(4).u16(0x0F).u16(0x10);
    for (const auto &d : m.digests) {
        mb.raw(d);
    }
    LM_CHECK_EQ(mb.v.size(), root::k_manifest_bytes);
    LM_CHECK(encodes_to([&](MutByteView o, std::size_t &l) { return root::encode_manifest(m, o, l); }, mb.v));
    root::Manifest m2;
    LM_CHECK_OK(root::detail::decode_manifest(view(mb.v), m2));
    LM_CHECK(m2.domain == m.domain && m2.expected_revision == m.expected_revision && m2.used == m.used &&
             m2.set_hash == m.set_hash && m2.pages == 4 && m2.received == 0x0F && m2.pending == 0x10 &&
             m2.digests == m.digests);
    LM_CHECK(strict_length(mb.v, [](ByteView b) {
        root::Manifest x;
        return root::detail::decode_manifest(b, x);
    }));
    Bytes mv = mb.v;
    mv[0] = 2;
    LM_CHECK(root::detail::decode_manifest(view(mv), m2) == Status::BadFrame);
    mv = mb.v;
    mv[1 + 16 + 8 + 8 + 32] = 17; // pages > 16
    LM_CHECK(root::detail::decode_manifest(view(mv), m2) == Status::BadFrame);
}

// ---- trust anchor and revocation floors (member/records.cpp) ----
LM_TEST("codec golden: trust anchor and floors records are byte-exact; bad key, count and length refuse") {
    LM_CHECK_OK(sec::crypto_init()); // the key is validated through PSA
    // The P-256 generator: a valid public key with fixed bytes.
    const std::array<uint8_t, 32> gx{0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
                                     0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96};
    const std::array<uint8_t, 32> gy{0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
                                     0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5};
    FleetId fleet;
    fleet.bytes = pattern<16>(4);
    sec::PublicKey key;
    key.x = gx;
    key.y = gy;
    member::TrustAnchor t;
    LM_CHECK_OK(member::make_trust_anchor(fleet, key, 0x0102030405060708, t));
    const Bytes t_bytes = Be{}.raw(fleet.bytes).raw(gx).raw(gy).u64(0x0102030405060708).v;
    LM_CHECK_EQ(t_bytes.size(), member::k_trust_bytes);
    LM_CHECK(encodes_to([&](MutByteView o, std::size_t &l) { return member::encode_trust(t, o, l); }, t_bytes));
    member::TrustAnchor t2;
    LM_CHECK_OK(member::decode_trust(view(t_bytes), t2));
    LM_CHECK(t2.fleet == t.fleet && t2.key.x == gx && t2.key.y == gy && t2.min_credential_generation == 0x0102030405060708 &&
             t2.key_id == t.key_id);
    LM_CHECK(strict_length(t_bytes, [](ByteView b) {
        member::TrustAnchor x;
        return member::decode_trust(b, x);
    }));
    Bytes bad_key = t_bytes;
    bad_key[16 + 31] ^= 1; // x no longer on the curve with this y
    LM_CHECK(member::decode_trust(view(bad_key), t2) == Status::InvalidArgument);

    member::Floors f;
    DeviceId a;
    a.bytes = pattern<32>(10);
    DeviceId b;
    b.bytes = pattern<32>(20);
    LM_CHECK_OK(f.raise(a, 5, 6));
    LM_CHECK_OK(f.raise(b, 0x0102030405060708, 1));
    const Bytes f_bytes = Be{}.u8(2).raw(a.bytes).u64(5).u64(6).raw(b.bytes).u64(0x0102030405060708).u64(1).v;
    LM_CHECK(encodes_to([&](MutByteView o, std::size_t &l) { return member::encode_floors(f, o, l); }, f_bytes));
    member::Floors g;
    LM_CHECK_OK(member::decode_floors(view(f_bytes), g));
    LM_CHECK_EQ(g.count(), 2u);
    LM_CHECK(g.at(0).device == a && g.at(0).assignment == 5 && g.at(0).membership == 6);
    LM_CHECK(g.at(1).device == b && g.at(1).assignment == 0x0102030405060708 && g.at(1).membership == 1);
    LM_CHECK(strict_length(f_bytes, [](ByteView v) {
        member::Floors x;
        return member::decode_floors(v, x);
    }));
    const Bytes empty = Be{}.u8(0).v;
    LM_CHECK(encodes_to([&](MutByteView o, std::size_t &l) { return member::encode_floors(member::Floors{}, o, l); }, empty));
    LM_CHECK_OK(member::decode_floors(view(empty), g));
    LM_CHECK_EQ(g.count(), 0u);
    const Bytes too_many = Be{}.u8(member::k_max_floors + 1).v;
    LM_CHECK(member::decode_floors(view(too_many), g) == Status::BadFrame);
    const Bytes twice = Be{}.u8(2).raw(a.bytes).u64(5).u64(9).raw(a.bytes).u64(7).u64(1).v; // one device twice: merged
    LM_CHECK_OK(member::decode_floors(view(twice), g));
    LM_CHECK(g.count() == 1u && g.at(0).assignment == 7 && g.at(0).membership == 9);
}

// ---- channel records (channel/wire.cpp): the field lists moved to core/codec.hpp ----
LM_TEST("codec golden: channel records are byte-exact") {
    channel::State s;
    s.epoch = ChannelEpoch{0x01020304};
    s.channel = 11;
    const Bytes s_bytes = Be{}.u8(0xEA).u32(0x01020304).u8(11).v;
    LM_CHECK(encodes_to([&](MutByteView o, std::size_t &l) { return channel::encode(s, o, l); }, s_bytes));
    channel::State s2;
    LM_CHECK_OK(channel::decode(view(s_bytes), s2));
    LM_CHECK(s2.epoch == s.epoch && s2.channel == 11);
    LM_CHECK(strict_length(s_bytes, [](ByteView b) {
        channel::State x;
        return channel::decode(b, x);
    }));

    channel::TimeResp tr;
    tr.nonce = pattern<8>(1);
    tr.term = RootTerm{5};
    tr.t1_us = 1;
    tr.t2_us = 0x0102030405060708;
    tr.t3_us = 0x0102030405060709;
    const Bytes tr_bytes = Be{}.u8(0xE9).raw(tr.nonce).u32(5).u64(1).u64(tr.t2_us).u64(tr.t3_us).v;
    LM_CHECK(encodes_to([&](MutByteView o, std::size_t &l) { return channel::encode(tr, o, l); }, tr_bytes));
    channel::TimeResp tr2;
    LM_CHECK_OK(channel::decode(view(tr_bytes), tr2));
    LM_CHECK(tr2.nonce == tr.nonce && tr2.term == tr.term && tr2.t3_us == tr.t3_us);

    channel::PlanRec p;
    p.phase = channel::Phase::Commit;
    p.plan.id.bytes = pattern<16>(2);
    p.plan.term = RootTerm{3};
    p.plan.epoch = ChannelEpoch{4};
    p.plan.old_ch = 6;
    p.plan.new_ch = 11;
    p.plan.switch_root_ms = 0x0102030405060708;
    p.plan.max_err_ms = 200;
    p.plan.settle_ms = 30000;
    p.plan.policy_rev = 7;
    p.plan.participants = pattern<32>(9);
    const Bytes p_bytes = Be{}
                              .u8(0xE6)
                              .u8(1)
                              .raw(p.plan.id.bytes)
                              .u32(3)
                              .u32(4)
                              .u8(6)
                              .u8(11)
                              .u64(0x0102030405060708)
                              .u32(200)
                              .u32(30000)
                              .u64(7)
                              .raw(p.plan.participants)
                              .v;
    LM_CHECK(encodes_to([&](MutByteView o, std::size_t &l) { return channel::encode(p, o, l); }, p_bytes));
    channel::PlanRec p2;
    LM_CHECK_OK(channel::decode(view(p_bytes), p2));
    LM_CHECK(p2.phase == channel::Phase::Commit && p2.plan.id == p.plan.id && p2.plan.settle_ms == 30000 &&
             p2.plan.participants == p.plan.participants);
    LM_CHECK(strict_length(p_bytes, [](ByteView b) {
        channel::PlanRec x;
        return channel::decode(b, x);
    }));
}

LM_TEST_MAIN()
