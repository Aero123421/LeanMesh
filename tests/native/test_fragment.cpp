// Fragmentation (S12): FRAGMENT / TRANSFER_BITMAP over the real core on simulated ports, credentials
// from the TEST-ONLY fleet issuer. Full-path tests drive lm_send / lm_send_object / lm_next_event over
// 1..40 hops; the fault tests play the origin with its own end-session state (crafted records
// injected through the medium), because the sim medium never reorders or duplicates by itself.
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <vector>

#include "capi/context.hpp"
#include "fleet.hpp"
#include "lmtest.hpp"
#include "port/sim/sim_node.hpp"
#include "port/sim/sim_world.hpp"
#include "security/crypto.hpp"
#include "stack_probe.hpp"

using namespace lm;
using namespace lm::sim;

namespace {

using Bytes = std::vector<uint8_t>;
constexpr uint64_t k_root_ms0 = 1'000'000;

struct Received {
    lm_event_t ev{};
    Bytes payload;
};

struct Net {
    explicit Net(unsigned n_nodes, bool object = false, uint64_t seed = 77) : n(n_nodes), net(seed), world(WorldOptions{seed, 0}) {
        for (unsigned i = 0; i < n; ++i) {
            NodeOptions o;
            o.role = i == 0 ? Role::Root : Role::Relay;
            o.object_transfer_enabled = object;
            (void)world.add_node(o);
            kits.push_back(i == 0 ? net.make_root() : net.make_node(i, static_cast<uint16_t>(i + 1)));
        }
        world.make_chain();
        for (unsigned i = 0; i < n; ++i) {
            LM_CHECK_OK(fleet::provision(node(i).store, net, kits[i]));
        }
        for (unsigned i = 0; i < n; ++i) {
            LM_CHECK_OK(node(i).boot());
            LM_CHECK_EQ(lm_start(node(i).ctx()), LM_STATUS_OK);
        }
        run_ms(50);
        for (unsigned i = 1; i < n; ++i) {
            LM_CHECK_OK(eng(i).link().connect(mac(i - 1), now(i)));
            node(i).notify();
            run_ms(2500);
        }
        t0_us = world.now_us();
        for (unsigned i = 0; i < n; ++i) {
            RootTimeBound b;
            b.term = RootTerm{1};
            b.earliest_ms = b.latest_ms = k_root_ms0;
            b.valid = true;
            eng(i).set_root_time(b, now(i));
            node(i).notify();
        }
    }

    SimNode &node(unsigned i) { return world.node(static_cast<uint16_t>(i)); }
    Engine &eng(unsigned i) { return node(i).ctx()->engine; }
    delivery::Delivery &dv(unsigned i) { return eng(i).delivery(); }
    lm_context_t *ctx(unsigned i) { return node(i).ctx(); }
    void run_ms(uint64_t ms) { world.run_until(world.now_us() + ms * 1000); }
    MonoTime now(unsigned i) { return node(i).clock.now(); }
    const MacAddr &mac(unsigned i) { return node(i).radio.mac(); }
    const DeviceId &id(unsigned i) { return kits[i].kit.id; }
    static uint16_t addr(unsigned i) { return static_cast<uint16_t>(i + 1); }
    [[nodiscard]] uint64_t root_ms() const { return k_root_ms0 + (world.now_us() - t0_us) / 1000; }

    template <class P> bool until(P pred, uint64_t max_ms) {
        for (uint64_t t = 0; t < max_ms; t += 5) {
            if (pred()) {
                return true;
            }
            run_ms(5);
        }
        return pred();
    }

    delivery::PathSpec spec(unsigned a, unsigned b) {
        delivery::PathSpec ps;
        ps.origin = ShortAddr{addr(a)};
        ps.dest = ShortAddr{addr(b)};
        const int dir = b > a ? 1 : -1;
        ps.len = static_cast<uint8_t>(b > a ? b - a : a - b);
        for (unsigned k = 0; k < ps.len; ++k) {
            ps.path[k] = addr(static_cast<unsigned>(static_cast<int>(a) + dir * static_cast<int>(k + 1)));
        }
        ps.term = RootTerm{1};
        ps.revision = PathRevision{1};
        return ps;
    }
    void routes(unsigned a, unsigned b) {
        LM_CHECK_OK(dv(a).install_route(id(b), spec(a, b), MonoTime::never()));
        LM_CHECK_OK(dv(b).install_route(id(a), spec(b, a), MonoTime::never()));
        node(a).notify();
        node(b).notify();
    }

    struct Sent {
        lm_status_t st = LM_STATUS_OK;
        lm_operation_id_t op = 0;
    };
    Sent send(unsigned from, unsigned to, uint32_t delivery_kind, const Bytes &payload, uint64_t ttl_ms = 200000,
              bool object = false, bool strict = false, uint16_t port = 100) {
        lm_send_request_t rq{};
        rq.struct_size = sizeof(rq);
        rq.abi_version = LM_ABI_VERSION;
        rq.destination.kind = LM_DEST_NODE;
        std::memcpy(rq.destination.node.bytes, id(to).bytes.data(), 32);
        rq.app_port = port;
        rq.delivery = static_cast<uint8_t>(delivery_kind);
        rq.storage = LM_VOLATILE;
        rq.priority = LM_PRIORITY_NORMAL;
        rq.queue_mode = LM_FIFO;
        rq.strict_single_frame = strict ? 1 : 0;
        rq.root_term = 1;
        rq.expires_root_ms = root_ms() + ttl_ms;
        Sent s;
        s.st = object ? lm_send_object(ctx(from), &rq, payload.data(), payload.size(), &s.op)
                      : lm_send(ctx(from), &rq, payload.data(), payload.size(), &s.op);
        node(from).notify();
        return s;
    }
    lm_operation_t op(unsigned i, lm_operation_id_t id_) {
        lm_operation_t o{};
        o.struct_size = sizeof(o);
        o.abi_version = LM_ABI_VERSION;
        LM_CHECK_EQ(lm_get_operation(ctx(i), id_, &o), LM_STATUS_OK);
        return o;
    }
    bool pop(unsigned i, Received &out, uint32_t kind = 0) {
        for (;;) {
            Received r;
            r.ev.struct_size = sizeof(r.ev);
            r.ev.abi_version = LM_ABI_VERSION;
            r.payload.assign(4200, 0);
            size_t req = 0;
            if (lm_next_event(ctx(i), &r.ev, r.payload.data(), r.payload.size(), &req) != LM_STATUS_OK) {
                return false;
            }
            r.payload.resize(req);
            if (kind == 0 || r.ev.kind == kind) {
                out = r;
                return true;
            }
        }
    }
    lm_status_t report(unsigned i, const lm_event_t &e, uint32_t outcome, const Bytes &result) {
        lm_message_ref_t m{};
        m.origin = e.peer;
        m.assignment_generation = e.origin_assignment_generation;
        m.id = e.message_id;
        std::memcpy(m.intent_hash, e.intent_hash, 32);
        lm_operation_id_t o = 0;
        const lm_status_t st = lm_report_application_result(ctx(i), &m, outcome, result.data(), result.size(), &o);
        node(i).notify();
        return st;
    }

    unsigned n;
    fleet::Network net;
    World world;
    std::vector<fleet::NodeKit> kits;
    uint64_t t0_us = 0;
};

Bytes bytes_of(uint8_t seed, std::size_t len) {
    Bytes b(len);
    for (std::size_t i = 0; i < len; ++i) {
        b[i] = static_cast<uint8_t>(seed * 31U + i * 7U + (i >> 8U));
    }
    return b;
}

void warm_up(Net &n, unsigned from, unsigned to) { // opens the end session
    const auto s = n.send(from, to, LM_RECEIVED, bytes_of(9, 4));
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.op(from, s.op).outcome == LM_OUTCOME_RECEIVED; }, 30000));
    Received m;
    LM_CHECK(n.pop(to, m, LM_EVENT_MESSAGE));
}

// ---- the full path ----
// A 512 B APPLIED message and its receipt with an application result over `hops` hops: one event at
// the destination, the payload and hash intact, the result reaching the origin (S9 gap: at 40 hops a
// receipt with a result does not fit one frame).
void big_message(unsigned hops, uint64_t wait_ms) {
    Net n(hops + 1);
    n.routes(0, hops);
    const Bytes body = bytes_of(3, 512);
    const auto s = n.send(0, hops, LM_APPLIED, body);
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    Received m;
    LM_CHECK(n.until([&] { return n.pop(hops, m, LM_EVENT_MESSAGE); }, wait_ms));
    LM_CHECK(m.payload == body);
    LM_CHECK(std::memcmp(m.ev.intent_hash, n.op(0, s.op).intent_hash, 32) == 0);
    LM_CHECK(n.until([&] { return (n.op(0, s.op).evidence_bits & delivery::ev::end_received) != 0; }, wait_ms));
    const Bytes result = bytes_of(5, 32); // the largest typed result
    LM_CHECK_EQ(n.report(hops, m.ev, LM_OUTCOME_APPLIED, result), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.op(0, s.op).outcome == LM_OUTCOME_APPLIED; }, wait_ms));
    Received oe;
    LM_CHECK(n.pop(0, oe, LM_EVENT_OPERATION));
    LM_CHECK(oe.payload == result);
    LM_CHECK(!n.pop(hops, m, LM_EVENT_MESSAGE)); // exactly one completion at the destination
    LM_CHECK_EQ(n.dv(hops).frag_stats().completed, 1u);
    LM_CHECK_EQ(n.dv(hops).stats().delivered, 1u);
    LM_CHECK(n.dv(0).frag_stats().tx >= 512U / wire::fragment_chunk(hops));
    LM_CHECK(n.dv(0).frag_stats().bitmap_rx > 0u);
    LM_CHECK_EQ(n.dv(hops).frag_stats().tx > 0u, hops == 40); // only at 40 hops the receipt itself is fragmented
    for (unsigned i = 1; i < hops; ++i) {
        LM_CHECK_EQ(n.dv(i).stats().rx_data, 0u); // relays forward fragments and read none
    }
}

} // namespace

LM_TEST("D07 sim 20 hops: 512 B in 48 B fragments, one completion, hash intact, the receipt with a result arrives") {
    big_message(20, 200000);
}

LM_TEST("D07 sim 40 hops: 512 B in 16 B fragments; the APP_APPLIED receipt with a result reaches the origin") {
    big_message(40, 600000);
}

LM_TEST("D07 sim: strict_single_frame refuses what would be fragmented; the default splits it") {
    Net n(6);
    n.routes(0, 5);
    LM_CHECK_EQ(n.send(0, 5, LM_RECEIVED, bytes_of(1, 127), 60000, false, true).st, LM_STATUS_PAYLOAD_TOO_LARGE);
    LM_CHECK_EQ(n.send(0, 5, LM_RECEIVED, bytes_of(1, 126), 60000, false, true).st, LM_STATUS_OK);
    LM_CHECK_EQ(n.send(0, 5, LM_RECEIVED, bytes_of(1, 513), 60000).st, LM_STATUS_PAYLOAD_TOO_LARGE); // 512 is the ceiling
    const auto s = n.send(0, 5, LM_RECEIVED, bytes_of(2, 300), 120000);
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.op(0, s.op).outcome == LM_OUTCOME_RECEIVED; }, 60000));
}

LM_TEST("D07 sim: a lossy last hop loses fragments; only the missing ones are repeated and the message completes once") {
    Net n(3);
    n.routes(0, 2);
    warm_up(n, 0, 2);
    LinkParams p;
    p.up = true;
    p.loss_permille = 500;
    n.world.set_link(1, 2, p);
    const Bytes body = bytes_of(7, 400);
    const uint64_t tx0 = n.dv(0).frag_stats().tx;
    const auto s = n.send(0, 2, LM_RECEIVED, body, 250000);
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.op(0, s.op).outcome == LM_OUTCOME_RECEIVED; }, 240000));
    Received m;
    LM_CHECK(n.pop(2, m, LM_EVENT_MESSAGE));
    LM_CHECK(m.payload == body);
    LM_CHECK(!n.pop(2, m, LM_EVENT_MESSAGE));
    LM_CHECK_EQ(n.dv(2).frag_stats().completed, 1u);
    LM_CHECK(n.dv(1).hop_stats().rf_failed > 0u); // the loss was real
    const uint64_t sent = n.dv(0).frag_stats().tx - tx0;
    LM_CHECK(sent >= 400U / 80U);
    LM_CHECK(sent < 2U * (400U / 32U)); // not the whole message repeated every round (chunk is 32 B at 2 hops)
}

LM_TEST("D07 sim: best effort fragments are SUBMITTED only when the destination has every byte") {
    Net n(4);
    n.routes(0, 3);
    warm_up(n, 0, 3);
    const Bytes body = bytes_of(13, 300);
    const auto s = n.send(0, 3, LM_BEST_EFFORT, body, 60000);
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.op(0, s.op).outcome == LM_OUTCOME_SUBMITTED; }, 30000));
    Received m;
    LM_CHECK(n.pop(3, m, LM_EVENT_MESSAGE));
    LM_CHECK(m.payload == body);
    LM_CHECK_EQ(n.dv(3).frag_stats().completed, 1u);
    LM_CHECK(n.dv(0).frag_stats().bitmap_rx > 0u);
}

LM_TEST("D07 sim: fragments of a receipt are lost; the origin's next round makes the destination send them again") {
    Net n(31);
    n.routes(0, 30);
    const auto s = n.send(0, 30, LM_APPLIED, bytes_of(14, 200), 600000);
    Received m;
    LM_CHECK(n.until([&] { return n.pop(30, m, LM_EVENT_MESSAGE); }, 300000));
    LinkParams p;
    p.up = true;
    p.loss_permille = 600; // the way back is lossy from now on: receipt fragments will go missing
    n.world.set_link(29, 30, p);
    LM_CHECK_EQ(n.report(30, m.ev, LM_OUTCOME_APPLIED, bytes_of(15, 32)), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.op(0, s.op).outcome == LM_OUTCOME_APPLIED; }, 500000));
    LM_CHECK(n.dv(30).frag_stats().tx > 3u); // more receipt fragments were sent than one receipt has
    Received oe;
    LM_CHECK(n.pop(0, oe, LM_EVENT_OPERATION));
    LM_CHECK(oe.payload == bytes_of(15, 32));
}

LM_TEST("D07 sim: a transfer cut off mid-way ends INDETERMINATE at its deadline and frees every slot and buffer") {
    Net n(3);
    n.routes(0, 2);
    warm_up(n, 0, 2);
    const std::size_t free_o = n.dv(0).free_msg_buffers();
    const std::size_t free_d = n.dv(2).free_msg_buffers();
    const auto s = n.send(0, 2, LM_RECEIVED, bytes_of(16, 500), 20000);
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.dv(2).frag_stats().rx >= 2u; }, 20000));
    LinkParams down;
    down.up = false;
    n.world.set_link(1, 2, down); // nothing reaches the destination any more
    LM_CHECK(n.until([&] { return n.op(0, s.op).phase == static_cast<uint32_t>(delivery::Phase::Final); }, 60000));
    LM_CHECK_EQ(n.op(0, s.op).outcome, static_cast<uint32_t>(LM_OUTCOME_INDETERMINATE)); // it may have partly arrived
    n.run_ms(35000);
    LM_CHECK_EQ(n.dv(2).frag_stats().rx_expired, 1u); // the slot never outlives the message's own deadline
    LM_CHECK_EQ(n.dv(2).free_msg_buffers(), free_d);
    LM_CHECK_EQ(n.dv(0).free_msg_buffers(), free_o);
    Received m;
    LM_CHECK(!n.pop(2, m, LM_EVENT_MESSAGE));
}

// ---- crafted fragments: order, duplicates, gaps, expiry, conflicts, exhaustion ----
namespace {

struct Crafter {
    Net &n;
    unsigned from;
    unsigned to;
    uint8_t mid;
    Bytes payload;
    uint64_t expires;
    uint16_t port = 100;
    uint8_t delivery_kind = LM_RECEIVED;

    [[nodiscard]] Sha256Digest hash() const {
        delivery::IntentFields f;
        f.origin = n.id(from);
        f.target = n.id(to);
        f.domain = n.eng(from).identity().delegation().domain;
        f.app_port = port;
        f.delivery = delivery_kind;
        f.storage = 0;
        f.priority = LM_PRIORITY_NORMAL;
        f.root_term = 1;
        f.expires_root_ms = expires;
        f.payload = ByteView{payload.data(), payload.size()};
        Sha256Digest h{};
        LM_CHECK_OK(delivery::intent_hash(f, h));
        return h;
    }

    // One FRAGMENT record for [offset, offset+len) of `payload` (bytes may be overridden).
    [[nodiscard]] link::SealedFrame fragment(uint16_t offset, uint16_t len, const Bytes *other = nullptr,
                                             uint16_t total_override = 0) const {
        delivery::EndSession *s = n.dv(from).sessions().find_peer(n.id(to));
        LM_CHECK(s != nullptr);
        wire::FragmentPrefix p;
        p.total_len = total_override != 0 ? total_override : static_cast<uint16_t>(payload.size());
        p.offset = offset;
        p.fragment_len = len;
        p.original_kind = wire::RecordKind::Data;
        p.object_class = payload.size() > 512 ? wire::ObjectClass::Object : wire::ObjectClass::Small;
        p.intent_hash = hash();
        Bytes plain(wire::k_fragment_prefix_bytes + len);
        LM_CHECK_OK(wire::encode_fragment_prefix(p, MutByteView{plain.data(), wire::k_fragment_prefix_bytes}));
        const Bytes &src = other != nullptr ? *other : payload;
        std::memcpy(plain.data() + wire::k_fragment_prefix_bytes, src.data() + offset, len);
        wire::EndHeader h;
        h.message_id.fill(mid);
        h.app_port = port;
        h.record_kind = wire::RecordKind::Fragment;
        h.flags = wire::make_end_flags(static_cast<wire::Delivery>(delivery_kind), wire::Priority::Normal, false);
        h.expires_root_ms = expires;
        std::array<uint8_t, 250> rec{};
        std::size_t rlen = 0;
        LM_CHECK_OK(delivery::seal_end_record(*s, s->tx_sid, RootTerm{1}, h, ByteView{plain.data(), plain.size()},
                                              MutByteView{rec}, rlen));
        const delivery::PathSpec ps = n.spec(from, to);
        std::array<uint8_t, 250> body{};
        std::size_t hl = 0;
        LM_CHECK_OK(wire::encode_route(ps.header(), MutByteView{body}, hl));
        std::memcpy(body.data() + hl, rec.data(), rlen);
        link::SealedFrame f;
        LM_CHECK_OK(n.eng(from).link().seal(n.id(to), wire::FrameKind::Data, ByteView{body.data(), hl + rlen}, f,
                                            n.now(from)));
        return f;
    }
    void inject(const link::SealedFrame &f) {
        n.world.inject(n.mac(from), static_cast<uint16_t>(from), n.mac(to), f.view());
        n.run_ms(60);
    }
    void send(uint16_t offset, uint16_t len) { inject(fragment(offset, len)); }
};

} // namespace

LM_TEST("D07 sim: out-of-order and duplicate fragments complete once; a transfer with a gap is dropped at its timeout") {
    Net n(2);
    n.routes(0, 1);
    warm_up(n, 0, 1);
    const std::size_t free0 = n.dv(1).free_msg_buffers();
    Crafter c{n, 0, 1, 0xA1, bytes_of(4, 100), n.root_ms() + 200000};
    c.send(64, 32); // out of order: third, first, first again, fourth, second last
    c.send(0, 32);
    c.send(0, 32);
    LM_CHECK_EQ(n.dv(1).frag_stats().rx_dup, 1u);
    Received m;
    LM_CHECK(!n.pop(1, m, LM_EVENT_MESSAGE)); // nothing before the message is complete
    c.send(96, 4);
    LM_CHECK(!n.pop(1, m, LM_EVENT_MESSAGE));
    LM_CHECK_EQ(n.dv(1).free_msg_buffers(), free0 - 1); // the slot holds one pool buffer
    c.send(32, 32);
    LM_CHECK(n.pop(1, m, LM_EVENT_MESSAGE));
    LM_CHECK(m.payload == c.payload);
    LM_CHECK(std::memcmp(m.ev.intent_hash, c.hash().data(), 32) == 0);
    c.send(32, 32); // a repeat of a finished transfer: no second event, no new slot
    c.send(0, 32);
    LM_CHECK(!n.pop(1, m, LM_EVENT_MESSAGE));
    LM_CHECK_EQ(n.dv(1).frag_stats().completed, 1u);
    LM_CHECK_EQ(n.dv(1).stats().delivered, 2u); // warm-up + this one
    // A gap: the fourth fragment never comes. The slot dies at 30 s and frees its buffer.
    Crafter g{n, 0, 1, 0xA2, bytes_of(5, 100), n.root_ms() + 200000};
    g.send(0, 32);
    g.send(32, 32);
    g.send(64, 32);
    LM_CHECK(!n.pop(1, m, LM_EVENT_MESSAGE));
    LM_CHECK_EQ(n.dv(1).free_msg_buffers(), free0 - 1);
    n.run_ms(31000);
    LM_CHECK_EQ(n.dv(1).frag_stats().rx_expired, 1u);
    LM_CHECK_EQ(n.dv(1).free_msg_buffers(), free0);
    LM_CHECK(!n.pop(1, m, LM_EVENT_MESSAGE));
    // The transfer starts over afterwards and completes normally.
    g.send(0, 32);
    g.send(32, 32);
    g.send(64, 32);
    g.send(96, 4);
    LM_CHECK(n.pop(1, m, LM_EVENT_MESSAGE));
    LM_CHECK(m.payload == g.payload);
}

LM_TEST("D09 sim: the same offset with other bytes is CONFLICT: the transfer is void and no half message reaches the app") {
    Net n(2);
    n.routes(0, 1);
    warm_up(n, 0, 1);
    Crafter c{n, 0, 1, 0xB1, bytes_of(6, 96), n.root_ms() + 200000};
    c.send(0, 32);
    c.send(32, 32);
    const Bytes other = bytes_of(99, 96);
    c.inject(c.fragment(32, 32, &other)); // same offset, different bytes, valid tag, fresh counter
    LM_CHECK_EQ(n.dv(1).frag_stats().rx_conflict, 1u);
    c.send(64, 32); // the rest of the original message arrives: it cannot complete on top of the void slot
    Received m;
    LM_CHECK(!n.pop(1, m, LM_EVENT_MESSAGE));
    LM_CHECK_EQ(n.dv(1).frag_stats().completed, 0u);
    LM_CHECK_EQ(n.dv(1).frag_stats().rx_refused, 1u); // refused with a receipt: nothing was applied
    // A different cut of the same bytes is a duplicate, not a conflict.
    Crafter d{n, 0, 1, 0xB2, bytes_of(8, 96), n.root_ms() + 200000};
    d.send(0, 32);
    d.send(0, 16); // first half of the same quanta again
    d.send(16, 16);
    LM_CHECK_EQ(n.dv(1).frag_stats().rx_conflict, 1u);
    d.send(32, 32);
    d.send(64, 32);
    LM_CHECK(n.pop(1, m, LM_EVENT_MESSAGE));
    LM_CHECK(m.payload == d.payload);
}

LM_TEST("D07 sim: an expired transfer is refused with evidence and reserves nothing; a bad hash is never delivered") {
    Net n(2);
    n.routes(0, 1);
    warm_up(n, 0, 1);
    const std::size_t free0 = n.dv(1).free_msg_buffers();
    Crafter c{n, 0, 1, 0xC1, bytes_of(1, 64), n.root_ms() + 500};
    n.run_ms(1500); // the deadline passes before the first fragment arrives
    c.send(0, 32);
    LM_CHECK_EQ(n.dv(1).frag_stats().rx_refused, 1u);
    LM_CHECK_EQ(n.dv(1).free_msg_buffers(), free0);
    // Authentic fragments whose bytes do not hash to what the first fragment promised.
    Crafter h{n, 0, 1, 0xC2, bytes_of(2, 64), n.root_ms() + 200000};
    const Bytes lie = bytes_of(3, 64);
    h.inject(h.fragment(0, 32));
    h.inject(h.fragment(32, 32, &lie)); // bytes differ from the payload the hash was computed over
    Received m;
    LM_CHECK(!n.pop(1, m, LM_EVENT_MESSAGE));
    LM_CHECK_EQ(n.dv(1).free_msg_buffers(), free0);
}

LM_TEST("D07 sim: full reassembly slots answer BUSY (no loss) and never block a control object") {
    Net n(2);
    n.routes(0, 1);
    warm_up(n, 0, 1);
    std::vector<Bytes> controls;
    // Fill every message reassembly slot of node 1 with a transfer that never completes.
    std::vector<Crafter> open;
    for (unsigned i = 0; i < delivery::k_small_slots; ++i) {
        open.push_back(Crafter{n, 0, 1, static_cast<uint8_t>(0xD0 + i), bytes_of(static_cast<uint8_t>(i), 200), n.root_ms() + 250000});
        open.back().send(0, 32);
    }
    LM_CHECK_EQ(n.dv(1).frag_stats().rx_busy, 0u);
    Crafter extra{n, 0, 1, 0xDF, bytes_of(9, 200), n.root_ms() + 250000};
    extra.send(0, 32); // no slot: BUSY, counted as our capacity, not as a lost frame
    LM_CHECK(n.dv(1).frag_stats().rx_busy >= 1u);
    LM_CHECK_EQ(n.dv(0).hop_stats().rf_failed, 0u);
    // A control object of 900 B still goes through (own slot and buffer) ...
    delivery::ControlSendRequest cr;
    cr.dest = n.id(1);
    cr.root_term = 1;
    cr.expires_root_ms = n.root_ms() + 100000;
    n.dv(1).set_control_sink(
        [](void *ctx, const DeviceId &, const std::array<uint8_t, 16> &, ByteView p, MonoTime) {
            auto *got = static_cast<std::vector<Bytes> *>(ctx);
            got->emplace_back(p.begin(), p.end());
        },
        &controls);
    const Bytes obj = bytes_of(4, 900);
    Command cmd;
    cmd.kind = CommandKind::SendControl;
    cmd.request = &cr;
    cmd.request_size = sizeof(cr);
    cmd.payload = ByteView{obj.data(), obj.size()};
    const Reply r = n.eng(0).execute(cmd, n.now(0));
    LM_CHECK_EQ(r.status, Status::Ok);
    n.node(0).notify();
    LM_CHECK(n.until([&] { return !controls.empty(); }, 60000));
    LM_CHECK(controls[0] == obj);
    LM_CHECK(n.until([&] { return n.op(0, r.operation_id).outcome == LM_OUTCOME_SUBMITTED; }, 60000));
    // ... more than one page is refused at acceptance, and the same object is not dispatched twice.
    const Bytes big = bytes_of(5, 1025);
    cmd.payload = ByteView{big.data(), big.size()};
    LM_CHECK_EQ(n.eng(0).execute(cmd, n.now(0)).status, Status::PayloadTooLarge);
    n.run_ms(5000);
    LM_CHECK_EQ(controls.size(), 1u);
    LM_CHECK_EQ(n.dv(1).frag_stats().control_rx, 1u);
    // The open transfers die at their timeout, the BUSY one can start again.
    n.run_ms(31000);
    LM_CHECK_EQ(n.dv(1).frag_stats().rx_expired, delivery::k_small_slots);
    const uint64_t rx0 = n.dv(1).frag_stats().rx;
    extra.send(0, 32);
    LM_CHECK_EQ(n.dv(1).frag_stats().rx, rx0 + 1); // it found a free slot
}

LM_TEST("D08 sim: a 4096 B object (opt-in) is restored in bounded memory; 4097 B and a disabled build are refused") {
    Net n(3, true);
    n.routes(0, 2);
    const Bytes obj = bytes_of(11, 4096);
    LM_CHECK_EQ(n.send(0, 2, LM_RECEIVED, bytes_of(1, 4097), 60000, true).st, LM_STATUS_PAYLOAD_TOO_LARGE);
    LM_CHECK_EQ(n.send(0, 2, LM_RECEIVED, obj, 60000, false).st, LM_STATUS_PAYLOAD_TOO_LARGE); // lm_send stops at 512
    const auto s = n.send(0, 2, LM_APPLIED, obj, 250000, true);
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    LM_CHECK_EQ(n.send(0, 2, LM_RECEIVED, obj, 60000, true).st, LM_STATUS_NO_CAPACITY); // the object buffer is in use
    Received m;
    LM_CHECK(n.until([&] { return n.pop(2, m, LM_EVENT_MESSAGE); }, 240000));
    LM_CHECK_EQ(m.payload.size(), 4096u);
    LM_CHECK(m.payload == obj);
    LM_CHECK(std::memcmp(m.ev.intent_hash, n.op(0, s.op).intent_hash, 32) == 0);
    LM_CHECK_EQ(n.report(2, m.ev, LM_OUTCOME_APPLIED, Bytes{1, 2, 3}), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.op(0, s.op).outcome == LM_OUTCOME_APPLIED; }, 60000));
    LM_CHECK_EQ(n.dv(2).frag_stats().completed, 1u);
    // Capability and configuration.
    lm_capabilities_t caps{};
    caps.struct_size = sizeof(caps);
    caps.abi_version = LM_ABI_VERSION;
    LM_CHECK_EQ(lm_get_capabilities(n.ctx(0), &caps), LM_STATUS_OK);
    LM_CHECK_EQ(caps.max_object_bytes, 4096u);
    // The buffer is free again after the application took the object: a second one goes.
    const auto s2 = n.send(0, 2, LM_RECEIVED, bytes_of(12, 2000), 250000, true);
    LM_CHECK_EQ(s2.st, LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.op(0, s2.op).outcome == LM_OUTCOME_RECEIVED; }, 240000));
}

LM_TEST("D08 sim: without the application's opt-in lm_send_object is UNSUPPORTED and a peer refuses an object") {
    Net n(2, false);
    n.routes(0, 1);
    LM_CHECK_EQ(n.send(0, 1, LM_RECEIVED, bytes_of(1, 600), 60000, true).st, LM_STATUS_UNSUPPORTED);
    lm_capabilities_t caps{};
    caps.struct_size = sizeof(caps);
    caps.abi_version = LM_ABI_VERSION;
    LM_CHECK_EQ(lm_get_capabilities(n.ctx(0), &caps), LM_STATUS_OK);
    LM_CHECK_EQ(caps.max_object_bytes, 0u);
    // A crafted Object-class transfer to a node that did not enable it is refused with evidence.
    warm_up(n, 0, 1);
    Crafter c{n, 0, 1, 0xE1, bytes_of(2, 700), n.root_ms() + 100000};
    c.send(0, 80);
    LM_CHECK_EQ(n.dv(1).frag_stats().rx_refused, 1u);
    Received m;
    LM_CHECK(!n.pop(1, m, LM_EVENT_MESSAGE));
}

LM_TEST("D07 sim: a DURABLE 300 B message is persisted, fragmented, and confirmed only after the destination's commit") {
    Net n(4);
    n.routes(0, 3);
    warm_up(n, 0, 3);
    lm_send_request_t rq{};
    rq.struct_size = sizeof(rq);
    rq.abi_version = LM_ABI_VERSION;
    rq.destination.kind = LM_DEST_NODE;
    std::memcpy(rq.destination.node.bytes, n.id(3).bytes.data(), 32);
    rq.app_port = 100;
    rq.delivery = LM_RECEIVED;
    rq.storage = LM_DURABLE;
    rq.priority = LM_PRIORITY_NORMAL;
    rq.root_term = 1;
    rq.expires_root_ms = n.root_ms() + 100000;
    const Bytes body = bytes_of(21, 300);
    lm_operation_id_t op = 0;
    LM_CHECK_EQ(lm_send(n.ctx(0), &rq, body.data(), body.size(), &op), LM_STATUS_OK);
    n.node(0).notify();
    LM_CHECK(n.until([&] { return n.op(0, op).outcome == LM_OUTCOME_RECEIVED; }, 60000));
    LM_CHECK((n.op(0, op).evidence_bits & delivery::ev::persisted) != 0);
    Received m;
    LM_CHECK(n.pop(3, m, LM_EVENT_MESSAGE));
    LM_CHECK(m.payload == body);
    // FIX2-D6: the small-message limit (512 B) is also the durable limit, journalled at both ends.
    const Bytes full = bytes_of(23, 512);
    LM_CHECK_EQ(lm_send(n.ctx(0), &rq, full.data(), full.size(), &op), LM_STATUS_OK);
    n.node(0).notify();
    LM_CHECK(n.until([&] { return n.op(0, op).outcome == LM_OUTCOME_RECEIVED; }, 60000));
    LM_CHECK((n.op(0, op).evidence_bits & delivery::ev::persisted) != 0);
    LM_CHECK(n.pop(3, m, LM_EVENT_MESSAGE));
    LM_CHECK(m.payload == full);
    // One byte more is refused up front.
    const Bytes too_big = bytes_of(22, 513);
    LM_CHECK_EQ(lm_send(n.ctx(0), &rq, too_big.data(), too_big.size(), &op), LM_STATUS_PAYLOAD_TOO_LARGE);
}

LM_TEST("R10 sim: stopping both ends in the middle of a transfer releases every slot, lane and buffer") {
    Net n(3, true);
    n.routes(0, 2);
    warm_up(n, 0, 2);
    const std::size_t free_o = n.dv(0).free_msg_buffers();
    const std::size_t free_d = n.dv(2).free_msg_buffers();
    const auto s = n.send(0, 2, LM_RECEIVED, bytes_of(23, 3000), 200000, true); // object lane on both ends
    const auto s2 = n.send(0, 2, LM_RECEIVED, bytes_of(24, 400), 200000);
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    LM_CHECK_EQ(s2.st, LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.dv(2).frag_stats().rx >= 4u; }, 30000));
    LM_CHECK_EQ(lm_stop(n.ctx(2), 0, nullptr), LM_STATUS_OK);
    LM_CHECK_EQ(lm_stop(n.ctx(0), 0, nullptr), LM_STATUS_OK);
    n.run_ms(1000);
    LM_CHECK_EQ(n.dv(2).free_msg_buffers(), free_d);
    LM_CHECK_EQ(n.dv(0).free_msg_buffers(), free_o);
}

LM_TEST("measure: sizeof of the fragment state and owner stack depth of fragmenting, reassembling and a fragmented receipt") {
    std::printf("  [measure] sizeof: FragState=%zu RxSlot=%zu Active=%zu InEntry=%zu (slots=%zu, small=%zu, object lane %s)\n",
                sizeof(delivery::FragState), sizeof(delivery::RxSlot), sizeof(delivery::Active), sizeof(delivery::InEntry),
                delivery::k_frag_slots, delivery::k_small_slots, delivery::k_object_capable ? "built" : "not built");
    Net n(31); // 30 hops: a receipt with a result no longer fits one frame
    n.routes(0, 30);
    warm_up(n, 0, 30);
    const std::size_t idle = lmtest::depth_of([&] { n.run_ms(1); });
    lm_operation_id_t op_id = 0;
    const std::size_t d_send = lmtest::depth_of([&] { // fragments out, reassembly at the destination
        op_id = n.send(0, 30, LM_APPLIED, bytes_of(1, 400), 600000).op;
        n.run_ms(60000);
    });
    Received m;
    LM_CHECK(n.pop(30, m, LM_EVENT_MESSAGE));
    const std::size_t d_report = lmtest::depth_of([&] { // the fragmented receipt back to the origin
        (void)n.report(30, m.ev, LM_OUTCOME_APPLIED, bytes_of(2, 32));
        n.run_ms(60000);
    });
    LM_CHECK(n.op(0, op_id).outcome == LM_OUTCOME_APPLIED);
    const std::size_t depth = std::max(d_send, d_report);
    std::printf("  [measure] send %zu report %zu\n", d_send, d_report);
    LM_CHECK(n.dv(30).frag_stats().tx > 0u);
    std::printf("  [measure] owner-side stack depth, fragmented APPLIED exchange over 30 hops: %zu B (simulator baseline %zu B => ~%zu B)\n",
                depth, idle, depth > idle ? depth - idle : 0);
#if LM_STACK_PROBE_EXACT
    LM_CHECK(depth - idle < 4000); // the owner task stack is 4 KiB (S3): regression guard
#endif
}

LM_TEST_MAIN()
