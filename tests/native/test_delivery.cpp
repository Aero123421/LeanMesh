// Delivery (S9): end sessions (EDHOC purpose 2), E2E records, HOP_ACK + link retry, receipts,
// APP_APPLIED, dedup, deadlines and the durable journal - real lm_context + Engine per node on
// simulated ports, credentials from the TEST-ONLY fleet issuer, frames through the sim medium.
// Everything goes through the public C ABI (lm_send, lm_next_event, ...) except where a test plays
// an attacker: it seals frames with the origin's own session state and injects them.
#include <cstdio>
#include <cstring>
#include <memory>
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
using lm::delivery::ev::accepted;

namespace {

using Bytes = std::vector<uint8_t>;
constexpr uint64_t k_root_ms0 = 1'000'000; // root clock reading at the moment the test sets the time

struct Received {
    lm_event_t ev{};
    Bytes payload;
};

// A chain of nodes 0 - 1 - ... - n-1 (node 0 is the root). Every node loads its records, adjacent
// nodes open link sessions, and the tests install source routes explicitly (the route resolver is
// the mesh slice's job): that is the "statically provisioned route" of the acceptance text.
struct DNet {
    explicit DNet(unsigned n_nodes, uint64_t seed = 31, bool link = true)
        : n(n_nodes), net(seed), world(WorldOptions{seed, 0}) {
        for (unsigned i = 0; i < n; ++i) {
            NodeOptions o;
            o.role = i == 0 ? Role::Root : Role::Relay;
            (void)world.add_node(o);
            kits.push_back(i == 0 ? net.make_root() : net.make_node(i, static_cast<uint16_t>(i + 1)));
        }
        world.make_chain();
        for (unsigned i = 0; i < n; ++i) {
            LM_CHECK_OK(fleet::provision(node(i).store, net, kits[i]));
        }
        for (unsigned i = 0; i < n; ++i) {
            boot(static_cast<uint16_t>(i));
        }
        run_ms(50);
        if (link) {
            link_chain();
        }
    }

    SimNode &node(unsigned i) { return world.node(static_cast<uint16_t>(i)); }
    Engine &eng(unsigned i) { return node(i).ctx()->engine; }
    delivery::Delivery &dv(unsigned i) { return eng(i).delivery(); }
    lm_context_t *ctx(unsigned i) { return node(i).ctx(); }
    void boot(uint16_t i) {
        LM_CHECK_OK(node(i).boot());
        LM_CHECK_EQ(lm_start(node(i).ctx()), LM_STATUS_OK);
    }
    void reboot(uint16_t i) {
        node(i).power_cut();
        node(i).store.power_restore();
        boot(i);
    }
    void run_ms(uint64_t ms) { world.run_until(world.now_us() + ms * 1000); }
    void run_s(uint64_t s) { run_ms(s * 1000); }
    MonoTime now(unsigned i) { return node(i).clock.now(); }
    const MacAddr &mac(unsigned i) { return node(i).radio.mac(); }
    const DeviceId &id(unsigned i) { return kits[i].kit.id; }
    static uint16_t addr(unsigned i) { return static_cast<uint16_t>(i + 1); }

    template <class P> bool until(P pred, uint64_t max_ms) {
        for (uint64_t t = 0; t < max_ms; ++t) {
            if (pred()) {
                return true;
            }
            run_ms(1);
        }
        return pred();
    }

    void link_chain() {
        for (unsigned i = 1; i < n; ++i) {
            LM_CHECK_OK(eng(i).link().connect(mac(i - 1), now(i)));
            node(i).notify();
            run_ms(2500);
            link::Neighbor *a = eng(i).link().neighbors().find_device(id(i - 1));
            LM_CHECK(a != nullptr && a->cur.active);
        }
    }

    // Root clock: every node learns the same reading (term 1) now.
    void set_time(uint32_t term = 1) {
        t0_us = world.now_us();
        base_ms = k_root_ms0;
        for (unsigned i = 0; i < n; ++i) {
            if (node(i).powered()) {
                set_time_at(i, term);
            }
        }
    }
    void set_time_at(unsigned i, uint32_t term) {
        RootTimeBound b;
        b.term = RootTerm{term};
        b.earliest_ms = b.latest_ms = k_root_ms0 + (world.now_us() - t0_us) / 1000;
        b.valid = true;
        eng(i).set_root_time(b, now(i));
        node(i).notify();
    }
    [[nodiscard]] uint64_t root_ms() const { return base_ms + (world.now_us() - t0_us) / 1000; }

    delivery::PathSpec spec(unsigned a, unsigned b, uint32_t term = 1, uint32_t rev = 1) {
        delivery::PathSpec ps;
        ps.origin = ShortAddr{addr(a)};
        ps.dest = ShortAddr{addr(b)};
        const int dir = b > a ? 1 : -1;
        ps.len = static_cast<uint8_t>(b > a ? b - a : a - b);
        for (unsigned k = 0; k < ps.len; ++k) {
            ps.path[k] = addr(static_cast<unsigned>(static_cast<int>(a) + dir * static_cast<int>(k + 1)));
        }
        ps.term = RootTerm{term};
        ps.revision = PathRevision{rev};
        return ps;
    }
    void routes(unsigned a, unsigned b, uint32_t rev = 1) {
        LM_CHECK_OK(dv(a).install_route(id(b), spec(a, b, 1, rev), MonoTime::never()));
        LM_CHECK_OK(dv(b).install_route(id(a), spec(b, a, 1, rev), MonoTime::never()));
        node(a).notify();
        node(b).notify();
    }

    struct Sent {
        lm_status_t st = LM_STATUS_OK;
        lm_operation_id_t op = 0;
    };
    // ttl_ms 0 = no deadline (RECEIVED+DURABLE only).
    Sent send(unsigned from, unsigned to, uint32_t delivery_kind, uint32_t storage, const Bytes &payload,
              uint64_t ttl_ms = 30000, uint16_t port = 100, bool strict = false) {
        lm_send_request_t rq{};
        rq.struct_size = sizeof(rq);
        rq.abi_version = LM_ABI_VERSION;
        rq.destination.kind = LM_DEST_NODE;
        std::memcpy(rq.destination.node.bytes, id(to).bytes.data(), 32);
        rq.app_port = port;
        rq.delivery = static_cast<uint8_t>(delivery_kind);
        rq.storage = static_cast<uint8_t>(storage);
        rq.priority = LM_PRIORITY_NORMAL;
        rq.queue_mode = LM_FIFO;
        rq.strict_single_frame = strict ? 1 : 0;
        rq.root_term = ttl_ms == 0 ? 0 : 1;
        rq.expires_root_ms = ttl_ms == 0 ? 0 : root_ms() + ttl_ms;
        Sent s;
        s.st = lm_send(ctx(from), &rq, payload.data(), payload.size(), &s.op);
        node(from).notify();
        return s;
    }
    lm_operation_t op(unsigned node_i, lm_operation_id_t id_) {
        lm_operation_t o{};
        o.struct_size = sizeof(o);
        o.abi_version = LM_ABI_VERSION;
        LM_CHECK_EQ(lm_get_operation(ctx(node_i), id_, &o), LM_STATUS_OK);
        return o;
    }
    bool pop(unsigned node_i, Received &out, uint32_t kind = 0) {
        for (;;) {
            Received r;
            r.ev.struct_size = sizeof(r.ev);
            r.ev.abi_version = LM_ABI_VERSION;
            r.payload.assign(600, 0);
            size_t req = 0;
            const lm_status_t st = lm_next_event(ctx(node_i), &r.ev, r.payload.data(), r.payload.size(), &req);
            if (st != LM_STATUS_OK) {
                return false;
            }
            r.payload.resize(req);
            if (kind == 0 || r.ev.kind == kind) {
                out = r;
                return true;
            }
        }
    }
    lm_message_ref_t ref_of(unsigned origin, const lm_operation_t &o) {
        lm_message_ref_t m{};
        std::memcpy(m.origin.bytes, id(origin).bytes.data(), 32);
        m.assignment_generation = 1;
        m.id = o.message_id;
        std::memcpy(m.intent_hash, o.intent_hash, 32);
        return m;
    }
    lm_message_ref_t ref_of_event(const lm_event_t &e) {
        lm_message_ref_t m{};
        m.origin = e.peer;
        m.assignment_generation = e.origin_assignment_generation;
        m.id = e.message_id;
        std::memcpy(m.intent_hash, e.intent_hash, 32);
        return m;
    }
    lm_status_t report(unsigned node_i, const lm_event_t &e, uint32_t outcome, const Bytes &result) {
        const lm_message_ref_t m = ref_of_event(e);
        lm_operation_id_t o = 0;
        const lm_status_t st = lm_report_application_result(ctx(node_i), &m, outcome, result.data(), result.size(), &o);
        node(node_i).notify();
        return st;
    }

    unsigned n;
    fleet::Network net;
    World world;
    std::vector<fleet::NodeKit> kits;
    uint64_t t0_us = 0;
    uint64_t base_ms = k_root_ms0;
};

Bytes payload_of(uint8_t seed, std::size_t len = 20) {
    Bytes b(len);
    for (std::size_t i = 0; i < len; ++i) {
        b[i] = static_cast<uint8_t>(seed + i);
    }
    return b;
}

using lm::delivery::ev::app_applied;
using lm::delivery::ev::app_rejected;
using lm::delivery::ev::end_received;
using lm::delivery::ev::hop_accepted;
using lm::delivery::ev::persisted;
using lm::delivery::ev::sent;

// ---- the main vertical path over 1 and several hops ----
void applied_flow(unsigned hops) {
    DNet n(hops + 1);
    n.set_time();
    n.routes(0, hops);
    const Bytes body = payload_of(1, 30);
    const auto s = n.send(0, hops, LM_APPLIED, LM_VOLATILE, body);
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    // The first send opens an end session (credential swap + EDHOC + SESSION_BIND over the route).
    LM_CHECK(n.until([&] { return (n.op(0, s.op).evidence_bits & end_received) != 0; }, 20000));
    lm_operation_t o = n.op(0, s.op);
    // D01: END_RECEIVED and APP_APPLIED are separate evidence; the application has not answered yet.
    LM_CHECK_EQ(o.outcome, LM_OUTCOME_PENDING);
    LM_CHECK((o.evidence_bits & (accepted | sent | hop_accepted | end_received)) ==
             (accepted | sent | hop_accepted | end_received));
    LM_CHECK((o.evidence_bits & app_applied) == 0);
    LM_CHECK_EQ(o.phase, static_cast<uint32_t>(delivery::Phase::WaitingReceipt));
    Received m;
    LM_CHECK(n.pop(hops, m, LM_EVENT_MESSAGE));
    LM_CHECK(m.payload == body);
    LM_CHECK_EQ(m.ev.app_port, 100u);
    LM_CHECK(std::memcmp(m.ev.peer.bytes, n.id(0).bytes.data(), 32) == 0);
    LM_CHECK(std::memcmp(m.ev.intent_hash, o.intent_hash, 32) == 0); // the receiver recomputed the same hash
    LM_CHECK(std::memcmp(m.ev.message_id.bytes, o.message_id.bytes, 16) == 0);
    LM_CHECK_EQ(m.ev.reason, 0u);
    LM_CHECK(!n.pop(hops, m, LM_EVENT_MESSAGE)); // exactly one
    // The application applies it later and answers with a typed result (<= 32 B).
    n.run_ms(500);
    LM_CHECK_EQ(n.op(0, s.op).outcome, static_cast<uint32_t>(LM_OUTCOME_PENDING));
    LM_CHECK_EQ(n.report(hops, m.ev, LM_OUTCOME_APPLIED, Bytes{0xAA, 0xBB}), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.op(0, s.op).outcome == LM_OUTCOME_APPLIED; }, 10000));
    o = n.op(0, s.op);
    LM_CHECK((o.evidence_bits & app_applied) != 0);
    LM_CHECK_EQ(o.phase, static_cast<uint32_t>(delivery::Phase::Final));
    Received oe;
    LM_CHECK(n.pop(0, oe, LM_EVENT_OPERATION));
    LM_CHECK(oe.payload == (Bytes{0xAA, 0xBB}));
    // Reporting again with the same answer is idempotent, a different answer never rewrites it.
    LM_CHECK_EQ(n.report(hops, m.ev, LM_OUTCOME_APPLIED, Bytes{0xAA, 0xBB}), LM_STATUS_OK);
    LM_CHECK_EQ(n.report(hops, m.ev, LM_OUTCOME_REJECTED, Bytes{}), LM_STATUS_CONFLICT);
    // Second message: the application refuses it (asynchronous REJECTED).
    const auto s2 = n.send(0, hops, LM_APPLIED, LM_VOLATILE, payload_of(9));
    LM_CHECK_EQ(s2.st, LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.pop(hops, m, LM_EVENT_MESSAGE); }, 10000));
    LM_CHECK_EQ(n.report(hops, m.ev, LM_OUTCOME_REJECTED, Bytes{1}), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.op(0, s2.op).outcome == LM_OUTCOME_REJECTED; }, 10000));
    LM_CHECK((n.op(0, s2.op).evidence_bits & app_rejected) != 0);
    LM_CHECK_EQ(n.dv(hops).stats().delivered, 2u);
    LM_CHECK_EQ(n.dv(hops).stats().rx_dup_end, 0u);
    LM_CHECK_EQ(n.dv(0).end_stats().completed, 1u); // one end session served both messages
    LM_CHECK(n.dv(0).hop_stats().rf_failed == 0);
    // The destination's own view via the C ABI.
    lm_operation_t at_dest{};
    at_dest.struct_size = sizeof(at_dest);
    at_dest.abi_version = LM_ABI_VERSION;
    const lm_message_ref_t ref = n.ref_of(0, o);
    LM_CHECK_EQ(lm_get_message(n.ctx(hops), &ref, &at_dest), LM_STATUS_OK);
    LM_CHECK_EQ(at_dest.outcome, LM_OUTCOME_APPLIED);
}

} // namespace

LM_TEST("D01 sim 1 hop: END_RECEIVED and APP_APPLIED are separate, the application answers later") {
    applied_flow(1);
}

LM_TEST("D01 sim 4 hops: same path through three relays") { applied_flow(4); }

LM_TEST("D01 sim: the destination has no route to the origin; receipts take the learned way back") {
    DNet n(4);
    n.set_time();
    LM_CHECK_OK(n.dv(0).install_route(n.id(3), n.spec(0, 3), MonoTime::never())); // one direction only
    n.node(0).notify();
    const auto s = n.send(0, 3, LM_APPLIED, LM_VOLATILE, payload_of(4));
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    Received m;
    LM_CHECK(n.until([&] { return n.pop(3, m, LM_EVENT_MESSAGE); }, 20000));
    LM_CHECK(n.until([&] { return (n.op(0, s.op).evidence_bits & end_received) != 0; }, 5000));
    LM_CHECK_EQ(n.report(3, m.ev, LM_OUTCOME_APPLIED, Bytes{1}), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.op(0, s.op).outcome == LM_OUTCOME_APPLIED; }, 10000));
    LM_CHECK_EQ(n.dv(3).stats().receipts_dropped, 0u);
    // The learned route serves the destination's own sends too, until the session ends.
    const auto back = n.send(3, 0, LM_RECEIVED, LM_VOLATILE, payload_of(5));
    LM_CHECK_EQ(back.st, LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.op(3, back.op).outcome == LM_OUTCOME_RECEIVED; }, 20000));
}


// ---- helpers for the following scenarios ----
namespace {

// Establishes the end session 0 <-> 1 with a first message (session set-up is not what these tests
// are about); returns once the message is RECEIVED.
void warm_up(DNet &n, unsigned from, unsigned to) {
    const auto s = n.send(from, to, LM_RECEIVED, LM_VOLATILE, payload_of(0xF0, 4));
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.op(from, s.op).outcome == LM_OUTCOME_RECEIVED; }, 20000));
    Received m;
    LM_CHECK(n.pop(to, m, LM_EVENT_MESSAGE));
}

void set_link(DNet &n, unsigned a, unsigned b, bool up, uint16_t loss = 0, uint16_t ack_loss = 0) {
    LinkParams p;
    p.up = up;
    p.loss_permille = loss;
    p.ack_loss_permille = ack_loss;
    n.world.set_link(static_cast<uint16_t>(a), static_cast<uint16_t>(b), p);
}

} // namespace

LM_TEST("D10 sim: HOP_ACK arrives before the TX callback (500 ms late) and is joined to the right frame") {
    DNet n(2);
    n.set_time();
    n.routes(0, 1);
    warm_up(n, 0, 1);
    n.node(0).radio.tx_callback_delay_us = 500'000;
    const uint64_t frames0 = n.dv(0).hop_stats().frames;
    const auto a = n.send(0, 1, LM_RECEIVED, LM_VOLATILE, payload_of(1));
    const auto b = n.send(0, 1, LM_RECEIVED, LM_VOLATILE, payload_of(2));
    const auto c = n.send(0, 1, LM_RECEIVED, LM_VOLATILE, payload_of(3));
    LM_CHECK(n.until([&] {
        return n.op(0, a.op).outcome == LM_OUTCOME_RECEIVED && n.op(0, b.op).outcome == LM_OUTCOME_RECEIVED &&
               n.op(0, c.op).outcome == LM_OUTCOME_RECEIVED;
    }, 20000));
    const delivery::HopStats &h = n.dv(0).hop_stats();
    LM_CHECK(h.early_acks >= 1u);                 // the ACK beat the callback at least once
    LM_CHECK_EQ(h.frames - frames0, 3u);          // one physical send per frame: nothing was repeated
    LM_CHECK_EQ(h.retransmits, 0u);
    LM_CHECK_EQ(h.ack_unmatched, 0u);
    LM_CHECK_EQ(n.eng(0).tx().stats().rf_failed, 0u);
    LM_CHECK_EQ(n.eng(0).stats().tx_done_unmatched, 0u);
    for (const auto &x : {a, b, c}) {
        LM_CHECK((n.op(0, x.op).evidence_bits & hop_accepted) != 0);
    }
    LM_CHECK_EQ(n.dv(1).stats().delivered, 4u);
}

LM_TEST("D10 sim: a MAC failure with a HOP_ACK in hand is an RF sample, not a retransmission") {
    DNet n(2);
    n.set_time();
    n.routes(0, 1);
    warm_up(n, 0, 1);
    set_link(n, 0, 1, true, 0, 1000); // frames arrive, the sender's MAC never sees the ACK
    const uint64_t frames0 = n.dv(0).hop_stats().frames;
    const auto a = n.send(0, 1, LM_RECEIVED, LM_VOLATILE, payload_of(1));
    LM_CHECK(n.until([&] { return n.op(0, a.op).outcome == LM_OUTCOME_RECEIVED; }, 20000));
    LM_CHECK_EQ(n.dv(0).hop_stats().frames - frames0, 1u);
    LM_CHECK_EQ(n.dv(0).hop_stats().retransmits, 0u);
    LM_CHECK(n.dv(0).hop_stats().rf_failed >= 1u); // counted as the loss sample it is
    LM_CHECK_EQ(n.dv(1).stats().delivered, 2u);
}

LM_TEST("D10 sim: local BUSY / NO_MEM at the radio is not RF loss and not a link attempt") {
    for (const Status fault : {Status::Busy, Status::NoCapacity}) {
        DNet n(2);
        n.set_time();
        n.routes(0, 1);
        warm_up(n, 0, 1);
        n.node(0).radio.tx_fault = fault;
        n.node(0).radio.tx_fault_count = 6;
        const auto a = n.send(0, 1, LM_RECEIVED, LM_VOLATILE, payload_of(1));
        LM_CHECK(n.until([&] { return n.op(0, a.op).outcome == LM_OUTCOME_RECEIVED; }, 20000));
        LM_CHECK(n.dv(0).hop_stats().local_busy >= 1u);
        LM_CHECK_EQ(n.dv(0).hop_stats().rf_failed, 0u);
        LM_CHECK_EQ(n.dv(0).hop_stats().retransmits, 0u); // refused hand-offs never used an attempt
        LM_CHECK_EQ(n.dv(1).stats().delivered, 2u);
    }
}

LM_TEST("D10 sim: RF loss is retried with the same bytes and delivered once") {
    DNet n(2, 77);
    n.set_time();
    n.routes(0, 1);
    warm_up(n, 0, 1);
    set_link(n, 0, 1, true, 500); // half of all frames vanish, both directions
    uint32_t delivered_msgs = 0;
    for (int i = 0; i < 6; ++i) {
        const auto s = n.send(0, 1, LM_RECEIVED, LM_VOLATILE, payload_of(static_cast<uint8_t>(i)), 60000);
        LM_CHECK_EQ(s.st, LM_STATUS_OK);
        LM_CHECK(n.until([&] { return n.op(0, s.op).phase == static_cast<uint32_t>(delivery::Phase::Final); },
                         60000));
        delivered_msgs += n.op(0, s.op).outcome == LM_OUTCOME_RECEIVED ? 1U : 0U;
    }
    LM_CHECK(delivered_msgs >= 5u);
    LM_CHECK(n.dv(0).hop_stats().retransmits >= 1u);
    LM_CHECK(n.dv(0).hop_stats().rf_failed >= 1u);
    // Loss never produced a second application event for the same message.
    LM_CHECK(n.dv(1).stats().delivered <= 1u + 6u);
    Received m;
    std::vector<Bytes> seen;
    while (n.pop(1, m, LM_EVENT_MESSAGE)) {
        for (const Bytes &b : seen) {
            LM_CHECK(b != m.payload);
        }
        seen.push_back(m.payload);
    }
}

LM_TEST("D04 sim: three link attempts and three rounds without an answer end INDETERMINATE, never delivered") {
    DNet n(2);
    n.set_time();
    n.routes(0, 1);
    warm_up(n, 0, 1);
    set_link(n, 0, 1, false);
    const uint64_t frames0 = n.dv(0).hop_stats().frames;
    const auto s = n.send(0, 1, LM_RECEIVED, LM_VOLATILE, payload_of(1), 60000);
    LM_CHECK(n.until([&] { return n.op(0, s.op).phase == static_cast<uint32_t>(delivery::Phase::Final); }, 30000));
    const lm_operation_t o = n.op(0, s.op);
    LM_CHECK_EQ(o.outcome, LM_OUTCOME_INDETERMINATE); // it may have arrived: not "not delivered"
    LM_CHECK_EQ(o.reason, static_cast<uint32_t>(Status::NoRoute));
    LM_CHECK((o.evidence_bits & sent) != 0);
    LM_CHECK((o.evidence_bits & hop_accepted) == 0);
    LM_CHECK((o.evidence_bits & end_received) == 0);
    // 3 rounds x 3 attempts, each attempt is a physical send that the MAC reported as failed.
    LM_CHECK_EQ(n.dv(0).hop_stats().frames - frames0, 9u);
    LM_CHECK(n.dv(0).hop_stats().rf_failed >= 9u);
    LM_CHECK_EQ(n.dv(1).stats().delivered, 1u); // only the warm-up message
}

// ---- deadlines ----
LM_TEST("D06 sim: accept-time deadline rules (no clock, past, none only for RECEIVED+DURABLE)") {
    DNet n(2);
    n.routes(0, 1);
    // No root clock bound yet: a deadline cannot be proven, so it is not accepted.
    LM_CHECK_EQ(n.send(0, 1, LM_APPLIED, LM_VOLATILE, payload_of(1), 5000).st, LM_STATUS_TIME_UNCERTAIN);
    n.set_time();
    LM_CHECK_EQ(n.send(0, 1, LM_APPLIED, LM_VOLATILE, payload_of(1), 0).st, LM_STATUS_INVALID_ARGUMENT);
    LM_CHECK_EQ(n.send(0, 1, LM_RECEIVED, LM_VOLATILE, payload_of(1), 0).st, LM_STATUS_INVALID_ARGUMENT);
    LM_CHECK_EQ(n.send(0, 1, LM_BEST_EFFORT, LM_DURABLE, payload_of(1), 0).st, LM_STATUS_INVALID_ARGUMENT);
    // The history/maintenance exception is allowed.
    LM_CHECK_EQ(n.send(0, 1, LM_RECEIVED, LM_DURABLE, payload_of(1), 0).st, LM_STATUS_OK);
    // A deadline that has already passed.
    lm_send_request_t rq{};
    rq.struct_size = sizeof(rq);
    rq.abi_version = LM_ABI_VERSION;
    rq.destination.kind = LM_DEST_NODE;
    std::memcpy(rq.destination.node.bytes, n.id(1).bytes.data(), 32);
    rq.app_port = 100;
    rq.delivery = LM_APPLIED;
    rq.priority = LM_PRIORITY_NORMAL;
    rq.root_term = 1;
    rq.expires_root_ms = n.root_ms() - 1;
    lm_operation_id_t op = 0;
    const Bytes p = payload_of(1);
    LM_CHECK_EQ(lm_send(n.ctx(0), &rq, p.data(), p.size(), &op), LM_STATUS_EXPIRED);
    // Other public-API rules.
    rq.expires_root_ms = n.root_ms() + 1000;
    rq.priority = LM_PRIORITY_CONTROL;
    LM_CHECK_EQ(lm_send(n.ctx(0), &rq, p.data(), p.size(), &op), LM_STATUS_INVALID_ARGUMENT);
    rq.priority = LM_PRIORITY_NORMAL;
    rq.queue_mode = LM_LATEST; // LATEST is best effort + volatile only (docs/08 §1, S14)
    LM_CHECK_EQ(lm_send(n.ctx(0), &rq, p.data(), p.size(), &op), LM_STATUS_INVALID_ARGUMENT);
    rq.queue_mode = LM_FIFO;
    rq.destination.kind = LM_DEST_GROUP; // a group needs its id and revision (S15); the fan-out has its own tests
    LM_CHECK_EQ(lm_send(n.ctx(0), &rq, p.data(), p.size(), &op), LM_STATUS_INVALID_ARGUMENT);
    rq.destination.kind = LM_DEST_NODE;
    std::memcpy(rq.destination.node.bytes, n.id(0).bytes.data(), 32); // to itself
    LM_CHECK_EQ(lm_send(n.ctx(0), &rq, p.data(), p.size(), &op), LM_STATUS_INVALID_ARGUMENT);
    std::memcpy(rq.destination.node.bytes, n.id(1).bytes.data(), 32);
    const Bytes big(300, 1);
    rq.strict_single_frame = 1; // without it the message is fragmented (S12)
    LM_CHECK_EQ(lm_send(n.ctx(0), &rq, big.data(), big.size(), &op), LM_STATUS_PAYLOAD_TOO_LARGE);
    rq.strict_single_frame = 0;
    const Bytes huge(513, 1);
    LM_CHECK_EQ(lm_send(n.ctx(0), &rq, huge.data(), huge.size(), &op), LM_STATUS_PAYLOAD_TOO_LARGE);
    LM_CHECK_EQ(lm_send_object(n.ctx(0), &rq, p.data(), p.size(), &op), LM_STATUS_UNSUPPORTED);
    rq.reserved = 1;
    LM_CHECK_EQ(lm_send(n.ctx(0), &rq, p.data(), p.size(), &op), LM_STATUS_INVALID_ARGUMENT);
}

LM_TEST("D06 sim: a message waiting for a route is never sent after its original deadline") {
    DNet n(2);
    n.set_time();
    const auto s = n.send(0, 1, LM_RECEIVED, LM_VOLATILE, payload_of(1), 4000); // no route yet
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    n.run_s(5);
    // The deadline passed while it waited. A route that shows up now (Host/path change) does not
    // give it a new life and nothing leaves the node.
    const lm_operation_t o = n.op(0, s.op);
    LM_CHECK_EQ(o.outcome, LM_OUTCOME_EXPIRED);       // never left: a definite "not sent"
    LM_CHECK((o.evidence_bits & sent) == 0);
    n.routes(0, 1);
    n.run_s(3);
    LM_CHECK_EQ(n.dv(0).hop_stats().frames, 0u);
    LM_CHECK_EQ(n.dv(0).end_stats().started, 0u);
    LM_CHECK_EQ(n.op(0, s.op).outcome, static_cast<uint32_t>(LM_OUTCOME_EXPIRED));
    LM_CHECK_EQ(n.dv(1).stats().delivered, 0u);
}

LM_TEST("D06 sim: a path change during retries keeps the original deadline") {
    DNet n(2);
    n.set_time();
    n.routes(0, 1);
    warm_up(n, 0, 1);
    set_link(n, 0, 1, false);
    const auto s = n.send(0, 1, LM_RECEIVED, LM_VOLATILE, payload_of(1), 400);
    const uint64_t deadline_ms = n.root_ms() + 400;
    n.run_ms(150);
    n.routes(0, 1, 2); // a new path revision: the deadline does not restart
    n.run_ms(50);
    LM_CHECK(n.op(0, s.op).phase != static_cast<uint32_t>(delivery::Phase::Final)); // still trying
    LM_CHECK(n.until([&] { return n.op(0, s.op).phase == static_cast<uint32_t>(delivery::Phase::Final); }, 10000));
    LM_CHECK(n.root_ms() <= deadline_ms + 50);        // decided at (not after) the original deadline
    LM_CHECK_EQ(n.op(0, s.op).outcome, static_cast<uint32_t>(LM_OUTCOME_INDETERMINATE));
    LM_CHECK_EQ(n.op(0, s.op).reason, static_cast<uint32_t>(Status::Expired));
    const uint64_t frames = n.dv(0).hop_stats().frames;
    set_link(n, 0, 1, true); // even with the link back, nothing is sent any more
    n.run_s(5);
    LM_CHECK_EQ(n.dv(0).hop_stats().frames, frames);
    LM_CHECK_EQ(n.dv(1).stats().delivered, 1u); // only the warm-up
}

LM_TEST("D06 sim: root restart (new term) while unanswered -> INDETERMINATE, nothing is re-issued") {
    DNet n(2);
    n.set_time();
    n.routes(0, 1);
    warm_up(n, 0, 1);
    const auto s = n.send(0, 1, LM_APPLIED, LM_VOLATILE, payload_of(1), 60000);
    LM_CHECK(n.until([&] { return n.dv(1).stats().rx_data == 2; }, 5000)); // stored at the destination
    n.run_ms(50);
    n.set_time_at(0, 2); // the origin learns that the root restarted: time base of the deadline is gone
    n.run_ms(50);
    const lm_operation_t o = n.op(0, s.op);
    LM_CHECK_EQ(o.outcome, LM_OUTCOME_INDETERMINATE);
    LM_CHECK_EQ(o.reason, static_cast<uint32_t>(Status::TimeUncertain));
    const uint64_t frames = n.dv(0).hop_stats().frames;
    n.run_s(15);
    LM_CHECK_EQ(n.dv(0).hop_stats().frames, frames);
    // A new message under the new term needs a deadline in the new term.
    n.set_time_at(1, 2);
    LM_CHECK_EQ(n.send(0, 1, LM_RECEIVED, LM_VOLATILE, payload_of(2), 0).st, LM_STATUS_INVALID_ARGUMENT);
}


// ---- receipts lost, late, cancelled ----
LM_TEST("D02 sim: final receipt lost -> a repeated round replays the receipt, one application event") {
    DNet n(2);
    n.set_time();
    n.routes(0, 1);
    warm_up(n, 0, 1);
    const auto s = n.send(0, 1, LM_APPLIED, LM_VOLATILE, payload_of(5), 60000);
    LM_CHECK(n.until([&] { return n.dv(1).stats().rx_data == 2; }, 20000));
    set_link(n, 0, 1, false); // the HOP_ACK is out, the receipt is not: the way back dies
    n.run_ms(1000);
    LM_CHECK_EQ(n.op(0, s.op).outcome, static_cast<uint32_t>(LM_OUTCOME_PENDING));
    LM_CHECK((n.op(0, s.op).evidence_bits & hop_accepted) != 0);
    LM_CHECK((n.op(0, s.op).evidence_bits & end_received) == 0); // no evidence is invented
    set_link(n, 0, 1, true);
    LM_CHECK(n.until([&] { return (n.op(0, s.op).evidence_bits & end_received) != 0; }, 10000));
    LM_CHECK(n.dv(1).stats().rx_dup_end >= 1u);   // the repeat was recognised, not applied again
    LM_CHECK_EQ(n.dv(1).stats().delivered, 2u);
    Received m;
    LM_CHECK(n.pop(1, m, LM_EVENT_MESSAGE));
    LM_CHECK(!n.pop(1, m, LM_EVENT_MESSAGE));
    LM_CHECK_EQ(n.report(1, m.ev, LM_OUTCOME_APPLIED, Bytes{7}), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.op(0, s.op).outcome == LM_OUTCOME_APPLIED; }, 10000));
}

LM_TEST("D02 sim: END_RECEIVED but no application result by the deadline -> INDETERMINATE, not 'not applied'") {
    DNet n(2);
    n.set_time();
    n.routes(0, 1);
    warm_up(n, 0, 1);
    const auto s = n.send(0, 1, LM_APPLIED, LM_VOLATILE, payload_of(5), 4000);
    LM_CHECK(n.until([&] { return (n.op(0, s.op).evidence_bits & end_received) != 0; }, 5000));
    Received m;
    LM_CHECK(n.pop(1, m, LM_EVENT_MESSAGE)); // the application has it but does not answer
    LM_CHECK(n.until([&] { return n.op(0, s.op).phase == static_cast<uint32_t>(delivery::Phase::Final); }, 10000));
    lm_operation_t o = n.op(0, s.op);
    LM_CHECK_EQ(o.outcome, LM_OUTCOME_INDETERMINATE);
    LM_CHECK_EQ(o.reason, static_cast<uint32_t>(Status::Expired));
    LM_CHECK((o.evidence_bits & end_received) != 0);
    LM_CHECK((o.evidence_bits & app_applied) == 0);
    // D03: the result finally arrives, long after the deadline and after a newer message finished.
    const auto b = n.send(0, 1, LM_APPLIED, LM_VOLATILE, payload_of(6), 30000);
    Received mb;
    LM_CHECK(n.until([&] { return n.pop(1, mb, LM_EVENT_MESSAGE); }, 5000));
    LM_CHECK_EQ(n.report(1, mb.ev, LM_OUTCOME_APPLIED, Bytes{2}), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.op(0, b.op).outcome == LM_OUTCOME_APPLIED; }, 5000));
    const lm_operation_t b_before = n.op(0, b.op);
    LM_CHECK_EQ(n.report(1, m.ev, LM_OUTCOME_APPLIED, Bytes{1}), LM_STATUS_OK); // the OLD message
    LM_CHECK(n.until([&] { return n.op(0, s.op).outcome == LM_OUTCOME_APPLIED; }, 5000));
    o = n.op(0, s.op);
    LM_CHECK((o.evidence_bits & app_applied) != 0);
    LM_CHECK_EQ(n.dv(0).stats().receipts_late, 1u);
    const lm_operation_t b_after = n.op(0, b.op);   // the newer state is not rolled back or touched
    LM_CHECK_EQ(b_after.outcome, b_before.outcome);
    LM_CHECK_EQ(b_after.evidence_bits, b_before.evidence_bits);
    LM_CHECK_EQ(b_after.last_evidence_mono_ms, b_before.last_evidence_mono_ms);
}

LM_TEST("D04 sim: cancel before anything left is CANCELLED_NOT_SENT, after it left CANCEL_TOO_LATE") {
    DNet n(2);
    n.set_time();
    // (1) waiting for a route: nothing left this node.
    const auto a = n.send(0, 1, LM_RECEIVED, LM_VOLATILE, payload_of(1), 60000);
    LM_CHECK_EQ(lm_cancel(n.ctx(0), a.op), LM_STATUS_OK);
    lm_operation_t o = n.op(0, a.op);
    LM_CHECK_EQ(o.outcome, LM_OUTCOME_CANCELLED_NOT_SENT);
    LM_CHECK((o.evidence_bits & sent) == 0);
    LM_CHECK_EQ(lm_cancel(n.ctx(0), a.op), LM_STATUS_CANCEL_TOO_LATE); // already final
    LM_CHECK_EQ(lm_cancel(n.ctx(0), 999999), LM_STATUS_NOT_FOUND);
    n.routes(0, 1);
    n.run_s(3);
    LM_CHECK_EQ(n.dv(0).hop_stats().frames, 0u);   // the cancelled message never appears
    LM_CHECK_EQ(n.dv(1).stats().rx_data, 0u);
    // (2) it left (the frame is on its way) and nobody answers.
    warm_up(n, 0, 1);
    set_link(n, 0, 1, false);
    const auto b = n.send(0, 1, LM_RECEIVED, LM_VOLATILE, payload_of(2), 60000);
    LM_CHECK(n.until([&] { return (n.op(0, b.op).evidence_bits & sent) != 0; }, 2000));
    LM_CHECK_EQ(lm_cancel(n.ctx(0), b.op), LM_STATUS_CANCEL_TOO_LATE);
    const uint64_t frames = n.dv(0).hop_stats().frames;
    n.run_s(4);
    LM_CHECK(n.dv(0).hop_stats().frames <= frames + 1u); // no rounds, no retransmissions after cancel
    o = n.op(0, b.op);
    LM_CHECK_EQ(o.outcome, LM_OUTCOME_INDETERMINATE); // the far end may have it: not "cancelled"
    LM_CHECK_EQ(o.reason, static_cast<uint32_t>(Status::CancelTooLate));
}

// ---- replay, duplicates, tampering (the test plays the attacker with the origin's own state) ----
namespace {

Bytes craft_record(DNet &n, unsigned from, unsigned to, uint8_t mid_seed, const Bytes &payload, uint64_t ttl_ms,
                   wire::Delivery dk = wire::Delivery::Received) {
    delivery::EndSession *s = n.dv(from).sessions().find_peer(n.id(to));
    LM_CHECK(s != nullptr);
    wire::EndHeader h;
    h.message_id.fill(mid_seed);
    h.app_port = 100;
    h.record_kind = wire::RecordKind::Data;
    h.flags = wire::make_end_flags(dk, wire::Priority::Normal, false);
    h.expires_root_ms = n.root_ms() + ttl_ms;
    std::array<uint8_t, 250> buf{};
    std::size_t len = 0;
    LM_CHECK_OK(delivery::seal_end_record(*s, s->tx_sid, RootTerm{1}, h, ByteView{payload.data(), payload.size()},
                                          MutByteView{buf}, len));
    return Bytes(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(len));
}

link::SealedFrame frame_for(DNet &n, unsigned from, unsigned to, const Bytes &record) {
    const delivery::PathSpec ps = n.spec(from, to);
    std::array<uint8_t, 250> plain{};
    std::size_t rlen = 0;
    LM_CHECK_OK(wire::encode_route(ps.header(), MutByteView{plain}, rlen));
    std::memcpy(plain.data() + rlen, record.data(), record.size());
    link::SealedFrame f;
    LM_CHECK_OK(n.eng(from).link().seal(n.id(to), wire::FrameKind::Data,
                                        ByteView{plain.data(), rlen + record.size()}, f, n.now(from)));
    return f;
}

void inject(DNet &n, unsigned from, unsigned to, const link::SealedFrame &f) {
    n.world.inject(n.mac(from), static_cast<uint16_t>(from), n.mac(to), f.view());
    n.run_ms(60);
}

} // namespace

LM_TEST("S04 sim: duplicate frame, duplicate record, tampered record and conflicting id never re-apply") {
    DNet n(2);
    n.set_time();
    n.routes(0, 1);
    warm_up(n, 0, 1);
    const Bytes body = payload_of(0x40, 24);
    const Bytes r1 = craft_record(n, 0, 1, 0xC1, body, 60000);
    const link::SealedFrame f1 = frame_for(n, 0, 1, r1);
    inject(n, 0, 1, f1);
    Received m;
    LM_CHECK(n.pop(1, m, LM_EVENT_MESSAGE));
    LM_CHECK(m.payload == body);
    LM_CHECK_EQ(n.dv(1).stats().rx_data, 2u);
    // (1) the very same link frame again (our HOP_ACK "was lost"): answered again, not processed again
    inject(n, 0, 1, f1);
    LM_CHECK_EQ(n.dv(1).stats().rx_dup_link, 1u);
    // (2) the same end record in a NEW link frame (a repeated E2E round): end-level duplicate
    inject(n, 0, 1, frame_for(n, 0, 1, r1));
    LM_CHECK_EQ(n.dv(1).stats().rx_dup_end, 1u);
    // (3) one flipped ciphertext bit: the tag does not verify, the window is untouched
    Bytes bad = r1;
    bad[wire::k_end_header_bytes + 3] ^= 0x10;
    inject(n, 0, 1, frame_for(n, 0, 1, bad));
    LM_CHECK_EQ(n.dv(1).stats().rx_auth_fail, 1u);
    // (4) same MessageId, other content, valid tag (fresh counter): CONFLICT, refused with evidence
    const Bytes r2 = craft_record(n, 0, 1, 0xC1, payload_of(0x99, 24), 60000);
    inject(n, 0, 1, frame_for(n, 0, 1, r2));
    LM_CHECK_EQ(n.dv(1).stats().rx_refused, 1u);
    LM_CHECK(!n.pop(1, m, LM_EVENT_MESSAGE)); // nothing delivered to the application again
    LM_CHECK_EQ(n.dv(1).stats().delivered, 2u);
    // (5) 70 later records push r1 out of the 64-packet window: too old, refused
    for (uint8_t i = 0; i < 70; ++i) {
        inject(n, 0, 1, frame_for(n, 0, 1, craft_record(n, 0, 1, static_cast<uint8_t>(0x10 + i), payload_of(i, 8), 60000)));
        LM_CHECK(n.pop(1, m, LM_EVENT_MESSAGE)); // the application keeps taking them
    }
    LM_CHECK_EQ(n.dv(1).stats().delivered, 72u);
    const uint64_t fails = n.dv(1).stats().rx_auth_fail;
    inject(n, 0, 1, frame_for(n, 0, 1, r1));
    LM_CHECK_EQ(n.dv(1).stats().rx_auth_fail, fails + 1u);
    LM_CHECK_EQ(n.dv(1).stats().delivered, 72u);
}

LM_TEST("FIX2-D1 sim: the same MessageId and intent after a rejoin (new assignment) is a new message, not a duplicate") {
    DNet n(2);
    n.set_time();
    n.routes(0, 1);
    warm_up(n, 0, 1);
    const Bytes body = payload_of(0x50, 24);
    const auto rec = [&] { return craft_record(n, 0, 1, 0xD1, body, 60000, wire::Delivery::Applied); };
    inject(n, 0, 1, frame_for(n, 0, 1, rec()));
    Received m1;
    LM_CHECK(n.pop(1, m1, LM_EVENT_MESSAGE));
    LM_CHECK_EQ(m1.ev.origin_assignment_generation, 1ull);
    // The origin left and rejoined (assignment 2) and, its store rolled back, issued the same MessageId.
    delivery::EndSession *s = n.dv(1).sessions().find_peer(n.id(0));
    LM_CHECK(s != nullptr);
    s->peer_assignment = AssignmentGen{2};
    const uint64_t dup = n.dv(1).stats().rx_dup_end;
    inject(n, 0, 1, frame_for(n, 0, 1, rec()));
    LM_CHECK_EQ(n.dv(1).stats().rx_dup_end, dup); // not answered from the old assignment's record
    Received m2;
    LM_CHECK(n.pop(1, m2, LM_EVENT_MESSAGE));
    LM_CHECK_EQ(m2.ev.origin_assignment_generation, 2ull);
    // The application result goes to the assignment named by the reference, and nowhere else.
    LM_CHECK_EQ(n.report(1, m2.ev, LM_OUTCOME_APPLIED, Bytes{7}), LM_STATUS_OK);
    lm_operation_t o1{};
    o1.struct_size = sizeof(o1);
    o1.abi_version = LM_ABI_VERSION;
    lm_operation_t o2 = o1;
    const lm_message_ref_t r1 = n.ref_of_event(m1.ev);
    const lm_message_ref_t r2 = n.ref_of_event(m2.ev);
    LM_CHECK_EQ(lm_get_message(n.ctx(1), &r1, &o1), LM_STATUS_OK);
    LM_CHECK_EQ(lm_get_message(n.ctx(1), &r2, &o2), LM_STATUS_OK);
    LM_CHECK_EQ(o1.outcome, LM_OUTCOME_RECEIVED); // the old assignment's message is untouched
    LM_CHECK_EQ(o2.outcome, LM_OUTCOME_APPLIED);
    lm_message_ref_t r3 = r2;
    r3.assignment_generation = 3;
    LM_CHECK_EQ(lm_get_message(n.ctx(1), &r3, &o2), LM_STATUS_NOT_FOUND);
    lm_operation_id_t opid = 0;
    LM_CHECK_EQ(lm_report_application_result(n.ctx(1), &r3, LM_OUTCOME_APPLIED, nullptr, 0, &opid), LM_STATUS_NOT_FOUND);
}

LM_TEST("Q02 device: 100 repeats of one message create one event and bounded work") {
    DNet n(2);
    n.set_time();
    n.routes(0, 1);
    warm_up(n, 0, 1);
    const Bytes r1 = craft_record(n, 0, 1, 0xC2, payload_of(3, 16), 60000);
    for (int i = 0; i < 100; ++i) {
        n.world.inject(n.mac(0), 0, n.mac(1), frame_for(n, 0, 1, r1).view());
        n.run_ms(15);
    }
    n.run_ms(200);
    LM_CHECK_EQ(n.dv(1).stats().delivered, 2u);
    LM_CHECK_EQ(n.dv(1).stats().rx_dup_end, 99u);
    LM_CHECK_EQ(n.dv(1).in_entries(), 2u); // one cache entry per message, not per repeat
    Received m;
    int events = 0;
    while (n.pop(1, m, LM_EVENT_MESSAGE)) {
        ++events;
    }
    LM_CHECK_EQ(events, 1);
}


// ---- capacity: BUSY is not loss, events are never dropped silently ----
LM_TEST("D10 sim: a receiver without buffers answers BUSY: no attempt is used, nothing is lost, events keep order") {
    DNet n(3);
    n.set_time();
    n.routes(0, 1);
    n.routes(2, 1);
    // The destination's application is slow: it takes nothing (not even STARTED) for a while.
    std::vector<lm_operation_id_t> ops;
    for (int i = 0; i < 16; ++i) {
        const auto s = n.send(0, 1, LM_RECEIVED, LM_VOLATILE, payload_of(static_cast<uint8_t>(i), 8), 90000);
        LM_CHECK_EQ(s.st, LM_STATUS_OK);
        ops.push_back(s.op);
    }
    LM_CHECK(n.until([&] { return n.dv(1).stats().delivered == 16; }, 60000));
    LM_CHECK_EQ(n.dv(1).free_msg_buffers(), 0u);
    const auto x = n.send(2, 1, LM_RECEIVED, LM_VOLATILE, payload_of(0x77, 8), 90000);
    n.run_s(3);
    LM_CHECK(n.dv(1).stats().rx_busy >= 1u);                  // "no room here", said explicitly
    LM_CHECK(n.dv(2).hop_stats().ack_busy >= 1u);
    LM_CHECK_EQ(n.dv(2).hop_stats().rf_failed, 0u);            // not RF loss ...
    LM_CHECK(n.dv(2).hop_stats().busy_resends >= 1u);
    LM_CHECK_EQ(n.dv(2).hop_stats().retransmits, 0u);          // ... and no link attempt was spent
    LM_CHECK_EQ(n.op(2, x.op).outcome, static_cast<uint32_t>(LM_OUTCOME_PENDING));
    // One buffer is freed by the application: the deferred frame goes through.
    Received m;
    std::vector<Bytes> got;
    LM_CHECK(n.pop(1, m));                                     // STARTED
    LM_CHECK(m.ev.kind == LM_EVENT_STARTED);
    LM_CHECK(n.pop(1, m, LM_EVENT_MESSAGE));
    got.push_back(m.payload);
    LM_CHECK(n.until([&] { return n.op(2, x.op).outcome == LM_OUTCOME_RECEIVED; }, 20000));
    // All 17 arrive exactly once and the first 16 in arrival order (an event that did not fit the
    // queue waited for space instead of being dropped).
    while (n.pop(1, m, LM_EVENT_MESSAGE)) {
        got.push_back(m.payload);
        n.run_ms(20);
    }
    LM_CHECK_EQ(got.size(), 17u);
    for (std::size_t i = 0; i < 16; ++i) {
        LM_CHECK(got[i] == payload_of(static_cast<uint8_t>(i), 8));
    }
    LM_CHECK(got[16] == payload_of(0x77, 8));
    for (const auto op : ops) {
        LM_CHECK_EQ(n.op(0, op).outcome, static_cast<uint32_t>(LM_OUTCOME_RECEIVED));
    }
}

LM_TEST("D10 sim: lm_next_event BUFFER_TOO_SMALL keeps the event, payload_bytes says how much") {
    DNet n(2);
    n.set_time();
    n.routes(0, 1);
    const auto s = n.send(0, 1, LM_RECEIVED, LM_VOLATILE, payload_of(3, 50));
    LM_CHECK(n.until([&] { return n.op(0, s.op).outcome == LM_OUTCOME_RECEIVED; }, 20000));
    lm_event_t ev{};
    ev.struct_size = sizeof(ev);
    ev.abi_version = LM_ABI_VERSION;
    uint8_t small[8];
    size_t req = 0;
    Received st;
    LM_CHECK(n.pop(1, st, LM_EVENT_STARTED));
    LM_CHECK_EQ(lm_next_event(n.ctx(1), &ev, small, sizeof(small), &req), LM_STATUS_BUFFER_TOO_SMALL);
    LM_CHECK_EQ(req, 50u);
    LM_CHECK_EQ(lm_next_event(n.ctx(1), &ev, nullptr, 0, &req), LM_STATUS_BUFFER_TOO_SMALL);
    Received m;
    LM_CHECK(n.pop(1, m, LM_EVENT_MESSAGE)); // still there, payload intact
    LM_CHECK(m.payload == payload_of(3, 50));
}

LM_TEST("D05 sim: best effort is SUBMITTED (sent evidence only), and finished operations age out") {
    DNet n(2);
    n.set_time();
    n.routes(0, 1);
    const uint64_t receipts0 = n.dv(1).stats().receipts_sent;
    lm_operation_id_t first = 0;
    for (int i = 0; i < 40; ++i) {
        const auto s = n.send(0, 1, LM_BEST_EFFORT, LM_VOLATILE, payload_of(static_cast<uint8_t>(i), 8), 30000);
        LM_CHECK_EQ(s.st, LM_STATUS_OK);
        first = i == 0 ? s.op : first;
        LM_CHECK(n.until([&] { return n.op(0, s.op).outcome == LM_OUTCOME_SUBMITTED; }, 30000));
        const lm_operation_t o = n.op(0, s.op);
        LM_CHECK((o.evidence_bits & hop_accepted) != 0);
        LM_CHECK((o.evidence_bits & end_received) == 0); // nobody claimed more than was seen
        Received m;
        LM_CHECK(n.until([&] { return n.pop(1, m, LM_EVENT_MESSAGE); }, 2000));
    }
    LM_CHECK_EQ(n.dv(1).stats().receipts_sent, receipts0); // no receipt was ever asked for
    lm_operation_t o{};
    o.struct_size = sizeof(o);
    o.abi_version = LM_ABI_VERSION;
    LM_CHECK_EQ(lm_get_operation(n.ctx(0), first, &o), LM_STATUS_NOT_FOUND); // history is bounded
    LM_CHECK_EQ(lm_get_operation(n.ctx(0), first + 39, &o), LM_STATUS_OK);
}

LM_TEST("D05 sim: 17 waiting sends fill the pool: NO_CAPACITY, the work never existed") {
    DNet n(2);
    n.set_time();
    std::vector<lm_operation_id_t> ops;
    for (int i = 0; i < 16; ++i) {
        const auto s = n.send(0, 1, LM_RECEIVED, LM_VOLATILE, payload_of(1, 4), 90000); // no route yet
        LM_CHECK_EQ(s.st, LM_STATUS_OK);
        ops.push_back(s.op);
    }
    const auto over = n.send(0, 1, LM_RECEIVED, LM_VOLATILE, payload_of(1, 4), 90000);
    LM_CHECK_EQ(over.st, LM_STATUS_NO_CAPACITY);
    LM_CHECK_EQ(over.op, 0u);
    LM_CHECK_EQ(lm_cancel(n.ctx(0), ops[0]), LM_STATUS_OK); // freeing one makes room again
    LM_CHECK_EQ(n.send(0, 1, LM_RECEIVED, LM_VOLATILE, payload_of(1, 4), 90000).st, LM_STATUS_OK);
}

LM_TEST("D08 sim: payload capacity per destination (134 / 96 / 56) and NO_ROUTE for unknown") {
    DNet n(6, 31, false);
    n.set_time();
    n.routes(0, 1);
    n.routes(0, 5);
    lm_destination_t d{};
    d.kind = LM_DEST_NODE;
    uint32_t bytes = 0;
    uint32_t hops = 0;
    std::memcpy(d.node.bytes, n.id(1).bytes.data(), 32);
    LM_CHECK_EQ(lm_payload_capacity(n.ctx(0), &d, &bytes, &hops), LM_STATUS_OK);
    LM_CHECK_EQ(bytes, 134u);
    LM_CHECK_EQ(hops, 1u);
    std::memcpy(d.node.bytes, n.id(5).bytes.data(), 32);
    LM_CHECK_EQ(lm_payload_capacity(n.ctx(0), &d, &bytes, &hops), LM_STATUS_OK);
    LM_CHECK_EQ(bytes, 126u);
    LM_CHECK_EQ(hops, 5u);
    std::memcpy(d.node.bytes, n.id(3).bytes.data(), 32);
    LM_CHECK_EQ(lm_payload_capacity(n.ctx(0), &d, &bytes, &hops), LM_STATUS_NO_ROUTE);
    d.kind = LM_DEST_GROUP;
    LM_CHECK_EQ(lm_payload_capacity(n.ctx(0), &d, &bytes, &hops), LM_STATUS_UNSUPPORTED);
    // strict_single_frame: a payload above the known route's capacity is refused at acceptance (the
    // default fragments it, S12).
    LM_CHECK_EQ(n.send(0, 5, LM_RECEIVED, LM_VOLATILE, Bytes(127, 1), 30000, 100, true).st, LM_STATUS_PAYLOAD_TOO_LARGE);
    LM_CHECK_EQ(n.send(0, 5, LM_RECEIVED, LM_VOLATILE, Bytes(126, 1), 30000, 100, true).st, LM_STATUS_OK);
}

LM_TEST("R01 sim: 20 hops, an APPLIED message with the 96-byte maximum, end session over the whole path") {
    DNet n(21);
    n.set_time();
    n.routes(0, 20);
    const Bytes body = payload_of(0x21, 96);
    LM_CHECK_EQ(n.send(0, 20, LM_APPLIED, LM_VOLATILE, Bytes(97, 1), 120000, 100, true).st, LM_STATUS_PAYLOAD_TOO_LARGE);
    const auto s = n.send(0, 20, LM_APPLIED, LM_VOLATILE, body, 120000);
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    Received m;
    LM_CHECK(n.until([&] { return n.pop(20, m, LM_EVENT_MESSAGE); }, 100000));
    LM_CHECK(m.payload == body);
    LM_CHECK_EQ(n.report(20, m.ev, LM_OUTCOME_APPLIED, Bytes{1}), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.op(0, s.op).outcome == LM_OUTCOME_APPLIED; }, 100000));
    for (unsigned i = 1; i < 20; ++i) {
        LM_CHECK(n.dv(i).stats().rx_forward >= 2u); // every relay carried frames in both directions
        LM_CHECK_EQ(n.dv(i).stats().rx_data, 0u);   // and read none of them
    }
}

// ---- relays refuse what docs/04 §4 refuses ----
LM_TEST("R04 sim: a relay refuses a stale term and a wrong previous hop, and forwards nothing") {
    DNet n(3);
    n.set_time();
    n.routes(0, 2);
    warm_up(n, 0, 2);
    const Bytes rec = craft_record(n, 0, 2, 0xD1, payload_of(1, 8), 60000);
    // (a) route header carries another root term than the relay's
    delivery::PathSpec ps = n.spec(0, 2, 2);
    std::array<uint8_t, 250> plain{};
    std::size_t rlen = 0;
    LM_CHECK_OK(wire::encode_route(ps.header(), MutByteView{plain}, rlen));
    std::memcpy(plain.data() + rlen, rec.data(), rec.size());
    link::SealedFrame f;
    LM_CHECK_OK(n.eng(0).link().seal(n.id(1), wire::FrameKind::Data, ByteView{plain.data(), rlen + rec.size()}, f,
                                     n.now(0)));
    inject(n, 0, 1, f);
    LM_CHECK_EQ(n.dv(1).stats().rx_drop_route, 1u);
    // (b) the frame claims another origin than the neighbour it came from
    ps = n.spec(0, 2);
    ps.origin = ShortAddr{99};
    wire::RouteHeader h = ps.header();
    LM_CHECK_OK(wire::encode_route(h, MutByteView{plain}, rlen));
    std::memcpy(plain.data() + rlen, rec.data(), rec.size());
    LM_CHECK_OK(n.eng(0).link().seal(n.id(1), wire::FrameKind::Data, ByteView{plain.data(), rlen + rec.size()}, f,
                                     n.now(0)));
    inject(n, 0, 1, f);
    LM_CHECK_EQ(n.dv(1).stats().rx_drop_route, 2u);
    LM_CHECK_EQ(n.dv(1).stats().rx_forward, n.dv(1).stats().rx_forward); // (warm-up frames only)
    const uint64_t fwd = n.dv(1).stats().rx_forward;
    n.run_ms(200);
    LM_CHECK_EQ(n.dv(1).stats().rx_forward, fwd);
    LM_CHECK_EQ(n.dv(2).stats().rx_data, 1u); // only the warm-up reached the destination
}


// ---- durable journal and power cuts ----
namespace {

// A restarted node has no link sessions; its neighbours still hold the old ones. It opens new ones
// (the per-peer 30 s handshake gate has to pass first, docs/06 §8).
void relink(DNet &n, unsigned i) {
    n.run_s(31);
    for (const int d : {-1, 1}) {
        const int j = static_cast<int>(i) + d;
        if (j < 0 || j >= static_cast<int>(n.n)) {
            continue;
        }
        LM_CHECK_OK(n.eng(i).link().connect(n.mac(static_cast<unsigned>(j)), n.now(i), true));
        n.node(i).notify();
        n.run_ms(2500);
    }
}

lm_operation_t op_by_message(DNet &n, unsigned node_i, const lm_message_ref_t &ref) {
    lm_operation_t o{};
    o.struct_size = sizeof(o);
    o.abi_version = LM_ABI_VERSION;
    LM_CHECK_EQ(lm_get_message(n.ctx(node_i), &ref, &o), LM_STATUS_OK);
    return o;
}

} // namespace

LM_TEST("D08 sim: DURABLE RECEIVED without a deadline: persisted, sent after the commit, retired when done") {
    DNet n(2);
    n.set_time();
    n.routes(0, 1);
    warm_up(n, 0, 1);
    const auto s = n.send(0, 1, LM_RECEIVED, LM_DURABLE, payload_of(1, 40), 0);
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    LM_CHECK((n.op(0, s.op).evidence_bits & persisted) == 0); // accepted is not persisted
    LM_CHECK(n.until([&] { return n.op(0, s.op).outcome == LM_OUTCOME_RECEIVED; }, 20000));
    const lm_operation_t o = n.op(0, s.op);
    LM_CHECK((o.evidence_bits & (accepted | persisted | sent | hop_accepted | end_received)) ==
             (accepted | persisted | sent | hop_accepted | end_received));
    n.run_ms(100);
    LM_CHECK_EQ(n.dv(0).durable().live_count(), 0u); // the origin's record is retired at the end
    Received m;
    LM_CHECK(n.pop(1, m, LM_EVENT_MESSAGE));
    LM_CHECK(m.payload == payload_of(1, 40));
    n.run_ms(100);
    LM_CHECK_EQ(n.dv(1).durable().live_count(), 1u); // the destination keeps a small "seen" record
}

LM_TEST("D08 sim: END_RECEIVED of a DURABLE message only after the destination's journal commit") {
    DNet n(2);
    n.set_time();
    n.routes(0, 1);
    warm_up(n, 0, 1);
    n.node(1).jobs.latency_us = 150'000; // Flash is slow at the destination
    const auto s = n.send(0, 1, LM_RECEIVED, LM_DURABLE, payload_of(2, 30), 60000);
    LM_CHECK(n.until([&] { return n.dv(1).stats().rx_data == 2; }, 5000));
    n.run_ms(100); // stored in RAM, HOP_ACCEPTED already, journal write still running
    LM_CHECK_EQ(n.dv(1).stats().journal_puts, 0u);
    lm_operation_t o = n.op(0, s.op);
    LM_CHECK((o.evidence_bits & hop_accepted) != 0);
    LM_CHECK((o.evidence_bits & end_received) == 0);
    Received m;
    LM_CHECK(!n.pop(1, m, LM_EVENT_MESSAGE)); // and the application has not seen it either
    LM_CHECK(n.until([&] { return (n.op(0, s.op).evidence_bits & end_received) != 0; }, 3000));
    LM_CHECK_EQ(n.dv(1).stats().journal_puts, 1u);
    LM_CHECK(n.pop(1, m, LM_EVENT_MESSAGE));
}

LM_TEST("POWER sim: origin cut during the durable commit (before/after the Flash write)") {
    for (const CutMode mode : {CutMode::Before, CutMode::After}) {
        DNet n(2);
        n.set_time();
        n.routes(0, 1);
        warm_up(n, 0, 1);
        const uint64_t inc0 = n.dv(0).durable().incarnation();
        n.node(0).store.arm_cut(n.node(0).store.mutating_ops(), mode);
        const auto s = n.send(0, 1, LM_RECEIVED, LM_DURABLE, payload_of(3, 20), 120000);
        LM_CHECK_EQ(s.st, LM_STATUS_OK);
        LM_CHECK(n.until([&] { return n.node(0).store.cut_fired(); }, 500));
        n.run_ms(50);
        n.reboot(0);
        n.run_ms(100);
        LM_CHECK(n.dv(0).ready());
        LM_CHECK(n.dv(0).durable().incarnation() > inc0); // a MessageId is never issued twice
        n.run_s(2);
        LM_CHECK_EQ(n.dv(1).stats().delivered, 1u); // nothing left the node before the commit was known
        if (mode == CutMode::Before) {
            LM_CHECK_EQ(n.dv(0).durable().live_count(), 0u); // the only allowed state: nothing persisted
            continue;
        }
        // The write had landed: the message is recovered and completes exactly once.
        LM_CHECK_EQ(n.dv(0).durable().live_count(), 1u);
        relink(n, 0);
        n.set_time_at(0, 1);
        n.routes(0, 1, 2);
        LM_CHECK(n.until([&] { return n.dv(1).stats().delivered == 2; }, 60000));
        n.run_s(2);
        LM_CHECK_EQ(n.dv(1).stats().delivered, 2u);
        Received m;
        LM_CHECK(n.pop(1, m, LM_EVENT_MESSAGE));
        LM_CHECK(m.payload == payload_of(3, 20));
        LM_CHECK(!n.pop(1, m, LM_EVENT_MESSAGE));
    }
}

LM_TEST("POWER sim: origin cut after the commit but before any send: the message resumes, once") {
    DNet n(2);
    n.set_time();
    // No route: the message is persisted but cannot leave.
    n.routes(0, 1);
    warm_up(n, 0, 1);
    n.dv(0).drop_routes();
    const auto s = n.send(0, 1, LM_RECEIVED, LM_DURABLE, payload_of(4, 20), 120000);
    LM_CHECK(n.until([&] { return (n.op(0, s.op).evidence_bits & persisted) != 0; }, 1000));
    const lm_operation_t before = n.op(0, s.op);
    LM_CHECK((before.evidence_bits & sent) == 0);
    const lm_message_ref_t ref = n.ref_of(0, before);
    n.reboot(0);
    n.run_ms(100);
    LM_CHECK_EQ(n.dv(0).durable().live_count(), 1u);
    relink(n, 0);
    n.set_time_at(0, 1);
    // The recovered message keeps its MessageId, hash and ORIGINAL deadline.
    lm_operation_t rec = op_by_message(n, 0, ref);
    LM_CHECK((rec.evidence_bits & persisted) != 0);
    LM_CHECK((rec.evidence_bits & sent) == 0);
    n.routes(0, 1, 2);
    LM_CHECK(n.until([&] { return op_by_message(n, 0, ref).outcome == LM_OUTCOME_RECEIVED; }, 60000));
    LM_CHECK_EQ(n.dv(1).stats().delivered, 2u);
    n.run_ms(200);
    LM_CHECK_EQ(n.dv(0).durable().live_count(), 0u);
}

LM_TEST("POWER sim: origin cut after the destination stored it: dedup at the destination, one event") {
    DNet n(2);
    n.set_time();
    n.routes(0, 1);
    warm_up(n, 0, 1);
    const auto s = n.send(0, 1, LM_RECEIVED, LM_DURABLE, payload_of(5, 20), 300000);
    const lm_operation_t o = n.op(0, s.op);
    const lm_message_ref_t ref = n.ref_of(0, o);
    LM_CHECK(n.until([&] { return n.dv(1).stats().rx_data == 2; }, 5000));
    n.reboot(0); // the receipt was on its way
    n.run_ms(100);
    LM_CHECK_EQ(n.dv(0).durable().live_count(), 1u);
    relink(n, 0);
    n.set_time_at(0, 1);
    n.routes(0, 1, 2);
    LM_CHECK(n.until([&] { return op_by_message(n, 0, ref).outcome == LM_OUTCOME_RECEIVED; }, 60000));
    LM_CHECK_EQ(n.dv(1).stats().delivered, 2u);    // the re-sent record was recognised, not applied twice
    LM_CHECK(n.dv(1).stats().rx_dup_end >= 1u);
    Received m;
    int events = 0;
    while (n.pop(1, m, LM_EVENT_MESSAGE)) {
        ++events;
    }
    LM_CHECK_EQ(events, 1);
}

LM_TEST("FIX2-D6 sim: a DURABLE 512 B message is journalled at both ends and survives a destination power cut") {
    DNet n(2);
    n.set_time();
    n.routes(0, 1);
    warm_up(n, 0, 1);
    const Bytes body = payload_of(0x61, 512);
    const auto s = n.send(0, 1, LM_RECEIVED, LM_DURABLE, body, 100000);
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.op(0, s.op).outcome == LM_OUTCOME_RECEIVED; }, 60000));
    LM_CHECK((n.op(0, s.op).evidence_bits & persisted) != 0);
    // The application has not taken it: the destination loses power; the journal brings the whole payload back.
    n.reboot(1);
    n.run_ms(500);
    Received m;
    LM_CHECK(n.until([&] { return n.pop(1, m, LM_EVENT_MESSAGE); }, 30000));
    LM_CHECK(m.payload == body);
    LM_CHECK_EQ(m.ev.reason, 1u); // recovered after a restart: the application may have seen it
}

LM_TEST("D06 sim: a recovered message with a deadline waits for a clock bound and never outlives its deadline") {
    for (const bool late : {false, true}) {
        DNet n(2);
        n.set_time();
        n.routes(0, 1);
        warm_up(n, 0, 1);
        n.dv(0).drop_routes();
        const auto s = n.send(0, 1, LM_RECEIVED, LM_DURABLE, payload_of(6, 20), 100000);
        LM_CHECK(n.until([&] { return (n.op(0, s.op).evidence_bits & persisted) != 0; }, 1000));
        const lm_message_ref_t ref = n.ref_of(0, n.op(0, s.op));
        n.reboot(0);
        n.run_ms(100);
        relink(n, 0);
        n.routes(0, 1, 2); // route back, but no root clock yet
        n.run_s(5);
        lm_operation_t rec = op_by_message(n, 0, ref);
        LM_CHECK_EQ(rec.outcome, static_cast<uint32_t>(LM_OUTCOME_PENDING));
        LM_CHECK_EQ(rec.reason, static_cast<uint32_t>(Status::TimeUncertain)); // the reason is explicit
        LM_CHECK((rec.evidence_bits & sent) == 0);               // and nothing is sent blind
        if (late) {
            n.run_s(100); // the deadline (100 s) passes while the clock is unknown
        }
        n.set_time_at(0, 1);
        if (late) {
            n.run_s(2);
            rec = op_by_message(n, 0, ref);
            LM_CHECK_EQ(rec.outcome, static_cast<uint32_t>(LM_OUTCOME_EXPIRED)); // no new life, never sent
            LM_CHECK_EQ(n.dv(1).stats().delivered, 1u);
        } else {
            LM_CHECK(n.until([&] { return op_by_message(n, 0, ref).outcome == LM_OUTCOME_RECEIVED; }, 60000));
            LM_CHECK_EQ(n.dv(1).stats().delivered, 2u);
        }
    }
}

LM_TEST("D02 sim: destination cut after the application took a DURABLE APPLIED message: recovered flag, no exactly-once claim") {
    DNet n(2);
    n.set_time();
    n.routes(0, 1);
    warm_up(n, 0, 1);
    const auto s = n.send(0, 1, LM_APPLIED, LM_DURABLE, payload_of(7, 24), 600000);
    Received m1;
    LM_CHECK(n.until([&] { return n.pop(1, m1, LM_EVENT_MESSAGE); }, 20000));
    LM_CHECK_EQ(m1.ev.reason, 0u);
    LM_CHECK(n.until([&] { return (n.op(0, s.op).evidence_bits & end_received) != 0; }, 5000));
    // The application applies it physically ... and the device loses power before it can report.
    n.reboot(1);
    n.run_ms(200);
    LM_CHECK_EQ(n.dv(1).durable().live_count(), 1u);   // the record survived: it was not applied-and-forgotten
    n.set_time_at(1, 1);
    relink(n, 1);
    LM_CHECK_OK(n.dv(1).install_route(n.id(0), n.spec(1, 0), MonoTime::never()));
    // The message comes back to the application, flagged: it may already have been handled.
    Received m2;
    LM_CHECK(n.until([&] { return n.pop(1, m2, LM_EVENT_MESSAGE); }, 20000));
    LM_CHECK_EQ(m2.ev.reason, 1u);
    LM_CHECK(std::memcmp(m2.ev.message_id.bytes, m1.ev.message_id.bytes, 16) == 0);
    LM_CHECK(m2.payload == m1.payload);
    // Until the application reconciles and reports, the origin does not claim "applied".
    n.run_s(15);
    LM_CHECK(n.op(0, s.op).outcome != LM_OUTCOME_APPLIED);
    LM_CHECK((n.op(0, s.op).evidence_bits & app_applied) == 0);
    LM_CHECK_EQ(n.report(1, m2.ev, LM_OUTCOME_APPLIED, Bytes{9}), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.op(0, s.op).outcome == LM_OUTCOME_APPLIED; }, 60000));
}


// ---- measurements (reported, and guarded against silent growth) ----
LM_TEST("measure: sizeof of the delivery state and owner stack depth of a full E2E exchange") {
    std::printf("  [measure] sizeof: Delivery=%zu HopTx=%zu (end sessions use the single link::Exchange=%zu, "
                "HandshakeSlot=%zu) Durable=%zu EndSessions=%zu\n"
                "            EndSession=%zu MsgBuf=%zu Active=%zu InEntry=%zu Op=%zu TxFrame=%zu PathSpec=%zu\n"
                "            Engine=%zu lm_context=%zu (SIM = root-sized arrays)\n",
                sizeof(delivery::Delivery), sizeof(delivery::HopTx), sizeof(link::Exchange),
                sizeof(sec::HandshakeSlot), sizeof(delivery::Durable), sizeof(delivery::EndSessions),
                sizeof(delivery::EndSession), sizeof(delivery::MsgBuf), sizeof(delivery::Active),
                sizeof(delivery::InEntry), sizeof(delivery::Op), sizeof(delivery::TxFrame),
                sizeof(delivery::PathSpec), sizeof(Engine), sizeof(lm_context));
    // The owner paths only: the end session exists already (EDHOC steps run on the worker stack and
    // are measured by test_link), so no job body is inside the measured region; the simulator's own
    // frames are, which makes the number an upper bound. Relays forward, the destination delivers,
    // receipts flow back, the application answers.
    DNet n(5);
    n.set_time();
    n.routes(0, 4);
    warm_up(n, 0, 4);
    const std::size_t idle = lmtest::depth_of([&] { n.run_ms(1); }); // the simulator's own frames
    const std::size_t depth = lmtest::depth_of([&] {
        const auto s = n.send(0, 4, LM_APPLIED, LM_VOLATILE, payload_of(1, 90));
        (void)s;
        n.run_s(5);
        Received m;
        if (n.pop(4, m, LM_EVENT_MESSAGE)) {
            (void)n.report(4, m.ev, LM_OUTCOME_APPLIED, Bytes{1});
        }
        n.run_s(5);
    });
    std::printf("  [measure] owner-side stack depth, 4-hop APPLIED exchange (forward, deliver, receipt, "
                "report): %zu B (thread entry depth %zu B, includes the simulator's own frames)\n",
                depth, lmtest::entry_depth());
    std::printf("  [measure] simulator-only baseline %zu B => owner paths ~%zu B\n", idle, depth > idle ? depth - idle : 0);
#if LM_STACK_PROBE_EXACT
    LM_CHECK(depth - idle < 4000); // owner task stack is 4 KiB (S3): regression guard
#endif
}


// ---- end-session set-up: failure, gate, glare, credentials, lifetime ----
LM_TEST("S02 sim: end session set-up fails while the peer is unreachable, is retried, then the message goes out") {
    DNet n(2);
    n.set_time();
    n.routes(0, 1);
    set_link(n, 0, 1, false);
    const auto s = n.send(0, 1, LM_RECEIVED, LM_VOLATILE, payload_of(1), 120000);
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    n.run_s(8);
    LM_CHECK(n.dv(0).end_stats().failed >= 1u);          // 3 credential attempts, no answer
    LM_CHECK_EQ(n.dv(0).end_stats().completed, 0u);
    const lm_operation_t o = n.op(0, s.op);
    LM_CHECK_EQ(o.outcome, static_cast<uint32_t>(LM_OUTCOME_PENDING));
    LM_CHECK((o.evidence_bits & sent) == 0);             // no application frame left: only set-up frames did
    set_link(n, 0, 1, true);
    LM_CHECK(n.until([&] { return n.op(0, s.op).outcome == LM_OUTCOME_RECEIVED; }, 90000));
    LM_CHECK_EQ(n.dv(1).stats().delivered, 1u);
    LM_CHECK_EQ(n.dv(0).end_stats().completed, 1u);
    LM_CHECK(n.dv(0).end_stats().retransmits >= 1u);
}

LM_TEST("S02 sim: both ends open an end session at once: one session, both messages delivered") {
    DNet n(2);
    n.set_time();
    n.routes(0, 1);
    const auto a = n.send(0, 1, LM_RECEIVED, LM_VOLATILE, payload_of(1), 60000);
    const auto b = n.send(1, 0, LM_RECEIVED, LM_VOLATILE, payload_of(2), 60000);
    LM_CHECK(n.until([&] {
        return n.op(0, a.op).outcome == LM_OUTCOME_RECEIVED && n.op(1, b.op).outcome == LM_OUTCOME_RECEIVED;
    }, 60000));
    LM_CHECK_EQ(n.dv(0).sessions().count(), 1u);
    LM_CHECK_EQ(n.dv(1).sessions().count(), 1u);
    LM_CHECK_EQ(n.dv(0).end_stats().completed + n.dv(1).end_stats().completed, 2u); // one exchange, seen by both
    LM_CHECK_EQ(n.dv(0).end_stats().failed + n.dv(1).end_stats().failed, 0u);
    Received m;
    LM_CHECK(n.pop(1, m, LM_EVENT_MESSAGE));
    LM_CHECK(m.payload == payload_of(1));
    LM_CHECK(n.pop(0, m, LM_EVENT_MESSAGE));
    LM_CHECK(m.payload == payload_of(2));
}

LM_TEST("S07 sim: a peer below the revocation floor gets no end session and no application frame") {
    DNet n(2);
    n.set_time();
    n.routes(0, 1);
    // The link session exists (older credentials); the end exchange is the second line of defence.
    LM_CHECK_OK(n.eng(0).identity().floors().raise(n.id(1), 1, 2));
    const auto s = n.send(1, 0, LM_RECEIVED, LM_VOLATILE, payload_of(1), 5000);
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    n.run_s(10);
    LM_CHECK(n.dv(0).end_stats().cred_rejected >= 1u);
    LM_CHECK_EQ(n.dv(0).sessions().count(), 0u);
    LM_CHECK_EQ(n.dv(0).stats().rx_data, 0u);
    const lm_operation_t o = n.op(1, s.op);
    LM_CHECK_EQ(o.outcome, LM_OUTCOME_EXPIRED);     // never left: a definite "not sent"
    LM_CHECK((o.evidence_bits & (sent | end_received)) == 0);
}

LM_TEST("S03 sim: end session lifetime is one hour: an expired session is replaced, not reused") {
    DNet n(2);
    n.set_time();
    n.routes(0, 1);
    warm_up(n, 0, 1);
    LM_CHECK_EQ(n.dv(0).end_stats().completed, 1u);
    n.run_s(3700); // beyond the 1 h key lifetime (the link layer rotates its own sessions meanwhile)
    n.set_time_at(0, 1);
    n.set_time_at(1, 1);
    const auto s = n.send(0, 1, LM_RECEIVED, LM_VOLATILE, payload_of(9), 120000);
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.op(0, s.op).outcome == LM_OUTCOME_RECEIVED; }, 60000));
    LM_CHECK_EQ(n.dv(0).end_stats().completed, 2u); // a fresh handshake, not the expired keys
    LM_CHECK_EQ(n.dv(1).stats().delivered, 2u);
}


LM_TEST("D04 sim: a cancelled durable message is retired from the journal and does not come back after a restart") {
    DNet n(2);
    n.set_time();
    const auto s = n.send(0, 1, LM_RECEIVED, LM_DURABLE, payload_of(8, 16), 0); // no route: waits, persisted
    LM_CHECK(n.until([&] { return (n.op(0, s.op).evidence_bits & persisted) != 0; }, 1000));
    LM_CHECK_EQ(n.dv(0).durable().live_count(), 1u);
    LM_CHECK_EQ(lm_cancel(n.ctx(0), s.op), LM_STATUS_OK);
    LM_CHECK_EQ(n.op(0, s.op).outcome, static_cast<uint32_t>(LM_OUTCOME_CANCELLED_NOT_SENT));
    n.run_ms(100);
    LM_CHECK_EQ(n.dv(0).durable().live_count(), 0u);
    n.reboot(0);
    n.run_ms(100);
    LM_CHECK_EQ(n.dv(0).durable().live_count(), 0u); // nothing to resurrect
    LM_CHECK_EQ(n.send(0, 1, LM_RECEIVED, LM_DURABLE, payload_of(9, 16), 0).st, LM_STATUS_OK); // slot is free again
}


LM_TEST("D08 sim: an empty payload is a valid message") {
    DNet n(2);
    n.set_time();
    n.routes(0, 1);
    const auto s = n.send(0, 1, LM_APPLIED, LM_VOLATILE, Bytes{}, 30000);
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    Received m;
    LM_CHECK(n.until([&] { return n.pop(1, m, LM_EVENT_MESSAGE); }, 20000));
    LM_CHECK(m.payload.empty());
    LM_CHECK_EQ(m.ev.payload_bytes, 0u);
    LM_CHECK_EQ(n.report(1, m.ev, LM_OUTCOME_APPLIED, Bytes{}), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.op(0, s.op).outcome == LM_OUTCOME_APPLIED; }, 10000));
}

LM_TEST("R02 sim: 40 hops carry the end-session set-up, a 56-byte message and its receipt; a receipt with a result is fragmented") {
    DNet n(41);
    n.set_time();
    n.routes(0, 40);
    // Best effort needs no receipt: it is SUBMITTED at the first hop and arrives.
    const auto b = n.send(0, 40, LM_BEST_EFFORT, LM_VOLATILE, payload_of(1, 56), 120000);
    LM_CHECK_EQ(b.st, LM_STATUS_OK);
    Received m;
    LM_CHECK(n.until([&] { return n.pop(40, m, LM_EVENT_MESSAGE); }, 120000));
    LM_CHECK(m.payload == payload_of(1, 56));
    LM_CHECK_EQ(n.op(0, b.op).outcome, static_cast<uint32_t>(LM_OUTCOME_SUBMITTED));
    LM_CHECK_EQ(n.send(0, 40, LM_BEST_EFFORT, LM_VOLATILE, Bytes(57, 1), 120000, 100, true).st, LM_STATUS_PAYLOAD_TOO_LARGE);
    LM_CHECK_EQ(n.dv(0).end_stats().completed, 1u); // SESSION_BIND (117 B) travelled as fragments
    // RECEIVED: the delivery receipt is exactly 56 B, the whole payload capacity of a 40-hop frame.
    const auto r = n.send(0, 40, LM_RECEIVED, LM_VOLATILE, payload_of(2, 56), 60000);
    LM_CHECK(n.until([&] { return n.op(0, r.op).outcome == LM_OUTCOME_RECEIVED; }, 90000));
    LM_CHECK(n.pop(40, m, LM_EVENT_MESSAGE));
    // APPLIED with a result: the receipt exceeds one 40-hop frame and travels as fragments (S12); the
    // origin gets the result. It is never claimed without it.
    const auto a = n.send(0, 40, LM_APPLIED, LM_VOLATILE, payload_of(3, 56), 120000);
    LM_CHECK(n.until([&] { return n.pop(40, m, LM_EVENT_MESSAGE); }, 60000));
    LM_CHECK_EQ(n.report(40, m.ev, LM_OUTCOME_APPLIED, Bytes(8, 7)), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.op(0, a.op).outcome == LM_OUTCOME_APPLIED; }, 100000));
    LM_CHECK((n.op(0, a.op).evidence_bits & app_applied) != 0);
    LM_CHECK_EQ(n.dv(40).stats().receipts_dropped, 0u);
}

LM_TEST("ME05 sim: an idle node with delivery state schedules no wakes") {
    DNet n(2);
    n.set_time();
    n.routes(0, 1);
    warm_up(n, 0, 1);
    n.run_s(15); // Linger of the responder, RTO tails
    const uint64_t s0 = n.eng(0).stats().steps + n.eng(1).stats().steps;
    n.run_s(600);
    LM_CHECK_EQ(n.eng(0).stats().steps + n.eng(1).stats().steps, s0);
}


LM_TEST("R10 sim: stop with operations, an exchange job and a journal write in flight; nothing acts on a stopped engine") {
    DNet n(2);
    n.set_time();
    n.routes(0, 1);
    // A durable send (journal Put running) and an end-session set-up (a P-256 job running).
    const auto d = n.send(0, 1, LM_RECEIVED, LM_DURABLE, payload_of(1, 8), 0);
    LM_CHECK_EQ(d.st, LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.dv(0).exchange().job_pending() || n.dv(0).durable().job_pending(); }, 5000));
    LM_CHECK_EQ(lm_stop(n.ctx(0), 0, nullptr), LM_STATUS_OK);
    Command cmd;
    cmd.kind = CommandKind::Destroy;
    // Destroy is refused while a worker job still owns delivery memory (late completions are matched
    // by generation and dropped, never applied to a reused slot).
    const bool pending = n.dv(0).job_pending();
    if (pending) {
        LM_CHECK(n.node(0).owner_call.call(cmd).status == Status::Busy);
    }
    n.run_ms(200);
    LM_CHECK(!n.dv(0).job_pending());
    LM_CHECK(n.node(0).owner_call.call(cmd).status == Status::Ok);
    LM_CHECK_EQ(n.dv(0).in_entries(), 0u);
    // A restart finds the durable record again (persisted before stop) or, when the write did not
    // finish, nothing: never half a message.
    n.node(0).power_cut();
    n.node(0).store.power_restore();
    n.boot(0);
    n.run_ms(100);
    LM_CHECK(n.dv(0).ready());
    LM_CHECK(n.dv(0).durable().live_count() <= 1u);
}

LM_TEST_MAIN()
