// CHANNEL slice (S17): time bounds, survey, PREPARE / COMMIT / recovery, freeze, rollback, persisted states.
// Real lm_context + Engine per node on simulated ports, credentials from the TEST-ONLY fleet issuer; the
// nodes form their mesh by themselves and the root's coordinator drives every plan through the real core.
// "sim" results are protocol-bench numbers (virtual time, no RF, no energy), never hardware evidence; the
// interference model of the world (per node and channel loss) stands in for "the new channel is bad at some
// spots". Scenario IDs are in the test names.
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>

#include "capi/context.hpp"
#include "core/channel/score.hpp"
#include "fleet.hpp"
#include "cut_matrix.hpp"
#include "lmtest.hpp"
#include "port/sim/sim_node.hpp"
#include "port/sim/sim_provision.hpp"
#include "port/sim/sim_world.hpp"

using namespace lm;
using namespace lm::sim;
using root::CState;
using root::Why;

namespace {

// Root = node 0 (address 1), the others get addresses 2, 3, ... in index order. `links` overrides the chain.
// LM_SEED_SHIFT=k re-runs every scenario on another random stream (robustness sweeps; the default run uses 0).
uint64_t seed_shift() {
    const char *v = std::getenv("LM_SEED_SHIFT");
    return v == nullptr ? 0 : std::strtoull(v, nullptr, 10);
}

struct CNet {
    unsigned n;
    fleet::Network net;
    World world;
    std::vector<uint16_t> addrs;
    std::vector<fleet::NodeKit> kits;

    explicit CNet(unsigned n_nodes, uint64_t seed = 61, bool chain = true, unsigned drift_node = 0, int32_t drift_ppm = 0,
                  bool channel_module = true)
        : n(n_nodes), net(seed), world(WorldOptions{seed + seed_shift(), 0}) {
        for (unsigned i = 0; i < n; ++i) {
            NodeOptions o;
            o.role = i == 0 ? Role::Root : Role::Relay;
            o.mesh = true;
            o.channel = channel_module;
            o.clock_drift_ppm = i == drift_node ? drift_ppm : 0;
            (void)world.add_node(o);
            node(i).jobs.latency_us = 2000;
            addrs.push_back(i == 0 ? 1 : static_cast<uint16_t>(i + 1));
            kits.push_back(i == 0 ? net.make_root() : net.make_node(i + 1, addrs.back()));
        }
        if (chain) {
            world.make_chain();
        }
        for (unsigned i = 0; i < n; ++i) {
            LM_CHECK_OK(fleet::provision(node(i).store, net, kits[i]));
        }
    }

    SimNode &node(unsigned i) { return world.node(static_cast<uint16_t>(i)); }
    Engine &eng(unsigned i) { return node(i).ctx()->engine; }
    lm_context_t *ctx(unsigned i) { return node(i).ctx(); }
    MonoTime now(unsigned i) { return node(i).clock.now(); }
    route::Mesh &mesh(unsigned i) { return eng(i).mesh(); }
    channel::Channel &chan(unsigned i) { return eng(i).chan(); }
    root::Coordinator &coord() { return eng(0).coordinator(); }
    root::Coordinator::View view() { return coord().view(); }
    uint8_t radio(unsigned i) { return eng(i).channel(); }

    void link(unsigned a, unsigned b, bool up = true, uint16_t loss = 0, uint32_t delay_us = 1000) {
        LinkParams p;
        p.up = up;
        p.loss_permille = loss;
        p.delay_us = delay_us;
        world.set_link(static_cast<uint16_t>(a), static_cast<uint16_t>(b), p);
    }
    void boot(unsigned i) {
        LM_CHECK_OK(node(i).boot());
        LM_CHECK_EQ(lm_start(node(i).ctx()), LM_STATUS_OK);
    }
    void boot_all() {
        for (unsigned i = 0; i < n; ++i) {
            boot(i);
        }
    }
    void cut_and_boot(unsigned i, uint64_t down_ms = 0) {
        node(i).power_cut();
        node(i).store.power_restore();
        run_ms(down_ms);
        boot(i);
    }
    void run_ms(uint64_t ms) { world.run_until(world.now_us() + ms * 1000); }
    template <class P> bool until(P pred, uint64_t max_ms, uint64_t step_ms = 5) {
        for (uint64_t t = 0; t <= max_ms; t += step_ms) {
            if (pred()) {
                return true;
            }
            run_ms(step_ms);
        }
        return pred();
    }
    void poke() { node(0).notify(); }
    uint64_t at_ms() { return world.now_us() / 1000; }
    unsigned bit(unsigned i) { return 1U << (addrs[i] - 2U); }
    uint64_t mask(std::initializer_list<unsigned> nodes) {
        uint64_t m = 0;
        for (unsigned i : nodes) {
            m |= 1ULL << (addrs[i] - 2U);
        }
        return m;
    }
    Status request(uint32_t action, uint64_t revision) {
        lm_operation_id_t op = 0;
        const Status st = static_cast<Status>(lm_channel_request(ctx(0), action, revision, &op));
        poke();
        return st;
    }
    // A message towards the root (traffic for the RF-attempt windows of the degradation report).
    lm_operation_id_t send_to_root(unsigned from, uint64_t ttl_ms = 30000) {
        lm_send_request_t rq{};
        rq.struct_size = sizeof(rq);
        rq.abi_version = LM_ABI_VERSION;
        rq.destination.kind = LM_DEST_NODE;
        std::memcpy(rq.destination.node.bytes, kits[0].kit.id.bytes.data(), 32);
        rq.app_port = 100;
        rq.delivery = LM_RECEIVED;
        rq.storage = LM_VOLATILE;
        rq.priority = LM_PRIORITY_NORMAL;
        rq.queue_mode = LM_FIFO;
        rq.root_term = 1;
        rq.expires_root_ms = node(0).clock.now().to_ms() + ttl_ms;
        const uint8_t payload[24] = {1, 2, 3};
        lm_operation_id_t op = 0;
        (void)lm_send(ctx(from), &rq, payload, sizeof(payload), &op);
        node(from).notify();
        return op;
    }
    // Drains the events of node i and returns how many of them were messages.
    unsigned drain_messages(unsigned i) {
        unsigned messages = 0;
        lm_event_t ev{};
        std::array<uint8_t, 600> buf{};
        for (;;) {
            ev.struct_size = sizeof(ev);
            ev.abi_version = LM_ABI_VERSION;
            size_t req = 0;
            if (lm_next_event(ctx(i), &ev, buf.data(), buf.size(), &req) != LM_STATUS_OK) {
                return messages;
            }
            messages += ev.kind == LM_EVENT_MESSAGE ? 1U : 0U;
        }
    }
    bool received(unsigned from, lm_operation_id_t op) {
        lm_operation_t o{};
        o.struct_size = sizeof(o);
        o.abi_version = LM_ABI_VERSION;
        return lm_get_operation(ctx(from), op, &o) == LM_STATUS_OK && (o.evidence_bits & (1U << 4)) != 0;
    }
    void drain(unsigned i) {
        lm_event_t ev{};
        std::array<uint8_t, 600> buf{};
        for (;;) {
            ev.struct_size = sizeof(ev);
            ev.abi_version = LM_ABI_VERSION;
            size_t req = 0;
            if (lm_next_event(ctx(i), &ev, buf.data(), buf.size(), &req) != LM_STATUS_OK) {
                return;
            }
        }
    }
    // Runs for `ms`, sending one message from `from` every `gap_ms` and draining the events of the root.
    void traffic(unsigned from, uint64_t ms, uint64_t gap_ms = 2000) {
        for (uint64_t t = 0; t < ms; t += gap_ms) {
            send_to_root(from);
            run_ms(gap_ms);
            drain(0);
            drain(from);
        }
    }
    // The true root time lies inside every node's bound.
    bool clocks_hold() {
        const uint64_t truth = node(0).clock.now().to_ms();
        for (unsigned i = 1; i < n; ++i) {
            const RootTimeBound b = eng(i).delivery().root_time(now(i));
            if (node(i).powered() && b.valid && (truth < b.earliest_ms || truth > b.latest_ms)) {
                return false;
            }
        }
        return true;
    }

    bool ready(unsigned i) { return node(i).powered() && mesh(i).state() == route::Mesh::State::Ready; }
    bool has_clock(unsigned i) { return chan(i).stats().time_updates > 0; }
    bool formed(std::initializer_list<unsigned> nodes) {
        for (unsigned i : nodes) {
            if (!ready(i) || !has_clock(i)) {
                return false;
            }
        }
        return true;
    }
    bool formed_all() {
        for (unsigned i = 1; i < n; ++i) {
            if (!ready(i) || !has_clock(i)) {
                return false;
            }
        }
        return chan(0).loaded();
    }
    bool everyone_on(uint8_t ch, uint32_t epoch) {
        for (unsigned i = 0; i < n; ++i) {
            if (!node(i).powered() || radio(i) != ch || chan(i).epoch().value() != epoch || chan(i).current() != ch) {
                return false;
            }
        }
        return true;
    }
    void dump() {
        static const char *const st[] = {"MONITOR", "SURVEY", "PREPARING", "COMMITTED", "SWITCHING", "SETTLING", "ABORTED", "RECOVERING"};
        static const char *const md[] = {"normal", "prepared", "committed", "searching"};
        const auto v = view();
        std::printf("  t=%llu ms root %s why %u cur %u epoch %u req %llx ready %llx stored %llx applied %llx unreach %llx\n",
                    (unsigned long long)(world.now_us() / 1000), st[static_cast<unsigned>(v.state)], (unsigned)v.why,
                    v.current, v.epoch, (unsigned long long)v.required, (unsigned long long)v.ready,
                    (unsigned long long)v.stored, (unsigned long long)v.applied, (unsigned long long)v.unreachable);
        for (unsigned p = 0; p < coord().pairs(); ++p) {
            std::printf("  pair %u:", p);
            for (unsigned c = 0; c <= coord().candidates(); ++c) {
                const auto &s = coord().samples()[p][c];
                std::printf(" [%s ok %u fail %u svc %u]", c == 0 ? "home" : std::to_string(coord().candidate_channel(c - 1)).c_str(), s.ok, s.fail, s.svc_ms);
            }
            std::printf("\n");
        }
        std::printf("  survey reason %u visits %llu\n", (unsigned)coord().survey_reason(), (unsigned long long)coord().stats().visits);
        for (unsigned i = 0; i < n; ++i) {
            if (!node(i).powered()) {
                std::printf("  node %u off\n", i);
                continue;
            }
            const auto &s = chan(i).stats();
            std::printf("  node %u radio %u cur %u epoch %u %s mesh %u susp %llu time %llu prep %llu commit %llu sw %llu refused %llu scans %llu dwell %llu width %lld\n",
                        i, radio(i), chan(i).current(), chan(i).epoch().value(), md[static_cast<unsigned>(chan(i).mode())],
                        (unsigned)mesh(i).state(), (unsigned long long)mesh(i).stats().suspects, (unsigned long long)s.time_updates, (unsigned long long)s.prepared,
                        (unsigned long long)s.committed, (unsigned long long)s.switched, (unsigned long long)s.refused,
                        (unsigned long long)s.scans, (unsigned long long)s.scan_dwells,
                        (long long)(chan(i).clock_width_ms(now(i)) == UINT64_MAX ? -1 : (long long)chan(i).clock_width_ms(now(i))));
        }
    }
};

} // namespace


namespace {
// A formed chain with everybody's clock known. Returns after the network was quiet for a few seconds.
void form(CNet &n, uint64_t limit_ms = 300'000) {
    n.boot_all();
    const bool ok = n.until([&] { return n.formed_all(); }, limit_ms, 20);
    if (!ok) {
        n.dump();
    }
    LM_CHECK(ok);
    n.run_ms(5000);
}
} // namespace

LM_TEST("S17 smoke: a three-node chain learns the root clock and moves from channel 6 to 11") {
    CNet n(3);
    form(n);
    for (unsigned i = 0; i < 3; ++i) {
        LM_CHECK_EQ(n.radio(i), 6);
    }
    LM_CHECK(n.clocks_hold());
    LM_CHECK_OK(n.coord().plan_to(11, n.now(0)));
    n.poke();
    LM_CHECK(n.until([&] { return n.view().state == CState::Monitor && n.view().why == Why::Moved; }, 400'000, 50));
    LM_CHECK(n.everyone_on(11, 1));
    n.dump();
    LM_CHECK(n.view().applied == n.mask({1, 2}));
    LM_CHECK(n.view().unreachable == 0);
    LM_CHECK(n.clocks_hold());
}

LM_TEST("C03 sim: READY of a required relay never arrives: no COMMIT, ABORT after the timeout, the denominator keeps the relay") {
    CNet n(4);
    form(n);
    LM_CHECK_OK(n.coord().plan_to(11, n.now(0)));
    n.link(2, 3, false); // PREPARE cannot reach node 3 (and no READY comes back): node 3 stays required
    n.poke();
    n.run_ms(100'000);
    auto v = n.view();
    LM_CHECK(v.state == CState::Preparing);
    LM_CHECK(v.required == n.mask({1, 2, 3}));  // never dropped from the denominator
    LM_CHECK((v.ready & n.mask({3})) == 0);
    LM_CHECK(n.chan(1).mode() == channel::Mode::Prepared || n.chan(1).mode() == channel::Mode::Normal);
    LM_CHECK(n.until([&] { return n.view().state == CState::Monitor; }, 60'000, 100));
    v = n.view();
    LM_CHECK(v.why == Why::PrepareTimeout);
    LM_CHECK_EQ(n.coord().stats().commits, 0);
    LM_CHECK_EQ(v.epoch, 0);
    n.run_ms(20'000);
    for (unsigned i = 0; i < 3; ++i) { // the ABORT reached everybody who could hear it: nobody stays prepared
        LM_CHECK(n.chan(i).mode() == channel::Mode::Normal);
        LM_CHECK_EQ(n.radio(i), 6);
        LM_CHECK_EQ(n.chan(i).epoch().value(), 0);
    }
}

LM_TEST("C06 sim: a relay whose clock bound is wider than the tolerance refuses READY with TIME_UNCERTAIN; the interval holds under drift") {
    CNet n(4, 62, true, 3, 400); // node 3 runs 400 ppm fast (inside the assumed 500 ppm)
    n.link(2, 3, true, 0, 80'000); // 80 ms each way on the last hop: RTT >= 160 ms
    form(n);
    n.run_ms(60'000);
    LM_CHECK(n.clocks_hold()); // every node's interval contains the root's true time, drift included
    LM_CHECK(n.chan(3).clock_width_ms(n.now(3)) >= 150);
    n.coord().set_max_clock_error(50);
    LM_CHECK_OK(n.coord().plan_to(11, n.now(0)));
    n.poke();
    LM_CHECK(n.until([&] { return n.view().state == CState::Aborted || n.view().state == CState::Monitor; }, 60'000, 20));
    LM_CHECK(n.view().why == Why::TimeUncertain);
    LM_CHECK(n.coord().last_refusal() == Status::TimeUncertain);
    LM_CHECK_EQ(n.coord().stats().commits, 0);
    n.run_ms(30'000);
    for (unsigned i = 0; i < 4; ++i) {
        LM_CHECK_EQ(n.radio(i), 6);
        LM_CHECK(n.chan(i).mode() == channel::Mode::Normal);
    }
    // The same network with the default tolerance (2000 ms) does move: the bound is honest, not the network broken.
    n.coord().set_max_clock_error(2000);
    LM_CHECK_OK(n.coord().plan_to(11, n.now(0)));
    n.poke();
    LM_CHECK(n.until([&] { return n.view().state == CState::Monitor && n.view().why == Why::Moved; }, 500'000, 50));
    LM_CHECK(n.everyone_on(11, 2)); // the aborted plan burned epoch 1: epochs never repeat
    LM_CHECK(n.clocks_hold());
}

LM_TEST("API sim: lm_policy_get/set on the root (channel freeze, compare-and-set, refused changes) and lm_connectivity_get on a formed chain") {
    CNet n(3);
    form(n);
    lm_context_t *root = n.ctx(0);
    auto get = [&](lm_context_t *c, lm_policy_t &p) {
        p = lm_policy_t{};
        p.struct_size = sizeof(p);
        p.abi_version = LM_ABI_VERSION;
        return lm_policy_get(c, &p);
    };
    lm_policy_t p;
    LM_CHECK_EQ(get(root, p), LM_STATUS_OK);
    LM_CHECK_EQ(p.revision, 0u);
    LM_CHECK_EQ(p.join_mode, 1u); // external
    LM_CHECK_EQ(p.channel_automatic, 1u);
    LM_CHECK_EQ(p.channel_freeze, 0u);
    LM_CHECK_EQ(p.relay_allowed, 1u);
    LM_CHECK_EQ(p.auto_transfer_on_isolation, 0u);
    lm_operation_id_t op = 99;
    // Unchanged policy at the right revision: accepted, nothing happens, no revision bump.
    LM_CHECK_EQ(lm_policy_set(root, &p, 0, &op), LM_STATUS_OK);
    LM_CHECK_EQ(op, 0u);
    LM_CHECK_EQ(n.view().policy_revision, 0u);
    // Freeze through the policy is the same act as lm_channel_request(FREEZE).
    lm_policy_t want = p;
    want.channel_automatic = 0;
    want.channel_freeze = 1;
    LM_CHECK_EQ(lm_policy_set(root, &want, 1, &op), LM_STATUS_CONFLICT); // stale revision
    LM_CHECK_EQ(lm_policy_set(root, &want, 0, &op), LM_STATUS_OK);
    LM_CHECK(n.view().frozen);
    LM_CHECK_EQ(get(root, p), LM_STATUS_OK);
    LM_CHECK_EQ(p.revision, 1u);
    LM_CHECK_EQ(p.channel_freeze, 1u);
    LM_CHECK_EQ(p.channel_automatic, 0u);
    // A change this build has no mechanism for is refused, never applied: not a fake success. (The join mode is a
    // policy field since FIX8-D12: test_join "J04 FIX8"; two fields at once are refused.)
    lm_policy_t both = p;
    both.join_mode = 0;
    both.channel_automatic = 1;
    both.channel_freeze = 0;
    LM_CHECK_EQ(lm_policy_set(root, &both, 1, &op), LM_STATUS_INVALID_ARGUMENT);
    lm_policy_t transfer = p;
    transfer.auto_transfer_on_isolation = 1;
    LM_CHECK_EQ(lm_policy_set(root, &transfer, 1, &op), LM_STATUS_UNSUPPORTED);
    LM_CHECK_EQ(get(root, p), LM_STATUS_OK);
    LM_CHECK_EQ(p.join_mode, 1u);
    // Malformed requests.
    lm_policy_t bad = want;
    bad.channel_automatic = 1; // both automatic and frozen
    LM_CHECK_EQ(lm_policy_set(root, &bad, 1, &op), LM_STATUS_INVALID_ARGUMENT);
    bad = want;
    bad.join_mode = 3;
    LM_CHECK_EQ(lm_policy_set(root, &bad, 1, &op), LM_STATUS_INVALID_ARGUMENT);
    bad = want;
    bad.reserved[1] = 1;
    LM_CHECK_EQ(lm_policy_set(root, &bad, 1, &op), LM_STATUS_INVALID_ARGUMENT);
    bad = want;
    bad.struct_size = 8;
    LM_CHECK_EQ(lm_policy_set(root, &bad, 1, &op), LM_STATUS_INVALID_ARGUMENT);
    bad = want;
    bad.abi_version = 1;
    LM_CHECK_EQ(lm_policy_set(root, &bad, 1, &op), LM_STATUS_UNSUPPORTED);
    LM_CHECK_EQ(lm_policy_set(root, &want, UINT64_MAX, &op), LM_STATUS_INVALID_ARGUMENT);
    LM_CHECK_EQ(lm_policy_set(root, &want, 1, nullptr), LM_STATUS_INVALID_ARGUMENT);
    // Unfreeze again.
    want.channel_automatic = 1;
    want.channel_freeze = 0;
    LM_CHECK_EQ(lm_policy_set(root, &want, 1, &op), LM_STATUS_OK);
    LM_CHECK_EQ(get(root, p), LM_STATUS_OK);
    LM_CHECK_EQ(p.revision, 2u);
    LM_CHECK_EQ(p.channel_freeze, 0u);
    // A relay holds no policy.
    LM_CHECK_EQ(get(n.ctx(1), p), LM_STATUS_UNSUPPORTED);
    LM_CHECK_EQ(lm_policy_set(n.ctx(1), &want, 0, &op), LM_STATUS_UNSUPPORTED);

    // ---- connectivity ----
    auto conn = [&](unsigned i) {
        lm_connectivity_t c{};
        c.struct_size = sizeof(c);
        c.abi_version = LM_ABI_VERSION;
        LM_CHECK_EQ(lm_connectivity_get(n.ctx(i), &c), LM_STATUS_OK);
        return c;
    };
    const lm_connectivity_t cr = conn(0);
    LM_CHECK_EQ(cr.state, static_cast<uint32_t>(LM_REACHABLE));
    LM_CHECK_EQ(cr.root_depth, 0u);
    LM_CHECK((cr.validity_bits & LM_CONNECTIVITY_VALID_STATE) != 0);
    const lm_connectivity_t c2 = conn(2);
    LM_CHECK_EQ(c2.state, static_cast<uint32_t>(LM_REACHABLE));
    LM_CHECK_EQ(c2.root_depth, 2u);
    LM_CHECK((c2.validity_bits & LM_CONNECTIVITY_VALID_ROOT_DEPTH) != 0);
    LM_CHECK((c2.validity_bits & LM_CONNECTIVITY_VALID_STATE_SINCE) != 0);
    LM_CHECK(c2.state_since_mono_ms > 0);
    LM_CHECK_EQ(c2.validity_bits & (LM_CONNECTIVITY_VALID_LAST_AUTH_RX | LM_CONNECTIVITY_VALID_LAST_ROOT_ROUNDTRIP), 0u);
    LM_CHECK_EQ(c2.last_authenticated_rx_mono_ms, 0u);
    // The link to the parent goes away: the node is cut off, and stays a member (ACTIVE + not reachable, docs/07).
    n.link(1, 2, false);
    lm_connectivity_t cut{};
    LM_CHECK(n.until([&] { cut = conn(2); return cut.state != LM_REACHABLE; }, 300'000, 20));
    LM_CHECK(cut.state == LM_DEGRADED || cut.state == LM_ISOLATED);
    LM_CHECK_EQ(cut.reason, static_cast<uint32_t>(LM_STATUS_NO_ROUTE));
    lm_membership_t m{};
    m.struct_size = sizeof(m);
    m.abi_version = LM_ABI_VERSION;
    LM_CHECK_EQ(lm_membership_get(n.ctx(2), &m), LM_STATUS_OK);
    LM_CHECK_EQ(m.state, static_cast<uint32_t>(LM_ACTIVE));
    n.link(1, 2, true);
    LM_CHECK(n.until([&] { return conn(2).state == LM_REACHABLE; }, 300'000, 20));
}

LM_TEST("C07 unit/sim: freeze stops a plan in PREPARING and never cancels a COMMITTED one; the revision is a compare-and-set") {
    CNet n(3);
    form(n);
    // (a) PREPARING: the freeze aborts, nothing is committed
    LM_CHECK_OK(n.coord().plan_to(11, n.now(0)));
    n.poke();
    LM_CHECK(n.request(LM_CHANNEL_FREEZE, 0) == Status::Ok);
    LM_CHECK(n.request(LM_CHANNEL_FREEZE, 0) == Status::Conflict); // stale revision
    n.run_ms(60'000);
    LM_CHECK(n.view().state == CState::Monitor && n.view().frozen && n.view().policy_revision == 1);
    LM_CHECK_EQ(n.coord().stats().commits, 0);
    for (unsigned i = 0; i < 3; ++i) {
        LM_CHECK_EQ(n.radio(i), 6);
        LM_CHECK(n.chan(i).mode() == channel::Mode::Normal);
    }
    LM_CHECK(n.coord().plan_to(11, n.now(0)) == Status::Conflict); // frozen: no new plan
    LM_CHECK(n.request(LM_CHANNEL_RECALCULATE, 1) == Status::Conflict);
    LM_CHECK(n.request(LM_CHANNEL_AUTO, 1) == Status::Ok);
    LM_CHECK_EQ(n.view().policy_revision, 2);
    // (b) COMMITTED: the freeze changes nothing for that plan
    LM_CHECK_OK(n.coord().plan_to(11, n.now(0)));
    n.poke();
    LM_CHECK(n.until([&] { return n.view().state == CState::Committed; }, 200'000, 5));
    LM_CHECK(n.request(LM_CHANNEL_FREEZE, 2) == Status::Ok);
    LM_CHECK(n.until([&] { return n.view().state == CState::Monitor && n.view().why == Why::Moved; }, 500'000, 50));
    LM_CHECK(n.everyone_on(11, 2));
    LM_CHECK(n.view().frozen);
    LM_CHECK(n.coord().plan_to(1, n.now(0)) == Status::Conflict);
}

LM_TEST("C12 sim: the root rolls back with a higher epoch to the old channel; an old plan is never given life again") {
    CNet n(3);
    form(n);
    LM_CHECK_OK(n.coord().plan_to(11, n.now(0)));
    n.poke();
    LM_CHECK(n.until([&] { return n.view().state == CState::Monitor && n.view().why == Why::Moved; }, 500'000, 50));
    LM_CHECK(n.everyone_on(11, 1));
    const channel::Plan first = n.coord().plan();
    LM_CHECK_OK(n.coord().rollback(n.now(0)));
    n.poke();
    LM_CHECK(n.until([&] { return n.view().state == CState::Monitor && n.view().why == Why::Moved; }, 500'000, 50));
    LM_CHECK(n.everyone_on(6, 2)); // back on the old channel, under epoch 2
    LM_CHECK(n.coord().plan().epoch.value() == 2 && n.coord().plan().old_ch == 11 && n.coord().plan().new_ch == 6);
    // Replays of plan 1 (epoch 1) from the root's own end session: refused, nothing moves.
    const uint64_t refused = n.chan(2).stats().refused;
    for (channel::Phase ph : {channel::Phase::Prepare, channel::Phase::Commit}) {
        channel::PlanRec rec;
        rec.phase = ph;
        rec.plan = first;
        std::array<uint8_t, channel::k_max_record> buf{};
        std::size_t len = 0;
        LM_CHECK_OK(channel::encode(rec, MutByteView{buf}, len));
        delivery::PathSpec route;
        LM_CHECK(n.eng(0).routes().path_to(n.kits[2].kit.id, route, n.now(0)));
        LM_CHECK_OK(n.eng(0).delivery().send_control(n.kits[2].kit.id, route, ByteView{buf.data(), len}, n.now(0)));
        n.poke();
        n.run_ms(3000);
    }
    LM_CHECK(n.chan(2).stats().refused >= refused + 2);
    LM_CHECK(n.everyone_on(6, 2));
}

namespace {
// Plans 6 -> 11 on a chain and deafens `deaf` on channel 6 (and, with `both`, on 11) from the moment the last READY
// arrived: the COMMIT reaches only the nodes before it.
void plan_with_deaf_tail(CNet &n, unsigned deaf, bool both = false) {
    LM_CHECK_OK(n.coord().plan_to(11, n.now(0)));
    n.poke();
    LM_CHECK(n.until([&] {
        const auto v = n.view();
        return v.state == CState::Preparing && v.ready == v.required && v.required != 0;
    }, 200'000, 1));
    n.world.set_noise(static_cast<int>(deaf), 6, 1000);
    if (both) {
        n.world.set_noise(static_cast<int>(deaf), 11, 1000);
    }
}
} // namespace

LM_TEST("C04 sim: a relay never gets COMMIT; the rest moves, the result says STORED / APPLIED / RECOVERING, the stragglers find the mesh") {
    CNet n(4);
    form(n);
    plan_with_deaf_tail(n, 2, true); // node 2 (and node 3 behind it) hear nothing on 6 or 11 for a while
    LM_CHECK(n.until([&] { return n.view().state == CState::Settling; }, 400'000, 50));
    const uint64_t switched_at = n.at_ms();
    LM_CHECK_EQ(n.radio(0), 11);
    LM_CHECK_EQ(n.radio(1), 11);
    // Past the settle window with the tail still cut off: partial arrival is stated, not hidden.
    LM_CHECK(n.until([&] { return n.view().state == CState::Recovering; }, 120'000, 50));
    auto v = n.view();
    LM_CHECK(v.stored == n.mask({1}));
    LM_CHECK(v.applied == n.mask({1}));
    LM_CHECK(v.unreachable == n.mask({2, 3})); // required, never confirmed STORED
    LM_CHECK(n.chan(2).mode() != channel::Mode::Committed && n.chan(3).mode() != channel::Mode::Committed);
    LM_CHECK_EQ(n.radio(2), 6); // no node went back or ahead alone
    LM_CHECK_EQ(n.radio(3), 6);
    // The tail hears again: an authenticated scan (stored channel, pending target, allowed set) brings it in.
    n.world.clear_noise();
    LM_CHECK(n.until([&] { return n.everyone_on(11, 1) && n.view().state == CState::Monitor; }, 360'000, 100));
    const uint64_t took_s = (n.at_ms() - switched_at) / 1000;
    std::printf("  C04-sim: all four on channel 11 %llu s after the switch (target: <= 360 s after the tail hears again)\n",
                static_cast<unsigned long long>(took_s));
    LM_CHECK(n.view().applied == n.mask({1, 2, 3}));
    LM_CHECK(n.view().why == Why::Moved);
    LM_CHECK(n.eng(2).identity().is_member() && n.eng(3).identity().is_member()); // membership kept
    LM_CHECK(n.chan(2).stats().scan_dwells > 0);
    LM_CHECK(n.chan(2).stats().scan_dwells < 200); // bounded search
}

LM_TEST("C05 sim: the root loses power right after COMMIT is durable; it comes back on the target channel, never on the old one") {
    CNet n(3);
    form(n);
    LM_CHECK_OK(n.coord().plan_to(11, n.now(0)));
    n.poke();
    LM_CHECK(n.until([&] { return n.view().state == CState::Committed; }, 200'000, 1));
    const uint64_t cut_at = n.at_ms();
    const RootTerm term_before = n.eng(0).identity().term();
    n.node(0).power_cut();
    n.node(0).store.power_restore();
    n.run_ms(3000);
    n.boot(0);
    // The stored COMMITTED record decides before the mesh starts: the target channel, at once.
    LM_CHECK(n.until([&] { return n.node(0).powered() && n.chan(0).loaded(); }, 20'000, 1));
    LM_CHECK_EQ(n.radio(0), 11);
    LM_CHECK_EQ(n.chan(0).current(), 11);
    LM_CHECK_EQ(n.chan(0).epoch().value(), 1);
    LM_CHECK(!n.chan(0).committed());
    // No lone rollback: nobody is ever seen on the old channel again once the plan reached them.
    bool back_on_6 = false;
    LM_CHECK(n.until([&] {
        back_on_6 = back_on_6 || n.radio(0) == 6;
        return n.everyone_on(11, 1) && n.ready(1) && n.ready(2) && n.view().state == CState::Monitor;
    }, 900'000, 100));
    LM_CHECK(!back_on_6);
    LM_CHECK(n.view().why == Why::Moved);
    // docs/18 C05 "新term": the restarted root publishes a new root_term (ARCH2-D1) and the members follow it.
    LM_CHECK(term_before < n.eng(0).identity().term());
    LM_CHECK(n.eng(1).identity().term() == n.eng(0).identity().term() && n.eng(2).identity().term() == n.eng(0).identity().term());
    std::printf("  C05-sim: root back on 11 immediately, all three converged %llu s after the power cut\n",
                static_cast<unsigned long long>((n.at_ms() - cut_at) / 1000));
}


// FIX6-D2: the stored COMMITTED channel is applied with a checked set+readback before the mesh (and the root's
// coordinator) starts; a refusal keeps the mesh held, is retried a bounded number of times and never reports a switch.
LM_TEST("FIX6 sim: the root's boot cannot set the stored committed channel: the mesh stays held, no switch is reported, the retry succeeds") {
    CNet n(3);
    form(n);
    LM_CHECK_OK(n.coord().plan_to(11, n.now(0)));
    n.poke();
    LM_CHECK(n.until([&] { return n.view().state == CState::Committed; }, 200'000, 1));
    n.node(0).power_cut();
    n.node(0).store.power_restore();
    n.run_ms(3000);
    n.node(0).radio.set_channel_fault_count = 3; // the first three attempts fail
    n.boot(0);
    n.run_ms(1800); // the first attempts have failed by now
    LM_CHECK(n.chan(0).holds_mesh());
    LM_CHECK(!n.chan(0).loaded());
    LM_CHECK(n.mesh(0).state() == route::Mesh::State::Off);
    LM_CHECK_EQ(n.chan(0).stats().switched, 0u);
    LM_CHECK(n.until([&] { return n.chan(0).loaded(); }, 5000, 10));
    LM_CHECK_EQ(n.radio(0), 11);
    LM_CHECK(!n.chan(0).holds_mesh());
    LM_CHECK(n.until([&] { return n.mesh(0).state() != route::Mesh::State::Off; }, 5000, 10));
}

LM_TEST("FIX6 sim: a radio that never takes the stored channel keeps the mesh off after the bounded retries") {
    CNet n(3);
    form(n);
    LM_CHECK_OK(n.coord().plan_to(11, n.now(0)));
    n.poke();
    LM_CHECK(n.until([&] { return n.view().state == CState::Committed; }, 200'000, 1));
    n.node(0).power_cut();
    n.node(0).store.power_restore();
    n.run_ms(3000);
    n.node(0).radio.set_channel_fault_count = 1000;
    n.boot(0);
    n.run_ms(60'000);
    LM_CHECK(n.chan(0).holds_mesh());
    LM_CHECK(n.mesh(0).state() == route::Mesh::State::Off);
    LM_CHECK_EQ(n.chan(0).stats().switched, 0u);
    LM_CHECK(n.node(0).radio.set_channel_fault_count > 900); // bounded: it was not hammered
}

LM_TEST("C08 sim: a candidate that is better on average but jammed at one relay is not adopted; the worst link decides") {
    CNet n(4);
    form(n);
    n.coord().set_maintenance_gap(true); // the operator allows the short measurement pause (a chain has no alternative path)
    n.world.set_noise(-1, 6, 100);       // the home channel is mediocre everywhere ...
    n.world.set_noise(-1, 1, 400);       // ... channel 1 is worse ...
    n.world.set_noise(2, 11, 900);       // ... channel 11 is clean except at relay 2
    n.run_ms(10'000);
    LM_CHECK(n.request(LM_CHANNEL_RECALCULATE, 0) == Status::Ok);
    LM_CHECK(n.view().state == CState::Survey);
    LM_CHECK(n.until([&] { return n.view().state != CState::Survey; }, 1'500'000, 200));
    n.dump();
    LM_CHECK(n.view().state == CState::Monitor);
    LM_CHECK(n.view().why == Why::RetainedWorse); // CURRENT_CHANNEL_RETAINED
    LM_CHECK_EQ(n.coord().stats().plans, 0);
    n.run_ms(20'000);
    for (unsigned i = 0; i < 4; ++i) { // everybody came back from its visits
        LM_CHECK_EQ(n.radio(i), 6);
        LM_CHECK(n.chan(i).mode() == channel::Mode::Normal);
    }
}

LM_TEST("C01 sim: a clearly better channel measured at every pair is adopted through the full plan") {
    CNet n(4);
    form(n);
    n.coord().set_maintenance_gap(true);
    n.world.set_noise(-1, 6, 80); 
    n.run_ms(10'000);
    LM_CHECK(n.request(LM_CHANNEL_RECALCULATE, 0) == Status::Ok);
    LM_CHECK(n.until([&] { return n.coord().stats().plans > 0; }, 1'500'000, 200));
    LM_CHECK(n.until([&] { return n.view().state == CState::Monitor; }, 900'000, 200));
    n.dump();
    LM_CHECK(n.view().why == Why::Moved);
    n.world.clear_noise();
    LM_CHECK(n.everyone_on(n.radio(0), 1));
    LM_CHECK(n.radio(0) != 6);
}

LM_TEST("C11 sim: without a maintenance gap a chain is not surveyed: nobody leaves its channel, the reason is stated") {
    CNet n(4);
    form(n);
    LM_CHECK(n.request(LM_CHANNEL_RECALCULATE, 0) == Status::Ok);
    LM_CHECK(n.view().state == CState::Monitor);
    LM_CHECK(n.view().why == Why::GapNeeded);
    n.run_ms(120'000);
    for (unsigned i = 0; i < 4; ++i) {
        LM_CHECK_EQ(n.chan(i).stats().surveys, 0);
        LM_CHECK_EQ(n.chan(i).stats().scan_dwells, 0);
        LM_CHECK(n.ready(i) || i == 0);
        LM_CHECK_EQ(n.radio(i), 6);
    }
    // A two-node network has no stranded child: the link is measured without any gap.
    CNet m(2, 63);
    form(m);
    LM_CHECK(m.request(LM_CHANNEL_RECALCULATE, 0) == Status::Ok);
    LM_CHECK(m.view().state == CState::Survey);
    LM_CHECK(m.until([&] { return m.view().state != CState::Survey; }, 900'000, 200));
    LM_CHECK(m.view().why == Why::RetainedSmall); // nothing to gain on a quiet channel: CURRENT_CHANNEL_RETAINED
    LM_CHECK_EQ(m.radio(1), 6);
}


LM_TEST("C09/LP15 sim: a sleepy leaf misses two channel changes over 24 h; on wake it searches a bounded set and follows only the last plan") {
    CNet n(3);
    form(n);
    n.coord().set_sleepy(ShortAddr{n.addrs[2]}, true); // node 2 sleeps: a deferred participant, not a required one
    n.node(2).power_cut();
    n.node(2).store.power_restore();
    n.run_ms(5000);
    for (uint8_t target : {uint8_t{11}, uint8_t{1}}) { // two changes while it sleeps
        LM_CHECK_OK(n.coord().plan_to(target, n.now(0)));
        n.poke();
        LM_CHECK(n.until([&] { return n.view().state == CState::Monitor && n.view().why == Why::Moved; }, 500'000, 50));
        LM_CHECK((n.view().required & n.mask({2})) == 0);
        LM_CHECK((n.view().deferred & n.mask({2})) != 0); // the deferred set is stated, not folded into "success"
        n.run_ms(60'000);
    }
    LM_CHECK_EQ(n.radio(0), 1);
    LM_CHECK_EQ(n.radio(1), 1);
    n.run_ms(24ULL * 3600 * 1000);
    LM_CHECK(n.ready(1) && n.chan(1).epoch().value() == 2);
    n.boot(2);
    const uint64_t woke = n.at_ms();
    LM_CHECK(n.until([&] { return n.ready(2) && n.radio(2) == 1 && n.chan(2).epoch().value() == 2 && n.chan(2).current() == 1; },
                     360'000, 100));
    std::printf("  C09/LP15-sim: back on channel 1 (epoch 2) %llu s after the wake, %llu scan(s), %llu dwell(s)\n",
                static_cast<unsigned long long>((n.at_ms() - woke) / 1000),
                static_cast<unsigned long long>(n.chan(2).stats().scans), static_cast<unsigned long long>(n.chan(2).stats().scan_dwells));
    LM_CHECK(n.eng(2).identity().is_member()); // the membership was never touched
    LM_CHECK_EQ(n.chan(2).stats().prepared, 0);  // the old plans are not replayed in order ...
    LM_CHECK_EQ(n.chan(2).stats().committed, 1); // ... one authenticated catch-up to the final plan
    LM_CHECK(n.chan(2).stats().scan_dwells < 60);
}

LM_TEST("LP16 sim: a critical receiver that sleeps defers the plan; only an explicit deferred permission lets it go on") {
    CNet n(3);
    form(n);
    n.coord().set_sleepy(ShortAddr{n.addrs[2]}, true);
    n.coord().set_critical(ShortAddr{n.addrs[2]}, true);
    n.node(2).power_cut();
    n.node(2).store.power_restore();
    n.run_ms(400'000); // its lease at the root has run out: it is not attached
    LM_CHECK(n.coord().plan_to(11, n.now(0)) == Status::PeerAsleep); // not silently dropped from the required set
    LM_CHECK(n.view().why == Why::CriticalAsleep);
    LM_CHECK_EQ(n.coord().stats().plans, 0);
    n.run_ms(60'000);
    for (unsigned i = 0; i < 2; ++i) {
        LM_CHECK_EQ(n.radio(i), 6);
        LM_CHECK_EQ(n.chan(i).stats().prepared, 0);
    }
    n.coord().allow_deferred(true); // the administrator's explicit permission
    LM_CHECK_OK(n.coord().plan_to(11, n.now(0)));
    n.poke();
    LM_CHECK(n.until([&] { return n.view().state == CState::Monitor && n.view().why == Why::Moved; }, 500'000, 50));
    LM_CHECK((n.view().deferred & n.mask({2})) != 0);
    n.run_ms(3600ULL * 1000);
    n.boot(2);
    LM_CHECK(n.until([&] { return n.ready(2) && n.radio(2) == 11 && n.chan(2).epoch().value() == 1; }, 360'000, 100));
}

LM_TEST("C10 sim: every channel jammed after a partial commit: the straggler says it is searching, the search stays inside its budget, nothing is undone")
{
    CNet n(3);
    form(n);
    plan_with_deaf_tail(n, 2, true);
    LM_CHECK(n.until([&] { return n.view().state == CState::Settling; }, 400'000, 50));
    n.world.set_noise(-1, 0, 1000); // all channels dead, everywhere
    const uint64_t scans0 = n.chan(2).stats().scans, dwells0 = n.chan(2).stats().scan_dwells;
    n.run_ms(600'000);
    LM_CHECK(n.chan(2).mode() == channel::Mode::Searching); // stated, not a silent "connected"
    LM_CHECK(n.eng(2).identity().is_member());              // no membership loss because nobody can be reached
    LM_CHECK(n.view().state == CState::Recovering);
    LM_CHECK((n.view().unreachable & n.mask({2})) != 0);
    // Budget: at most ~12 attempts in 10 minutes (backoff 1 s doubling to 60 s), two laps of <= 3 channels each.
    const uint64_t scans = n.chan(2).stats().scans - scans0, dwells = n.chan(2).stats().scan_dwells - dwells0;
    std::printf("  C10-sim: 600 s of total jam: %llu attempts, %llu dwells (%.1f %% of the time on the air)\n",
                static_cast<unsigned long long>(scans), static_cast<unsigned long long>(dwells),
                100.0 * static_cast<double>(dwells) * 0.2 / 600.0);
    LM_CHECK(scans <= 12);
    LM_CHECK(dwells <= 12 * 6);
    // The jam ends: the mesh is found again and the network is whole on the committed channel.
    n.world.clear_noise();
    const uint64_t t0 = n.at_ms();
    LM_CHECK(n.until([&] { return n.everyone_on(11, 1) && n.view().state == CState::Monitor; }, 600'000, 100));
    std::printf("  C10-sim: whole again %llu s after the jam ended\n", static_cast<unsigned long long>((n.at_ms() - t0) / 1000));
}


namespace {
// Root 0; relays 1 and 2 hear the root; 3 hears 1 and 2; 4 hears 2 and 1. Every leaf has a spare parent.
struct Spare5 : CNet {
    Spare5() : CNet(5, 71, false) {
        link(0, 1);
        link(0, 2);
        link(1, 3);
        link(2, 3);
        link(2, 4);
        link(1, 4);
    }
};
} // namespace

LM_TEST("C02 sim: one bad link (and BUSY at its child) does not start a channel change: the route module repairs, the channel stays") {
    Spare5 n;
    form(n);
    n.link(1, 3, true, 250); // the link between relay 1 and leaf 3 loses a quarter of the frames
    n.node(3).radio.tx_fault = Status::Busy; // and the leaf's driver is BUSY now and then: never an RF-loss sample
    n.node(3).radio.tx_fault_count = 30;
    const uint64_t drops_before = n.eng(3).tx().stats().local_refused;
    for (unsigned k = 0; k < 4; ++k) { // 20 minutes of traffic from the leaf
        n.traffic(3, 300'000);
    }
    n.dump();
    LM_CHECK(n.eng(3).tx().stats().local_refused >= drops_before); // (the faults happened only if the leaf transmitted)
    LM_CHECK_EQ(n.coord().stats().surveys, 0);
    LM_CHECK_EQ(n.coord().stats().plans, 0);
    LM_CHECK(n.view().state == CState::Monitor);
    LM_CHECK_EQ(n.view().epoch, 0);
    for (unsigned i = 0; i < 5; ++i) {
        LM_CHECK_EQ(n.radio(i), 6);
    }
    LM_CHECK(n.until([&] { return n.ready(3); }, 300'000, 100)); // (the lossy link may keep it flapping for a while)
    std::printf("  C02-sim: leaf 3 parent is now address %u; %llu degraded report(s) sent by it\n", n.mesh(3).parent_addr().value(),
                static_cast<unsigned long long>(n.chan(3).stats().degraded_sent));
}

LM_TEST("C01 sim (automatic): two independent nodes losing frames on the home channel start the survey and the move on their own") {
    Spare5 n;
    form(n);
    n.coord().set_maintenance_gap(true);
    n.world.set_noise(3, 6, 250); // interference near leaf 3 ...
    n.world.set_noise(4, 6, 250); // ... and near leaf 4, on the home channel only
    const uint64_t t0 = n.at_ms();
    LM_CHECK(n.until([&] {
        n.send_to_root(3);
        n.send_to_root(4);
        n.run_ms(2000);
        n.drain(0);
        n.drain(3);
        n.drain(4);
        return n.coord().stats().plans > 0;
    }, 3'000'000, 1));
    LM_CHECK(n.until([&] { return n.view().state == CState::Monitor; }, 900'000, 200));
    n.dump();
    std::printf("  C01-auto-sim: survey %llu s after the first traffic, %llu degraded report(s) at the root, now on channel %u\n",
                static_cast<unsigned long long>((n.at_ms() - t0) / 1000), static_cast<unsigned long long>(n.coord().stats().degraded),
                n.radio(0));
    LM_CHECK(n.view().why == Why::Moved);
    LM_CHECK(n.radio(0) != 6);
    LM_CHECK(n.coord().stats().degraded >= 2);
}


// POWER-* for the channel record (sim store injection, docs/12 §4): a member loses power before, in the middle of and
// after every record write of one plan. Whatever the Flash kept must be an allowed state: the old channel with or
// without PREPARED, or the target channel; then the network finishes the plan.
LM_TEST("POWER-* channel (sim): power cut before/torn/after every channel record write of a member leaves only allowed states") {
    const lmtest::CutTotals t = lmtest::cut_matrix(
        "channel commit", {{0, "root"}, {1, "member"}}, [](unsigned target, uint64_t k, sim::CutMode mode) {
            lmtest::CutRun out;
            CNet n(3, 81 + k);
            form(n);
            sim::SimStore &st = n.node(target).store;
            st.arm_cut(st.mutating_ops() + k, mode);
            LM_CHECK_OK(n.coord().plan_to(11, n.now(0)));
            n.poke();
            if (n.until([&] { return st.cut_fired(); }, 400'000, 5)) {
                out.fired = true;
                n.node(target).power_cut();
                st.power_restore();
                n.run_ms(2000);
                n.boot(target);
                LM_CHECK(n.until([&] { return n.node(target).powered() && n.chan(target).loaded(); }, 20'000, 1));
                const channel::Mode m = n.chan(target).mode();
                LM_CHECK(m == channel::Mode::Normal || m == channel::Mode::Prepared);
                LM_CHECK(n.radio(target) == 6 || n.radio(target) == 11);
                if (m == channel::Mode::Prepared) {
                    LM_CHECK_EQ(n.radio(target), 6); // PREPARED only: the old channel
                }
                if (n.chan(target).epoch().value() == 1) {
                    LM_CHECK_EQ(n.radio(target), 11); // a COMMITTED record (or an applied epoch): the target, no rollback
                    LM_CHECK_EQ(n.chan(target).current(), 11);
                }
            }
            // Either the plan completes, or it was never begun / timed out / was aborted after a restart and every node
            // is still consistent on the old channel with no plan held anywhere (a root cut included: FIX10-H7).
            out.ok = n.until([&] {
                return n.view().state == CState::Monitor &&
                       (n.everyone_on(11, 1) ||
                        (n.everyone_on(6, 0) && !n.chan(0).unsettled() && !n.chan(1).unsettled() && !n.chan(2).unsettled()));
            }, 1'500'000, 100);
            if (!out.ok) {
                out.why = "the plan neither completed on the target channel nor aborted everyone back to the old one";
                n.dump();
            }
            out.converged = out.ok && n.radio(0) == 11;
            return out;
        }, 0, 40);
    LM_CHECK(t.points >= 12);
    LM_CHECK_EQ(t.truncated, 0u);
}

LM_TEST("C-switch sim: a message queued inside the guard of the switch is held, then delivered once under its own MessageId") {
    CNet n(3);
    form(n);
    LM_CHECK_OK(n.coord().plan_to(11, n.now(0)));
    n.poke();
    LM_CHECK(n.until([&] { return n.view().state == CState::Committed; }, 200'000, 20));
    const uint64_t switch_ms = n.coord().plan().switch_root_ms;
    LM_CHECK(n.until([&] { return n.node(0).clock.now().to_ms() + 2500 >= switch_ms; }, 400'000, 20));
    LM_CHECK_EQ(n.radio(2), 6); // still on the old channel: the guard has begun, the switch has not
    (void)n.drain_messages(0);
    const lm_operation_id_t op = n.send_to_root(2, 60'000);
    LM_CHECK(n.until([&] { return n.radio(0) == 11 && n.radio(1) == 11 && n.radio(2) == 11; }, 20'000, 5));
    LM_CHECK(n.until([&] { return n.received(2, op); }, 60'000, 20));
    n.run_ms(10'000);
    LM_CHECK_EQ(n.drain_messages(0), 1); // exactly once
    LM_CHECK(n.everyone_on(11, 1));
}


LM_TEST("ME05-style sim: an idle network with the channel module wakes its owners about once a minute more, never on a fixed tick") {
    uint64_t steps[2] = {0, 0};
    for (unsigned with = 0; with < 2; ++with) {
        CNet n(3, 66, true, 0, 0, with == 1);
        n.boot_all();
        LM_CHECK(n.until([&] { return n.ready(1) && n.ready(2) && (with == 0 || n.formed_all()); }, 300'000, 20));
        n.run_ms(60'000); // let the attach traffic settle
        const uint64_t before = n.eng(1).stats().steps;
        n.run_ms(600'000);
        steps[with] = n.eng(1).stats().steps - before;
    }
    std::printf("  [measure] owner steps of a relay in 10 idle minutes: %llu without / %llu with the channel module (sim)\n",
                static_cast<unsigned long long>(steps[0]), static_cast<unsigned long long>(steps[1]));
    LM_CHECK(steps[1] <= steps[0] + 50); // the clock refresh: one request/answer pair per 300 s and the relaying of the neighbours' pairs
}


LM_TEST("R01/C01-scale sim: a 21-node, 20-hop chain runs a full plan; every relay is required, READY / STORED / APPLIED come back over 20 hops") {
    CNet n(21, 67);
    n.boot_all();
    const bool formed = n.until([&] { return n.formed_all(); }, 900'000, 100);
    if (!formed) {
        n.dump();
    }
    LM_CHECK(formed);
    n.run_ms(30'000);
    LM_CHECK_OK(n.coord().plan_to(11, n.now(0)));
    n.poke();
    LM_CHECK(n.until([&] { return n.view().state == CState::Committed; }, 200'000, 100));
    LM_CHECK_EQ(__builtin_popcountll(n.view().required), 20);
    const bool moved = n.until([&] { return n.view().state == CState::Monitor && n.view().why == Why::Moved; }, 900'000, 200);
    if (!moved) {
        n.dump();
    }
    LM_CHECK(moved);
    LM_CHECK(n.everyone_on(11, 1));
    LM_CHECK_EQ(__builtin_popcountll(n.view().applied), 20);
    uint64_t widest = 0;
    for (unsigned i = 1; i < 21; ++i) {
        widest = std::max<uint64_t>(widest, n.chan(i).clock_width_ms(n.now(i)));
    }
    std::printf("  [measure] 20-hop plan: clock interval of the widest node %llu ms (tolerance 2000 ms)\n", static_cast<unsigned long long>(widest));
    LM_CHECK(widest < 2000);
    LM_CHECK(n.clocks_hold());
}


// ---- pure functions ----------------------------------------------------------------------------------------
namespace {
channel::Sample smp(unsigned ok, unsigned fail) { return channel::Sample{static_cast<uint8_t>(ok), static_cast<uint8_t>(fail), 2}; }
} // namespace

LM_TEST("C08 unit: the decision needs data everywhere, the worst pair must not get worse, the total must gain 25 %") {
    using channel::Verdict;
    channel::Row good{}, jam{}, mid{}, hole{};
    good[0] = jam[0] = mid[0] = hole[0] = smp(5, 3);            // home: 37 % loss
    good[1] = smp(8, 0);                                        // candidate 1 clean
    jam[1] = smp(0, 8);                                         // candidate 1 jammed
    mid[1] = smp(6, 2);                                         // candidate 1 a little better
    hole[1] = smp(1, 1);                                        // fewer probes than the minimum: says nothing
    const channel::Row all_good[2] = {good, good};
    LM_CHECK(channel::decide(all_good, 2, 1, 25).verdict == Verdict::Move);
    const channel::Row one_jammed[2] = {good, jam}; // better on average, worse at one pair
    LM_CHECK(channel::decide(one_jammed, 2, 1, 25).verdict == Verdict::Worse);
    const channel::Row barely[2] = {mid, mid};
    LM_CHECK(channel::decide(barely, 2, 1, 25).verdict == Verdict::Small);
    const channel::Row gap[2] = {good, hole}; // a pair without data never counts as "good"
    LM_CHECK(channel::decide(gap, 2, 1, 25).verdict == Verdict::NoData);
    LM_CHECK(channel::decide(all_good, 0, 1, 25).verdict == Verdict::NoData);
    channel::Row two = good; // the better of two clean candidates wins; a tie keeps the first
    two[2] = smp(8, 0);
    const channel::Row tie[1] = {two};
    LM_CHECK(channel::decide(tie, 1, 2, 25).index == 1);
}

LM_TEST("S17 unit: every record round-trips, a truncated or extended record and an out-of-range field are rejected") {
    channel::PlanRec plan;
    plan.phase = channel::Phase::Commit;
    plan.plan.id.bytes.fill(7);
    plan.plan.term = RootTerm{3};
    plan.plan.epoch = ChannelEpoch{9};
    plan.plan.old_ch = 6;
    plan.plan.new_ch = 11;
    plan.plan.switch_root_ms = 123456;
    plan.plan.max_err_ms = 2000;
    plan.plan.settle_ms = 60000;
    plan.plan.participants.fill(5);
    std::array<uint8_t, channel::k_max_record> buf{};
    std::size_t len = 0;
    LM_CHECK_OK(channel::encode(plan, MutByteView{buf}, len));
    LM_CHECK(len <= channel::k_max_record && len == 84);
    channel::PlanRec back;
    LM_CHECK_OK(channel::decode(ByteView{buf.data(), len}, back));
    LM_CHECK(back.plan.id == plan.plan.id && back.plan.switch_root_ms == 123456 && back.phase == channel::Phase::Commit);
    for (std::size_t cut = 0; cut < len; ++cut) { // every prefix is rejected
        channel::PlanRec x;
        LM_CHECK(channel::decode(ByteView{buf.data(), cut}, x) != Status::Ok);
    }
    buf[len] = 0;
    channel::PlanRec x;
    LM_CHECK(channel::decode(ByteView{buf.data(), len + 1}, x) != Status::Ok); // trailing byte
    plan.plan.new_ch = 6; // old == new
    LM_CHECK_OK(channel::encode(plan, MutByteView{buf}, len));
    LM_CHECK(channel::decode(ByteView{buf.data(), len}, x) != Status::Ok);
    channel::Survey sv;
    sv.sid = 1;
    sv.channel = 11;
    sv.peer = 2;
    sv.start_root_ms = 5;
    sv.visit_ms = 60;
    sv.tol_ms = 100;
    sv.probes = 8;
    LM_CHECK_OK(channel::encode(sv, MutByteView{buf}, len));
    channel::Survey svb;
    LM_CHECK_OK(channel::decode(ByteView{buf.data(), len}, svb));
    sv.probes = 200; // out of range
    LM_CHECK_OK(channel::encode(sv, MutByteView{buf}, len));
    LM_CHECK(channel::decode(ByteView{buf.data(), len}, svb) != Status::Ok);
    channel::Receipt rc;
    rc.evidence = channel::Evidence::Applied;
    LM_CHECK_OK(channel::encode(rc, MutByteView{buf}, len));
    buf[1 + 16 + 32] = 4; // evidence 4 does not exist
    channel::Receipt rcb;
    LM_CHECK(channel::decode(ByteView{buf.data(), len}, rcb) != Status::Ok);
    LM_CHECK(!channel::is_record(ByteView{}) && !channel::is_record(ByteView{buf.data(), 0}));
}


LM_TEST("LP15b sim: a battery node's search is limited per wake episode and starts again only when the episode is renewed") {
    CNet n(2);
    form(n);
    n.chan(1).set_scan_limit(2); // the power slice hands each wake episode two search attempts
    n.node(0).power_cut(); // nobody to find: the root is gone
    n.run_ms(600'000);
    LM_CHECK_EQ(n.chan(1).scan_tries(), 2);
    LM_CHECK(n.chan(1).mode() == channel::Mode::Normal); // not searching any more: it sleeps until the next episode
    LM_CHECK(n.eng(1).identity().is_member());
    const uint64_t dwells = n.chan(1).stats().scan_dwells;
    n.run_ms(600'000);
    LM_CHECK_EQ(n.chan(1).stats().scan_dwells, dwells); // no radio time spent without an episode
    n.chan(1).rearm_scan(n.now(1));
    n.node(1).notify();
    n.run_ms(60'000);
    LM_CHECK(n.chan(1).stats().scan_dwells > dwells); // the new episode searches again
}

// ---- external review FIX3 (gpt-5.6-sol on 3596820) ---------------------------------------------------------------------

// FIX3-D6: a plan is what its whole canonical body says, not what its id says.
LM_TEST("FIX3-13 sim: PREPARE / COMMIT / ABORT with the id of the held plan but another channel, epoch or time is a conflict") {
    CNet n(3);
    form(n);
    channel::Channel &c = n.chan(1);
    channel::Plan p;
    n.eng(1).random(MutByteView{p.id.bytes});
    p.term = n.eng(1).identity().member().root_term;
    p.epoch = ChannelEpoch{c.epoch().value() + 1};
    p.old_ch = n.radio(1);
    p.new_ch = 11;
    p.switch_root_ms = n.at_ms() + 3'600'000;
    p.max_err_ms = 2000;
    p.settle_ms = 60000;
    p.policy_rev = 4;
    p.participants[0] = 0x77;
    auto send = [&](channel::Phase ph, const channel::Plan &q) {
        LM_CHECK(n.until([&] { return !c.job_pending(); }, 2000, 5));
        channel::PlanRec r;
        r.phase = ph;
        r.plan = q;
        LM_CHECK_OK(c.local_plan(r, n.now(1)));
        LM_CHECK(n.until([&] { return !c.job_pending(); }, 2000, 5));
    };
    auto altered = [&](unsigned how) {
        channel::Plan q = p;
        q.new_ch = how == 0 ? 12 : q.new_ch;
        q.switch_root_ms += how == 1 ? 1000 : 0;
        q.epoch = ChannelEpoch{q.epoch.value() + (how == 2 ? 1U : 0U)};
        q.participants[0] = how == 3 ? 0x78 : q.participants[0];
        return q;
    };
    send(channel::Phase::Prepare, p);
    LM_CHECK(c.have_plan() && !c.committed());
    // A repeated PREPARE with the same id and other contents is refused; the held plan is untouched.
    for (unsigned how = 0; how < 4; ++how) {
        const uint32_t refused = c.stats().refused;
        send(channel::Phase::Prepare, altered(how));
        LM_CHECK_EQ(c.stats().refused, refused + 1U);
        LM_CHECK(c.have_plan() && !c.committed());
        LM_CHECK_EQ(c.plan().new_ch, 11);
    }
    // A COMMIT that only shares the id is refused: nothing becomes COMMITTED, nothing is persisted.
    for (unsigned how = 0; how < 4; ++how) {
        const uint32_t refused = c.stats().refused;
        const uint32_t committed = c.stats().committed;
        send(channel::Phase::Commit, altered(how));
        LM_CHECK_EQ(c.stats().refused, refused + 1U);
        LM_CHECK_EQ(c.stats().committed, committed);
        LM_CHECK(!c.committed());
        LM_CHECK_EQ(c.plan().new_ch, 11);
        LM_CHECK(c.plan().switch_root_ms == p.switch_root_ms);
    }
    // An ABORT that only shares the id does not abort.
    for (unsigned how = 0; how < 4; ++how) {
        send(channel::Phase::Abort, altered(how));
        LM_CHECK(c.have_plan());
        LM_CHECK_EQ(c.plan().new_ch, 11);
    }
    // The real COMMIT is accepted; a repeat with other contents is a conflict, the stored plan does not change.
    send(channel::Phase::Commit, p);
    LM_CHECK(c.committed());
    LM_CHECK_EQ(c.stats().committed, 1u);
    for (unsigned how = 0; how < 4; ++how) {
        const uint32_t refused = c.stats().refused;
        send(channel::Phase::Commit, altered(how));
        LM_CHECK_EQ(c.stats().refused, refused + 1U);
        LM_CHECK(c.committed());
        LM_CHECK_EQ(c.plan().new_ch, 11);
        LM_CHECK(c.plan().switch_root_ms == p.switch_root_ms);
    }
    LM_CHECK_EQ(c.stats().committed, 1u);
}

// FIX3-D7: the plan's participants are the devices of the snapshot, not "whoever answers at that address".
LM_TEST("FIX3-8 sim: the device that takes over a required address after the snapshot is not that participant") {
    CNet n(3);
    form(n);
    // Node 2 (address 3) is the snapshot's participant; the ledger names a stand-in for it when the plan is made
    // (the participant "departed") and node 2 - a different device - sits at that address when the rounds run.
    auto &entry = const_cast<root::Entry &>(n.eng(0).ledger().entry(1));
    LM_CHECK(entry.address.value() == 3);
    const DeviceId real = entry.device;
    DeviceId departed = real;
    departed.bytes[31] ^= 0x5A;
    entry.device = departed;
    LM_CHECK_OK(n.coord().plan_to(11, n.now(0)));
    entry.device = real; // the new occupant
    n.poke();
    n.run_ms(60'000);
    auto v = n.view();
    LM_CHECK((v.required & n.mask({2})) != 0);       // still in the denominator
    LM_CHECK((v.ready & n.mask({2})) == 0);          // a stranger's READY does not count for it
    LM_CHECK_EQ(n.chan(2).stats().prepared, 0u);     // and it was never told to prepare
    LM_CHECK(!n.chan(2).have_plan());
    n.run_ms(100'000);
    LM_CHECK(n.view().state != CState::Committed && n.view().state != CState::Switching);
    LM_CHECK_EQ(n.radio(2), 6);
}

// FIX3-D8: pacing limits are debt that survives a restart; unknown elapsed time refills nothing.
LM_TEST("FIX3-14 sim: cooldown and the daily change count survive a root restart") {
    CNet n(3);
    form(n);
    LM_CHECK_OK(n.coord().plan_to(11, n.now(0)));
    n.poke();
    LM_CHECK(n.until([&] { return n.view().state == CState::Monitor && n.view().why == Why::Moved; }, 500'000, 50));
    n.run_ms(5000);
    LM_CHECK_EQ(n.view().changes_24h, 1u);
    const uint32_t left = n.view().cooldown_left_ms;
    LM_CHECK(left > 3'000'000u); // one hour, minus what has passed
    n.cut_and_boot(0, 30'000);
    LM_CHECK(n.until([&] { return n.chan(0).loaded(); }, 30'000, 20));
    n.run_ms(2000);
    LM_CHECK_EQ(n.view().changes_24h, 1u);           // the change count is not reset by the restart
    LM_CHECK(n.view().cooldown_left_ms > 3'000'000u); // neither is the cooldown (the time the power was off is not counted)
    LM_CHECK(n.view().cooldown_left_ms <= left);
}

// ---- external review FIX10 (opus on 8668c69): every plan state has a bounded exit -------------------------------------

namespace {
// A durable send whose journal job holds the node's one record memory for `latency_us` (the channel record must wait).
void hold_record_memory(CNet &n, unsigned node, unsigned to, uint64_t latency_us) {
    n.node(node).jobs.latency_us = latency_us;
    lm_send_request_t rq{};
    rq.struct_size = sizeof(rq);
    rq.abi_version = LM_ABI_VERSION;
    rq.destination.kind = LM_DEST_NODE;
    std::memcpy(rq.destination.node.bytes, n.kits[to].kit.id.bytes.data(), 32);
    rq.app_port = 100;
    rq.delivery = LM_RECEIVED;
    rq.storage = LM_DURABLE;
    rq.priority = LM_PRIORITY_NORMAL;
    rq.queue_mode = LM_FIFO;
    const uint8_t payload[8] = {1};
    lm_operation_id_t op = 0;
    LM_CHECK_EQ(lm_send(n.ctx(node), &rq, payload, sizeof(payload), &op), LM_STATUS_OK);
}
} // namespace

LM_TEST("FIX10-H7a sim: the root loses power in PREPARING after its own PREPARE is durable: on restart the plan is aborted and the network plans again") {
    CNet n(3);
    form(n);
    LM_CHECK_OK(n.coord().plan_to(11, n.now(0)));
    n.poke();
    LM_CHECK(n.until([&] { return n.chan(0).mode() == channel::Mode::Prepared && n.chan(1).mode() == channel::Mode::Prepared; }, 200'000, 1));
    LM_CHECK(n.view().state == CState::Preparing);
    n.node(0).power_cut();
    n.node(0).store.power_restore();
    n.run_ms(3000);
    n.boot(0);
    LM_CHECK(n.until([&] { return n.chan(0).loaded() && n.ready(1) && n.ready(2); }, 600'000, 100));
    // docs/05 §6: the plan is aborted (here after the restart, not after 120 s): the root, and the members it still knew
    LM_CHECK(n.until([&] { return n.view().state == CState::Monitor && !n.chan(0).have_plan() && !n.chan(1).have_plan() && !n.chan(2).have_plan(); },
                     300'000, 100));
    LM_CHECK(n.chan(0).mode() == channel::Mode::Normal);
    LM_CHECK(!n.chan(0).unsettled());
    n.run_ms(1'900'000); // the abort cooldown (600 s) and the pacing are over
    LM_CHECK_OK(n.coord().plan_to(1, n.now(0)));
    n.poke();
    LM_CHECK(n.until([&] { return n.radio(0) == 1 && n.radio(1) == 1 && n.radio(2) == 1 && n.view().state == CState::Monitor; }, 900'000, 100));
}

LM_TEST("FIX10-H7b sim: an ABORT that finds the root's record memory lent is kept and made durable") {
    CNet n(3);
    form(n);
    LM_CHECK_OK(n.coord().plan_to(11, n.now(0)));
    n.world.set_noise(2, 6, 1000); // node 2 never hears the PREPARE: the plan waits for its READY
    n.poke();
    LM_CHECK(n.until([&] { return n.chan(0).mode() == channel::Mode::Prepared && !n.chan(0).job_pending(); }, 200'000, 1));
    hold_record_memory(n, 0, 1, 300'000); // the journal job holds the record memory for 300 ms
    LM_CHECK_EQ(n.request(LM_CHANNEL_FREEZE, n.view().policy_revision), Status::Ok);
    n.run_ms(2000);
    n.node(0).jobs.latency_us = 2000;
    n.world.clear_noise();
    LM_CHECK(n.until([&] { return n.view().state == CState::Monitor; }, 120'000, 10));
    LM_CHECK(n.chan(0).mode() == channel::Mode::Normal); // not PREPARED for good
    LM_CHECK(!n.chan(0).unsettled());
    LM_CHECK_EQ(n.request(LM_CHANNEL_AUTO, n.view().policy_revision), Status::Ok);
    n.run_ms(1'900'000);
    LM_CHECK_OK(n.coord().plan_to(1, n.now(0)));
}

LM_TEST("FIX10-H7c sim: an ABORT that arrives while a member is still writing its PREPARED record is applied once that write is durable") {
    CNet n(3);
    form(n);
    n.node(1).jobs.latency_us = 9'000'000; // very slow Flash on the members: the PREPARED write takes 9 s
    n.node(2).jobs.latency_us = 9'000'000;
    LM_CHECK_OK(n.coord().plan_to(11, n.now(0)));
    n.poke();
    LM_CHECK(n.until([&] { return n.chan(1).job_pending() && n.chan(2).job_pending(); }, 200'000, 1));
    LM_CHECK_EQ(n.request(LM_CHANNEL_FREEZE, n.view().policy_revision), Status::Ok);
    n.run_ms(15'000);
    n.node(1).jobs.latency_us = 2000;
    n.node(2).jobs.latency_us = 2000;
    LM_CHECK(n.until([&] { return n.view().state == CState::Monitor; }, 120'000, 10));
    LM_CHECK(n.until([&] { return !n.chan(1).unsettled() && !n.chan(2).unsettled(); }, 60'000, 100)); // a PREPARED plan vetoes every sleep ticket
    LM_CHECK(!n.chan(1).have_plan() && !n.chan(2).have_plan());
}

LM_TEST("FIX10-H7d sim: a member whose root disappeared after its PREPARE drops the plan by itself (bounded, never a COMMITTED one)") {
    CNet n(3);
    form(n);
    LM_CHECK_OK(n.coord().plan_to(11, n.now(0)));
    n.poke();
    LM_CHECK(n.until([&] { return n.chan(1).mode() == channel::Mode::Prepared && n.chan(2).mode() == channel::Mode::Prepared; }, 200'000, 1));
    n.node(0).power_cut(); // no ABORT, no COMMIT will ever come
    LM_CHECK(n.chan(1).unsettled());
    LM_CHECK(n.until([&] { return !n.chan(1).unsettled() && !n.chan(2).unsettled(); }, 700'000, 1000));
    LM_CHECK(!n.chan(1).have_plan());
    LM_CHECK_EQ(n.radio(1), 6); // PREPARED only: never a switch
    LM_CHECK_EQ(n.chan(1).epoch().value(), 0u);
}

LM_TEST("FIX10-H8 sim: a freeze during the root's own COMMIT write does not make the root switch alone; the view says what happened") {
    CNet n(3);
    form(n);
    n.node(0).jobs.latency_us = 300'000; // the root's Flash writes take 300 ms (widens the window)
    LM_CHECK_OK(n.coord().plan_to(11, n.now(0)));
    n.poke();
    LM_CHECK(n.until([&] {
        const auto v = n.view();
        return v.state == CState::Preparing && v.ready == v.required && v.required != 0 && n.chan(0).mode() == channel::Mode::Prepared &&
               n.chan(0).job_pending();
    }, 400'000, 1));
    LM_CHECK_EQ(n.request(LM_CHANNEL_FREEZE, n.view().policy_revision), Status::Ok);
    n.node(0).jobs.latency_us = 2000;
    uint64_t alone_ms = 0;
    for (int i = 0; i < 3000; ++i) {
        n.run_ms(100);
        alone_ms += (n.radio(0) != n.radio(1)) ? 100U : 0U;
    }
    const auto v = n.view();
    std::printf("  H8: root on %u, node 1 on %u, state %u why %u, commits %u aborts %u, skew %llu ms\n", n.radio(0), n.radio(1),
                (unsigned)v.state, (unsigned)v.why, n.coord().stats().commits, n.coord().stats().aborts, (unsigned long long)alone_ms);
    // Either the plan was aborted everywhere, or (the root's COMMIT was already being written) it is followed to its end.
    // Never a root that switched while the coordinator reports an abort.
    if (n.radio(0) == 11) {
        LM_CHECK(n.everyone_on(11, 1));
        LM_CHECK(v.state != CState::Aborted && !(v.state == CState::Monitor && v.why == Why::Frozen));
        LM_CHECK(v.stored != 0 && n.coord().stats().commits == 1);
    } else {
        LM_CHECK(n.everyone_on(6, 0));
        LM_CHECK(v.state == CState::Monitor && v.why == Why::Frozen);
    }
    LM_CHECK(alone_ms <= 3000u); // (the switch skew of a plan is inside its guard of 2 x error + drain, never a lone root)
    LM_CHECK(v.frozen);
}

LM_TEST("FIX10-M11a sim: a deferred sleeper that wakes after a root restart learns the network's channel AND epoch") {
    CNet n(3);
    form(n);
    n.coord().set_sleepy(ShortAddr{n.addrs[2]}, true);
    n.node(2).power_cut();
    n.node(2).store.power_restore();
    n.run_ms(5000);
    LM_CHECK_OK(n.coord().plan_to(11, n.now(0)));
    n.poke();
    LM_CHECK(n.until([&] { return n.view().state == CState::Monitor && n.view().why == Why::Moved; }, 500'000, 50));
    n.node(0).power_cut(); // a mains outage while the sleeper still sleeps
    n.node(0).store.power_restore();
    n.run_ms(3000);
    n.boot(0);
    LM_CHECK(n.until([&] { return n.ready(1) && n.chan(0).loaded() && n.radio(0) == 11; }, 600'000, 100));
    n.run_ms(60'000);
    n.boot(2);
    LM_CHECK(n.until([&] { return n.ready(2) && n.radio(2) == 11; }, 360'000, 100));
    LM_CHECK(n.until([&] { return n.chan(2).current() == 11 && n.chan(2).epoch().value() == 1; }, 60'000, 100));
    LM_CHECK(n.until([&] { return !n.chan(2).unsettled(); }, 30'000, 100));
    // its next cold boot starts where the network is
    n.node(2).power_cut();
    n.node(2).store.power_restore();
    n.run_ms(1000);
    n.boot(2);
    n.run_ms(200);
    LM_CHECK_EQ(n.radio(2), 11);
    LM_CHECK(n.until([&] { return n.ready(2); }, 60'000, 50));
}

LM_TEST("FIX10-M11b sim: RECOVERING ends by its time bound when a required member never confirms: MONITOR with the reason 'partial', the sets stay visible") {
    CNet n(3);
    form(n);
    LM_CHECK_OK(n.coord().plan_to(11, n.now(0)));
    n.poke();
    LM_CHECK(n.until([&] {
        const auto v = n.view();
        return v.state == CState::Preparing && v.ready == v.required && v.required != 0;
    }, 200'000, 1));
    n.world.set_noise(2, 6, 1000);
    n.world.set_noise(2, 11, 1000);
    LM_CHECK(n.until([&] { return n.view().state == CState::Recovering; }, 600'000, 50));
    n.node(2).power_cut(); // the relay is gone for good
    n.world.clear_noise();
    LM_CHECK(n.until([&] { return n.view().state == CState::Monitor; }, 3'600'000, 1000));
    const auto v = n.view();
    LM_CHECK(v.why == Why::Partial);
    LM_CHECK((v.required & ~v.applied) != 0); // not called a success
    LM_CHECK_EQ(n.radio(0), 11);
    LM_CHECK_EQ(n.radio(1), 11);
}

LM_TEST("FIX10-L1 sim: a freeze is reported with an operation that completes when the record is durable") {
    CNet n(3);
    form(n);
    n.node(0).jobs.latency_us = 300'000;
    lm_operation_id_t op = 0;
    LM_CHECK_EQ(lm_channel_request(n.ctx(0), LM_CHANNEL_FREEZE, n.view().policy_revision, &op), LM_STATUS_OK);
    n.poke();
    LM_CHECK(op != 0);
    auto seen = [&] {
        unsigned found = 0;
        lm_event_t ev{};
        std::array<uint8_t, 600> buf{};
        for (;;) {
            ev.struct_size = sizeof(ev);
            ev.abi_version = LM_ABI_VERSION;
            size_t req = 0;
            if (lm_next_event(n.ctx(0), &ev, buf.data(), buf.size(), &req) != LM_STATUS_OK) {
                return found;
            }
            found += (ev.kind == LM_EVENT_OPERATION && ev.operation_id == op && ev.reason == 0) ? 1U : 0U;
        }
    };
    n.run_ms(100);
    LM_CHECK_EQ(seen(), 0u); // the write is not done: not reported as durable
    n.run_ms(1500);
    LM_CHECK_EQ(seen(), 1u);
    // a power cut after the report finds the freeze
    n.node(0).power_cut();
    n.node(0).store.power_restore();
    n.node(0).jobs.latency_us = 2000;
    n.boot(0);
    LM_CHECK(n.until([&] { return n.chan(0).loaded(); }, 60'000, 50));
    LM_CHECK(n.view().frozen);
}

// ---- external review FIX10 (astra on 8668c69): an uncertain write is reconciled before anything is written over it -------

namespace {
unsigned durable_phase(CNet &n, unsigned node) {
    store::RecordJob rec;
    rec.arm(store::RecordJob::Op::Load, store::rec::channel_plan);
    LM_CHECK_OK(store::record_load(n.node(node).store, rec));
    return rec.state;
}
} // namespace

LM_TEST("FIX10-A4a sim: a COMMIT write that took effect but reported an error is not overwritten by an ABORT") {
    CNet n(3);
    form(n);
    auto &c = n.chan(1);
    channel::Plan p;
    n.eng(1).random(MutByteView{p.id.bytes});
    p.term = n.eng(1).identity().member().root_term;
    p.epoch = ChannelEpoch{c.epoch().value() + 1};
    p.old_ch = n.radio(1);
    p.new_ch = 11;
    p.switch_root_ms = n.at_ms() + 3'600'000;
    p.max_err_ms = 2000;
    p.settle_ms = 60000;
    p.policy_rev = 4;
    p.participants[0] = 0x77;
    auto send = [&](channel::Phase ph) {
        LM_CHECK(n.until([&] { return !c.job_pending(); }, 5000, 5));
        channel::PlanRec r;
        r.phase = ph;
        r.plan = p;
        LM_CHECK_OK(c.local_plan(r, n.now(1)));
        LM_CHECK(n.until([&] { return !c.job_pending(); }, 5000, 5));
    };
    send(channel::Phase::Prepare);
    LM_CHECK(c.have_plan() && !c.committed());
    sim::SimStore &st = n.node(1).store;
    st.arm_cut(st.mutating_ops() + 1, CutMode::After); // the write takes effect, the owner is told StorageFailure
    send(channel::Phase::Commit);
    LM_CHECK(st.cut_fired());
    st.power_restore();
    LM_CHECK(n.until([&] { return !c.job_pending() && c.committed(); }, 5000, 5));
    LM_CHECK_EQ(durable_phase(n, 1), 2u);
    LM_CHECK(c.committed()); // memory follows what is durable
    send(channel::Phase::Abort);
    LM_CHECK_EQ(durable_phase(n, 1), 2u); // a committed plan cannot be aborted
    LM_CHECK(c.committed());
}

LM_TEST("FIX10-A4b sim: the root's own COMMIT write that reported an error is followed, not timed out into PREPARED") {
    CNet n(3);
    form(n);
    auto &c = n.chan(0);
    sim::SimStore &st = n.node(0).store;
    LM_CHECK_OK(n.coord().plan_to(11, n.now(0)));
    n.poke();
    LM_CHECK(n.until([&] { return c.have_plan() && !c.committed() && n.view().ready == n.view().required; }, 10'000, 1));
    st.arm_cut(st.mutating_ops() + 1, CutMode::After);
    LM_CHECK(n.until([&] { return st.cut_fired(); }, 10'000, 1));
    st.power_restore();
    LM_CHECK_EQ(durable_phase(n, 0), 2u);
    st.arm_cut(st.mutating_ops(), CutMode::Before); // and every later write fails until the store is restored
    n.run_ms(121'000);                              // ... through the prepare timeout
    st.power_restore();
    n.poke();
    n.run_ms(2000);
    LM_CHECK_EQ(durable_phase(n, 0), 2u); // never PREPARED again from stale memory
    LM_CHECK(n.view().state != CState::Aborted && !(n.view().state == CState::Monitor && n.view().why == Why::PrepareTimeout));
    LM_CHECK(n.until([&] { return n.everyone_on(11, 1); }, 600'000, 100));
}

LM_TEST_MAIN()
