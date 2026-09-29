// Scheduler (S14): the decision function of the DRR classes / control reserve / airtime bucket, the
// TX-pool admission that is the queue of that scheduler, and the owner under a join storm. The
// end-to-end evidence (control under a flood, LATEST) is in host/tests/e2e/test_sched_meshsim.py;
// the decision tests here are pure functions of (state, time), the storm test runs real nodes.
#include <algorithm>
#include <array>
#include <cstdio>
#include <vector>

#include "capi/context.hpp"
#include "core/radio/tx_pool.hpp"
#include "core/sched/sched.hpp"
#include "fleet.hpp"
#include "lmtest.hpp"
#include "port/sim/sim_node.hpp"
#include "port/sim/sim_provision.hpp"
#include "port/sim/sim_world.hpp"

using namespace lm;
using namespace lm::sched;
using namespace lm::sim;

namespace {

constexpr uint16_t k_frame = 200; // bytes of every frame in the decision tests

struct Run {
    std::array<uint64_t, k_classes> frames{};
    std::array<int64_t, k_classes> airtime{};
    int64_t elapsed_us = 0;
};

// Every class in `ready` always has a frame of k_frame bytes; the radio is busy for the frame's airtime.
Run drive(Scheduler &s, MonoTime &now, std::array<bool, k_classes> ready, int64_t duration_us, int64_t gap_us = 0) {
    Run r;
    const MonoTime t0 = now;
    while ((now - t0).us < duration_us) {
        std::array<uint16_t, k_classes> head{};
        for (std::size_t c = 0; c < k_classes; ++c) {
            head[c] = ready[c] ? k_frame : 0;
        }
        Class c = Class::Control;
        MonoTime wake;
        if (!s.pick(head, now, c, wake)) {
            LM_CHECK(!wake.is_never()); // never stuck without a timer
            now = wake;
            continue;
        }
        s.charge(c, k_frame, now, true);
        ++r.frames[static_cast<std::size_t>(c)];
        r.airtime[static_cast<std::size_t>(c)] += airtime_us(k_frame);
        now = now + Duration{airtime_us(k_frame) + gap_us};
    }
    r.elapsed_us = (now - t0).us;
    return r;
}

} // namespace

LM_TEST("Q01 DRR: URGENT, NORMAL and BULK share the air 8:4:1 when all are backlogged, none starves") {
    Scheduler s;
    MonoTime now{1'000'000};
    // Idle gaps keep the bucket full: the weights alone decide who goes next.
    Run r = drive(s, now, {false, true, true, true}, 600'000'000, 40'000);
    const auto u = static_cast<double>(r.frames[1]);
    const auto n = static_cast<double>(r.frames[2]);
    const auto b = static_cast<double>(r.frames[3]);
    LM_CHECK(b > 0 && n > 0 && u > 0);
    LM_CHECK(u / b > 7.0 && u / b < 9.0);
    LM_CHECK(n / b > 3.5 && n / b < 4.5);
    LM_CHECK_EQ(s.stats().token_waits, 0u);
}

LM_TEST("Q01 airtime bucket: a saturated link is held to 300 ms/s + burst + the urgent debt; URGENT borrows, BULK cannot") {
    Scheduler s;
    MonoTime now{1'000'000};
    Run r = drive(s, now, {false, true, true, true}, 60'000'000);
    const int64_t air = r.airtime[1] + r.airtime[2] + r.airtime[3];
    const int64_t budget = k_rate_ms_per_s * 1000 * r.elapsed_us / 1'000'000;
    LM_CHECK(air <= budget + k_burst_us + k_urgent_debt_us);
    LM_CHECK(air >= budget * 9 / 10); // and it uses what it is entitled to
    LM_CHECK(s.stats().token_waits > 0);
    LM_CHECK(r.frames[1] > r.frames[2] && r.frames[2] > r.frames[3] && r.frames[3] > 0);
}

LM_TEST("Q01 control reserve: 20 % of every 100 ms window survives an empty bucket and a saturated data flood") {
    Scheduler s;
    MonoTime now{1'000'000};
    for (int i = 0; i < 200; ++i) { // ACK / handshake airtime charged without gating: the bucket is at its floor
        s.charge(Class::Control, 250, now, false);
    }
    LM_CHECK(s.tokens_us(now) <= -static_cast<int64_t>(k_burst_us) + 1);
    Run r = drive(s, now, {true, true, true, true}, 10'000'000);
    const int64_t control = r.airtime[0];
    LM_CHECK(control * 100 >= r.elapsed_us * k_reserve_percent * 9 / 10); // >= 20 % of the time (10 % tolerance)
    LM_CHECK(s.stats().reserve_picks > 0);
    LM_CHECK(r.frames[1] + r.frames[2] + r.frames[3] > 0); // the reserve is not a monopoly
    const int64_t data = r.airtime[1] + r.airtime[2] + r.airtime[3];
    LM_CHECK(data <= k_rate_ms_per_s * 1000 * r.elapsed_us / 1'000'000 + k_urgent_debt_us);
}

LM_TEST("Q01 URGENT yields: after two URGENT frames in a row a ready control frame is served") {
    Scheduler s;
    MonoTime now{1'000'000};
    constexpr uint16_t small = 60; // small frames: the URGENT quantum alone would allow five in a row
    // Use up the window entitlement of CONTROL, so only the yield rule can put control in front.
    for (int i = 0; i < 6; ++i) {
        s.charge(Class::Control, small, now, true);
    }
    unsigned run = 0;
    unsigned longest = 0;
    uint64_t control = 0;
    unsigned urgent = 0;
    for (int i = 0; i < 12; ++i) { // 12 * 3.9 ms: inside the same 100 ms window
        std::array<uint16_t, k_classes> head{small, small, 0, 0};
        Class c = Class::Control;
        MonoTime wake;
        LM_CHECK(s.pick(head, now, c, wake));
        s.charge(c, small, now, true);
        control += c == Class::Control ? 1U : 0U;
        urgent += c == Class::Urgent ? 1U : 0U;
        run = c == Class::Urgent ? run + 1 : 0;
        longest = run > longest ? run : longest;
        now = now + Duration{airtime_us(small)};
    }
    LM_CHECK(control > 0 && urgent > 0);
    LM_CHECK(longest <= k_urgent_run);
    LM_CHECK(s.stats().urgent_yields > 0);
    LM_CHECK_EQ(s.stats().reserve_picks, 0u);
}

LM_TEST("Q01 TX pool: BULK cannot fill the pool, CONTROL and borrowed buffers always find room") {
    TxPool pool;
    constexpr std::size_t n = TxPool::k_frames;
    Handle h[n];
    MacAddr peers[4];
    for (uint8_t i = 0; i < 4; ++i) {
        peers[i].bytes[5] = static_cast<uint8_t>(i + 1);
    }
    std::size_t used = 0;
    auto fill = [&](Class c, std::size_t want_used) {
        for (uint8_t k = 0; used < want_used + 1 && used < n; ++k) {
            TxFrame *f = pool.reserve(h[used], c, peers[k % 4]);
            if (f == nullptr) {
                return;
            }
            f->st = TxFrame::St::Ready;
            ++used;
        }
    };
    fill(Class::Bulk, n);
    LM_CHECK_EQ(used, TxPool::limit(Class::Bulk)); // stops at the BULK share
    LM_CHECK(TxPool::limit(Class::Bulk) < TxPool::limit(Class::Normal));
    fill(Class::Normal, n);
    LM_CHECK_EQ(used, TxPool::limit(Class::Normal));
    fill(Class::Urgent, n);
    LM_CHECK_EQ(used, TxPool::limit(Class::Urgent));
    LM_CHECK(TxPool::limit(Class::Urgent) < TxPool::limit(Class::Control));
    // Every data class is at its limit: control still gets its frame ...
    Handle c;
    LM_CHECK(pool.reserve(c, Class::Control, peers[0]) != nullptr);
    ++used;
    while (pool.reserve(h[used], Class::Control, peers[used % 4]) != nullptr) { // control fills up to its own limit
        ++used;
    }
    LM_CHECK_EQ(used, TxPool::limit(Class::Control));
    LM_CHECK(used < n); // ... and the last slot is never given to a queued frame
    {
        Lease lease{pool}; // the HOP_ACK seal buffer of a node whose queue is as full as it can get
        LM_CHECK(lease.ok());
        LM_CHECK(pool.borrow(h[0]) == nullptr); // then it is really full
    }
    LM_CHECK_EQ(pool.in_use(), used);
}

LM_TEST("Q01 TX pool: one dead next hop cannot pin the pool (per-peer cap), control is exempt") {
    TxPool pool;
    MacAddr dead;
    dead.bytes[5] = 0x66;
    MacAddr live;
    live.bytes[5] = 0x77;
    Handle h;
    std::size_t taken = 0;
    while (pool.reserve(h, Class::Urgent, dead) != nullptr) {
        ++taken;
    }
    LM_CHECK_EQ(taken, TxPool::k_peer_max);
    LM_CHECK(pool.reserve(h, Class::Urgent, live) != nullptr); // another peer still has room
    LM_CHECK(pool.reserve(h, Class::Control, dead) != nullptr);
}

// ---------------------------------------------------------------------------------------------
// S08 (sim): the owner of a node that carries traffic keeps making progress while unjoined devices
// storm it with handshakes. Nothing here is timing evidence: virtual time, no RF, no CPU model.
// ---------------------------------------------------------------------------------------------
namespace {

constexpr unsigned k_storm_devices = 8;

struct StormNet {
    // Node 0: root. Node 1: a member that sends. Nodes 2..: provisioned devices that have not joined.
    StormNet() : net(31), world(WorldOptions{31, 0}) {
        for (unsigned i = 0; i < 2 + k_storm_devices; ++i) {
            NodeOptions o;
            o.role = i == 0 ? Role::Root : (i == 1 ? Role::Relay : Role::Leaf);
            (void)world.add_node(o);
            kits.push_back(i == 0 ? net.make_root() : (i == 1 ? net.make_node(1, 2) : net.make_unjoined(i)));
        }
        world.make_full();
        LM_CHECK_OK(fleet::provision(node(0).store, net, kits[0]));
        LM_CHECK_OK(fleet::provision(node(1).store, net, kits[1]));
        for (unsigned i = 2; i < kits.size(); ++i) {
            sim::ProvisionInput in;
            in.scalar32 = ByteView{kits[i].kit.scalar};
            in.device_cose = ByteView{kits[i].kit.device_cose.data(), kits[i].kit.device_cose.size()};
            in.trust = net.fleet.trust();
            LM_CHECK_OK(sim::provision_store(node(i).store, in));
        }
        for (unsigned i = 0; i < kits.size(); ++i) {
            LM_CHECK_OK(node(static_cast<uint16_t>(i)).boot());
            LM_CHECK_EQ(lm_start(ctx(i)), LM_STATUS_OK);
        }
        run_ms(50);
        eng(0).ledger().set_join_mode(root::JoinMode::Preapproved);
    }
    SimNode &node(unsigned i) { return world.node(static_cast<uint16_t>(i)); }
    lm_context_t *ctx(unsigned i) { return node(i).ctx(); }
    Engine &eng(unsigned i) { return ctx(i)->engine; }
    void run_ms(uint64_t ms) { world.run_until(world.now_us() + ms * 1000); }
    const DeviceId &id(unsigned i) { return kits[i].kit.id; }

    fleet::Network net;
    World world;
    std::vector<fleet::NodeKit> kits;
};

} // namespace

LM_TEST("S08 sim: under a join storm the owner keeps delivering, queues stay bounded, joins are refused or serialised") {
    StormNet n;
    LM_CHECK_OK(n.eng(1).link().connect(n.node(0).radio.mac(), n.node(1).clock.now()));
    n.node(1).notify();
    n.run_ms(2500);
    LM_CHECK(n.eng(1).link().neighbors().find_device(n.id(0)) != nullptr);
    delivery::PathSpec to_root;
    to_root.origin = ShortAddr{2};
    to_root.dest = ShortAddr{1};
    to_root.len = 1;
    to_root.path[0] = 1;
    to_root.term = RootTerm{1};
    to_root.revision = PathRevision{1};
    delivery::PathSpec to_member = to_root;
    to_member.origin = ShortAddr{1};
    to_member.dest = ShortAddr{2};
    to_member.path[0] = 2;
    LM_CHECK_OK(n.eng(1).delivery().install_route(n.id(0), to_root, MonoTime::never()));
    LM_CHECK_OK(n.eng(0).delivery().install_route(n.id(1), to_member, MonoTime::never()));
    const uint64_t t0_us = n.world.now_us();
    for (unsigned i : {0U, 1U}) {
        RootTimeBound b;
        b.term = RootTerm{1};
        b.earliest_ms = b.latest_ms = 1'000'000;
        b.valid = true;
        n.eng(i).set_root_time(b, n.node(i).clock.now());
        n.node(i).notify();
    }
    auto root_ms = [&] { return 1'000'000 + (n.world.now_us() - t0_us) / 1000; };

    // The storm: every unjoined device asks to join at once (none has a grant: the root refuses them
    // after a full credential exchange, the same work as a legitimate join up to the decision).
    for (unsigned i = 2; i < 2 + k_storm_devices; ++i) {
        lm_join_request_t r{};
        r.struct_size = sizeof(r);
        r.abi_version = LM_ABI_VERSION;
        r.request_id.bytes[0] = static_cast<uint8_t>(i);
        r.mode = LM_JOIN_NEW;
        lm_operation_id_t op = 0;
        LM_CHECK_EQ(lm_join(n.ctx(i), &r, &op), LM_STATUS_OK);
        n.node(i).notify();
    }
    // Meanwhile the member keeps sending to the root, one message per 200 ms, each with a deadline.
    constexpr unsigned k_messages = 25;
    std::vector<lm_operation_id_t> ops;
    uint64_t steps0 = n.eng(0).stats().steps;
    std::size_t max_pool = 0;
    for (unsigned m = 0; m < k_messages; ++m) {
        lm_send_request_t rq{};
        rq.struct_size = sizeof(rq);
        rq.abi_version = LM_ABI_VERSION;
        rq.destination.kind = LM_DEST_ROOT_APP;
        rq.app_port = 100;
        rq.delivery = LM_RECEIVED;
        rq.storage = LM_VOLATILE;
        rq.priority = LM_PRIORITY_NORMAL;
        rq.root_term = 1;
        rq.expires_root_ms = root_ms() + 20'000;
        const uint8_t payload[4] = {static_cast<uint8_t>(m), 1, 2, 3};
        lm_operation_id_t op = 0;
        LM_CHECK_EQ(lm_send(n.ctx(1), &rq, payload, sizeof payload, &op), LM_STATUS_OK);
        ops.push_back(op);
        n.node(1).notify();
        for (int ms = 0; ms < 200; ++ms) {
            n.run_ms(1);
            max_pool = std::max({max_pool, n.eng(0).frames().in_use(), n.eng(1).frames().in_use()});
            lm_event_t ev{};
            ev.struct_size = sizeof(ev);
            ev.abi_version = LM_ABI_VERSION;
            uint8_t buf[600];
            size_t req = 0;
            while (lm_next_event(n.ctx(0), &ev, buf, sizeof buf, &req) == LM_STATUS_OK) { // the root application takes its messages
            }
        }
    }
    n.run_ms(15'000);
    unsigned received = 0;
    for (lm_operation_id_t op : ops) {
        lm_operation_t o{};
        o.struct_size = sizeof(o);
        o.abi_version = LM_ABI_VERSION;
        LM_CHECK_EQ(lm_get_operation(n.ctx(1), op, &o), LM_STATUS_OK);
        received += (o.evidence_bits & delivery::ev::end_received) != 0 ? 1U : 0U;
    }
    // (1) the traffic of the members was never starved by the storm ...
    LM_CHECK_EQ(received, k_messages);
    // (2) ... the storm really reached the owner (handshakes started, the single slot refused or
    // rate-limited the rest) ...
    const link::LinkStats &ls = n.eng(0).link().stats();
    std::printf("  [measure] root: hs_started=%llu completed=%llu failed=%llu busy_drop=%llu rate_limited=%llu steps=%llu\n",
                static_cast<unsigned long long>(ls.hs_started), static_cast<unsigned long long>(ls.hs_completed),
                static_cast<unsigned long long>(ls.hs_failed), static_cast<unsigned long long>(ls.hs_busy_drop),
                static_cast<unsigned long long>(ls.hs_rate_limited),
                static_cast<unsigned long long>(n.eng(0).stats().steps - steps0));
    LM_CHECK(ls.hs_started + ls.hs_busy_drop + ls.hs_rate_limited >= k_storm_devices / 2);
    // (3) ... every queue stayed inside its bound, and the owner never spun: steps are events, not a poll.
    LM_CHECK(max_pool <= TxPool::k_frames);
    LM_CHECK(n.eng(0).stats().steps - steps0 < 200'000);
    LM_CHECK(n.eng(0).sched().stats().cls[0].frames > 0); // the handshakes went out as control
}

LM_TEST_MAIN()
