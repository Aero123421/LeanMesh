// DIAG slice (S19, T19): diagnostics snapshot with validity bits, capability rows and the no-polling rule, on
// real SimNodes (real Engine over sim ports). Sim evidence only: the simulator has no heap, stacks, CPU time,
// RSSI or energy, so those stay UNKNOWN here, which is the point of the first test. Nothing measures a device.
#include <array>
#include <cstring>

#include "capi/context.hpp"
#include "core/diag/diag.hpp"
#include "lmtest.hpp"
#include "port/sim/sim_node.hpp"
#include "port/sim/sim_world.hpp"

using namespace lm;
using namespace lm::sim;

namespace {

struct Net {
    explicit Net(uint16_t nodes, bool health = true) : world(WorldOptions{19, 0}) {
        for (uint16_t i = 0; i < nodes; ++i) {
            NodeOptions o;
            o.role = i == 0 ? Role::Root : Role::Relay;
            o.health_port = health;
            (void)world.add_node(o);
        }
        world.make_chain();
        for (uint16_t i = 0; i < nodes; ++i) {
            LM_CHECK_OK(world.node(i).boot());
            LM_CHECK_EQ(lm_start(world.node(i).ctx()), LM_STATUS_OK);
        }
        run_ms(10);
    }
    void run_ms(uint64_t ms) { world.run_until(world.now_us() + ms * 1000); }
    lm_context_t *ctx(uint16_t i) { return world.node(i).ctx(); }
    Engine &eng(uint16_t i) { return ctx(i)->engine; }
    MacAddr mac(uint16_t i) { return world.node(i).radio.mac(); }
    Status raw(uint16_t from, uint16_t to, uint32_t tag) {
        PeerHandle h;
        LM_TRY(eng(from).peers().acquire(world.node(from).radio, mac(to), PeerClass::Regular, h));
        const std::array<uint8_t, 8> f{'L', 'M', 1, 1, 0, 0, 0, static_cast<uint8_t>(tag)};
        const Status s = eng(from).transmit(mac(to), ByteView{f}, tag, world.node(from).clock.now());
        world.node(from).notify();
        return s;
    }
    lm_diagnostics_t diag(uint16_t i) {
        lm_diagnostics_t d{};
        d.struct_size = sizeof(d);
        d.abi_version = LM_ABI_VERSION;
        LM_CHECK_EQ(lm_diagnostics_get(ctx(i), &d), LM_STATUS_OK);
        return d;
    }
    World world;
};

bool has(const lm_diagnostics_t &d, uint64_t bit) { return (d.validity_bits & bit) != 0; }

} // namespace

LM_TEST("T19 diagnostics: a value the build cannot know is unknown (bit clear, zero), never a measured 0") {
    Net net(2);
    const lm_diagnostics_t d = net.diag(1);
    // What the sim knows: a boot cause and its callback ring. What it does not: heap, stacks, CPU, RSSI, energy.
    LM_CHECK(has(d, diag::valid::reset_reason));
    LM_CHECK(has(d, diag::valid::rx_ring));
    LM_CHECK(!has(d, diag::valid::heap));
    LM_CHECK(!has(d, diag::valid::stack));
    LM_CHECK(!has(d, diag::valid::owner_cpu));
    LM_CHECK_EQ(d.min_heap_bytes, 0u);
    LM_CHECK_EQ(d.stack_free_bytes, 0u);
    LM_CHECK_EQ(d.owner_cpu_us, 0u);
    // A relay that never joined has no root term and no channel module: those are unknown as well.
    LM_CHECK(!has(d, diag::valid::root_term));
    LM_CHECK(!has(d, diag::valid::channel));
    // A platform that has the sensors fills them, and only then the bits appear.
    net.world.node(1).health.extra.heap_valid = true;
    net.world.node(1).health.extra.min_heap_bytes = 52'000;
    const lm_diagnostics_t d2 = net.diag(1);
    LM_CHECK(has(d2, diag::valid::heap));
    LM_CHECK_EQ(d2.min_heap_bytes, 52'000u);
    LM_CHECK(!has(d2, diag::valid::stack));
    // No Health port at all (a build without one): the whole driver group is unknown, the SDK group still is not.
    Net bare(1, false);
    const lm_diagnostics_t b = bare.diag(0);
    LM_CHECK_EQ(b.validity_bits & 0xFFFFULL, 0ULL);
    LM_CHECK(has(b, diag::valid::counters));
    LM_CHECK(has(b, diag::valid::peers));
    LM_CHECK(has(b, diag::valid::interval)); // started: the span of the counters is known
    // Driver and SDK facts live in separate bit ranges.
    LM_CHECK((d.validity_bits & 0xFFFF0000ULL) != 0);
    LM_CHECK((d.validity_bits >> 32) == 0); // FIX7-D12: the app bits have no field in the C struct
}

LM_TEST("ISSUE19-3 diagnostics: recovery facts are known only with a valid port reading") {
    Net net(1);
    auto &facts = net.world.node(0).health.extra;
    facts.radio_recovery_valid = true;
    facts.radio_recovery_reason = 256;
    facts.radio_recovery_attempts = 2;
    diag::Snapshot snap;
    Command cmd;
    cmd.kind = CommandKind::DiagnosticsSnapshot;
    cmd.response = &snap;
    cmd.response_size = sizeof snap;
    LM_CHECK_OK(net.eng(0).execute(cmd, net.world.node(0).clock.now()).status);
    LM_CHECK_EQ(snap.radio_recovery_reason, 256u);
    LM_CHECK_EQ(snap.radio_recovery_attempts, 2u);
    LM_CHECK_EQ(net.diag(0).validity_bits & (diag::valid::radio_recovery), 0u); // ABI has no field
    facts.radio_recovery_valid = false;
    LM_CHECK_OK(net.eng(0).execute(cmd, net.world.node(0).clock.now()).status);
    LM_CHECK_EQ(snap.validity & (diag::valid::radio_recovery), 0u);
}

LM_TEST("T19 diagnostics: local shortage (BUSY) is not RF loss; a MAC failure is, and only that") {
    Net net(2);
    // One TX in flight: the second frame is refused by the driver slot, a local condition.
    LM_CHECK_OK(net.raw(0, 1, 1));
    LM_CHECK(net.raw(0, 1, 2) == Status::Busy);
    net.run_ms(50);
    lm_diagnostics_t d = net.diag(0);
    LM_CHECK_EQ(d.tx_frames, 1u);
    LM_CHECK_EQ(d.local_busy, 1u);
    LM_CHECK_EQ(d.rf_failures, 0u);
    LM_CHECK_EQ(net.diag(1).rx_frames, 1u);
    // The receiver never acknowledges at the MAC level: MacFailed is the one RF-loss sample.
    LinkParams p;
    p.up = true;
    p.ack_loss_permille = 1000;
    net.world.set_link(0, 1, p);
    LM_CHECK_OK(net.raw(0, 1, 3));
    net.run_ms(50);
    d = net.diag(0);
    LM_CHECK_EQ(d.rf_failures, 1u);
    LM_CHECK_EQ(d.local_busy, 1u);
    LM_CHECK_EQ(d.tx_frames, 2u);
    LM_CHECK(d.regular_peers >= 1);
    LM_CHECK(d.interval_us >= 100'000ULL);
}

LM_TEST("T19 diagnostics: ABI checks of the caller's struct; a query consumes and changes nothing") {
    Net net(1);
    lm_diagnostics_t d{};
    d.abi_version = LM_ABI_VERSION;
    LM_CHECK_EQ(lm_diagnostics_get(net.ctx(0), &d), LM_STATUS_INVALID_ARGUMENT); // struct_size 0 (D9)
    d.struct_size = sizeof(d);
    d.abi_version = LM_ABI_VERSION + 1;
    LM_CHECK_EQ(lm_diagnostics_get(net.ctx(0), &d), LM_STATUS_UNSUPPORTED);
    LM_CHECK_EQ(lm_diagnostics_get(net.ctx(0), nullptr), LM_STATUS_INVALID_ARGUMENT);
    d.abi_version = LM_ABI_VERSION;
    const uint64_t frames = net.eng(0).stats().rx_frames;
    LM_CHECK_EQ(lm_diagnostics_get(net.ctx(0), &d), LM_STATUS_OK);
    LM_CHECK_EQ(d.struct_size, sizeof(d));
    LM_CHECK_EQ(net.eng(0).stats().rx_frames, frames);
    lm_event_t ev{};
    ev.struct_size = sizeof(ev);
    ev.abi_version = LM_ABI_VERSION;
    size_t need = 0;
    uint8_t buf[600];
    (void)lm_next_event(net.ctx(0), &ev, buf, sizeof buf, &need); // drain the STARTED event
    const lm_diagnostics_t d2 = net.diag(0);
    // FIX7-D12: the C struct has no event/operation fields, so it claims no such validity bit (the Host map has them)
    LM_CHECK(!has(d2, diag::valid::events));
    LM_CHECK(!has(d2, diag::valid::operations));
    LM_CHECK_EQ(d2.validity_bits & ~diag::valid::abi_bits, 0ULL);
    LM_CHECK_EQ(d2.reserved, 0);
}

LM_TEST("ME05 sim: diagnostics never poll - no query, no wake; a query costs at most one owner step and arms no timer") {
    Net net(2);
    for (uint16_t i = 0; i < 2; ++i) {
        LM_CHECK(net.eng(i).step(net.world.node(i).clock.now()).is_never());
    }
    const uint64_t s0 = net.eng(0).stats().steps;
    const uint64_t s1 = net.eng(1).stats().steps;
    const uint64_t reads0 = net.world.node(0).health.reads;
    net.run_ms(3'600'000); // an hour of idle: no diagnostics timer exists
    LM_CHECK_EQ(net.eng(0).stats().steps, s0);
    LM_CHECK_EQ(net.eng(1).stats().steps, s1);
    LM_CHECK_EQ(net.world.node(0).health.reads, reads0); // the port is read only for a request
    for (int i = 0; i < 100; ++i) {
        (void)net.diag(0);
    }
    net.run_ms(100);
    LM_CHECK(net.eng(0).stats().steps - s0 <= 100); // the command notify, once per query, nothing more
    LM_CHECK_EQ(net.world.node(0).health.reads, reads0 + 100);
    LM_CHECK(net.eng(0).step(net.world.node(0).clock.now()).is_never()); // no deadline was armed by the queries
    const uint64_t after = net.eng(0).stats().steps;
    net.run_ms(3'600'000);
    LM_CHECK_EQ(net.eng(0).stats().steps, after); // and an hour later the owner still has not woken by itself
    LM_CHECK_EQ(net.eng(1).stats().steps, s1);    // the other node was never involved
}

LM_TEST("T19 capabilities: build, implemented, qualified and enabled are separate facts; nothing is claimed qualified") {
    Net net(1);
    lm_capabilities_t c{};
    c.struct_size = sizeof(c);
    c.abi_version = LM_ABI_VERSION;
    LM_CHECK_EQ(lm_get_capabilities(net.ctx(0), &c), LM_STATUS_OK);
    LM_CHECK_EQ(c.qualified_bits, 0ULL); // no hardware evidence exists (docs/18 §6)
    LM_CHECK((c.build_bits & LM_FEATURE_SMALL_MESSAGE) != 0);
    LM_CHECK((c.enabled_bits & ~c.implemented_bits) == 0); // nothing is enabled that is not implemented
    LM_CHECK((c.implemented_bits & ~c.build_bits) == 0);   // nothing is implemented that is not built
    LM_CHECK((c.implemented_bits & LM_FEATURE_RTC_SECURE_RESUME_RESERVED) == 0); // reserved: stays false
    LM_CHECK((c.enabled_bits & LM_FEATURE_RTC_SECURE_RESUME_RESERVED) == 0);
    // The object lane is compiled into the bench but the node's config leaves it off: built, not enabled.
    LM_CHECK((c.build_bits & LM_FEATURE_OBJECT_4K) != 0);
    LM_CHECK((c.enabled_bits & LM_FEATURE_OBJECT_4K) == 0);
    LM_CHECK_EQ(c.max_object_bytes, 0u);
    std::array<diag::Feature, diag::k_max_features> rows{};
    const std::size_t n = diag::features(c, rows);
    LM_CHECK_EQ(n, 12u);
    for (std::size_t i = 0; i < n; ++i) {
        LM_CHECK(!rows[i].qualified);
        LM_CHECK(!rows[i].enabled || rows[i].implemented);
    }
    // OTA has no ABI bit; its row is never implemented as a whole feature and never enabled in this release.
    LM_CHECK(std::strcmp(rows[n - 1].name, "OTA") == 0);
    LM_CHECK(!rows[n - 1].implemented && !rows[n - 1].enabled);
    LM_CHECK(rows[n - 1].note != nullptr);
    // A node without a sleep port cannot claim the power modes (S16): built and implemented, not enabled.
    NodeOptions o;
    o.power_port = false;
    World w(WorldOptions{20, 0});
    (void)w.add_node(o);
    LM_CHECK_OK(w.node(0).boot());
    lm_capabilities_t c2{};
    c2.struct_size = sizeof(c2);
    c2.abi_version = LM_ABI_VERSION;
    LM_CHECK_EQ(lm_get_capabilities(w.node(0).ctx(), &c2), LM_STATUS_OK);
    LM_CHECK((c2.implemented_bits & LM_FEATURE_POWER_WINDOWED_RX) != 0);
    LM_CHECK((c2.enabled_bits & LM_FEATURE_POWER_WINDOWED_RX) == 0);
}

LM_TEST_MAIN()
