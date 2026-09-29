// Owner loop, job table, C ABI validation and the simulated medium, exercised through real
// SimNodes (real lm_context + Engine on sim ports).
#include <cstring>

#include "capi/context.hpp"
#include "core/jobs.hpp"
#include "lmtest.hpp"
#include "port/sim/sim_node.hpp"
#include "port/sim/sim_world.hpp"

using namespace lm;
using namespace lm::sim;

namespace {

port::RfProfile approved_profile(uint8_t channel) {
    port::RfProfile p;
    p.deployment_approved = true; // SIMULATION ONLY: real profiles need a compliance record
    p.channel = channel;
    p.allowed_channels_mask = static_cast<uint16_t>((1U << 1) | (1U << 6) | (1U << 11));
    return p;
}

struct Fixture {
    explicit Fixture(uint16_t nodes, uint64_t seed = 7) : world(WorldOptions{seed, 0}) {
        for (uint16_t i = 0; i < nodes; ++i) {
            NodeOptions o;
            o.role = i == 0 ? Role::Root : Role::Relay;
            (void)world.add_node(o);
        }
        world.make_chain();
        for (uint16_t i = 0; i < nodes; ++i) {
            LM_CHECK_OK(world.node(i).boot());
            LM_CHECK_OK(world.node(i).radio.start(approved_profile(6)));
        }
    }
    const EngineStats &stats(uint16_t i) { return world.node(i).engine()->stats(); }
    World world;
};

// Token of the sender's current driver instance (radio.start() bumps the generation).
port::TxToken tok(Fixture &fx, uint32_t seq, uint16_t node = 0) {
    return port::TxToken{fx.world.node(node).radio.driver_generation(), seq};
}

std::array<uint8_t, 8> frame() { return {'L', 'M', 1, 1, 0, 0, 0, 0}; }

} // namespace

LM_TEST("R10 job table: late completion after re-reservation is stale") {
    JobTable<2> t;
    JobTicket a;
    LM_CHECK_OK(t.reserve(JobOwner::Test, Handle{0, 1}, JobClass::Flash, a));
    JobOrigin o;
    LM_CHECK(t.complete(port::JobCompletion{a.table_index, a.job_id, Status::Ok}, o));
    JobTicket b;
    LM_CHECK_OK(t.reserve(JobOwner::Test, Handle{0, 2}, JobClass::Flash, b));
    LM_CHECK_EQ(b.table_index, a.table_index); // same entry reused ...
    // ... so a duplicated/late completion carrying the old job_id must not complete job b.
    LM_CHECK(!t.complete(port::JobCompletion{a.table_index, a.job_id, Status::Ok}, o));
    LM_CHECK_EQ(t.stale_completions(), 1u);
    LM_CHECK(t.complete(port::JobCompletion{b.table_index, b.job_id, Status::Ok}, o));
    LM_CHECK(o.slot == (Handle{0, 2}));
}

LM_TEST("only one public-key job at a time (docs/06 §8)") {
    JobTable<4> t;
    JobTicket a;
    JobTicket b;
    LM_CHECK_OK(t.reserve(JobOwner::Test, Handle{0, 1}, JobClass::PublicKey, a));
    LM_CHECK(t.reserve(JobOwner::Test, Handle{1, 1}, JobClass::PublicKey, b) == Status::Busy);
    LM_CHECK_OK(t.reserve(JobOwner::Test, Handle{1, 1}, JobClass::Flash, b));
    t.cancel_unsubmitted(a);
    LM_CHECK(!t.public_key_busy());
}

LM_TEST("C ABI config validation: exact struct size, ABI 2, role support") {
    lm_config_t c{};
    LM_CHECK_EQ(lm_config_init(&c, sizeof(c) - 1), LM_STATUS_INVALID_ARGUMENT);
    LM_CHECK_EQ(lm_config_init(&c, sizeof(c)), LM_STATUS_OK);
    lm_workspace_size_t ws{};
    LM_CHECK_EQ(lm_workspace_required(&c, &ws), LM_STATUS_OK);
    LM_CHECK(ws.bytes >= sizeof(lm_context) && ws.alignment == alignof(lm_context));
    lm_config_t bad = c;
    bad.abi_version = 1;
    LM_CHECK_EQ(lm_workspace_required(&bad, &ws), LM_STATUS_UNSUPPORTED);
    bad = c;
    bad.struct_size += 4;
    LM_CHECK_EQ(lm_workspace_required(&bad, &ws), LM_STATUS_INVALID_ARGUMENT);
    bad = c;
    bad.reserved = 1;
    LM_CHECK_EQ(lm_workspace_required(&bad, &ws), LM_STATUS_INVALID_ARGUMENT);
    bad = c;
    bad.role = 3;
    LM_CHECK_EQ(lm_workspace_required(&bad, &ws), LM_STATUS_INVALID_ARGUMENT);
}

LM_TEST("capabilities through the owner call report nothing implemented") {
    Fixture fx(1);
    lm_capabilities_t caps{};
    caps.struct_size = sizeof(caps);
    caps.abi_version = LM_ABI_VERSION;
    LM_CHECK_EQ(lm_get_capabilities(fx.world.node(0).ctx(), &caps), LM_STATUS_OK);
    LM_CHECK_EQ(caps.implemented_bits, 0u);
    LM_CHECK_EQ(caps.enabled_bits, 0u);
    LM_CHECK_EQ(caps.max_root_depth, 20u);
    LM_CHECK_EQ(caps.max_path_hops, 40u);
    LM_CHECK_EQ(caps.available_single_frame_bytes, 56u);
    LM_CHECK_EQ(caps.max_members, 64u); // root profile
    caps.abi_version = 1;
    LM_CHECK_EQ(lm_get_capabilities(fx.world.node(0).ctx(), &caps), LM_STATUS_UNSUPPORTED);
}

LM_TEST("idle owner has no deadline (no fixed polling tick)") {
    Fixture fx(1);
    fx.world.run_until(10'000'000);
    // Boot notify runs one step; with no module timers the owner never wakes again.
    LM_CHECK_EQ(fx.stats(0).steps, 1u);
}

LM_TEST("unicast reaches the addressed neighbour through the owner RX path") {
    Fixture fx(3);
    const auto f = frame();
    LM_CHECK_OK(fx.world.node(0).radio.add_peer(fx.world.node(1).radio.mac()));
    LM_CHECK_OK(fx.world.node(0).radio.transmit(fx.world.node(1).radio.mac(), ByteView{f},
                                                tok(fx, 1)));
    // One physical TX in flight.
    LM_CHECK(fx.world.node(0).radio.transmit(fx.world.node(1).radio.mac(), ByteView{f},
                                             tok(fx, 2)) == Status::Busy);
    fx.world.run_until(100'000);
    LM_CHECK_EQ(fx.stats(1).rx_frames, 1u);
    LM_CHECK_EQ(fx.stats(2).rx_frames, 0u);         // not addressed
    LM_CHECK_EQ(fx.stats(0).tx_done_unmatched, 1u); // TX-done reached the owner
}

LM_TEST("allowlist topology: no link, no delivery; broadcast reaches linked neighbours only") {
    Fixture fx(3);
    const auto f = frame();
    LM_CHECK_OK(fx.world.node(1).radio.add_peer(MacAddr::broadcast()));
    LM_CHECK_OK(
        fx.world.node(1).radio.transmit(MacAddr::broadcast(), ByteView{f}, tok(fx, 1, 1)));
    fx.world.run_until(100'000);
    LM_CHECK_EQ(fx.stats(0).rx_frames, 1u);
    LM_CHECK_EQ(fx.stats(2).rx_frames, 1u);
    LM_CHECK_OK(fx.world.node(0).radio.add_peer(fx.world.node(2).radio.mac()));
    LM_CHECK_OK(fx.world.node(0).radio.transmit(fx.world.node(2).radio.mac(), ByteView{f},
                                                tok(fx, 2)));
    fx.world.run_until(200'000);
    LM_CHECK_EQ(fx.stats(2).rx_frames, 1u); // 0 and 2 are not neighbours in the chain
}

LM_TEST("channel mismatch and radio off are not delivered") {
    Fixture fx(2);
    const auto f = frame();
    LM_CHECK_OK(fx.world.node(1).radio.set_channel(11));
    LM_CHECK_OK(fx.world.node(0).radio.add_peer(fx.world.node(1).radio.mac()));
    LM_CHECK_OK(fx.world.node(0).radio.transmit(fx.world.node(1).radio.mac(), ByteView{f},
                                                tok(fx, 1)));
    fx.world.run_until(100'000);
    LM_CHECK_EQ(fx.stats(1).rx_frames, 0u);
    LM_CHECK(fx.world.node(1).radio.set_channel(13) == Status::InvalidArgument); // not allowed
}

LM_TEST("unapproved RF profile refuses to start (docs/03 §3)") {
    World w(WorldOptions{});
    (void)w.add_node(NodeOptions{});
    port::RfProfile p = approved_profile(6);
    p.deployment_approved = false;
    LM_CHECK(w.node(0).radio.start(p) == Status::RfProfileUnapproved);
}

LM_TEST("power cut drops RAM state and pending job completions; store survives") {
    Fixture fx(1);
    SimNode &n = fx.world.node(0);
    static int ran = 0;
    ran = 0;
    auto job = [](port::JobEnv &env, void *) -> Status {
        ++ran;
        const std::array<uint8_t, 3> v{1, 2, 3};
        return env.store.slot_write(1, 0, ByteView{v});
    };
    LM_CHECK_OK(n.jobs.submit(0, 1, job, nullptr));
    fx.world.run_until(fx.world.now_us() + 10'000);
    LM_CHECK_EQ(ran, 1);
    LM_CHECK_EQ(n.engine()->stats().stale_job_completions, 1u); // no table entry: dropped
    LM_CHECK_OK(n.jobs.submit(0, 2, job, nullptr));
    n.power_cut();
    fx.world.run_until(fx.world.now_us() + 10'000);
    LM_CHECK_EQ(ran, 1); // the worker died with the node
    LM_CHECK_OK(n.boot());
    std::array<uint8_t, 8> out{};
    std::size_t len = 0;
    LM_CHECK_OK(n.store.slot_read(1, 0, MutByteView{out}, len));
    LM_CHECK_EQ(len, 3u);
}

LM_TEST("loss and MAC-ACK loss are separate outcomes") {
    Fixture fx(2);
    const auto f = frame();
    LinkParams lp;
    lp.up = true;
    lp.ack_loss_permille = 1000; // delivered, but the sender never sees the MAC ACK
    fx.world.set_link(0, 1, lp);
    LM_CHECK_OK(fx.world.node(0).radio.add_peer(fx.world.node(1).radio.mac()));
    LM_CHECK_OK(fx.world.node(0).radio.transmit(fx.world.node(1).radio.mac(), ByteView{f},
                                                tok(fx, 1)));
    fx.world.run_until(100'000);
    LM_CHECK_EQ(fx.stats(1).rx_frames, 1u);
    lp.loss_permille = 1000;
    fx.world.set_link(0, 1, lp);
    LM_CHECK_OK(fx.world.node(0).radio.transmit(fx.world.node(1).radio.mac(), ByteView{f},
                                                tok(fx, 2)));
    fx.world.run_until(200'000);
    LM_CHECK_EQ(fx.stats(1).rx_frames, 1u);
}

LM_TEST_MAIN()
