// Radio ownership on the mesh owner: peer registry (16+3+1), single-TX manager with watchdog and
// driver generations, lm_start/lm_stop, and the idle/yield behaviour of Engine::step. Every test
// drives real SimNodes (real Engine + sim radio/medium); nothing is mocked. Sim evidence only:
// the medium has no RF model (AGENTS.md), so nothing here replaces hardware D10/R08/ME05.
#include <array>
#include <cstring>

#include "capi/context.hpp"
#include "lmtest.hpp"
#include "port/sim/sim_node.hpp"
#include "port/sim/sim_world.hpp"

using namespace lm;
using namespace lm::sim;

namespace {

struct Fixture {
    explicit Fixture(uint16_t nodes, uint64_t seed = 11) : world(WorldOptions{seed, 0}) {
        for (uint16_t i = 0; i < nodes; ++i) {
            NodeOptions o;
            o.role = i == 0 ? Role::Root : Role::Relay;
            (void)world.add_node(o);
        }
        world.make_chain();
        for (uint16_t i = 0; i < nodes; ++i) {
            LM_CHECK_OK(world.node(i).boot());
            LM_CHECK_EQ(lm_start(world.node(i).ctx()), LM_STATUS_OK);
        }
        settle();
    }
    void settle() { world.run_until(world.now_us() + 10'000); }
    void run_ms(uint64_t ms) { world.run_until(world.now_us() + ms * 1000); }
    Engine &eng(uint16_t i) { return world.node(i).ctx()->engine; }
    SimRadio &radio(uint16_t i) { return world.node(i).radio; }
    MonoTime now(uint16_t i) { return world.node(i).clock.now(); }
    MacAddr mac(uint16_t i) { return world.node(i).radio.mac(); }
    // Registers node j as a regular peer of node i and sends one frame to it.
    Status send(uint16_t i, uint16_t j, uint32_t tag) {
        PeerHandle h;
        LM_TRY(eng(i).peers().acquire(radio(i), mac(j), PeerClass::Regular, h));
        const std::array<uint8_t, 8> f{'L', 'M', 1, 1, 0, 0, 0, static_cast<uint8_t>(tag)};
        const Status s = eng(i).transmit(mac(j), ByteView{f}, tag, now(i));
        world.node(i).notify();
        return s;
    }
    World world;
};

MacAddr fake_mac(uint32_t n) {
    return MacAddr{{0x02, 0xEE, 0, 0, static_cast<uint8_t>(n >> 8U), static_cast<uint8_t>(n)}};
}

} // namespace

// ---- R08 (sim): peer capacity, class isolation, churn --------------------------------------------

LM_TEST("R08 sim: 16 regular + 3 transient + broadcast; full is explicit; classes never borrow") {
    Fixture fx(1);
    Engine &e = fx.eng(0);
    SimRadio &r = fx.radio(0);
    LM_CHECK_EQ(r.peer_count(), 1u); // broadcast, registered by the owner on start
    std::array<PeerHandle, 16> reg{};
    std::array<PeerHandle, 3> trn{};
    for (uint32_t i = 0; i < 16; ++i) {
        LM_CHECK_OK(e.peers().acquire(r, fake_mac(i), PeerClass::Regular, reg[i]));
    }
    PeerHandle extra;
    LM_CHECK(e.peers().acquire(r, fake_mac(100), PeerClass::Regular, extra) == Status::NoCapacity);
    // Regular full does not block a transient (Join/repair) reservation ...
    for (uint32_t i = 0; i < 3; ++i) {
        LM_CHECK_OK(e.peers().acquire(r, fake_mac(200 + i), PeerClass::Transient, trn[i]));
    }
    LM_CHECK(e.peers().acquire(r, fake_mac(300), PeerClass::Transient, extra) == Status::NoCapacity);
    LM_CHECK_EQ(r.peer_count(), 20u); // == driver maximum
    LM_CHECK(r.add_peer(fake_mac(400)) == Status::NoCapacity); // the driver refuses a 21st
    // Idempotent for the same class, Conflict across classes, broadcast is never leased.
    PeerHandle again;
    LM_CHECK_OK(e.peers().acquire(r, fake_mac(3), PeerClass::Regular, again));
    LM_CHECK(again.slot == reg[3].slot);
    LM_CHECK(e.peers().acquire(r, fake_mac(3), PeerClass::Transient, again) == Status::Conflict);
    LM_CHECK(e.peers().acquire(r, MacAddr::broadcast(), PeerClass::Regular, again) ==
             Status::InvalidArgument);
    // Handoff transient -> regular needs a free regular slot; the reservation survives NoCapacity.
    PeerHandle promoted;
    LM_CHECK(e.peers().promote(trn[0], promoted) == Status::NoCapacity);
    LM_CHECK(e.peers().valid(trn[0]));
    LM_CHECK_OK(e.peers().release(r, reg[5]));
    LM_CHECK_OK(e.peers().promote(trn[0], promoted));
    LM_CHECK(!e.peers().valid(trn[0]));
    LM_CHECK(e.peers().valid(promoted));
    LM_CHECK_EQ(r.peer_count(), 19u); // promotion moved the reservation, not the driver entry
    LM_CHECK_EQ(e.peers().regular_count(), 16u);
    LM_CHECK_EQ(e.peers().transient_count(), 2u);
}

LM_TEST("R08 sim: 100 churn cycles with delayed releases leak nothing; stale handles are inert") {
    Fixture fx(1, 5);
    Engine &e = fx.eng(0);
    SimRadio &r = fx.radio(0);
    // A window of live leases released late (FIFO), so slots are reused while old handles exist.
    std::array<PeerHandle, 24> live{};
    std::size_t head = 0;
    std::size_t count = 0;
    std::size_t full_seen = 0;
    std::array<PeerHandle, 100> retired{};
    std::size_t retired_n = 0;
    for (uint32_t cycle = 0; cycle < 100; ++cycle) {
        const PeerClass cls = cycle % 4 == 3 ? PeerClass::Transient : PeerClass::Regular;
        PeerHandle h;
        const Status s = e.peers().acquire(r, fake_mac(1000 + cycle), cls, h);
        if (s == Status::NoCapacity) {
            ++full_seen; // full is reported, never a silent success
            LM_CHECK(count > 0);
        } else {
            LM_CHECK_OK(s);
            live[(head + count) % live.size()] = h;
            ++count;
        }
        if (count >= 22 || s == Status::NoCapacity) { // late release, oldest first
            LM_CHECK_OK(e.peers().release(r, live[head]));
            retired[retired_n++] = live[head];
            head = (head + 1) % live.size();
            --count;
        }
        LM_CHECK(e.peers().regular_count() <= 16 && e.peers().transient_count() <= 3);
        LM_CHECK_EQ(r.peer_count(), 1 + e.peers().regular_count() + e.peers().transient_count());
    }
    LM_CHECK(r.peak_peer_count() <= 20);
    LM_CHECK(full_seen > 0); // the churn does reach the limit
    // Double release of an old handle after its slot was reused is refused.
    for (std::size_t i = 0; i < retired_n; ++i) {
        LM_CHECK(e.peers().release(r, retired[i]) == Status::NotFound);
    }
    while (count > 0) {
        LM_CHECK_OK(e.peers().release(r, live[head]));
        head = (head + 1) % live.size();
        --count;
    }
    LM_CHECK_EQ(e.peers().regular_count() + e.peers().transient_count(), 0u);
    LM_CHECK_EQ(r.peer_count(), 1u); // only broadcast: no leaked reservation
}

// ---- D10 (sim): TX callback delay ------------------------------------------------------------------

LM_TEST("D10 sim: callback delay 20/100/500 ms: RX before TX-done, credit to the right frame") {
    for (const uint32_t delay_ms : {20U, 100U, 500U}) {
        Fixture fx(2);
        fx.radio(0).tx_callback_delay_us = delay_ms * 1000;
        LM_CHECK_OK(fx.send(0, 1, 7));
        // While the callback is outstanding the physical TX slot is taken: local Busy, no loss.
        LM_CHECK(fx.send(0, 1, 8) == Status::Busy);
        fx.run_ms(delay_ms / 2); // frame reached node 1, TX-done callback still pending
        LM_CHECK_EQ(fx.eng(1).stats().rx_frames, 1u);
        LM_CHECK(fx.eng(0).tx().in_flight());
        fx.run_ms(delay_ms);
        LM_CHECK(!fx.eng(0).tx().in_flight());
        LM_CHECK_EQ(fx.eng(0).tx().last_outcome().tag, 7u);
        LM_CHECK(fx.eng(0).tx().last_outcome().result == port::TxResult::MacAcked);
        LM_CHECK_OK(fx.send(0, 1, 9)); // the next frame gets its own token and its own outcome
        fx.run_ms(delay_ms + 20);
        LM_CHECK_EQ(fx.eng(0).tx().last_outcome().tag, 9u);
        const TxStats &t = fx.eng(0).tx().stats();
        LM_CHECK_EQ(t.started, 2u);
        LM_CHECK_EQ(t.mac_acked, 2u);
        LM_CHECK_EQ(t.rf_failed, 0u);
        LM_CHECK_EQ(t.local_refused, 1u); // the Busy above, kept apart from RF failures
        LM_CHECK_EQ(t.unmatched, 0u);
    }
}

LM_TEST("HIL-F11: a completion at 1.05 s is a normal outcome: no UNKNOWN, no radio restart") {
    // ESP-IDF delivered the slow LR completions at 1.02-1.06 s; a 1000 ms watchdog turned each into a radio restart.
    Fixture fx(2);
    fx.radio(0).tx_callback_delay_us = 1'060'000;
    const uint32_t gen_before = fx.radio(0).driver_generation();
    LM_CHECK_OK(fx.send(0, 1, 1));
    fx.run_ms(1100);
    const TxStats &t = fx.eng(0).tx().stats();
    LM_CHECK_EQ(t.unknown, 0u);
    LM_CHECK_EQ(t.mac_acked, 1u);
    LM_CHECK_EQ(fx.eng(0).tx().last_outcome().tag, 1u);
    LM_CHECK_EQ(fx.eng(0).stats().radio_restarts, 0u);
    LM_CHECK_EQ(fx.radio(0).driver_generation(), gen_before);
}

LM_TEST("D10 sim: callback later than the 3000 ms watchdog is never credited to the next frame") {
    Fixture fx(2);
    fx.radio(0).tx_callback_delay_us = 3'500'000;
    const uint32_t gen_before = fx.radio(0).driver_generation();
    LM_CHECK_OK(fx.send(0, 1, 1));
    fx.run_ms(3010); // watchdog fired at 3000 ms
    const TxStats &t = fx.eng(0).tx().stats();
    LM_CHECK_EQ(t.unknown, 1u);
    LM_CHECK_EQ(t.rf_failed, 0u); // unknown is neither success nor an RF-loss sample
    LM_CHECK(fx.eng(0).tx().last_outcome().result == port::TxResult::Unknown);
    LM_CHECK_EQ(fx.eng(0).stats().radio_restarts, 1u);
    LM_CHECK(fx.radio(0).driver_generation() != gen_before); // new driver instance
    LM_CHECK(fx.eng(0).radio_state() == RadioState::Running);
    LM_CHECK(!fx.eng(0).tx().isolated());
    LM_CHECK_EQ(fx.radio(0).peer_count(), 2u); // broadcast + the leased regular peer, re-registered
    fx.radio(0).tx_callback_delay_us = 800'000; // frame 2 completes in time, but after the old one
    LM_CHECK_OK(fx.send(0, 1, 2));
    fx.run_ms(600);                            // now ~3610 ms: the OLD callback (3500 ms) arrived
    LM_CHECK(fx.eng(0).tx().in_flight());      // frame 2 still waits for its own callback
    LM_CHECK_EQ(t.mac_acked, 0u);
    LM_CHECK_EQ(fx.eng(0).stats().tx_done_unmatched, 1u);
    fx.run_ms(400); // frame 2's own callback (~3810 ms)
    LM_CHECK_EQ(fx.eng(0).tx().last_outcome().tag, 2u);
    LM_CHECK(fx.eng(0).tx().last_outcome().result == port::TxResult::MacAcked);
    LM_CHECK_EQ(t.mac_acked, 1u);
}

LM_TEST("D10 sim: failed radio re-init isolates TX, retries with backoff, then FAULT; restart heals") {
    Fixture fx(2);
    fx.radio(0).tx_callback_delay_us = 7'000'000; // the result never arrives in time
    fx.radio(0).start_fault_count = 3;            // and the driver cannot be re-initialised
    LM_CHECK_OK(fx.send(0, 1, 1));
    fx.run_ms(3010);
    LM_CHECK(fx.eng(0).radio_state() == RadioState::Recovering);
    LM_CHECK(fx.send(0, 1, 2) == Status::DriverResultUnknown); // isolated, not "loss"
    LM_CHECK_EQ(fx.eng(0).tx().stats().rf_failed, 0u);
    fx.run_ms(2100); // attempts at +0, +1 s, +2 s
    LM_CHECK(fx.eng(0).radio_state() == RadioState::Faulted);
    LM_CHECK_EQ(fx.eng(0).stats().radio_faults, 1u);
    lm_event_t ev{};
    ev.struct_size = sizeof(ev);
    ev.abi_version = LM_ABI_VERSION;
    LM_CHECK_EQ(lm_next_event(fx.world.node(0).ctx(), &ev, nullptr, 0, nullptr), LM_STATUS_OK);
    LM_CHECK_EQ(ev.kind, LM_EVENT_STARTED); // from the initial start
    ev = lm_event_t{};
    ev.struct_size = sizeof(ev);
    ev.abi_version = LM_ABI_VERSION;
    LM_CHECK_EQ(lm_next_event(fx.world.node(0).ctx(), &ev, nullptr, 0, nullptr), LM_STATUS_OK);
    LM_CHECK_EQ(ev.kind, LM_EVENT_FAULT);
    LM_CHECK_EQ(ev.reason, LM_STATUS_DRIVER_RESULT_UNKNOWN);
    // Faulted stays quiet (no timers) until the application stops and starts the SDK.
    fx.run_ms(5000); // the old callback (7 s) and the command notifications cause their own steps
    const uint64_t steps = fx.eng(0).stats().steps;
    fx.run_ms(60'000);
    LM_CHECK_EQ(fx.eng(0).stats().steps, steps);
    LM_CHECK_EQ(lm_stop(fx.world.node(0).ctx(), 0, nullptr), LM_STATUS_OK);
    LM_CHECK_EQ(lm_start(fx.world.node(0).ctx()), LM_STATUS_OK);
    LM_CHECK(fx.eng(0).radio_state() == RadioState::Running);
    fx.radio(0).tx_callback_delay_us = 0;
    LM_CHECK_OK(fx.send(0, 1, 3));
    fx.run_ms(50);
    LM_CHECK_EQ(fx.eng(0).tx().last_outcome().tag, 3u);
}

// ---- BUSY / NO_MEM are local shortages ---------------------------------------------------------------

LM_TEST("driver BUSY and NO_MEM are local refusals, never RF-loss samples; MAC failure is") {
    Fixture fx(2);
    fx.radio(0).tx_fault = Status::Busy;
    fx.radio(0).tx_fault_count = 1;
    LM_CHECK(fx.send(0, 1, 1) == Status::Busy);
    fx.radio(0).tx_fault = Status::NoCapacity; // ESP_ERR_ESPNOW_NO_MEM
    fx.radio(0).tx_fault_count = 2;
    LM_CHECK(fx.send(0, 1, 2) == Status::NoCapacity);
    LM_CHECK(fx.send(0, 1, 3) == Status::NoCapacity);
    fx.run_ms(100);
    const TxStats &t = fx.eng(0).tx().stats();
    LM_CHECK_EQ(t.local_refused, 3u);
    LM_CHECK_EQ(t.rf_failed, 0u);
    LM_CHECK_EQ(t.started, 0u); // no physical TX existed
    LM_CHECK(!fx.eng(0).tx().in_flight());
    // A real RF failure (delivered, MAC ACK lost) is exactly one loss sample.
    LinkParams lp;
    lp.up = true;
    lp.ack_loss_permille = 1000;
    fx.world.set_link(0, 1, lp);
    LM_CHECK_OK(fx.send(0, 1, 4));
    fx.run_ms(100);
    LM_CHECK_EQ(t.rf_failed, 1u);
    LM_CHECK_EQ(t.local_refused, 3u);
    LM_CHECK(fx.eng(0).tx().last_outcome().result == port::TxResult::MacFailed);
}

// ---- lm_start / lm_stop / power cut -------------------------------------------------------------------

LM_TEST("lm_start needs an approved RF profile; start twice conflicts; stop is idempotent") {
    World w(WorldOptions{});
    NodeOptions o;
    o.rf.deployment_approved = false;
    (void)w.add_node(o);
    LM_CHECK_OK(w.node(0).boot());
    lm_context_t *ctx = w.node(0).ctx();
    LM_CHECK_EQ(lm_start(ctx), LM_STATUS_RF_PROFILE_UNAPPROVED);
    LM_CHECK(!w.node(0).radio.receiving());
    lm_event_t ev{};
    ev.struct_size = sizeof(ev);
    ev.abi_version = LM_ABI_VERSION;
    LM_CHECK_EQ(lm_next_event(ctx, &ev, nullptr, 0, nullptr), LM_STATUS_NOT_FOUND); // no work exists
    Fixture fx(1);
    lm_context_t *c2 = fx.world.node(0).ctx();
    LM_CHECK_EQ(lm_start(c2), LM_STATUS_CONFLICT);
    lm_operation_id_t op = 99;
    LM_CHECK_EQ(lm_stop(c2, 0, &op), LM_STATUS_OK);
    LM_CHECK_EQ(op, 0u);
    LM_CHECK(!fx.radio(0).receiving());
    LM_CHECK_EQ(lm_stop(c2, 0, &op), LM_STATUS_OK);
    LM_CHECK(fx.eng(0).transmit(fx.mac(0), ByteView{}, 0, fx.now(0)) == Status::Conflict);
}

LM_TEST("FIX1-5 failed driver teardown is a fault: not Stopped, destroy refused, stop retries") {
    Fixture fx(1);
    lm_context_t *ctx = fx.world.node(0).ctx();
    fx.radio(0).stop_fault_count = 1;
    LM_CHECK_EQ(lm_stop(ctx, 0, nullptr), LM_STATUS_RECOVERY_REQUIRED);
    LM_CHECK(fx.eng(0).radio_state() == RadioState::Faulted);
    LM_CHECK(fx.radio(0).receiving()); // the driver really is still up
    Command destroy;
    destroy.kind = CommandKind::Destroy;
    LM_CHECK(fx.eng(0).execute(destroy, fx.now(0)).status == Status::Busy);
    LM_CHECK_EQ(lm_start(ctx), LM_STATUS_CONFLICT); // no restart over a live driver
    LM_CHECK_EQ(lm_stop(ctx, 0, nullptr), LM_STATUS_OK); // the retry tears it down
    LM_CHECK(fx.eng(0).radio_state() == RadioState::Stopped);
    LM_CHECK(!fx.radio(0).receiving());
    LM_CHECK(fx.eng(0).execute(destroy, fx.now(0)).status == Status::Ok);
}

LM_TEST("power cut: the radio and every TX record are gone after boot; nothing is inherited") {
    Fixture fx(2);
    fx.radio(0).tx_callback_delay_us = 300'000;
    LM_CHECK_OK(fx.send(0, 1, 1));
    fx.world.node(0).power_cut();
    fx.run_ms(500); // the old callback lands on a dead node and is discarded
    LM_CHECK_OK(fx.world.node(0).boot());
    LM_CHECK(fx.eng(0).radio_state() == RadioState::Stopped);
    LM_CHECK_EQ(lm_start(fx.world.node(0).ctx()), LM_STATUS_OK);
    fx.radio(0).tx_callback_delay_us = 0;
    LM_CHECK_OK(fx.send(0, 1, 2));
    fx.run_ms(50);
    LM_CHECK_EQ(fx.eng(0).tx().stats().mac_acked, 1u);
    LM_CHECK_EQ(fx.eng(0).tx().stats().unmatched, 0u);
}

// ---- idle owner (ME05, sim part) -----------------------------------------------------------------------

LM_TEST("ME05 sim: an idle owner takes zero wakes for an hour; a TX adds only event-driven steps") {
    Fixture fx(3);
    for (uint16_t i = 0; i < 3; ++i) {
        LM_CHECK(fx.eng(i).step(fx.now(i)).is_never()); // no deadline while idle
    }
    std::array<uint64_t, 3> before{};
    for (uint16_t i = 0; i < 3; ++i) {
        before[i] = fx.eng(i).stats().steps;
    }
    fx.run_ms(3'600'000);
    for (uint16_t i = 0; i < 3; ++i) {
        LM_CHECK_EQ(fx.eng(i).stats().steps, before[i]); // 0 wakes: no 1/2 ms or 10 ms tick
    }
    LM_CHECK_OK(fx.send(0, 1, 1));
    fx.run_ms(200);
    const uint64_t sender_steps = fx.eng(0).stats().steps - before[0];
    const uint64_t receiver_steps = fx.eng(1).stats().steps - before[1];
    LM_CHECK(sender_steps <= 2); // the command notify, the TX-done callback
    LM_CHECK(receiver_steps <= 1); // the RX callback
    LM_CHECK_EQ(fx.eng(2).stats().steps, before[2]); // uninvolved node stays asleep
    const uint64_t after = fx.eng(0).stats().steps;
    fx.run_ms(3'600'000);
    LM_CHECK_EQ(fx.eng(0).stats().steps, after); // the watchdog timer was cancelled by the outcome
}

LM_TEST("RX burst: the owner pass is bounded, yields, and no accepted frame is lost") {
    Fixture fx(2);
    const uint64_t before = fx.eng(1).stats().steps;
    const std::array<uint8_t, 8> f{'L', 'M', 1, 1, 0, 0, 0, 0};
    for (int i = 0; i < 16; ++i) {
        fx.world.inject(fx.mac(0), 0, fx.mac(1), ByteView{f});
    }
    fx.run_ms(100);
    LM_CHECK_EQ(fx.eng(1).stats().rx_frames, 16u);
    LM_CHECK_EQ(fx.radio(1).rx_dropped(), 0u);
    // 16 frames at 8 per pass: at least two passes, each handling at most k_max_radio_events.
    LM_CHECK(fx.eng(1).stats().steps - before >= 2);
    LM_CHECK(fx.eng(1).stats().steps - before <= 6);
    // Overload beyond the ring is counted, not queued without bound.
    for (int i = 0; i < 40; ++i) {
        fx.world.inject(fx.mac(0), 0, fx.mac(1), ByteView{f});
    }
    fx.run_ms(100);
    LM_CHECK(fx.eng(1).stats().rx_frames + fx.radio(1).rx_dropped() >= 16u + 40u);
}

LM_TEST("trace records the medium's decisions and is bounded") {
    Fixture fx(2);
    fx.world.trace_enable(4);
    for (uint32_t i = 1; i <= 3; ++i) {
        LM_CHECK_OK(fx.send(0, 1, i));
        fx.run_ms(50);
    }
    const auto t = fx.world.trace();
    LM_CHECK_EQ(t.size(), 4u);                // ring keeps the newest four of nine entries
    LM_CHECK_EQ(fx.world.trace_overwritten(), 5u);
    std::size_t done = 0;
    for (const TraceEntry &e : t) {
        done += e.kind == TraceKind::TxDone ? 1U : 0U;
    }
    LM_CHECK(done >= 1);
    LM_CHECK(t.front().at_us <= t.back().at_us);
}

LM_TEST_MAIN()
