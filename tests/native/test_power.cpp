// POWER slice (S16): the three power modes, poll/grant, the parent mailbox, episodes and budgets, the sleep ticket
// race, session retention and the root's view, on real lm_context + Engine nodes over simulated ports (virtual
// time, no RF, TEST-ONLY fleet credentials). Scenario IDs are in the test names; every "sim" result is a protocol
// bench result. The time a node spends with its radio on is counted by the SDK from the virtual clock: it is a
// MODEL of awake time (SYNTHETIC), never a current, a charge or an energy, and no electrical quantity is measured.
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <memory>
#include <vector>

#include "capi/context.hpp"
#include "core/power/policy.hpp"
#include "fleet.hpp"
#include "gen/golden.hpp"
#include "gen/power_policy.hpp"
#include "lmtest.hpp"
#include "port/sim/sim_node.hpp"
#include "port/sim/sim_world.hpp"

using namespace lm;
using namespace lm::sim;

namespace {

using Bytes = std::vector<uint8_t>;
namespace pw = lm::power;

lm_power_policy_t to_c(const pw::Policy &o) {
    lm_power_policy_t p{};
    p.struct_size = sizeof(p);
    p.abi_version = LM_ABI_VERSION;
    p.revision = o.revision;
    p.mode = o.mode;
    p.pending_policy = o.pending;
    p.wake_interval_ms = o.wake_interval_ms;
    p.rx_window_ms = o.rx_window_ms;
    p.max_rx_window_ms = o.max_rx_window_ms;
    p.awake_budget_ms = o.awake_budget_ms;
    p.shutdown_reserve_ms = o.shutdown_reserve_ms;
    p.search_budget_ms = o.search_budget_ms;
    p.guard_ms = o.guard_ms;
    p.retry_min_ms = o.retry_min_ms;
    p.retry_max_ms = o.retry_max_ms;
    p.offline_radio_ms_per_hour = o.offline_radio_ms_per_hour;
    p.extra_event_wakes_per_day = o.extra_wakes_per_day;
    p.extra_event_radio_ms_per_day = o.extra_radio_ms_per_day;
    p.shutdown_overrun_limit_ms = o.shutdown_overrun_ms;
    p.mailbox_frames_per_child = o.mailbox_child;
    p.mailbox_frames_total = o.mailbox_total;
    return p;
}

struct Spec {
    Role role = Role::Relay;
    uint64_t lease_ms = 0xFFFFFFFFFFULL;
};

// Node 0 is the root (address 1), node i has address i + 1. Links are a chain unless the test rewires them.
struct PNet {
    explicit PNet(std::vector<Spec> specs, uint64_t seed = 61, uint32_t job_latency_us = 2000, bool channel_module = false)
        : n(static_cast<unsigned>(specs.size())), net(seed), world(WorldOptions{seed, 0}) {
        for (unsigned i = 0; i < n; ++i) {
            NodeOptions o;
            o.role = i == 0 ? Role::Root : specs[i].role;
            o.mesh = true;
            o.channel = channel_module;
            (void)world.add_node(o);
            node(i).jobs.latency_us = job_latency_us;
            if (i == 0) {
                kits.push_back(net.make_root());
            } else {
                fleet::MemberSpec ms;
                ms.address = static_cast<uint16_t>(i + 1);
                ms.role = static_cast<uint8_t>(specs[i].role);
                ms.relay_allowed = specs[i].role != Role::Leaf;
                ms.lease_expires_root_ms = specs[i].lease_ms;
                kits.push_back(net.make_node(i, ms.address, ms.role, &ms));
            }
        }
        world.make_chain();
        for (unsigned i = 0; i < n; ++i) {
            LM_CHECK_OK(fleet::provision(node(i).store, net, kits[i]));
        }
    }

    SimNode &node(unsigned i) { return world.node(static_cast<uint16_t>(i)); }
    Engine &eng(unsigned i) { return node(i).ctx()->engine; }
    lm_context_t *ctx(unsigned i) { return node(i).ctx(); }
    const DeviceId &id(unsigned i) { return kits[i].kit.id; }
    MonoTime now(unsigned i) { return node(i).clock.now(); }
    uint64_t root_ms() { return node(0).clock.now().to_ms(); }
    void link(unsigned a, unsigned b, bool up = true) {
        LinkParams p;
        p.up = up;
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
    void set_time_at(unsigned i) {
        RootTimeBound b;
        b.term = RootTerm{1};
        b.earliest_ms = b.latest_ms = root_ms();
        b.valid = true;
        eng(i).set_root_time(b, now(i));
        node(i).notify();
    }
    void set_time() {
        for (unsigned i = 0; i < n; ++i) {
            if (node(i).powered()) {
                set_time_at(i);
            }
        }
    }
    bool ready(unsigned i) { return eng(i).mesh().state() == route::Mesh::State::Ready; }
    bool formed() {
        for (unsigned i = 1; i < n; ++i) {
            root::RouteGrant g;
            if (!node(i).powered() || !ready(i) ||
                eng(0).routes().topology().path_from_root(ShortAddr{static_cast<uint16_t>(i + 1)}, root_ms(), g) != Status::Ok) {
                return false;
            }
        }
        return true;
    }
    // Every node linked to the root only (node 0 is the parent of all).
    void star() {
        for (unsigned i = 1; i + 1 < n; ++i) {
            link(i, i + 1, false);
        }
        for (unsigned i = 1; i < n; ++i) {
            link(0, i);
        }
    }
    void form(uint64_t limit_ms = 60'000) {
        boot_all();
        set_time();
        LM_CHECK(until([&] { return formed(); }, limit_ms, 20));
        run_ms(200);
    }

    // ---- power API ----
    lm_power_snapshot_t snap(unsigned i) {
        lm_power_snapshot_t s{};
        s.struct_size = sizeof(s);
        s.abi_version = LM_ABI_VERSION;
        LM_CHECK_EQ(lm_power_get(ctx(i), &s), LM_STATUS_OK);
        return s;
    }
    lm_power_policy_t policy_of(unsigned i) {
        lm_power_policy_t p{};
        p.struct_size = sizeof(p);
        p.abi_version = LM_ABI_VERSION;
        LM_CHECK_EQ(lm_power_policy_get(ctx(i), &p), LM_STATUS_OK);
        return p;
    }
    lm_status_t set_policy(unsigned i, const pw::Policy &want, lm_operation_id_t *op = nullptr) {
        lm_power_policy_t p = to_c(want);
        const uint64_t expected = policy_of(i).revision;
        p.revision = expected + 1;
        lm_operation_id_t o = 0;
        const lm_status_t st = lm_power_policy_set(ctx(i), &p, expected, &o);
        node(i).notify();
        if (op != nullptr) {
            *op = o;
        }
        return st;
    }
    // Sets the policy and waits for the commit (the operation is final).
    void apply_policy(unsigned i, const pw::Policy &want) {
        lm_operation_id_t op = 0;
        LM_CHECK_EQ(set_policy(i, want, &op), LM_STATUS_OK);
        LM_CHECK(until([&] { return this->op(i, op).phase == 3; }, 2000, 5));
        LM_CHECK_EQ(this->op(i, op).reason, 0u);
    }
    lm_operation_t op(unsigned i, lm_operation_id_t o) {
        lm_operation_t r{};
        r.struct_size = sizeof(r);
        r.abi_version = LM_ABI_VERSION;
        LM_CHECK_EQ(lm_get_operation(ctx(i), o, &r), LM_STATUS_OK);
        return r;
    }
    struct Prep {
        lm_status_t st = LM_STATUS_OK;
        lm_operation_id_t op = 0;
    };
    Prep prepare(unsigned i, uint32_t kind, uint32_t sources, uint64_t sleep_ms, uint32_t pending, uint32_t budget_ms = 3000) {
        lm_sleep_request_t r{};
        r.struct_size = sizeof(r);
        r.abi_version = LM_ABI_VERSION;
        r.sleep_kind = kind;
        r.wake_source_mask = sources;
        r.awake_budget_ms = budget_ms;
        r.pending_policy = pending;
        r.requested_sleep_ms = sleep_ms;
        Prep p;
        p.st = lm_sleep_prepare_ex(ctx(i), &r, &p.op);
        node(i).notify();
        return p;
    }
    // prepare -> wait for the operation -> ticket. Returns the status that ended the sequence.
    lm_status_t get_ticket(unsigned i, const Prep &p, lm_sleep_ticket_t &t) {
        LM_CHECK(until([&] { return op(i, p.op).phase == 3; }, 5000, 5));
        return lm_sleep_ticket_get(ctx(i), p.op, &t);
    }
    lm_status_t sleep_now(unsigned i, uint32_t kind, uint32_t sources, uint64_t sleep_ms, uint32_t pending) {
        const Prep p = prepare(i, kind, sources, sleep_ms, pending);
        if (p.st != LM_STATUS_OK) {
            return p.st;
        }
        lm_sleep_ticket_t t{};
        const lm_status_t g = get_ticket(i, p, t);
        if (g != LM_STATUS_OK) {
            return g;
        }
        return lm_sleep_enter(ctx(i), &t);
    }
    bool asleep(unsigned i) { return node(i).powered() && eng(i).radio_state() == RadioState::Asleep; }

    // A deep sleeper reboots by itself at its wake time; the application then gives it the root time again.
    void await_boot(unsigned i, uint64_t max_ms) {
        LM_CHECK(until([&] { return node(i).powered() && eng(i).radio_state() == RadioState::Running; }, max_ms, 20));
        set_time_at(i);
    }
    // A valid POWER poll sealed under the current link session of node i towards node j: the bytes an
    // eavesdropper could keep and replay later.
    Bytes sealed_poll(unsigned i, unsigned j) {
        wire::PowerPoll p;
        p.rx_credit = 2;
        p.poll_nonce = 0x1234567890ABCDEFULL;
        p.window_ms = 250;
        std::array<uint8_t, 64> plain{};
        std::size_t len = 0;
        LM_CHECK_OK(wire::encode_power_poll(p, MutByteView{plain}, len));
        link::SealedFrame f;
        LM_CHECK_OK(eng(i).link().seal(id(j), wire::FrameKind::Power, ByteView{plain.data(), len}, f, now(i)));
        return Bytes(f.view().data(), f.view().data() + f.view().size());
    }
    // A minimal application on node i: whenever the node is awake and its receive window has closed (or the search
    // budget is used up) it sleeps `sleep_ms` (LIGHT, timer). Runs the world until `until_us`.
    void app_cycle(unsigned i, uint64_t sleep_ms, uint64_t until_us, uint32_t kind = LM_SLEEP_LIGHT) {
        while (world.now_us() < until_us) {
            run_ms(50);
            const auto st = eng(i).power().state();
            if (!node(i).powered() || (st != power::Power::State::Running && st != power::Power::State::BudgetBlocked)) {
                continue;
            }
            const unsigned closed = power_events(i, pw::kWindowClosed);
            const unsigned ended = power_events(i, pw::kSearchBudgetEnd) + power_events(i, pw::kEpisodeBudgetEnd) +
                                   power_events(i, pw::kWakeDenied) + power_events(i, pw::kOfflineBudget);
            if ((closed > cycles_seen_ && ready(i) && eng(i).power().poll_done()) || ended > search_seen_) {
                cycles_seen_ = closed;
                search_seen_ = ended;
                (void)sleep_now(i, kind, LM_WAKE_TIMER, sleep_ms, LM_PENDING_SAVE_AND_SLEEP);
            }
        }
    }
    unsigned cycles_seen_ = 0, search_seen_ = 0;

    // Runs until node i is awake again after a sleep (its own wake, at most `max_ms` later).
    void wake_up(unsigned i, uint64_t max_ms = 70'000) {
        LM_CHECK(until([&] { return node(i).powered() && !asleep(i) && eng(i).power().state() != power::Power::State::Sleeping; }, max_ms, 50));
    }

    // ---- messages ----
    struct Sent {
        lm_status_t st = LM_STATUS_OK;
        lm_operation_id_t op = 0;
    };
    Sent send(unsigned from, unsigned to, uint32_t delivery_kind, const Bytes &payload, uint64_t ttl_ms = 30000,
              uint32_t storage = LM_VOLATILE) {
        lm_send_request_t rq{};
        rq.struct_size = sizeof(rq);
        rq.abi_version = LM_ABI_VERSION;
        rq.destination.kind = LM_DEST_NODE;
        std::memcpy(rq.destination.node.bytes, id(to).bytes.data(), 32);
        rq.app_port = 100;
        rq.delivery = static_cast<uint8_t>(delivery_kind);
        rq.storage = static_cast<uint8_t>(storage);
        rq.priority = LM_PRIORITY_NORMAL;
        rq.queue_mode = LM_FIFO;
        rq.root_term = 1;
        rq.expires_root_ms = ttl_ms == 0 ? 0 : root_ms() + ttl_ms; // 0: a DURABLE history record without deadline
        Sent s;
        s.st = lm_send(ctx(from), &rq, payload.data(), payload.size(), &s.op);
        node(from).notify();
        return s;
    }
    bool has(unsigned i, lm_operation_id_t o, uint32_t bit) { return (op(i, o).evidence_bits & bit) != 0; }
    // Next MESSAGE event of node i (payload copied).
    bool pop_message(unsigned i, Bytes &out) {
        for (;;) {
            lm_event_t ev{};
            ev.struct_size = sizeof(ev);
            ev.abi_version = LM_ABI_VERSION;
            Bytes buf(600);
            size_t req = 0;
            if (lm_next_event(ctx(i), &ev, buf.data(), buf.size(), &req) != LM_STATUS_OK) {
                return false;
            }
            if (ev.kind == LM_EVENT_MESSAGE) {
                buf.resize(req);
                out = buf;
                return true;
            }
        }
    }
    // Drains the events of node i, counting LM_EVENT_POWER by reason; returns how many were seen so far.
    unsigned power_events(unsigned i, uint32_t reason) {
        for (;;) {
            lm_event_t ev{};
            ev.struct_size = sizeof(ev);
            ev.abi_version = LM_ABI_VERSION;
            if (lm_next_event(ctx(i), &ev, nullptr, 0, nullptr) != LM_STATUS_OK) {
                break;
            }
            if (ev.kind == LM_EVENT_POWER) {
                ++seen_[{i, ev.reason}];
            }
        }
        return seen_[{i, reason}];
    }

    std::map<std::pair<unsigned, uint32_t>, unsigned> seen_;
    unsigned n;
    fleet::Network net;
    World world;
    std::vector<fleet::NodeKit> kits;
};

unsigned active_members(PNet &n) {
    unsigned c = 0;
    for (std::size_t i = 0; i < root::k_ledger_slots; ++i) {
        c += n.eng(0).ledger().entry(i).state == root::EntryState::Active ? 1U : 0U;
    }
    return c;
}

const pw::Policy k_report = gen::power_policy::k_report_only;
const pw::Policy k_windowed = gen::power_policy::k_windowed_rx;
// A REPORT_ONLY policy whose episode can finish a repair: 12 s of search, 20 s awake (the reference policy has 1 s).
pw::Policy report_long() {
    pw::Policy p = gen::power_policy::k_report_only;
    p.search_budget_ms = 12000;
    p.awake_budget_ms = 20000;
    p.offline_radio_ms_per_hour = 3600000; // tests that are not about the hourly budget must not run into it
    return p;
}

[[maybe_unused]] Bytes payload_of(uint8_t seed, std::size_t len = 40) {
    Bytes b(len);
    for (std::size_t i = 0; i < len; ++i) {
        b[i] = static_cast<uint8_t>(seed + i);
    }
    return b;
}

} // namespace

LM_TEST(
    "review G02 real cores evacuate a relay child before DRAIN, or retain membership at the deadline") {
    for (const bool alternate : {false, true}) {
        PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
        n.form();
        LM_CHECK_EQ(n.eng(2).mesh().parent_addr().value(), 2u);
        if (alternate) {
            n.world.set_link(0, 2, LinkParams{true});
        }
        lm_operation_id_t op = 0;
        LM_CHECK_EQ(lm_leave(n.ctx(1), LM_LEAVE_DRAIN, 30000, &op), LM_STATUS_OK);
        LM_CHECK(n.until([&] { return !n.eng(1).membership().leaving(); }, 35000, 10));
        if (alternate) {
            LM_CHECK(!n.eng(1).identity().is_member());
            LM_CHECK_EQ(n.eng(2).mesh().parent_addr().value(), 1u);
            LM_CHECK_EQ(n.eng(2).mesh().connectivity(n.node(2).clock.now()), LM_REACHABLE);
        } else {
            LM_CHECK(n.eng(1).identity().is_member());
            LM_CHECK(n.eng(1).membership().reason() == Status::DeadlineUnreachable);
            LM_CHECK_EQ(n.eng(2).mesh().parent_addr().value(), 2u);
        }
    }
}

LM_TEST("review G02 DRAIN waits for a moved subtree's descendants to adopt the new root path") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Relay}, Spec{Role::Leaf}});
    n.form();
    n.world.set_link(0, 2, LinkParams{true});
    lm_operation_id_t op = 0;
    LM_CHECK_EQ(lm_leave(n.ctx(1), LM_LEAVE_DRAIN, 30000, &op), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return !n.eng(1).membership().leaving(); }, 35000, 10));
    LM_CHECK(!n.eng(1).identity().is_member());
    for (unsigned i : {2U, 3U}) {
        const auto &mesh = n.eng(i).mesh();
        LM_CHECK_EQ(mesh.connectivity(n.node(i).clock.now()), LM_REACHABLE);
        LM_CHECK(std::find(mesh.path(), mesh.path() + mesh.path_size(), 2u) ==
                 mesh.path() + mesh.path_size());
    }
}

LM_TEST("review R01 synchronous windowed light wake uses fresh owner time and excludes sleep from radio "
        "accounting") {
    for (const uint64_t advance_ms : {1000U, 5000U, 30000U}) {
        PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
        n.form();
        n.apply_policy(2, k_windowed);
        n.node(2).pm.synchronous_wake_ms = advance_ms;
        const uint64_t before = n.eng(2).power().radio_on_us(n.node(2).clock.now());
        LM_CHECK(n.until([&] { return n.node(2).pm.sleep_calls() != 0; }, 5000));
        const MonoTime fresh = n.node(2).clock.now();
        LM_CHECK(n.eng(2).step_time() >= fresh + Duration::from_ms(-5));
        const uint64_t after = n.eng(2).power().radio_on_us(fresh);
        const MonoTime next = n.eng(2).step(fresh);
        LM_CHECK(next.is_never() || next >= fresh);
        // A stale time must not move the accounting origin back into the sleep gap.
        (void)n.eng(2).power().radio_on_us(fresh +
                                           Duration::from_ms(-static_cast<int64_t>(advance_ms)));
        LM_CHECK_EQ(n.eng(2).power().radio_on_us(fresh), after);
        LM_CHECK(after - before < 5'000'000U);
    }
}

LM_TEST("S16 unit: the policy record and the schedule report round-trip and refuse malformed input") {
    std::array<uint8_t, 128> buf{};
    std::size_t len = 0;
    pw::Policy p = report_long();
    p.revision = 77;
    LM_CHECK_OK(pw::encode_policy(p, MutByteView{buf}, len));
    LM_CHECK_EQ(len, pw::k_policy_record_bytes);
    pw::Policy q;
    LM_CHECK(pw::decode_policy(ByteView{buf.data(), len}, q) == Status::Ok);
    LM_CHECK_EQ(q.revision, 77u);
    LM_CHECK_EQ(q.search_budget_ms, 12000u);
    LM_CHECK(pw::decode_policy(ByteView{buf.data(), len - 1}, q) == Status::RecoveryRequired);
    pw::Report r;
    r.mode = LM_POWER_REPORT_ONLY;
    r.quality = pw::k_quality_bounded;
    r.earliest_ms = 100;
    r.latest_ms = 200;
    LM_CHECK_OK(pw::encode(r, MutByteView{buf}, len));
    pw::Report d;
    LM_CHECK(pw::decode(ByteView{buf.data(), len}, d) == Status::Ok);
    LM_CHECK_EQ(d.latest_ms, 200u);
    buf[len - 1] = 0;
    buf[len - 5] = 9; // earliest > latest
    LM_CHECK(pw::decode(ByteView{buf.data(), len}, d) == Status::BadFrame);
}

LM_TEST("S16 smoke: REPORT_ONLY policy, episode, authenticated poll and grant with the parent") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    n.form();
    lm_capabilities_t caps{};
    caps.struct_size = sizeof(caps);
    caps.abi_version = LM_ABI_VERSION;
    LM_CHECK_EQ(lm_get_capabilities(n.ctx(2), &caps), LM_STATUS_OK);
    const uint64_t modes = LM_FEATURE_POWER_REPORT_ONLY | LM_FEATURE_POWER_WINDOWED_RX | LM_FEATURE_RAM_SESSION_RETAIN;
    LM_CHECK_EQ(caps.implemented_bits & modes, modes);
    LM_CHECK_EQ(caps.qualified_bits & modes, 0u);                                  // nothing is qualified (no HIL)
    LM_CHECK_EQ(caps.implemented_bits & LM_FEATURE_RTC_SECURE_RESUME_RESERVED, 0u); // reserved: not implemented ...
    LM_CHECK_EQ(caps.enabled_bits & LM_FEATURE_RTC_SECURE_RESUME_RESERVED, 0u);     // ... and not enabled
    n.apply_policy(2, k_report);
    LM_CHECK_EQ(n.snap(2).mode, static_cast<uint32_t>(LM_POWER_REPORT_ONLY));
    LM_CHECK_EQ(n.snap(2).policy_revision, 2u);
    LM_CHECK(n.until([&] { return n.snap(2).polls >= 1; }, 2000));
    LM_CHECK(n.until([&] { return n.eng(1).power().stats().polls_served >= 1; }, 2000));
    LM_CHECK(n.until([&] { return n.eng(2).power().stats().grants >= 1; }, 2000));
    LM_CHECK_EQ(n.snap(2).missed_windows, 0u);
}

LM_TEST("LP17 LP08 sim: a light-sleeping REPORT_ONLY leaf takes no unscheduled step and keeps its sessions") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    n.form();
    n.apply_policy(2, k_report);
    LM_CHECK(n.until([&] { return n.eng(2).power().stats().grants >= 1; }, 2000));
    const uint64_t hs = n.snap(2).handshake_count;
    LM_CHECK_EQ(n.sleep_now(2, LM_SLEEP_LIGHT, LM_WAKE_TIMER, 60'000, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK);
    LM_CHECK(n.asleep(2));
    LM_CHECK_EQ(n.snap(2).state, static_cast<uint32_t>(LM_POWER_SLEEPING));
    n.run_ms(5); // the step that the sleep-enter command itself causes
    const uint64_t steps = n.eng(2).stats().steps;
    n.run_ms(59'000);
    // 32 s hello and 60 s lease refresh came due while asleep: they did not wake the node (docs/20 §11).
    LM_CHECK_EQ(n.eng(2).stats().steps, steps);
    LM_CHECK(n.asleep(2));
    n.run_ms(1'500);
    LM_CHECK(!n.asleep(2));
    LM_CHECK_EQ(n.snap(2).state, static_cast<uint32_t>(LM_POWER_RUNNING));
    LM_CHECK_EQ(n.snap(2).episode_count, 2u); // the policy set, the wake
    LM_CHECK(n.eng(2).power().last_session_path() == pw::SessionPath::RamReuse);
    LM_CHECK(n.until([&] { return n.eng(2).power().stats().grants >= 2; }, 2000));
    LM_CHECK_EQ(n.snap(2).handshake_count, hs); // no EDHOC for a wake inside the key lifetime
    LM_CHECK_EQ(n.eng(2).mesh().stats().suspects, 0u);
    LM_CHECK(n.ready(2));
}

LM_TEST("LP01 sim: relay and root cannot leave ALWAYS_RX; a refused change leaves policy and radio alone") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    n.form();
    for (unsigned i : {0U, 1U}) {
        LM_CHECK_EQ(n.set_policy(i, k_windowed), LM_STATUS_ROLE_NOT_ALLOWED);
        LM_CHECK_EQ(n.set_policy(i, k_report), LM_STATUS_ROLE_NOT_ALLOWED);
        LM_CHECK_EQ(n.policy_of(i).revision, 1u);
        LM_CHECK_EQ(n.policy_of(i).mode, static_cast<uint32_t>(LM_POWER_ALWAYS_RX));
        LM_CHECK(n.eng(i).radio_state() == RadioState::Running);
        lm_operation_id_t op = 0;
        LM_CHECK_EQ(n.prepare(i, LM_SLEEP_LIGHT, LM_WAKE_TIMER, 1000, 0).st, LM_STATUS_ROLE_NOT_ALLOWED);
        (void)op;
    }
    LM_CHECK(n.ready(1));
    LM_CHECK(n.ready(2));
    // A leaf may choose any mode, but only by the CAS rules: expected revision, revision + 1, valid fields.
    lm_power_policy_t p = to_c(k_windowed);
    lm_operation_id_t op = 0;
    p.revision = 2;
    LM_CHECK_EQ(lm_power_policy_set(n.ctx(2), &p, 5, &op), LM_STATUS_CONFLICT);
    p.revision = 7;
    LM_CHECK_EQ(lm_power_policy_set(n.ctx(2), &p, 1, &op), LM_STATUS_INVALID_ARGUMENT);
    p.revision = 2;
    p.guard_ms = p.rx_window_ms; // a window that cannot hold its guards
    LM_CHECK_EQ(lm_power_policy_set(n.ctx(2), &p, 1, &op), LM_STATUS_INVALID_ARGUMENT);
    p = to_c(k_windowed);
    p.revision = 2;
    p.reserved[1] = 1;
    LM_CHECK_EQ(lm_power_policy_set(n.ctx(2), &p, 1, &op), LM_STATUS_INVALID_ARGUMENT);
    LM_CHECK_EQ(n.policy_of(2).revision, 1u); // the old policy stayed in force through every refusal
    LM_CHECK_EQ(n.policy_of(2).mode, static_cast<uint32_t>(LM_POWER_ALWAYS_RX));
    // The u63 limit is refused, never wrapped (docs/20 §1).
    pw::Policy top = k_report;
    top.revision = k_u63_max + 1;
    LM_CHECK(pw::validate(top, Role::Leaf) == Status::InvalidArgument);
    n.apply_policy(2, k_windowed);
    LM_CHECK_EQ(n.policy_of(2).mode, static_cast<uint32_t>(LM_POWER_WINDOWED_RX));
    // ALWAYS_RX never sleeps: lm_sleep_prepare on it is ROLE_NOT_ALLOWED, and the radio keeps running.
    PNet m({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    m.form();
    lm_operation_id_t op2 = 0;
    LM_CHECK_EQ(lm_sleep_prepare(m.ctx(2), 2000, &op2), LM_STATUS_ROLE_NOT_ALLOWED);
    LM_CHECK(m.eng(2).radio_state() == RadioState::Running);
}

LM_TEST("P01 LP04 sim: a frame that arrives after the ticket makes sleep_enter refuse, and nothing is dropped") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    n.form();
    n.apply_policy(2, k_report);
    LM_CHECK(n.until([&] { return n.eng(2).power().stats().grants >= 1; }, 2000));
    // The leaf reports to the root with RECEIVED; SAVE_AND_SLEEP lets the ticket come before the receipt does.
    const auto m = n.send(2, 0, LM_RECEIVED, payload_of(7), 30000);
    LM_CHECK_EQ(m.st, LM_STATUS_OK);
    const PNet::Prep p = n.prepare(2, LM_SLEEP_LIGHT, LM_WAKE_TIMER, 60'000, LM_PENDING_SAVE_AND_SLEEP);
    LM_CHECK_EQ(p.st, LM_STATUS_OK);
    lm_sleep_ticket_t t{};
    LM_CHECK_EQ(n.get_ticket(2, p, t), LM_STATUS_OK);
    LM_CHECK_EQ(n.snap(2).state, static_cast<uint32_t>(LM_POWER_SLEEP_READY));
    LM_CHECK_EQ(lm_sleep_ticket_get(n.ctx(2), p.op, &t), LM_STATUS_CONFLICT); // one ticket per prepare
    // While the ticket is in hand a new send is refused (nothing may start behind a prepared sleep) ...
    LM_CHECK_EQ(n.send(2, 0, LM_RECEIVED, payload_of(8)).st, LM_STATUS_BUSY);
    // ... and the receipt of the first arrives: END_RECEIVED is recorded, the ticket is stale.
    LM_CHECK(n.until([&] { return n.has(2, m.op, lm::delivery::ev::end_received); }, 1500));
    LM_CHECK_EQ(lm_sleep_enter(n.ctx(2), &t), LM_STATUS_SLEEP_TICKET_STALE);
    LM_CHECK(!n.asleep(2));
    LM_CHECK_EQ(n.snap(2).state, static_cast<uint32_t>(LM_POWER_RUNNING));
    LM_CHECK_EQ(lm_sleep_enter(n.ctx(2), &t), LM_STATUS_SLEEP_TICKET_STALE); // and it was single use
    // Prepare again: the same node now sleeps.
    LM_CHECK_EQ(n.sleep_now(2, LM_SLEEP_LIGHT, LM_WAKE_TIMER, 60'000, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK);
    LM_CHECK(n.asleep(2));
    // A policy change between ticket and enter also invalidates the ticket.
    PNet q({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    q.form();
    q.apply_policy(2, k_report);
    const PNet::Prep p2 = q.prepare(2, LM_SLEEP_LIGHT, LM_WAKE_TIMER, 60'000, LM_PENDING_SAVE_AND_SLEEP);
    lm_sleep_ticket_t t2{};
    LM_CHECK_EQ(q.get_ticket(2, p2, t2), LM_STATUS_OK);
    LM_CHECK_EQ(q.set_policy(2, k_report), LM_STATUS_BUSY); // a prepared sleep blocks a policy change
    LM_CHECK_EQ(lm_sleep_abort(q.ctx(2), p2.op), LM_STATUS_OK);
    q.apply_policy(2, k_windowed);
    LM_CHECK_EQ(lm_sleep_enter(q.ctx(2), &t2), LM_STATUS_SLEEP_TICKET_STALE);
    // The ticket also dies after 2000 ms.
    PNet r({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    r.form();
    r.apply_policy(2, k_report);
    const PNet::Prep p3 = r.prepare(2, LM_SLEEP_DEEP, LM_WAKE_TIMER, 60'000, LM_PENDING_SAVE_AND_SLEEP);
    lm_sleep_ticket_t t3{};
    LM_CHECK_EQ(r.get_ticket(2, p3, t3), LM_STATUS_OK);
    r.run_ms(2100);
    LM_CHECK_EQ(lm_sleep_enter(r.ctx(2), &t3), LM_STATUS_SLEEP_TICKET_STALE);
    LM_CHECK_EQ(r.snap(2).state, static_cast<uint32_t>(LM_POWER_RUNNING));
}

// PM locks are a level (port::pm_lock): a lock is held exactly while its reason holds, whatever ended the activity.
static bool locks_balanced(PNet &n, unsigned i) {
    const SimPm &pm = n.node(i).pm;
    for (unsigned b = 0; b < 4; ++b) {
        if (pm.acquired(b) - pm.released(b) != ((pm.locks() >> b) & 1U)) {
            return false;
        }
    }
    return true;
}

LM_TEST("LP05 LP18 sim: a veto restores the node, and PM locks are released on success, failure, timeout and cancel") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    n.form();
    n.apply_policy(2, k_report);
    LM_CHECK(n.until([&] { return n.eng(2).power().stats().grants >= 1; }, 2000));
    const SimPm &pm = n.node(2).pm;
    LM_CHECK((pm.locks() & port::pm_lock::episode) != 0); // awake episode holds the CPU
    LM_CHECK(locks_balanced(n, 2));
    // Veto: the application's sensor is still busy, so it calls lm_sleep_abort.
    const PNet::Prep p = n.prepare(2, LM_SLEEP_DEEP, LM_WAKE_TIMER, 60'000, LM_PENDING_SAVE_AND_SLEEP);
    lm_sleep_ticket_t t{};
    LM_CHECK_EQ(n.get_ticket(2, p, t), LM_STATUS_OK);
    LM_CHECK_EQ(lm_sleep_abort(n.ctx(2), p.op), LM_STATUS_OK);
    LM_CHECK_EQ(lm_sleep_enter(n.ctx(2), &t), LM_STATUS_SLEEP_TICKET_STALE);
    LM_CHECK_EQ(lm_sleep_ticket_get(n.ctx(2), p.op, &t), LM_STATUS_SLEEP_TICKET_STALE);
    LM_CHECK_EQ(n.snap(2).state, static_cast<uint32_t>(LM_POWER_RUNNING));
    LM_CHECK(n.eng(2).radio_state() == RadioState::Running);
    LM_CHECK_EQ(n.power_events(2, pw::kSleepAborted), 1u);
    LM_CHECK_EQ(lm_sleep_abort(n.ctx(2), p.op), LM_STATUS_CONFLICT); // nothing left to abort
    LM_CHECK(n.ready(2));
    LM_CHECK(locks_balanced(n, 2));
    // Timeout: a prepare that cannot settle within the caller's budget fails with POWER_BUDGET_EXHAUSTED, no ticket.
    const auto m = n.send(2, 0, LM_RECEIVED, payload_of(3), 30000);
    LM_CHECK_EQ(m.st, LM_STATUS_OK);
    n.link(0, 1, false); // the root cannot be reached: REQUIRE_SETTLED cannot finish
    const PNet::Prep tp = n.prepare(2, LM_SLEEP_LIGHT, LM_WAKE_TIMER, 60'000, LM_PENDING_REQUIRE_SETTLED, 400);
    LM_CHECK_EQ(tp.st, LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.op(2, tp.op).phase == 3; }, 3000));
    LM_CHECK_EQ(n.op(2, tp.op).reason, static_cast<uint32_t>(LM_STATUS_POWER_BUDGET_EXHAUSTED));
    LM_CHECK_EQ(lm_sleep_ticket_get(n.ctx(2), tp.op, &t), LM_STATUS_POWER_BUDGET_EXHAUSTED);
    LM_CHECK_EQ(n.snap(2).state, static_cast<uint32_t>(LM_POWER_RUNNING));
    // Cancel: the pending send is cancelled while its EDHOC/journal work may still hold a lock.
    (void)lm_cancel(n.ctx(2), m.op);
    n.run_ms(300);
    LM_CHECK(locks_balanced(n, 2));
    LM_CHECK_EQ(n.node(2).pm.locks() & (port::pm_lock::crypto | port::pm_lock::flash | port::pm_lock::radio), 0u);
    n.link(0, 1, true);
    // Sleep: every lock is off while asleep; stop releases whatever is left.
    LM_CHECK_EQ(n.sleep_now(2, LM_SLEEP_LIGHT, LM_WAKE_TIMER, 30'000, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK);
    LM_CHECK_EQ(n.node(2).pm.locks(), 0u);
    LM_CHECK(locks_balanced(n, 2));
    n.run_ms(31'000);
    LM_CHECK((n.node(2).pm.locks() & port::pm_lock::episode) != 0);
    LM_CHECK(locks_balanced(n, 2));
    LM_CHECK_EQ(lm_stop(n.ctx(2), 0, nullptr), LM_STATUS_OK);
    LM_CHECK_EQ(n.node(2).pm.locks(), 0u);
    LM_CHECK(locks_balanced(n, 2));
    for (unsigned b = 0; b < 4; ++b) {
        LM_CHECK_EQ(n.node(2).pm.acquired(b), n.node(2).pm.released(b)); // symmetric over the whole run
    }
}

LM_TEST("LP14 sim: a lost or late GRANT is asked for again with the same nonce, at most twice, window not extended") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    n.form();
    // Lost: the relay's answer never arrives once, the retry (same nonce) is answered.
    LinkParams lossy;
    lossy.up = true;
    lossy.loss_permille = 1000;
    n.world.set_link_one_way(1, 2, lossy);
    lm_operation_id_t op = 0;
    lm_power_policy_t pol = to_c(k_report);
    pol.revision = 2;
    LM_CHECK_EQ(lm_power_policy_set(n.ctx(2), &pol, 1, &op), LM_STATUS_OK);
    n.node(2).notify();
    LM_CHECK(n.until([&] { return n.eng(1).power().stats().polls_served >= 1; }, 2000, 1));
    LinkParams good;
    good.up = true;
    n.world.set_link_one_way(1, 2, good); // the first GRANT is gone; the second try goes through
    LM_CHECK(n.until([&] { return n.eng(2).power().stats().grants >= 1; }, 2000, 1));
    LM_CHECK_EQ(n.eng(2).power().stats().polls, 2u);          // first try and one retry, never a third
    LM_CHECK_EQ(n.eng(1).power().stats().polls_served, 2u);   // both were answered, one child entry
    LM_CHECK_EQ(n.snap(2).missed_windows, 0u);
    n.run_ms(3000);
    LM_CHECK_EQ(n.eng(2).power().stats().polls, 2u);
    // Both lost: two tries, then the window is a missed window (not proof of RF loss), and no third poll.
    PNet m({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    m.form();
    m.world.set_link_one_way(1, 2, lossy);
    pol.revision = 2;
    LM_CHECK_EQ(lm_power_policy_set(m.ctx(2), &pol, 1, &op), LM_STATUS_OK);
    m.node(2).notify();
    m.run_ms(2000);
    LM_CHECK_EQ(m.eng(2).power().stats().polls, 2u);
    LM_CHECK_EQ(m.snap(2).missed_windows, 1u);
    LM_CHECK_EQ(m.eng(2).power().stats().grants, 0u);
    // Late and duplicated: the first GRANT arrives after the retry was sent; the second is a duplicate and ignored.
    PNet d({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    d.form();
    LinkParams slow;
    slow.up = true;
    slow.delay_us = 100'000; // 100 ms each way: the answer is later than the retry gap
    d.world.set_link(1, 2, slow);
    pol.revision = 2;
    LM_CHECK_EQ(lm_power_policy_set(d.ctx(2), &pol, 1, &op), LM_STATUS_OK);
    d.node(2).notify();
    d.run_ms(2000);
    LM_CHECK_EQ(d.eng(2).power().stats().polls, 2u);
    LM_CHECK_EQ(d.eng(2).power().stats().grants, 1u);
    LM_CHECK_EQ(d.eng(1).power().stats().polls_served, 2u);
    LM_CHECK_EQ(d.snap(2).missed_windows, 0u);
}

LM_TEST("P03 GS05 sim: a command whose deadline is before the target's next wake is refused at once, nothing is spooled") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    n.form();
    n.apply_policy(2, k_report);
    LM_CHECK(n.until([&] { return n.eng(2).power().stats().grants >= 1; }, 2000));
    LM_CHECK_EQ(n.sleep_now(2, LM_SLEEP_LIGHT, LM_WAKE_TIMER, 60'000, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK);
    n.run_ms(500);
    pw::MemberPower mp;
    LM_CHECK(n.eng(0).power().member_power(ShortAddr{3}, mp)); // the root knows the schedule hint
    LM_CHECK_EQ(mp.quality, pw::k_quality_bounded);
    LM_CHECK_EQ(mp.mode, static_cast<uint8_t>(LM_POWER_REPORT_ONLY));
    const std::size_t root_frames = n.eng(0).delivery().hop().in_use();
    const auto refused = n.send(0, 2, LM_RECEIVED, payload_of(1), 5'000); // wakes in ~60 s, deadline 5 s
    LM_CHECK_EQ(refused.st, LM_STATUS_DEADLINE_UNREACHABLE);
    LM_CHECK_EQ(n.eng(0).delivery().hop().in_use(), root_frames);
    LM_CHECK_EQ(n.eng(0).delivery().settle_state().active, 0u);
    // A deadline after the wake is accepted and waits: WAIT_WAKE, the copy is parked at the parent (RAM only).
    const auto ok = n.send(0, 2, LM_RECEIVED, payload_of(2), 120'000);
    LM_CHECK_EQ(ok.st, LM_STATUS_OK);
    n.run_ms(2'000);
    LM_CHECK_EQ(n.eng(1).delivery().hop().queued_for(n.node(2).radio.mac()), 1u);
    LM_CHECK((n.op(0, ok.op).evidence_bits & lm::delivery::ev::hop_accepted) != 0); // relay took it: HOP_ACCEPTED ...
    LM_CHECK((n.op(0, ok.op).evidence_bits & lm::delivery::ev::end_received) == 0); // ... which is not a receipt
    LM_CHECK_EQ(n.eng(1).delivery().hop_stats().rf_failed, 0u);   // sleep is not RF loss
    LM_CHECK_EQ(n.eng(1).delivery().hop_stats().retransmits, 0u); // and burns no link attempt
    n.run_ms(58'000);
    Bytes got;
    LM_CHECK(n.until([&] { return n.pop_message(2, got); }, 5'000));
    LM_CHECK(got == payload_of(2));
    LM_CHECK(n.until([&] { return n.has(0, ok.op, lm::delivery::ev::end_received); }, 5'000));
    LM_CHECK_EQ(n.eng(1).delivery().hop_stats().rf_failed, 0u);
    LM_CHECK_EQ(n.eng(1).mesh().stats().suspects, 0u);
}

LM_TEST("GS06 sim: an unknown wake time is never called unreachable; a finite command ends at its deadline") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    n.form();
    pw::Policy pol = k_report;
    pol.extra_wakes_per_day = 1000;
    n.apply_policy(2, pol);
    LM_CHECK(n.until([&] { return n.eng(2).power().stats().grants >= 1; }, 2000));
    // FIX6-D3: the external Deep Sleep wake below is charged to the wake quota, which a cold boot starts with used up:
    // at 1000 wakes/day one is back after 87 s.
    n.run_ms(100'000);
    const uint64_t rf0 = n.eng(1).delivery().hop_stats().rf_failed;
    LM_CHECK_EQ(n.sleep_now(2, LM_SLEEP_DEEP, LM_WAKE_EXTERNAL, 0, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK); // GPIO only
    n.run_ms(500);
    LM_CHECK(n.node(2).deep_sleeping());
    // Short deadline, GPIO-only sleeper: accepted (WAIT_WAKE with schedule UNKNOWN), never DEADLINE_UNREACHABLE.
    const auto finite = n.send(0, 2, LM_RECEIVED, payload_of(3), 20'000);
    LM_CHECK_EQ(finite.st, LM_STATUS_OK);
    // A DURABLE record without a deadline (history) is accepted too and keeps waiting.
    lm_send_request_t rq{};
    rq.struct_size = sizeof(rq);
    rq.abi_version = LM_ABI_VERSION;
    rq.destination.kind = LM_DEST_NODE;
    std::memcpy(rq.destination.node.bytes, n.id(2).bytes.data(), 32);
    rq.app_port = 101;
    rq.delivery = LM_RECEIVED;
    rq.storage = LM_DURABLE;
    rq.priority = LM_PRIORITY_NORMAL;
    rq.root_term = 1;
    rq.expires_root_ms = 0;
    lm_operation_id_t hist = 0;
    const Bytes body = payload_of(4);
    LM_CHECK_EQ(lm_send(n.ctx(0), &rq, body.data(), body.size(), &hist), LM_STATUS_OK);
    n.node(0).notify();
    n.run_ms(30'000);
    // The finite command ended at its deadline (never delivered: the node did not wake); the history did not.
    const lm_operation_t f = n.op(0, finite.op);
    LM_CHECK_EQ(f.phase, 3u);
    LM_CHECK(f.outcome == LM_OUTCOME_EXPIRED || f.outcome == LM_OUTCOME_INDETERMINATE);
    LM_CHECK_EQ(n.op(0, hist).phase == 3, false);
    LM_CHECK_EQ(n.eng(1).delivery().hop_stats().rf_failed, rf0);
    // The external wake: the node comes back, polls, and the history reaches it exactly once.
    n.node(2).wake_external();
    n.set_time_at(2);
    Bytes got;
    LM_CHECK(n.until([&] { return n.pop_message(2, got); }, 90'000));
    LM_CHECK(got == body);
    LM_CHECK(n.until([&] { return n.has(0, hist, lm::delivery::ev::end_received); }, 150'000, 50)); // the origin asks again (backoff)
}

LM_TEST("LP02 sim: WINDOWED_RX cycles by itself, receives only after an authenticated poll, and is radio-off in between") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    n.form();
    n.apply_policy(2, k_windowed); // 5000 ms interval, 250 ms window
    LM_CHECK(n.until([&] { return n.eng(2).power().stats().sleeps >= 1; }, 3000));
    // Steady state: measure 60 s of the cycle.
    n.run_ms(12'000);
    const uint64_t on0 = n.snap(2).radio_on_us;
    const uint64_t steps0 = n.eng(2).stats().steps;
    const uint64_t polls0 = n.snap(2).polls;
    const uint64_t t0 = n.world.now_us();
    unsigned asleep_samples = 0;
    unsigned samples = 0;
    Bytes got;
    uint64_t sent_us = 0;
    bool delivered = false;
    lm_operation_id_t mop = 0;
    for (unsigned k = 0; k < 6000; ++k) { // 60 s in 10 ms slices
        n.run_ms(10);
        ++samples;
        asleep_samples += n.asleep(2) ? 1U : 0U;
        if (k == 1330) { // a downlink command in the middle of an interval
            const auto m = n.send(0, 2, LM_RECEIVED, payload_of(9), 60'000);
            LM_CHECK_EQ(m.st, LM_STATUS_OK);
            mop = m.op;
            sent_us = n.world.now_us();
        }
        if (!delivered && sent_us != 0 && n.pop_message(2, got)) {
            delivered = true;
            const uint64_t latency_ms = (n.world.now_us() - sent_us) / 1000;
            std::printf("  LP02-sim WINDOWED 5000/250 ms: downlink latency %llu ms (interval 5000 ms)\n", (unsigned long long)latency_ms);
            LM_CHECK(latency_ms <= 5000 + 250 + 500); // one interval, its window and the radio path
        }
    }
    LM_CHECK(delivered);
    LM_CHECK(got == payload_of(9));
    LM_CHECK(n.until([&] { return n.has(0, mop, lm::delivery::ev::end_received); }, 8000));
    const uint64_t elapsed_us = n.world.now_us() - t0;
    const uint64_t on_us = n.snap(2).radio_on_us - on0;
    const uint64_t windows = n.snap(2).polls - polls0;
    std::printf("  LP02-sim MODEL (virtual time, SYNTHETIC, not energy): radio-on %.1f %% of %llu s, %llu windows, %llu owner steps, asleep in %u/%u samples\n",
                100.0 * static_cast<double>(on_us) / static_cast<double>(elapsed_us), static_cast<unsigned long long>(elapsed_us / 1000000),
                static_cast<unsigned long long>(windows), static_cast<unsigned long long>(n.eng(2).stats().steps - steps0), asleep_samples, samples);
    LM_CHECK(windows >= 11 && windows <= 14);                                  // 60 s / 5 s
    LM_CHECK(on_us * 100 < elapsed_us * 20);                                    // radio off most of the time
    LM_CHECK(asleep_samples * 100 > samples * 80);
    LM_CHECK(n.ready(2));                                                       // lease renewals fit into the windows
    LM_CHECK_EQ(n.eng(2).mesh().stats().suspects, 0u);
    LM_CHECK_EQ(n.eng(1).delivery().hop_stats().rf_failed, 0u);                 // the parent lost nothing to sleep
    // The same node in ALWAYS_RX keeps the radio on for the whole time (the A/B model comparison).
    PNet b({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    b.form();
    const uint64_t b_on0 = b.snap(2).radio_on_us;
    const uint64_t b_t0 = b.world.now_us();
    b.run_ms(60'000);
    const uint64_t b_on = b.snap(2).radio_on_us - b_on0;
    LM_CHECK(b_on * 100 > (b.world.now_us() - b_t0) * 99);
    LM_CHECK(on_us * 5 < b_on);
}

LM_TEST("GS04 sim: awake targets are served first; a sleeping target holds a bounded mailbox, not the pool") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Relay}, Spec{Role::Relay}, Spec{Role::Leaf}});
    n.star();
    n.form();
    n.apply_policy(4, k_report);
    LM_CHECK(n.until([&] { return n.eng(4).power().stats().grants >= 1; }, 2000));
    LM_CHECK_EQ(n.sleep_now(4, LM_SLEEP_LIGHT, LM_WAKE_TIMER, 60'000, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK);
    n.run_ms(500);
    // Four commands to the sleeper first, then one to each awake relay: none waits behind the sleeper.
    lm_operation_id_t ops[3];
    for (unsigned k = 0; k < 4; ++k) {
        const auto s = n.send(0, 4, LM_RECEIVED, payload_of(static_cast<uint8_t>(20 + k)), 300'000);
        LM_CHECK_EQ(s.st, LM_STATUS_OK);
    }
    for (unsigned k = 0; k < 3; ++k) {
        const auto s = n.send(0, k + 1, LM_RECEIVED, payload_of(static_cast<uint8_t>(40 + k)), 30'000);
        LM_CHECK_EQ(s.st, LM_STATUS_OK);
        ops[k] = s.op;
    }
    const uint64_t t0 = n.world.now_us();
    LM_CHECK(n.until([&] { return n.has(0, ops[0], lm::delivery::ev::end_received) && n.has(0, ops[1], lm::delivery::ev::end_received) &&
                                  n.has(0, ops[2], lm::delivery::ev::end_received); }, 5000, 5));
    std::printf("  GS04-sim: awake targets done %llu ms after submit; sleeper mailbox at the root holds %zu frame(s)\n",
                static_cast<unsigned long long>((n.world.now_us() - t0) / 1000),
                n.eng(0).delivery().hop().queued_for(n.node(4).radio.mac()));
    // The mailbox of the sleeper is capped (mailbox_frames_per_child = 2), the rest of the pool is free.
    LM_CHECK(n.eng(0).delivery().hop().queued_for(n.node(4).radio.mac()) <= 2);
    LM_CHECK(n.eng(0).delivery().hop().in_use() <= 3);
    LM_CHECK_EQ(n.eng(0).delivery().hop_stats().rf_failed, 0u);
    // The wake: all four reach the sleeper, none twice, and they are END_RECEIVED only by the receipts.
    n.run_ms(60'000);
    unsigned msgs = 0;
    Bytes got;
    LM_CHECK(n.until([&] {
        while (n.pop_message(4, got)) {
            ++msgs;
        }
        return msgs >= 4;
    }, 120'000, 200));
    n.run_ms(20'000);
    while (n.pop_message(4, got)) {
        ++msgs;
    }
    LM_CHECK_EQ(msgs, 4u);
    LM_CHECK_EQ(n.eng(0).delivery().hop_stats().rf_failed, 0u);
}

LM_TEST("LP10 sim: a parent that loses its mailbox is recovered by the origin sending the same MessageId again") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    n.form();
    n.apply_policy(2, report_long());
    LM_CHECK(n.until([&] { return n.eng(2).power().stats().grants >= 1; }, 2000));
    LM_CHECK_EQ(n.sleep_now(2, LM_SLEEP_LIGHT, LM_WAKE_TIMER, 60'000, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK);
    n.run_ms(500);
    const auto a = n.send(0, 2, LM_RECEIVED, payload_of(50), 0, LM_DURABLE);
    const auto b = n.send(0, 2, LM_RECEIVED, payload_of(51), 0, LM_DURABLE);
    LM_CHECK_EQ(a.st, LM_STATUS_OK);
    LM_CHECK_EQ(b.st, LM_STATUS_OK);
    n.run_ms(3'000);
    LM_CHECK_EQ(n.eng(1).delivery().hop().queued_for(n.node(2).radio.mac()), 2u); // both parked at the parent
    LM_CHECK((n.op(0, a.op).evidence_bits & lm::delivery::ev::hop_accepted) != 0);
    LM_CHECK((n.op(0, a.op).evidence_bits & lm::delivery::ev::end_received) == 0);
    // The parent loses power: its RAM mailbox is gone. The root's operations are not done, and say so.
    n.node(1).power_cut();
    n.node(1).store.power_restore();
    n.boot(1);
    n.set_time_at(1);
    n.run_ms(1'000);
    LM_CHECK((n.op(0, a.op).evidence_bits & lm::delivery::ev::end_received) == 0);
    LM_CHECK((n.op(0, b.op).evidence_bits & lm::delivery::ev::end_received) == 0);
    LM_CHECK_EQ(n.op(0, a.op).phase == 3, false);
    // The leaf wakes, re-attaches, polls; the origin's copies arrive by the next rounds. Each message once.
    Bytes got;
    unsigned seen = 0;
    bool s50 = false;
    bool s51 = false;
    for (unsigned k = 0; k < 400 && !(s50 && s51); ++k) {
        n.app_cycle(2, 60'000, n.world.now_us() + 1'000'000); // the application: sleeps after every receive window
        while (n.pop_message(2, got)) {
            ++seen;
            s50 = s50 || got == payload_of(50);
            s51 = s51 || got == payload_of(51);
        }
    }
    LM_CHECK(s50 && s51);
    LM_CHECK(n.until([&] { return n.has(0, a.op, lm::delivery::ev::end_received) && n.has(0, b.op, lm::delivery::ev::end_received); }, 200'000, 100));
    LM_CHECK(n.eng(2).power().stats().missed_windows >= 1); // the wake after the parent's restart found no session ...
    LM_CHECK(n.eng(2).link().stats().hs_completed >= 2);    // ... and made a new one with that parent only
    lm_membership_t mem{};
    mem.struct_size = sizeof(mem);
    mem.abi_version = LM_ABI_VERSION;
    LM_CHECK_EQ(lm_membership_get(n.ctx(2), &mem), LM_STATUS_OK);
    LM_CHECK_EQ(mem.state, static_cast<uint32_t>(LM_ACTIVE)); // never a new Join
    LM_CHECK_EQ(seen, 2u);
}

LM_TEST("LP08 sim: 1000 light-sleep wakes reuse the sessions: no EDHOC, monotone counters, a replayed poll changes nothing") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    n.form();
    n.apply_policy(2, k_report);
    LM_CHECK(n.until([&] { return n.eng(2).power().stats().grants >= 1; }, 2000));
    const uint64_t hs0 = n.snap(2).handshake_count;
    const uint64_t rl_hs0 = n.eng(1).link().stats().hs_completed;
    const Bytes replay = n.sealed_poll(2, 1); // captured now, replayed at the end
    uint64_t last_counter = 0;
    unsigned monotone_violations = 0;
    for (unsigned cycle = 0; cycle < 1000; ++cycle) {
        lm_status_t st = LM_STATUS_SLEEP_TICKET_STALE;
        for (unsigned tries = 0; tries < 8 && st == LM_STATUS_SLEEP_TICKET_STALE; ++tries) { // a frame arrived: ask again
            st = n.sleep_now(2, LM_SLEEP_LIGHT, LM_WAKE_TIMER, 2'000, LM_PENDING_SAVE_AND_SLEEP);
        }
        LM_CHECK_EQ(st, LM_STATUS_OK);
        n.run_ms(2'100);
        if (n.asleep(2) || n.snap(2).state != LM_POWER_RUNNING) {
            LM_CHECK(false);
            break;
        }
        n.run_ms(400); // the poll and its window
        const link::Neighbor *nb = n.eng(2).link().neighbors().find_device(n.id(1));
        LM_CHECK(nb != nullptr && nb->cur.active);
        if (nb != nullptr) {
            monotone_violations += nb->cur.rec.tx_used() < last_counter ? 1U : 0U;
            last_counter = nb->cur.rec.tx_used();
        }
    }
    std::printf("  LP08-sim: 1000 wakes, handshakes at the leaf %llu -> %llu, at the relay %llu -> %llu, tx counter %llu, polls %llu, missed %llu\n",
                static_cast<unsigned long long>(hs0), static_cast<unsigned long long>(n.snap(2).handshake_count),
                static_cast<unsigned long long>(rl_hs0), static_cast<unsigned long long>(n.eng(1).link().stats().hs_completed),
                static_cast<unsigned long long>(last_counter), static_cast<unsigned long long>(n.snap(2).polls),
                static_cast<unsigned long long>(n.snap(2).missed_windows));
    LM_CHECK_EQ(monotone_violations, 0u);
    LM_CHECK(last_counter >= 1000);                                     // the counter kept counting over 1000 wakes
    LM_CHECK_EQ(n.eng(2).power().stats().sessions_dropped, 0u);
    LM_CHECK_EQ(n.eng(2).power().stats().sessions_kept, 1000u);
    LM_CHECK(n.snap(2).handshake_count <= hs0 + 1);                     // at most the scheduled key rotation
    LM_CHECK(n.eng(1).link().stats().hs_completed <= rl_hs0 + 1);
    LM_CHECK_EQ(n.snap(2).missed_windows, 0u);
    LM_CHECK(n.ready(2));
    // A frame recorded a thousand wakes ago is authentic, old and outside the replay window: it opens no window.
    const uint64_t served = n.eng(1).power().stats().polls_served;
    const uint64_t old0 = n.eng(1).link().stats().rx_replay_old;
    n.world.inject(n.node(2).radio.mac(), 2, n.node(1).radio.mac(), ByteView{replay.data(), replay.size()});
    n.run_ms(200);
    LM_CHECK_EQ(n.eng(1).power().stats().polls_served, served);
    LM_CHECK_EQ(n.eng(1).link().stats().rx_replay_old, old0 + 1);
}

LM_TEST("LP09 sim: after a deep sleep the node runs a fresh EDHOC, needs no new approval, and old SID/ciphertext are dead") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    n.form();
    n.apply_policy(2, report_long());
    LM_CHECK(n.until([&] { return n.eng(2).power().stats().grants >= 1; }, 2000));
    const Bytes old_up = n.sealed_poll(2, 1);   // leaf -> relay under the session that dies with the sleep
    const Bytes old_down = n.sealed_poll(1, 2); // relay -> leaf under the same session
    const unsigned ledger_entries = active_members(n);
    LM_CHECK_EQ(n.sleep_now(2, LM_SLEEP_DEEP, LM_WAKE_TIMER, 60'000, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK);
    n.run_ms(500);
    LM_CHECK(n.node(2).deep_sleeping());
    LM_CHECK(!n.node(2).powered()); // the RAM (keys, counters, replay window) is gone
    n.run_ms(59'800);
    n.await_boot(2, 5'000);
    LM_CHECK_EQ(n.snap(2).wake_reason, static_cast<uint32_t>(pw::kTimer));
    LM_CHECK(n.eng(2).power().last_session_path() == pw::SessionPath::FreshEdhoc);
    LM_CHECK(n.until([&] { return n.ready(2) && n.eng(2).power().stats().grants >= 1; }, 60'000));
    LM_CHECK(n.snap(2).handshake_count >= 1);          // a full handshake happened, on the new incarnation
    LM_CHECK(n.eng(2).link().stats().hs_completed >= 1);
    LM_CHECK_EQ(active_members(n), ledger_entries); // no new approval: the ledger is what it was
    lm_membership_t mem{};
    mem.struct_size = sizeof(mem);
    mem.abi_version = LM_ABI_VERSION;
    LM_CHECK_EQ(lm_membership_get(n.ctx(2), &mem), LM_STATUS_OK);
    LM_CHECK_EQ(mem.state, static_cast<uint32_t>(LM_ACTIVE));
    // The old SID: an authentic-looking frame of the dead session reaches nothing (the replaced session at the
    // parent only receives for a 10 s grace, and this one waits longer).
    n.run_ms(15'000);
    const uint64_t up0 = n.eng(1).link().stats().rx_unknown_sid;
    const uint64_t dn0 = n.eng(2).link().stats().rx_unknown_sid;
    const uint64_t served = n.eng(1).power().stats().polls_served;
    n.world.inject(n.node(2).radio.mac(), 2, n.node(1).radio.mac(), ByteView{old_up.data(), old_up.size()});
    n.world.inject(n.node(1).radio.mac(), 1, n.node(2).radio.mac(), ByteView{old_down.data(), old_down.size()});
    n.run_ms(200);
    LM_CHECK(n.eng(1).link().stats().rx_unknown_sid + n.eng(1).link().stats().rx_auth_fail >= up0 + 1);
    LM_CHECK(n.eng(2).link().stats().rx_unknown_sid + n.eng(2).link().stats().rx_auth_fail >= dn0 + 1);
    LM_CHECK_EQ(n.eng(1).power().stats().polls_served, served);
}

LM_TEST("LP12 sim: sleeping past a key or authorization lifetime restores nothing; membership is never erased") {
    // (a) 70 min asleep > 1 h key lifetime: fresh EDHOC, the node comes back.
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    n.form();
    n.apply_policy(2, report_long());
    LM_CHECK(n.until([&] { return n.eng(2).power().stats().grants >= 1; }, 2000));
    LM_CHECK_EQ(n.sleep_now(2, LM_SLEEP_LIGHT, LM_WAKE_TIMER, 70 * 60'000, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK);
    const int64_t life = n.eng(2).power().last_sleep_life_ms();
    n.run_ms(70 * 60'000 + 500);
    LM_CHECK(life > 0 && life < 70 * 60'000);
    LM_CHECK(n.eng(2).power().last_session_path() == pw::SessionPath::FreshEdhoc);
    LM_CHECK_EQ(n.eng(2).power().stats().sessions_dropped, 1u);
    LM_CHECK(n.until([&] { return n.ready(2); }, 90'000));
    LM_CHECK(n.eng(2).link().stats().hs_completed >= 1);
    lm_membership_t mem{};
    mem.struct_size = sizeof(mem);
    mem.abi_version = LM_ABI_VERSION;
    LM_CHECK_EQ(lm_membership_get(n.ctx(2), &mem), LM_STATUS_OK);
    LM_CHECK_EQ(mem.state, static_cast<uint32_t>(LM_ACTIVE));
    // (b) authorization (MemberCredential lease) of 20 min, 30 min asleep: nothing is restored. The relay admits the
    // node only to be renewed (restricted, short: S18-D2), the root renews it by its ledger, and the renewed
    // credential - never the old lease - brings it back; the membership record stays ACTIVE (docs/20 §7, LP12).
    PNet m({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf, 1'200'000}});
    m.form();
    m.apply_policy(2, report_long());
    LM_CHECK(m.until([&] { return m.eng(2).power().stats().grants >= 1; }, 2000));
    LM_CHECK_EQ(m.sleep_now(2, LM_SLEEP_LIGHT, LM_WAKE_TIMER, 30 * 60'000, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK);
    const int64_t life_b = m.eng(2).power().last_sleep_life_ms();
    m.run_ms(30 * 60'000 + 500);
    LM_CHECK(life_b > 0 && life_b < 30 * 60'000);
    LM_CHECK(m.eng(2).power().last_session_path() == pw::SessionPath::FreshEdhoc);
    LM_CHECK(m.until([&] {
        return m.ready(2) && m.eng(2).identity().member().lease_expires_root_ms > m.root_ms();
    }, 120'000));
    LM_CHECK(m.eng(1).link().stats().renew_only >= 1u);
    LM_CHECK(m.eng(2).membership().stats().renewals >= 1u);
    LM_CHECK_EQ(lm_membership_get(m.ctx(2), &mem), LM_STATUS_OK);
    LM_CHECK_EQ(mem.state, static_cast<uint32_t>(LM_ACTIVE));
}

LM_TEST("LP13 sim: only the parent restarts; the leaf makes that one session again, no Join, no other handshake") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    n.form();
    n.apply_policy(2, report_long());
    LM_CHECK(n.until([&] { return n.eng(2).power().stats().grants >= 1; }, 2000));
    LM_CHECK_EQ(n.sleep_now(2, LM_SLEEP_LIGHT, LM_WAKE_TIMER, 60'000, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK);
    const uint64_t end_started = n.eng(2).delivery().end_stats().started;
    const uint64_t hs_started = n.eng(2).link().stats().hs_started;
    n.run_ms(1'000);
    n.node(1).power_cut();
    n.node(1).store.power_restore();
    n.boot(1);
    n.set_time_at(1);
    n.run_ms(60'000);
    LM_CHECK(!n.asleep(2));
    // The old peer SID is asked: two polls, no GRANT, and only then is the parent's session made again.
    LM_CHECK(n.until([&] { return n.ready(2) && n.eng(2).power().stats().grants >= 2; }, 90'000));
    LM_CHECK(n.eng(2).power().stats().missed_windows >= 1);
    LM_CHECK_EQ(n.eng(2).link().stats().hs_started, hs_started + 1);          // exactly the parent's session
    LM_CHECK_EQ(n.eng(2).delivery().end_stats().started, end_started);        // the end session with the root stayed
    lm_membership_t mem{};
    mem.struct_size = sizeof(mem);
    mem.abi_version = LM_ABI_VERSION;
    LM_CHECK_EQ(lm_membership_get(n.ctx(2), &mem), LM_STATUS_OK);
    LM_CHECK_EQ(mem.state, static_cast<uint32_t>(LM_ACTIVE));
    LM_CHECK_EQ(active_members(n), 2u);                        // the root's member list did not change
}

LM_TEST("LP03 GS12 sim: a DURABLE report is journalled before the sleep, survives a deep sleep, converges once, no false success") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    n.form();
    n.apply_policy(2, report_long());
    LM_CHECK(n.until([&] { return n.eng(2).power().stats().grants >= 1; }, 2000));
    n.link(0, 1, false); // the root cannot be reached: the report cannot complete in this episode
    const Bytes body = payload_of(70, 60);
    const auto s = n.send(2, 0, LM_RECEIVED, body, 600'000, LM_DURABLE);
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.has(2, s.op, lm::delivery::ev::persisted); }, 2000)); // the origin's own journal
    lm_message_ref_t ref{};
    {
        const lm_operation_t o = n.op(2, s.op);
        std::memcpy(ref.origin.bytes, n.id(2).bytes.data(), 32);
        ref.assignment_generation = 1;
        ref.id = o.message_id;
        std::memcpy(ref.intent_hash, o.intent_hash, 32);
    }
    // SAVE_AND_SLEEP: the episode ends with the report unfinished; the sleep is allowed once the journal has it.
    LM_CHECK_EQ(n.sleep_now(2, LM_SLEEP_DEEP, LM_WAKE_TIMER, 60'000, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK);
    n.run_ms(5);
    LM_CHECK(n.node(2).deep_sleeping());
    n.link(0, 1, true);
    n.run_ms(59'800);
    n.await_boot(2, 5'000);
    // The message is back from the journal with its MessageId, persisted, and not "received" by anybody yet.
    lm_operation_t rec{};
    rec.struct_size = sizeof(rec);
    rec.abi_version = LM_ABI_VERSION;
    LM_CHECK(n.until([&] { return lm_get_message(n.ctx(2), &ref, &rec) == LM_STATUS_OK; }, 3000));
    LM_CHECK((rec.evidence_bits & lm::delivery::ev::persisted) != 0);
    LM_CHECK(rec.outcome != LM_OUTCOME_RECEIVED);
    LM_CHECK(n.until([&] { return lm_get_message(n.ctx(2), &ref, &rec) == LM_STATUS_OK && rec.outcome == LM_OUTCOME_RECEIVED; }, 120'000));
    LM_CHECK((rec.evidence_bits & lm::delivery::ev::end_received) != 0);
    Bytes got;
    LM_CHECK(n.pop_message(0, got));
    LM_CHECK(got == body);
    LM_CHECK(!n.pop_message(0, got)); // once
    // Then it sleeps again.
    LM_CHECK(n.until([&] { return n.eng(2).power().state() == power::Power::State::Running && n.eng(2).power().poll_done(); }, 30'000));
    lm_status_t st = LM_STATUS_SLEEP_TICKET_STALE;
    for (unsigned tries = 0; tries < 8 && st == LM_STATUS_SLEEP_TICKET_STALE; ++tries) {
        st = n.sleep_now(2, LM_SLEEP_LIGHT, LM_WAKE_TIMER, 60'000, LM_PENDING_REQUIRE_SETTLED);
    }
    LM_CHECK_EQ(st, LM_STATUS_OK);
    LM_CHECK(n.asleep(2));
}

LM_TEST("LP06 sim: 24 h without any parent: the radio time spent searching stays inside the hourly budget, the backoff grows") {
    PNet n({Spec{}, Spec{Role::Leaf}});
    n.link(0, 1, false); // no parent, no channel to try: nothing to find
    n.boot_all();
    n.set_time();
    n.run_ms(500);
    n.apply_policy(1, k_report); // 60 s of radio per hour, 1 s of search per episode
    const uint64_t t0 = n.world.now_us();
    uint64_t hour_start_on = n.snap(1).radio_on_us;
    uint64_t worst_hour_us = 0;
    for (unsigned hour = 0; hour < 24; ++hour) {
        n.app_cycle(1, 30'000, t0 + (hour + 1) * 3'600'000'000ULL); // the application sleeps 30 s after each episode
        const uint64_t on = n.snap(1).radio_on_us;
        worst_hour_us = std::max(worst_hour_us, on - hour_start_on);
        hour_start_on = on;
    }
    const auto &st = n.eng(1).power().stats();
    std::printf("  LP06-sim (SYNTHETIC radio-on model, no current): worst hour %llu ms of 60000 ms budget, episodes %llu, wakes denied %llu, overruns %llu\n",
                static_cast<unsigned long long>(worst_hour_us / 1000), static_cast<unsigned long long>(st.episodes),
                static_cast<unsigned long long>(st.wake_denied), static_cast<unsigned long long>(st.overruns));
    LM_CHECK(worst_hour_us <= 63'000'000ULL);            // the budget plus one episode of overshoot
    LM_CHECK(st.wake_denied > 0);                       // the backoff and the budget withheld the radio
    LM_CHECK(st.episodes < 24U * 60U);                  // far fewer radio episodes than 30 s wakes (2880)
    LM_CHECK_EQ(st.overruns, 0u);
    lm_membership_t mem{};
    mem.struct_size = sizeof(mem);
    mem.abi_version = LM_ABI_VERSION;
    LM_CHECK_EQ(lm_membership_get(n.ctx(1), &mem), LM_STATUS_OK);
    LM_CHECK_EQ(mem.state, static_cast<uint32_t>(LM_ACTIVE)); // a hint that led nowhere never removes the membership
    // The parent comes back: the next episode finds it (the budget is refilled by then), nothing else changed.
    n.link(0, 1, true);
    n.app_cycle(1, 30'000, n.world.now_us() + 3'700'000'000ULL);
    LM_CHECK(n.ready(1));
}

LM_TEST("LP07 sim: unplanned wakes beyond the daily quota get no radio, no transmission, and say what was lost") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    n.form();
    pw::Policy pol = report_long();
    pol.extra_wakes_per_day = 3;
    n.apply_policy(2, pol);
    n.app_cycle(2, 60'000, n.world.now_us() + 25ULL * 3'600'000'000ULL); // a day of ordinary life refills the (conservative) quota
    n.set_time(); // (the root clock estimate of every node is refreshed once a day here)
    n.wake_up(2);
    LM_CHECK(n.ready(2));
    unsigned allowed = 0;
    unsigned denied = 0;
    const uint64_t denied0 = n.eng(2).power().stats().wake_denied;
    (void)n.power_events(2, pw::kWakeDenied);
    const unsigned ev0 = n.power_events(2, pw::kWakeDenied);
    for (unsigned k = 0; k < 10; ++k) { // a storm of external interrupts, one per second
        LM_CHECK_EQ(n.sleep_now(2, LM_SLEEP_LIGHT, LM_WAKE_EXTERNAL, 0, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK);
        const uint64_t on_before = n.snap(2).radio_on_us;
        const uint64_t tx_before = n.node(2).radio.tx_done_dropped();
        n.run_ms(300);
        n.node(2).wake_external();
        n.run_ms(300);
        if (n.asleep(2)) { // radio withheld
            ++denied;
            LM_CHECK_EQ(n.snap(2).state, static_cast<uint32_t>(LM_POWER_BUDGET_BLOCKED));
            LM_CHECK_EQ(n.snap(2).last_reason, static_cast<uint32_t>(pw::kWakeDenied));
            LM_CHECK_EQ(n.snap(2).radio_on_us, on_before);           // no radio time
            LM_CHECK_EQ(n.node(2).radio.tx_done_dropped(), tx_before); // nothing sent
            LM_CHECK_EQ(n.send(2, 0, LM_RECEIVED, payload_of(1)).st, LM_STATUS_POWER_BUDGET_EXHAUSTED);
        } else {
            ++allowed;
            LM_CHECK(n.snap(2).radio_on_us > on_before);
        }
        n.run_ms(400);
        (void)n.power_events(2, pw::kWakeDenied); // the application reads its events
    }
    LM_CHECK_EQ(allowed, 3u);
    LM_CHECK_EQ(denied, 7u);
    LM_CHECK_EQ(n.eng(2).power().stats().wake_denied - denied0, 7u);
    LM_CHECK_EQ(n.power_events(2, pw::kWakeDenied) - ev0, 7u); // the application is told every time
}

LM_TEST("LP20 sim: without proven RTC continuity a cold boot starts with no budget left; a deep sleep with continuity keeps it") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    n.form();
    n.apply_policy(2, report_long()); // 3 600 000 ms/h: leaves no doubt what "remaining" means
    pw::Policy pol = k_report;
    pol.awake_budget_ms = 20000;
    pol.search_budget_ms = 12000;
    n.apply_policy(2, pol); // 60 000 ms per hour
    n.app_cycle(2, 60'000, n.world.now_us() + 3'601'000'000ULL); // an hour of ordinary cycles, attached: the budget is whole
    n.wake_up(2);
    LM_CHECK(n.snap(2).offline_budget_remaining_ms >= 59'000u);
    // Deep sleep with a timer: the RTC keeps counting, the budget survives (and refills with the time slept).
    LM_CHECK_EQ(n.sleep_now(2, LM_SLEEP_DEEP, LM_WAKE_TIMER, 600'000, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK);
    n.run_ms(600'500);
    n.await_boot(2, 5'000);
    LM_CHECK(n.snap(2).offline_budget_remaining_ms >= 59'000u);
    // The RTC is not trusted (elapsed time unknown): the boot episode is granted, the remaining budget is zero.
    n.node(2).pm.elapsed_known = false;
    LM_CHECK(n.until([&] { return n.ready(2); }, 30'000));
    LM_CHECK_EQ(n.sleep_now(2, LM_SLEEP_DEEP, LM_WAKE_TIMER, 30'000, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK);
    n.run_ms(30'500);
    n.await_boot(2, 5'000);
    LM_CHECK_EQ(n.snap(2).offline_budget_remaining_ms, 0u);
    // Cold boot (power on: no retained memory): the same, and the boot episode can still search. (The power comes back
    // after the parent's one-handshake-per-30-s gate for this peer has run out: this test is about the budget.)
    n.run_ms(31'000);
    n.node(2).pm.elapsed_known = true;
    n.node(2).pm.clear_retained();
    n.node(2).power_cut();
    n.node(2).store.power_restore();
    n.boot(2);
    n.set_time_at(2);
    LM_CHECK_EQ(n.snap(2).offline_budget_remaining_ms, 0u);
    LM_CHECK(n.until([&] { return n.ready(2); }, 60'000)); // the boot episode found its parent although the budget said 0
    // The budget refills with observed time: after 30 min of uptime about half of it is back.
    n.app_cycle(2, 60'000, n.world.now_us() + 1'800'000'000ULL);
    LM_CHECK(n.snap(2).offline_budget_remaining_ms >= 28'000 && n.snap(2).offline_budget_remaining_ms <= 32'000);
}

// ---- tests/power_golden.json replayed through the engine ------------------------------------------------------------
struct GoldenCase {
    std::string cause, expected;
    bool complete = false, peer_valid = false, elapsed_known = false;
    int64_t elapsed = 0, auth = 0, key = 0;
};

// The file is fixed-format JSON; each case is one flat object after "session_cases".
std::vector<GoldenCase> load_golden() {
    std::ifstream f(LM_POWER_GOLDEN);
    std::stringstream ss;
    ss << f.rdbuf();
    const std::string all = ss.str();
    std::vector<GoldenCase> out;
    std::size_t at = all.find("\"session_cases\"");
    auto value = [&](const std::string &obj, const char *key) {
        const std::size_t k = obj.find(std::string("\"") + key + "\"");
        std::size_t v = obj.find(':', k) + 1;
        while (obj[v] == ' ') {
            ++v;
        }
        std::size_t e = obj.find_first_of(",\n}", v);
        std::string r = obj.substr(v, e - v);
        if (!r.empty() && r[0] == '"') {
            r = r.substr(1, r.size() - 2);
        }
        return r;
    };
    while (at != std::string::npos && (at = all.find('{', at + 1)) != std::string::npos) {
        const std::size_t end = all.find('}', at);
        const std::string obj = all.substr(at, end - at + 1);
        GoldenCase c;
        c.cause = value(obj, "reset_cause");
        c.complete = value(obj, "complete_ram_state") == "true";
        c.peer_valid = value(obj, "peer_session_valid") == "true";
        c.elapsed_known = value(obj, "elapsed_upper_ms") != "null";
        c.elapsed = c.elapsed_known ? std::stoll(value(obj, "elapsed_upper_ms")) : 0;
        c.auth = std::stoll(value(obj, "authorization_remaining_ms"));
        c.key = std::stoll(value(obj, "key_remaining_ms"));
        c.expected = value(obj, "expected");
        out.push_back(c);
        at = end;
    }
    return out;
}

LM_TEST("LP08 LP09 sim: every session case of tests/power_golden.json gives the same answer in the spec model and in the engine") {
    const std::vector<GoldenCase> cases = load_golden();
    LM_CHECK_EQ(cases.size(), 7u);
    unsigned idx = 0;
    for (const GoldenCase &c : cases) {
        ++idx;
        // The pure decision (the spec model in src/core/power/policy.hpp) ...
        pw::ResumeFacts f;
        f.cause = c.cause == "LIGHT_WAKE" ? pw::Wake::LightWake : (c.cause == "MODEM_WINDOW" ? pw::Wake::ModemWindow : pw::Wake::DeepWake);
        f.complete_ram_state = c.complete;
        f.peer_session_valid = c.peer_valid;
        f.elapsed_known = c.elapsed_known;
        f.elapsed_upper_ms = static_cast<uint64_t>(c.elapsed);
        f.authorization_remaining_ms = c.auth;
        f.key_remaining_ms = c.key;
        const bool want_reuse = c.expected == "RAM_REUSE";
        LM_CHECK_EQ(pw::session_path(f) == pw::SessionPath::RamReuse, want_reuse);
        // ... and what the real engine does when the same facts are produced on a live node.
        Spec leaf{Role::Leaf, 905'000}; // authorization: 900 s left at the sleep, key life longer
        PNet n({Spec{}, Spec{Role::Relay}, leaf});
        n.form();
        pw::Policy pol = c.cause == "MODEM_WINDOW" ? k_windowed : report_long();
        n.apply_policy(2, pol);
        LM_CHECK(n.until([&] { return n.eng(2).power().stats().grants >= 1; }, 3000));
        n.node(2).pm.ram_complete = c.complete;
        n.node(2).pm.elapsed_known = c.elapsed_known;
        const uint64_t hs0 = n.eng(2).link().stats().hs_started;
        // elapsed relation to min(authorization, key) is what the case is about; the engine sleeps that long.
        const bool reaches = c.elapsed_known && c.elapsed >= std::min(c.auth, c.key);
        const uint64_t sleep_ms = reaches ? 1'000'000 : 5'000; // 1000 s > the 900 s of authorization that are left
        bool fresh = false;
        if (c.cause == "MODEM_WINDOW") { // the engine's own window cycle: sleeps happen by themselves
            LM_CHECK(n.until([&] { return n.eng(2).power().stats().sleeps >= 2 && !n.asleep(2); }, 20'000));
            fresh = n.eng(2).power().last_session_path() == pw::SessionPath::FreshEdhoc;
        } else if (c.cause == "DEEP_WAKE") {
            LM_CHECK_EQ(n.sleep_now(2, LM_SLEEP_DEEP, LM_WAKE_TIMER, sleep_ms, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK);
            n.run_ms(sleep_ms + 200);
            n.await_boot(2, 5'000);
            (void)n.until([&] { return n.ready(2); }, 60'000);
            fresh = n.eng(2).link().stats().hs_started >= 1 && n.eng(2).power().last_session_path() == pw::SessionPath::FreshEdhoc;
        } else {
            if (!c.peer_valid) { // the parent alone forgot the session while the leaf slept
                LM_CHECK_EQ(n.sleep_now(2, LM_SLEEP_LIGHT, LM_WAKE_TIMER, sleep_ms, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK);
                n.run_ms(500);
                n.node(1).power_cut();
                n.node(1).store.power_restore();
                n.boot(1);
                n.set_time_at(1);
                n.run_ms(sleep_ms);
                (void)n.until([&] { return n.ready(2) && n.eng(2).power().stats().grants >= 2; }, 90'000);
                fresh = n.eng(2).link().stats().hs_started > hs0 || n.eng(2).power().stats().missed_windows > 0;
            } else {
                LM_CHECK_EQ(n.sleep_now(2, LM_SLEEP_LIGHT, LM_WAKE_TIMER, sleep_ms, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK);
                n.run_ms(sleep_ms + 200);
                fresh = n.eng(2).power().last_session_path() == pw::SessionPath::FreshEdhoc;
                if (!fresh) {
                    LM_CHECK_EQ(n.eng(2).link().stats().hs_started, hs0); // reuse: no handshake, at all
                }
            }
        }
        std::printf("  golden case %u (%s, ram %d, peer %d, elapsed %s): expected %s, engine %s\n", idx, c.cause.c_str(), (int)c.complete, (int)c.peer_valid,
                    c.elapsed_known ? "known" : "null", c.expected.c_str(), fresh ? "FRESH_EDHOC" : "RAM_REUSE");
        LM_CHECK_EQ(!fresh, want_reuse);
    }
}

LM_TEST("LP11 sim: a 20-hop DURABLE report whose receipt is not back when the budget ends: original kept, same id next wake, no false success") {
    std::vector<Spec> specs(21, Spec{Role::Relay});
    specs[0] = Spec{};
    specs[20] = Spec{Role::Leaf};
    PNet n(specs);
    n.form(150'000);
    { Bytes drop; while (n.pop_message(0, drop)) {} } // the root's event queue holds 20 nodes' formation events
    pw::Policy pol = report_long();
    pol.awake_budget_ms = 150000; // an authentication over 20 hops needs a long episode (no guarantee is given, docs/20 §2)
    pol.search_budget_ms = 100000;
    n.apply_policy(20, pol);
    LM_CHECK(n.until([&] { return n.eng(20).power().stats().grants >= 1; }, 5000));
    n.link(10, 11, false); // the receipt cannot come back through the middle of the chain
    const Bytes body = payload_of(90, 60);
    const auto s = n.send(20, 0, LM_RECEIVED, body, 900'000, LM_DURABLE);
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.has(20, s.op, lm::delivery::ev::persisted); }, 3000));
    n.run_ms(1500);
    lm_message_ref_t ref{};
    {
        const lm_operation_t o = n.op(20, s.op);
        std::memcpy(ref.origin.bytes, n.id(20).bytes.data(), 32);
        ref.assignment_generation = 1;
        ref.id = o.message_id;
        std::memcpy(ref.intent_hash, o.intent_hash, 32);
        LM_CHECK((o.evidence_bits & lm::delivery::ev::hop_accepted) != 0); // the first hop took it: HOP_ACCEPTED only
        LM_CHECK((o.evidence_bits & lm::delivery::ev::end_received) == 0);
        LM_CHECK(o.outcome != LM_OUTCOME_RECEIVED);
    }
    const uint64_t on_before = n.snap(20).radio_on_us;
    LM_CHECK_EQ(n.sleep_now(20, LM_SLEEP_DEEP, LM_WAKE_TIMER, 120'000, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK);
    n.run_ms(5);
    n.link(10, 11, true); // (the network heals while the leaf sleeps)
    n.run_ms(119'800);
    n.await_boot(20, 5'000);
    lm_operation_t rec{};
    rec.struct_size = sizeof(rec);
    rec.abi_version = LM_ABI_VERSION;
    LM_CHECK(n.until([&] { return lm_get_message(n.ctx(20), &ref, &rec) == LM_STATUS_OK; }, 3000));
    LM_CHECK(rec.outcome != LM_OUTCOME_RECEIVED); // the journal brought it back as it was: not delivered
    for (unsigned k = 0; k < 600 && !(lm_get_message(n.ctx(20), &ref, &rec) == LM_STATUS_OK && rec.outcome == LM_OUTCOME_RECEIVED); ++k) {
        n.app_cycle(20, 60'000, n.world.now_us() + 1'000'000); // the receipt waits at the parent until the next poll
    }
    LM_CHECK(rec.outcome == LM_OUTCOME_RECEIVED);
    Bytes got;
    LM_CHECK(n.until([&] { return n.pop_message(0, got); }, 5'000, 50));
    LM_CHECK(got == body);
    LM_CHECK(!n.pop_message(0, got));
    std::printf("  LP11-sim: 21 nodes / 20 hops; radio-on model of the leaf before its first sleep: %llu ms (SYNTHETIC)\n", static_cast<unsigned long long>(on_before / 1000));
}

// ---- external review FIX3 (gpt-5.6-sol on 3596820) ---------------------------------------------------------------------

// FIX3-D1: extra_event_radio_ms_per_day is milliseconds and the bucket counts microseconds.
LM_TEST("FIX3-3 sim: 120 s of unplanned radio time exhaust extra_event_radio_ms_per_day = 120000") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    n.form();
    pw::Policy pol = report_long();
    pol.extra_wakes_per_day = 32;
    pol.extra_radio_ms_per_day = 120000;
    n.apply_policy(2, pol);
    n.app_cycle(2, 60'000, n.world.now_us() + 25ULL * 3'600'000'000ULL); // a day of ordinary life: every bucket is refilled
    n.set_time();
    n.wake_up(2);
    LM_CHECK(n.ready(2));
    LM_CHECK_EQ(n.sleep_now(2, LM_SLEEP_LIGHT, LM_WAKE_EXTERNAL, 0, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK);
    n.run_ms(300);
    n.node(2).wake_external();
    n.run_ms(300);
    LM_CHECK(!n.asleep(2)); // the first unplanned wake is inside the quota
    n.run_ms(125'000);      // 125 s of radio time in an unplanned episode
    LM_CHECK_EQ(n.sleep_now(2, LM_SLEEP_LIGHT, LM_WAKE_EXTERNAL, 0, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK);
    n.run_ms(300);
    n.node(2).wake_external();
    n.run_ms(300);
    LM_CHECK(n.asleep(2)); // 120 000 ms are used up: the radio stays off (before the fix the limit was ~33 h)
    LM_CHECK_EQ(n.snap(2).last_reason, static_cast<uint32_t>(pw::kWakeDenied));
}

// FIX3-D2: a cold boot has no continuity: every bucket is used up against the STORED policy's limits.
LM_TEST("FIX3-4 sim: a cold boot with stored limits above the defaults starts with nothing left") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    n.form();
    pw::Policy pol = report_long(); // 3 600 000 ms/h offline: far above the 60 000 of the ALWAYS_RX defaults
    pol.extra_wakes_per_day = 100;
    pol.extra_radio_ms_per_day = 3'600'000;
    n.apply_policy(2, pol);
    n.app_cycle(2, 10'000, n.world.now_us() + 120'000'000ULL); // ordinary cycles: the parent's state is settled
    n.wake_up(2);
    LM_CHECK(n.until([&] { return n.ready(2); }, 30'000));
    n.node(2).pm.clear_retained();
    n.node(2).power_cut();
    n.node(2).store.power_restore();
    n.boot(2);
    n.set_time_at(2);
    n.run_ms(300); // the stored policy is loaded; the node has only just started to search
    LM_CHECK_EQ(n.policy_of(2).offline_radio_ms_per_hour, 3'600'000u);
    LM_CHECK(n.snap(2).offline_budget_remaining_ms < 1000u); // used up (plus this boot's episode), not 3 540 000
    LM_CHECK(n.until([&] { return n.ready(2); }, 60'000)); // the boot episode still finds its parent
    LM_CHECK_EQ(n.sleep_now(2, LM_SLEEP_LIGHT, LM_WAKE_EXTERNAL, 0, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK);
    n.run_ms(300);
    n.node(2).wake_external();
    n.run_ms(300);
    LM_CHECK(n.asleep(2)); // no wake credit after a power cut: 100 wakes/day would have allowed it against the defaults
    LM_CHECK_EQ(n.snap(2).last_reason, static_cast<uint32_t>(pw::kWakeDenied));
}

// FIX6-D3: a Deep Sleep wake by an external source is the same unplanned wake as a Light one: it is admitted against the
// retained quota and charged once; beyond the quota the radio stays off (BudgetBlocked, kWakeDenied), nothing is sent.
LM_TEST("FIX6 sim: repeated external Deep Sleep wakes are charged against the retained quota; beyond it the radio stays off") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    n.form();
    pw::Policy pol = report_long();
    pol.extra_wakes_per_day = 2;
    n.apply_policy(2, pol);
    n.app_cycle(2, 60'000, n.world.now_us() + 25ULL * 3'600'000'000ULL); // a day of ordinary life: the quota is whole
    n.set_time();
    n.wake_up(2);
    LM_CHECK(n.ready(2));
    unsigned allowed = 0;
    unsigned denied = 0;
    for (unsigned k = 0; k < 6; ++k) {
        LM_CHECK_EQ(n.sleep_now(2, LM_SLEEP_DEEP, LM_WAKE_EXTERNAL, 0, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK);
        n.run_ms(300);
        n.node(2).wake_external();
        n.run_ms(600);
        LM_CHECK(n.node(2).powered());
        if (n.eng(2).radio_state() == RadioState::Running) {
            ++allowed;
            continue;
        }
        ++denied;
        LM_CHECK(n.asleep(2));
        LM_CHECK_EQ(n.snap(2).state, static_cast<uint32_t>(LM_POWER_BUDGET_BLOCKED));
        LM_CHECK_EQ(n.snap(2).last_reason, static_cast<uint32_t>(pw::kWakeDenied));
        LM_CHECK_EQ(n.node(2).radio.tx_done_dropped(), 0u); // nothing was sent in this boot
    }
    LM_CHECK_EQ(allowed, 2u);
    LM_CHECK_EQ(denied, 4u);
}

// FIX3-D3: a driver that cannot be stopped is not asleep.
LM_TEST("FIX3-6 sim: a radio driver that will not stop means no sleep: locks kept, ticket spent, the port never sleeps") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    n.form();
    n.apply_policy(2, report_long());
    const auto p = n.prepare(2, LM_SLEEP_LIGHT, LM_WAKE_TIMER, 30'000, LM_PENDING_SAVE_AND_SLEEP);
    LM_CHECK_EQ(p.st, LM_STATUS_OK);
    lm_sleep_ticket_t t{};
    LM_CHECK_EQ(n.get_ticket(2, p, t), LM_STATUS_OK);
    n.node(2).radio.stop_fault_count = 1;
    LM_CHECK(lm_sleep_enter(n.ctx(2), &t) != LM_STATUS_OK);
    n.run_ms(50);
    LM_CHECK_EQ(n.node(2).pm.sleep_calls(), 0u);                       // pm->sleep() was never called
    LM_CHECK((n.node(2).pm.locks() & port::pm_lock::episode) != 0);    // the locks were not released
    LM_CHECK(n.snap(2).state != static_cast<uint32_t>(LM_POWER_SLEEPING));
    LM_CHECK_EQ(lm_sleep_enter(n.ctx(2), &t), LM_STATUS_SLEEP_TICKET_STALE); // the ticket is spent
}

// FIX3-D5: PREPARED / COMMITTED but not switched: the node has promised to be on the air.
LM_TEST("FIX3-7 sim: an unsettled channel plan vetoes the sleep ticket; a settled one does not") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}}, 61, 2000, true);
    n.form();
    LM_CHECK(n.until([&] { return n.eng(0).chan().loaded() && n.eng(2).chan().stats().time_updates > 0; }, 60'000, 20));
    LM_CHECK_OK(n.eng(0).coordinator().plan_to(11, n.now(0)));
    n.node(0).notify();
    LM_CHECK(n.until([&] { return n.eng(1).chan().have_plan(); }, 20'000, 20));
    n.apply_policy(2, report_long()); // its episode polls the parent, which then hands over the PREPARE it holds
    LM_CHECK(n.until([&] { return n.eng(2).chan().have_plan(); }, 20'000, 20));
    // READY was sent: the node sleeping now would be stranded before COMMIT.
    uint32_t reason = 0;
    for (unsigned k = 0; k < 3 && reason != static_cast<uint32_t>(LM_STATUS_POWER_BUDGET_EXHAUSTED); ++k) {
        const auto p = n.prepare(2, LM_SLEEP_LIGHT, LM_WAKE_TIMER, 30'000, LM_PENDING_SAVE_AND_SLEEP, 1000);
        LM_CHECK_EQ(p.st, LM_STATUS_OK);
        LM_CHECK(n.until([&] { return n.op(2, p.op).phase == 3; }, 3000, 5));
        reason = n.op(2, p.op).reason;
        LM_CHECK(reason != 0); // never a ticket while the plan is unsettled (a stale ticket is a veto too, but only a transient one)
    }
    LM_CHECK_EQ(reason, static_cast<uint32_t>(LM_STATUS_POWER_BUDGET_EXHAUSTED));
    LM_CHECK(!n.asleep(2));
    // ... and the plan runs to its end; then sleeping is allowed again.
    LM_CHECK(n.until([&] { return !n.eng(2).chan().have_plan() && n.eng(2).chan().current() == 11; }, 400'000, 100));
    n.set_time();
    LM_CHECK_EQ(n.sleep_now(2, LM_SLEEP_LIGHT, LM_WAKE_TIMER, 30'000, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK);
}

// FIX3-D4: the lock level the port confirms is what counts, not what was asked.
LM_TEST("FIX3-15 sim: a PM lock the port could not take blocks new work and is asked for again; one it could not release blocks a light sleep") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    n.form();
    n.apply_policy(2, report_long());
    // Acquire fails at the wake: the episode is unlocked, so new sends are refused (fail closed) until it is confirmed.
    LM_CHECK_EQ(n.sleep_now(2, LM_SLEEP_LIGHT, LM_WAKE_TIMER, 5000, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK);
    n.node(2).pm.take_fail = port::pm_lock::episode;
    n.wake_up(2, 20'000);
    LM_CHECK((n.node(2).pm.locks() & port::pm_lock::episode) == 0);
    LM_CHECK(n.eng(2).power().stats().lock_faults >= 1u);
    LM_CHECK_EQ(n.send(2, 0, LM_RECEIVED, payload_of(3)).st, LM_STATUS_BUSY);
    n.node(2).pm.take_fail = 0;
    n.run_ms(600); // the retry is a timer of its own, not a side effect of some other event
    LM_CHECK((n.node(2).pm.locks() & port::pm_lock::episode) != 0);
    LM_CHECK_EQ(n.send(2, 0, LM_RECEIVED, payload_of(4)).st, LM_STATUS_OK);
    // Release fails: a LIGHT sleep would keep the CPU up while the node claims to sleep - refused, node stays running.
    n.run_ms(2000);
    n.node(2).pm.drop_fail = port::pm_lock::episode;
    const uint64_t sleeps = n.node(2).pm.sleep_calls();
    LM_CHECK_EQ(n.sleep_now(2, LM_SLEEP_LIGHT, LM_WAKE_TIMER, 5000, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_BUSY);
    LM_CHECK(!n.asleep(2));
    LM_CHECK(n.eng(2).radio_state() == RadioState::Running);
    n.node(2).pm.drop_fail = 0;
    n.run_ms(600);
    LM_CHECK_EQ(n.sleep_now(2, LM_SLEEP_LIGHT, LM_WAKE_TIMER, 5000, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK);
    LM_CHECK_EQ(n.node(2).pm.sleep_calls(), sleeps + 1U);
}

// FIX3-D9: WAIT_WAKE is a target-level state: sleeping targets take no in-flight slot.
LM_TEST("FIX3-9 sim: 4 sleeping and 4 awake group targets: the awake ones finish, the sleepers show WAIT_WAKE and hold no slot") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Relay}, Spec{Role::Relay}, Spec{Role::Relay}, Spec{Role::Leaf}, Spec{Role::Leaf},
            Spec{Role::Leaf}, Spec{Role::Leaf}});
    n.star();
    n.form();
    for (unsigned i = 5; i < 9; ++i) {
        n.apply_policy(i, k_report);
    }
    n.run_ms(1000);
    for (unsigned i = 5; i < 9; ++i) { // the four leaves tell the root when they wake (in ~60 s) and sleep
        LM_CHECK_EQ(n.sleep_now(i, LM_SLEEP_LIGHT, LM_WAKE_TIMER, 60'000, LM_PENDING_SAVE_AND_SLEEP), LM_STATUS_OK);
    }
    n.run_ms(1000);
    std::vector<lm_device_id_t> ids(8);
    for (unsigned k = 0; k < 8; ++k) {
        std::memcpy(ids[k].bytes, n.id(k + 1).bytes.data(), 32);
    }
    lm_operation_id_t setop = 0;
    LM_CHECK_EQ(lm_group_set(n.ctx(0), 5, 0, ids.data(), ids.size(), &setop), LM_STATUS_OK);
    n.node(0).notify();
    n.run_ms(200); // FIX8-D10: the definition is durable (its operation ends) before a send can name its revision
    lm_send_request_t rq{};
    rq.struct_size = sizeof(rq);
    rq.abi_version = LM_ABI_VERSION;
    rq.destination.kind = LM_DEST_GROUP;
    rq.destination.group_id = 5;
    rq.destination.group_revision = 1;
    rq.app_port = 100;
    rq.delivery = LM_RECEIVED;
    rq.storage = LM_VOLATILE;
    rq.priority = LM_PRIORITY_NORMAL;
    rq.queue_mode = LM_FIFO;
    rq.root_term = 1;
    rq.expires_root_ms = n.root_ms() + 300'000;
    const Bytes body = payload_of(9);
    lm_operation_id_t op = 0;
    LM_CHECK_EQ(lm_send(n.ctx(0), &rq, body.data(), body.size(), &op), LM_STATUS_OK);
    n.node(0).notify();
    auto progress = [&] {
        lm_group_progress_t g{};
        g.struct_size = sizeof(g);
        g.abi_version = LM_ABI_VERSION;
        LM_CHECK_EQ(lm_group_progress(n.ctx(0), op, &g), LM_STATUS_OK);
        return g;
    };
    LM_CHECK(n.until([&] { return progress().received == 4; }, 15'000, 20)); // the four awake targets, long before any wake
    const lm_group_progress_t g = progress();
    LM_CHECK_EQ(g.pending, 4u);
    std::array<lm_group_target_t, 16> page{};
    size_t written = 0;
    uint32_t total = 0;
    LM_CHECK_EQ(lm_group_targets(n.ctx(0), op, g.snapshot_token, 0, page.data(), page.size(), &written, &total), LM_STATUS_OK);
    unsigned waiting = 0;
    for (size_t k = 0; k < written; ++k) {
        waiting += page[k].outcome == LM_OUTCOME_PENDING && page[k].phase == LM_TARGET_WAIT_WAKE ? 1U : 0U;
    }
    LM_CHECK_EQ(waiting, 4u);
    for (std::size_t k = 0; k < lm::group::k_ops; ++k) {
        if (n.eng(0).group().op_at(k)->id == op) {
            LM_CHECK_EQ(n.eng(0).group().op_at(k)->live, 0u); // no delivery child, no slot
        }
    }
    // The wake: the sleepers are served too, nobody twice.
    LM_CHECK(n.until([&] { return progress().received == 8; }, 200'000, 100));
}

// FIX10-H9: the root derives the deferred set from its S16 schedule view: a REPORT_ONLY leaf asleep during a plan is
// deferred (docs/20 §9), not a required participant that aborts every plan.
LM_TEST("H9 sim: a REPORT_ONLY leaf asleep during a channel plan - deferred, or required (plan aborts)?") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}}, 61, 2000, true);
    n.form();
    LM_CHECK(n.until([&] {
        return n.eng(0).chan().loaded() && n.eng(1).chan().stats().time_updates > 0 && n.eng(2).chan().stats().time_updates > 0;
    }, 120'000, 20));
    n.apply_policy(2, report_long());
    lm_status_t sl = LM_STATUS_BUSY;
    for (int i = 0; i < 200 && sl != LM_STATUS_OK; ++i) {
        n.run_ms(100);
        sl = n.sleep_now(2, LM_SLEEP_LIGHT, LM_WAKE_TIMER, 1'800'000, LM_PENDING_SAVE_AND_SLEEP); // 30 min between reports
    }
    std::printf("  sleep_now -> %u\n", (unsigned)sl);
    n.run_ms(5000);
    LM_CHECK(n.asleep(2));
    root::RouteGrant g;
    std::printf("  leaf attached at the root while asleep: %d\n",
                n.eng(0).routes().topology().path_from_root(ShortAddr{3}, n.root_ms(), g) == Status::Ok ? 1 : 0);
    const Status st = n.eng(0).coordinator().plan_to(11, n.now(0));
    n.node(0).notify();
    auto v = n.eng(0).coordinator().view();
    std::printf("  plan_to(11) -> %u; required %llx deferred %llx\n", (unsigned)st, (unsigned long long)v.required,
                (unsigned long long)v.deferred);
    LM_CHECK(n.until([&] { return n.eng(0).coordinator().state() == root::CState::Monitor; }, 400'000, 100));
    v = n.eng(0).coordinator().view();
    std::printf("  after: state %u why %u required %llx ready %llx deferred %llx; aborts %u commits %u; root on %u, relay on %u\n",
                (unsigned)v.state, (unsigned)v.why, (unsigned long long)v.required, (unsigned long long)v.ready,
                (unsigned long long)v.deferred, n.eng(0).coordinator().stats().aborts, n.eng(0).coordinator().stats().commits,
                n.eng(0).channel(), n.eng(1).channel());
    LM_CHECK((v.required & (1ULL << (3 - 2))) == 0); // docs/20 §9: a sleeping leaf is deferred, not required
    LM_CHECK_EQ(n.eng(0).channel(), 11);
}


// FIX10-H9: a REPORT_ONLY deep sleeper misses one channel change (deferred because the root sees it sleep). Every cold
// boot is one episode of the policy's search budget; the channel search has to fit into it and continue where it stopped.
void h9_rejoin(const pw::Policy &pol, const char *name, bool change = true, uint8_t target = 11) {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}}, 61, 2000, true);
    n.form();
    LM_CHECK(n.until([&] {
        return n.eng(0).chan().loaded() && n.eng(1).chan().stats().time_updates > 0 && n.eng(2).chan().stats().time_updates > 0;
    }, 120'000, 20));
    n.apply_policy(2, pol);
    lm_status_t sl = LM_STATUS_BUSY;
    for (int i = 0; i < 200 && sl != LM_STATUS_OK; ++i) {
        n.run_ms(100);
        sl = n.sleep_now(2, LM_SLEEP_DEEP, LM_WAKE_TIMER, 600'000, LM_PENDING_SAVE_AND_SLEEP);
    }
    LM_CHECK_EQ(sl, LM_STATUS_OK);
    n.run_ms(5000);
    if (change) {
        LM_CHECK_OK(n.eng(0).coordinator().plan_to(11, n.now(0)));
        n.node(0).notify();
        LM_CHECK(n.until([&] { return n.eng(0).coordinator().state() == root::CState::Monitor && n.eng(0).channel() == 11; }, 500'000, 100));
    }
    unsigned attached_boots = 0;
    bool counted = false;
    // The leaf's application: deep sleep 10 min whenever its episode is over (search/episode budget, or its window).
    bool ever_ready = false;
    bool learned = false; // the stored channel and epoch are the network's (an authenticated word of the root, not a beacon)
    unsigned boots = 0;
    bool was_powered = n.node(2).powered();
    const uint64_t end = n.world.now_us() + 3ULL * 3600 * 1000000;
    while (n.world.now_us() < end) {
        n.run_ms(50);
        const bool p = n.node(2).powered();
        boots += (p && !was_powered) ? 1U : 0U;
        was_powered = p;
        if (!p) {
            counted = false;
            continue;
        }
        const bool r = n.ready(2) && n.eng(2).channel() == target;
        if (r && !counted) {
            ++attached_boots;
            counted = true;
        }
        ever_ready = ever_ready || r;
        learned = learned || (r && n.eng(2).chan().current() == target && n.eng(2).chan().epoch().value() == (change ? 1U : 0U));
        const auto st = n.eng(2).power().state();
        if (st != power::Power::State::Running && st != power::Power::State::BudgetBlocked) {
            continue;
        }
        const unsigned closed = n.power_events(2, pw::kWindowClosed);
        const unsigned ended = n.power_events(2, pw::kSearchBudgetEnd) + n.power_events(2, pw::kEpisodeBudgetEnd) +
                               n.power_events(2, pw::kWakeDenied) + n.power_events(2, pw::kOfflineBudget);
        if ((closed > n.cycles_seen_ && n.ready(2) && n.eng(2).power().poll_done()) || ended > n.search_seen_) {
            if (boots <= 4) {
                const auto sn = n.snap(2);
                std::printf("    boot %u sleeps: closed %u ended %u (search %u episode %u denied %u offline %u) mesh %u radio %u chan loaded %d cur %u scans %u offline_left %u wake_reason %u\n",
                            boots, closed, ended, n.power_events(2, pw::kSearchBudgetEnd), n.power_events(2, pw::kEpisodeBudgetEnd),
                            n.power_events(2, pw::kWakeDenied), n.power_events(2, pw::kOfflineBudget),
                            (unsigned)n.eng(2).mesh().state(), n.eng(2).channel(), n.eng(2).chan().loaded() ? 1 : 0,
                            n.eng(2).chan().current(), n.eng(2).chan().stats().scans, sn.offline_budget_remaining_ms, sn.wake_reason);
            }
            n.cycles_seen_ = closed;
            n.search_seen_ = ended;
            (void)n.sleep_now(2, LM_SLEEP_DEEP, LM_WAKE_TIMER, 600'000, LM_PENDING_SAVE_AND_SLEEP);
        }
    }
    std::printf("  [%s] attached in %u boots;", name, attached_boots);
    std::printf("  [%s] 3 h after the change: leaf boots %u, ever attached on 11: %d; channel stats (last boot): scans %u dwells %u; stored cur %u epoch %u\n",
                name, boots, ever_ready ? 1 : 0, n.node(2).powered() ? n.eng(2).chan().stats().scans : 0,
                n.node(2).powered() ? n.eng(2).chan().stats().scan_dwells : 0,
                n.node(2).powered() ? n.eng(2).chan().current() : 0, n.node(2).powered() ? n.eng(2).chan().epoch().value() : 0);
    LM_CHECK(ever_ready);
    LM_CHECK(learned);
    LM_CHECK(attached_boots + 4 >= boots); // not only once: (nearly) every boot after the first rejoins
}

LM_TEST("H9a sim: REPORT_ONLY deep sleeper, reference policy (1 s search), misses a channel change") { h9_rejoin(k_report, "reference"); }
LM_TEST("H9c sim: control - no channel change, reference policy") { h9_rejoin(k_report, "control-reference", false, 6); }
LM_TEST("H9d sim: control - no channel change, report_long") { h9_rejoin(report_long(), "control-report_long", false, 6); }
LM_TEST("H9b sim: REPORT_ONLY deep sleeper, 12 s search policy (report_long), misses a channel change") { h9_rejoin(report_long(), "report_long"); }


// FIX10-A6 (astra on 8668c69)
// late = false: queued before the command (FIX10-D8). late = true (FIX13-D3, astra N4): the "callback" enqueues after the
// drain and the ticket check, at the instant the radio is held for the sleep - the ticket must go stale, not the frame.
static void a6_case(bool late) {
    PNet n({Spec{},Spec{Role::Relay},Spec{Role::Leaf}}); n.form();
    auto s=n.send(1,2,LM_RECEIVED,payload_of(3),30000);
    LM_CHECK_EQ(s.st,LM_STATUS_OK);
    LM_CHECK(n.until([&]{return n.op(1,s.op).phase==3;},10000));
    Bytes received; LM_CHECK(n.pop_message(2,received));
    n.run_ms(100); n.apply_policy(2,k_report);
    LM_CHECK(n.until([&]{return n.eng(2).power().stats().grants>=1;},2000));
    auto p=n.prepare(2,LM_SLEEP_LIGHT,LM_WAKE_TIMER,60000,LM_PENDING_SAVE_AND_SLEEP);
    lm_sleep_ticket_t t{}; LM_CHECK_EQ(n.get_ticket(2,p,t),LM_STATUS_OK);
    auto* session=n.eng(1).delivery().sessions().find_peer(n.id(2)); LM_CHECK(session!=nullptr);
    if(!session)return;
    wire::EndHeader h;h.message_id.fill(0xD1);h.app_port=100;h.record_kind=wire::RecordKind::Data;
    h.flags=wire::make_end_flags(wire::Delivery::Received,wire::Priority::Normal,false);
    h.expires_root_ms=n.node(0).clock.now().to_ms()+30000;
    std::array<uint8_t,250> rec{};std::size_t rlen=0;uint8_t value=7;
    LM_CHECK_OK(delivery::seal_end_record(*session,session->tx_sid,RootTerm{1},h,ByteView{&value,1},MutByteView{rec},rlen));
    delivery::PathSpec ps;ps.origin=ShortAddr{2};ps.dest=ShortAddr{3};ps.len=1;ps.path[0]=3;ps.term=RootTerm{1};ps.revision=PathRevision{1};
    std::array<uint8_t,250> plain{};std::size_t plen=0;
    LM_CHECK_OK(wire::encode_route(ps.header(),MutByteView{plain},plen));
    std::memcpy(plain.data()+plen,rec.data(),rlen);
    link::SealedFrame f;LM_CHECK_OK(n.eng(1).link().seal(n.id(2),wire::FrameKind::Data,ByteView{plain.data(),plen+rlen},f,n.node(1).clock.now()));
    port::RadioEvent ev{};ev.rx.src=n.node(1).radio.mac();ev.rx.at=n.node(2).clock.now();ev.rx.len=static_cast<uint8_t>(f.view().size());
    std::memcpy(ev.rx.bytes.data(),f.view().data(),f.view().size());if(late){n.node(2).radio.stage_late_rx(ev);}else{n.node(2).radio.deliver(ev);LM_CHECK_EQ(n.node(2).radio.rx_depth(),1u);}
    const auto status=lm_sleep_enter(n.ctx(2),&t);
    LM_CHECK_EQ(status,LM_STATUS_SLEEP_TICKET_STALE);LM_CHECK(!n.asleep(2));
    LM_CHECK_EQ(n.node(2).radio.rx_depth(),0u); // handled by the ordinary receive path before the ticket was judged / the sleep
    Bytes got; LM_CHECK(n.until([&]{return n.pop_message(2,got);},2000)); // the frame reached the application
}
LM_TEST("FIX10-A6 sim: authenticated DATA queued in the radio after the ticket makes lm_sleep_enter STALE; the frame is delivered, not dropped") { a6_case(false); }
LM_TEST("FIX13-D3 sim: authenticated DATA queued between the sleep validation and the radio stop makes the ticket stale; the radio keeps running and the frame is delivered") { a6_case(true); }

// ---- FIX10-M12: tests that must fail when the property they name is broken (mutation-checked) --------------------

// ME05 in the SHIPPED configuration: mesh and channel modules on (the firmware runs both), every node idle in a formed
// network. An absolute bound, not a comparison with a run that has the same fault: a periodic wake of any period up to
// a second fails it, and so does a run of consecutive busy 10 ms windows.
LM_TEST("FIX10-M12 ME05 sim: a formed idle network in the shipped configuration (mesh + channel + power port) has no periodic owner wake") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Relay}, Spec{Role::Leaf}}, 61, 2000, true);
    n.form();
    LM_CHECK(n.until([&] {
        return n.eng(0).chan().loaded() && n.eng(1).chan().stats().time_updates > 0 && n.eng(2).chan().stats().time_updates > 0 &&
               n.eng(3).chan().stats().time_updates > 0;
    }, 120'000, 20));
    n.run_ms(120'000); // the attach traffic and the first refreshes are over
    for (unsigned i = 0; i < n.n; ++i) {
        LM_CHECK(n.eng(i).mesh().state() == (i == 0 ? route::Mesh::State::Root : route::Mesh::State::Ready));
    }
    std::array<uint64_t, 4> before{};
    std::array<unsigned, 4> run{}, longest{};
    std::array<uint64_t, 4> last{};
    for (unsigned i = 0; i < n.n; ++i) {
        before[i] = last[i] = n.eng(i).stats().steps;
    }
    constexpr uint64_t k_window_ms = 10;
    constexpr uint64_t k_idle_ms = 900'000; // 15 minutes
    for (uint64_t t = 0; t < k_idle_ms; t += k_window_ms) {
        n.run_ms(k_window_ms);
        for (unsigned i = 0; i < n.n; ++i) {
            const uint64_t s = n.eng(i).stats().steps;
            run[i] = s != last[i] ? run[i] + 1 : 0;
            longest[i] = std::max(longest[i], run[i]);
            last[i] = s;
        }
    }
    for (unsigned i = 0; i < n.n; ++i) {
        const uint64_t steps = n.eng(i).stats().steps - before[i];
        std::printf("  [measure] node %u: %llu owner steps in 15 idle minutes, longest run of busy 10 ms windows %u (sim)\n", i,
                    static_cast<unsigned long long>(steps), longest[i]);
        // What is scheduled: the mesh's Trickle beacons (about one per second at their floor), the lease refresh every
        // 60 s, the clock refresh every 300 s and the neighbours' relayed pairs (measured: 300..880 on the sim). A 2 ms
        // poll would be 450 000, a 10 ms one 90 000, a 100 ms one 9 000.
        LM_CHECK(steps <= 1500);
        LM_CHECK(longest[i] <= 12);
    }
}

// LP04 with the generation check as the only thing that can refuse: the ticket is otherwise perfectly fresh (quiet node,
// same membership, inside its 2 s), and the state moves by one of the three events that must void it.
LM_TEST("FIX10-M12 LP04 sim: a state change between ticket and enter voids the ticket by its generation alone (no timing involved)") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    n.form();
    n.apply_policy(2, k_report);
    LM_CHECK(n.until([&] { return n.eng(2).power().stats().grants >= 1; }, 2000));
    auto ticket = [&](lm_sleep_ticket_t &t) {
        const PNet::Prep p = n.prepare(2, LM_SLEEP_LIGHT, LM_WAKE_TIMER, 60'000, LM_PENDING_SAVE_AND_SLEEP);
        LM_CHECK_EQ(p.st, LM_STATUS_OK);
        LM_CHECK_EQ(n.get_ticket(2, p, t), LM_STATUS_OK);
    };
    // 1. a channel plan step (Power::note_state_change) after the ticket
    lm_sleep_ticket_t t{};
    ticket(t);
    n.eng(2).power().note_state_change();
    LM_CHECK_EQ(lm_sleep_enter(n.ctx(2), &t), LM_STATUS_SLEEP_TICKET_STALE);
    LM_CHECK(!n.asleep(2));
    LM_CHECK(n.eng(2).radio_state() == RadioState::Running);
    // 2. authenticated DATA after the ticket (Power::note_rx)
    ticket(t);
    n.eng(2).power().note_rx(n.now(2));
    LM_CHECK_EQ(lm_sleep_enter(n.ctx(2), &t), LM_STATUS_SLEEP_TICKET_STALE);
    LM_CHECK(!n.asleep(2));
    // 3. the control: nothing moved, the very same kind of ticket is accepted
    ticket(t);
    LM_CHECK_EQ(lm_sleep_enter(n.ctx(2), &t), LM_STATUS_OK);
    LM_CHECK(n.asleep(2));
}

// LP18: the level of each lock follows the work it stands for, in both directions, at every step; and each of them is
// really taken (a build that never asked for the crypto, Flash or radio lock must fail here).
LM_TEST("FIX10-M12 LP18 sim: the crypto, Flash and radio PM locks are held exactly while their work runs, and are taken") {
    PNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    n.form();
    n.apply_policy(2, k_report);
    LM_CHECK(n.until([&] { return n.eng(2).power().stats().grants >= 1; }, 2000));
    SimPm &pm = n.node(2).pm;
    Engine &e = n.eng(2);
    auto consistent = [&] {
        const uint8_t m = pm.locks();
        return ((m & port::pm_lock::crypto) != 0) == e.crypto_busy() && ((m & port::pm_lock::flash) != 0) == e.flash_busy() &&
               ((m & port::pm_lock::radio) != 0) == e.tx().in_flight();
    };
    const std::array<uint64_t, 3> before = {pm.acquired(1), pm.acquired(2), pm.acquired(3)};
    // Crypto: an end session with the relay (a fresh EDHOC). Flash: a durable send (journal). Radio: every frame.
    LM_CHECK_EQ(n.send(2, 1, LM_RECEIVED, payload_of(1)).st, LM_STATUS_OK);
    LM_CHECK_EQ(n.send(2, 0, LM_RECEIVED, payload_of(2), 30000, LM_DURABLE).st, LM_STATUS_OK);
    bool crypto = false, flash = false, radio = false;
    for (int i = 0; i < 6000; ++i) {
        n.run_ms(1);
        LM_CHECK(consistent());
        crypto = crypto || e.crypto_busy();
        flash = flash || e.flash_busy();
        radio = radio || e.tx().in_flight();
    }
    LM_CHECK(crypto && flash && radio); // the work happened ...
    LM_CHECK(pm.acquired(1) > before[0]); // ... and its lock was taken
    LM_CHECK(pm.acquired(2) > before[1]);
    LM_CHECK(pm.acquired(3) > before[2]);
    LM_CHECK(locks_balanced(n, 2));
    LM_CHECK_EQ(pm.locks() & (port::pm_lock::crypto | port::pm_lock::flash | port::pm_lock::radio), 0u); // idle again: none held
}

LM_TEST_MAIN()
