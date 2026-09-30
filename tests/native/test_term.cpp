// Root term per root boot (docs/04 §7 "root_termはroot bootごとに永続増加", docs/05 §5/§7, docs/08 §5, docs/21 §2):
// the root's clock restarts at 0 when the root restarts, so every value it issued on the old clock (credential
// leases, command deadlines, commissioning windows, channel switch times) belongs to the old term and must never be
// read on the new clock. Real lm_context + Engine per node on simulated ports, the mesh and the channel module (time
// sync) run by themselves; credentials from the TEST-ONLY fleet issuer. Sim results are protocol-bench evidence only.
#include <array>
#include <cstdio>
#include <cstring>
#include <vector>

#include "capi/context.hpp"
#include "fleet.hpp"
#include "lmtest.hpp"
#include "port/sim/sim_node.hpp"
#include "port/sim/sim_world.hpp"

using namespace lm;
using namespace lm::sim;

namespace {

using Bytes = std::vector<uint8_t>;
constexpr uint64_t k_lease_ms = 15ULL * 60 * 1000; // docs/06 §7: an authorisation lease lasts at most 15 min

// Root = node 0 (address 1) on a chain; members get addresses 2, 3, ... and a real 15 min lease on the root clock
// (the root renews it at their READY), so a lease issued on the old clock exists when the root restarts.
struct TNet {
    unsigned n;
    fleet::Network net;
    World world;
    std::vector<fleet::NodeKit> kits;

    explicit TNet(unsigned n_nodes, uint64_t seed = 83) : n(n_nodes), net(seed), world(WorldOptions{seed, 0}) {
        for (unsigned i = 0; i < n; ++i) {
            NodeOptions o;
            o.role = i == 0 ? Role::Root : Role::Relay;
            o.mesh = true;
            o.channel = true;
            (void)world.add_node(o);
            node(i).jobs.latency_us = 2000;
            fleet::MemberSpec s;
            s.address = static_cast<uint16_t>(i + 1);
            s.role = 1;
            s.lease_expires_root_ms = k_lease_ms;
            kits.push_back(i == 0 ? net.make_root() : net.make_node(i + 1, s.address, 1, &s));
        }
        world.make_chain();
        for (unsigned i = 0; i < n; ++i) {
            LM_CHECK_OK(fleet::provision(node(i).store, net, kits[i]));
        }
    }

    SimNode &node(unsigned i) { return world.node(static_cast<uint16_t>(i)); }
    Engine &eng(unsigned i) { return node(i).ctx()->engine; }
    lm_context_t *ctx(unsigned i) { return node(i).ctx(); }
    MonoTime now(unsigned i) { return node(i).clock.now(); }
    void boot(unsigned i) {
        LM_CHECK_OK(node(i).boot());
        LM_CHECK_EQ(lm_start(ctx(i)), LM_STATUS_OK);
    }
    void boot_all() {
        for (unsigned i = 0; i < n; ++i) {
            boot(i);
        }
    }
    void cut(unsigned i) {
        node(i).power_cut();
        node(i).store.power_restore();
    }
    void run_ms(uint64_t ms) { world.run_until(world.now_us() + ms * 1000); }
    template <class P> bool until(P pred, uint64_t max_ms, uint64_t step_ms = 20) {
        for (uint64_t t = 0; t <= max_ms; t += step_ms) {
            if (pred()) {
                return true;
            }
            run_ms(step_ms);
        }
        return pred();
    }
    void link(unsigned a, unsigned b, bool up) {
        LinkParams p;
        p.up = up;
        world.set_link(static_cast<uint16_t>(a), static_cast<uint16_t>(b), p);
    }

    // The term a node publishes (root) or holds its membership in (member): the credential's root_term.
    uint32_t term(unsigned i) { return eng(i).identity().member().root_term.value(); }
    RootTimeBound bound(unsigned i) { return eng(i).delivery().root_time(now(i)); }
    bool ready(unsigned i) {
        return node(i).powered() && eng(i).mesh().state() == route::Mesh::State::Ready;
    }
    // Every member is attached in the root's current tree (the root knows its path) and holds a root clock of the
    // root's current term.
    bool formed() {
        if (!node(0).powered() || !eng(0).identity().is_member()) {
            return false;
        }
        for (unsigned i = 1; i < n; ++i) {
            const RootTimeBound b = bound(i);
            delivery::PathSpec ps;
            if (!ready(i) || !b.valid || b.term != eng(0).identity().member().root_term ||
                !eng(0).routes().path_to(kits[i].kit.id, ps, now(0))) {
                return false;
            }
        }
        return true;
    }
    void dump() {
        for (unsigned i = 0; i < n; ++i) {
            if (!node(i).powered()) {
                std::printf("  node %u off\n", i);
                continue;
            }
            const RootTimeBound b = bound(i);
            const auto &ms = eng(i).mesh().stats();
            std::printf("  t=%llu node %u mesh %u step %u term %u cred %u bound %d/%u regs %llu leases %llu readies %llu susp %llu\n",
                        (unsigned long long)(world.now_us() / 1000), i, (unsigned)eng(i).mesh().state(),
                        (unsigned)eng(i).mesh().attach_step_id(), eng(i).identity().term().value(), term(i),
                        b.valid ? 1 : 0, b.term.value(), (unsigned long long)ms.registers, (unsigned long long)ms.leases,
                        (unsigned long long)ms.readies, (unsigned long long)ms.suspects);
            const auto &es = eng(i).delivery().end_stats();
            const auto &ls = eng(i).link().stats();
            std::printf("    end started %llu done %llu failed %llu rate %llu busy %llu cred_rej %llu unc %llu | link hs %llu/%llu fail %llu rate %llu busy %llu cred_rej %llu unknown_sid %llu inadm %llu\n",
                        (unsigned long long)es.started, (unsigned long long)es.completed, (unsigned long long)es.failed,
                        (unsigned long long)es.rate_limited, (unsigned long long)es.busy_drop,
                        (unsigned long long)es.cred_rejected, (unsigned long long)es.cred_time_uncertain,
                        (unsigned long long)ls.hs_started, (unsigned long long)ls.hs_completed,
                        (unsigned long long)ls.hs_failed, (unsigned long long)ls.hs_rate_limited,
                        (unsigned long long)ls.hs_busy_drop, (unsigned long long)ls.cred_rejected,
                        (unsigned long long)ls.rx_unknown_sid, (unsigned long long)ls.rx_inadmissible);
        }
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
    // The public root clock getter (lm_root_time_get), what an application derives its deadlines from.
    lm_root_time_t root_time(unsigned i) {
        lm_root_time_t t{};
        t.struct_size = sizeof(t);
        t.abi_version = LM_ABI_VERSION;
        LM_CHECK_EQ(lm_root_time_get(ctx(i), &t), LM_STATUS_OK);
        return t;
    }
    // A send whose deadline is taken from the sender's own clock (as an application does).
    lm_operation_id_t send(unsigned from, unsigned to, uint8_t storage, uint64_t ttl_ms) {
        const lm_root_time_t b = root_time(from);
        lm_send_request_t rq{};
        rq.struct_size = sizeof(rq);
        rq.abi_version = LM_ABI_VERSION;
        rq.destination.kind = LM_DEST_NODE;
        std::memcpy(rq.destination.node.bytes, kits[to].kit.id.bytes.data(), 32);
        rq.app_port = 100;
        rq.delivery = LM_RECEIVED;
        rq.storage = storage;
        rq.priority = LM_PRIORITY_NORMAL;
        rq.queue_mode = LM_FIFO;
        rq.root_term = b.root_term;
        rq.expires_root_ms = b.earliest_root_ms + ttl_ms;
        const uint8_t payload[24] = {7, 7, 7};
        lm_operation_id_t op = 0;
        const lm_status_t st = lm_send(ctx(from), &rq, payload, sizeof(payload), &op);
        node(from).notify();
        return st == LM_STATUS_OK ? op : 0;
    }
    lm_operation_t op(unsigned i, lm_operation_id_t id) {
        lm_operation_t o{};
        o.struct_size = sizeof(o);
        o.abi_version = LM_ABI_VERSION;
        (void)lm_get_operation(ctx(i), id, &o);
        return o;
    }
    // Installs a signed control object at node i; the status the operation ended with (0xFFFF: none in time).
    uint32_t install(unsigned i, uint32_t type, const Bytes &obj) {
        lm_operation_id_t o = 0;
        lm_status_t s = LM_STATUS_BUSY;
        (void)until([&] { return (s = lm_install_control(ctx(i), type, obj.data(), obj.size(), &o)) != LM_STATUS_BUSY; },
                    2000, 5);
        if (s != LM_STATUS_OK) {
            return s;
        }
        uint32_t reason = 0xFFFF;
        (void)until([&] {
            lm_event_t ev{};
            ev.struct_size = sizeof(ev);
            ev.abi_version = LM_ABI_VERSION;
            while (lm_next_event(ctx(i), &ev, nullptr, 0, nullptr) == LM_STATUS_OK) {
                if (ev.kind == LM_EVENT_OPERATION && ev.operation_id == o) {
                    reason = ev.reason;
                }
            }
            return reason != 0xFFFF;
        }, 5000, 5);
        return reason;
    }
};

} // namespace

// The root's term is the root_term of its own MemberCredential; each boot re-issues it one higher and commits it
// before anything is published. A power cut anywhere in a boot (every mutating store call, before/torn/after) leaves
// either the old record (the next boot goes one above it) or the new one: a term is never published twice.
LM_TEST("ROOT-TERM sim: every root boot publishes a higher term, committed before use; a cut during a boot reuses none") {
    TNet n(2);
    n.boot_all();
    LM_CHECK(n.until([&] { return n.formed(); }, 120'000));
    std::vector<uint32_t> published{n.term(0)};
    for (int k = 0; k < 3; ++k) {
        n.cut(0);
        n.run_ms(2000);
        n.boot(0);
        const bool ok = n.until([&] { return n.formed(); }, 240'000);
        if (!ok) {
            n.dump();
        }
        LM_CHECK(ok);
        LM_CHECK(n.term(0) > published.back()); // a restarted root never publishes an old term again
        published.push_back(n.term(0));
    }
    // The mutating store calls of one root boot, measured on a clean boot.
    n.cut(0);
    const uint64_t ops0 = n.node(0).store.mutating_ops();
    n.boot(0);
    LM_CHECK(n.until([&] { return n.eng(0).identity().is_member() && n.eng(0).mesh().state() == route::Mesh::State::Root; }, 20'000, 5));
    const uint64_t boot_ops = n.node(0).store.mutating_ops() - ops0;
    published.push_back(n.term(0));
    LM_CHECK(boot_ops >= 2); // at least the record and its commit marker of the new term
    for (uint64_t k = 0; k < boot_ops; ++k) {
        for (const CutMode mode : {CutMode::Before, CutMode::Torn, CutMode::After}) {
            n.cut(0);
            n.node(0).store.arm_cut(n.node(0).store.mutating_ops() + k, mode);
            n.boot(0);
            (void)n.until([&] { return n.node(0).store.cut_fired() || n.eng(0).mesh().state() == route::Mesh::State::Root; },
                          20'000, 5);
            if (!n.node(0).store.cut_fired()) {
                published.push_back(n.term(0)); // the cut point lies after this boot's writes: it published a term
            }
            n.cut(0);
            n.boot(0);
            LM_CHECK(n.until([&] { return n.eng(0).identity().is_member() && n.eng(0).mesh().state() == route::Mesh::State::Root; },
                             20'000, 5));
            const uint32_t t = n.term(0);
            for (const uint32_t old : published) {
                LM_CHECK(t > old); // above every term any earlier boot published
            }
            published.push_back(t);
        }
    }
    std::printf("  ROOT-TERM-sim: %zu root boots published terms 1..%u, %llu store writes per boot swept (x3 cut modes)\n",
                published.size(), published.back(), static_cast<unsigned long long>(boot_ops));
}

// docs/04 §7 + docs/06 §7: a lease is root time of one term. After the root restarts, its clock starts again at 0; a
// member lease issued before (here ~35 min on the old clock) would look valid for that long on the new one. The new
// term makes it unprovable instead, the members follow the new term (register, clock, renewed credential) and
// application traffic flows again once the renewal is in.
LM_TEST("ROOT-TERM sim: after a root restart members follow the new term; an old-clock lease is never read on the new clock") {
    TNet n(3);
    n.boot_all();
    LM_CHECK(n.until([&] { return n.formed(); }, 180'000));
    n.run_ms(20ULL * 60 * 1000); // renewals ran: the leases now lie ~30 min out on the root clock
    const uint32_t old_term = n.term(0);
    const member::MemberCredential old_mc = n.eng(2).identity().member();
    const lm_root_time_t before = n.root_time(2); // the application's view: the root clock of the current term
    LM_CHECK(before.valid == 1u && before.root_term == old_term);
    LM_CHECK(before.earliest_root_ms <= n.now(0).to_ms() && n.now(0).to_ms() <= before.latest_root_ms);
    lm_root_time_t bad{};
    bad.struct_size = sizeof(bad) - 8;
    bad.abi_version = LM_ABI_VERSION;
    LM_CHECK_EQ(lm_root_time_get(n.ctx(2), &bad), LM_STATUS_INVALID_ARGUMENT);
    LM_CHECK_EQ(old_mc.root_term.value(), old_term);
    LM_CHECK(old_mc.lease_expires_root_ms > k_lease_ms); // renewed at least once on the old clock
    n.cut(0);
    n.run_ms(5000);
    n.boot(0);
    LM_CHECK(n.until([&] { return n.formed(); }, 300'000));
    const uint32_t new_term = n.term(0);
    LM_CHECK(new_term > old_term);
    const lm_root_time_t after = n.root_time(2);
    LM_CHECK(after.valid == 1u && after.root_term == new_term);
    LM_CHECK(after.earliest_root_ms <= n.now(0).to_ms() && n.now(0).to_ms() <= after.latest_root_ms);
    for (unsigned i = 1; i < n.n; ++i) {
        const RootTimeBound b = n.bound(i);
        LM_CHECK(b.valid && b.term == RootTerm{new_term});
        // The lease of the old clock is not provable on the new clock (it would be Before: its ms lie in the future).
        LM_CHECK(check_deadline(b, member::lease_of(old_mc)) == DeadlineCheck::Uncertain);
    }
    // Every member is renewed into the new term; its lease is a lease of the new clock.
    LM_CHECK(n.until([&] {
        for (unsigned i = 1; i < n.n; ++i) {
            if (n.term(i) != new_term) {
                return false;
            }
        }
        return true;
    }, 120'000));
    for (unsigned i = 1; i < n.n; ++i) {
        const RootTimeBound b = n.bound(i);
        LM_CHECK(n.eng(i).identity().member().lease_expires_root_ms <= b.latest_ms + k_lease_ms);
    }
    // Application traffic end to end in the new term.
    const lm_operation_id_t o = n.send(2, 0, LM_VOLATILE, 30'000);
    LM_CHECK(o != 0);
    LM_CHECK(n.until([&] { return n.op(2, o).phase == 3; }, 60'000));
    LM_CHECK_EQ(n.op(2, o).outcome, static_cast<uint32_t>(LM_OUTCOME_RECEIVED));
    std::printf("  ROOT-TERM-sim: root restart %u -> %u; members re-attached, re-timed and renewed in the new term\n",
                old_term, new_term);
}

// docs/08 §5: "root再起動で時刻termが変わった既送信commandはINDETERMINATE。新termへ自動で同じ有効時間を付け直さない".
// A durable command of the root with a 30 min deadline survives the restart in the journal; on the new clock its
// deadline has no meaning, so it ends (TIME_UNCERTAIN) and is never sent again, even though its destination is back.
LM_TEST("ROOT-TERM sim: a root command with a deadline of the old clock is never sent again after the restart") {
    TNet n(3);
    n.boot_all();
    LM_CHECK(n.until([&] { return n.formed(); }, 180'000));
    n.run_ms(60'000);
    n.link(1, 2, false); // the destination is out of reach: the command waits
    const lm_operation_id_t o = n.send(0, 2, LM_DURABLE, 30ULL * 60 * 1000);
    LM_CHECK(o != 0);
    LM_CHECK(n.until([&] { return (n.op(0, o).evidence_bits & (1U << 1)) != 0; }, 5000, 5)); // persisted
    const uint64_t delivered0 = n.eng(2).delivery().stats().delivered;
    n.cut(0);
    n.run_ms(5000);
    n.link(1, 2, true);
    n.boot(0);
    LM_CHECK(n.until([&] { return n.formed(); }, 300'000));
    n.run_ms(60'000);
    LM_CHECK_EQ(n.eng(2).delivery().stats().delivered, delivered0); // never delivered on the new clock
    LM_CHECK(n.eng(0).delivery().stats().expired >= 1u);            // the recovered command ended at once
    LM_CHECK_EQ(n.eng(0).delivery().durable().live_count(), 0u);    // and left the journal
}

// docs/21 §2: a CommissioningWindow is root time of one term; "term変更で有効時間を引き継がず、rootが明示的に再発行する".
// The same window object after a restart is refused; a window of the new term is accepted.
LM_TEST("ROOT-TERM sim: a commissioning window of the old term is refused after a root restart; the new term's works") {
    TNet n(2);
    n.boot_all();
    LM_CHECK(n.until([&] { return n.formed(); }, 120'000));
    const auto window = [&](uint32_t term, uint8_t id) {
        member::CommissioningWindow w;
        w.id[0] = id;
        w.term = RootTerm{term};
        w.expected_revision = 0;
        w.not_before_ms = n.now(0).to_ms();
        w.expires_ms = w.not_before_ms + 10ULL * 60 * 1000;
        w.max_new_members = 2;
        w.allowed_roles = 3;
        w.policy_revision = 1;
        return n.net.fleet.window(n.net.domain, w);
    };
    const Bytes w_old = window(n.term(0), 1);
    LM_CHECK_EQ(n.install(0, 30, w_old), static_cast<uint32_t>(LM_STATUS_OK));
    LM_CHECK(n.eng(0).ledger().window_open(n.now(0)));
    n.cut(0);
    n.run_ms(2000);
    n.boot(0);
    LM_CHECK(n.until([&] { return n.formed(); }, 240'000));
    LM_CHECK(!n.eng(0).ledger().window_open(n.now(0)));
    LM_CHECK(n.install(0, 30, w_old) != static_cast<uint32_t>(LM_STATUS_OK)); // its times are of the old clock
    LM_CHECK(!n.eng(0).ledger().window_open(n.now(0)));
    LM_CHECK_EQ(n.install(0, 30, window(n.term(0), 1)), static_cast<uint32_t>(LM_STATUS_OK)); // re-issued: goes on
    LM_CHECK(n.eng(0).ledger().window_open(n.now(0)));
}

// FIX6-D1: a frame that is ready in the hop queue when the node learns a newer term must not go on the air (docs/08 §5:
// nothing is re-issued under a new term). Origin frame: the operation ends EXPIRED (never left). Forwarded frame:
// aborted at the relay, the destination gets nothing.
namespace {
void hold_and_bump(TNet &n, unsigned node) {
    n.eng(node).sched().hold_until(n.now(node) + Duration::from_s(60));
}
void learn_next_term(TNet &n, unsigned node) {
    LM_CHECK(n.eng(node).identity().note_term(RootTerm{n.eng(node).identity().term().value() + 1}));
    n.eng(node).on_new_term(n.now(node));
    n.eng(node).sched().hold_until(MonoTime{});
    n.node(node).notify();
}
} // namespace

LM_TEST("FIX6 sim: an origin frame held in the hop queue when the node learns a newer term is never sent; the send ends EXPIRED") {
    TNet n(3);
    n.boot_all();
    LM_CHECK(n.until([&] { return n.formed(); }, 180'000));
    n.run_ms(60'000);
    const lm_operation_id_t warm = n.send(2, 0, LM_VOLATILE, 60'000); // opens the end session
    LM_CHECK(n.until([&] { return n.op(2, warm).outcome == LM_OUTCOME_RECEIVED; }, 20'000, 5));
    const uint64_t aborted = n.eng(2).delivery().hop_stats().aborted;
    const uint64_t delivered = n.eng(0).delivery().stats().delivered;
    hold_and_bump(n, 2);
    const lm_operation_id_t o = n.send(2, 0, LM_VOLATILE, 60'000);
    LM_CHECK(o != 0);
    n.run_ms(500);
    LM_CHECK(n.eng(2).delivery().hop().in_use() > 0); // sealed, ready, waiting for the hold
    learn_next_term(n, 2);
    n.run_ms(3000);
    LM_CHECK_EQ(n.op(2, o).outcome, static_cast<uint32_t>(LM_OUTCOME_EXPIRED));
    LM_CHECK(n.eng(2).delivery().hop_stats().aborted > aborted); // withdrawn at the hop, never handed to the radio
    LM_CHECK_EQ(n.eng(0).delivery().stats().delivered, delivered);
}

LM_TEST("FIX6 sim: a forwarded frame of the old term held at a relay that learns the newer term is aborted, not sent") {
    TNet n(3);
    n.boot_all();
    LM_CHECK(n.until([&] { return n.formed(); }, 180'000));
    n.run_ms(60'000);
    const lm_operation_id_t warm = n.send(2, 0, LM_VOLATILE, 60'000);
    LM_CHECK(n.until([&] { return n.op(2, warm).outcome == LM_OUTCOME_RECEIVED; }, 20'000, 5));
    const uint64_t delivered = n.eng(0).delivery().stats().delivered;
    const uint64_t aborted = n.eng(1).delivery().hop_stats().aborted;
    hold_and_bump(n, 1);
    LM_CHECK(n.send(2, 0, LM_VOLATILE, 60'000) != 0);
    LM_CHECK(n.until([&] { return n.eng(1).delivery().hop().in_use() > 0; }, 3000, 5)); // the relay holds the forward
    learn_next_term(n, 1);
    n.run_ms(3000);
    LM_CHECK(n.eng(1).delivery().hop_stats().aborted > aborted);
    LM_CHECK_EQ(n.eng(0).delivery().stats().delivered, delivered);
}


LM_TEST_MAIN()
