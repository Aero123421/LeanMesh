// MESH slice (S11): cold-boot formation, registration, leases, repair, path queries and delivery across
// the formed mesh. Real lm_context + Engine per node on simulated ports; credentials from the TEST-ONLY
// fleet issuer; every link session, end session and record goes through the real core. Nothing is
// installed by hand: the nodes find their parents, the root approves the tree, routes come from the
// root. Scenario IDs are in the test names; "sim" results are protocol-bench numbers (virtual time,
// no RF, no energy, worker latency 2 ms unless a test says otherwise), never hardware evidence.
#include <array>
#include <map>
#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>

#include "capi/context.hpp"
#include "core/wire/cbor.hpp"
#include "fleet.hpp"
#include "lmtest.hpp"
#include "core/member/discovery.hpp"
#include "core/member/proxy.hpp"
#include "core/route/mesh_wire.hpp"
#include "core/route/stitch.hpp"
#include "port/sim/sim_node.hpp"
#include "port/sim/sim_provision.hpp"
#include "port/sim/sim_world.hpp"
#include "security/crypto.hpp"

using namespace lm;
using namespace lm::sim;

namespace {

using Bytes = std::vector<uint8_t>;

struct Received {
    lm_event_t ev{};
    Bytes payload;
};

// Nodes 0..n-1 on a chain; `root_idx` is the root (address 1), the others get addresses 2, 3, ... in
// index order. Extra radio links (spares) are added by the tests before boot.
struct MNet {
    // The last `unjoined` nodes hold an identity and no membership (they join through the mesh); provisioned
    // members take addresses from `addr_base` and are listed ACTIVE in the root's ledger (SEC-D2: the root admits
    // nobody else), so they must lie in its slots 2..65; a joiner gets the next free slot.
    explicit MNet(unsigned n_nodes, unsigned root_index = 0, uint64_t seed = 41, uint32_t job_latency_us = 2000,
                  unsigned unjoined = 0, uint16_t addr_base = 2)
        : n(n_nodes), root_idx(root_index), net(seed), world(WorldOptions{seed, 0}) {
        uint16_t next_addr = addr_base;
        for (unsigned i = 0; i < n; ++i) {
            NodeOptions o;
            o.role = i == root_idx ? Role::Root : Role::Relay;
            o.mesh = true;
            (void)world.add_node(o);
            world.node(static_cast<uint16_t>(i)).jobs.latency_us = job_latency_us;
            const bool joiner = i >= n - unjoined;
            addrs.push_back(i == root_idx ? 1 : (joiner ? 0 : next_addr++));
            kits.push_back(i == root_idx ? net.make_root() : (joiner ? net.make_unjoined(i + 1) : net.make_node(i + 1, addrs.back())));
        }
        world.make_chain();
        for (unsigned i = 0; i < n; ++i) {
            if (i >= n - unjoined) {
                sim::ProvisionInput in;
                in.scalar32 = ByteView{kits[i].kit.scalar};
                in.device_cose = ByteView{kits[i].kit.device_cose.data(), kits[i].kit.device_cose.size()};
                in.trust = net.fleet.trust();
                LM_CHECK_OK(sim::provision_store(node(i).store, in));
            } else {
                LM_CHECK_OK(fleet::provision(node(i).store, net, kits[i]));
            }
        }
    }

    SimNode &node(unsigned i) { return world.node(static_cast<uint16_t>(i)); }
    Engine &eng(unsigned i) { return node(i).ctx()->engine; }
    lm_context_t *ctx(unsigned i) { return node(i).ctx(); }
    const DeviceId &id(unsigned i) { return kits[i].kit.id; }
    MonoTime now(unsigned i) { return node(i).clock.now(); }
    route::Mesh &mesh(unsigned i) { return eng(i).mesh(); }
    uint16_t addr(unsigned i) const { return addrs[i]; }

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
        t_boot_us = world.now_us();
    }
    void power_cycle_all() {
        for (unsigned i = 0; i < n; ++i) {
            node(i).power_cut();
            node(i).store.power_restore();
        }
        boot_all();
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

    // Root clock: the root is the time base of its term, so the reading is the root's own monotonic clock (the
    // ledger stamps member leases the same way). Every powered node learns it now; there is no time slice yet (S17).
    void set_time() {
        for (unsigned i = 0; i < n; ++i) {
            if (node(i).powered()) {
                set_time_at(i);
            }
        }
    }
    void set_time_at(unsigned i) {
        RootTimeBound b;
        b.term = RootTerm{1};
        b.earliest_ms = b.latest_ms = root_ms();
        b.valid = true;
        eng(i).set_root_time(b, now(i));
        node(i).notify();
    }
    [[nodiscard]] uint64_t root_ms() { return node(root_idx).clock.now().to_ms(); }

    // ---- observations ----
    bool ready(unsigned i) { return mesh(i).state() == route::Mesh::State::Ready; }
    bool all_ready(unsigned upto = 0) {
        for (unsigned i = 0; i < (upto == 0 ? n : upto); ++i) {
            if (i != root_idx && !ready(i)) {
                return false;
            }
        }
        return true;
    }
    // The root's approved path to node i, as addresses (root first).
    std::vector<uint16_t> root_path(unsigned i) {
        root::RouteGrant g;
        if (eng(root_idx).routes().topology().path_from_root(ShortAddr{addr(i)}, node(root_idx).clock.now().to_ms(), g) !=
            Status::Ok) {
            return {};
        }
        return std::vector<uint16_t>(g.path.begin(), g.path.begin() + g.len);
    }
    // For the plain chain with the root at `root_idx`: the expected root path of node i.
    std::vector<uint16_t> chain_path(unsigned i) {
        std::vector<uint16_t> p{1};
        if (i > root_idx) {
            for (unsigned k = root_idx + 1; k <= i; ++k) {
                p.push_back(addr(k));
            }
        } else {
            for (unsigned k = root_idx; k-- > i;) {
                p.push_back(addr(k));
            }
        }
        return p;
    }
    bool tree_is_chain(unsigned upto = 0) {
        for (unsigned i = 0; i < (upto == 0 ? n : upto); ++i) {
            if (i != root_idx && root_path(i) != chain_path(i)) {
                return false;
            }
        }
        return true;
    }
    bool formed(unsigned upto = 0) { return all_ready(upto) && tree_is_chain(upto); }
    void dump() {
        {
            const auto &es = eng(root_idx).delivery().end_stats();
            const auto &ls = eng(root_idx).link().stats();
            std::printf("  root end started %llu completed %llu failed %llu rate %llu busy_drop %llu cred_rej %llu retrans %llu | link hs_started %llu failed %llu busy_drop %llu | phase %u busy %d\n",
                        (unsigned long long)es.started, (unsigned long long)es.completed, (unsigned long long)es.failed, (unsigned long long)es.rate_limited,
                        (unsigned long long)es.busy_drop, (unsigned long long)es.cred_rejected, (unsigned long long)es.retransmits, (unsigned long long)ls.hs_started,
                        (unsigned long long)ls.hs_failed, (unsigned long long)ls.hs_busy_drop, (unsigned)eng(root_idx).link().exchange().phase(), (int)eng(root_idx).link().exchange().busy());
            const auto &ds = eng(root_idx).delivery().stats();
            std::printf("  root delivery rx_data %llu rx_forward %llu drop_route %llu no_session %llu auth_fail %llu unsupported %llu | link rx %llu unknown_sid %llu wrong_domain %llu no_identity %llu accepted %llu no_consumer %llu neighbors %zu ready %d\n",
                        (unsigned long long)ds.rx_data, (unsigned long long)ds.rx_forward, (unsigned long long)ds.rx_drop_route, (unsigned long long)ds.rx_no_session,
                        (unsigned long long)ds.rx_auth_fail, (unsigned long long)ds.rx_unsupported, (unsigned long long)ls.rx_frames, (unsigned long long)ls.rx_unknown_sid,
                        (unsigned long long)ls.rx_wrong_domain, (unsigned long long)ls.rx_no_identity, (unsigned long long)ls.rx_accepted, (unsigned long long)ls.rx_no_consumer,
                        eng(root_idx).link().neighbors().count(), (int)eng(root_idx).delivery().ready());
        }
        static const char *const k_st[] = {"Off", "Listen", "Search", "Attach", "Ready", "Root"};
        for (unsigned i = 0; i < n; ++i) {
            const auto &m = mesh(i);
            const auto &s = m.stats();
            std::printf("  node %2u addr %2u %-6s step %u parent %u depth %u bcn tx/rx %llu/%llu probe %llu/%llu reg %llu lease %llu ready %llu susp %llu fail %llu busy %llu\n",
                        i, addr(i), k_st[static_cast<unsigned>(m.state())], m.attach_step_id(), m.parent_addr().value(), m.depth(),
                        (unsigned long long)s.beacons_tx, (unsigned long long)s.beacons_rx,
                        (unsigned long long)s.probes_tx, (unsigned long long)s.probes_rx,
                        (unsigned long long)s.registers, (unsigned long long)s.leases,
                        (unsigned long long)s.readies, (unsigned long long)s.suspects,
                        (unsigned long long)s.attach_failed, (unsigned long long)s.tx_busy);
        }
    }

    // ---- messages (public C ABI) ----
    struct Sent {
        lm_status_t st = LM_STATUS_OK;
        lm_operation_id_t op = 0;
    };
    Sent send(unsigned from, unsigned to, uint32_t delivery_kind, const Bytes &payload, uint64_t ttl_ms = 30000) {
        lm_send_request_t rq{};
        rq.struct_size = sizeof(rq);
        rq.abi_version = LM_ABI_VERSION;
        rq.destination.kind = LM_DEST_NODE;
        std::memcpy(rq.destination.node.bytes, id(to).bytes.data(), 32);
        rq.app_port = 100;
        rq.delivery = static_cast<uint8_t>(delivery_kind);
        rq.storage = LM_VOLATILE;
        rq.priority = LM_PRIORITY_NORMAL;
        rq.queue_mode = LM_FIFO;
        rq.root_term = 1;
        rq.expires_root_ms = root_ms() + ttl_ms;
        Sent s;
        s.st = lm_send(ctx(from), &rq, payload.data(), payload.size(), &s.op);
        node(from).notify();
        return s;
    }
    lm_operation_t op(unsigned i, lm_operation_id_t o) {
        lm_operation_t r{};
        r.struct_size = sizeof(r);
        r.abi_version = LM_ABI_VERSION;
        LM_CHECK_EQ(lm_get_operation(ctx(i), o, &r), LM_STATUS_OK);
        return r;
    }
    bool pop_message(unsigned i, Received &out) {
        for (;;) {
            Received r;
            r.ev.struct_size = sizeof(r.ev);
            r.ev.abi_version = LM_ABI_VERSION;
            r.payload.assign(600, 0);
            size_t req = 0;
            if (lm_next_event(ctx(i), &r.ev, r.payload.data(), r.payload.size(), &req) != LM_STATUS_OK) {
                return false;
            }
            r.payload.resize(req);
            if (r.ev.kind == LM_EVENT_MESSAGE) {
                out = r;
                return true;
            }
        }
    }

    // ---- joining (public C ABI; preapproved root: no Host) ----
    Bytes ticket_for(unsigned i, uint64_t generation) {
        return net.fleet.ticket(kits[i].kit, DomainId{}, net.domain, net.delegation_cose, 0, generation);
    }
    Status install_control(unsigned i, uint32_t type, const Bytes &obj) {
        lm_operation_id_t op = 0;
        lm_status_t s = LM_STATUS_BUSY;
        // BUSY is local (another owner holds the record memory, e.g. at boot): the caller asks again, bounded.
        (void)until(
            [&] {
                s = lm_install_control(ctx(i), type, obj.data(), obj.size(), &op);
                return s != LM_STATUS_BUSY;
            },
            1000, 5);
        if (s != LM_STATUS_OK) {
            return static_cast<Status>(s);
        }
        lm_event_t ev{};
        return until([&] {
                   ev.struct_size = sizeof(ev);
                   ev.abi_version = LM_ABI_VERSION;
                   while (lm_next_event(ctx(i), &ev, nullptr, 0, nullptr) == LM_STATUS_OK) {
                       if (ev.kind == LM_EVENT_OPERATION && ev.operation_id == op) {
                           return true;
                       }
                   }
                   return false;
               }, 5000, 5)
                   ? (ev.reason == 0 ? Status::Ok : static_cast<Status>(ev.reason))
                   : Status::Expired;
    }
    Bytes expected_page(unsigned i, uint64_t generation, const Bytes &ticket, uint64_t revision) {
        Sha256Digest grant{};
        LM_CHECK_OK(sec::sha256(ByteView{ticket.data(), ticket.size()}, grant));
        std::array<uint8_t, 512> buf{};
        wire::CborWriter w{MutByteView{buf}};
        w.array(4);
        w.uint(0);
        w.uint(1);
        w.bytes(ByteView{grant});
        w.array(1);
        w.array(4);
        w.bytes(id(i).view());
        w.uint(generation);
        w.bytes(ByteView{grant});
        w.boolean(true);
        LM_CHECK_OK(w.finish());
        member::Envelope env;
        env.type = member::k_type_expected_set;
        env.domain = net.domain;
        env.revision = revision;
        env.issuer = net.fleet.trust().key_id;
        env.request.bytes[0] = static_cast<uint8_t>(revision);
        return net.fleet.sign(env, w.written());
    }
    // Ticket on the device and (optionally) the expected entry on the root.
    void grant(unsigned i, uint64_t generation, uint64_t revision, bool expected = true) {
        const Bytes t = ticket_for(i, generation);
        last_ticket = t; // an expected entry names this very ticket (signatures are randomised)
        LM_CHECK_OK(install_control(i, 3, t));
        if (expected) {
            LM_CHECK_OK(install_control(root_idx, 5, expected_page(i, generation, t, revision)));
        }
    }
    uint64_t join(unsigned i, uint8_t seed, uint32_t budget_ms = 0) {
        lm_join_request_t r{};
        r.struct_size = sizeof(r);
        r.abi_version = LM_ABI_VERSION;
        for (std::size_t k = 0; k < 16; ++k) {
            r.request_id.bytes[k] = static_cast<uint8_t>(seed + k);
        }
        r.mode = LM_JOIN_NEW;
        r.search_budget_ms = budget_ms;
        lm_operation_id_t op = 0;
        LM_CHECK_EQ(lm_join(ctx(i), &r, &op), LM_STATUS_OK);
        node(i).notify();
        return op;
    }
    // Drains the events of node i, remembering the outcome of `op` (reason) once it is over.
    bool op_done(unsigned i, uint64_t op, uint32_t &reason) {
        lm_event_t ev{};
        ev.struct_size = sizeof(ev);
        ev.abi_version = LM_ABI_VERSION;
        while (lm_next_event(ctx(i), &ev, nullptr, 0, nullptr) == LM_STATUS_OK) {
            if (ev.kind == LM_EVENT_MEMBERSHIP) {
                ++membership_events[std::make_pair(i, ev.reason)];
            }
            if (ev.kind == LM_EVENT_OPERATION && ev.operation_id == op) {
                reason = ev.reason;
                return true;
            }
            ev.struct_size = sizeof(ev);
            ev.abi_version = LM_ABI_VERSION;
        }
        return false;
    }
    unsigned membership_seen(unsigned i, uint32_t reason) {
        lm_event_t ev{};
        ev.struct_size = sizeof(ev);
        ev.abi_version = LM_ABI_VERSION;
        while (lm_next_event(ctx(i), &ev, nullptr, 0, nullptr) == LM_STATUS_OK) {
            if (ev.kind == LM_EVENT_MEMBERSHIP) {
                ++membership_events[std::make_pair(i, ev.reason)];
            }
            ev.struct_size = sizeof(ev);
            ev.abi_version = LM_ABI_VERSION;
        }
        return membership_events[std::make_pair(i, reason)];
    }

    std::map<std::pair<unsigned, uint32_t>, unsigned> membership_events;
    Bytes last_ticket;
    unsigned n;
    unsigned root_idx;
    fleet::Network net;
    World world;
    std::vector<fleet::NodeKit> kits;
    std::vector<uint16_t> addrs;
    uint64_t t_boot_us = 0;
};

[[maybe_unused]] Bytes payload_of(uint8_t seed, std::size_t len = 40) {
    Bytes b(len);
    for (std::size_t i = 0; i < len; ++i) {
        b[i] = static_cast<uint8_t>(seed + i);
    }
    return b;
}

// Formation of `hops` + 1 nodes on a chain (root at one end): time until every node is Ready and the
// root's tree is exactly the chain.
uint64_t form_chain(MNet &n, uint64_t limit_ms) {
    n.boot_all();
    n.set_time();
    const bool ok = n.until([&] { return n.formed(); }, limit_ms, 20);
    if (!ok) {
        n.dump();
    }
    LM_CHECK(ok);
    return (n.world.now_us() - n.t_boot_us) / 1000;
}

} // namespace

LM_TEST("R01 sim: 21 nodes / 20 hops cold boot form the whole mesh by themselves") {
    MNet n(21);
    const uint64_t ms = form_chain(n, 60'000);
    std::printf("  R01-sim formation: %llu ms (21 nodes, 20 hops, worker latency 2 ms, seed 41)\n",
                static_cast<unsigned long long>(ms));
    LM_CHECK(n.tree_is_chain());
    for (unsigned i = 1; i < n.n; ++i) {
        LM_CHECK_EQ(n.mesh(i).depth(), i);
        LM_CHECK_EQ(n.mesh(i).path_size(), i + 1);
        LM_CHECK_EQ(n.mesh(i).stats().attach_failed, 0u);
    }
}

using lm::delivery::ev::end_received;

namespace {
// Waits (bounded) until the origin's operation shows END_RECEIVED; returns the sim time it took in ms.
uint64_t await_received(MNet &n, unsigned from, lm_operation_id_t op, uint64_t limit_ms) {
    const uint64_t t0 = n.world.now_us();
    LM_CHECK(n.until([&] { return (n.op(from, op).evidence_bits & end_received) != 0; }, limit_ms, 5));
    return (n.world.now_us() - t0) / 1000;
}
} // namespace

LM_TEST("R01 sim: delivery across the formed mesh, both directions, no static routes") {
    MNet n(21);
    (void)form_chain(n, 120'000);
    // Node at 20 hops -> root, root -> node at 20 hops (the end sessions of the registration are reused).
    const Bytes up = payload_of(1, 60);
    const auto s1 = n.send(20, 0, LM_RECEIVED, up);
    LM_CHECK_EQ(s1.st, LM_STATUS_OK);
    const uint64_t up_ms = await_received(n, 20, s1.op, 30'000);
    Received m;
    LM_CHECK(n.pop_message(0, m));
    LM_CHECK(m.payload == up);
    const Bytes down = payload_of(9, 60);
    const auto s2 = n.send(0, 20, LM_RECEIVED, down);
    const uint64_t down_ms = await_received(n, 0, s2.op, 30'000);
    LM_CHECK(n.pop_message(20, m));
    LM_CHECK(m.payload == down);
    std::printf("  END_RECEIVED round trip, 20 hops: node->root %llu ms, root->node %llu ms (sim)\n",
                static_cast<unsigned long long>(up_ms), static_cast<unsigned long long>(down_ms));
    // Node <-> node at 10 hops: the route comes from a ROUTE_QUERY, the end session is set up on demand.
    const Bytes side = payload_of(5, 50);
    const auto s3 = n.send(5, 15, LM_RECEIVED, side);
    LM_CHECK_EQ(s3.st, LM_STATUS_OK);
    const uint64_t side_ms = await_received(n, 5, s3.op, 60'000);
    LM_CHECK(n.pop_message(15, m));
    LM_CHECK(m.payload == side);
    LM_CHECK(n.mesh(5).stats().queries >= 1);
    std::printf("  node 5 -> node 15 (10 hops, query + end session + delivery): %llu ms (sim)\n",
                static_cast<unsigned long long>(side_ms));
}

LM_TEST("R02 sim: 41 nodes, root in the middle, 40-hop node-to-node delivery (56 B and 512 B)") {
    MNet n(41, 20);
    const uint64_t ms = form_chain(n, 300'000);
    std::printf("  R02-sim formation: %llu ms (41 nodes, two arms of 20 hops)\n", static_cast<unsigned long long>(ms));
    for (unsigned i = 0; i < n.n; ++i) {
        if (i != 20) {
            LM_CHECK_EQ(n.mesh(i).depth(), i < 20 ? 20 - i : i - 20);
        }
    }
    // The route between the two ends is the join of their root paths at the LCA: 40 edges.
    const Bytes body = payload_of(3, 56); // data_capacity(40)
    const auto s = n.send(0, 40, LM_RECEIVED, body);
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    const uint64_t took = await_received(n, 0, s.op, 240'000);
    Received m;
    LM_CHECK(n.pop_message(40, m));
    LM_CHECK(m.payload == body);
    LM_CHECK(n.mesh(0).stats().queries >= 1);
    std::printf("  R02-sim node 0 -> node 40 (40 hops; query + end handshake + delivery): %llu ms\n",
                static_cast<unsigned long long>(took));
    // A second message reuses route and session: the pure 40-hop round trip.
    const auto s2 = n.send(40, 0, LM_RECEIVED, body);
    const uint64_t back = await_received(n, 40, s2.op, 30'000);
    std::printf("  R02-sim 40-hop END_RECEIVED round trip on a warm route: %llu ms\n", static_cast<unsigned long long>(back));
    // 512 B over the same 40 hops: the fragment engine (S12) splits it into 16 B quanta, the mesh only supplies the route.
    const Bytes big = payload_of(7, 512);
    const auto sb = n.send(0, 40, LM_RECEIVED, big, 120'000);
    LM_CHECK_EQ(sb.st, LM_STATUS_OK);
    const uint64_t big_ms = await_received(n, 0, sb.op, 120'000);
    LM_CHECK(n.pop_message(40, m));
    LM_CHECK(m.payload == big);
    std::printf("  R02-sim 512 B over 40 hops (fragmented): END_RECEIVED after %llu ms\n", static_cast<unsigned long long>(big_ms));
}

LM_TEST("R07 sim: 20 cold boots of the whole network converge again, memberships kept") {
    MNet n(21);
    std::vector<uint64_t> times;
    n.boot_all();
    n.set_time();
    LM_CHECK(n.until([&] { return n.formed(); }, 300'000, 20));
    times.push_back((n.world.now_us() - n.t_boot_us) / 1000);
    for (int cycle = 1; cycle < 20; ++cycle) {
        n.run_ms(2000 + static_cast<uint64_t>(cycle) * 37); // a moment of running network before the cut
        n.power_cycle_all();
        n.set_time();
        const bool ok = n.until([&] { return n.formed(); }, 300'000, 20);
        if (!ok) {
            n.dump();
        }
        LM_CHECK(ok);
        times.push_back((n.world.now_us() - n.t_boot_us) / 1000);
        for (unsigned i = 0; i < n.n; ++i) {
            LM_CHECK(n.eng(i).identity().is_member()); // the membership survived the power cut
        }
    }
    uint64_t lo = UINT64_MAX;
    uint64_t hi = 0;
    uint64_t sum = 0;
    for (uint64_t t : times) {
        lo = std::min(lo, t);
        hi = std::max(hi, t);
        sum += t;
    }
    std::printf("  R07-sim 20 cold boots (21 nodes, 20 hops): formation min %llu / mean %llu / max %llu ms\n",
                static_cast<unsigned long long>(lo), static_cast<unsigned long long>(sum / times.size()),
                static_cast<unsigned long long>(hi));
    // Delivery works after the last cycle without any hand-made route.
    const auto s = n.send(20, 0, LM_RECEIVED, payload_of(2, 30));
    (void)await_received(n, 20, s.op, 30'000);
}

// A chain 0..20 (root 0) plus a spare relay S (index 21) that hears node 9 and node 11 only.
struct SpareNet : MNet {
    SpareNet() : MNet(22) {
        link(20, 21, false);
        link(9, 21);
        link(11, 21);
    }
    bool spare_ready() {
        if (!ready(21)) {
            return false;
        }
        const link::Neighbor *nb = eng(11).link().neighbors().find_device(id(21));
        return nb != nullptr && nb->cur.active && mesh(11).state() == route::Mesh::State::Ready;
    }
    bool repaired() {
        return ready(11) && mesh(11).parent_addr() == ShortAddr{addr(21)} && ready(20) && mesh(20).path_size() == 21 &&
               mesh(20).path()[10] == addr(21);
    }
};

LM_TEST("R06 sim: relay failure with a spare neighbour is repaired (traffic driven), delivery resumes") {
    SpareNet n;
    n.boot_all();
    n.set_time();
    LM_CHECK(n.until([&] { return n.all_ready() && n.spare_ready(); }, 200'000, 20));
    n.run_ms(10'000); // the spare is linked and measured
    LM_CHECK_EQ(n.mesh(21).parent_addr().value(), n.addr(9));
    // Node 20 sends; at the same moment relay 10 dies (the node between 9 and 11).
    const auto s = n.send(20, 0, LM_RECEIVED, payload_of(4, 40), 60'000);
    LM_CHECK_EQ(s.st, LM_STATUS_OK);
    const uint64_t t_fail = n.world.now_us();
    n.node(10).power_cut();
    LM_CHECK(n.until([&] { return n.repaired(); }, 120'000, 5));
    const uint64_t t_parent = (n.world.now_us() - t_fail) / 1000;
    // Delivery of the very same message (same MessageId) over the new path.
    const uint64_t t_rx = [&] {
        LM_CHECK(n.until([&] { return (n.op(20, s.op).evidence_bits & end_received) != 0; }, 60'000, 5));
        return (n.world.now_us() - t_fail) / 1000;
    }();
    const lm_operation_t o = n.op(20, s.op);
    LM_CHECK(o.outcome != LM_OUTCOME_INDETERMINATE);
    Received m;
    LM_CHECK(n.pop_message(0, m));
    LM_CHECK(std::memcmp(m.ev.message_id.bytes, o.message_id.bytes, 16) == 0);
    LM_CHECK(!n.pop_message(0, m)); // delivered once
    LM_CHECK(n.mesh(11).stats().suspects >= 1);
    LM_CHECK(n.tree_is_chain() == false); // the tree changed: 11 hangs below the spare now
    root::RouteGrant g;
    LM_CHECK_OK(n.eng(0).routes().topology().path_from_root(ShortAddr{n.addr(11)}, n.node(0).clock.now().to_ms(), g));
    LM_CHECK_EQ(g.len, 12);
    LM_CHECK_EQ(g.path[10], n.addr(21));
    std::printf("  R06-sim relay 10 dies under traffic: node 11 re-approved below the spare after %llu ms "
                "(suspect->approved %llu ms), the pending message END_RECEIVED after %llu ms\n",
                static_cast<unsigned long long>(t_parent),
                static_cast<unsigned long long>(n.mesh(11).stats().last_repair_ms), static_cast<unsigned long long>(t_rx));
}

LM_TEST("R06 sim: idle parent loss (no traffic) is found within the hello liveness bound") {
    SpareNet n;
    n.boot_all();
    n.set_time();
    LM_CHECK(n.until([&] { return n.all_ready() && n.spare_ready(); }, 200'000, 20));
    n.run_ms(120'000); // hello interval is at its 32 s maximum by now
    const uint64_t t_fail = n.world.now_us();
    n.node(10).power_cut();
    LM_CHECK(n.until([&] { return n.repaired(); }, 200'000, 20));
    const uint64_t ms = (n.world.now_us() - t_fail) / 1000;
    std::printf("  R06-sim idle relay loss: node 11 re-approved below the spare after %llu ms (hello max 32 s, silence rule 96 s)\n",
                static_cast<unsigned long long>(ms));
    LM_CHECK(ms < 96'000);
}

LM_TEST("R06 sim: without the root, established paths and sessions keep carrying; a returning root re-admits everyone") {
    MNet n(21);
    (void)form_chain(n, 120'000);
    Received m;
    const auto s1 = n.send(5, 15, LM_RECEIVED, payload_of(1, 40), 120'000);
    (void)await_received(n, 5, s1.op, 60'000);
    LM_CHECK(n.pop_message(15, m));
    n.node(0).power_cut(); // the root dies; nobody elects another (docs/04 §7)
    n.run_ms(1000);
    const auto s2 = n.send(5, 15, LM_RECEIVED, payload_of(2, 40), 120'000);
    (void)await_received(n, 5, s2.op, 60'000); // cached route + live end session: no root needed
    LM_CHECK(n.pop_message(15, m));
    n.run_ms(240'000); // leases (180 s) run out: the paths are no longer claimed valid, nothing is invented
    LM_CHECK(!n.mesh(5).route_to_root(*std::make_unique<delivery::PathSpec>(), n.now(5)));
    LM_CHECK(n.mesh(5).state() != route::Mesh::State::Off);
    n.node(0).store.power_restore();
    n.boot(0);
    n.set_time_at(0);
    for (unsigned i = 1; i < n.n; ++i) {
        n.set_time_at(i);
    }
    const uint64_t t0 = n.world.now_us();
    const bool back = n.until([&] { return n.formed(); }, 400'000, 50);
    if (!back) {
        n.dump();
    }
    LM_CHECK(back);
    std::printf("  R06-sim root returns after 240 s: whole tree re-approved %llu ms later\n",
                static_cast<unsigned long long>((n.world.now_us() - t0) / 1000));
}

LM_TEST("R01 sim (model): formation with a slow worker, 150 ms per public-key job") {
    MNet n(21, 0, 41, 150'000);
    const uint64_t ms = form_chain(n, 900'000);
    std::printf("  R01-sim formation with 150 ms worker latency per EDHOC step (a MODEL parameter, not a C3 measurement): %llu ms\n",
                static_cast<unsigned long long>(ms));
}

// Diamond: root 0 - {1, 2} - 3 - 4.
struct Diamond : MNet {
    Diamond() : MNet(5) {
        link(1, 2, false);
        link(0, 2);
        link(1, 3);
    }
};

LM_TEST("R05 sim: diamond, the relay under a pending message dies, no flood, the same id arrives on the new path") {
    Diamond n;
    n.boot_all();
    n.set_time();
    LM_CHECK(n.until([&] { return n.all_ready(); }, 100'000, 20));
    n.run_ms(10'000);
    const uint16_t via = n.mesh(3).parent_addr().value();
    LM_CHECK(via == n.addr(1) || via == n.addr(2));
    const unsigned dying = via == n.addr(1) ? 1 : 2;
    const unsigned other = 3 - dying;
    // The spare must be linked before the failure (docs/04 §2: parent + two spare candidates).
    LM_CHECK(n.until([&] { return n.eng(3).link().neighbors().find_device(n.id(other)) != nullptr; }, 60'000, 20));
    const auto s = n.send(4, 0, LM_RECEIVED, payload_of(7, 30), 60'000);
    n.node(dying).power_cut();
    const uint64_t frames_before = n.eng(3).delivery().hop_stats().frames;
    LM_CHECK(n.until([&] { return (n.op(4, s.op).evidence_bits & end_received) != 0; }, 90'000, 5));
    Received m;
    LM_CHECK(n.pop_message(0, m));
    LM_CHECK(!n.pop_message(0, m));
    LM_CHECK_EQ(n.mesh(3).parent_addr().value(), n.addr(other));
    // Bounded: the stale path was tried by one frame (3 link attempts), not flooded.
    LM_CHECK(n.eng(3).delivery().hop_stats().frames - frames_before < 20);
    LM_CHECK(n.op(4, s.op).outcome != LM_OUTCOME_INDETERMINATE);
}

namespace {
// Root 0 + 19 relays on a chain (19 hops), then one unjoined device that hears only the last relay.
constexpr unsigned k_far = 20;
} // namespace

LM_TEST("J01 sim: an unjoined device 19 hops from the root joins through the proxy chain") {
    MNet n(k_far + 1, 0, 43, 2000, 1); // relays 2..20 are listed in the ledger (SEC-D2); the joiner gets the next slot
    n.boot_all();
    n.set_time();
    LM_CHECK(n.until([&] { return n.formed(k_far); }, 200'000, 20));
    n.eng(0).ledger().set_join_mode(root::JoinMode::Preapproved);
    n.grant(k_far, 1, 1);
    const uint64_t t0 = n.world.now_us();
    const uint64_t op = n.join(k_far, 0x30);
    uint32_t reason = 0xFFFF;
    LM_CHECK(n.until([&] { return n.op_done(k_far, op, reason); }, 120'000, 20));
    LM_CHECK_EQ(reason, 0u);
    const uint64_t join_ms = (n.world.now_us() - t0) / 1000;
    LM_CHECK(n.eng(k_far).identity().is_member());
    const root::Entry *e = n.eng(0).ledger().find(n.id(k_far));
    LM_CHECK(e != nullptr && e->state == root::EntryState::Active);
    // The relay carried frames it cannot read; the root alone decided (one join request, one commit).
    LM_CHECK(n.eng(k_far - 1).proxy().stats().up > 0 && n.eng(k_far - 1).proxy().stats().down > 0);
    LM_CHECK(n.eng(0).proxy().stats().up > 0);
    LM_CHECK_EQ(n.eng(0).ledger().stats().requests, 1ull);
    LM_CHECK_EQ(n.eng(0).ledger().stats().activated, 1ull);
    LM_CHECK_EQ(n.eng(k_far - 1).ledger().stats().requests, 0ull); // the relay decided nothing
    // The new member then forms like any other node: parent = the relay it joined through, depth 20.
    n.set_time_at(k_far);
    const bool joined_ready = n.until([&] { return n.ready(k_far); }, 120'000, 20);
    LM_CHECK(joined_ready);
    LM_CHECK_EQ(n.mesh(k_far).depth(), 20);
    std::printf("  J01-sim proxy join over 19 hops: request to ACTIVE %llu ms, then Ready at depth 20\n",
                static_cast<unsigned long long>(join_ms));
}

LM_TEST("J02 sim: a device started before its expected entry exists is not banned; the update lets it in") {
    MNet n(2, 0, 47, 2000, 1, 100);
    n.boot_all();
    n.set_time();
    LM_CHECK(n.until([&] { return n.eng(0).ledger().ready(); }, 2000, 5));
    n.eng(0).ledger().set_join_mode(root::JoinMode::Preapproved);
    n.grant(1, 1, 1, false); // the ticket is on the device, the root has no expected entry
    const uint64_t op = n.join(1, 0x50);
    uint32_t reason = 0xFFFF;
    LM_CHECK(!n.until([&] { return n.op_done(1, op, reason); }, 4000, 20));
    LM_CHECK_EQ(n.membership_seen(1, static_cast<uint32_t>(Status::NotFound)), 1u); // reported once: NOT_EXPECTED
    LM_CHECK(!n.eng(1).identity().is_member());
    // The fleet's expected list arrives (revision 1); nobody calls lm_join again.
    const uint64_t t_update = n.world.now_us();
    LM_CHECK_OK(n.install_control(0, 5, n.expected_page(1, 1, n.last_ticket, 1)));
    LM_CHECK(n.until([&] { return n.op_done(1, op, reason); }, 90'000, 20));
    LM_CHECK_EQ(reason, 0u);
    LM_CHECK(n.eng(1).identity().is_member());
    std::printf("  J02-sim: refused NOT_EXPECTED at ~1.5 s, expected list installed at %llu ms, ACTIVE %llu ms later\n",
                static_cast<unsigned long long>((t_update - n.t_boot_us) / 1000),
                static_cast<unsigned long long>((n.world.now_us() - t_update) / 1000));
}

LM_TEST("J02 sim: after the search budget the device asks again at once (no fixed ban), the update is honoured") {
    MNet n(2, 0, 48, 2000, 1, 100);
    n.boot_all();
    n.set_time();
    LM_CHECK(n.until([&] { return n.eng(0).ledger().ready(); }, 2000, 5));
    n.eng(0).ledger().set_join_mode(root::JoinMode::Preapproved);
    n.grant(1, 1, 1, false);
    const uint64_t op = n.join(1, 0x51, 5000);
    uint32_t reason = 0xFFFF;
    LM_CHECK(n.until([&] { return n.op_done(1, op, reason); }, 20'000, 20));
    LM_CHECK_EQ(reason, static_cast<uint32_t>(Status::Expired)); // budget spent: not a device fault, not a verdict
    LM_CHECK_OK(n.install_control(0, 5, n.expected_page(1, 1, n.last_ticket, 1)));
    const uint64_t t0 = n.world.now_us();
    const uint64_t op2 = n.join(1, 0x51); // the same request id
    LM_CHECK(n.until([&] { return n.op_done(1, op2, reason); }, 40'000, 20));
    LM_CHECK_EQ(reason, 0u);
    // Nothing but the 30 s full-handshake gate towards the root (docs/06 §8) stood in the way: no 6 h ban, no backoff.
    LM_CHECK((n.world.now_us() - t0) / 1000 < 30'000);
}

LM_TEST("J03 sim: a forged offer (hint false positive) costs one bounded handshake and authorises nothing") {
    MNet n(3, 0, 49, 2000, 2, 100);
    n.link(1, 2, true); // the impostor F (node 2) is in range of the joiner; it is never powered: it holds no key
    n.link(0, 2, false);
    n.boot(0);
    n.boot(1);
    n.t_boot_us = n.world.now_us();
    n.set_time();
    LM_CHECK(n.until([&] { return n.eng(0).ledger().ready(); }, 2000, 5));
    n.eng(0).ledger().set_join_mode(root::JoinMode::Preapproved);
    n.grant(1, 1, 1);
    const uint64_t op = n.join(1, 0x60);
    // The forgery echoes the joiner's hello nonce and claims to be the root (depth 0).
    std::array<uint8_t, 64> frame{};
    std::size_t len = 0;
    member::OfferHint hint;
    LM_CHECK_OK(member::encode_discovery(true, n.eng(1).membership().hello_nonce(),
                                         link::domain_hint_of(n.net.domain), MutByteView{frame}, len, &hint));
    n.run_ms(100);
    n.world.inject(n.node(2).radio.mac(), 2, n.node(1).radio.mac(), ByteView{frame.data(), len});
    uint32_t reason = 0xFFFF;
    LM_CHECK(n.until([&] { return n.op_done(1, op, reason); }, 90'000, 20));
    LM_CHECK_EQ(reason, 0u); // the real root answered the next hello; the forged hint got one failed handshake
    const auto &ls = n.eng(1).link().stats();
    LM_CHECK_EQ(ls.hs_failed, 1ull);
    LM_CHECK(ls.hs_started <= member::Discovery::k_full_handshakes + 1u); // + the first ordinary link after joining
    LM_CHECK_EQ(n.eng(0).ledger().stats().requests, 1ull); // the root saw one request, from the real device
    LM_CHECK_EQ(n.eng(0).ledger().count(root::EntryState::Active), 1u);
}

// A member that left is out of the root's tree at once (SEC-D2/SEC-D5 follow-up): no path through it, its children
// re-register, its end session is gone. Not 180 s later when its route lease would have lapsed.
LM_TEST("SEC-b sim: a member's leave removes it from the root's tree and its end session immediately") {
    MNet n(3);
    n.boot_all();
    n.set_time();
    LM_CHECK(n.until([&] { return n.formed(); }, 60'000, 20));
    LM_CHECK(n.eng(0).routes().topology().is_admitted(ShortAddr{n.addr(1)}));
    LM_CHECK(n.eng(0).delivery().sessions().find_peer(n.id(1)) != nullptr);
    lm_operation_id_t op = 0;
    LM_CHECK_EQ(lm_leave(n.ctx(1), LM_LEAVE_IMMEDIATE, 0, &op), LM_STATUS_OK);
    n.node(1).notify();
    LM_CHECK(n.until([&] {
        const root::Entry *e = n.eng(0).ledger().find(n.id(1));
        return e != nullptr && e->state == root::EntryState::Left;
    }, 5000, 5));
    n.run_ms(5); // the commit's completion is where the root forgets it; well inside any lease
    LM_CHECK(!n.eng(0).routes().topology().is_admitted(ShortAddr{n.addr(1)}));
    ShortAddr parent;
    LM_CHECK(n.eng(0).routes().topology().parent_of(ShortAddr{n.addr(2)}, parent) == Status::NotFound); // orphaned child
    LM_CHECK(n.eng(0).delivery().sessions().find_peer(n.id(1)) == nullptr);
    LM_CHECK(n.eng(0).link().neighbors().find_device(n.id(1)) == nullptr);
}

LM_TEST("mesh wire: beacon, probe and root records round-trip; malformed input is refused") {
    using namespace lm::route;
    Beacon b;
    b.flags = k_beacon_accepting;
    b.term = 7;
    b.revision = 9;
    b.n = 3;
    b.path = {1, 5, 9};
    std::array<uint8_t, 96> frame{};
    std::size_t len = 0;
    LM_CHECK_OK(encode_beacon(b, 0xAABBCCDD, MutByteView{frame}, len));
    wire::LinkHeader h;
    ByteView body;
    LM_CHECK_OK(wire::decode_link_frame(ByteView{frame.data(), len}, h, body));
    LM_CHECK(h.kind == wire::FrameKind::Discovery && !h.encrypted);
    Beacon d;
    LM_CHECK_OK(decode_beacon(body, d));
    LM_CHECK(d.n == 3 && d.path[2] == 9 && d.revision == 9 && d.term == 7);
    b.path = {1, 5, 5}; // a path that visits an address twice is not a path
    LM_CHECK(encode_beacon(b, 0, MutByteView{frame}, len) == Status::InvalidArgument);
    const uint8_t bad_depth[] = {1, 1, 9, 0, 0, 0, 7, 0, 0, 0, 9, 0, 1, 0, 5}; // depth says 10, two entries follow
    LM_CHECK(decode_beacon(ByteView{bad_depth, sizeof bad_depth}, d) == Status::BadFrame);

    Probe p;
    p.nonce[0] = 0x42;
    p.sender = 4;
    p.receiver = 5;
    p.credit = 200;
    p.membership = 3;
    DomainId dom;
    DeviceId dev;
    dev.bytes[0] = 1;
    std::array<uint8_t, 192> plain{};
    LM_CHECK_OK(encode_probe(p, dom, dev, MutByteView{plain}, len));
    Probe q;
    DeviceId who;
    LM_CHECK_OK(decode_probe(ByteView{plain.data(), len}, q, who));
    LM_CHECK(q.nonce == p.nonce && q.credit == 200 && q.sender == 4 && who == dev);
    LM_CHECK(decode_probe(ByteView{plain.data(), len - 1}, q, who) != Status::Ok);

    LeaseRec l;
    l.term = 1;
    l.revision = 4;
    l.lease_ms = 180000;
    l.n = 3;
    l.path = {1, 2, 3};
    std::array<uint8_t, 64> rec{};
    LM_CHECK_OK(encode(l, MutByteView{rec}, len));
    LeaseRec l2;
    LM_CHECK_OK(decode(ByteView{rec.data(), len}, l2));
    LM_CHECK(l2.n == 3 && l2.path[2] == 3 && l2.lease_ms == 180000);
    LM_CHECK(decode(ByteView{rec.data(), len - 1}, l2) == Status::BadFrame); // truncated
    rec[len - 1] = 2;                                                       // duplicate address in the path
    LM_CHECK(decode(ByteView{rec.data(), len}, l2) == Status::BadFrame);
    LM_CHECK(is_mesh_record(ByteView{rec.data(), len}));
    const uint8_t cbor_control[] = {0x87, 0x10};
    LM_CHECK(!is_mesh_record(ByteView{cbor_control, 2})); // a CBOR control-body is somebody else's
}

LM_TEST("stitch: the route between two nodes joins their root paths at the lowest common ancestor") {
    const uint16_t a[] = {1, 2, 3, 4};   // root 1 - 2 - 3 - 4
    const uint16_t b[] = {1, 2, 7, 8, 9}; // root 1 - 2 - 7 - 8 - 9
    uint16_t out[8];
    std::size_t n = 0;
    LM_CHECK_OK(route::stitch_route(a, 4, b, 5, out, 8, n));
    LM_CHECK_EQ(n, 5u);
    const uint16_t want[] = {3, 2, 7, 8, 9};
    LM_CHECK(std::memcmp(out, want, sizeof want) == 0);
    LM_CHECK_OK(route::stitch_route(a, 4, a, 2, out, 8, n)); // towards an ancestor: only the way up
    LM_CHECK_EQ(n, 2u);
    LM_CHECK(route::stitch_route(a, 4, a, 4, out, 8, n) == Status::InvalidArgument);
    LM_CHECK(route::stitch_route(a, 4, b, 5, out, 3, n) == Status::NoCapacity);
}

LM_TEST("discovery policy: listen first, jittered hello, 30 s budget, backoff 1..60 s, wake clears it") {
    member::Discovery d;
    MonoTime t{};
    d.begin(t, 250, true, member::Discovery::k_budget, true);
    LM_CHECK(d.listening(t));
    LM_CHECK(d.poll(t + Duration::from_ms(799)) == member::Discovery::Act::None);
    LM_CHECK(d.poll(t + Duration::from_ms(1049)) == member::Discovery::Act::None); // 800 listen + 250 jitter
    LM_CHECK(d.poll(t + Duration::from_ms(1050)) == member::Discovery::Act::Hello);
    LM_CHECK(d.poll(t + Duration::from_ms(1051)) == member::Discovery::Act::None);  // one hello per second
    LM_CHECK(d.poll(t + Duration::from_ms(2100)) == member::Discovery::Act::Hello);
    LM_CHECK(d.may_handshake());
    d.note_handshake();
    d.note_handshake();
    LM_CHECK(!d.may_handshake()); // two full handshakes per search
    uint32_t last = 0;
    MonoTime at = t + Duration::from_s(30);
    for (int i = 0; i < 9; ++i) { // exhausted, backoff 1, 2, 4 ... capped at 60 s, then the next search starts by itself
        LM_CHECK(d.poll(at) == member::Discovery::Act::Exhausted);
        LM_CHECK(d.in_backoff());
        const MonoTime resume = d.deadline();
        LM_CHECK(d.poll(resume) == member::Discovery::Act::Resumed);
        const uint32_t waited = static_cast<uint32_t>((resume - at).to_ms());
        LM_CHECK(waited >= last || waited == 60'000);
        last = waited;
        at = resume + member::Discovery::k_budget;
    }
    LM_CHECK_EQ(last, 60'000u);
    d.not_expected(at, Duration::from_s(30), 4);
    LM_CHECK(d.suppressed(at) && !d.revision_advanced(4) && d.revision_advanced(5));
    d.clear_suppress();
    LM_CHECK(!d.suppressed(at));
}

LM_TEST("P2: replaced link sessions of all neighbours share two grace slots") {
    link::Neighbors nb;
    auto keys = [](uint32_t sid, MonoTime until) {
        link::SessionKeys k;
        k.active = true;
        k.rx_sid = sid;
        k.valid_until = until;
        return k;
    };
    MacAddr a;
    MacAddr b;
    MacAddr c;
    a.bytes[0] = 1;
    b.bytes[0] = 2;
    c.bytes[0] = 3;
    const MonoTime t0{};
    nb.retire(a, keys(11, t0 + Duration::from_s(10)), t0 + Duration::from_s(10));
    nb.retire(b, keys(12, t0 + Duration::from_s(8)), t0 + Duration::from_s(8));
    LM_CHECK(nb.has_grace(a) && nb.has_grace(b));
    nb.retire(c, keys(13, t0 + Duration::from_s(9)), t0 + Duration::from_s(9)); // full: the one that ends first goes
    LM_CHECK(nb.has_grace(a) && !nb.has_grace(b) && nb.has_grace(c));
    nb.retire(a, keys(14, t0 + Duration::from_s(10)), t0 + Duration::from_s(10)); // one per neighbour
    LM_CHECK(nb.sid_in_use(14) && !nb.sid_in_use(11));
    PeerHandle released[4];
    (void)nb.sweep(t0 + Duration::from_s(10), released, 4);
    LM_CHECK(!nb.has_grace(a) && !nb.has_grace(c));
}

LM_TEST("J01 sim: a tunnel record cannot capture the address of a real neighbour of the root") {
    MNet n(3);
    n.boot_all();
    n.set_time();
    LM_CHECK(n.until([&] { return n.formed(); }, 100'000, 20));
    // A member forges a tunnel chunk "from" the MAC of the root's neighbour (node 1): the root must not start
    // routing its frames for that MAC into the tunnel.
    std::array<uint8_t, member::k_proxy_mac + 5 + 4> plain{};
    const MacAddr victim = n.node(1).radio.mac();
    std::copy(victim.bytes.begin(), victim.bytes.end(), plain.begin());
    member::JoinChunk c;
    const std::array<uint8_t, 4> bytes{1, 2, 3, 4};
    c.object_id = 1;
    c.total = 4;
    c.bytes = ByteView{bytes.data(), bytes.size()};
    std::size_t len = 0;
    LM_CHECK_OK(member::encode_chunk(c, MutByteView{plain.data() + member::k_proxy_mac, plain.size() - member::k_proxy_mac}, len));
    delivery::PathSpec reply;
    reply.dest = ShortAddr{n.addr(2)};
    n.eng(0).proxy().on_record(reply, ByteView{plain.data(), member::k_proxy_mac + len}, n.now(0));
    LM_CHECK(!n.eng(0).proxy().owns(victim));
    LM_CHECK_EQ(n.eng(0).proxy().entries(), 0u);
    // A stranger's MAC does open an entry (that is how a joiner behind a relay appears), bounded by join_slots.
    MacAddr stranger;
    stranger.bytes[0] = 0x02;
    std::copy(stranger.bytes.begin(), stranger.bytes.end(), plain.begin());
    n.eng(0).proxy().on_record(reply, ByteView{plain.data(), member::k_proxy_mac + len}, n.now(0));
    LM_CHECK(n.eng(0).proxy().owns(stranger));
}

LM_TEST_MAIN()
