// LIFECYCLE slice (S18): authorisation-lease renewal, and the membership lifecycle after the join. Real
// lm_context + Engine per node on simulated ports, credentials from the TEST-ONLY fleet issuer, the mesh and the
// channel module (root clock over TIME_REQ/RESP) running by themselves. Scenario IDs are in the test names; every
// result is a protocol-bench (sim) result: virtual time, no RF, no energy, no real Flash (docs/18 §3).
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "capi/context.hpp"
#include "core/wire/cbor.hpp"
#include "fleet.hpp"
#include "cut_matrix.hpp"
#include "lmtest.hpp"
#include "port/sim/sim_node.hpp"
#include "port/sim/sim_provision.hpp"
#include "port/sim/sim_world.hpp"
#include "security/crypto.hpp"

using namespace lm;
using namespace lm::sim;

namespace {

using Bytes = std::vector<uint8_t>;
constexpr uint64_t k_min = 60'000;

ByteView view(const Bytes &b) { return ByteView{b.data(), b.size()}; }

lm_request_id_t rid(uint8_t seed) {
    lm_request_id_t r{};
    for (std::size_t i = 0; i < 16; ++i) {
        r.bytes[i] = static_cast<uint8_t>(seed + i);
    }
    return r;
}

struct Spec {
    Role role = Role::Relay;
    uint64_t lease_ms = 15 * k_min; // provisioned members: a lease on the root clock as a join gives it
    bool unjoined = false;          // identity and trust only: joins through the ledger in the test
};

// Node 0 is the root (address 1); node i has address i + 1. The links are a chain unless a test rewires them.
struct LNet {
    unsigned n;
    fleet::Network net;
    World world;
    std::vector<fleet::NodeKit> kits;

    // `ledger_fill`: that many more members (never powered, addresses after the nodes') are listed in the root's
    // ledger, so that a new device can only get the address of one that left (the ledger's reuse rule).
    explicit LNet(std::vector<Spec> specs, uint64_t seed = 71, unsigned ledger_fill = 0)
        : n(static_cast<unsigned>(specs.size())), net(seed), world(WorldOptions{seed, 0}) {
        for (unsigned i = 0; i < n; ++i) {
            NodeOptions o;
            o.role = i == 0 ? Role::Root : specs[i].role;
            o.mesh = true;
            o.channel = true;
            (void)world.add_node(o);
            node(i).jobs.latency_us = 2000;
            if (i == 0) {
                kits.push_back(net.make_root());
            } else if (specs[i].unjoined) {
                kits.push_back(net.make_unjoined(i));
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
        for (unsigned k = 0; k < ledger_fill; ++k) {
            (void)net.make_node(1000 + k, static_cast<uint16_t>(n + k));
        }
        LM_CHECK_OK(fleet::provision(node(0).store, net, kits[0]));
        for (unsigned i = 1; i < n; ++i) {
            if (specs[i].unjoined) {
                sim::ProvisionInput in;
                in.scalar32 = ByteView{kits[i].kit.scalar};
                in.device_cose = view(kits[i].kit.device_cose);
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
    bool ready(unsigned i) { return eng(i).mesh().state() == route::Mesh::State::Ready; }
    bool all_ready() {
        for (unsigned i = 1; i < n; ++i) {
            if (!node(i).powered() || !eng(i).identity().is_member() || !ready(i)) {
                return false;
            }
        }
        return true;
    }
    uint64_t lease(unsigned i) { return eng(i).identity().member().lease_expires_root_ms; }
    uint32_t state(unsigned i) {
        lm_membership_t m{};
        m.struct_size = sizeof(m);
        m.abi_version = LM_ABI_VERSION;
        LM_CHECK_EQ(lm_membership_get(ctx(i), &m), LM_STATUS_OK);
        return m.state;
    }
    // The lease a peer holds for node i's credential on its link session (0: no session).
    uint64_t lease_at(unsigned peer, unsigned i) {
        const link::Neighbor *nb = eng(peer).link().neighbors().find_device(id(i));
        return nb != nullptr && nb->cur.active ? nb->lease.ms : 0;
    }

    // ---- join through the ledger (preapproved: a fleet ticket at the device, its expected entry at the root) ----
    lm_status_t install(unsigned i, uint32_t type, const Bytes &obj) {
        lm_operation_id_t op = 0;
        lm_status_t s = LM_STATUS_BUSY;
        (void)until([&] { return (s = lm_install_control(ctx(i), type, obj.data(), obj.size(), &op)) != LM_STATUS_BUSY; },
                    2000, 5);
        run_ms(200);
        return s;
    }
    Bytes expected_page(unsigned i, uint64_t generation, const Bytes &ticket, uint64_t revision) {
        Sha256Digest grant{};
        LM_CHECK_OK(sec::sha256(view(ticket), grant));
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
    void grant(unsigned i, uint64_t generation, uint64_t revision) {
        const Bytes t = net.fleet.ticket(kits[i].kit, DomainId{}, net.domain, net.delegation_cose, 0, generation);
        LM_CHECK_EQ(install(i, 3, t), LM_STATUS_OK);
        LM_CHECK_EQ(install(0, 5, expected_page(i, generation, t, revision)), LM_STATUS_OK);
    }
    lm_status_t join(unsigned i, uint8_t req) {
        lm_join_request_t r{};
        r.struct_size = sizeof(r);
        r.abi_version = LM_ABI_VERSION;
        r.request_id = rid(req);
        r.mode = LM_JOIN_NEW;
        lm_operation_id_t op = 0;
        const lm_status_t s = lm_join(ctx(i), &r, &op);
        node(i).notify();
        return s;
    }

    // A RECEIVED message to the root; the operation id (0: refused at once).
    lm_operation_id_t send_to_root(unsigned from, uint64_t ttl_ms = 60'000) { return send_to(from, id(0), ttl_ms); }
    lm_operation_id_t send_to(unsigned from, const DeviceId &dest, uint64_t ttl_ms = 60'000) {
        lm_send_request_t rq{};
        rq.struct_size = sizeof(rq);
        rq.abi_version = LM_ABI_VERSION;
        rq.destination.kind = LM_DEST_NODE;
        std::memcpy(rq.destination.node.bytes, dest.bytes.data(), 32);
        rq.app_port = 100;
        rq.delivery = LM_RECEIVED;
        rq.storage = LM_VOLATILE;
        rq.priority = LM_PRIORITY_NORMAL;
        rq.queue_mode = LM_FIFO;
        rq.root_term = 1;
        rq.expires_root_ms = root_ms() + ttl_ms;
        const uint8_t payload[24] = {1, 2, 3};
        lm_operation_id_t op = 0;
        lm_status_t s = LM_STATUS_TIME_UNCERTAIN;
        // A node that just attached may not know the root's clock yet: the deadline cannot be proven (local).
        (void)until([&] { return (s = lm_send(ctx(from), &rq, payload, sizeof(payload), &op)) != LM_STATUS_TIME_UNCERTAIN; },
                    30'000, 100);
        node(from).notify();
        return s == LM_STATUS_OK ? op : 0;
    }
    // Node i knows a route to `dest` (lm_payload_capacity answers NO_ROUTE otherwise).
    bool has_route(unsigned i, const DeviceId &dest) {
        lm_destination_t d{};
        d.kind = LM_DEST_NODE;
        std::memcpy(d.node.bytes, dest.bytes.data(), 32);
        uint32_t bytes = 0;
        uint32_t hops = 0;
        return lm_payload_capacity(ctx(i), &d, &bytes, &hops) == LM_STATUS_OK;
    }
    lm_operation_t op(unsigned i, lm_operation_id_t o) {
        lm_operation_t r{};
        r.struct_size = sizeof(r);
        r.abi_version = LM_ABI_VERSION;
        (void)lm_get_operation(ctx(i), o, &r);
        return r;
    }
    void drain_events() {
        for (unsigned i = 0; i < n; ++i) {
            if (!node(i).powered()) {
                continue;
            }
            lm_event_t ev{};
            ev.struct_size = sizeof(ev);
            ev.abi_version = LM_ABI_VERSION;
            std::array<uint8_t, 600> buf{};
            std::size_t len = 0;
            while (lm_next_event(ctx(i), &ev, buf.data(), buf.size(), &len) == LM_STATUS_OK) {
            }
        }
    }
};

// Two domains of one fleet: root A (node 0) and root B (node 1), each with its own ledger; devices 2.. are provisioned
// members of A (address = node + 1). The mesh is off: joins and sessions are one hop, as on the join slice's bench.
// Root time is set by hand on every node (term 1, the roots' own clocks agree: they booted together).
// Kind::Handover: node 1 is instead the replacement root of A (a new device, delegation generation 2, term 2), not
// provisioned until the test starts it (start_new_root).
struct DNet {
    enum class Kind : uint8_t { TwoDomains, Handover };
    unsigned n;
    fleet::Network a;
    fleet::Network b;
    World world;
    std::vector<fleet::NodeKit> kits;
    Bytes deleg2; // Handover: the new root's delegation

    explicit DNet(unsigned devices, uint64_t seed = 81, Kind kind = Kind::TwoDomains)
        : n(devices + 2), a(seed), b(seed, "fleet", "/B", 1001), world(WorldOptions{seed, 0}) {
        for (unsigned i = 0; i < n; ++i) {
            NodeOptions o;
            o.role = i < 2 ? Role::Root : Role::Relay;
            (void)world.add_node(o);
            node(i).jobs.latency_us = 2000;
        }
        kits.push_back(a.make_root());
        kits.push_back(kind == Kind::Handover ? a.make_new_root(1001, 2, 2, deleg2) : b.make_root());
        for (unsigned i = 2; i < n; ++i) {
            kits.push_back(a.make_node(i, static_cast<uint16_t>(i + 1)));
        }
        world.make_full();
        LM_CHECK_OK(fleet::provision(node(0).store, a, kits[0]));
        if (kind == Kind::TwoDomains) {
            LM_CHECK_OK(fleet::provision(node(1).store, b, kits[1]));
        }
        for (unsigned i = 2; i < n; ++i) {
            LM_CHECK_OK(fleet::provision(node(i).store, a, kits[i]));
        }
        for (unsigned i = 0; i < n; ++i) {
            if (i != 1 || kind == Kind::TwoDomains) {
                boot(i);
            }
        }
        run_ms(100);
        set_time();
    }
    // Handover: the new root device gets its own delegation and credential; `backup`: the old root's ledger copied
    // from its store now (a verified backup), else none. `boot`: powered on at once.
    void provision_new_root(bool backup) {
        LM_CHECK_OK(fleet::provision_replacement_root(node(1).store, a, kits[1], deleg2));
        if (backup) {
            LM_CHECK_OK(fleet::copy_ledger(node(0).store, node(1).store));
        }
    }
    member::RootHandover handover(uint32_t new_term = 2) {
        member::RootHandover h;
        h.id[0] = 0x48;
        h.old_root = id(0);
        h.new_root = id(1);
        h.old_generation = 1;
        h.new_generation = 2;
        LM_CHECK_OK(sec::sha256(view(deleg2), h.new_delegation_hash));
        h.new_term = RootTerm{new_term};
        return h;
    }
    SimNode &node(unsigned i) { return world.node(static_cast<uint16_t>(i)); }
    Engine &eng(unsigned i) { return node(i).ctx()->engine; }
    lm_context_t *ctx(unsigned i) { return node(i).ctx(); }
    const DeviceId &id(unsigned i) { return kits[i].kit.id; }
    MacAddr mac(unsigned i) { return node(i).radio.mac(); }
    void boot(unsigned i) {
        LM_CHECK_OK(node(i).boot());
        LM_CHECK_EQ(lm_start(ctx(i)), LM_STATUS_OK);
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
    // Root time of `term` (the clock of root node `from`) on every powered node whose membership has that term.
    void set_time(uint32_t term = 1, unsigned from = 0) {
        for (unsigned i = 0; i < n; ++i) {
            if (node(i).powered() &&
                (!eng(i).identity().is_member() || eng(i).identity().member().root_term == RootTerm{term})) {
                RootTimeBound t;
                t.term = RootTerm{term};
                t.earliest_ms = t.latest_ms = node(from).clock.now().to_ms();
                t.valid = true;
                eng(i).set_root_time(t, node(i).clock.now());
            }
        }
    }
    lm_membership_t membership(unsigned i) {
        lm_membership_t m{};
        m.struct_size = sizeof(m);
        m.abi_version = LM_ABI_VERSION;
        LM_CHECK_EQ(lm_membership_get(ctx(i), &m), LM_STATUS_OK);
        return m;
    }
    bool in_domain(unsigned i, const fleet::Network &net) {
        const lm_membership_t m = membership(i);
        return m.state == LM_ACTIVE && std::memcmp(m.domain.bytes, net.domain.bytes.data(), 16) == 0;
    }
    // Installs `obj` (type) at node i and waits for its operation; the operation's status (0xFFFF: none in time).
    uint32_t install(unsigned i, uint32_t type, const Bytes &obj, uint64_t wait_ms = 5000) {
        lm_operation_id_t op = 0;
        lm_status_t s = LM_STATUS_BUSY;
        (void)until([&] { return (s = lm_install_control(ctx(i), type, obj.data(), obj.size(), &op)) != LM_STATUS_BUSY; },
                    2000);
        if (s != LM_STATUS_OK) {
            return s;
        }
        uint32_t reason = 0xFFFF;
        (void)until([&] {
            lm_event_t ev{};
            ev.struct_size = sizeof(ev);
            ev.abi_version = LM_ABI_VERSION;
            while (lm_next_event(ctx(i), &ev, nullptr, 0, nullptr) == LM_STATUS_OK) {
                if (ev.kind == LM_EVENT_OPERATION && ev.operation_id == op) {
                    reason = ev.reason;
                }
            }
            return reason != 0xFFFF;
        }, wait_ms);
        return reason;
    }
    // An expected entry at the root of `net` (node `root`) granting `ticket` to device i.
    uint32_t expect(unsigned root, const fleet::Network &net, unsigned i, uint64_t generation, const Bytes &ticket,
                    uint64_t revision) {
        Sha256Digest grant{};
        LM_CHECK_OK(sec::sha256(view(ticket), grant));
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
        env.issuer = a.fleet.trust().key_id;
        env.request.bytes[0] = static_cast<uint8_t>(revision);
        return install(root, 5, a.fleet.sign(env, w.written()));
    }
    // The fleet's ticket moving device i from `from` to `to` (expected_old -> new generation).
    Bytes transfer_ticket(unsigned i, const fleet::Network &from, const fleet::Network &to, uint64_t expected_old,
                          uint64_t new_generation) {
        return a.fleet.ticket(kits[i].kit, from.domain, to.domain, to.delegation_cose, expected_old, new_generation);
    }
    // lm_join(TRANSFER_CANDIDATE) at node i; waits for the operation or for the membership to reach `to`. Returns
    // true when device i is an ACTIVE member of `to` (the SDK restarted there).
    bool transfer(unsigned i, const fleet::Network &to, uint8_t req, uint64_t wait_ms = 60'000) {
        return start_join(i, req, LM_JOIN_TRANSFER_CANDIDATE) == LM_STATUS_OK &&
               until([&] { return in_domain(i, to); }, wait_ms, 20);
    }
    lm_status_t start_join(unsigned i, uint8_t req, uint32_t mode) {
        lm_join_request_t r{};
        r.struct_size = sizeof(r);
        r.abi_version = LM_ABI_VERSION;
        r.request_id = rid(req);
        r.mode = mode;
        lm_operation_id_t op = 0;
        const lm_status_t s = lm_join(ctx(i), &r, &op);
        node(i).notify();
        return s;
    }
    // Power cut and restart of node i (its store works again), root time set again.
    void reboot(unsigned i) {
        node(i).power_cut();
        node(i).store.power_restore();
        boot(i);
        run_ms(300);
        set_time();
    }
    uint64_t assignment(unsigned i) { return membership(i).assignment_generation; }
};

} // namespace

// The member leases are 15 min on the root clock; nothing but the renewal keeps them. For three hours a joined
// leaf and provisioned relays/leaves stay members, keep their paths and carry application traffic; every link
// session is made again under each renewed lease, and no session ever ends because a lease ran out.
LM_TEST("S18 renewal soak: three hours on 15 min leases, members stay authorised and sessions never lapse") {
    LNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Relay}, Spec{Role::Leaf}, Spec{Role::Leaf, 0, true}});
    n.link(3, 4, false);
    n.link(2, 4); // the joiner hangs below relay 2 (its join goes through relay 2's proxy)
    for (unsigned i = 0; i < 4; ++i) {
        n.boot(i);
    }
    LM_CHECK(n.until([&] {
        for (unsigned i = 1; i < 4; ++i) {
            if (!n.ready(i)) {
                return false;
            }
        }
        return true;
    }, 90'000));
    n.eng(0).ledger().set_join_mode(root::JoinMode::Preapproved);
    n.boot(4);
    n.run_ms(500);
    n.grant(4, 1, 1);
    LM_CHECK_EQ(n.join(4, 40), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.eng(4).identity().is_member() && n.ready(4); }, 120'000));
    const uint64_t joined_lease = n.lease(4);
    LM_CHECK(joined_lease > n.root_ms() && joined_lease <= n.root_ms() + 15 * k_min);
    std::printf("  formed at %llu ms, joined lease %llu\n", static_cast<unsigned long long>(n.root_ms()),
                static_cast<unsigned long long>(joined_lease));

    unsigned sent = 0;
    unsigned received = 0;
    unsigned not_ready = 0;
    std::vector<std::pair<unsigned, lm_operation_id_t>> ops;
    const uint64_t end = n.root_ms() + 180 * k_min;
    while (n.root_ms() < end) {
        n.run_ms(k_min);
        n.drain_events();
        not_ready += n.all_ready() ? 0 : 1;
        if (!n.all_ready()) {
            std::printf("  not all ready at %llu ms:", static_cast<unsigned long long>(n.root_ms()));
            for (unsigned i = 1; i < 5; ++i) {
                std::printf(" n%u=%d", i, static_cast<int>(n.eng(i).mesh().state()));
            }
            std::printf("\n");
        }
        for (const auto &[from, o] : ops) {
            const lm_operation_t r = n.op(from, o);
            received += r.phase == 3 && r.outcome == LM_OUTCOME_RECEIVED ? 1 : 0;
            if (!(r.phase == 3 && r.outcome == LM_OUTCOME_RECEIVED)) {
                std::printf("  message of node %u at %llu ms: phase %u outcome %u reason %u evidence %x\n", from,
                            static_cast<unsigned long long>(n.root_ms()), r.phase, r.outcome, r.reason, r.evidence_bits);
            }
        }
        ops.clear();
        for (unsigned from : {3U, 4U}) {
            if (const lm_operation_id_t o = n.send_to_root(from); o != 0) {
                ops.emplace_back(from, o);
                ++sent;
            }
        }
    }
    n.run_ms(30'000);
    for (const auto &[from, o] : ops) {
        const lm_operation_t r = n.op(from, o);
        received += r.phase == 3 && r.outcome == LM_OUTCOME_RECEIVED ? 1 : 0;
    }
    std::printf("  3 h: sent %u received %u; minutes not all ready %u; root renewals %llu deferred %llu\n", sent,
                received, not_ready, static_cast<unsigned long long>(n.eng(0).ledger().stats().renewals),
                static_cast<unsigned long long>(n.eng(0).ledger().stats().renew_deferred));
    LM_CHECK(n.all_ready());
    LM_CHECK_EQ(sent, 2U * 180U);
    LM_CHECK(received >= sent - 2); // at most the last round in flight at a boundary
    for (unsigned i = 1; i < 5; ++i) {
        const auto &m = n.eng(i).membership().stats();
        const auto &l = n.eng(i).link().stats();
        std::printf("  node %u: renewals %llu dropped %llu, lease left %lld ms, rotations %llu, lease closes %llu/%llu\n",
                    i, static_cast<unsigned long long>(m.renewals), static_cast<unsigned long long>(m.renew_dropped),
                    static_cast<long long>(n.lease(i)) - static_cast<long long>(n.root_ms()),
                    static_cast<unsigned long long>(l.rotations_started),
                    static_cast<unsigned long long>(l.sessions_lease_expired),
                    static_cast<unsigned long long>(n.eng(i).delivery().end_stats().lease_expired));
        LM_CHECK(m.renewals >= 16); // ~every 10 min for 3 h (docs/06 §7)
        LM_CHECK_EQ(n.state(i), static_cast<uint32_t>(LM_ACTIVE));
        LM_CHECK(n.lease(i) > n.root_ms() + 4 * k_min); // renewed within the last ~11 min
        LM_CHECK_EQ(l.sessions_lease_expired, 0u);      // no session ever ran into a lease end
        LM_CHECK_EQ(n.eng(i).delivery().end_stats().lease_expired, 0u);
        LM_CHECK_EQ(l.renew_only, 0u);                  // nobody needed the expired-lease path
    }
    // Every neighbour holds the renewed lease of its peer (the rotation after each renewal handed it over). The root
    // admits by its ledger, never by the lease (S18-D1), so a renewal does not rotate the link with it (ARCH2-D1).
    for (auto [a, b] : {std::pair{1U, 2U}, {2U, 3U}, {2U, 4U}}) {
        LM_CHECK(n.lease_at(a, b) + 20'000 >= n.lease(b) || n.lease_at(a, b) == n.lease(b));
        LM_CHECK(n.lease_at(a, b) > n.root_ms());
    }
    LM_CHECK_EQ(n.eng(0).ledger().count(root::EntryState::Active), 4u);
}

// LP12 (sim): the authorisation ends during a 30 min sleep. The node's neighbour admits it only to be renewed (a
// restricted, short link), the root renews it by its ledger, and the renewed credential - never the old lease -
// brings it back; the membership was never erased.
LM_TEST("LP12 S18 sim: a lease that ran out while powered off is renewed, not restored; the membership stays") {
    LNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    for (unsigned i = 0; i < 3; ++i) {
        n.boot(i);
    }
    LM_CHECK(n.until([&] { return n.all_ready(); }, 90'000));
    const uint64_t first = n.lease(2);
    n.node(2).power_cut(); // 30 min without power: its lease (15 min) runs out, nobody renews it
    n.node(2).store.power_restore();
    n.run_ms(30 * k_min);
    LM_CHECK(n.root_ms() > first + 5 * k_min);
    LM_CHECK(n.lease_at(1, 2) == 0); // the relay's session with it ended with its lease
    n.boot(2);
    LM_CHECK(n.until([&] { return n.ready(2) && n.lease(2) > n.root_ms(); }, 120'000));
    LM_CHECK(n.eng(1).link().stats().renew_only >= 1u); // the relay admitted it only to be renewed
    LM_CHECK(n.until([&] { return n.lease_at(1, 2) > n.root_ms(); }, 60'000)); // ... and holds the new lease
    LM_CHECK(n.lease(2) > first);
    LM_CHECK_EQ(n.state(2), static_cast<uint32_t>(LM_ACTIVE));
    LM_CHECK(n.eng(2).membership().stats().renewals >= 1u);
    // Application traffic flows again (it was held while the lease could not be proven).
    const lm_operation_id_t o = n.send_to_root(2);
    LM_CHECK(o != 0);
    LM_CHECK(n.until([&] { return n.op(2, o).phase == 3; }, 30'000));
    LM_CHECK_EQ(n.op(2, o).outcome, static_cast<uint32_t>(LM_OUTCOME_RECEIVED));
}

// ADR-002 P4: a renewed credential is committed at once but goes live only when no handshake is sending the bundle.
// That wait can be a whole handshake; it must not keep the node's one record memory (a durable send's journal
// write would wait for it). The record goes back meanwhile and the committed credential is read again at adoption.
LM_TEST("P4 S18 sim: a renewal waiting for a busy exchange gives the record memory back and goes live afterwards") {
    LNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}});
    for (unsigned i = 0; i < 3; ++i) {
        n.boot(i);
    }
    LM_CHECK(n.until([&] { return n.all_ready(); }, 90'000));
    const uint64_t first = n.lease(2);
    // The leaf's exchange is taken (as by a long handshake) just before its renewal comes (due 5 min before the end).
    LM_CHECK(n.until([&] { return n.root_ms() + 6 * k_min >= first; }, 15 * k_min, 1000));
    link::Exchange &x = n.eng(2).link().exchange();
    MutByteView lent;
    LM_CHECK(n.until([&] { return !(lent = x.lend_scratch()).empty(); }, 60'000, 5));
    const uint64_t writes = n.node(2).store.slot_writes();
    // The renewal is due within 5 min of the lease end: verified and committed although the exchange is busy.
    LM_CHECK(n.until([&] { return n.node(2).store.slot_writes() > writes; }, 15 * k_min, 50));
    n.run_ms(200);
    LM_CHECK_EQ(n.lease(2), first); // not live yet: the bundle may be on its way to a neighbour
    store::RecordJob *r = n.eng(2).identity().lend_record();
    LM_CHECK(r != nullptr); // ... and the record memory is free meanwhile
    if (r != nullptr) {
        n.eng(2).identity().return_record();
    }
    if (!lent.empty()) {
        x.return_scratch();
    }
    n.node(2).notify();
    LM_CHECK(n.until([&] { return n.lease(2) > first; }, 5000, 5)); // the committed credential went live
    LM_CHECK(n.eng(2).membership().stats().renewals >= 1u);
    // The relay holds the new lease at the latest once the old one has run out (in this bench the relay renewed at
    // the same moment against the blocked exchange, and the rate gate keeps their rotation from finishing earlier:
    // the same before P4).
    LM_CHECK(n.until([&] { return n.lease_at(1, 2) > first; }, 10 * k_min));
}

// R09 + external review finding 20: an address given to another device (the ledger is full, the old owner left) must
// not keep old routes alive. The root drops what it learned when the slot changes owner; a member drops them when an
// authenticated session shows it the address now belongs to another device (the old peer's session at that address
// goes with them). Before: a route learned from the departed device lived up to its session's hour.
LM_TEST("R09 REV-20 sim: a reused address leaves no stale route at the root or at a member") {
    LNet n({Spec{}, Spec{Role::Relay, 0xFFFFFFFFFFULL}, Spec{Role::Relay, 0xFFFFFFFFFFULL}, Spec{Role::Leaf, 0, true}},
           73, 62);
    n.link(0, 2);    // X (node 2) hangs below the root too: D1 (node 1) is not on its way
    n.link(1, 2, false);
    n.link(2, 3);    // the new device D2 (node 3) reaches the root through X
    for (unsigned i = 0; i < 3; ++i) {
        n.boot(i);
    }
    LM_CHECK(n.until([&] { return n.ready(1) && n.ready(2); }, 90'000));
    LM_CHECK_EQ(n.eng(0).ledger().count(root::EntryState::Free), 0u); // every slot is used
    // X talks to D1: X holds an end session with D1 (address 2) and a route to it; the root learns D1's way too.
    const lm_operation_id_t o1 = n.send_to(2, n.id(1));
    LM_CHECK(o1 != 0);
    LM_CHECK(n.until([&] { return n.op(2, o1).phase == 3; }, 30'000));
    LM_CHECK_EQ(n.op(2, o1).outcome, static_cast<uint32_t>(LM_OUTCOME_RECEIVED));
    const lm_operation_id_t o0 = n.send_to_root(1);
    LM_CHECK(n.until([&] { return n.op(1, o0).phase == 3; }, 30'000));
    LM_CHECK(n.has_route(2, n.id(1)));
    // D1 leaves; its slot (address 2) is the only one a new device can get.
    lm_operation_id_t lop = 0;
    LM_CHECK_EQ(lm_leave(n.ctx(1), LM_LEAVE_IMMEDIATE, 0, &lop), LM_STATUS_OK);
    n.node(1).notify();
    LM_CHECK(n.until([&] {
        const root::Entry *e = n.eng(0).ledger().find(n.id(1));
        return e != nullptr && e->state == root::EntryState::Left;
    }, 10'000));
    n.node(1).power_cut(); // gone for good
    n.run_ms(1000);
    n.eng(0).ledger().set_join_mode(root::JoinMode::Preapproved);
    n.boot(3);
    n.run_ms(500);
    n.grant(3, 1, 1); // the expected entry of D2 takes the left slot: address 2
    const root::Entry *e2 = n.eng(0).ledger().find(n.id(3));
    LM_CHECK(e2 != nullptr && e2->address == ShortAddr{2});
    // The root keeps no route of D1 any more (its slot has a new owner).
    LM_CHECK(!n.has_route(0, n.id(1)));
    LM_CHECK_EQ(n.join(3, 90), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.eng(3).identity().is_member() && n.ready(3); }, 120'000));
    LM_CHECK_EQ(n.eng(3).identity().member().address.value(), 2u);
    // X meets the new owner of address 2 (an end session): D1's session and every route learned before go.
    const lm_operation_id_t o2 = n.send_to(2, n.id(3));
    LM_CHECK(n.until([&] { return n.op(2, o2).phase == 3; }, 30'000));
    LM_CHECK_EQ(n.op(2, o2).outcome, static_cast<uint32_t>(LM_OUTCOME_RECEIVED));
    LM_CHECK(n.eng(2).delivery().sessions().find_peer(n.id(1)) == nullptr);
    LM_CHECK(!n.has_route(2, n.id(1)));
}

// R09 + review finding 20, precision (docs/04 §7): only what depends on the reused address goes. A route of the
// same node that never touches that address survives the reuse; the routes to and through it do not.
LM_TEST("R09 ARCH2 sim: a reused address drops the routes through it and keeps the others") {
    LNet n({Spec{}, Spec{Role::Relay, 0xFFFFFFFFFFULL}, Spec{Role::Relay, 0xFFFFFFFFFFULL},
            Spec{Role::Leaf, 0xFFFFFFFFFFULL}, Spec{Role::Leaf, 0, true}},
           74, 61);
    n.link(1, 2, false); // D1 (node 1, address 2) hangs below the root only
    n.link(0, 2);        // X (node 2) below the root
    n.link(2, 3, false);
    n.link(0, 3);        // Y (node 3, address 4) below the root: X reaches it without address 2
    n.link(3, 4, false);
    n.link(2, 4);        // the new device D2 (node 4) reaches the root through X
    for (unsigned i = 0; i < 4; ++i) {
        n.boot(i);
    }
    LM_CHECK(n.until([&] { return n.ready(1) && n.ready(2) && n.ready(3); }, 120'000));
    LM_CHECK_EQ(n.eng(0).ledger().count(root::EntryState::Free), 0u); // every slot is used
    const lm_operation_id_t o1 = n.send_to(2, n.id(1));
    LM_CHECK(n.until([&] { return n.op(2, o1).phase == 3; }, 30'000));
    LM_CHECK_EQ(n.op(2, o1).outcome, static_cast<uint32_t>(LM_OUTCOME_RECEIVED));
    lm_operation_id_t lop = 0;
    LM_CHECK_EQ(lm_leave(n.ctx(1), LM_LEAVE_IMMEDIATE, 0, &lop), LM_STATUS_OK);
    n.node(1).notify();
    LM_CHECK(n.until([&] {
        const root::Entry *e = n.eng(0).ledger().find(n.id(1));
        return e != nullptr && e->state == root::EntryState::Left;
    }, 10'000));
    n.node(1).power_cut(); // gone for good
    n.run_ms(1000);
    n.eng(0).ledger().set_join_mode(root::JoinMode::Preapproved);
    n.boot(4);
    n.run_ms(500);
    n.grant(4, 1, 1); // the expected entry of D2 takes the left slot: address 2
    const root::Entry *e2 = n.eng(0).ledger().find(n.id(4));
    LM_CHECK(e2 != nullptr && e2->address == ShortAddr{2});
    LM_CHECK_EQ(n.join(4, 90), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.eng(4).identity().is_member() && n.ready(4); }, 120'000));
    // X gets a route that does not touch address 2, then meets the new owner of address 2.
    const lm_operation_id_t oy = n.send_to(2, n.id(3));
    LM_CHECK(n.until([&] { return n.op(2, oy).phase == 3; }, 30'000));
    LM_CHECK_EQ(n.op(2, oy).outcome, static_cast<uint32_t>(LM_OUTCOME_RECEIVED));
    LM_CHECK(n.has_route(2, n.id(3)));
    const lm_operation_id_t o2 = n.send_to(2, n.id(4));
    LM_CHECK(n.until([&] { return n.op(2, o2).phase == 3; }, 30'000));
    LM_CHECK_EQ(n.op(2, o2).outcome, static_cast<uint32_t>(LM_OUTCOME_RECEIVED));
    LM_CHECK(n.eng(2).delivery().sessions().find_peer(n.id(1)) == nullptr); // D1's session at address 2 went
    LM_CHECK(!n.has_route(2, n.id(1)));                                    // with its route
    LM_CHECK(n.has_route(2, n.id(3)));                                     // Y's route never used address 2
}

// docs/04 §7, generation: the same device at the same address with a new membership generation (it left and joined
// again under a new grant) is a new owner of that address for the routes that went through it. The device's end
// sessions of the old membership end with its leave, so a peer that still holds one finds out at its next message
// (a fresh handshake shows the new generation) and drops every route through that address.
LM_TEST("R09 ARCH2 sim: a new membership generation at an address drops the routes through it") {
    LNet n({Spec{}, Spec{Role::Relay, 0xFFFFFFFFFFULL}, Spec{Role::Relay, 0xFFFFFFFFFFULL},
            Spec{Role::Leaf, 0xFFFFFFFFFFULL}},
           75);
    n.link(1, 2, false); // D1 (node 1, address 2) below the root, X (node 2) below the root
    n.link(0, 2);
    n.link(2, 3, false);
    n.link(1, 3);        // Z (node 3, address 4) below D1: X reaches it through address 2
    for (unsigned i = 0; i < 4; ++i) {
        n.boot(i);
    }
    LM_CHECK(n.until([&] { return n.ready(1) && n.ready(2) && n.ready(3); }, 120'000));
    const lm_operation_id_t o1 = n.send_to(2, n.id(1)); // X holds an end session with D1 (membership 1)
    LM_CHECK(n.until([&] { return n.op(2, o1).phase == 3; }, 30'000));
    LM_CHECK_EQ(n.op(2, o1).outcome, static_cast<uint32_t>(LM_OUTCOME_RECEIVED));
    const uint64_t m1 = n.eng(1).identity().member().membership.value();
    lm_operation_id_t lop = 0;
    LM_CHECK_EQ(lm_leave(n.ctx(1), LM_LEAVE_IMMEDIATE, 0, &lop), LM_STATUS_OK);
    n.node(1).notify();
    LM_CHECK(n.until([&] { return !n.eng(1).identity().is_member(); }, 10'000));
    n.eng(0).ledger().set_join_mode(root::JoinMode::Preapproved);
    n.grant(1, 2, 1);
    n.run_ms(31'000); // one full handshake per peer per 30 s (docs/06 §8)
    LM_CHECK_EQ(n.join(1, 0x63), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.eng(1).identity().is_member() && n.ready(1) && n.ready(3); }, 180'000));
    LM_CHECK_EQ(n.eng(1).identity().member().address.value(), 2u); // the same address ...
    const uint64_t m2 = n.eng(1).identity().member().membership.value();
    LM_CHECK(m2 > m1);                                              // ... a new membership generation
    const lm_operation_id_t oz = n.send_to(2, n.id(3)); // X's route to Z goes through address 2
    LM_CHECK(n.until([&] { return n.op(2, oz).phase == 3; }, 60'000));
    LM_CHECK_EQ(n.op(2, oz).outcome, static_cast<uint32_t>(LM_OUTCOME_RECEIVED));
    LM_CHECK(n.has_route(2, n.id(3)));
    // X's next message to D1 still goes under the session of membership 1, which D1 ended with its leave: no answer,
    // INDETERMINATE (never "received" under a membership that no longer exists), and the session is suspect.
    const lm_operation_id_t o2 = n.send_to(2, n.id(1));
    LM_CHECK(n.until([&] { return n.op(2, o2).phase == 3; }, 60'000));
    LM_CHECK_EQ(n.op(2, o2).outcome, static_cast<uint32_t>(LM_OUTCOME_INDETERMINATE));
    // The message after that makes a fresh session: it shows the new generation at address 2.
    const lm_operation_id_t o3 = n.send_to(2, n.id(1));
    LM_CHECK(n.until([&] { return n.op(2, o3).phase == 3; }, 60'000));
    LM_CHECK_EQ(n.op(2, o3).outcome, static_cast<uint32_t>(LM_OUTCOME_RECEIVED));
    const delivery::EndSession *s = n.eng(2).delivery().sessions().find_peer(n.id(1));
    LM_CHECK(s != nullptr && s->peer_membership.value() == m2); // never the old membership's session
    LM_CHECK(!n.has_route(2, n.id(3))); // the route through address 2 went with the old generation
}

// M02 + M03 (sim): both roots run. The member moves A -> B with the fleet's ticket: it is never ACTIVE in both, A's
// root cannot reach it afterwards (its credential names another root), its key and DeviceId stay. Then B -> A with a
// higher generation: A takes it back although its own ledger still lists the old membership (A never heard of the
// move); an old grant (a ticket at or below a consumed generation) is refused on both sides.
LM_TEST("M02 M03 sim: A -> B while A runs, never ACTIVE twice, A refused afterwards; then B -> A, old grants refused") {
    DNet n(1);
    const unsigned d = 2;
    n.eng(1).ledger().set_join_mode(root::JoinMode::Preapproved);
    LM_CHECK(n.in_domain(d, n.a));
    LM_CHECK_EQ(n.assignment(d), 1u);
    const Bytes ab = n.transfer_ticket(d, n.a, n.b, 1, 2);
    LM_CHECK_EQ(n.expect(1, n.b, d, 2, ab, 1), 0u);
    LM_CHECK_EQ(n.install(d, 3, ab), 0u); // a member installs the transfer away from its assignment
    const DeviceId self = n.eng(d).identity().self();
    // Watch the membership while the transfer runs: A until the switch, B after, never neither-with-both.
    bool both = false;
    bool moved = false;
    lm_join_request_t r{};
    r.struct_size = sizeof(r);
    r.abi_version = LM_ABI_VERSION;
    r.request_id = rid(0x31);
    r.mode = LM_JOIN_TRANSFER_CANDIDATE;
    lm_operation_id_t op = 0;
    LM_CHECK_EQ(lm_join(n.ctx(d), &r, &op), LM_STATUS_OK);
    n.node(d).notify();
    for (int k = 0; k < 12000 && !moved; ++k) {
        n.run_ms(5);
        const lm_membership_t m = n.membership(d);
        const bool in_a = n.in_domain(d, n.a);
        const bool in_b = n.in_domain(d, n.b);
        both = both || (in_a && in_b);
        moved = in_b;
        LM_CHECK(m.state == LM_ACTIVE || m.state == LM_PREPARED || m.state == LM_APPROVAL_PENDING ||
                 m.state == LM_AUTHENTICATING || m.state == LM_DISCOVERING);
    }
    LM_CHECK(moved && !both);
    LM_CHECK_EQ(n.assignment(d), 2u);
    LM_CHECK(n.eng(d).identity().self() == self); // key and DeviceId kept
    LM_CHECK(n.until([&] { return n.eng(d).membership().phase() == member::JoinPhase::Idle; }, 30'000));
    // B's ledger: ACTIVE with the new generation; A's ledger still lists the old one (it never heard of the move).
    const root::Entry *eb = n.eng(1).ledger().find(self);
    LM_CHECK(eb != nullptr && eb->state == root::EntryState::Active && eb->assignment == 2);
    const root::Entry *ea = n.eng(0).ledger().find(self);
    LM_CHECK(ea != nullptr && ea->state == root::EntryState::Active && ea->assignment == 1);
    // A's commands are refused: its root cannot even get a session (its credential names another root).
    const uint64_t rej = n.eng(d).link().stats().cred_rejected + n.eng(d).link().stats().rx_wrong_domain;
    LM_CHECK_OK(n.eng(0).link().connect(n.mac(d), n.node(0).clock.now()));
    n.node(0).notify();
    n.run_ms(6000);
    LM_CHECK(n.eng(0).link().neighbors().find_device(self) == nullptr);
    LM_CHECK(n.eng(d).link().stats().cred_rejected + n.eng(d).link().stats().rx_wrong_domain > rej);
    // B works: a link session with B's root.
    n.run_ms(31'000);
    LM_CHECK_OK(n.eng(d).link().connect(n.mac(1), n.node(d).clock.now()));
    n.node(d).notify();
    LM_CHECK(n.until([&] { return n.eng(1).link().neighbors().find_device(self) != nullptr; }, 6000));
    // Old grants: the A->B ticket again at B (consumed), the initial generation at A (consumed there).
    const Bytes replay = n.transfer_ticket(d, n.a, n.b, 1, 2);
    LM_CHECK(n.install(d, 3, replay) != 0u); // not a transfer away from the device's current assignment (2)
    // B -> A with a higher generation; A (external mode: an operator decides) supersedes its stale entry.
    n.eng(0).ledger().set_join_mode(root::JoinMode::External);
    const Bytes ba = n.transfer_ticket(d, n.b, n.a, 2, 3);
    LM_CHECK_EQ(n.install(d, 3, ba), 0u);
    r.request_id = rid(0x32);
    op = 0;
    LM_CHECK_EQ(lm_join(n.ctx(d), &r, &op), LM_STATUS_OK);
    n.node(d).notify();
    root::PendingJoin pj;
    LM_CHECK(n.until([&] { return n.eng(0).ledger().pending_join(0, pj) || n.eng(0).ledger().pending_join(1, pj); },
                     30'000));
    root::JoinDecision dec;
    dec.request = pj.request;
    dec.approve = true;
    Command cmd;
    cmd.kind = CommandKind::RootJoinDecide;
    cmd.request = &dec;
    cmd.request_size = sizeof(dec);
    LM_CHECK_OK(n.node(0).owner_call.call(cmd).status);
    LM_CHECK(n.until([&] { return n.in_domain(d, n.a); }, 60'000, 20));
    LM_CHECK_EQ(n.assignment(d), 3u);
    const root::Entry *ea2 = n.eng(0).ledger().find(self);
    LM_CHECK(ea2 != nullptr && ea2->assignment == 3 && ea2->membership == 2); // the same slot, the next membership
    std::printf("  M03: A(1) -> B(2) -> A(3), address kept %u\n", ea2 != nullptr ? ea2->address.value() : 0);
}

// M01 (sim): A's root is off. The member still moves to B with the fleet's ticket (A's consent is not needed); A's
// ledger keeps listing it until A hears of the move: the transfer ticket installed at A's root reconciles it (entry
// left, generations floored, docs/07 §8), after which A refuses the old membership.
LM_TEST("M01 sim: A off, the move to B commits; A reconciles later from the same ticket") {
    DNet n(1, 82);
    const unsigned d = 2;
    n.eng(1).ledger().set_join_mode(root::JoinMode::Preapproved);
    const Bytes ab = n.transfer_ticket(d, n.a, n.b, 1, 2);
    LM_CHECK_EQ(n.expect(1, n.b, d, 2, ab, 1), 0u);
    LM_CHECK_EQ(n.install(d, 3, ab), 0u);
    n.node(0).power_cut(); // A's root is gone
    n.node(0).store.power_restore();
    LM_CHECK(n.transfer(d, n.b, 0x41));
    LM_CHECK_EQ(n.assignment(d), 2u);
    // A comes back: its ledger still says ACTIVE (reconciliation pending) until it is told.
    n.boot(0);
    n.run_ms(200);
    n.set_time();
    const root::Entry *ea = n.eng(0).ledger().find(n.id(d));
    LM_CHECK(ea != nullptr && ea->state == root::EntryState::Active);
    LM_CHECK_EQ(n.install(0, 3, ab), 0u); // the same fleet ticket: A learns of the move
    ea = n.eng(0).ledger().find(n.id(d));
    LM_CHECK(ea != nullptr && ea->state == root::EntryState::Left);
    LM_CHECK(n.eng(0).identity().floors().check(n.id(d), AssignmentGen{1}, MembershipGen{1}) == Status::Revoked);
    LM_CHECK_EQ(n.eng(0).ledger().stats().reconciled, 1u);
    LM_CHECK_EQ(n.install(0, 3, ab), 0u); // twice: done already (idempotent, no second entry commit)
    LM_CHECK_EQ(n.eng(0).ledger().stats().reconciled, 1u);
    LM_CHECK(n.eng(0).ledger().find(n.id(d))->state == root::EntryState::Left);
    LM_CHECK(n.in_domain(d, n.b)); // B's membership is untouched by A's reconciliation
}

// M04 (sim): a lost device. The fleet's RevokeObject (floors above its generations) reaches the roots; the device, which
// never heard of it, is refused by its root, and its move to B is refused too where B knows the floor. Without that
// knowledge B would accept (docs/07 §8: stale revocation information is the stated limit, not hidden).
LM_TEST("M04 sim: a revoked (lost) device is refused by its root and by a root that knows the fleet floor") {
    DNet n(1, 83);
    const unsigned d = 2;
    n.node(d).power_cut(); // lost: out of reach
    n.node(d).store.power_restore();
    const Bytes rv = n.a.fleet.revoke(n.id(d), 3, 0); // every assignment below 3: also the ticket it still holds
    LM_CHECK_EQ(n.install(0, 11, rv), 0u);
    const root::Entry *ea = n.eng(0).ledger().find(n.id(d));
    LM_CHECK(ea != nullptr && ea->state == root::EntryState::Blocked);
    LM_CHECK_EQ(n.eng(0).ledger().stats().revoked, 1u);
    LM_CHECK_EQ(n.install(1, 11, rv), 0u); // B learns the fleet floor too (no entry of its own for the device)
    n.eng(1).ledger().set_join_mode(root::JoinMode::Preapproved);
    const Bytes ab = n.transfer_ticket(d, n.a, n.b, 1, 2);
    LM_CHECK_EQ(n.expect(1, n.b, d, 2, ab, 1), 0u);
    // The device comes back (it still believes it is ACTIVE: nothing reached it).
    n.boot(d);
    n.run_ms(200);
    n.set_time();
    LM_CHECK(n.in_domain(d, n.a));
    const uint64_t refused = n.eng(0).link().stats().cred_rejected;
    LM_CHECK_OK(n.eng(d).link().connect(n.mac(0), n.node(d).clock.now()));
    n.node(d).notify();
    n.run_ms(6000);
    LM_CHECK(n.eng(0).link().neighbors().find_device(n.id(d)) == nullptr); // its root refuses it
    LM_CHECK(n.eng(0).link().stats().cred_rejected > refused);
    LM_CHECK_EQ(n.install(d, 3, ab), 0u);
    LM_CHECK(!n.transfer(d, n.b, 0x42, 40'000)); // B refuses the revoked device (fail closed on the floor)
    LM_CHECK(n.eng(1).ledger().stats().refused >= 1u);
    LM_CHECK(n.in_domain(d, n.a)); // and it is still what it was: nothing half-moved
}

// M05 (sim): a power cut before / torn / after every mutating Flash step of a transfer, on the device and on B's root.
// Right after the restart the device is an ACTIVE member of A or of B - never both, never neither, never a credential
// of one root under the delegation of the other - and B's ledger agrees with it (B ACTIVE while the device is still in
// A only with the device's PREPARED record, which it asks about again). Then both converge on B by the durable
// evidence: the resumed request, the same request id, or (the reservation aborted) a new expected entry.
namespace {
struct CutRun {
    bool fired = false;
    bool ok = false;
    bool moved = false;
    std::string why;
};
[[maybe_unused]] const char *cut_name(CutMode m) { return m == CutMode::Before ? "before" : m == CutMode::Torn ? "torn" : "after"; }

CutRun transfer_cut(unsigned target, uint64_t k, CutMode mode) {
    CutRun out;
    DNet n(1, 300 + k * 5 + target);
    const unsigned d = 2;
    n.eng(1).ledger().set_join_mode(root::JoinMode::Preapproved);
    const Bytes ab = n.transfer_ticket(d, n.a, n.b, 1, 2);
    if (n.expect(1, n.b, d, 2, ab, 1) != 0 || n.install(d, 3, ab) != 0) {
        out.why = "setup";
        return out;
    }
    SimStore &st = n.node(target).store;
    st.arm_cut(st.mutating_ops() + k, mode);
    if (n.start_join(d, 0x43, LM_JOIN_TRANSFER_CANDIDATE) != LM_STATUS_OK) {
        out.why = "transfer refused";
        return out;
    }
    out.fired = n.until([&] { return st.cut_fired(); }, 60'000, 20);
    if (!out.fired) {
        out.ok = n.in_domain(d, n.b); // fewer operations than k: the transfer completed untouched
        out.why = out.ok ? "" : "no cut, no move";
        return out;
    }
    n.reboot(target);
    n.eng(1).ledger().set_join_mode(root::JoinMode::Preapproved); // (B's application sets its policy at boot)
    // ---- allowed states right after the restart ----
    const member::LocalIdentity &id = n.eng(d).identity();
    const bool in_a = n.in_domain(d, n.a);
    const bool in_b = n.in_domain(d, n.b);
    const root::Entry *eb = n.eng(1).ledger().find(n.id(d));
    if (id.state() != member::LocalIdentity::State::Ready || in_a == in_b) {
        out.why = in_a ? "ACTIVE in both" : "device ACTIVE nowhere or unloadable";
        return out;
    }
    if (id.delegation().domain != (in_a ? n.a.domain : n.b.domain) || id.member().assignment.value() != (in_a ? 1U : 2U)) {
        out.why = "credential and delegation of different roots";
        return out;
    }
    if (eb == nullptr) {
        out.why = "B lost the expected entry";
        return out;
    }
    if (in_b && !(eb->state == root::EntryState::Active && eb->assignment == 2 &&
                  eb->membership == id.member().membership.value() && eb->address == id.member().address)) {
        out.why = "device in B, B's entry does not say so";
        return out;
    }
    if (in_a && eb->state == root::EntryState::Active && !n.eng(d).membership().prepared_record()) {
        out.why = "B ACTIVE, the device in A without its PREPARED record";
        return out;
    }
    if (eb->state != root::EntryState::Expected && eb->state != root::EntryState::Prepared &&
        eb->state != root::EntryState::Active && eb->state != root::EntryState::Aborted) {
        out.why = "B's entry in a state no join produces";
        return out;
    }
    // ---- convergence ----
    uint64_t revision = 1;
    for (int round = 0; round < 12; ++round) { // (a request waits up to 310 s for an answer: approval time)
        n.run_ms(31'000);
        n.set_time();
        const root::Entry *re = n.eng(1).ledger().find(n.id(d));
        const bool b_now = n.in_domain(d, n.b);
        if (b_now && re != nullptr && re->state == root::EntryState::Active && re->confirmed &&
            !n.eng(d).membership().confirm_pending()) {
            break;
        }
        const bool prepared = n.eng(d).membership().prepared_record();
        if (!b_now && !prepared && re != nullptr && re->state == root::EntryState::Aborted) {
            ++revision; // the operator: the reservation ended without the device, expect it again
            (void)n.expect(1, n.b, d, 2, ab, revision);
        }
        if (n.eng(d).membership().phase() != member::JoinPhase::Idle) {
            continue; // the resumed request, a join or its NOT_EXPECTED hold is still running
        }
        if (b_now) {
            (void)n.start_join(d, static_cast<uint8_t>(0x61 + round), LM_JOIN_RESUME); // owed acknowledgement
        } else if (prepared) {
            (void)n.start_join(d, 0x43, LM_JOIN_TRANSFER_CANDIDATE); // the stored request, by its own id
        } else {
            (void)n.start_join(d, static_cast<uint8_t>(0x70 + round), LM_JOIN_TRANSFER_CANDIDATE);
        }
        n.run_ms(6000);
    }
    const root::Entry *fe = n.eng(1).ledger().find(n.id(d));
    out.moved = n.in_domain(d, n.b) && fe != nullptr && fe->state == root::EntryState::Active && fe->confirmed &&
                !n.eng(d).membership().confirm_pending() && fe->membership == id.member().membership.value() &&
                fe->address == id.member().address;
    out.ok = out.moved;
    if (!out.ok) {
        out.why = std::string("did not converge: device ") + (n.in_domain(d, n.b) ? "in B" : "in A") + ", B's entry " +
                  std::to_string(fe != nullptr ? static_cast<int>(fe->state) : -1) +
                  (fe != nullptr && fe->confirmed ? " confirmed" : "") + " phase " +
                  std::to_string(static_cast<int>(n.eng(d).membership().phase()));
    }
    return out;
}
} // namespace

LM_TEST("M05 sim: power cut at each record-write boundary of a transfer (device, B's root) leaves exactly old or new") {
    const lmtest::CutTotals t = lmtest::cut_matrix(
        "transfer", {{2, "device"}, {1, "B root"}}, [](unsigned target, uint64_t k, CutMode mode) {
            const CutRun r = transfer_cut(target, k, mode);
            return lmtest::CutRun{r.fired, r.ok, r.moved, r.why};
        });
    LM_CHECK(t.points >= 20);
}

// S06 (sim): the revoked member is out of range. The network side proceeds at once (its root admits and renews it no
// more, its end session there ends), the rest of the network follows within the lease (no renewal: its neighbours
// only give it the short renewal-only link, and the root refuses the renewal), and the device's own erasure stays
// unconfirmed - reported apart from the network refusal. In range, the signed notice erases its membership.
LM_TEST("S06 sim: revocation proceeds without the target; its erasure is separate; in range the notice erases it") {
    LNet n({Spec{}, Spec{Role::Relay}, Spec{Role::Leaf}, Spec{Role::Leaf}});
    n.link(2, 3, false);
    n.link(1, 3); // both leaves hang below the relay
    for (unsigned i = 0; i < 4; ++i) {
        n.boot(i);
    }
    LM_CHECK(n.until([&] { return n.all_ready(); }, 90'000));
    n.link(1, 2, false); // leaf 2 is out of range
    const uint64_t revoke_at = n.root_ms();
    const Bytes rv = fleet::issue_root_revoke(n.kits[0].kit, n.net.domain, n.id(2), 2, 2);
    LM_CHECK_EQ(n.install(0, 11, rv), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.eng(0).ledger().stats().revoked == 1; }, 5000));
    LM_CHECK(n.eng(0).ledger().find(n.id(2))->state == root::EntryState::Blocked);
    n.run_ms(11'000); // the notice's chance is over: the root holds nothing of it any more
    LM_CHECK(n.eng(0).delivery().sessions().find_peer(n.id(2)) == nullptr);
    // Back in range before its lease ends: its neighbour still knows its lease, but the root renews nothing.
    n.link(1, 2);
    LM_CHECK(n.until([&] { return n.root_ms() > revoke_at + 16 * k_min; }, 20 * k_min, 1000));
    LM_CHECK(n.lease(2) < n.root_ms());                  // never renewed
    LM_CHECK(n.lease_at(1, 2) == 0 || n.eng(1).link().neighbors().find_device(n.id(2))->renew_only);
    LM_CHECK_EQ(n.state(2), static_cast<uint32_t>(LM_ACTIVE)); // its own erasure: not confirmed (it never heard)
    LM_CHECK(n.eng(0).ledger().find(n.id(2))->state == root::EntryState::Blocked);
    const lm_operation_id_t o2 = n.send_to_root(2, 20'000); // the network refuses it (locally or on the way)
    n.run_ms(25'000);
    LM_CHECK(o2 == 0 || n.op(2, o2).outcome != LM_OUTCOME_RECEIVED);
    LM_CHECK(n.ready(3)); // the others are untouched
    // In range, over the end session it already has with the root, the signed notice erases the membership on the
    // device itself (a revoked device gets no new session: the notice cannot open one).
    const lm_operation_id_t o3 = n.send_to_root(3);
    LM_CHECK(o3 != 0);
    LM_CHECK(n.until([&] { return n.op(3, o3).phase == 3; }, 30'000));
    const Bytes rv3 = fleet::issue_root_revoke(n.kits[0].kit, n.net.domain, n.id(3), 2, 2);
    LM_CHECK_EQ(n.install(0, 11, rv3), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.state(3) == LM_MEMBER_REVOKED; }, 30'000));
    LM_CHECK(!n.eng(3).identity().is_member());
    n.node(3).power_cut();
    n.node(3).store.power_restore();
    n.boot(3);
    n.run_ms(300);
    LM_CHECK_EQ(n.state(3), static_cast<uint32_t>(LM_MEMBER_REVOKED)); // durable: the REVOKED tombstone
}

// Handover helpers: device d moves to the new root (true when it is its member within the wait).
namespace {
bool switched(DNet &n, unsigned d) {
    const member::LocalIdentity &id = n.eng(d).identity();
    return id.is_member() && id.delegation().generation == 2 && id.delegation().root == n.id(1);
}
bool hand_over(DNet &n, unsigned d, uint8_t req, uint64_t wait_ms = 60'000) {
    return n.start_join(d, req, LM_JOIN_TRANSFER_CANDIDATE) == LM_STATUS_OK &&
           n.until([&] { return switched(n, d); }, wait_ms, 20);
}
} // namespace

// LC08 (sim): planned root replacement (docs/21 §8). The old root drains: it retires on the fleet's RootHandover,
// durably, and admits and offers nothing. Every member stores the object (per-node evidence). The new root device starts
// from the drained ledger (a verified backup) and each member authenticates afresh with it: a credential of the new
// term under the new delegation, the same assignment, the next membership generation. Nothing of the old root's
// authority is carried over (the old root's credential opens no session with a moved member).
LM_TEST("LC08 sim: planned root handover - old root retires, members re-authenticate under the new delegation") {
    DNet n(2, 85, DNet::Kind::Handover);
    const Bytes ho = n.a.fleet.handover(n.a.domain, n.handover());
    std::array<uint64_t, 4> before{};
    for (unsigned d = 2; d < 4; ++d) {
        before[d] = n.eng(d).identity().member().membership.value();
    }
    LM_CHECK_EQ(n.install(0, 31, ho), 0u); // the old root retires
    LM_CHECK(n.eng(0).ledger().retired());
    for (unsigned d = 2; d < 4; ++d) {
        LM_CHECK_EQ(n.install(d, 31, ho), 0u); // stored at every member (its own evidence)
    }
    n.provision_new_root(true);
    n.boot(1);
    n.run_ms(300);
    n.set_time(2, 1);
    LM_CHECK_EQ(n.install(1, 31, ho), 0u); // the new root recognises itself; nothing changes
    LM_CHECK_EQ(n.eng(1).ledger().count(root::EntryState::Active), 2u);
    n.reboot(0); // the retirement is durable
    LM_CHECK(n.eng(0).ledger().retired());
    for (unsigned d = 2; d < 4; ++d) {
        LM_CHECK(hand_over(n, d, static_cast<uint8_t>(0x50 + d)));
        const member::MemberCredential &mc = n.eng(d).identity().member();
        LM_CHECK(mc.root_term == RootTerm{2});
        LM_CHECK_EQ(mc.assignment.value(), 1u);
        LM_CHECK_EQ(mc.membership.value(), before[d] + 1);
        LM_CHECK(n.until([&] { return n.eng(d).membership().phase() == member::JoinPhase::Idle; }, 30'000));
        const root::Entry *e = n.eng(1).ledger().find(n.id(d));
        LM_CHECK(e != nullptr && e->state == root::EntryState::Active && e->membership == before[d] + 1);
    }
    std::printf("  LC08: members 2, 3 moved to the new root (term 2, delegation 2)\n");
    n.run_ms(31'000); // (the full-handshake gate towards the root the join just used)
    n.set_time(2, 1);
    // Fresh link sessions with the new root; the old root gets none.
    for (unsigned d = 2; d < 4; ++d) {
        LM_CHECK_OK(n.eng(d).link().connect(n.mac(1), n.node(d).clock.now()));
        n.node(d).notify();
        LM_CHECK(n.until([&] { return n.eng(1).link().neighbors().find_device(n.id(d)) != nullptr; }, 6000));
    }
    n.run_ms(31'000);
    (void)n.eng(0).link().connect(n.mac(2), n.node(0).clock.now());
    n.node(0).notify();
    n.run_ms(6000);
    LM_CHECK(n.eng(2).link().neighbors().find_device(n.id(0)) == nullptr);
    LM_CHECK(n.eng(0).link().neighbors().find_device(n.id(2)) == nullptr);
}

// LC09 (sim): the old root failed. Without a backup the new root is RECOVERY_REQUIRED: it offers nothing and admits
// nobody (never an empty ledger that re-admits members from nothing), and its members wait for their old root. A
// handover whose term is not above the members' known one is refused. With a verified backup the members move.
LM_TEST("LC09 sim: failed old root - no backup is RECOVERY_REQUIRED, the term must rise, a verified backup works") {
    {
        DNet n(1, 86, DNet::Kind::Handover);
        n.provision_new_root(false);
        n.node(0).power_cut(); // failed, never retired
        n.boot(1);
        n.run_ms(300);
        const Bytes ho = n.a.fleet.handover(n.a.domain, n.handover());
        LM_CHECK_EQ(n.install(1, 31, ho), static_cast<uint32_t>(LM_STATUS_RECOVERY_REQUIRED));
        LM_CHECK_EQ(n.install(2, 31, ho), 0u);
        LM_CHECK(!hand_over(n, 2, 0x51, 40'000));
        LM_CHECK(n.eng(2).identity().is_member() && n.eng(2).identity().delegation().generation == 1); // waits
        LM_CHECK_EQ(n.eng(1).ledger().count(root::EntryState::Active), 0u);
    }
    {
        DNet n(1, 87, DNet::Kind::Handover);
        n.provision_new_root(true);
        n.node(0).power_cut();
        n.boot(1);
        n.run_ms(300);
        const Bytes stale = n.a.fleet.handover(n.a.domain, n.handover(1)); // term 1: not above the known term
        // The new root cannot tell which of its boots' terms the fleet named (ARCH2-D1: one term per boot); it only
        // refuses a term it has not reached. The floor is the device's check: above the term it knows.
        LM_CHECK_EQ(n.install(1, 31, stale), 0u);
        LM_CHECK_EQ(n.install(2, 31, stale), 0u); // (the device checks the term against the root it meets)
        LM_CHECK(!hand_over(n, 2, 0x52, 40'000));
        LM_CHECK(n.eng(2).identity().delegation().generation == 1);
        n.run_ms(31'000);
        const Bytes ho = n.a.fleet.handover(n.a.domain, n.handover());
        LM_CHECK_EQ(n.install(2, 31, ho), 0u);
        LM_CHECK(hand_over(n, 2, 0x53));
        std::printf("  LC09: moved with a verified backup after the stale-term object was refused\n");
    }
}

// LC10 (sim): the old root reappears after a failure handover. A member that accepted the new delegation refuses it; a
// member the object never reached still follows it and is not counted as moved (its entry at the new root is the
// backup's, never re-issued); the object installed at the old root retires it, and then that member moves too.
LM_TEST("LC10 sim: old root reappears - refused by moved members, the unreached one not counted, retires on the object") {
    DNet n(2, 88, DNet::Kind::Handover);
    n.provision_new_root(true);
    n.node(0).power_cut();
    n.node(0).store.power_restore();
    n.boot(1);
    n.run_ms(300);
    const Bytes ho = n.a.fleet.handover(n.a.domain, n.handover());
    const uint64_t m3 = n.eng(3).identity().member().membership.value();
    LM_CHECK_EQ(n.install(2, 31, ho), 0u);
    LM_CHECK(hand_over(n, 2, 0x54));
    n.boot(0); // the old root is back, unaware
    n.run_ms(300);
    n.set_time();
    n.set_time(2, 1);
    LM_CHECK(!n.eng(0).ledger().retired());
    // The unreached member still has its session with the old root; the moved one refuses the old root.
    LM_CHECK_OK(n.eng(3).link().connect(n.mac(0), n.node(3).clock.now()));
    n.node(3).notify();
    LM_CHECK(n.until([&] { return n.eng(0).link().neighbors().find_device(n.id(3)) != nullptr; }, 6000));
    const uint64_t rej = n.eng(2).link().stats().cred_rejected + n.eng(2).link().stats().rx_wrong_domain +
                         n.eng(0).link().stats().cred_rejected;
    (void)n.eng(0).link().connect(n.mac(2), n.node(0).clock.now());
    n.node(0).notify();
    n.run_ms(6000);
    LM_CHECK(n.eng(2).link().neighbors().find_device(n.id(0)) == nullptr);
    LM_CHECK(n.eng(2).link().stats().cred_rejected + n.eng(2).link().stats().rx_wrong_domain +
                 n.eng(0).link().stats().cred_rejected > rej);
    const root::Entry *e3 = n.eng(1).ledger().find(n.id(3));
    LM_CHECK(e3 != nullptr && e3->membership == m3); // not moved: nothing issued for it at the new root
    LM_CHECK(!switched(n, 3));
    // The object reaches the old root: it retires and ends its sessions; then the last member moves.
    LM_CHECK_EQ(n.install(0, 31, ho), 0u);
    LM_CHECK(n.eng(0).ledger().retired());
    n.run_ms(1000);
    LM_CHECK(n.eng(0).link().neighbors().find_device(n.id(3)) == nullptr);
    LM_CHECK_EQ(n.install(3, 31, ho), 0u);
    LM_CHECK(hand_over(n, 3, 0x55));
    LM_CHECK(n.eng(1).ledger().find(n.id(3))->membership == m3 + 1);
}

// Commissioning window helpers: a star around the root (every device one hop away).
namespace {
void star(LNet &n) {
    for (unsigned i = 1; i < n.n; ++i) {
        n.link(0, i);
        if (i + 1 < n.n) {
            n.link(i, i + 1, false);
        }
    }
}
member::CommissioningWindow make_window(uint64_t now_ms, uint64_t span_ms, uint8_t max, uint64_t revision) {
    member::CommissioningWindow w;
    w.id[0] = static_cast<uint8_t>(revision);
    w.id[1] = max;
    w.term = RootTerm{1};
    w.expected_revision = revision;
    w.not_before_ms = now_ms;
    w.expires_ms = now_ms + span_ms;
    w.max_new_members = max;
    w.allowed_roles = 3; // leaves and relays
    w.policy_revision = 1;
    return w;
}
} // namespace

// LC01 (sim): a CLOSED root admits only inside its commissioning window (docs/21 §2). Before and after it nothing is
// approved; a request authenticated inside the window but decided after its end is refused (EXPIRED); the member
// admitted inside stays one and keeps working.
LM_TEST("LC01 sim: commissioning window expiry - only inside it; a late decision is refused; the admitted member stays") {
    LNet n({Spec{}, Spec{Role::Leaf, 0, true}, Spec{Role::Leaf, 0, true}, Spec{Role::Leaf, 0, true}}, 75);
    star(n);
    for (unsigned i = 0; i < 4; ++i) {
        n.boot(i);
    }
    n.run_ms(1000);
    n.eng(0).ledger().set_join_mode(root::JoinMode::Closed);
    for (unsigned i = 1; i < 4; ++i) {
        n.grant(i, 1, i); // ticket at the device, expected entry at the root (revisions 1..3)
    }
    LM_CHECK_EQ(n.join(1, 0x11), LM_STATUS_OK); // before the window: a CLOSED root does not even answer
    n.run_ms(40'000);
    LM_CHECK(!n.eng(1).identity().is_member());
    const member::CommissioningWindow w = make_window(n.root_ms(), 60'000, 3, 3);
    LM_CHECK_EQ(n.install(0, 30, n.net.fleet.window(n.net.domain, w)), LM_STATUS_OK);
    LM_CHECK(n.eng(0).ledger().window_open(n.node(0).clock.now()));
    LM_CHECK_EQ(n.join(1, 0x12), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.eng(1).identity().is_member(); }, 30'000));
    // Device 2 authenticates inside the window; the root's ticket check ends after it (a slow worker).
    LM_CHECK(n.until([&] { return n.root_ms() + 8000 >= w.expires_ms; }, 70'000, 100));
    LM_CHECK_EQ(n.join(2, 0x21), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.eng(2).membership().phase() == member::JoinPhase::LoadTicket; }, 8000, 1));
    LM_CHECK(n.root_ms() < w.expires_ms);
    n.node(0).jobs.latency_us = 12'000'000;
    LM_CHECK(n.until([&] { return n.eng(2).membership().phase() == member::JoinPhase::Idle; }, 60'000));
    n.node(0).jobs.latency_us = 2000;
    LM_CHECK(!n.eng(2).identity().is_member());
    LM_CHECK(n.eng(2).membership().reason() == Status::Expired);
    LM_CHECK_EQ(n.join(3, 0x31), LM_STATUS_OK); // after the window: nothing
    n.run_ms(40'000);
    LM_CHECK(!n.eng(3).identity().is_member());
    LM_CHECK_EQ(n.eng(0).ledger().stats().window_admitted, 1u);
    LM_CHECK(n.eng(1).identity().is_member());
    LM_CHECK(n.until([&] { return n.ready(1); }, 60'000));
    // The same window installed again (e.g. after a root restart) goes on with its durable count; a spent one admits
    // nobody more. (Here: a window of one, spent by device 1.)
    const member::CommissioningWindow w1 = make_window(n.root_ms(), 60'000, 1, 3);
    LM_CHECK_EQ(n.install(0, 30, n.net.fleet.window(n.net.domain, w1)), LM_STATUS_OK);
    LM_CHECK(n.eng(0).ledger().window_open(n.node(0).clock.now()));
}

// LC02 (sim; 10 devices instead of 64): a batch powered on at once under one window whose budget is two short. Each
// device's result is its own evidence (its membership matches its root entry), no request is reserved twice (repeats
// are answered, never counted again), the budget is exact, and an existing member's DATA flows meanwhile.
LM_TEST("LC02 sim: batch of 10 powered on at once - per-device evidence, no double reservation, exact budget, DATA flows") {
    const unsigned batch = 10;
    std::vector<Spec> specs{Spec{}, Spec{Role::Leaf}};
    for (unsigned i = 0; i < batch; ++i) {
        specs.push_back(Spec{Role::Leaf, 0, true});
    }
    LNet n(specs, 76);
    star(n);
    n.boot(0);
    n.boot(1);
    LM_CHECK(n.until([&] { return n.ready(1); }, 90'000));
    n.eng(0).ledger().set_join_mode(root::JoinMode::Closed);
    for (unsigned i = 2; i < n.n; ++i) {
        n.boot(i);
    }
    n.run_ms(500);
    for (unsigned i = 2; i < n.n; ++i) {
        n.grant(i, 1, i - 1);
    }
    const uint8_t budget = batch - 2;
    const member::CommissioningWindow w = make_window(n.root_ms(), 14 * k_min, budget, batch);
    LM_CHECK_EQ(n.install(0, 30, n.net.fleet.window(n.net.domain, w)), LM_STATUS_OK);
    for (unsigned i = 2; i < n.n; ++i) {
        LM_CHECK_EQ(n.join(i, static_cast<uint8_t>(0x40 + i)), LM_STATUS_OK);
    }
    unsigned sent = 0;
    unsigned received = 0;
    std::vector<lm_operation_id_t> ops;
    auto members = [&] {
        unsigned m = 0;
        for (unsigned i = 2; i < n.n; ++i) {
            m += n.eng(i).identity().is_member() ? 1 : 0;
        }
        return m;
    };
    // One message every 10 s, each looked at 10 s later (the operation table keeps recent operations only).
    for (int round = 0; round < 12 || (round < 40 && members() < budget); ++round) {
        for (const lm_operation_id_t o : ops) {
            const lm_operation_t r = n.op(1, o);
            received += r.phase == 3 && r.outcome == LM_OUTCOME_RECEIVED ? 1 : 0;
        }
        ops.clear();
        n.drain_events();
        for (unsigned i = 2; i < n.n; ++i) { // the application asks again for a device whose search ended
            if (!n.eng(i).identity().is_member() && n.eng(i).membership().phase() == member::JoinPhase::Idle) {
                const bool same = n.eng(i).membership().prepared_record();
                (void)n.join(i, static_cast<uint8_t>(same ? 0x40 + i : 0x80 + 16 * round + i));
            }
        }
        if (const lm_operation_id_t o = n.send_to_root(1, 30'000); o != 0) {
            ops.push_back(o);
            ++sent;
        }
        n.run_ms(10'000);
    }
    n.run_ms(30'000);
    for (const lm_operation_id_t o : ops) {
        received += n.op(1, o).outcome == LM_OUTCOME_RECEIVED ? 1 : 0;
    }
    n.run_ms(30'000); // the last ones settle (and the two over budget give up)
    const auto &st = n.eng(0).ledger().stats();
    std::printf("  LC02: %u of %u joined (budget %u); ledger prepared %llu requests %llu refused %llu; DATA %u/%u\n",
                members(), batch, budget, static_cast<unsigned long long>(st.prepared),
                static_cast<unsigned long long>(st.requests), static_cast<unsigned long long>(st.refused), received,
                sent);
    LM_CHECK_EQ(members(), static_cast<unsigned>(budget));
    LM_CHECK_EQ(st.window_admitted, static_cast<uint64_t>(budget));
    LM_CHECK_EQ(st.prepared, static_cast<uint64_t>(budget)); // one reservation per admitted request
    LM_CHECK_EQ(n.eng(0).ledger().count(root::EntryState::Active), 1u + budget);
    for (unsigned i = 2; i < n.n; ++i) {
        const root::Entry *e = n.eng(0).ledger().find(n.id(i));
        const bool member = n.eng(i).identity().is_member();
        LM_CHECK(e != nullptr);
        if (member) {
            LM_CHECK(e->state == root::EntryState::Active &&
                     e->membership == n.eng(i).identity().member().membership.value() &&
                     e->address == n.eng(i).identity().member().address);
        } else {
            LM_CHECK(e->state == root::EntryState::Expected); // nothing reserved for one that did not get in
        }
    }
    LM_CHECK(sent >= 12u && received >= sent - 1);
}

// LC11 (sim): network reset is lm_leave(IMMEDIATE) (docs/21 §9). The membership and its sessions go; the DeviceId, the
// fleet anchor, the floors (the device's own consumed generation) and the boot counter stay, across a restart too. The
// consumed grant brings nobody back; a new grant of a higher generation does.
LM_TEST("LC11 sim: network reset keeps identity, fleet anchor, floors and boot counter; no rejoin without a new grant") {
    LNet n({Spec{}, Spec{Role::Leaf, 0, true}}, 77);
    n.boot(0);
    n.boot(1);
    n.run_ms(1000);
    n.eng(0).ledger().set_join_mode(root::JoinMode::Preapproved);
    const Bytes t1 = n.net.fleet.ticket(n.kits[1].kit, DomainId{}, n.net.domain, n.net.delegation_cose, 0, 1);
    LM_CHECK_EQ(n.install(1, 3, t1), LM_STATUS_OK);
    LM_CHECK_EQ(n.install(0, 5, n.expected_page(1, 1, t1, 1)), LM_STATUS_OK);
    LM_CHECK_EQ(n.join(1, 0x61), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.eng(1).identity().is_member() && n.ready(1); }, 120'000));
    const DeviceId self = n.eng(1).identity().self();
    const DeviceId fleet_key = n.eng(1).identity().trust().key_id;
    const uint64_t boots = n.eng(1).delivery().durable().incarnation();
    lm_operation_id_t op = 0;
    LM_CHECK_EQ(lm_leave(n.ctx(1), LM_LEAVE_IMMEDIATE, 0, &op), LM_STATUS_OK);
    n.node(1).notify();
    LM_CHECK(n.until([&] { return !n.eng(1).identity().is_member(); }, 10'000));
    n.node(1).power_cut();
    n.node(1).store.power_restore();
    n.boot(1);
    n.run_ms(500);
    const member::LocalIdentity &id = n.eng(1).identity();
    LM_CHECK(id.state() == member::LocalIdentity::State::Ready && !id.is_member());
    LM_CHECK(id.self() == self);
    LM_CHECK(id.trust().key_id == fleet_key);
    LM_CHECK(id.own_floor().assignment >= 2u); // generation 1 consumed for good
    LM_CHECK(n.eng(1).delivery().durable().incarnation() > boots);
    LM_CHECK_EQ(n.state(1), static_cast<uint32_t>(LM_UNASSIGNED));
    LM_CHECK_EQ(n.install(1, 3, t1), LM_STATUS_REVOKED); // the consumed grant: refused on the device itself
    const root::Entry *e = n.eng(0).ledger().find(self);
    LM_CHECK(e != nullptr && e->state == root::EntryState::Left && e->consumed >= 1u);
    const Bytes t2 = n.net.fleet.ticket(n.kits[1].kit, DomainId{}, n.net.domain, n.net.delegation_cose, 0, 2);
    LM_CHECK_EQ(n.install(1, 3, t2), LM_STATUS_OK);
    LM_CHECK_EQ(n.install(0, 5, n.expected_page(1, 2, t2, 2)), LM_STATUS_OK);
    n.run_ms(31'000); // one full handshake per peer per 30 s (docs/06 §8), the root's gate included
    LM_CHECK_EQ(n.join(1, 0x62), LM_STATUS_OK);
    const bool rejoined = n.until([&] { return n.eng(1).identity().is_member(); }, 120'000);
    LM_CHECK(rejoined);
    LM_CHECK_EQ(n.eng(1).identity().member().assignment.value(), 2u);
    LM_CHECK(n.eng(1).identity().self() == self);
}

// POWER (sim) across a handover: a cut before / torn / after every mutating Flash step of the device and of the new
// root. After the restart the device is a member under the old delegation or the new one, never a credential of one
// under the other, and the new root's entry agrees; then the durable evidence converges on the new root.
namespace {
CutRun handover_cut(unsigned target, uint64_t k, CutMode mode) {
    CutRun out;
    DNet n(1, 400 + k * 5 + target, DNet::Kind::Handover);
    const unsigned d = 2;
    const Bytes ho = n.a.fleet.handover(n.a.domain, n.handover());
    if (n.install(0, 31, ho) != 0 || n.install(d, 31, ho) != 0) {
        out.why = "setup";
        return out;
    }
    n.provision_new_root(true);
    n.boot(1);
    n.run_ms(300);
    n.set_time(2, 1);
    const uint64_t m0 = n.eng(d).identity().member().membership.value();
    SimStore &st = n.node(target).store;
    st.arm_cut(st.mutating_ops() + k, mode);
    if (n.start_join(d, 0x46, LM_JOIN_TRANSFER_CANDIDATE) != LM_STATUS_OK) {
        out.why = "handover refused";
        return out;
    }
    out.fired = n.until([&] { return st.cut_fired(); }, 60'000, 20);
    if (!out.fired) {
        out.ok = switched(n, d);
        out.why = out.ok ? "" : "no cut, no move";
        return out;
    }
    n.reboot(target);
    n.set_time(2, 1);
    const member::LocalIdentity &id = n.eng(d).identity();
    const bool moved = switched(n, d);
    const root::Entry *e = n.eng(1).ledger().find(n.id(d));
    if (id.state() != member::LocalIdentity::State::Ready || !id.is_member()) {
        out.why = "device no member or unloadable";
        return out;
    }
    if (id.member().root_term != RootTerm{moved ? 2U : 1U} || (!moved && id.delegation().root != n.id(0))) {
        out.why = "credential and delegation of different roots";
        return out;
    }
    if (e == nullptr || (moved && !(e->state == root::EntryState::Active &&
                                    e->membership == id.member().membership.value()))) {
        out.why = "device moved, the new root's entry does not say so";
        return out;
    }
    if (!moved && e->state == root::EntryState::Active && e->membership != m0 &&
        !n.eng(d).membership().prepared_record()) {
        out.why = "new root ACTIVE for the re-issue, the device without its PREPARED record";
        return out;
    }
    for (int round = 0; round < 12; ++round) {
        n.run_ms(31'000);
        n.set_time();
        n.set_time(2, 1);
        const root::Entry *re = n.eng(1).ledger().find(n.id(d));
        if (switched(n, d) && re != nullptr && re->state == root::EntryState::Active && re->confirmed &&
            !n.eng(d).membership().confirm_pending()) {
            break;
        }
        if (n.eng(d).membership().phase() != member::JoinPhase::Idle) {
            continue;
        }
        if (switched(n, d)) {
            (void)n.start_join(d, static_cast<uint8_t>(0x61 + round), LM_JOIN_RESUME);
        } else if (n.eng(d).membership().prepared_record()) {
            (void)n.start_join(d, 0x46, LM_JOIN_TRANSFER_CANDIDATE);
        } else {
            (void)n.start_join(d, static_cast<uint8_t>(0x70 + round), LM_JOIN_TRANSFER_CANDIDATE);
        }
        n.run_ms(6000);
    }
    const root::Entry *fe = n.eng(1).ledger().find(n.id(d));
    out.moved = switched(n, d) && fe != nullptr && fe->state == root::EntryState::Active && fe->confirmed &&
                !n.eng(d).membership().confirm_pending() && fe->membership == id.member().membership.value();
    out.ok = out.moved;
    if (!out.ok) {
        out.why = std::string("did not converge: device ") + (switched(n, d) ? "moved" : "old") + ", entry " +
                  std::to_string(fe != nullptr ? static_cast<int>(fe->state) : -1) +
                  (fe != nullptr && fe->confirmed ? " confirmed" : "") + " phase " +
                  std::to_string(static_cast<int>(n.eng(d).membership().phase())) + " reason " +
                  std::to_string(static_cast<int>(n.eng(d).membership().reason()));
    }
    return out;
}
} // namespace

LM_TEST("LC08 POWER sim: power cut at each record-write boundary of a handover (device, new root) leaves old or new") {
    const lmtest::CutTotals t = lmtest::cut_matrix(
        "handover", {{2, "device"}, {1, "new root"}}, [](unsigned target, uint64_t k, CutMode mode) {
            const CutRun r = handover_cut(target, k, mode);
            return lmtest::CutRun{r.fired, r.ok, r.moved, r.why};
        });
    LM_CHECK(t.points >= 20);
}

// POWER (sim): a cut at the old root's retirement commit. After the restart it is retired or not - never half (its
// ledger unchanged either way); installing the object again completes the retirement.
LM_TEST("LC08 POWER sim: power cut at the old root's retirement commit - retired or not; the object again completes it") {
    unsigned retired_after_cut = 0;
    unsigned fired_cuts = 0;
    for (const CutMode mode : {CutMode::Before, CutMode::Torn, CutMode::After}) {
        for (uint64_t k = 0; k < 4; ++k) {
            DNet n(1, 500 + k, DNet::Kind::Handover);
            const Bytes ho = n.a.fleet.handover(n.a.domain, n.handover());
            SimStore &st = n.node(0).store;
            st.arm_cut(st.mutating_ops() + k, mode);
            (void)n.install(0, 31, ho, 3000);
            const bool fired = st.cut_fired();
            fired_cuts += fired ? 1 : 0;
            n.reboot(0);
            LM_CHECK_EQ(n.eng(0).ledger().count(root::EntryState::Active), 1u); // the ledger itself untouched
            retired_after_cut += fired && n.eng(0).ledger().retired() ? 1 : 0;
            if (!n.eng(0).ledger().retired()) {
                LM_CHECK_EQ(n.install(0, 31, ho), 0u);
            }
            LM_CHECK(n.eng(0).ledger().retired());
            n.reboot(0);
            LM_CHECK(n.eng(0).ledger().retired());
        }
    }
    std::printf("  [measure] retirement cuts: %u fired, %u left the old root retired, the rest completed on the second "
                "install\n", fired_cuts, retired_after_cut);
    LM_CHECK(fired_cuts >= 3u);
}

// LC07 (sim): A-bound history at the move (docs/21 §6). A durable message to the domain root's application is still
// unacknowledged (A's root is off) when the device moves to B. The history stays A's: it was accepted under assignment 1,
// so it is never re-addressed to B's root nor published there as new data; once the device is B's member it ends
// INDETERMINATE (NETWORK_MISMATCH: it may have left before the move), its record retired, counted (ARCH2).
LM_TEST("LC07 sim: unacknowledged A-bound history is never sent to B as new data; it ends as A's history") {
    DNet n(1, 89);
    const unsigned d = 2;
    n.eng(1).ledger().set_join_mode(root::JoinMode::Preapproved);
    const Bytes ab = n.transfer_ticket(d, n.a, n.b, 1, 2);
    LM_CHECK_EQ(n.expect(1, n.b, d, 2, ab, 1), 0u);
    LM_CHECK_EQ(n.install(d, 3, ab), 0u);
    const uint64_t t0 = n.node(0).clock.now().to_ms();
    n.node(0).power_cut(); // A's root is off: nothing will acknowledge the history
    n.node(0).store.power_restore();
    lm_send_request_t rq{};
    rq.struct_size = sizeof(rq);
    rq.abi_version = LM_ABI_VERSION;
    rq.destination.kind = LM_DEST_ROOT_APP;
    rq.app_port = 100;
    rq.delivery = LM_RECEIVED;
    rq.storage = LM_DURABLE;
    rq.priority = LM_PRIORITY_NORMAL;
    rq.queue_mode = LM_FIFO;
    rq.root_term = 1;
    rq.expires_root_ms = t0 + 120'000;
    const uint8_t payload[16] = {0xA1};
    lm_operation_id_t op = 0;
    LM_CHECK_EQ(lm_send(n.ctx(d), &rq, payload, sizeof(payload), &op), LM_STATUS_OK);
    n.node(d).notify();
    n.run_ms(2000);
    LM_CHECK(n.transfer(d, n.b, 0x47));
    n.run_ms(31'000);
    n.set_time();
    LM_CHECK_OK(n.eng(d).link().connect(n.mac(1), n.node(d).clock.now()));
    n.node(d).notify();
    LM_CHECK(n.until([&] { return n.eng(1).link().neighbors().find_device(n.id(d)) != nullptr; }, 6000));
    n.run_ms(150'000); // past the message's own deadline
    LM_CHECK_EQ(n.eng(1).delivery().stats().rx_data, 0u);   // B's root never got it ...
    LM_CHECK_EQ(n.eng(1).delivery().stats().delivered, 0u); // ... nor handed it to its application
    LM_CHECK_EQ(n.eng(d).delivery().stats().old_assignment, 1u); // it ended as history of assignment 1, undelivered
    LM_CHECK_EQ(n.eng(d).delivery().durable().live_count(), 0u);
}

// LC07 / FIX2-D1 (sim): A-bound history to a peer that moved too. The message identity is (origin, origin's assignment
// generation, MessageId): a durable send accepted under assignment 1 (A) is that message only. The origin and its peer
// both move to B; the recovered record must never be sent under assignment 2 (it would be a new message in B, the old
// payload published there as today's data, docs/21 §6). It ends INDETERMINATE (it may have left before the restart),
// its OPERATION event names the assignment it was accepted under, and the application finds it by that message ref.
LM_TEST("LC07 ARCH2 sim: a durable send accepted in A is never sent under the B assignment after both ends moved") {
    DNet n(2, 90);
    const unsigned o = 2; // the origin
    const unsigned p = 3; // its peer
    n.eng(1).ledger().set_join_mode(root::JoinMode::Preapproved);
    const Bytes to_o = n.transfer_ticket(o, n.a, n.b, 1, 2);
    const Bytes to_p = n.transfer_ticket(p, n.a, n.b, 1, 2);
    LM_CHECK_EQ(n.expect(1, n.b, o, 2, to_o, 1), 0u);
    LM_CHECK_EQ(n.expect(1, n.b, p, 2, to_p, 2), 0u);
    LM_CHECK_EQ(n.install(o, 3, to_o), 0u);
    LM_CHECK_EQ(n.install(p, 3, to_p), 0u);
    // A durable RECEIVED message without a deadline (history) to the peer; no route in A (the mesh is off): persisted,
    // never sent, unacknowledged when the origin moves.
    lm_send_request_t rq{};
    rq.struct_size = sizeof(rq);
    rq.abi_version = LM_ABI_VERSION;
    rq.destination.kind = LM_DEST_NODE;
    std::memcpy(rq.destination.node.bytes, n.id(p).bytes.data(), 32);
    rq.app_port = 100;
    rq.delivery = LM_RECEIVED;
    rq.storage = LM_DURABLE;
    rq.priority = LM_PRIORITY_NORMAL;
    rq.queue_mode = LM_FIFO;
    const uint8_t payload[16] = {0xA7};
    lm_operation_id_t op = 0;
    LM_CHECK_EQ(lm_send(n.ctx(o), &rq, payload, sizeof(payload), &op), LM_STATUS_OK);
    n.node(o).notify();
    lm_operation_t before{};
    before.struct_size = sizeof(before);
    before.abi_version = LM_ABI_VERSION;
    LM_CHECK(n.until([&] {
        (void)lm_get_operation(n.ctx(o), op, &before);
        return (before.evidence_bits & delivery::ev::persisted) != 0;
    }, 2000));
    LM_CHECK((before.evidence_bits & delivery::ev::sent) == 0);
    LM_CHECK(n.transfer(o, n.b, 0x71));
    LM_CHECK(n.transfer(p, n.b, 0x72));
    LM_CHECK_EQ(n.assignment(o), 2u);
    LM_CHECK_EQ(n.assignment(p), 2u);
    // In B the peer is reachable: a link session and a route (what the mesh would provide).
    n.run_ms(31'000);
    n.set_time();
    LM_CHECK_OK(n.eng(o).link().connect(n.mac(p), n.node(o).clock.now()));
    n.node(o).notify();
    LM_CHECK(n.until([&] {
        const link::Neighbor *nb = n.eng(o).link().neighbors().find_device(n.id(p));
        return nb != nullptr && nb->cur.active;
    }, 6000));
    delivery::PathSpec ps;
    ps.origin = n.eng(o).identity().member().address;
    ps.dest = n.eng(p).identity().member().address;
    ps.len = 1;
    ps.path[0] = ps.dest.value();
    ps.term = n.eng(o).identity().member().root_term;
    ps.revision = PathRevision{1};
    LM_CHECK_OK(n.eng(o).delivery().install_route(n.id(p), ps, MonoTime::never()));
    n.eng(o).delivery().routes_changed(n.node(o).clock.now());
    n.node(o).notify();
    n.run_ms(60'000);
    LM_CHECK_EQ(n.eng(p).delivery().stats().rx_data, 0u);   // never sent in B ...
    LM_CHECK_EQ(n.eng(p).delivery().stats().delivered, 0u); // ... nor handed to the peer's application
    LM_CHECK_EQ(n.eng(o).delivery().stats().old_assignment, 1u);
    LM_CHECK_EQ(n.eng(o).delivery().durable().live_count(), 0u); // the record is retired, its outcome is history
    // The history, by the message ref it was accepted under: INDETERMINATE (it might have left before the restart).
    lm_message_ref_t ref{};
    std::memcpy(ref.origin.bytes, n.id(o).bytes.data(), 32);
    ref.assignment_generation = 1;
    ref.id = before.message_id;
    std::memcpy(ref.intent_hash, before.intent_hash, 32);
    lm_operation_t after{};
    after.struct_size = sizeof(after);
    after.abi_version = LM_ABI_VERSION;
    LM_CHECK_EQ(lm_get_message(n.ctx(o), &ref, &after), LM_STATUS_OK);
    LM_CHECK_EQ(after.outcome, static_cast<uint32_t>(LM_OUTCOME_INDETERMINATE));
    LM_CHECK_EQ(after.reason, static_cast<uint32_t>(Status::NetworkMismatch));
    ref.assignment_generation = 2; // the same MessageId under the B assignment is another message: unknown here
    LM_CHECK_EQ(lm_get_message(n.ctx(o), &ref, &after), LM_STATUS_NOT_FOUND);
}

// LC03 (sim): powered on before the plan (docs/21 §3). The root does not expect the device yet: NOT_EXPECTED is a hold
// with a bounded re-evaluation, not a verdict. When the expected set's revision rises, the device re-evaluates at its
// next search (the offer's higher revision ends the hold through the rate-limited hint) and joins; nothing is reserved
// for it meanwhile.
LM_TEST("LC03 sim: power-on before the plan - NOT_EXPECTED holds, the later revision is picked up, then it joins") {
    LNet n({Spec{}, Spec{Role::Leaf, 0, true}}, 78);
    n.boot(0);
    n.boot(1);
    n.run_ms(1000);
    n.eng(0).ledger().set_join_mode(root::JoinMode::Preapproved);
    const Bytes t = n.net.fleet.ticket(n.kits[1].kit, DomainId{}, n.net.domain, n.net.delegation_cose, 0, 1);
    LM_CHECK_EQ(n.install(1, 3, t), LM_STATUS_OK); // the device has its grant; the root has no plan for it yet
    LM_CHECK_EQ(n.join(1, 0x71), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.eng(1).membership().stats().refusals >= 1; }, 60'000));
    LM_CHECK(!n.eng(1).identity().is_member());
    LM_CHECK(n.eng(1).membership().phase() != member::JoinPhase::Idle); // a hold, not a verdict
    LM_CHECK(n.eng(0).ledger().find(n.id(1)) == nullptr);               // nothing reserved
    n.run_ms(20'000);
    LM_CHECK_EQ(n.install(0, 5, n.expected_page(1, 1, t, 1)), LM_STATUS_OK); // the plan arrives (revision 1)
    LM_CHECK(n.until([&] { return n.eng(1).identity().is_member(); }, 150'000));
    std::printf("  LC03: joined after %llu NOT_EXPECTED answer(s)\n",
                static_cast<unsigned long long>(n.eng(1).membership().stats().refusals));
}

// LC04 (sim): factory -> production (docs/21 §1). The factory domain's membership (A) is worth nothing in production
// (B): B's root refuses its credential, a join without a production grant has nothing to show, the factory's own ticket
// is never shown to B, and only a production grant of a higher assignment makes it B's member.
LM_TEST("LC04 sim: a factory membership gives no production access; only a production grant of a higher assignment") {
    DNet n(1, 90);
    const unsigned d = 2;
    n.eng(1).ledger().set_join_mode(root::JoinMode::Preapproved);
    n.run_ms(31'000);
    const uint64_t rej = n.eng(1).link().stats().cred_rejected + n.eng(1).link().stats().rx_wrong_domain;
    LM_CHECK_OK(n.eng(d).link().connect(n.mac(1), n.node(d).clock.now()));
    n.node(d).notify();
    n.run_ms(6000);
    LM_CHECK(n.eng(1).link().neighbors().find_device(n.id(d)) == nullptr); // the factory credential opens nothing
    LM_CHECK(n.eng(1).link().stats().cred_rejected + n.eng(1).link().stats().rx_wrong_domain > rej);
    LM_CHECK_EQ(n.start_join(d, 0x81, LM_JOIN_TRANSFER_CANDIDATE), LM_STATUS_OK); // no production grant installed
    LM_CHECK(n.until([&] { return n.eng(d).membership().phase() == member::JoinPhase::Idle; }, 30'000));
    LM_CHECK(n.eng(d).membership().reason() == Status::AuthPending);
    LM_CHECK_EQ(n.eng(1).ledger().stats().requests, 0u); // nothing reached the production root
    const Bytes ab = n.transfer_ticket(d, n.a, n.b, 1, 2);
    LM_CHECK_EQ(n.expect(1, n.b, d, 2, ab, 1), 0u);
    LM_CHECK_EQ(n.install(d, 3, ab), 0u);
    LM_CHECK(n.transfer(d, n.b, 0x82));
    LM_CHECK_EQ(n.assignment(d), 2u);
}

// POWER (sim) across a commissioning window: a cut of the root's store at each mutating step of the window's install
// and of a windowed join (the budget count, the reservation, the activation). The window's budget is counted by durable
// reservations: after the restart and the same window installed again, it never admits more than its budget (a cut
// between the count and the reservation over-counts: fewer admissions, never more).
LM_TEST("LC02 POWER sim: power cut at each commit of a window and a windowed join - the budget is never exceeded") {
    unsigned iterations = 0;
    unsigned admitted_total = 0;
    for (const CutMode mode : {CutMode::Before, CutMode::Torn, CutMode::After}) {
        for (uint64_t k = 0; k < 12; ++k) {
            LNet n({Spec{}, Spec{Role::Leaf, 0, true}, Spec{Role::Leaf, 0, true}}, 600 + k);
            star(n);
            for (unsigned i = 0; i < 3; ++i) {
                n.boot(i);
            }
            n.run_ms(1000);
            n.eng(0).ledger().set_join_mode(root::JoinMode::Closed);
            n.grant(1, 1, 1);
            n.grant(2, 1, 2);
            const Bytes win = n.net.fleet.window(n.net.domain, make_window(n.root_ms(), 10 * k_min, 1, 2));
            SimStore &st = n.node(0).store;
            st.arm_cut(st.mutating_ops() + k, mode);
            (void)n.install(0, 30, win);
            (void)n.join(1, 0x31);
            const bool fired = n.until([&] { return st.cut_fired() || n.eng(1).identity().is_member(); }, 60'000) &&
                               st.cut_fired();
            if (!fired) {
                LM_CHECK(n.eng(1).identity().is_member());
                break; // fewer root store operations than k: this mode is complete
            }
            ++iterations;
            n.node(0).power_cut();
            n.node(0).store.power_restore();
            n.boot(0);
            n.run_ms(1000);
            n.eng(0).ledger().set_join_mode(root::JoinMode::Closed);
            LM_CHECK(n.eng(0).ledger().ready());
            (void)n.install(0, 30, win); // the same window again: its durable count goes on
            n.run_ms(500);
            auto reserved = [&] {
                unsigned r = 0;
                for (unsigned i = 1; i < 3; ++i) {
                    const root::Entry *e = n.eng(0).ledger().find(n.id(i));
                    r += e != nullptr && (e->state == root::EntryState::Prepared || e->state == root::EntryState::Active)
                             ? 1
                             : 0;
                }
                return r;
            };
            LM_CHECK(!(reserved() >= 1 && n.eng(0).ledger().window_open(n.node(0).clock.now())));
            // Both devices keep asking for a while; at most one gets in.
            for (int round = 0; round < 6; ++round) {
                for (unsigned i = 1; i < 3; ++i) {
                    if (!n.eng(i).identity().is_member() && n.eng(i).membership().phase() == member::JoinPhase::Idle) {
                        const bool same = n.eng(i).membership().prepared_record();
                        (void)n.join(i, static_cast<uint8_t>(same ? 0x31 : 0x50 + 8 * round + i));
                    }
                }
                n.run_ms(40'000);
            }
            unsigned admitted = 0;
            for (unsigned i = 1; i < 3; ++i) {
                admitted += n.eng(i).identity().is_member() ? 1 : 0;
            }
            LM_CHECK(admitted <= 1u);
            LM_CHECK(reserved() <= 1u);
            admitted_total += admitted;
        }
    }
    std::printf("  [measure] window power-cut sweep: %u cut points, %u admitted afterwards (never above the budget of 1)\n",
                iterations, admitted_total);
    LM_CHECK(iterations >= 6u);
}

int main(int argc, char **argv) { return lmtest::run_all(argc, argv); }
