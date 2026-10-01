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
#include "core/member/records.hpp"
#include "core/wire/cbor.hpp"
#include "fleet.hpp"
#include "cut_matrix.hpp"
#include "lmtest.hpp"
#include "port/sim/sim_node.hpp"
#include "port/sim/sim_provision.hpp"
#include "port/sim/sim_world.hpp"
#include "security/crypto.hpp"
#include "store/record.hpp"

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
    // Installs `obj` at node i and waits for its operation: the operation's status (0xFFFF: none in time), or the
    // refusal of lm_install_control itself.
    uint32_t install_result(unsigned i, uint32_t type, const Bytes &obj, uint64_t wait_ms = 5000) {
        lm_operation_id_t op = 0;
        lm_status_t s = LM_STATUS_BUSY;
        (void)until([&] { return (s = lm_install_control(ctx(i), type, obj.data(), obj.size(), &op)) != LM_STATUS_BUSY; },
                    2000, 5);
        if (s != LM_STATUS_OK) {
            return s;
        }
        node(i).notify();
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
        }, wait_ms, 5);
        return reason;
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

    // `new_root_term`: Handover: the first term the new root publishes (its handover names it).
    explicit DNet(unsigned devices, uint64_t seed = 81, Kind kind = Kind::TwoDomains, uint32_t new_root_term = 2)
        : n(devices + 2), a(seed), b(seed, "fleet", "/B", 1001), world(WorldOptions{seed, 0}) {
        for (unsigned i = 0; i < n; ++i) {
            NodeOptions o;
            o.role = i < 2 ? Role::Root : Role::Relay;
            (void)world.add_node(o);
            node(i).jobs.latency_us = 2000;
        }
        kits.push_back(a.make_root());
        kits.push_back(kind == Kind::Handover ? a.make_new_root(1001, 2, new_root_term, deleg2) : b.make_root());
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
LM_TEST(
    "G01 isolation trigger is opt-in, persistent, delayed, and uses the existing signed transfer") {
    DNet n(1);
    const unsigned d = 2;
    n.eng(0).mesh().set_enabled(true);
    n.eng(d).mesh().set_enabled(true);
    n.node(0).notify();
    n.node(d).notify();
    LM_CHECK(
        n.until([&] { return n.eng(d).mesh().state() == route::Mesh::State::Ready; }, 120000, 20));
    lm_policy_t policy{};
    policy.struct_size = sizeof(policy);
    policy.abi_version = LM_ABI_VERSION;
    LM_CHECK_EQ(lm_policy_get(n.ctx(d), &policy), LM_STATUS_OK);
    LM_CHECK_EQ(policy.auto_transfer_on_isolation, 0u);
    policy.auto_transfer_on_isolation = 1;
    policy.isolation_before_transfer_ms = 599999;
    lm_operation_id_t op = 0;
    LM_CHECK_EQ(lm_policy_set(n.ctx(d), &policy, 0, &op), LM_STATUS_INVALID_ARGUMENT);
    policy.isolation_before_transfer_ms = 600000;
    lm_status_t policy_status = LM_STATUS_BUSY;
    LM_CHECK(n.until(
        [&] {
            return (policy_status = lm_policy_set(n.ctx(d), &policy, 0, &op)) != LM_STATUS_BUSY;
        },
        5000));
    LM_CHECK_EQ(policy_status, LM_STATUS_OK);
    lm_operation_t policy_operation{};
    policy_operation.struct_size = sizeof(policy_operation);
    policy_operation.abi_version = LM_ABI_VERSION;
    LM_CHECK_EQ(lm_get_operation(n.ctx(d), op, &policy_operation), LM_STATUS_OK);
    LM_CHECK_EQ(policy_operation.phase, 1u); // accepted, still committing
    n.run_ms(100);
    LM_CHECK_EQ(lm_get_operation(n.ctx(d), op, &policy_operation), LM_STATUS_OK);
    LM_CHECK_EQ(policy_operation.outcome, static_cast<uint32_t>(LM_OUTCOME_APPLIED));
    LM_CHECK_EQ(lm_policy_set(n.ctx(d), &policy, 0, &op), LM_STATUS_CONFLICT);
    policy = lm_policy_t{};
    policy.struct_size = sizeof(policy);
    policy.abi_version = LM_ABI_VERSION;
    LM_CHECK_EQ(lm_policy_get(n.ctx(d), &policy), LM_STATUS_OK);
    LM_CHECK_EQ(policy.revision, 1u);
    const Bytes ab = n.transfer_ticket(d, n.a, n.b, 1, 2);
    n.eng(1).ledger().set_join_mode(root::JoinMode::Preapproved);
    LM_CHECK_EQ(n.expect(1, n.b, d, 2, ab, 1), 0u);
    LM_CHECK_EQ(n.install(d, 3, ab), 0u);
    n.node(0).power_cut();
    n.run_ms(590000);
    LM_CHECK(n.in_domain(d, n.a)); // old membership retained; neither silence nor policy is a grant
    LM_CHECK(n.until([&] { return n.in_domain(d, n.b); }, 180000, 50));
    LM_CHECK_EQ(n.assignment(d), 2u);
    // Reboot reads the durable opt-in; a cold boot starts the isolation duration again.
    n.node(d).power_cut();
    n.boot(d);
    n.run_ms(100);
    policy = lm_policy_t{};
    policy.struct_size = sizeof(policy);
    policy.abi_version = LM_ABI_VERSION;
    LM_CHECK_EQ(lm_policy_get(n.ctx(d), &policy), LM_STATUS_OK);
    LM_CHECK_EQ(policy.auto_transfer_on_isolation, 1u);
    LM_CHECK_EQ(policy.revision, 1u);
}

LM_TEST("G01 isolation alone cannot transfer; recovery restarts the minimum interval") {
    for (const unsigned scenario : {0U, 1U, 2U}) {
        DNet n(1);
        const unsigned d = 2;
        n.eng(0).mesh().set_enabled(true);
        n.eng(d).mesh().set_enabled(true);
        n.node(0).notify();
        n.node(d).notify();
        LM_CHECK(n.until([&] { return n.eng(d).mesh().state() == route::Mesh::State::Ready; },
                         120000, 20));
        lm_policy_t p{};
        p.struct_size = sizeof(p);
        p.abi_version = LM_ABI_VERSION;
        LM_CHECK_EQ(lm_policy_get(n.ctx(d), &p), LM_STATUS_OK);
        if (scenario != 0) {
            p.auto_transfer_on_isolation = 1;
            p.isolation_before_transfer_ms = 600000;
            lm_operation_id_t op = 0;
            lm_status_t st = LM_STATUS_BUSY;
            LM_CHECK(n.until(
                [&] { return (st = lm_policy_set(n.ctx(d), &p, 0, &op)) != LM_STATUS_BUSY; },
                5000));
            LM_CHECK_EQ(st, LM_STATUS_OK);
            n.run_ms(100);
        }
        const Bytes ab = n.transfer_ticket(d, n.a, n.b, 1, 2);
        if (scenario != 1) {
            n.eng(1).ledger().set_join_mode(root::JoinMode::Preapproved);
            LM_CHECK_EQ(n.expect(1, n.b, d, 2, ab, 1), 0u);
            LM_CHECK_EQ(n.install(d, 3, ab), 0u);
        }
        if (scenario == 2) {
            n.world.set_link(0, d, LinkParams{false});
            n.run_ms(500000);
            n.world.set_link(0, d, LinkParams{true});
            LM_CHECK(n.until(
                [&] { return n.eng(d).mesh().connectivity(n.node(d).clock.now()) == LM_REACHABLE; },
                120000));
            n.run_ms(100); // the membership owner observes recovery
            n.world.set_link(0, d, LinkParams{false});
            n.run_ms(590000);
        } else {
            n.node(0).power_cut();
            n.run_ms(780000); // OFF despite a valid ticket, or ON without a grant
        }
        LM_CHECK(n.in_domain(d, n.a));
        LM_CHECK_EQ(n.assignment(d), 1u);
    }
}

LM_TEST("G01 unknown local policy commit disables automatic transfer until recovery") {
    for (const CutMode mode : {CutMode::Before, CutMode::After}) {
        DNet n(1);
        const unsigned d = 2;
        lm_policy_t p{};
        p.struct_size = sizeof(p);
        p.abi_version = LM_ABI_VERSION;
        LM_CHECK_EQ(lm_policy_get(n.ctx(d), &p), LM_STATUS_OK);
        p.auto_transfer_on_isolation = 1;
        p.isolation_before_transfer_ms = 600000;
        SimStore &st = n.node(d).store;
        st.arm_cut(st.mutating_ops() + 1, mode);
        lm_operation_id_t op = 0;
        LM_CHECK_EQ(lm_policy_set(n.ctx(d), &p, 0, &op), LM_STATUS_OK);
        n.run_ms(100);
        LM_CHECK(st.cut_fired());
        LM_CHECK_EQ(lm_policy_get(n.ctx(d), &p), LM_STATUS_RECOVERY_REQUIRED);
        LM_CHECK_EQ(lm_policy_set(n.ctx(d), &p, 0, &op), LM_STATUS_RECOVERY_REQUIRED);
        LM_CHECK(n.in_domain(d, n.a));
    }
}

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
    // The fleet names a first term for the new root above any term the failed old root may publish when it comes back:
    // each of its boots publishes one more (ARCH2-D1), and it retires only on a new term above its own (FIX5-D4). Here it
    // comes back once (term 2), so the new root starts at term 3.
    DNet n(2, 88, DNet::Kind::Handover, 3);
    n.provision_new_root(true);
    n.node(0).power_cut();
    n.node(0).store.power_restore();
    n.boot(1);
    n.run_ms(300);
    const Bytes ho = n.a.fleet.handover(n.a.domain, n.handover(3));
    const uint64_t m3 = n.eng(3).identity().member().membership.value();
    LM_CHECK_EQ(n.install(2, 31, ho), 0u);
    LM_CHECK(hand_over(n, 2, 0x54));
    n.boot(0); // the old root is back, unaware
    n.run_ms(300);
    n.set_time();
    n.set_time(3, 1);
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
    // FIX5-D6: the budget belongs to the window. The same window again (signed anew, re-issued with new times) goes on
    // with its durable count (1 of 3 used); another window under the counted policy revision is refused (before: it
    // started a count of its own - an old window replayed reset the budget); a higher revision is a new budget.
    member::CommissioningWindow again = w;
    again.not_before_ms = n.root_ms();
    again.expires_ms = again.not_before_ms + 60'000;
    LM_CHECK_EQ(n.install_result(0, 30, n.net.fleet.window(n.net.domain, again)), 0u);
    LM_CHECK(n.eng(0).ledger().window_open(n.node(0).clock.now()));
    member::CommissioningWindow other = make_window(n.root_ms(), 60'000, 1, 3); // another id and budget, revision 1
    LM_CHECK_EQ(n.install_result(0, 30, n.net.fleet.window(n.net.domain, other)),
                static_cast<uint32_t>(LM_STATUS_CONFLICT));
    other.policy_revision = 2;
    LM_CHECK_EQ(n.install_result(0, 30, n.net.fleet.window(n.net.domain, other)), 0u);
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
            // A new term above the old root's own across the restarts below (FIX5-D4; ARCH2-D1: one more per boot).
            const Bytes ho = n.a.fleet.handover(n.a.domain, n.handover(3));
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

// ---- FIX5: external review of 8d5e5e9 (lifecycle and root authority) ----
namespace {

// What the node's store holds for record `id` right now: its state byte, -1 when it has no committed record, -2 when
// it cannot be read. Read directly (the bench's view of the Flash, not the node's RAM).
int stored_state(SimStore &st, uint16_t id) {
    auto job = std::make_unique<store::RecordJob>();
    job->arm(store::RecordJob::Op::Load, id);
    const Status s = store::record_load(st, *job);
    return s == Status::Ok ? job->state : (s == Status::NotFound ? -1 : -2);
}

// The status of the next OPERATION event for `op` at node i (0xFFFF: none within `wait_ms`).
uint32_t op_reason(World &w, SimNode &node, lm_operation_id_t op, uint64_t wait_ms) {
    for (uint64_t t = 0; t <= wait_ms; t += 5) {
        lm_event_t ev{};
        ev.struct_size = sizeof(ev);
        ev.abi_version = LM_ABI_VERSION;
        while (lm_next_event(node.ctx(), &ev, nullptr, 0, nullptr) == LM_STATUS_OK) {
            if (ev.kind == LM_EVENT_OPERATION && ev.operation_id == op) {
                return ev.reason;
            }
        }
        w.run_until(w.now_us() + 5000);
    }
    return 0xFFFF;
}

// A renewal of `live` (member i of DNet domain A) signed by A's root: the same credential with another term and lease.
Bytes renewal_of(DNet &n, unsigned i, const member::MemberCredential &live, uint32_t term, uint64_t lease_ms) {
    fleet::MemberSpec ms;
    ms.address = live.address.value();
    ms.assignment = live.assignment.value();
    ms.membership = live.membership.value();
    ms.role = live.role;
    ms.relay_allowed = live.relay_allowed;
    ms.root_term = term;
    ms.lease_expires_root_ms = lease_ms;
    return fleet::issue_member(n.kits[0].kit, n.a.domain, n.kits[i].kit, ms);
}

} // namespace

// Finding 1: the old root's retirement commit wrote the record durably but its read-back failed (StorageFailure). The
// old root must not keep admitting and serving while the new one runs: it is retired (fail closed) from the moment the
// verified object names it, whatever the commit's result, and the operation's result is reconciled from the record.
LM_TEST("LC08 FIX5 sim: a retirement whose read-back failed leaves the old root retired at once; the reload reconciles") {
    {
        DNet n(1, 93, DNet::Kind::Handover);
        LM_CHECK_OK(n.eng(2).link().connect(n.mac(0), n.node(2).clock.now()));
        n.node(2).notify();
        LM_CHECK(n.until([&] { return n.eng(0).link().neighbors().find_device(n.id(2)) != nullptr; }, 6000));
        const Bytes ho = n.a.fleet.handover(n.a.domain, n.handover());
        SimStore &st = n.node(0).store;
        st.arm_cut(st.mutating_ops() + 1, CutMode::After); // the record's commit marker: written, then the call fails
        lm_operation_id_t op = 0;
        LM_CHECK_EQ(lm_install_control(n.ctx(0), 31, ho.data(), ho.size(), &op), LM_STATUS_OK);
        n.node(0).notify();
        LM_CHECK(n.until([&] { return st.cut_fired(); }, 3000));
        n.run_ms(100);
        // Storage down: the old root admits and serves nobody, now (not only after a restart).
        LM_CHECK(n.eng(0).ledger().retired());
        LM_CHECK(n.eng(0).ledger().admission() != Status::Ok);
        LM_CHECK(n.eng(0).link().neighbors().find_device(n.id(2)) == nullptr);
        st.power_restore(); // storage answers again; the root was never restarted
        LM_CHECK(stored_state(st, store::rec::root_handover) >= 0); // precondition: the retirement IS durable
        LM_CHECK_EQ(op_reason(n.world, n.node(0), op, 6000), 0u);   // reconciled from the record: applied
        LM_CHECK(n.eng(0).ledger().retired());
        (void)n.eng(2).link().connect(n.mac(0), n.node(2).clock.now());
        n.node(2).notify();
        n.run_ms(3000);
        LM_CHECK(n.eng(0).link().neighbors().find_device(n.id(2)) == nullptr);
    }
    {
        // Nothing reached the Flash: retired for this boot all the same (the fleet's verified word), the result says
        // RECOVERY_REQUIRED (not durable), and the object installed again makes it durable.
        DNet n(1, 94, DNet::Kind::Handover);
        const Bytes ho = n.a.fleet.handover(n.a.domain, n.handover());
        SimStore &st = n.node(0).store;
        st.arm_cut(st.mutating_ops(), CutMode::Before);
        lm_operation_id_t op = 0;
        LM_CHECK_EQ(lm_install_control(n.ctx(0), 31, ho.data(), ho.size(), &op), LM_STATUS_OK);
        n.node(0).notify();
        LM_CHECK(n.until([&] { return st.cut_fired(); }, 3000));
        st.power_restore();
        LM_CHECK_EQ(op_reason(n.world, n.node(0), op, 6000), static_cast<uint32_t>(LM_STATUS_RECOVERY_REQUIRED));
        LM_CHECK(stored_state(st, store::rec::root_handover) == -1);
        LM_CHECK(n.eng(0).ledger().retired());
        LM_CHECK_EQ(n.install(0, 31, ho), 0u);
        LM_CHECK(stored_state(st, store::rec::root_handover) >= 0);
    }
}

// Finding 4: one semantic check of a RootHandover for every party. A handover to the same device, one whose delegation
// generation does not rise, or one whose new term is not above the term the old root lives in would retire the old
// root while no member can follow it (the domain strands): refused by the old root, the device and the new root.
LM_TEST("LC08 FIX5 sim: a same-root, non-increasing or stale-term handover is refused by old root, device and new root") {
    DNet n(1, 95, DNet::Kind::Handover);
    member::RootHandover same = n.handover();
    same.new_root = n.id(0); // the "new" root is the old one
    const Bytes same_obj = n.a.fleet.handover(n.a.domain, same);
    LM_CHECK_EQ(n.install(0, 31, same_obj), static_cast<uint32_t>(LM_STATUS_INVALID_ARGUMENT));
    LM_CHECK(!n.eng(0).ledger().retired());
    LM_CHECK_EQ(n.install(2, 31, same_obj), static_cast<uint32_t>(LM_STATUS_INVALID_ARGUMENT)); // never stored
    const Bytes stale = n.a.fleet.handover(n.a.domain, n.handover(1)); // term 1: the old root's own
    LM_CHECK_EQ(n.install(0, 31, stale), static_cast<uint32_t>(LM_STATUS_CONFLICT));
    LM_CHECK(!n.eng(0).ledger().retired());
    LM_CHECK_EQ(n.eng(0).ledger().admission(), Status::Ok);
    n.provision_new_root(true);
    n.boot(1);
    n.run_ms(300);
    n.set_time(2, 1);
    member::RootHandover down = n.handover();
    down.old_generation = 3; // the new delegation (generation 2) is not above the old one
    LM_CHECK_EQ(n.install(1, 31, n.a.fleet.handover(n.a.domain, down)), static_cast<uint32_t>(LM_STATUS_INVALID_ARGUMENT));
    // The valid object still works everywhere.
    const Bytes ho = n.a.fleet.handover(n.a.domain, n.handover());
    LM_CHECK_EQ(n.install(1, 31, ho), 0u);
    LM_CHECK_EQ(n.install(0, 31, ho), 0u);
    LM_CHECK(n.eng(0).ledger().retired());
}

// Finding 6: a commissioning window's budget cannot be reset by replaying an older window (W1, W2, W1 ... each W1 used
// to start from zero again). The durable record keeps the window replay floor (policy revision) and the digest of the
// window it counts: the same window again resumes its count, an older revision or another body under the counted
// revision fails closed.
LM_TEST("LC01 FIX5 sim: an older or altered commissioning window never resets the budget; the same one resumes it") {
    LNet n({Spec{}, Spec{Role::Leaf, 0, true}, Spec{Role::Leaf, 0, true}, Spec{Role::Leaf, 0, true}}, 78);
    star(n);
    for (unsigned i = 0; i < 4; ++i) {
        n.boot(i);
    }
    n.run_ms(1000);
    n.eng(0).ledger().set_join_mode(root::JoinMode::Closed);
    for (unsigned i = 1; i < 4; ++i) {
        n.grant(i, 1, i);
    }
    auto window = [&](uint8_t id, uint64_t policy_revision, uint8_t max, uint64_t from_ms) {
        member::CommissioningWindow w = make_window(from_ms, 10 * k_min, max, 3);
        w.id = {};
        w.id[0] = id;
        w.policy_revision = policy_revision;
        return w;
    };
    auto install = [&](const member::CommissioningWindow &w) {
        const Bytes obj = n.net.fleet.window(n.net.domain, w); // a fresh signature every time (ES256 is randomised)
        lm_operation_id_t op = 0;
        lm_status_t s = LM_STATUS_BUSY; // (a join transaction may hold the ledger's buffers for a moment)
        (void)n.until([&] { return (s = lm_install_control(n.ctx(0), 30, obj.data(), obj.size(), &op)) != LM_STATUS_BUSY; },
                      5000, 5);
        LM_CHECK_EQ(s, LM_STATUS_OK);
        n.node(0).notify();
        return op_reason(n.world, n.node(0), op, 5000);
    };
    auto joins = [&](unsigned i, uint8_t req) {
        LM_CHECK_EQ(n.join(i, req), LM_STATUS_OK);
        return n.until([&] { return n.eng(i).identity().is_member(); }, 40'000);
    };
    const uint64_t t0 = n.root_ms();
    const member::CommissioningWindow w1 = window(0xA1, 1, 1, t0);
    const member::CommissioningWindow w2 = window(0xB2, 2, 1, t0);
    LM_CHECK_EQ(install(w1), 0u);
    LM_CHECK(joins(1, 0x11));
    LM_CHECK_EQ(install(w2), 0u);
    LM_CHECK(joins(2, 0x21));
    LM_CHECK_EQ(n.eng(0).ledger().stats().window_admitted, 2u);
    // W1 again: older than the counted window. Before: a new count from zero, device 3 got in.
    LM_CHECK_EQ(install(w1), static_cast<uint32_t>(LM_STATUS_CONFLICT));
    LM_CHECK(!n.eng(0).ledger().window_open(n.node(0).clock.now()));
    LM_CHECK(!joins(3, 0x31));
    // W2 again (signed anew, the same body): the same window, its count goes on - spent.
    LM_CHECK_EQ(install(w2), 0u);
    LM_CHECK(!n.eng(0).ledger().window_open(n.node(0).clock.now()));
    // Another body under the counted revision (a larger budget): fail closed.
    member::CommissioningWindow w2x = w2;
    w2x.max_new_members = 5;
    LM_CHECK_EQ(install(w2x), static_cast<uint32_t>(LM_STATUS_CONFLICT));
    LM_CHECK(!joins(3, 0x32));
    LM_CHECK_EQ(n.eng(0).ledger().stats().window_admitted, 2u);
    // The floor is durable: after a restart (a new term) the old revision is still refused.
    n.node(0).power_cut();
    n.node(0).store.power_restore();
    n.boot(0);
    n.run_ms(1000);
    n.eng(0).ledger().set_join_mode(root::JoinMode::Closed);
    member::CommissioningWindow w1t = w1;
    w1t.term = n.eng(0).identity().term();
    w1t.not_before_ms = n.root_ms();
    w1t.expires_ms = w1t.not_before_ms + 10 * k_min;
    LM_CHECK_EQ(install(w1t), static_cast<uint32_t>(LM_STATUS_CONFLICT));
    // A new window (higher revision) is a new budget.
    member::CommissioningWindow w3 = window(0xC3, 3, 1, n.root_ms());
    w3.term = w1t.term;
    LM_CHECK_EQ(install(w3), 0u);
    LM_CHECK(n.eng(0).ledger().window_open(n.node(0).clock.now()));
}

// Finding 2: the floors are raised (RAM) before the entry becomes Blocked. When the entry's commit fails the floors are
// already the authorisation: the member's link and end sessions and the routes through its address end at once (not
// only new sessions are refused), the entry is made Blocked durably as soon as the store answers, and a root restarted
// with a stale ACTIVE entry below its durable floors reconciles it at boot.
LM_TEST("S06 FIX5 sim: a revocation whose entry commit failed ends sessions and routes at once; the entry is blocked") {
    LNet n({Spec{}, Spec{Role::Leaf}, Spec{Role::Leaf}, Spec{Role::Leaf}}, 79);
    star(n);
    for (unsigned i = 0; i < 4; ++i) {
        n.boot(i);
    }
    LM_CHECK(n.until([&] { return n.all_ready(); }, 90'000));
    SimStore &st = n.node(0).store;
    const uint16_t rec1 = static_cast<uint16_t>(root::k_rec_ledger_base + 0); // node 1 = address 2 = slot 0
    const uint16_t rec2 = static_cast<uint16_t>(root::k_rec_ledger_base + 1);
    LM_CHECK(n.eng(0).link().neighbors().find_device(n.id(1)) != nullptr);
    LM_CHECK(n.eng(0).delivery().sessions().find_peer(n.id(1)) != nullptr);
    // FIX8-D1: the entry is the floor record of a listed device - the revocation is one entry commit. Its first write is
    // cut; the store is dead meanwhile.
    st.arm_cut(st.mutating_ops(), CutMode::Before);
    const Bytes rv = fleet::issue_root_revoke(n.kits[0].kit, n.net.domain, n.id(1), 2, 2);
    lm_operation_id_t op = 0;
    LM_CHECK_EQ(lm_install_control(n.ctx(0), 11, rv.data(), rv.size(), &op), LM_STATUS_OK);
    n.node(0).notify();
    LM_CHECK_EQ(op_reason(n.world, n.node(0), op, 5000), static_cast<uint32_t>(LM_STATUS_RECOVERY_REQUIRED));
    LM_CHECK(st.cut_fired());
    // At once, with the store still dead: nothing of the member serves on.
    LM_CHECK(n.eng(0).link().neighbors().find_device(n.id(1)) == nullptr);
    LM_CHECK(n.eng(0).delivery().sessions().find_peer(n.id(1)) == nullptr);
    LM_CHECK(!n.has_route(0, n.id(1)));
    LM_CHECK(n.eng(0).ledger().authorized(n.id(1)) == nullptr);
    n.run_ms(3000);
    LM_CHECK(n.eng(0).link().neighbors().find_device(n.id(1)) == nullptr); // and it gets no new session
    st.power_restore();
    LM_CHECK(stored_state(st, rec1) == static_cast<int>(root::EntryState::Active)); // precondition: nothing durable yet
    // ... and the entry is made Blocked durably once the store answers (bounded retry).
    LM_CHECK(n.until([&] { return stored_state(st, rec1) == static_cast<int>(root::EntryState::Blocked); }, 10'000));
    LM_CHECK(n.eng(0).ledger().find(n.id(1))->state == root::EntryState::Blocked);
    LM_CHECK(n.ready(2)); // the other member is untouched
    // The same failure, and the root restarts before it could repair the entry: nothing of the revocation was durable
    // (it answered RECOVERY_REQUIRED, never "applied"): the entry is ACTIVE again and the same object blocks it.
    st.arm_cut(st.mutating_ops(), CutMode::Before);
    const Bytes rv2 = fleet::issue_root_revoke(n.kits[0].kit, n.net.domain, n.id(2), 2, 2);
    LM_CHECK_EQ(lm_install_control(n.ctx(0), 11, rv2.data(), rv2.size(), &op), LM_STATUS_OK);
    n.node(0).notify();
    LM_CHECK(n.until([&] { return st.cut_fired(); }, 5000));
    n.node(0).power_cut();
    st.power_restore();
    LM_CHECK(stored_state(st, rec2) == static_cast<int>(root::EntryState::Active));
    n.boot(0);
    LM_CHECK(n.until([&] { return n.eng(0).ledger().ready(); }, 5000));
    LM_CHECK(n.eng(0).ledger().find(n.id(2))->state == root::EntryState::Active);
    LM_CHECK_EQ(n.install_result(0, 11, rv2), 0u);
    LM_CHECK(stored_state(st, rec2) == static_cast<int>(root::EntryState::Blocked));
    // An ACTIVE entry below a durable floor of the table (a provisioned floor, written while the root is off) is refused
    // at boot and made Blocked durably, the floor folded into the entry.
    const uint16_t rec3 = static_cast<uint16_t>(root::k_rec_ledger_base + 2); // node 3 = address 4 = slot 2
    LM_CHECK(stored_state(st, rec3) == static_cast<int>(root::EntryState::Active));
    n.node(0).power_cut();
    {
        member::Floors f;
        auto job = std::make_unique<store::RecordJob>();
        job->arm(store::RecordJob::Op::Load, store::rec::revocation_floors);
        if (store::record_load(st, *job) == Status::Ok) {
            LM_CHECK_OK(member::decode_floors(ByteView{job->payload.data(), job->payload_len}, f));
        }
        LM_CHECK_OK(f.raise(n.id(3), 9, 9));
        std::size_t len = 0;
        LM_CHECK_OK(member::encode_floors(f, MutByteView{job->payload}, len));
        job->arm(store::RecordJob::Op::Commit, store::rec::revocation_floors, 0, len);
        LM_CHECK_OK(store::record_commit(st, *job));
    }
    n.boot(0);
    LM_CHECK(n.until([&] { return stored_state(st, rec3) == static_cast<int>(root::EntryState::Blocked); }, 10'000));
    const root::Entry *e3 = n.eng(0).ledger().find(n.id(3));
    LM_CHECK(e3 != nullptr && e3->state == root::EntryState::Blocked && e3->membership >= 8 && e3->consumed >= 8);
    n.run_ms(40'000);
    LM_CHECK(n.eng(0).link().neighbors().find_device(n.id(3)) == nullptr);
    LM_CHECK(n.eng(0).delivery().sessions().find_peer(n.id(3)) == nullptr);
}

// Finding 8: a member lives in the term the root's authenticated word gave it (a LEASE of a newer term), while its
// credential is still of the older one until the renewal of the new term arrives. A delayed renewal of the older term
// has a later lease on a clock that no longer counts: it is never adopted - checked before the verification, before
// the commit and again at adoption (the term may move while the worker verifies or the exchange is busy).
LM_TEST("LP12 FIX5 sim: a renewal of a term older than the one the member lives in is never adopted") {
    DNet n(1, 96);
    const unsigned d = 2;
    member::Membership &m = n.eng(d).membership();
    const member::MemberCredential live = n.eng(d).identity().member();
    LM_CHECK(live.root_term == RootTerm{1});
    const uint64_t lease0 = live.lease_expires_root_ms;
    auto inject = [&](const Bytes &cose) {
        m.on_lifecycle_object(n.id(0), view(cose), n.node(d).clock.now());
        n.node(d).notify();
    };
    // Control: a renewal of the live term with a later lease is adopted (the path works in this state).
    inject(renewal_of(n, d, live, 1, lease0 + 1));
    LM_CHECK(n.until([&] { return n.eng(d).identity().member().lease_expires_root_ms == lease0 + 1; }, 2000));
    // (b) The term moves while the worker verifies: dropped before the commit.
    const uint64_t writes = n.node(d).store.slot_writes();
    inject(renewal_of(n, d, live, 1, lease0 + 2));
    LM_CHECK(n.eng(d).identity().note_term(RootTerm{2}));
    n.run_ms(500);
    LM_CHECK_EQ(n.eng(d).identity().member().lease_expires_root_ms, lease0 + 1);
    LM_CHECK_EQ(n.node(d).store.slot_writes(), writes);
    // (a) The member lives in term 2: a renewal of term 1 is dropped before any verification.
    const uint64_t dropped = m.stats().renew_dropped;
    inject(renewal_of(n, d, live, 1, lease0 + 3));
    LM_CHECK_EQ(m.stats().renew_dropped, dropped + 1);
    n.run_ms(500);
    LM_CHECK_EQ(n.eng(d).identity().member().lease_expires_root_ms, lease0 + 1);
    // (c) A renewal of term 2 is verified and committed while the exchange is busy; the member moves to term 3 before it
    // goes live: never adopted.
    link::Exchange &x = n.eng(d).link().exchange();
    MutByteView lent;
    LM_CHECK(n.until([&] { return !(lent = x.lend_scratch()).empty(); }, 5000, 5));
    const uint64_t writes2 = n.node(d).store.slot_writes();
    inject(renewal_of(n, d, live, 2, 5000));
    LM_CHECK(n.until([&] { return n.node(d).store.slot_writes() > writes2; }, 2000)); // committed, waits for adoption
    LM_CHECK(n.eng(d).identity().note_term(RootTerm{3}));
    if (!lent.empty()) {
        x.return_scratch();
    }
    n.node(d).notify();
    n.run_ms(1000);
    LM_CHECK(n.eng(d).identity().member().root_term == RootTerm{1});
    LM_CHECK_EQ(n.eng(d).identity().member().lease_expires_root_ms, lease0 + 1);
    LM_CHECK(n.eng(d).identity().term() == RootTerm{3});
}

// ---------------------------------------------------------------------------------------------------------------
// FIX8 (independent reviews of 8668c69: membership, lifecycle, groups). Each test failed on 8668c69.
namespace {
bool root_linked(DNet &n, unsigned d) {
    const link::Neighbor *nb = n.eng(0).link().neighbors().find_device(n.id(d));
    return nb != nullptr && nb->cur.active && !nb->join_only;
}
bool connect_root(DNet &n, unsigned d, uint64_t wait_ms = 10'000) {
    if (root_linked(n, d)) {
        return true;
    }
    (void)n.eng(d).link().connect(n.mac(0), n.node(d).clock.now());
    n.node(d).notify();
    return n.until([&] { return root_linked(n, d); }, wait_ms, 20);
}
bool left_at_root(DNet &n, unsigned d) {
    const root::Entry *e = n.eng(0).ledger().find(n.id(d));
    return e != nullptr && e->state == root::EntryState::Left;
}
bool leave_at_root(DNet &n, unsigned d) {
    lm_operation_id_t op = 0;
    if (lm_leave(n.ctx(d), LM_LEAVE_IMMEDIATE, 0, &op) != LM_STATUS_OK) {
        return false;
    }
    n.node(d).notify();
    return n.until([&] { return left_at_root(n, d); }, 10'000, 20);
}
// lm_group_set at the root; waits until its operation is final (the definition is durable) and returns its outcome.
uint32_t group_set_done(LNet &n, uint32_t gid, uint64_t expected, const std::vector<unsigned> &members) {
    std::vector<lm_device_id_t> ids(members.size());
    for (std::size_t k = 0; k < members.size(); ++k) {
        std::memcpy(ids[k].bytes, n.id(members[k]).bytes.data(), 32);
    }
    lm_operation_id_t op = 0;
    const lm_status_t s = lm_group_set(n.ctx(0), gid, expected, ids.data(), ids.size(), &op);
    if (s != LM_STATUS_OK) {
        return 0x10000U | s;
    }
    n.node(0).notify();
    const uint32_t reason = op_reason(n.world, n.node(0), op, 5000); // the OPERATION event: once it is durable
    return reason == 0 ? static_cast<uint32_t>(LM_OUTCOME_APPLIED)
                       : (reason == 0xFFFFU ? 0xFFFFU : static_cast<uint32_t>(LM_OUTCOME_REJECTED));
}
} // namespace

// C1: every ordinary leave took one of the root's 10 revocation-floor entries; after ten, every revocation ended
// NO_CAPACITY and a stolen member stayed ACTIVE. A listed device's floor is its ledger entry: revocation never needs
// table room. The table serves devices without an entry; a leave's copy there (it lets the slot be reused) gives way.
LM_TEST("S06 FIX8 sim: ten routine leaves never use up revocation; the 11th member is revoked for good; so is an unlisted device") {
    DNet n(11, 91);
    for (unsigned d = 2; d < 12; ++d) {
        LM_CHECK(connect_root(n, d));
        LM_CHECK(leave_at_root(n, d));
        n.run_ms(500); // the leave's floor copy is committed
    }
    LM_CHECK_EQ(n.eng(0).identity().floors().count(), member::k_max_floors); // precondition: the table is full
    const unsigned victim = 12;
    LM_CHECK(connect_root(n, victim));
    LM_CHECK(n.eng(0).ledger().authorized(n.id(victim)) != nullptr);
    LM_CHECK_EQ(n.install(0, 11, n.a.fleet.revoke(n.id(victim), 2, 2)), 0u); // NO_CAPACITY (4) on 8668c69
    const root::Entry *e = n.eng(0).ledger().find(n.id(victim));
    LM_CHECK(e != nullptr && e->state == root::EntryState::Blocked);
    LM_CHECK(n.eng(0).ledger().authorized(n.id(victim)) == nullptr);
    n.run_ms(11'000); // the notice had its chance: its sessions end
    LM_CHECK(!root_linked(n, victim));
    LM_CHECK(!connect_root(n, victim, 8000)); // and it gets no new one
    // Durable: the entry is the floor record of a listed device.
    n.reboot(0);
    e = n.eng(0).ledger().find(n.id(victim));
    LM_CHECK(e != nullptr && e->state == root::EntryState::Blocked);
    LM_CHECK(!connect_root(n, victim, 8000));
    // A device this root never listed (B's root): the fleet floor is recorded although the table was full.
    LM_CHECK(n.eng(0).ledger().find(n.id(1)) == nullptr);
    LM_CHECK_EQ(n.install(0, 11, n.a.fleet.revoke(n.id(1), 5, 5)), 0u);
    LM_CHECK(n.eng(0).identity().floors().check(n.id(1), AssignmentGen{4}, MembershipGen{9}) == Status::Revoked);
    n.reboot(0);
    LM_CHECK(n.eng(0).identity().floors().check(n.id(1), AssignmentGen{4}, MembershipGen{9}) == Status::Revoked);
    LM_CHECK(n.eng(0).identity().floors().count() <= member::k_max_floors);
}

// C1, the table's own limit: floors of devices this root never listed. Ten of them fill the table with floors nothing else
// keeps; the next one gets a Blocked entry of its own in a free slot (the entry is its floor record). With the ledger
// full as well nothing changes (NO_CAPACITY) - and then no new device can get a slot here either.
LM_TEST("S06 FIX8 sim: unlisted revocations beyond the table get a Blocked entry; with the ledger full nothing is admitted") {
    // Node 1 (address 2) and 62 listed members (addresses 3..64): one free slot left (address 65).
    LNet n({Spec{}, Spec{Role::Leaf, 0xFFFFFFFFFFULL}, Spec{Role::Leaf, 0, true}}, 96, 62);
    n.boot(0);
    n.boot(1);
    LM_CHECK(n.until([&] { return n.ready(1); }, 90'000));
    LM_CHECK_EQ(n.eng(0).ledger().count(root::EntryState::Free), 1u);
    auto stranger = [](uint8_t k) {
        DeviceId d;
        d.bytes.fill(static_cast<uint8_t>(0xA0 + k));
        return d;
    };
    const std::size_t provisioned = n.eng(0).identity().floors().count();
    for (uint8_t k = 0; k < member::k_max_floors - provisioned; ++k) {
        LM_CHECK_EQ(n.install_result(0, 11, n.net.fleet.revoke(stranger(k), 3, 3)), 0u);
    }
    LM_CHECK_EQ(n.eng(0).identity().floors().count(), member::k_max_floors);
    // The table holds only floors nothing else keeps: a Blocked entry in the free slot.
    LM_CHECK_EQ(n.install_result(0, 11, n.net.fleet.revoke(stranger(20), 3, 3)), 0u);
    const root::Entry *e = n.eng(0).ledger().find(stranger(20));
    LM_CHECK(e != nullptr && e->state == root::EntryState::Blocked && e->consumed == 2 && e->membership == 2);
    LM_CHECK_EQ(n.eng(0).ledger().count(root::EntryState::Free), 0u);
    // No free slot and no redundant copy: NO_CAPACITY, nothing changed - and no new device can get a slot (a join needs
    // a free or reusable one), so the revoked device cannot join this root either.
    LM_CHECK_EQ(n.install_result(0, 11, n.net.fleet.revoke(stranger(21), 3, 3)), static_cast<uint32_t>(Status::NoCapacity));
    LM_CHECK(n.eng(0).ledger().find(stranger(21)) == nullptr);
    n.node(0).power_cut();
    n.node(0).store.power_restore();
    n.boot(0);
    LM_CHECK(n.until([&] { return n.eng(0).ledger().ready(); }, 5000));
    e = n.eng(0).ledger().find(stranger(20));
    LM_CHECK(e != nullptr && e->state == root::EntryState::Blocked); // durable
    for (uint8_t k = 0; k < member::k_max_floors - provisioned; ++k) {
        LM_CHECK(n.eng(0).identity().floors().check(stranger(k), AssignmentGen{2}, MembershipGen{9}) == Status::Revoked);
    }
}

// M4: a device that left, whose ledger slot was then given to another device, restarted its membership generation at 1 -
// below its own leave floor - and was refused REVOKED forever, even with a fresh fleet grant and expected entry.
LM_TEST("R09 FIX8 sim: a departed device whose slot was reused rejoins with a new grant above its own floor") {
    LNet n({Spec{}, Spec{Role::Relay, 0xFFFFFFFFFFULL}, Spec{Role::Relay, 0xFFFFFFFFFFULL},
            Spec{Role::Leaf, 0xFFFFFFFFFFULL}, Spec{Role::Leaf, 0, true}},
           76, 61);
    n.link(1, 2, false);
    n.link(0, 2);
    n.link(2, 3, false);
    n.link(0, 3);
    n.link(3, 4, false);
    n.link(2, 4); // D2 (node 4) reaches the root through X (node 2)
    for (unsigned i = 0; i < 4; ++i) {
        n.boot(i);
    }
    LM_CHECK(n.until([&] { return n.ready(1) && n.ready(2) && n.ready(3); }, 120'000));
    LM_CHECK_EQ(n.eng(0).ledger().count(root::EntryState::Free), 0u); // every slot is used
    for (unsigned d : {1u, 3u}) { // D1 and D3 leave
        lm_operation_id_t lop = 0;
        LM_CHECK_EQ(lm_leave(n.ctx(d), LM_LEAVE_IMMEDIATE, 0, &lop), LM_STATUS_OK);
        n.node(d).notify();
        LM_CHECK(n.until([&] {
            const root::Entry *x = n.eng(0).ledger().find(n.id(d));
            return x != nullptr && x->state == root::EntryState::Left;
        }, 10'000));
        n.run_ms(1000);
    }
    n.eng(0).ledger().set_join_mode(root::JoinMode::Preapproved);
    n.boot(4);
    n.run_ms(500);
    n.grant(4, 1, 1); // D2's expected entry takes D1's slot (address 2): D1's entry is gone, its floor stays
    LM_CHECK(n.eng(0).ledger().find(n.id(1)) == nullptr);
    LM_CHECK_EQ(n.join(4, 90), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.eng(4).identity().is_member() && n.ready(4); }, 120'000));
    n.grant(1, 2, 2); // D1 comes back with a fresh fleet grant (generation 2 > its old 1)
    n.run_ms(31'000); // one full handshake per peer per 30 s
    LM_CHECK_EQ(n.join(1, 0x63), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.eng(1).identity().is_member(); }, 120'000)); // REVOKED (8) on 8668c69
    LM_CHECK(n.eng(1).identity().member().membership.value() >= 2); // above the floor its own leave left (1 + 1)
    LM_CHECK_EQ(n.eng(1).identity().member().assignment.value(), 2u);
}

// M3: the root kept ONE pending leave: a LeaveRequest that arrived while an earlier one waited for the ledger's memory
// overwrote it, and that device - erased on its side - stayed ACTIVE in the ledger.
LM_TEST("M06 FIX8 sim: three members leaving together are all Left at the root") {
    DNet n(3, 92);
    for (unsigned d = 2; d < 5; ++d) {
        LM_CHECK(connect_root(n, d));
    }
    n.node(0).jobs.latency_us = 300'000; // a Flash commit takes 300 ms on the root's worker
    for (unsigned d = 2; d < 5; ++d) {
        lm_operation_id_t op = 0;
        LM_CHECK_EQ(lm_leave(n.ctx(d), LM_LEAVE_IMMEDIATE, 0, &op), LM_STATUS_OK);
        n.node(d).notify();
    }
    n.run_ms(20'000);
    for (unsigned d = 2; d < 5; ++d) {
        LM_CHECK(!n.eng(d).identity().is_member());
        LM_CHECK(left_at_root(n, d)); // one of them stayed Active on 8668c69
    }
}

// H2: a request waiting for the operator is judged again when it is approved, and before any JoinCommit signature leaves
// the root: a revocation that arrived meanwhile refuses it (8668c69 committed ACTIVE and sent the signature).
LM_TEST("J04 FIX8 sim: an approval given after a revocation issues nothing; the request ends refused") {
    DNet n(1, 93);
    const unsigned d = 2;
    const Bytes ab = n.transfer_ticket(d, n.a, n.b, 1, 2);
    LM_CHECK_EQ(n.install(d, 3, ab), 0u);
    LM_CHECK_EQ(n.start_join(d, 0x44, LM_JOIN_TRANSFER_CANDIDATE), LM_STATUS_OK); // B is in external mode
    root::PendingJoin pj;
    LM_CHECK(n.until([&] {
        for (std::size_t i = 0; i < root::k_join_txns; ++i) {
            if (n.eng(1).ledger().pending_join(i, pj)) {
                return true;
            }
        }
        return false;
    }, 30'000, 20));
    LM_CHECK_EQ(n.install(1, 11, n.a.fleet.revoke(n.id(d), 3, 0)), 0u); // the fleet revokes every assignment below 3
    root::JoinDecision dec;
    dec.request = pj.request;
    dec.approve = true; // a stale operator view approves
    LM_CHECK_OK(n.eng(1).ledger().decide(dec, n.node(1).clock.now()));
    n.node(1).notify();
    LM_CHECK(!n.until([&] { return n.in_domain(d, n.b); }, 60'000, 20)); // the revoked device never holds B's credential
    const root::Entry *e = n.eng(1).ledger().find(n.id(d));
    LM_CHECK(e == nullptr || (e->state != root::EntryState::Active && e->state != root::EntryState::Prepared));
    for (std::size_t i = 0; i < root::k_join_txns; ++i) {
        LM_CHECK(!n.eng(1).ledger().pending_join(i, pj)); // not pending any more: refused
    }
    LM_CHECK(n.in_domain(d, n.a)); // nothing half-moved
}

// Second review #2: a group named its members by ledger slot; a member left, another device took its slot and the
// unchanged group revision then named the newcomer. A slot a group names is not given to another device while it does.
LM_TEST("R09 FIX8 sim: a group keeps naming its departed member; its slot goes to nobody else until the group is edited") {
    LNet n({Spec{}, Spec{Role::Relay, 0xFFFFFFFFFFULL}, Spec{Role::Relay, 0xFFFFFFFFFFULL}, Spec{Role::Leaf, 0, true}},
           73, 62);
    n.link(0, 2);
    n.link(1, 2, false);
    n.link(2, 3);
    for (unsigned i = 0; i < 3; ++i) {
        n.boot(i);
    }
    LM_CHECK(n.until([&] { return n.ready(1) && n.ready(2); }, 90'000));
    LM_CHECK_EQ(group_set_done(n, 7, 0, {1}), static_cast<uint32_t>(LM_OUTCOME_APPLIED));
    lm_operation_id_t op = 0;
    LM_CHECK_EQ(lm_leave(n.ctx(1), LM_LEAVE_IMMEDIATE, 0, &op), LM_STATUS_OK);
    n.node(1).notify();
    LM_CHECK(n.until([&] {
        const root::Entry *x = n.eng(0).ledger().find(n.id(1));
        return x != nullptr && x->state == root::EntryState::Left;
    }, 10'000));
    n.node(1).power_cut();
    n.run_ms(1000);
    n.eng(0).ledger().set_join_mode(root::JoinMode::Preapproved);
    n.boot(3);
    n.run_ms(500);
    // The ledger is full: the only reusable slot is the departed member's, and group 7 names it.
    const Bytes t = n.net.fleet.ticket(n.kits[3].kit, DomainId{}, n.net.domain, n.net.delegation_cose, 0, 1);
    LM_CHECK_EQ(n.install(3, 3, t), LM_STATUS_OK);
    LM_CHECK(n.install_result(0, 5, n.expected_page(3, 1, t, 1)) == static_cast<uint32_t>(Status::NoCapacity));
    LM_CHECK_EQ(n.join(3, 90), LM_STATUS_OK);
    n.run_ms(40'000);
    LM_CHECK(!n.eng(3).identity().is_member());
    group::Op snap{};
    DeviceId ids[group::k_max_targets];
    LM_CHECK_OK(n.eng(0).groups().snapshot(7, 1, snap, ids));
    LM_CHECK(ids[0] == n.id(1)); // the newcomer on 8668c69
    // The Host drops the departed member from the group: the slot is free for another device now.
    LM_CHECK_EQ(group_set_done(n, 7, 1, {}), static_cast<uint32_t>(LM_OUTCOME_APPLIED));
    LM_CHECK_EQ(n.install_result(0, 5, n.expected_page(3, 1, t, 2)), 0u);
    LM_CHECK(n.until([&] {
        if (n.eng(3).membership().phase() == member::JoinPhase::Idle && !n.eng(3).identity().is_member()) {
            (void)n.join(3, 91); // (the first request may have ended meanwhile: ask again)
        }
        return n.eng(3).identity().is_member() && n.ready(3);
    }, 150'000, 1000));
    LM_CHECK_OK(n.eng(0).groups().snapshot(7, 2, snap, ids));
    LM_CHECK_EQ(snap.total, 0u);
}

// Second review #13: lm_get_request put the private join phase into the public phase field (an APPLIED join read
// phase 0 = PENDING).
LM_TEST("J01 FIX8 sim: lm_get_request reports public phases: a completed join is FINAL") {
    LNet n({Spec{}, Spec{Role::Leaf, 0, true}}, 74);
    n.boot(0);
    n.boot(1);
    n.run_ms(500);
    n.eng(0).ledger().set_join_mode(root::JoinMode::Preapproved);
    n.grant(1, 1, 1);
    LM_CHECK_EQ(n.join(1, 91), LM_STATUS_OK);
    lm_request_id_t request = rid(91);
    lm_operation_t out{};
    out.struct_size = sizeof(out);
    out.abi_version = LM_ABI_VERSION;
    LM_CHECK_EQ(lm_get_request(n.ctx(1), &request, &out), LM_STATUS_OK);
    LM_CHECK(out.phase == LM_PHASE_PENDING || out.phase == LM_PHASE_SENDING || out.phase == LM_PHASE_WAITING_RECEIPT);
    LM_CHECK(n.until([&] { return n.eng(1).identity().is_member() && n.ready(1); }, 120'000));
    n.run_ms(1000);
    LM_CHECK_EQ(lm_get_request(n.ctx(1), &request, &out), LM_STATUS_OK);
    LM_CHECK_EQ(out.outcome, static_cast<uint32_t>(LM_OUTCOME_APPLIED));
    LM_CHECK_EQ(out.phase, static_cast<uint32_t>(LM_PHASE_FINAL)); // 0 on 8668c69
}

// Second review #3: the LEFT tombstone reached the Flash but its read-back failed; 8668c69 reported the failure, undid
// the send prohibition and kept the member live in RAM (storage LEFT, RAM ACTIVE, lm_send OK). The leave stays fail
// closed: RAM leaves at once, the stored record is read back and the operation ends by what it says.
LM_TEST("M06 FIX8 sim: a leave whose commit reported a failure stays left; the stored record decides its result") {
    for (const CutMode mode : {CutMode::After, CutMode::Before}) {
        DNet n(1, 94);
        const unsigned d = 2;
        (void)n.eng(d).link().close(n.id(0)); // no root link: the commit starts at once
        SimStore &st = n.node(d).store;
        st.arm_cut(st.mutating_ops() + 1, mode); // the marker of the LEFT record: written (After) or not (Before)
        lm_operation_id_t op = 0;
        LM_CHECK_EQ(lm_leave(n.ctx(d), LM_LEAVE_IMMEDIATE, 0, &op), LM_STATUS_OK);
        n.node(d).notify();
        n.run_ms(100);
        LM_CHECK(st.cut_fired());
        LM_CHECK(!n.eng(d).identity().is_member()); // fail closed at once (live on 8668c69)
        lm_membership_t m = n.membership(d);
        LM_CHECK(m.state != LM_ACTIVE);
        st.power_restore();
        const uint32_t reason = op_reason(n.world, n.node(d), op, 10'000);
        LM_CHECK_EQ(reason, 0u); // APPLIED: read back LEFT (After), or committed again (Before)
        LM_CHECK_EQ(stored_state(st, store::rec::membership), static_cast<int>(member::k_membership_left));
        LM_CHECK(!n.eng(d).identity().is_member());
        n.reboot(d);
        LM_CHECK_EQ(n.membership(d).state, static_cast<uint32_t>(LM_UNASSIGNED));
    }
}

// Second review #3 (revocation): a verified revocation notice holds whatever its tombstone commit does.
LM_TEST("S06 FIX8 sim: a revocation notice whose tombstone commit failed leaves the device revoked all the same") {
    LNet n({Spec{}, Spec{Role::Leaf}}, 95);
    n.boot(0);
    n.boot(1);
    LM_CHECK(n.until([&] { return n.all_ready(); }, 90'000));
    const lm_operation_id_t o = n.send_to_root(1); // the end session the notice travels over
    LM_CHECK(o != 0);
    LM_CHECK(n.until([&] { return n.op(1, o).phase == LM_PHASE_FINAL; }, 30'000));
    SimStore &st = n.node(1).store;
    st.arm_cut(st.mutating_ops() + 1, CutMode::Before); // the tombstone's marker never reaches the Flash
    LM_CHECK_EQ(n.install(0, 11, fleet::issue_root_revoke(n.kits[0].kit, n.net.domain, n.id(1), 2, 2)), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return st.cut_fired(); }, 30'000));
    n.run_ms(200);
    LM_CHECK(!n.eng(1).identity().is_member()); // the verified revocation holds in RAM
    LM_CHECK_EQ(n.state(1), static_cast<uint32_t>(LM_MEMBER_REVOKED));
    st.power_restore();
    LM_CHECK(n.until([&] { return stored_state(st, store::rec::membership) ==
                                  static_cast<int>(member::k_membership_revoked); }, 10'000)); // then durably
    LM_CHECK(!n.eng(1).identity().is_member());
}

// ---- FIX8 addendum: the independent review of the FIX8 diff (its experiments HA, HB, HD), asserting the fix ----
namespace {
std::size_t stored_len(SimStore &st, uint16_t id) {
    auto job = std::make_unique<store::RecordJob>();
    job->arm(store::RecordJob::Op::Load, id);
    return store::record_load(st, *job) == Status::Ok ? job->payload_len : 0;
}
bool revoked_event(LNet &n, unsigned about) {
    bool seen = false;
    lm_event_t ev{};
    ev.struct_size = sizeof(ev);
    ev.abi_version = LM_ABI_VERSION;
    std::array<uint8_t, 700> buf{};
    std::size_t len = 0;
    while (lm_next_event(n.ctx(0), &ev, buf.data(), buf.size(), &len) == LM_STATUS_OK) {
        if (ev.kind == LM_EVENT_MEMBERSHIP && ev.reason == LM_MEMBER_REVOKED &&
            std::memcmp(ev.peer.bytes, n.id(about).bytes.data(), 32) == 0) {
            seen = true;
        }
    }
    return seen;
}
void write_table_floor(SimStore &st, const DeviceId &d, uint64_t a, uint64_t m) {
    member::Floors f;
    auto job = std::make_unique<store::RecordJob>();
    job->arm(store::RecordJob::Op::Load, store::rec::revocation_floors);
    if (store::record_load(st, *job) == Status::Ok) {
        LM_CHECK_OK(member::decode_floors(ByteView{job->payload.data(), job->payload_len}, f));
    }
    LM_CHECK_OK(f.raise(d, a, m));
    std::size_t len = 0;
    LM_CHECK_OK(member::encode_floors(f, MutByteView{job->payload}, len));
    job->arm(store::RecordJob::Op::Commit, store::rec::revocation_floors, 0, len);
    LM_CHECK_OK(store::record_commit(st, *job));
}
DeviceId stranger(uint8_t k) {
    DeviceId d;
    d.bytes.fill(static_cast<uint8_t>(0xA0 + k));
    return d;
}
} // namespace

// A revocation whose entry commit failed and whose repair gave up (the store stayed dead) must never later write that
// slot's record over a newer state of it: the member was re-allowed by a signed expected page and joined again; a later
// unrelated floor copy restarted the repairs, which rewrote the ACTIVE record without its credential (review HA).
LM_TEST("S06 FIX8 sim: a repair that gave up never rewrites the member's later ACTIVE record") {
    LNet n({Spec{}, Spec{Role::Leaf}, Spec{Role::Leaf}}, 79);
    star(n);
    for (unsigned i = 0; i < 3; ++i) {
        n.boot(i);
    }
    LM_CHECK(n.until([&] { return n.all_ready(); }, 90'000));
    SimStore &st = n.node(0).store;
    const uint16_t rec1 = static_cast<uint16_t>(root::k_rec_ledger_base + 0);
    st.arm_cut(st.mutating_ops(), CutMode::Before);
    const Bytes rv = fleet::issue_root_revoke(n.kits[0].kit, n.net.domain, n.id(1), 2, 2);
    lm_operation_id_t op = 0;
    LM_CHECK_EQ(lm_install_control(n.ctx(0), 11, rv.data(), rv.size(), &op), LM_STATUS_OK);
    n.node(0).notify();
    LM_CHECK(n.until([&] { return st.cut_fired(); }, 5000));
    n.run_ms(40'000); // the store stays dead: every repair fails until k_recon_tries
    st.power_restore();
    n.run_ms(3000);
    LM_CHECK(stored_state(st, rec1) == static_cast<int>(root::EntryState::Active)); // precondition
    LM_CHECK(n.eng(0).ledger().find(n.id(1))->state == root::EntryState::Blocked);
    lm_operation_id_t lop = 0;
    LM_CHECK_EQ(lm_leave(n.ctx(1), LM_LEAVE_IMMEDIATE, 0, &lop), LM_STATUS_OK);
    n.node(1).notify();
    LM_CHECK(n.until([&] { return !n.eng(1).identity().is_member(); }, 10'000));
    n.eng(0).ledger().set_join_mode(root::JoinMode::Preapproved);
    n.grant(1, 2, 1); // a new fleet grant and an expected entry for it (Blocked -> Expected)
    n.run_ms(31'500);
    LM_CHECK_EQ(n.join(1, 0x61), LM_STATUS_OK);
    LM_CHECK(n.until([&] { return n.eng(1).identity().is_member() && n.ready(1); }, 120'000));
    n.run_ms(3000);
    const std::size_t before = stored_len(st, rec1);
    LM_CHECK(stored_state(st, rec1) == static_cast<int>(root::EntryState::Active) && before > 105); // holds its credential
    (void)revoked_event(n, 1);
    lm_operation_id_t lop2 = 0; // an unrelated member leaves: its floor copy restarts the ledger's repairs
    LM_CHECK_EQ(lm_leave(n.ctx(2), LM_LEAVE_IMMEDIATE, 0, &lop2), LM_STATUS_OK);
    n.node(2).notify();
    n.run_ms(5000);
    LM_CHECK_EQ(stored_len(st, rec1), before); // 105 (credential dropped) on the first FIX8 diff
    LM_CHECK(!revoked_event(n, 1));
    LM_CHECK(n.eng(0).ledger().authorized(n.id(1)) != nullptr);
}

// A table floor below which an ACTIVE entry lies is folded into the entry at boot (RAM Blocked); when that repair fails,
// the table copy is the only durable floor and must never be evicted for an unlisted revocation (review HB).
LM_TEST("S06 FIX8 sim: a table floor whose entry repair failed is never evicted; after a restart it still refuses") {
    bool hit = false;
    for (uint64_t k = 0; k < 24 && !hit; ++k) {
        LNet n({Spec{}, Spec{Role::Leaf}, Spec{Role::Leaf}, Spec{Role::Leaf}}, 79);
        star(n);
        for (unsigned i = 0; i < 4; ++i) {
            n.boot(i);
        }
        LM_CHECK(n.until([&] { return n.all_ready(); }, 90'000));
        const std::size_t provisioned = n.eng(0).identity().floors().count();
        for (uint8_t s = 0; s + 1 + provisioned < member::k_max_floors; ++s) {
            LM_CHECK_EQ(n.install_result(0, 11, n.net.fleet.revoke(stranger(s), 3, 3)), 0u);
        }
        SimStore &st = n.node(0).store;
        const uint16_t rec3 = static_cast<uint16_t>(root::k_rec_ledger_base + 2);
        n.node(0).power_cut();
        write_table_floor(st, n.id(3), 9, 9); // a durable table floor above node 3's ACTIVE entry
        st.arm_cut(st.mutating_ops() + k, CutMode::Before);
        if (n.node(0).boot() != Status::Ok || lm_start(n.ctx(0)) != LM_STATUS_OK) {
            continue;
        }
        n.run_ms(300);
        const root::Entry *e3 = n.eng(0).ledger().ready() ? n.eng(0).ledger().find(n.id(3)) : nullptr;
        if (!st.cut_fired() || e3 == nullptr || e3->state != root::EntryState::Blocked) {
            continue;
        }
        n.run_ms(40'000);
        st.power_restore();
        n.run_ms(1000);
        if (stored_state(st, rec3) != static_cast<int>(root::EntryState::Active)) {
            continue; // the cut was not the repair commit
        }
        hit = true;
        (void)n.install_result(0, 11, n.net.fleet.revoke(stranger(20), 3, 3)); // an unlisted revocation, table full
        LM_CHECK(n.eng(0).identity().floors().floor_of(n.id(3)).assignment == 9); // kept (evicted on the first diff)
        n.run_ms(1000);
        n.node(0).power_cut();
        n.boot(0);
        LM_CHECK(n.until([&] { return n.eng(0).ledger().ready(); }, 5000));
        LM_CHECK(n.eng(0).ledger().authorized(n.id(3)) == nullptr);
    }
    LM_CHECK(hit); // some cut index hit the boot-time repair commit
}

// An expected-page entry commit into a reused slot reported a failure although the record landed (RAM keeps the departed
// device there): that slot is in doubt, so the departed device's table copy - now its only durable floor - is never
// evicted as "redundant" (review HD).
LM_TEST("R09 FIX8 sim: a slot whose commit result is unknown keeps the floor of its former device") {
    bool hit = false;
    for (uint64_t k = 0; k < 16 && !hit; ++k) {
        // Node 1 (address 2, slot 0) and 63 more listed members: the ledger is full. Node 2 is unjoined.
        LNet n({Spec{}, Spec{Role::Leaf, 0xFFFFFFFFFFULL}, Spec{Role::Leaf, 0, true}}, 96, 63);
        n.boot(0);
        n.boot(1);
        LM_CHECK(n.until([&] { return n.ready(1); }, 90'000));
        LM_CHECK_EQ(n.eng(0).ledger().count(root::EntryState::Free), 0u);
        lm_operation_id_t lop = 0;
        LM_CHECK_EQ(lm_leave(n.ctx(1), LM_LEAVE_IMMEDIATE, 0, &lop), LM_STATUS_OK);
        n.node(1).notify();
        LM_CHECK(n.until([&] {
            const root::Entry *x = n.eng(0).ledger().find(n.id(1));
            return x != nullptr && x->state == root::EntryState::Left;
        }, 10'000));
        n.run_ms(1000); // its floor copy is durable: slot 0 is reusable
        const std::size_t have = n.eng(0).identity().floors().count();
        for (uint8_t s = 0; s + have < member::k_max_floors; ++s) {
            LM_CHECK_EQ(n.install_result(0, 11, n.net.fleet.revoke(stranger(s), 3, 3)), 0u);
        }
        LM_CHECK_EQ(n.eng(0).identity().floors().count(), member::k_max_floors);
        n.boot(2);
        n.run_ms(500);
        const Bytes t = n.net.fleet.ticket(n.kits[2].kit, DomainId{}, n.net.domain, n.net.delegation_cose, 0, 1);
        LM_CHECK_EQ(n.install(2, 3, t), LM_STATUS_OK);
        SimStore &st = n.node(0).store;
        st.arm_cut(st.mutating_ops() + k, CutMode::After);
        const uint32_t er = n.install_result(0, 5, n.expected_page(2, 1, t, 1));
        st.power_restore();
        const root::Entry &ram0 = n.eng(0).ledger().entry(0);
        auto job = std::make_unique<store::RecordJob>();
        job->arm(store::RecordJob::Op::Load, static_cast<uint16_t>(root::k_rec_ledger_base + 0));
        const bool loaded = store::record_load(st, *job) == Status::Ok && job->payload_len >= 57;
        const bool durable_is_2 = loaded && std::memcmp(job->payload.data() + 25, n.id(2).bytes.data(), 32) == 0;
        if (er == 0 || !(ram0.device == n.id(1) && ram0.state == root::EntryState::Left) || !durable_is_2) {
            continue;
        }
        hit = true;
        (void)n.install_result(0, 11, n.net.fleet.revoke(stranger(20), 3, 3)); // an unlisted revocation, table full
        n.run_ms(1000);
        n.node(0).power_cut();
        n.boot(0);
        LM_CHECK(n.until([&] { return n.eng(0).ledger().ready(); }, 5000));
        // Node 1's floor survives: in its entry (none: the slot holds node 2 now) or in the table.
        LM_CHECK(n.eng(0).ledger().find(n.id(1)) != nullptr ||
                 n.eng(0).identity().floors().floor_of(n.id(1)).assignment > 0);
    }
    LM_CHECK(hit); // some cut index gave the unknown-result entry commit
}

int main(int argc, char **argv) { return lmtest::run_all(argc, argv); }

// FIX12-D1 (final review N1): the same revocation object installed again after its commit failed must not answer OK
// from the fail-closed RAM alone; only a durable entry is an idempotent success (a restart would authorize it again).
LM_TEST("S06 FIX12 sim: a revocation whose commit failed is not reported applied by a retry until it is durable") {
    LNet n({Spec{}, Spec{Role::Leaf}, Spec{Role::Leaf}, Spec{Role::Leaf}}, 79);
    star(n);
    for (unsigned i = 0; i < 4; ++i) {
        n.boot(i);
    }
    LM_CHECK(n.until([&] { return n.all_ready(); }, 90'000));
    SimStore &st = n.node(0).store;
    const uint16_t rec1 = static_cast<uint16_t>(root::k_rec_ledger_base + 0);
    const Bytes rv = fleet::issue_root_revoke(n.kits[0].kit, n.net.domain, n.id(1), 2, 2);
    st.arm_cut(st.mutating_ops(), CutMode::Before);
    LM_CHECK_EQ(n.install_result(0, 11, rv), static_cast<uint32_t>(LM_STATUS_RECOVERY_REQUIRED));
    LM_CHECK(st.cut_fired());
    LM_CHECK_EQ(n.install_result(0, 11, rv), static_cast<uint32_t>(LM_STATUS_RECOVERY_REQUIRED)); // store still dead
    n.node(0).power_cut();
    st.power_restore();
    LM_CHECK(stored_state(st, rec1) == static_cast<int>(root::EntryState::Active)); // what a restart would see
    n.boot(0);
    LM_CHECK(n.until([&] { return n.eng(0).ledger().ready(); }, 5000));
    LM_CHECK(n.eng(0).ledger().find(n.id(1))->state == root::EntryState::Active);
    LM_CHECK_EQ(n.install_result(0, 11, rv), 0u); // now durable: OK, and it stays blocked after a restart
    LM_CHECK(stored_state(st, rec1) == static_cast<int>(root::EntryState::Blocked));
    LM_CHECK_EQ(n.install_result(0, 11, rv), 0u); // idempotent once durable
}
