// JOIN slice (S8): membership over the simulated medium. Real lm_context + Engine per node on sim
// ports, credentials from the TEST-ONLY fleet issuer, EDHOC through the worker jobs, every ledger and
// membership record through the sealed record layer on the SimStore. No Host exists in this file:
// preapproved Join is decided by the root alone (docs/07 §4). Scenario IDs are in the test names.
// Everything here is a protocol bench: virtual time, no RF, no energy, no real Flash (docs/18 §3).
#include <array>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "capi/context.hpp"
#include "core/codec.hpp"
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

struct Ev {
    uint32_t kind = 0;
    uint32_t reason = 0;
    uint64_t op = 0;
    DeviceId peer;
};

ByteView view(const Bytes &b) { return ByteView{b.data(), b.size()}; }

lm_request_id_t rid(uint8_t seed) {
    lm_request_id_t r{};
    for (std::size_t i = 0; i < 16; ++i) {
        r.bytes[i] = static_cast<uint8_t>(seed + i);
    }
    return r;
}

struct JNet {
    // Node 0 is the root (preapproved by default), 1..n-1 are provisioned but unjoined devices. `channel`: the
    // devices run the channel module (as firmware does), which borrows the record memory at boot too.
    explicit JNet(unsigned n, uint64_t seed = 31, bool boot_all = true, bool channel = false)
        : net(seed), world(WorldOptions{seed, 0}), events(n), tickets(n) {
        for (unsigned i = 0; i < n; ++i) {
            NodeOptions o;
            o.role = i == 0 ? Role::Root : Role::Leaf;
            o.channel = channel && i != 0;
            (void)world.add_node(o);
            kits.push_back(i == 0 ? net.make_root() : net.make_unjoined(i));
        }
        world.make_full();
        LM_CHECK_OK(fleet::provision(node(0).store, net, kits[0]));
        for (unsigned i = 1; i < n; ++i) {
            provision_unjoined(i);
        }
        if (boot_all) {
            start_all();
        }
    }

    void start_all() {
        for (unsigned i = 0; i < kits.size(); ++i) {
            boot(static_cast<uint16_t>(i));
        }
        run_ms(50);
        root_loaded();
        eng(0).ledger().set_join_mode(root::JoinMode::Preapproved);
    }
    // The root answers once its ledger is loaded (other owners may hold the identity's record memory at boot).
    void root_loaded() {
        (void)run_until([&] { return eng(0).ledger().ready() || eng(0).ledger().failed(); }, 1000, 5000);
    }

    // Identity + trust anchor only: no delegation, no membership (the domain is learned from the root).
    void provision_unjoined(unsigned i) {
        sim::ProvisionInput in;
        in.scalar32 = ByteView{kits[i].kit.scalar};
        in.device_cose = view(kits[i].kit.device_cose);
        in.trust = net.fleet.trust();
        LM_CHECK_OK(sim::provision_store(node(i).store, in));
    }

    SimNode &node(unsigned i) { return world.node(static_cast<uint16_t>(i)); }
    lm_context_t *ctx(unsigned i) { return node(i).ctx(); }
    Engine &eng(unsigned i) { return node(i).ctx()->engine; }
    member::Membership &mem(unsigned i) { return eng(i).membership(); }
    root::Ledger &ledger() { return eng(0).ledger(); }
    const DeviceId &id(unsigned i) { return kits[i].kit.id; }

    void boot(uint16_t i) {
        events[i].clear(); // operation ids are per context: a rebooted node numbers them again
        LM_CHECK_OK(node(i).boot());
        LM_CHECK_EQ(lm_start(ctx(i)), LM_STATUS_OK);
    }
    void reboot(uint16_t i) {
        node(i).power_cut();
        node(i).store.power_restore();
        boot(i);
        run_ms(50);
        if (i == 0) {
            root_loaded();
            eng(0).ledger().set_join_mode(root::JoinMode::Preapproved);
        }
    }
    void run_ms(uint64_t ms) { world.run_until(world.now_us() + ms * 1000); }
    template <class P> bool run_until(P pred, uint64_t max_ms, uint64_t step_us = 1000) {
        for (uint64_t t = 0; t < max_ms * 1000; t += step_us) {
            if (pred()) {
                return true;
            }
            world.run_until(world.now_us() + step_us);
        }
        return pred();
    }
    void set_link(unsigned a, unsigned b, bool up) {
        LinkParams p = world.link(static_cast<uint16_t>(a), static_cast<uint16_t>(b));
        p.up = up;
        world.set_link(static_cast<uint16_t>(a), static_cast<uint16_t>(b), p);
    }

    void pump_events(unsigned i) {
        for (;;) {
            lm_event_t ev{};
            ev.struct_size = sizeof(ev);
            ev.abi_version = LM_ABI_VERSION;
            if (lm_next_event(ctx(i), &ev, nullptr, 0, nullptr) != LM_STATUS_OK) {
                return;
            }
            Ev e{ev.kind, ev.reason, ev.operation_id, DeviceId{}};
            std::memcpy(e.peer.bytes.data(), ev.peer.bytes, 32);
            events[i].push_back(e);
        }
    }
    bool has_event(unsigned i, uint32_t kind, uint32_t reason) {
        pump_events(i);
        for (const Ev &e : events[i]) {
            if (e.kind == kind && e.reason == reason) {
                return true;
            }
        }
        return false;
    }
    // Waits for the LM_EVENT_OPERATION of `op` on node i; returns its reason (status), 0xFFFF if none.
    uint32_t wait_operation(unsigned i, uint64_t op, uint64_t max_ms) {
        uint32_t reason = 0xFFFF;
        (void)run_until(
            [&] {
                pump_events(i);
                for (const Ev &e : events[i]) {
                    if (e.kind == LM_EVENT_OPERATION && e.op == op) {
                        reason = e.reason;
                        return true;
                    }
                }
                return false;
            },
            max_ms, 5000);
        return reason;
    }

    Bytes ticket_for(unsigned i, uint64_t generation) {
        return net.fleet.ticket(kits[i].kit, DomainId{}, net.domain, net.delegation_cose, 0, generation);
    }
    // BUSY is local (another owner holds the record memory, e.g. at boot): the caller asks again, bounded.
    lm_status_t install(unsigned i, uint32_t type, const Bytes &obj, lm_operation_id_t &op) {
        lm_status_t s = LM_STATUS_BUSY;
        (void)run_until(
            [&] {
                s = lm_install_control(ctx(i), type, obj.data(), obj.size(), &op);
                return s != LM_STATUS_BUSY;
            },
            1000, 5000);
        return s;
    }
    Status install_ticket(unsigned i, const Bytes &t) {
        lm_operation_id_t op = 0;
        const lm_status_t s = install(i, 3, t, op);
        if (s != LM_STATUS_OK) {
            return static_cast<Status>(s);
        }
        return wait_operation(i, op, 2000) == 0 ? Status::Ok : Status::StorageFailure;
    }

    // Signed ExpectedSet page (fleet) granting `ticket` to device i.
    Bytes expected_page(unsigned i, uint64_t generation, const Bytes &ticket, uint64_t revision, bool allowed = true) {
        Sha256Digest grant{};
        LM_CHECK_OK(sec::sha256(view(ticket), grant));
        std::array<uint8_t, 512> buf{};
        wire::CborWriter w{MutByteView{buf}};
        w.array(4);
        w.uint(0);
        w.uint(1);
        w.bytes(ByteView{grant}); // set-hash: one digest per revision (not checked by the ledger)
        w.array(1);
        w.array(4);
        w.bytes(id(i).view());
        w.uint(generation);
        w.bytes(ByteView{grant});
        w.boolean(allowed);
        LM_CHECK_OK(w.finish());
        member::Envelope env;
        env.type = member::k_type_expected_set;
        env.domain = net.domain;
        env.revision = revision;
        env.issuer = net.fleet.trust().key_id;
        env.request.bytes[0] = static_cast<uint8_t>(revision);
        return net.fleet.sign(env, w.written());
    }
    Status install_expected(const Bytes &page) {
        lm_operation_id_t op = 0;
        const lm_status_t s = install(0, 5, page, op);
        if (s != LM_STATUS_OK) {
            return static_cast<Status>(s);
        }
        return wait_operation(0, op, 2000) == 0 ? Status::Ok : Status::Conflict;
    }
    // The operation's own result (the status in its event; 0xFFFF: no result within the wait).
    uint32_t install_expected_result(const Bytes &page) {
        lm_operation_id_t op = 0;
        const lm_status_t s = install(0, 5, page, op);
        return s != LM_STATUS_OK ? s : wait_operation(0, op, 2000);
    }
    // Any fleet-signed ExpectedSet page: `devices` are granted generation 1 with a grant hash derived from `tag`.
    Bytes page(uint64_t revision, uint8_t index, uint8_t pages, uint8_t set_tag, const std::vector<unsigned> &devices,
               uint8_t tag = 1) {
        Sha256Digest set_hash{};
        set_hash.fill(set_tag);
        std::array<uint8_t, 1024> buf{};
        wire::CborWriter w{MutByteView{buf}};
        w.array(4);
        w.uint(index);
        w.uint(pages);
        w.bytes(ByteView{set_hash});
        w.array(devices.size());
        for (unsigned d : devices) {
            Sha256Digest g{};
            g.fill(static_cast<uint8_t>(tag + d));
            w.array(4);
            w.bytes(id(d).view());
            w.uint(1);
            w.bytes(ByteView{g});
            w.boolean(true);
        }
        LM_CHECK_OK(w.finish());
        member::Envelope env;
        env.type = member::k_type_expected_set;
        env.domain = net.domain;
        env.revision = revision;
        env.issuer = net.fleet.trust().key_id;
        env.request.bytes[0] = static_cast<uint8_t>(revision + index + tag);
        return net.fleet.sign(env, w.written());
    }
    bool expected(unsigned i) {
        const root::Entry *e = ledger().find(id(i));
        return e != nullptr && e->state == root::EntryState::Expected;
    }
    // Ticket + expected entry for device i, ready for a preapproved join.
    Bytes grant(unsigned i, uint64_t generation, uint64_t revision) {
        const Bytes t = ticket_for(i, generation);
        LM_CHECK_OK(install_ticket(i, t));
        LM_CHECK_OK(install_expected(expected_page(i, generation, t, revision)));
        tickets[i] = t;
        return t;
    }

    uint64_t join(unsigned i, uint8_t req_seed, uint32_t mode = LM_JOIN_NEW, lm_status_t *st = nullptr,
                  uint32_t budget_ms = 0) {
        lm_join_request_t r{};
        r.struct_size = sizeof(r);
        r.abi_version = LM_ABI_VERSION;
        r.request_id = rid(req_seed);
        r.mode = mode;
        r.search_budget_ms = budget_ms;
        lm_operation_id_t op = 0;
        const lm_status_t s = lm_join(ctx(i), &r, &op);
        if (st != nullptr) {
            *st = s;
        }
        return s == LM_STATUS_OK ? op : 0;
    }
    // Grants and joins device i; waits for the operation; returns its reason (0 = OK).
    uint32_t join_device(unsigned i, uint8_t req, uint64_t gen, uint64_t revision) {
        grant(i, gen, revision);
        lm_status_t st = 0;
        const uint64_t op = join(i, req, LM_JOIN_NEW, &st);
        LM_CHECK_EQ(st, LM_STATUS_OK);
        return op == 0 ? 0xFFFF : wait_operation(i, op, 60000);
    }
    lm_membership_t membership(unsigned i) {
        lm_membership_t m{};
        m.struct_size = sizeof(m);
        m.abi_version = LM_ABI_VERSION;
        LM_CHECK_EQ(lm_membership_get(ctx(i), &m), LM_STATUS_OK);
        return m;
    }
    lm_operation_t request_status(unsigned i, uint8_t req_seed) {
        lm_operation_t o{};
        o.struct_size = sizeof(o);
        o.abi_version = LM_ABI_VERSION;
        const lm_request_id_t r = rid(req_seed);
        LM_CHECK_EQ(lm_get_request(ctx(i), &r, &o), LM_STATUS_OK);
        return o;
    }
    bool linked(unsigned a, unsigned b) {
        const link::Neighbor *x = eng(a).link().neighbors().find_device(id(b));
        const link::Neighbor *y = eng(b).link().neighbors().find_device(id(a));
        return x != nullptr && y != nullptr && x->cur.active && y->cur.active && x->cur.ctx_hash == y->cur.ctx_hash;
    }
    Status decide(uint8_t req_seed, bool approve) {
        root::JoinDecision d;
        const lm_request_id_t r = rid(req_seed);
        std::memcpy(d.request.bytes.data(), r.bytes, 16);
        d.approve = approve;
        Command cmd;
        cmd.kind = CommandKind::RootJoinDecide;
        cmd.request = &d;
        cmd.request_size = sizeof(d);
        return node(0).owner_call.call(cmd).status;
    }
    std::size_t join_only_neighbors(unsigned i) {
        std::size_t n = 0;
        eng(i).link().neighbors().for_each([&](Handle, link::Neighbor &nb) { n += nb.join_only ? 1 : 0; });
        return n;
    }

    fleet::Network net;
    World world;
    std::vector<fleet::NodeKit> kits;
    std::vector<std::vector<Ev>> events;
    std::vector<Bytes> tickets;
};

const char *entry_name(root::EntryState s) {
    static const char *const k[] = {"free", "expected", "prepared", "active", "left", "aborted", "blocked"};
    return k[static_cast<unsigned>(s)];
}

} // namespace

// ---------------------------------------------------------------------------------------------
// The centrepiece: 1-hop preapproved Join, both sides commit, without a Host.
// ---------------------------------------------------------------------------------------------
LM_TEST("T07 J-join: preapproved 1-hop Join without Host, both sides commit PREPARE->STORED->COMMIT->ACTIVE") {
    JNet n(2);
    LM_CHECK_EQ(n.membership(1).state, static_cast<uint32_t>(LM_UNASSIGNED));
    n.grant(1, 1, 1);
    lm_status_t st = 0;
    const uint64_t op = n.join(1, 0x10, LM_JOIN_NEW, &st);
    LM_CHECK_EQ(st, LM_STATUS_OK);
    LM_CHECK(op != 0);
    LM_CHECK_EQ(n.wait_operation(1, op, 20000), 0u); // the operation finished with status OK
    const lm_membership_t m = n.membership(1);
    LM_CHECK_EQ(m.state, static_cast<uint32_t>(LM_ACTIVE));
    LM_CHECK_EQ(m.assignment_generation, 1ull);
    LM_CHECK_EQ(m.membership_generation, 1ull);
    LM_CHECK(std::memcmp(m.domain.bytes, n.net.domain.bytes.data(), 16) == 0);
    // Root ledger: one Active, confirmed entry at address 2, holding the same request and generations.
    const root::Entry *e = n.ledger().find(n.id(1));
    LM_CHECK(e != nullptr);
    if (e != nullptr) {
        LM_CHECK(e->state == root::EntryState::Active);
        LM_CHECK(e->confirmed);
        LM_CHECK_EQ(e->address.value(), 2u);
        LM_CHECK_EQ(e->membership, 1ull);
    }
    // Evidence: each stage is a separate fact and all five are present.
    const lm_operation_t o = n.request_status(1, 0x10);
    LM_CHECK_EQ(o.outcome, static_cast<uint32_t>(LM_OUTCOME_APPLIED));
    LM_CHECK_EQ(o.evidence_bits, member::kEvRequested | member::kEvRootStored | member::kEvDeviceStored |
                                     member::kEvDeviceActive | member::kEvRootConfirmed);
    // The credential is durable: after a power cut the device is ACTIVE from its own record.
    n.run_ms(5000);
    LM_CHECK_EQ(n.join_only_neighbors(0), 0u); // the JOIN_ONLY session is gone, never an ordinary neighbour
    LM_CHECK(n.linked(0, 1));                  // the first ordinary session follows by itself
    n.node(1).power_cut();
    n.node(1).store.power_restore();
    n.boot(1);
    n.run_ms(100);
    LM_CHECK_EQ(n.membership(1).state, static_cast<uint32_t>(LM_ACTIVE));
    LM_CHECK(n.eng(1).identity().is_member());
    // Nothing of this needed a Host: the root's decisions came from the signed ticket and the expected entry.
    LM_CHECK_EQ(n.ledger().stats().refused, 0ull);
    // Idle afterwards: no join/ledger timer keeps either owner awake (docs/20 §11, no polling).
    n.run_ms(2000);
    const uint64_t steps0 = n.eng(0).stats().steps;
    const uint64_t steps1 = n.eng(1).stats().steps;
    n.run_ms(600000);
    LM_CHECK_EQ(n.eng(0).stats().steps, steps0);
    LM_CHECK_EQ(n.eng(1).stats().steps, steps1);
}

LM_TEST("J05 resume: an ACTIVE member restarts, links again without approval; the ledger does not change") {
    JNet n(2);
    LM_CHECK_EQ(n.join_device(1, 0x20, 1, 1), 0u);
    n.run_ms(31000); // one full handshake per peer per 30 s (docs/06 §8): the device is back after that
    LM_CHECK(n.linked(0, 1));
    const uint64_t prepared = n.ledger().stats().prepared;
    const uint64_t writes = n.node(0).store.slot_writes();
    // Cold boot of the device: identity + ACTIVE record come back, the link session does not (docs/06 §6).
    n.node(1).power_cut();
    n.node(1).store.power_restore();
    n.boot(1);
    n.run_ms(100);
    LM_CHECK_EQ(n.membership(1).state, static_cast<uint32_t>(LM_ACTIVE));
    LM_CHECK(n.eng(1).link().neighbors().find_device(n.id(0)) == nullptr);
    lm_status_t st = 0;
    const uint64_t op = n.join(1, 0x21, LM_JOIN_RESUME, &st);
    LM_CHECK_EQ(st, LM_STATUS_OK);
    LM_CHECK_EQ(n.wait_operation(1, op, 20000), 0u);
    n.run_ms(500);
    LM_CHECK(n.linked(0, 1));
    LM_CHECK_EQ(n.ledger().stats().prepared, prepared); // no second reservation
    LM_CHECK_EQ(n.node(0).store.slot_writes(), writes);  // the root wrote nothing for a resume
    LM_CHECK_EQ(n.membership(1).membership_generation, 1ull);
    // A member cannot ask for a new join (CONFLICT); a fresh join needs leave first.
    LM_CHECK_EQ(n.join(1, 0x22, LM_JOIN_NEW, &st), 0ull);
    LM_CHECK_EQ(st, LM_STATUS_CONFLICT);
}

namespace {
// A send that cannot finish by itself: to a device nobody knows (no route), RECEIVED + DURABLE without a deadline.
lm_operation_id_t open_send(JNet &n, unsigned i, lm_status_t want = LM_STATUS_OK) {
    lm_send_request_t rq{};
    rq.struct_size = sizeof(rq);
    rq.abi_version = LM_ABI_VERSION;
    rq.destination.kind = LM_DEST_NODE;
    std::memset(rq.destination.node.bytes, 0x5A, 32);
    rq.app_port = 100;
    rq.delivery = LM_RECEIVED;
    rq.storage = LM_DURABLE;
    rq.priority = LM_PRIORITY_NORMAL;
    rq.queue_mode = LM_FIFO;
    const std::array<uint8_t, 8> payload{1, 2, 3, 4, 5, 6, 7, 8};
    lm_operation_id_t op = 0;
    LM_CHECK_EQ(lm_send(n.ctx(i), &rq, payload.data(), payload.size(), &op), want);
    n.run_ms(100);
    return op;
}
lm_operation_t send_status(JNet &n, unsigned i, lm_operation_id_t op) {
    lm_operation_t o{};
    o.struct_size = sizeof(o);
    o.abi_version = LM_ABI_VERSION;
    LM_CHECK_EQ(lm_get_operation(n.ctx(i), op, &o), LM_STATUS_OK);
    return o;
}
} // namespace

// FIX8 (H10): the membership hooks are the production wiring (Engine), not a test's: DRAIN waits for the open sends,
// refuses new ones meanwhile, and a leave that commits ends every open send (never PENDING forever).
LM_TEST("M06 leave: IMMEDIATE erases membership durably; DRAIN never turns into IMMEDIATE by itself; re-join uses a new generation") {
    JNet n(2);
    LM_CHECK_EQ(n.join_device(1, 0x30, 1, 1), 0u);
    n.run_ms(6000);
    LM_CHECK(n.linked(0, 1));
    // DRAIN with an open send that never settles: explicit failure at the deadline, still ACTIVE, the send untouched.
    const lm_operation_id_t s1 = open_send(n, 1);
    lm_operation_id_t op = 0;
    LM_CHECK_EQ(lm_leave(n.ctx(1), LM_LEAVE_DRAIN, 1500, &op), LM_STATUS_OK);
    LM_CHECK_EQ(n.membership(1).state, static_cast<uint32_t>(LM_LEAVING));
    (void)open_send(n, 1, LM_STATUS_BUSY); // no new send while the device drains
    LM_CHECK_EQ(n.wait_operation(1, op, 5000), static_cast<uint32_t>(Status::DeadlineUnreachable));
    LM_CHECK_EQ(n.membership(1).state, static_cast<uint32_t>(LM_ACTIVE));
    LM_CHECK(n.ledger().find(n.id(1))->state == root::EntryState::Active);
    LM_CHECK_EQ(send_status(n, 1, s1).outcome, static_cast<uint32_t>(LM_OUTCOME_PENDING));
    const lm_operation_id_t s2 = open_send(n, 1); // the failed drain gave sending back
    // Once nothing is open (both cancelled before they left) the same DRAIN succeeds.
    LM_CHECK_EQ(lm_cancel(n.ctx(1), s1), LM_STATUS_OK);
    LM_CHECK_EQ(lm_cancel(n.ctx(1), s2), LM_STATUS_OK);
    LM_CHECK(n.run_until([&] {
        return send_status(n, 1, s1).phase == LM_PHASE_FINAL && send_status(n, 1, s2).phase == LM_PHASE_FINAL;
    }, 2000));
    LM_CHECK_EQ(lm_leave(n.ctx(1), LM_LEAVE_DRAIN, 5000, &op), LM_STATUS_OK);
    LM_CHECK_EQ(n.wait_operation(1, op, 5000), 0u);
    LM_CHECK_EQ(n.membership(1).state, static_cast<uint32_t>(LM_UNASSIGNED));
    n.run_ms(300);
    LM_CHECK(n.ledger().find(n.id(1))->state == root::EntryState::Left);
    LM_CHECK(n.eng(0).link().neighbors().find_device(n.id(1)) == nullptr); // root closed its sessions
    // Durable: a reboot stays unassigned (the tombstone wins over the old ACTIVE record).
    n.reboot(1);
    LM_CHECK_EQ(n.membership(1).state, static_cast<uint32_t>(LM_UNASSIGNED));
    LM_CHECK(!n.eng(1).identity().is_member());
    n.run_ms(31000); // one full handshake per peer per 30 s (docs/06 §8) applies to the root too
    // The consumed generation stays consumed (floors); a fresh grant with a higher generation joins
    // again with membership 2, never reusing 1, and keeps its address.
    LM_CHECK(n.eng(0).identity().floors().count() >= 1);
    LM_CHECK_EQ(n.join_device(1, 0x31, 2, 2), 0u);
    const lm_membership_t m = n.membership(1);
    LM_CHECK_EQ(m.state, static_cast<uint32_t>(LM_ACTIVE));
    LM_CHECK_EQ(m.membership_generation, 2ull);
    LM_CHECK_EQ(m.assignment_generation, 2ull);
    LM_CHECK_EQ(n.ledger().find(n.id(1))->address.value(), 2u);
    // IMMEDIATE leave right away: the open send ends with the leave (it never left: CANCELLED_NOT_SENT).
    n.run_ms(6000);
    const lm_operation_id_t s3 = open_send(n, 1);
    LM_CHECK_EQ(lm_leave(n.ctx(1), LM_LEAVE_IMMEDIATE, 0, &op), LM_STATUS_OK);
    LM_CHECK_EQ(n.wait_operation(1, op, 5000), 0u);
    LM_CHECK_EQ(n.membership(1).state, static_cast<uint32_t>(LM_UNASSIGNED));
    const lm_operation_t o3 = send_status(n, 1, s3);
    LM_CHECK_EQ(o3.phase, static_cast<uint32_t>(LM_PHASE_FINAL)); // PENDING forever on 8668c69
    LM_CHECK(o3.outcome == LM_OUTCOME_CANCELLED_NOT_SENT || o3.outcome == LM_OUTCOME_INDETERMINATE);
    { // FIX9-D9: the operation lm_leave returned is queryable after its event (lifecycle ops are retained, not NOT_FOUND)
        lm_operation_t lo{};
        lo.struct_size = sizeof(lo);
        lo.abi_version = LM_ABI_VERSION;
        LM_CHECK_EQ(lm_get_operation(n.ctx(1), op, &lo), LM_STATUS_OK);
        LM_CHECK_EQ(lo.phase, 3u);
        LM_CHECK_EQ(lo.outcome, static_cast<uint32_t>(LM_OUTCOME_APPLIED));
    }
    // Leave of a non-member is NOT_FOUND (nothing to leave).
    LM_CHECK_EQ(lm_leave(n.ctx(1), LM_LEAVE_IMMEDIATE, 0, &op), LM_STATUS_NOT_FOUND);
}

// FIX8 (M10): the join mode is part of the root's policy: lm_policy_set changes it (compare-and-set on the one policy
// revision), the change is durable before its operation ends, a restart keeps it, and a CLOSED root admits nobody.
LM_TEST("J04 FIX8 sim: lm_policy_set sets the join mode durably; CLOSED answers no joiner; a restart keeps it") {
    JNet n(2);
    auto get = [&](lm_policy_t &p) {
        p = lm_policy_t{};
        p.struct_size = sizeof(p);
        p.abi_version = LM_ABI_VERSION;
        return lm_policy_get(n.ctx(0), &p);
    };
    lm_policy_t p;
    LM_CHECK_EQ(get(p), LM_STATUS_OK);
    const uint64_t r0 = p.revision;
    lm_policy_t closed = p;
    closed.join_mode = 0;
    lm_operation_id_t op = 0;
    LM_CHECK_EQ(lm_policy_set(n.ctx(0), &closed, r0 + 1, &op), LM_STATUS_CONFLICT); // stale revision
    LM_CHECK_EQ(lm_policy_set(n.ctx(0), &closed, r0, &op), LM_STATUS_OK);       // UNSUPPORTED on 8668c69
    LM_CHECK(op != 0);
    LM_CHECK_EQ(n.wait_operation(0, op, 2000), 0u); // durable
    LM_CHECK_EQ(get(p), LM_STATUS_OK);
    LM_CHECK_EQ(p.join_mode, 0u);
    LM_CHECK_EQ(p.revision, r0 + 1);
    // A granted device finds no root to ask: a CLOSED root answers no hello.
    n.grant(1, 1, 1);
    uint64_t jop = n.join(1, 0x50, LM_JOIN_NEW, nullptr, 3000);
    LM_CHECK(jop != 0);
    LM_CHECK(n.wait_operation(1, jop, 20000) != 0u);
    LM_CHECK(!n.eng(1).identity().is_member());
    // A restart keeps the mode (no bench setter this time: the policy record).
    n.node(0).power_cut();
    n.node(0).store.power_restore();
    n.boot(0);
    n.run_ms(50);
    n.root_loaded();
    LM_CHECK_EQ(get(p), LM_STATUS_OK);
    LM_CHECK_EQ(p.join_mode, 0u);
    LM_CHECK_EQ(p.revision, r0 + 1);
    // Preapproved again: the device joins with the grant it holds.
    lm_policy_t pre = p;
    pre.join_mode = 2;
    LM_CHECK_EQ(lm_policy_set(n.ctx(0), &pre, r0 + 1, &op), LM_STATUS_OK);
    LM_CHECK_EQ(n.wait_operation(0, op, 2000), 0u);
    jop = n.join(1, 0x51);
    LM_CHECK(jop != 0);
    LM_CHECK_EQ(n.wait_operation(1, jop, 60000), 0u);
    LM_CHECK(n.eng(1).identity().is_member());
}

// ---------------------------------------------------------------------------------------------
// Refusals and policy
// ---------------------------------------------------------------------------------------------
LM_TEST("J06 same request_id with other content is CONFLICT and never reserves a second address") {
    JNet n(2);
    n.grant(1, 1, 1);
    const uint64_t op1 = n.join(1, 0x40);
    LM_CHECK(op1 != 0);
    // Cut the link the moment the root reserved (PREPARED): the device never sees the JoinPrepare.
    LM_CHECK(n.run_until(
        [&] {
            const root::Entry *e = n.ledger().find(n.id(1));
            return e != nullptr && e->state == root::EntryState::Prepared;
        },
        10000, 100));
    n.set_link(0, 1, false);
    n.run_ms(3000);
    n.reboot(1); // the device restarts: it stored nothing (it never saw the JoinPrepare)
    LM_CHECK(!n.mem(1).prepared_record());
    const root::Entry *e = n.ledger().find(n.id(1));
    LM_CHECK(e != nullptr && e->state == root::EntryState::Prepared);
    const uint16_t address = e != nullptr ? e->address.value() : 0;
    const uint64_t membership = e != nullptr ? e->membership : 0;
    // The same request id again, but a different ticket (other grant id): different content.
    n.set_link(0, 1, true);
    n.run_ms(31000);
    const Bytes other = n.ticket_for(1, 1);
    LM_CHECK_OK(n.install_ticket(1, other));
    lm_status_t st = 0;
    const uint64_t op2 = n.join(1, 0x40, LM_JOIN_NEW, &st);
    LM_CHECK_EQ(st, LM_STATUS_OK);
    LM_CHECK_EQ(n.wait_operation(1, op2, 30000), static_cast<uint32_t>(Status::Conflict));
    LM_CHECK_EQ(n.ledger().stats().conflicts, 1ull);
    LM_CHECK_EQ(n.ledger().count(root::EntryState::Prepared), 1u); // still one reservation
    e = n.ledger().find(n.id(1));
    LM_CHECK(e != nullptr && e->address.value() == address && e->membership == membership);
    LM_CHECK_EQ(n.membership(1).state, static_cast<uint32_t>(LM_UNASSIGNED));
}

LM_TEST("J04 external approval: pending without a decision, no automatic approve; approve completes; timeout is retryable") {
    JNet n(3);
    n.eng(0).ledger().set_join_mode(root::JoinMode::External);
    const Bytes t1 = n.ticket_for(1, 1);
    LM_CHECK_OK(n.install_ticket(1, t1));
    LM_CHECK_OK(n.install_ticket(2, n.ticket_for(2, 1)));
    lm_status_t st = 0;
    const uint64_t op = n.join(1, 0x80, LM_JOIN_NEW, &st);
    LM_CHECK_EQ(st, LM_STATUS_OK);
    LM_CHECK(n.run_until([&] { return n.has_event(0, LM_EVENT_MEMBERSHIP, LM_APPROVAL_PENDING); }, 10000, 5000));
    LM_CHECK_EQ(n.membership(1).state, static_cast<uint32_t>(LM_APPROVAL_PENDING));
    n.run_ms(120000); // two minutes without the operator: still pending, nothing reserved, nothing approved
    LM_CHECK_EQ(n.membership(1).state, static_cast<uint32_t>(LM_APPROVAL_PENDING));
    LM_CHECK(n.ledger().find(n.id(1)) == nullptr || n.ledger().find(n.id(1))->state != root::EntryState::Active);
    LM_CHECK_EQ(n.ledger().stats().prepared, 0ull);
    LM_CHECK_EQ(n.decide(0x7F, true), Status::NotFound); // a decision for an unknown request
    LM_CHECK_EQ(n.decide(0x80, true), Status::Ok);
    LM_CHECK_EQ(n.wait_operation(1, op, 30000), 0u);
    LM_CHECK_EQ(n.membership(1).state, static_cast<uint32_t>(LM_ACTIVE));
    // A second device whose request nobody decides: refused with EXPIRED after 300 s, and can ask again.
    const uint64_t op2 = n.join(2, 0x81, LM_JOIN_NEW, &st);
    LM_CHECK_EQ(st, LM_STATUS_OK);
    LM_CHECK_EQ(n.wait_operation(2, op2, 400000), static_cast<uint32_t>(Status::Expired));
    LM_CHECK_EQ(n.request_status(2, 0x81).outcome, static_cast<uint32_t>(LM_OUTCOME_EXPIRED));
    LM_CHECK_EQ(n.membership(2).state, static_cast<uint32_t>(LM_UNASSIGNED));
    n.run_ms(31000);
    const uint64_t op3 = n.join(2, 0x82, LM_JOIN_NEW, &st);
    LM_CHECK_EQ(st, LM_STATUS_OK);
    LM_CHECK(n.run_until(
        [&] {
            return n.ledger().txn_state(0) == root::Ledger::TxnState::Pending ||
                   n.ledger().txn_state(1) == root::Ledger::TxnState::Pending;
        },
        10000, 5000));
    LM_CHECK_EQ(n.decide(0x82, false), Status::Ok); // the operator refuses
    LM_CHECK_EQ(n.wait_operation(2, op3, 30000), static_cast<uint32_t>(Status::AuthRejected));
}

LM_TEST("LC05 sim: a pending external request, the device restarts (deep sleep) and asks again with the same request id: one approval, one reservation") {
    JNet n(2);
    n.eng(0).ledger().set_join_mode(root::JoinMode::External);
    LM_CHECK_OK(n.install_ticket(1, n.ticket_for(1, 1)));
    lm_status_t st = 0;
    (void)n.join(1, 0x80, LM_JOIN_NEW, &st);
    LM_CHECK_EQ(st, LM_STATUS_OK);
    auto pending = [&] {
        return n.ledger().txn_state(0) == root::Ledger::TxnState::Pending || n.ledger().txn_state(1) == root::Ledger::TxnState::Pending;
    };
    LM_CHECK(n.run_until(pending, 10000, 5000));
    n.reboot(1); // the application sleeps: RAM is gone, the ticket and the identity are in Flash
    n.run_ms(31000); // (a full handshake with one peer is allowed once per 30 s)
    LM_CHECK_EQ(n.ledger().stats().prepared, 0ull); // nothing was reserved meanwhile
    const uint64_t op = n.join(1, 0x80, LM_JOIN_NEW, &st, 30000);
    LM_CHECK_EQ(st, LM_STATUS_OK);
    LM_CHECK(n.run_until([&] { return n.membership(1).state == static_cast<uint32_t>(LM_APPROVAL_PENDING); }, 25000, 5000));
    LM_CHECK(n.run_until(pending, 5000, 5000));
    LM_CHECK_EQ(n.decide(0x80, true), Status::Ok);
    LM_CHECK_EQ(n.wait_operation(1, op, 30000), 0u);
    LM_CHECK_EQ(n.membership(1).state, static_cast<uint32_t>(LM_ACTIVE));
    LM_CHECK_EQ(n.ledger().stats().prepared, 1ull);
    LM_CHECK_EQ(n.ledger().count(root::EntryState::Active), 1u);
}

LM_TEST("J02 policy: closed root offers nothing; preapproved refuses an unexpected device; foreign tickets never reach the root") {
    JNet n(2);
    const Bytes t = n.ticket_for(1, 1);
    LM_CHECK_OK(n.install_ticket(1, t));
    // Closed: no offer, the search budget is spent (EXPIRED, not a device fault).
    n.eng(0).ledger().set_join_mode(root::JoinMode::Closed);
    lm_status_t st = 0;
    uint64_t op = n.join(1, 0x90, LM_JOIN_NEW, &st, 3000);
    LM_CHECK_EQ(st, LM_STATUS_OK);
    LM_CHECK_EQ(n.wait_operation(1, op, 10000), static_cast<uint32_t>(Status::Expired));
    LM_CHECK_EQ(n.ledger().stats().requests, 0ull);
    // Preapproved without an expected entry: refused NOT_EXPECTED (a hint, not a permanent verdict).
    n.eng(0).ledger().set_join_mode(root::JoinMode::Preapproved);
    // S11: the refusal is reported (membership event) and the search holds and asks again inside its budget;
    // when the budget ends the operation is EXPIRED (not a verdict on the device) and a new request starts fresh.
    op = n.join(1, 0x91, LM_JOIN_NEW, &st, 5000);
    LM_CHECK_EQ(st, LM_STATUS_OK);
    LM_CHECK_EQ(n.wait_operation(1, op, 30000), static_cast<uint32_t>(Status::Expired));
    LM_CHECK(n.has_event(1, LM_EVENT_MEMBERSHIP, static_cast<uint32_t>(Status::NotFound)));
    LM_CHECK_EQ(n.membership(1).state, static_cast<uint32_t>(LM_UNASSIGNED));
    // A ticket of another fleet or for another device is refused when it is installed.
    fleet::Network rogue(77, "rogue");
    const Bytes foreign = rogue.fleet.ticket(n.kits[1].kit, DomainId{}, rogue.domain, rogue.delegation_cose, 0, 1);
    LM_CHECK_EQ(n.install_ticket(1, foreign), Status::AuthRejected);
    const Bytes other_device = n.net.fleet.ticket(n.kits[0].kit, DomainId{}, n.net.domain, n.net.delegation_cose, 0, 1);
    LM_CHECK_EQ(n.install_ticket(1, other_device), Status::AuthRejected);
    // A ticket for another domain than the root's: the device never presents it to this root.
    DomainId elsewhere;
    elsewhere.bytes[0] = 0xEE;
    const Bytes wrong_domain = n.net.fleet.ticket(n.kits[1].kit, DomainId{}, elsewhere, n.net.delegation_cose, 0, 1);
    LM_CHECK_OK(n.install_ticket(1, wrong_domain));
    n.run_ms(31000);
    op = n.join(1, 0x92, LM_JOIN_NEW, &st);
    LM_CHECK_EQ(n.wait_operation(1, op, 30000), static_cast<uint32_t>(Status::NetworkMismatch)); // names another root
    LM_CHECK_EQ(n.ledger().stats().requests, 1ull); // only the NOT_EXPECTED attempt ever reached the root
}

// ---------------------------------------------------------------------------------------------
// One-sided loss and convergence (LC06, J07)
// ---------------------------------------------------------------------------------------------
LM_TEST("J07/LC06 JOIN_ACTIVE lost: the device is ACTIVE, the root stays unconfirmed, the next link converges by request evidence") {
    JNet n(2);
    n.grant(1, 1, 1);
    const uint64_t op = n.join(1, 0x50);
    // The device commits ACTIVE, then the medium goes away before JOIN_ACTIVE can be delivered.
    LM_CHECK(n.run_until([&] { return n.eng(1).identity().is_member(); }, 10000, 50));
    n.set_link(0, 1, false);
    LM_CHECK_EQ(n.wait_operation(1, op, 30000), static_cast<uint32_t>(Status::Expired));
    const lm_operation_t o = n.request_status(1, 0x50);
    LM_CHECK_EQ(o.outcome, static_cast<uint32_t>(LM_OUTCOME_INDETERMINATE)); // active_unconfirmed is not "complete"
    LM_CHECK(o.evidence_bits & member::kEvDeviceActive);
    LM_CHECK(!(o.evidence_bits & member::kEvRootConfirmed));
    LM_CHECK_EQ(n.membership(1).state, static_cast<uint32_t>(LM_ACTIVE));
    const root::Entry *e = n.ledger().find(n.id(1));
    LM_CHECK(e != nullptr && e->state == root::EntryState::Active && !e->confirmed); // root: active, unconfirmed
    LM_CHECK(n.mem(1).confirm_pending());                                           // and the device knows it owes it
    // Medium back: an ordinary link session repeats the evidence; the root confirms exactly once.
    n.set_link(0, 1, true);
    n.run_ms(31000);
    lm_status_t st = 0;
    const uint64_t rop = n.join(1, 0x51, LM_JOIN_RESUME, &st);
    LM_CHECK_EQ(st, LM_STATUS_OK);
    LM_CHECK_EQ(n.wait_operation(1, rop, 30000), 0u);
    LM_CHECK(n.run_until([&] { return !n.mem(1).confirm_pending(); }, 10000, 5000));
    e = n.ledger().find(n.id(1));
    LM_CHECK(e != nullptr && e->state == root::EntryState::Active && e->confirmed);
    LM_CHECK_EQ(n.ledger().stats().confirmed, 1ull);
    LM_CHECK_EQ(n.ledger().count(root::EntryState::Active), 1u); // no false second membership
    LM_CHECK_EQ(n.membership(1).membership_generation, 1ull);
    // The confirmation state survives a device power cut (it is a durable record, not RAM).
    n.run_ms(1000);
    n.reboot(1);
    LM_CHECK(!n.mem(1).confirm_pending());
}

LM_TEST("LC06 JOIN_COMMIT lost: root ACTIVE, device only PREPARED; a repeated request (same id, same hash) converges") {
    JNet n(2);
    n.grant(1, 1, 1);
    const uint64_t op = n.join(1, 0x52);
    // The moment the root committed ACTIVE the medium goes away: JOIN_COMMIT never arrives.
    LM_CHECK(n.run_until(
        [&] {
            const root::Entry *e = n.ledger().find(n.id(1));
            return e != nullptr && e->state == root::EntryState::Active;
        },
        10000, 50));
    n.set_link(0, 1, false);
    // The device keeps waiting for JoinCommit until its reservation (120 s) is over: then EXPIRED, PREPARED stays.
    LM_CHECK_EQ(n.wait_operation(1, op, 130000), static_cast<uint32_t>(Status::Expired));
    LM_CHECK(!n.eng(1).identity().is_member()); // PREPARED is not ACTIVE: no ordinary traffic allowed
    LM_CHECK(n.mem(1).prepared_record());
    LM_CHECK_EQ(n.membership(1).state, static_cast<uint32_t>(LM_PREPARED));
    const root::Entry *e = n.ledger().find(n.id(1));
    LM_CHECK(e != nullptr && e->state == root::EntryState::Active && !e->confirmed);
    // Back online: the same request again; the root repeats its JoinCommit (no second address).
    n.set_link(0, 1, true);
    n.run_ms(31000);
    lm_status_t st = 0;
    LM_CHECK_EQ(n.join(1, 0x99, LM_JOIN_NEW, &st), 0ull); // another id while one is outstanding: CONFLICT
    LM_CHECK_EQ(st, LM_STATUS_CONFLICT);
    const uint64_t op2 = n.join(1, 0x52, LM_JOIN_NEW, &st);
    LM_CHECK_EQ(st, LM_STATUS_OK);
    LM_CHECK_EQ(n.wait_operation(1, op2, 60000), 0u);
    LM_CHECK_EQ(n.membership(1).state, static_cast<uint32_t>(LM_ACTIVE));
    e = n.ledger().find(n.id(1));
    LM_CHECK(e != nullptr && e->confirmed && e->address.value() == 2u);
    LM_CHECK_EQ(n.ledger().stats().prepared, 1ull);
    LM_CHECK_EQ(n.ledger().count(root::EntryState::Active), 1u);
}

// ---------------------------------------------------------------------------------------------
// R09: a short address belongs to one device at a time
// ---------------------------------------------------------------------------------------------
namespace {

void commit_record(SimStore &store, uint16_t id, uint8_t state, ByteView payload) {
    auto job = std::make_unique<store::RecordJob>();
    std::memcpy(job->payload.data(), payload.data(), payload.size());
    job->op = store::RecordJob::Op::Commit;
    job->id = id;
    job->state = state;
    job->payload_len = static_cast<uint32_t>(payload.size());
    LM_CHECK_OK(store::record_commit(store, *job));
}

// A ledger record as documented in src/root/ledger_internal.hpp: confirmed u8 | assignment | membership |
// consumed | device | request 16 | hash 32 (no credential: a departed/foreign member of the table). A crafted
// Active/Left entry consumed its assignment (SEC-D4).
void craft_entry(SimStore &store, std::size_t slot, const DeviceId &dev, root::EntryState st, uint64_t assignment,
                 uint64_t membership) {
    std::array<uint8_t, 105> p{};
    Writer w{MutByteView{p}};
    w.u8(1);
    w.u64be(assignment);
    w.u64be(membership);
    w.u64be(st == root::EntryState::Active || st == root::EntryState::Left ? assignment : 0);
    w.bytes(dev.view());
    w.zeros(16 + 32);
    LM_CHECK_OK(w.finish());
    commit_record(store, static_cast<uint16_t>(root::k_rec_ledger_base + slot), static_cast<uint8_t>(st),
                  ByteView{p.data(), w.size()});
}

} // namespace

LM_TEST("R09 short address reuse: a departed device's address goes to another device; the old credential and session are refused") {
    JNet n(3, 41, false);
    for (std::size_t s = 1; s < root::k_ledger_slots; ++s) { // 63 other members: the table is full but slot 0
        DeviceId d;
        d.bytes.fill(static_cast<uint8_t>(s));
        d.bytes[1] = 0xF0;
        craft_entry(n.node(0).store, s, d, root::EntryState::Active, 1, 1);
    }
    n.start_all();
    LM_CHECK_EQ(n.ledger().count(root::EntryState::Active), 63u);
    LM_CHECK_EQ(n.join_device(1, 0x70, 1, 1), 0u);
    LM_CHECK_EQ(n.ledger().find(n.id(1))->address.value(), 2u);
    n.run_ms(6000);
    const ByteView mc = n.eng(1).identity().member_cose();
    const Bytes old_mc(mc.begin(), mc.end());
    lm_operation_id_t lop = 0;
    LM_CHECK_EQ(lm_leave(n.ctx(1), LM_LEAVE_IMMEDIATE, 0, &lop), LM_STATUS_OK);
    LM_CHECK_EQ(n.wait_operation(1, lop, 5000), 0u);
    n.run_ms(31000);
    // The table is full; device B takes A's slot (its old credential is below the floor) and A's address.
    LM_CHECK_EQ(n.join_device(2, 0x71, 1, 2), 0u);
    LM_CHECK_EQ(n.ledger().find(n.id(2))->address.value(), 2u);
    LM_CHECK(n.ledger().find(n.id(1)) == nullptr);
    LM_CHECK_EQ(n.membership(2).state, static_cast<uint32_t>(LM_ACTIVE));
    // A stolen copy of A's old credential (on a device that lacks the floors record) cannot link.
    n.node(1).power_cut();
    n.node(1).store.power_restore();
    commit_record(n.node(1).store, store::rec::membership, member::k_membership_active, view(old_mc));
    const member::Floors none;
    std::array<uint8_t, 8> fbuf{};
    std::size_t flen = 0;
    LM_CHECK_OK(member::encode_floors(none, MutByteView{fbuf}, flen));
    commit_record(n.node(1).store, store::rec::revocation_floors, 0, ByteView{fbuf.data(), flen});
    n.boot(1);
    n.run_ms(100);
    LM_CHECK(n.eng(1).identity().is_member()); // the copy looks valid to its holder
    const uint64_t rejected = n.eng(0).link().stats().cred_rejected;
    lm_status_t st = 0;
    (void)n.join(1, 0x72, LM_JOIN_RESUME, &st);
    LM_CHECK_EQ(st, LM_STATUS_OK);
    n.run_ms(45000);
    LM_CHECK(n.eng(0).link().stats().cred_rejected > rejected); // root: revoked by the floor recorded at leave
    LM_CHECK(n.eng(0).link().neighbors().find_device(n.id(1)) == nullptr);
    LM_CHECK(n.linked(0, 2)); // B is fine
}

// ---------------------------------------------------------------------------------------------
// POWER-*: cut at every persistence boundary of a join (sim store injection, docs/12 §4)
// ---------------------------------------------------------------------------------------------
namespace {

struct SweepOutcome {
    bool fired = false;
    bool ok = false;
    std::string why;
    bool joined_after_cut = false;
};


// One join with a power cut at mutating store call `k` of node `target` (0 = root, 1 = device).
SweepOutcome run_cut(unsigned target, uint64_t k, CutMode mode) {
    SweepOutcome out;
    JNet n(2, 500 + k * 7 + target);
    const Bytes ticket = n.grant(1, 1, 1);
    SimStore &st = n.node(target).store;
    st.arm_cut(st.mutating_ops() + k, mode);
    lm_status_t s = 0;
    (void)n.join(1, 0x60, LM_JOIN_NEW, &s);
    if (s != LM_STATUS_OK) {
        out.why = "join refused";
        return out;
    }
    out.fired = n.run_until([&] { return st.cut_fired(); }, 60000, 100);
    if (!out.fired) {
        out.ok = true; // the run finished with fewer commits than k: nothing left to cut
        return out;
    }
    n.reboot(static_cast<uint16_t>(target));
    // ---- allowed states right after the restart (docs/12 §4: the only permitted outcomes) ----
    const bool dev_member = n.eng(1).identity().is_member();
    const root::Entry *e = n.ledger().find(n.id(1));
    if (e == nullptr) {
        out.why = "root lost the expected entry";
        return out;
    }
    if (dev_member && !(e->state == root::EntryState::Active &&
                        e->membership == n.eng(1).identity().member().membership.value() &&
                        e->address.value() == n.eng(1).identity().member().address.value())) {
        out.why = std::string("device ACTIVE but root entry is ") + entry_name(e->state);
        return out;
    }
    if (e->state == root::EntryState::Active && !dev_member && !n.mem(1).prepared_record()) {
        out.why = "root ACTIVE, device neither ACTIVE nor PREPARED";
        return out;
    }
    if (e->state == root::EntryState::Prepared && dev_member) {
        out.why = "device ACTIVE while the root only reserved";
        return out;
    }
    if (e->state != root::EntryState::Expected && e->state != root::EntryState::Prepared &&
        e->state != root::EntryState::Active && e->state != root::EntryState::Aborted) {
        out.why = std::string("root entry in a state no join may produce: ") + entry_name(e->state);
        return out;
    }
    // ---- convergence: the durable evidence of both sides settles it (or a clean restart) ----
    uint64_t revision = 1;
    for (int round = 0; round < 8; ++round) {
        n.run_ms(31000);
        const bool member_now = n.eng(1).identity().is_member();
        const root::Entry *re = n.ledger().find(n.id(1));
        if (member_now && re != nullptr && re->state == root::EntryState::Active && re->confirmed &&
            !n.mem(1).confirm_pending()) {
            break;
        }
        lm_status_t js = 0;
        uint64_t op = 0;
        if (member_now) {
            op = n.join(1, 0x61, LM_JOIN_RESUME, &js);
        } else if (n.mem(1).prepared_record()) {
            op = n.join(1, 0x60, LM_JOIN_NEW, &js); // the outstanding request, by its own id
        } else {
            if (re == nullptr || re->state != root::EntryState::Expected) {
                ++revision;
                (void)n.install_expected(n.expected_page(1, 1, ticket, 1 + revision));
            }
            op = n.join(1, static_cast<uint8_t>(0x70 + round), LM_JOIN_NEW, &js);
        }
        if (js == LM_STATUS_OK && op != 0) {
            (void)n.wait_operation(1, op, 60000);
        }
        n.run_ms(6000);
    }
    const root::Entry *fe = n.ledger().find(n.id(1));
    const bool done = n.eng(1).identity().is_member() && fe != nullptr && fe->state == root::EntryState::Active &&
                      fe->confirmed && !n.mem(1).confirm_pending() &&
                      fe->membership == n.eng(1).identity().member().membership.value() &&
                      fe->address.value() == n.eng(1).identity().member().address.value() &&
                      n.ledger().count(root::EntryState::Active) == 1;
    out.joined_after_cut = done;
    if (!done) {
        out.why = std::string("did not converge: device ") +
                  (n.eng(1).identity().is_member() ? "member" : "not member") + ", root " +
                  (fe != nullptr ? entry_name(fe->state) : "none");
        return out;
    }
    out.ok = true;
    return out;
}

} // namespace

LM_TEST("POWER-* join (sim): power cut before/torn/after every record commit of the device and of the root leaves only allowed states") {
    const lmtest::CutTotals t = lmtest::cut_matrix(
        "join", {{1, "device"}, {0, "root"}}, [](unsigned target, uint64_t k, CutMode mode) {
            const SweepOutcome r = run_cut(target, k, mode);
            return lmtest::CutRun{r.fired, r.ok, r.joined_after_cut, r.why};
        });
    LM_CHECK(t.points >= 30);
}

LM_TEST("S8 lm_stop in the middle of a join gives every borrowed buffer back; the restarted device joins") {
    JNet n(2);
    n.grant(1, 1, 1);
    LM_CHECK(n.join(1, 0x18) != 0);
    n.run_ms(60); // handshake done, request in flight or being checked
    lm_operation_id_t so = 0;
    LM_CHECK_EQ(lm_stop(n.ctx(1), 0, &so), LM_STATUS_OK);
    n.run_ms(200); // late job completions arrive after the stop and are discarded
    LM_CHECK(!n.eng(1).link().exchange().busy()); // the credential buffer is not lent any more
    LM_CHECK_EQ(lm_start(n.ctx(1)), LM_STATUS_OK);
    n.run_ms(50);
    LM_CHECK_EQ(n.membership(1).state, static_cast<uint32_t>(LM_UNASSIGNED));
    n.run_ms(31000);
    lm_status_t st = 0;
    const uint64_t op = n.join(1, 0x18, LM_JOIN_NEW, &st);
    LM_CHECK_EQ(st, LM_STATUS_OK);
    LM_CHECK_EQ(n.wait_operation(1, op, 60000), 0u);
    LM_CHECK_EQ(n.membership(1).state, static_cast<uint32_t>(LM_ACTIVE));
    LM_CHECK(n.ledger().find(n.id(1))->confirmed);
    // The root stops in the middle of a request as well and comes back with its ledger intact.
    LM_CHECK_EQ(n.ledger().count(root::EntryState::Active), 1u);
    lm_operation_id_t ro = 0;
    LM_CHECK_EQ(lm_stop(n.ctx(0), 0, &ro), LM_STATUS_OK);
    LM_CHECK(!n.eng(0).link().exchange().busy());
    LM_CHECK_EQ(lm_start(n.ctx(0)), LM_STATUS_OK);
    n.run_ms(50);
    LM_CHECK_EQ(n.ledger().count(root::EntryState::Active), 1u);
}

namespace {

// One leave with a power cut at mutating store call `k` of node `target` (0 = root, 1 = device).
SweepOutcome run_leave_cut(unsigned target, uint64_t k, CutMode mode) {
    SweepOutcome out;
    JNet n(2, 900 + k * 7 + target);
    if (n.join_device(1, 0x30, 1, 1) != 0) {
        out.why = "setup join failed";
        return out;
    }
    n.run_ms(31000);
    SimStore &st = n.node(target).store;
    st.arm_cut(st.mutating_ops() + k, mode);
    lm_operation_id_t op = 0;
    if (lm_leave(n.ctx(1), LM_LEAVE_IMMEDIATE, 0, &op) != LM_STATUS_OK) {
        out.why = "leave refused";
        return out;
    }
    out.fired = n.run_until([&] { return st.cut_fired(); }, 20000, 100);
    if (!out.fired) {
        out.ok = true;
        return out;
    }
    n.reboot(static_cast<uint16_t>(target));
    const bool member = n.eng(1).identity().is_member();
    const root::Entry *e = n.ledger().find(n.id(1));
    if (e == nullptr || (e->state != root::EntryState::Active && e->state != root::EntryState::Left)) {
        out.why = "root entry is neither Active nor Left after a leave";
        return out;
    }
    if (member) {
        // The device's LEFT record never became durable: it is still ACTIVE, and if the root already recorded
        // the leave the root refuses its credential (the ledger only ever denies).
        n.run_ms(31000);
        lm_status_t js = 0;
        (void)n.join(1, 0x33, LM_JOIN_RESUME, &js);
        n.run_ms(45000);
        if (e->state == root::EntryState::Left && n.linked(0, 1)) {
            out.why = "a device the root recorded as Left got an ordinary session";
            return out;
        }
        // The application repeats the leave and now it holds.
        n.run_ms(31000);
        lm_operation_id_t op2 = 0;
        lm_status_t ls = static_cast<lm_status_t>(lm_leave(n.ctx(1), LM_LEAVE_IMMEDIATE, 0, &op2));
        if (ls == LM_STATUS_BUSY) {
            n.run_ms(60000);
            ls = static_cast<lm_status_t>(lm_leave(n.ctx(1), LM_LEAVE_IMMEDIATE, 0, &op2));
        }
        if (ls != LM_STATUS_OK || n.wait_operation(1, op2, 20000) != 0) {
            out.why = "second leave did not complete";
            return out;
        }
    }
    n.reboot(1);
    if (n.eng(1).identity().is_member() || n.membership(1).state != LM_UNASSIGNED) {
        out.why = "device is a member again after its leave was durable";
        return out;
    }
    out.ok = true;
    return out;
}

} // namespace

LM_TEST("POWER-* leave (sim): power cut before/torn/after every record commit of a leave leaves only allowed states") {
    const lmtest::CutTotals t = lmtest::cut_matrix(
        "leave", {{1, "device"}, {0, "root"}}, [](unsigned target, uint64_t k, CutMode mode) {
            const SweepOutcome r = run_leave_cut(target, k, mode);
            return lmtest::CutRun{r.fired, r.ok, r.ok, r.why};
        });
    LM_CHECK(t.points >= 15); // SEC-D8: the device's leave is one record commit (tombstone + floor), was two
}

// ---------------------------------------------------------------------------------------------
// SEC-D2: the root admits a Link or End session (either direction) only for an ACTIVE ledger entry of
// exactly this device, address, assignment and membership. No entry is no admission.
// ---------------------------------------------------------------------------------------------
namespace {

// Nodes 1..n-1 become members with fleet-issued credentials (address i + 1, assignment/membership 1); the root
// ledger lists them only as the test crafts it.
void make_members(JNet &n, unsigned from, unsigned to) {
    for (unsigned i = from; i < to; ++i) {
        n.kits[i] = n.net.make_node(i, static_cast<uint16_t>(i + 1));
        LM_CHECK_OK(fleet::provision(n.node(i).store, n.net, n.kits[i]));
    }
}

delivery::PathSpec path_to_root(uint16_t origin, std::initializer_list<uint16_t> via) {
    delivery::PathSpec p;
    p.origin = ShortAddr{origin};
    for (uint16_t a : via) {
        p.path[p.len++] = a;
    }
    p.dest = ShortAddr{p.path[p.len - 1U]};
    p.term = RootTerm{1};
    p.revision = PathRevision{1};
    return p;
}

} // namespace

LM_TEST("SEC-2 root-initiated link: refused unless the ledger lists the member ACTIVE with this assignment/membership/address") {
    JNet n(4, 71, false);
    make_members(n, 1, 4);
    craft_entry(n.node(0).store, 0, n.id(1), root::EntryState::Left, 1, 1);   // address 2: departed
    craft_entry(n.node(0).store, 1, n.id(2), root::EntryState::Active, 2, 1); // address 3: other assignment
    craft_entry(n.node(0).store, 2, n.id(3), root::EntryState::Active, 1, 1); // address 4: exactly this credential
    n.start_all();
    for (unsigned i = 1; i < 4; ++i) {
        LM_CHECK_OK(n.eng(0).link().connect(n.node(i).radio.mac(), n.node(0).clock.now()));
        n.node(0).notify();
        n.run_ms(4000);
    }
    LM_CHECK(n.eng(0).link().neighbors().find_device(n.id(1)) == nullptr);
    LM_CHECK(n.eng(0).link().neighbors().find_device(n.id(2)) == nullptr);
    LM_CHECK(n.linked(0, 3)); // the one the ledger lists exactly
    LM_CHECK(n.eng(0).link().stats().cred_rejected >= 2u);
    // A member-initiated attempt of the refused ones fails the same way.
    n.run_ms(31000);
    LM_CHECK_OK(n.eng(2).link().connect(n.node(0).radio.mac(), n.node(2).clock.now()));
    n.node(2).notify();
    n.run_ms(4000);
    LM_CHECK(n.eng(0).link().neighbors().find_device(n.id(2)) == nullptr);
}

LM_TEST("SEC-2 end session with the root: refused in both directions for a member the ledger does not list ACTIVE") {
    JNet n(3, 72, false);
    n.set_link(0, 2, false); // 0 - 1 - 2: node 2 reaches the root only over the relay
    make_members(n, 1, 3);
    craft_entry(n.node(0).store, 0, n.id(1), root::EntryState::Active, 1, 1); // the relay is a member
    craft_entry(n.node(0).store, 1, n.id(2), root::EntryState::Left, 1, 1);   // node 2 left
    n.start_all();
    LM_CHECK_OK(n.eng(1).link().connect(n.node(0).radio.mac(), n.node(1).clock.now()));
    n.node(1).notify();
    n.run_ms(3000);
    LM_CHECK_OK(n.eng(2).link().connect(n.node(1).radio.mac(), n.node(2).clock.now()));
    n.node(2).notify();
    n.run_ms(3000);
    LM_CHECK(n.linked(0, 1) && n.linked(1, 2));
    // Node 2 -> root over 1 (member-initiated end handshake).
    LM_CHECK_OK(n.eng(2).link().exchange().start_end(n.id(0), path_to_root(3, {2, 1}), n.node(2).clock.now()));
    n.node(2).notify();
    n.run_ms(15000);
    LM_CHECK(n.eng(0).delivery().sessions().find_peer(n.id(2)) == nullptr);
    LM_CHECK(n.eng(2).delivery().sessions().find_peer(n.id(0)) == nullptr);
    LM_CHECK(n.eng(0).link().exchange().end_stats().cred_rejected >= 1u);
    // Root -> node 2 (root-initiated end handshake).
    n.run_ms(31000);
    delivery::PathSpec back = path_to_root(1, {2, 3});
    LM_CHECK_OK(n.eng(0).link().exchange().start_end(n.id(2), back, n.node(0).clock.now()));
    n.node(0).notify();
    n.run_ms(15000);
    LM_CHECK(n.eng(0).delivery().sessions().find_peer(n.id(2)) == nullptr);
    LM_CHECK(n.eng(2).delivery().sessions().find_peer(n.id(0)) == nullptr);
}

// SEC-D1: what the root sends at PREPARE is not a credential yet. A joiner that keeps it, never stores, never
// answers and lets the reservation run out holds nothing an ordinary member accepts.
LM_TEST("SEC-1 the PREPARE artifact never opens an ordinary session with a member peer") {
    JNet n(3, 81, false);
    make_members(n, 2, 3); // node 2: an ordinary member (address 3), no ledger involvement
    n.start_all();
    n.grant(1, 1, 1);
    LM_CHECK(n.join(1, 0x71) != 0);
    // What the device received in JoinPrepare, as its PREPARED record holds it (request | nonce | hash | credential).
    auto rec = std::make_unique<store::RecordJob>();
    const bool got = n.run_until(
        [&] {
            rec->op = store::RecordJob::Op::Load;
            rec->id = store::rec::membership_prepared;
            return store::record_load(n.node(1).store, *rec) == Status::Ok && rec->state == member::k_prepared_state;
        },
        20000, 1);
    LM_CHECK(got);
    n.set_link(0, 1, false); // the hostile joiner goes silent: no JoinStored, the reservation lapses
    const Bytes artifact(rec->payload.begin() + member::k_prepared_head, rec->payload.begin() + rec->payload_len);
    // Hostile firmware installs the artifact as its ACTIVE credential without any check and asks a member for a link.
    member::RootDelegation deleg;
    LM_CHECK_OK(member::check_root_delegation(n.net.fleet.trust(), view(n.net.delegation_cose), deleg));
    member::Envelope env;
    ByteView data;
    member::MemberCredential mc;
    LM_CHECK_OK(member::peek_signed(view(artifact), member::k_type_member_credential, env, data));
    LM_CHECK_OK(member::decode_member_credential(data, mc));
    n.run_ms(130000); // the reservation (120 s) is over at the root
    n.mem(1).stop();  // the join state machine is out of the way (hostile firmware does not run it)
    LM_CHECK_OK(n.eng(1).identity().adopt_member(deleg, mc, view(artifact)));
    const uint64_t rejected = n.eng(2).link().stats().cred_rejected;
    LM_CHECK_OK(n.eng(1).link().connect(n.node(2).radio.mac(), n.node(1).clock.now()));
    n.node(1).notify();
    n.run_ms(6000);
    LM_CHECK(n.eng(2).link().neighbors().find_device(n.id(1)) == nullptr);
    LM_CHECK(!n.linked(1, 2));
    LM_CHECK(n.eng(2).link().stats().cred_rejected > rejected); // refused by the peer's own signature check
}

// SEC-D4 / S18 (supersedes SEC-D4a): ticket modes (docs/07 §8, control.cddl note 3). A mode-0 ticket names the nonce
// the device issued (lm_transfer_nonce_get) and the device vouches for it in its authenticated JoinRequest; a ticket
// for any other nonce - one it never issued, or one a restart forgot - never reaches the root.
LM_TEST("SEC-4 S18 a mode-0 ticket works only for the device's own outstanding nonce, once") {
    JNet n(2, 83);
    std::array<uint8_t, 16> nonce{};
    nonce.fill(0x5A);
    const Bytes forged = n.net.fleet.ticket(n.kits[1].kit, DomainId{}, n.net.domain, n.net.delegation_cose, 0, 1, 0, &nonce);
    LM_CHECK_EQ(n.install_ticket(1, forged), Status::AuthRejected); // a nonce this device never issued
    // A ticket record written behind the install check (another nonce): the device does not present it.
    n.node(1).power_cut();
    n.node(1).store.power_restore();
    commit_record(n.node(1).store, store::rec::assignment_ticket, 0, view(forged));
    n.boot(1);
    n.run_ms(100);
    LM_CHECK_OK(n.install_expected(n.expected_page(1, 1, forged, 1)));
    uint64_t op = n.join(1, 0x72);
    LM_CHECK_EQ(n.wait_operation(1, op, 30000), static_cast<uint32_t>(Status::AuthRejected));
    LM_CHECK_EQ(n.ledger().stats().requests, 0ull);
    // The real thing: the device's nonce, the fleet's ticket for it, the join.
    std::array<uint8_t, 16> mine{};
    LM_CHECK_EQ(lm_transfer_nonce_get(n.ctx(1), mine.data()), LM_STATUS_OK);
    std::array<uint8_t, 16> again{};
    LM_CHECK_EQ(lm_transfer_nonce_get(n.ctx(1), again.data()), LM_STATUS_OK);
    LM_CHECK(mine == again); // one outstanding nonce until it is spent
    const Bytes t0 = n.net.fleet.ticket(n.kits[1].kit, DomainId{}, n.net.domain, n.net.delegation_cose, 0, 1, 0, &mine);
    LM_CHECK_OK(n.install_ticket(1, t0));
    n.run_ms(31000); // the full-handshake gate after the refused attempt
    LM_CHECK_OK(n.install_expected(n.expected_page(1, 1, t0, 2)));
    op = n.join(1, 0x73);
    LM_CHECK_EQ(n.wait_operation(1, op, 60000), 0u);
    LM_CHECK(n.eng(1).identity().is_member());
    LM_CHECK_EQ(lm_transfer_nonce_get(n.ctx(1), again.data()), LM_STATUS_OK);
    LM_CHECK(mine != again); // spent by the membership it bought
    // A restart forgets an outstanding nonce: a ticket issued for it is refused afterwards.
    const Bytes stale = n.net.fleet.ticket(n.kits[1].kit, n.net.domain, n.net.domain, n.net.delegation_cose, 1, 2, 0, &again);
    n.reboot(1);
    n.run_ms(200);
    LM_CHECK_EQ(n.install_ticket(1, stale), Status::AuthRejected);
}

// SEC-D4: the root keeps what a device consumed (its highest ACTIVE assignment generation) in the ledger entry
// itself, so a consumed grant stays consumed even when the floor table has no room for the departed device.
LM_TEST("SEC-4 a consumed mode-1 grant is never accepted again by the root, even with a full floor table") {
    JNet n(2, 84, false);
    member::Floors full;
    for (std::size_t i = 0; i < member::k_max_floors; ++i) {
        DeviceId d;
        d.bytes.fill(static_cast<uint8_t>(0xA0 + i));
        LM_CHECK_OK(full.raise(d, 1, 1));
    }
    LM_CHECK_OK(fleet::provision(n.node(0).store, n.net, n.kits[0], true, &full)); // no room for another floor
    n.start_all();
    const Bytes t = n.grant(1, 1, 1);
    lm_status_t st = 0;
    uint64_t op = n.join(1, 0x73, LM_JOIN_NEW, &st);
    LM_CHECK_EQ(st, LM_STATUS_OK);
    LM_CHECK_EQ(n.wait_operation(1, op, 30000), 0u);
    n.run_ms(6000);
    lm_operation_id_t lop = 0;
    LM_CHECK_EQ(lm_leave(n.ctx(1), LM_LEAVE_IMMEDIATE, 0, &lop), LM_STATUS_OK);
    LM_CHECK_EQ(n.wait_operation(1, lop, 5000), 0u);
    n.run_ms(1000);
    LM_CHECK(n.ledger().find(n.id(1)) != nullptr && n.ledger().find(n.id(1))->state == root::EntryState::Left);
    // A copy of the device without any memory of it (no floors, no LEFT tombstone) presents the same ticket; an
    // expected page grants it (again). Only the root can refuse now.
    n.node(1).power_cut();
    n.node(1).store.power_restore();
    for (uint8_t slot = 0; slot < 2; ++slot) {
        (void)n.node(1).store.slot_erase(store::rec::membership, slot);
        (void)n.node(1).store.slot_erase(static_cast<uint16_t>(store::rec::membership | store::k_marker_flag), slot);
    }
    const member::Floors none;
    std::array<uint8_t, 8> fbuf{};
    std::size_t flen = 0;
    LM_CHECK_OK(member::encode_floors(none, MutByteView{fbuf}, flen));
    commit_record(n.node(1).store, store::rec::revocation_floors, 0, ByteView{fbuf.data(), flen});
    n.boot(1);
    n.run_ms(31000);
    LM_CHECK_OK(n.install_expected(n.expected_page(1, 1, t, 2)));
    op = n.join(1, 0x74, LM_JOIN_NEW, &st);
    LM_CHECK_EQ(st, LM_STATUS_OK);
    LM_CHECK_EQ(n.wait_operation(1, op, 30000), static_cast<uint32_t>(Status::Conflict));
    LM_CHECK_EQ(n.ledger().stats().prepared, 1ull); // one reservation ever: the first join
    LM_CHECK(!n.eng(1).identity().is_member());
}

// SEC-D8: a leave is APPLIED only together with the device's own record of what it consumed. That record needs no
// room in the revocation-floor table (it rides in the membership tombstone), so a full table cannot lose it.
LM_TEST("SEC-8 leave with a full floor table still keeps the device's own floor; the consumed ticket is refused locally") {
    JNet n(2, 86, false);
    member::Floors full;
    for (std::size_t i = 0; i < member::k_max_floors; ++i) {
        DeviceId d;
        d.bytes.fill(static_cast<uint8_t>(0xB0 + i));
        LM_CHECK_OK(full.raise(d, 1, 1));
    }
    sim::ProvisionInput in; // device 1: identity, trust and a floor table without room
    in.scalar32 = ByteView{n.kits[1].kit.scalar};
    in.device_cose = view(n.kits[1].kit.device_cose);
    in.trust = n.net.fleet.trust();
    in.floors = &full;
    LM_CHECK_OK(sim::provision_store(n.node(1).store, in));
    n.start_all();
    LM_CHECK_EQ(n.join_device(1, 0x75, 1, 1), 0u);
    n.run_ms(6000);
    lm_operation_id_t lop = 0;
    LM_CHECK_EQ(lm_leave(n.ctx(1), LM_LEAVE_IMMEDIATE, 0, &lop), LM_STATUS_OK);
    LM_CHECK_EQ(n.wait_operation(1, lop, 5000), 0u); // APPLIED, with the floor retained
    n.reboot(1);
    LM_CHECK_EQ(n.membership(1).state, static_cast<uint32_t>(LM_UNASSIGNED));
    // The same (consumed) ticket again: the device refuses it itself, the root never hears of it.
    n.run_ms(31000);
    LM_CHECK_OK(n.install_expected(n.expected_page(1, 1, n.tickets[1], 2)));
    const uint64_t requests = n.ledger().stats().requests;
    lm_status_t st = 0;
    const uint64_t op = n.join(1, 0x76, LM_JOIN_NEW, &st);
    LM_CHECK_EQ(st, LM_STATUS_OK);
    LM_CHECK_EQ(n.wait_operation(1, op, 60000), static_cast<uint32_t>(Status::Revoked));
    LM_CHECK_EQ(n.ledger().stats().requests, requests);
}

// SEC-D7: an ExpectedSet revision is one signed set: its pages carry one set hash and page count, a page is taken
// once (the same bytes again are the same answer), and the progress survives a restart. A failure after the first
// entry of a page changed is RECOVERY_REQUIRED (authorisation moved), never an ordinary refusal; the same page
// completes it.
LM_TEST("SEC-7 ExpectedSet: one set per revision, a page once, page < pages, progress durable") {
    JNet n(4, 87);
    LM_CHECK_EQ(n.install_expected_result(n.page(5, 0, 2, 0x11, {1})), 0u);
    LM_CHECK(n.expected(1));
    LM_CHECK_EQ(n.install_expected_result(n.page(5, 0, 2, 0x11, {1})), 0u); // the same page again: same answer
    // The same revision and page with other entries, the same revision with another set hash or page count:
    // not this set.
    LM_CHECK_EQ(n.install_expected_result(n.page(5, 0, 2, 0x11, {2})), static_cast<uint32_t>(Status::Conflict));
    LM_CHECK_EQ(n.install_expected_result(n.page(5, 1, 2, 0x22, {2})), static_cast<uint32_t>(Status::Conflict));
    LM_CHECK_EQ(n.install_expected_result(n.page(5, 1, 3, 0x11, {2})), static_cast<uint32_t>(Status::Conflict));
    LM_CHECK(!n.expected(2));
    // A page number outside its own set.
    LM_CHECK(n.install_expected_result(n.page(6, 2, 2, 0x33, {3})) != 0u);
    LM_CHECK(!n.expected(3));
    // Revision 5 progress is durable: after a restart the root still knows page 0 and its content.
    n.reboot(0);
    LM_CHECK_EQ(n.install_expected_result(n.page(5, 0, 2, 0x11, {2})), static_cast<uint32_t>(Status::Conflict));
    LM_CHECK_EQ(n.install_expected_result(n.page(5, 1, 2, 0x11, {2})), 0u);
    LM_CHECK(n.expected(1) && n.expected(2));
    LM_CHECK_EQ(n.ledger().manifest().received, 3u);
}

LM_TEST("SEC-7 ExpectedSet: an entry commit failing after the first entry changed is RECOVERY_REQUIRED; the same page completes it") {
    JNet n(4, 88);
    SimStore &st = n.node(0).store;
    // Page with two entries: the root commits its progress mark, then entry 1, then entry 2 (the one that fails).
    const Bytes p = n.page(3, 0, 1, 0x44, {1, 2});
    bool partial = false;
    for (uint64_t k = 0; k < 12 && !partial; ++k) {
        JNet m(4, 88);
        SimStore &ms = m.node(0).store;
        ms.arm_cut(ms.mutating_ops() + k, CutMode::Before);
        lm_operation_id_t op = 0;
        LM_CHECK_EQ(lm_install_control(m.ctx(0), 5, p.data(), p.size(), &op), LM_STATUS_OK);
        const bool fired = m.run_until([&] { return ms.cut_fired(); }, 2000, 1);
        ms.power_restore(); // a transient Flash failure: the node keeps running
        const uint32_t reason = m.wait_operation(0, op, 2000);
        if (!fired) {
            break;
        }
        if (m.expected(1) && !m.expected(2)) { // entry 1 changed, entry 2 did not: authorisation moved
            partial = true;
            LM_CHECK_EQ(reason, static_cast<uint32_t>(Status::RecoveryRequired));
            LM_CHECK_EQ(m.install_expected_result(p), 0u); // the same page again completes the set
            LM_CHECK(m.expected(1) && m.expected(2));
            LM_CHECK_EQ(m.install_expected_result(m.page(3, 0, 1, 0x44, {3})), static_cast<uint32_t>(Status::Conflict));
        }
    }
    LM_CHECK(partial);
    (void)st;
}

// SEC-Da (docs/07 §2-§3): the optional DiscoveryScopeKey narrows discovery. A scoped root offers only to hellos that
// carry its scope's tag and tags its offers; a scoped device follows only offers with its scope's tag. The tag is a
// filter every holder of the key can make: it never authorises (the handshake and the credentials do).
LM_TEST("SEC-a DiscoveryScopeKey: only a hello of the root's scope gets an offer; an untagged hint is not followed") {
    JNet n(4, 91, false);
    const std::array<uint8_t, 32> scope_a{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17};
    const std::array<uint8_t, 32> scope_b{9, 9, 9};
    commit_record(n.node(0).store, store::rec::discovery_scope, 0, ByteView{scope_a});
    commit_record(n.node(1).store, store::rec::discovery_scope, 0, ByteView{scope_a});
    commit_record(n.node(2).store, store::rec::discovery_scope, 0, ByteView{scope_b}); // another scope
    // node 3 holds no scope key
    n.start_all();
    const uint64_t hs1 = n.eng(1).link().stats().hs_started;
    lm_status_t st = 0;
    n.grant(1, 1, 1);
    uint64_t op = n.join(1, 0x77, LM_JOIN_NEW, &st);
    // A forged offer without the tag, echoing device 1's hello: not followed (no handshake is spent on it).
    std::array<uint8_t, 64> frame{};
    std::size_t len = 0;
    member::OfferHint hint;
    n.run_ms(900);
    LM_CHECK_OK(member::encode_discovery(true, n.eng(1).membership().hello_nonce(), link::domain_hint_of(n.net.domain),
                                         MutByteView{frame}, len, &hint));
    n.world.inject(n.node(3).radio.mac(), 3, n.node(1).radio.mac(), ByteView{frame.data(), len});
    LM_CHECK_EQ(n.wait_operation(1, op, 30000), 0u); // the scoped root answered with a tagged offer
    // The JOIN_ONLY handshake with the root and the first ordinary link after it; nothing for the forged hint.
    LM_CHECK_EQ(n.eng(1).link().stats().hs_started - hs1, 2u);
    n.grant(2, 1, 2);
    op = n.join(2, 0x78, LM_JOIN_NEW, &st, 5000);
    LM_CHECK_EQ(n.wait_operation(2, op, 30000), static_cast<uint32_t>(Status::Expired));
    n.grant(3, 1, 3);
    op = n.join(3, 0x79, LM_JOIN_NEW, &st, 5000);
    LM_CHECK_EQ(n.wait_operation(3, op, 30000), static_cast<uint32_t>(Status::Expired));
    LM_CHECK_EQ(n.ledger().stats().requests, 1ull); // other scopes never reached the root
    LM_CHECK(n.eng(1).identity().is_member() && !n.eng(2).identity().is_member() && !n.eng(3).identity().is_member());
}

// SEC-D5 (docs/12 §5): a root that lost its whole ledger never comes back as an empty one with the same domain key.
LM_TEST("SEC-5 complete loss of the root ledger is RECOVERY_REQUIRED, never an empty ledger that re-admits a departed member") {
    JNet n(2, 73);
    LM_CHECK_EQ(n.join_device(1, 0x90, 1, 1), 0u);
    n.run_ms(6000);
    const ByteView mc = n.eng(1).identity().member_cose();
    const Bytes old_mc(mc.begin(), mc.end());
    lm_operation_id_t lop = 0;
    LM_CHECK_EQ(lm_leave(n.ctx(1), LM_LEAVE_IMMEDIATE, 0, &lop), LM_STATUS_OK);
    LM_CHECK_EQ(n.wait_operation(1, lop, 5000), 0u);
    n.run_ms(1000);
    LM_CHECK(n.ledger().find(n.id(1)) != nullptr && n.ledger().find(n.id(1))->state == root::EntryState::Left);
    // The root's state records are gone (ledger, its manifest, the floors); identity and delegation survive.
    n.node(0).power_cut();
    auto erase = [&](uint16_t id) {
        for (uint8_t slot = 0; slot < 2; ++slot) {
            (void)n.node(0).store.slot_erase(id, slot);
            (void)n.node(0).store.slot_erase(static_cast<uint16_t>(id | store::k_marker_flag), slot);
        }
    };
    erase(store::rec::root_ledger);
    erase(store::rec::revocation_floors);
    for (std::size_t s = 0; s < root::k_ledger_slots; ++s) {
        erase(static_cast<uint16_t>(root::k_rec_ledger_base + s));
    }
    n.node(0).store.power_restore();
    n.events[0].clear();
    n.boot(0);
    n.run_ms(100);
    LM_CHECK(!n.ledger().ready());
    LM_CHECK(n.has_event(0, LM_EVENT_FAULT, static_cast<uint32_t>(Status::RecoveryRequired)));
    // The departed device brings its old credential back (a copy without floors) and asks the root.
    n.node(1).power_cut();
    n.node(1).store.power_restore();
    commit_record(n.node(1).store, store::rec::membership, member::k_membership_active, view(old_mc));
    const member::Floors none;
    std::array<uint8_t, 8> fbuf{};
    std::size_t flen = 0;
    LM_CHECK_OK(member::encode_floors(none, MutByteView{fbuf}, flen));
    commit_record(n.node(1).store, store::rec::revocation_floors, 0, ByteView{fbuf.data(), flen});
    n.boot(1);
    n.run_ms(100);
    LM_CHECK(n.eng(1).identity().is_member());
    n.run_ms(31000);
    LM_CHECK_OK(n.eng(1).link().connect(n.node(0).radio.mac(), n.node(1).clock.now()));
    n.node(1).notify();
    n.run_ms(6000);
    LM_CHECK(n.eng(0).link().neighbors().find_device(n.id(1)) == nullptr);
    LM_CHECK(!n.linked(0, 1));
    // The root can decide no admission at all (SEC-D2): it answers no handshake and starts none, and that is its own
    // state, not a rejected credential of the peer.
    LM_CHECK(n.eng(0).link().stats().hs_busy_drop >= 1u);
    LM_CHECK_EQ(n.eng(0).link().stats().cred_rejected + n.eng(0).link().stats().hs_started, 0u);
    LM_CHECK(n.eng(0).link().connect(n.node(1).radio.mac(), n.node(0).clock.now()) == Status::RecoveryRequired);
}

LM_TEST("S8 root restart between PREPARED and STORED: the old reservation is aborted, never extended; the next join gets a new generation") {
    JNet n(2);
    n.grant(1, 1, 1);
    LM_CHECK(n.join(1, 0x41) != 0);
    LM_CHECK(n.run_until(
        [&] {
            const root::Entry *e = n.ledger().find(n.id(1));
            return e != nullptr && e->state == root::EntryState::Prepared;
        },
        10000, 100));
    n.set_link(0, 1, false);
    n.reboot(0); // the root restarts holding a PREPARED reservation whose deadline it cannot know
    n.set_link(0, 1, true);
    LM_CHECK(n.ledger().find(n.id(1))->state == root::EntryState::Prepared);
    n.run_ms(320000); // the device gave up on its unanswered request meanwhile
    LM_CHECK_EQ(n.membership(1).state, static_cast<uint32_t>(LM_UNASSIGNED));
    lm_status_t st = 0;
    uint64_t op = n.join(1, 0x42, LM_JOIN_NEW, &st);
    LM_CHECK_EQ(st, LM_STATUS_OK);
    LM_CHECK_EQ(n.wait_operation(1, op, 60000), static_cast<uint32_t>(Status::Conflict)); // aborts the old reservation
    n.run_ms(2000);
    LM_CHECK(n.ledger().find(n.id(1))->state == root::EntryState::Aborted);
    // The operator grants again (Aborted is not Expected): a new request joins with membership 2, never 1.
    n.run_ms(31000);
    LM_CHECK_OK(n.install_expected(n.expected_page(1, 1, n.tickets[1], 2)));
    op = n.join(1, 0x43, LM_JOIN_NEW, &st);
    LM_CHECK_EQ(st, LM_STATUS_OK);
    LM_CHECK_EQ(n.wait_operation(1, op, 60000), 0u);
    LM_CHECK_EQ(n.membership(1).membership_generation, 2ull);
    LM_CHECK_EQ(n.ledger().find(n.id(1))->address.value(), 2u);
    LM_CHECK_EQ(n.ledger().count(root::EntryState::Active), 1u);
}

// ADR-002 P4: the node has one record memory (the identity's RecordJob). A root join transaction keeps the
// credential buffer for its whole life, but takes the record memory only for its own record jobs: while it waits
// for the device (PREPARE out), anything else may use it; when its commit is due and the memory is lent, the step
// waits for it on the transaction's retry timer and completes once it is back. Before P4 the transaction held it
// from the JoinRequest to the confirmation (minutes with a slow device), blocking every other record job.
LM_TEST("P4 root: a join transaction lends the record memory out while it waits for the device; its commit waits for it") {
    JNet n(2);
    n.grant(1, 1, 1);
    const uint64_t op = n.join(1, 0x51);
    LM_CHECK(op != 0);
    const auto in_state = [&](root::Ledger::TxnState s) {
        for (std::size_t i = 0; i < root::k_join_txns; ++i) {
            if (n.ledger().txn_state(i) == s) {
                return true;
            }
        }
        return false;
    };
    LM_CHECK(n.run_until([&] { return in_state(root::Ledger::TxnState::PrepareOut); }, 20000, 100));
    member::LocalIdentity &rid0 = n.eng(0).identity();
    store::RecordJob *held = rid0.lend_record(); // what a journal, channel or power job would do right now
    LM_CHECK(held != nullptr);                   // nothing holds it while the transaction waits for the device
    // STORED arrives while the memory is lent: the ACTIVE commit waits (no refusal, no second reservation).
    LM_CHECK(n.run_until([&] { return in_state(root::Ledger::TxnState::Activating); }, 5000, 100));
    n.run_ms(1000);
    LM_CHECK(in_state(root::Ledger::TxnState::Activating));
    const root::Entry *e = n.ledger().find(n.id(1));
    LM_CHECK(e != nullptr && e->state == root::EntryState::Prepared);
    LM_CHECK_EQ(n.ledger().stats().refused, 0ull);
    if (held != nullptr) {
        rid0.return_record(); // (a module returns it inside the owner's step; the test wakes the owner)
        n.node(0).notify();
    }
    LM_CHECK_EQ(n.wait_operation(1, op, 60000), 0u);
    e = n.ledger().find(n.id(1));
    LM_CHECK(e != nullptr && e->state == root::EntryState::Active && e->confirmed);
    LM_CHECK_EQ(n.ledger().stats().prepared, 1ull);
    n.run_ms(500);
    store::RecordJob *again = rid0.lend_record(); // every job gave it back
    LM_CHECK(again != nullptr);
    if (again != nullptr) {
        rid0.return_record();
    }
}

// ADR-002 P4: the journal borrows the same record memory per job. A durable send's commit waits while another
// module holds it (the send stays "accepted", nothing is sent before it is durable), the owner sleeps meanwhile
// (no retry poll), and the commit runs in the owner's next pass once the memory is back.
LM_TEST("P4 member: a durable commit waits for the record memory without polling and runs as soon as it is back") {
    JNet n(2);
    LM_CHECK_EQ(n.join_device(1, 0x52, 1, 1), 0u);
    n.run_ms(10000); // lingering join timers end
    member::LocalIdentity &id1 = n.eng(1).identity();
    store::RecordJob *held = id1.lend_record();
    LM_CHECK(held != nullptr);
    lm_send_request_t rq{};
    rq.struct_size = sizeof(rq);
    rq.abi_version = LM_ABI_VERSION;
    rq.destination.kind = LM_DEST_NODE;
    std::memcpy(rq.destination.node.bytes, n.id(0).bytes.data(), 32);
    rq.app_port = 100;
    rq.delivery = LM_RECEIVED;
    rq.storage = LM_DURABLE; // RECEIVED+DURABLE may go without a deadline (docs/08 §5)
    rq.priority = LM_PRIORITY_NORMAL;
    rq.queue_mode = LM_FIFO;
    const std::array<uint8_t, 8> payload{1, 2, 3, 4, 5, 6, 7, 8};
    lm_operation_id_t sop = 0;
    LM_CHECK_EQ(lm_send(n.ctx(1), &rq, payload.data(), payload.size(), &sop), LM_STATUS_OK);
    n.node(1).notify();
    n.run_ms(20);
    const auto evidence = [&] {
        lm_operation_t o{};
        o.struct_size = sizeof(o);
        o.abi_version = LM_ABI_VERSION;
        LM_CHECK_EQ(lm_get_operation(n.ctx(1), sop, &o), LM_STATUS_OK);
        return o.evidence_bits;
    };
    const uint64_t steps0 = n.eng(1).stats().steps;
    n.run_ms(3000);
    LM_CHECK((evidence() & delivery::ev::accepted) != 0);
    LM_CHECK((evidence() & (delivery::ev::persisted | delivery::ev::sent)) == 0); // waits, sends nothing
    LM_CHECK(n.eng(1).stats().steps - steps0 <= 3); // asleep while it waits (a 20 ms retry would be 150 passes)
    LM_CHECK(n.eng(1).delivery().durable().live_count() == 0);
    if (held != nullptr) {
        id1.return_record();
        n.node(1).notify();
    }
    n.run_ms(20); // one journal write
    LM_CHECK((evidence() & delivery::ev::persisted) != 0);
    LM_CHECK_EQ(n.eng(1).delivery().durable().live_count(), 1u);
    store::RecordJob *again = id1.lend_record(); // the journal gave it back after its job
    LM_CHECK(again != nullptr);
    if (again != nullptr) {
        id1.return_record();
    }
}

// ADR-002 P4 (every borrower waits, none gives up): at boot the channel module and the membership both need the one
// record memory as soon as the identity is loaded. The membership's load of its PREPARED/ACTIVATED record must wait
// for the channel's job, not be skipped: before, a device with the channel module (every firmware image) lost the
// "root acknowledgement owed" state of LC06 on a reboot.
LM_TEST("P4 LC06 sim: with the channel module, the boot load of the ACTIVATED record waits for the record memory") {
    JNet n(2, 31, true, true);
    n.grant(1, 1, 1);
    const uint64_t op = n.join(1, 0x53);
    LM_CHECK(n.run_until([&] { return n.eng(1).identity().is_member(); }, 10000, 50));
    n.set_link(0, 1, false); // JOIN_ACTIVE never reaches the root
    LM_CHECK_EQ(n.wait_operation(1, op, 30000), static_cast<uint32_t>(Status::Expired));
    LM_CHECK(n.mem(1).confirm_pending());
    n.reboot(1);
    n.run_ms(500);
    LM_CHECK(n.eng(1).chan().loaded()); // the channel record was loaded at boot as well
    LM_CHECK(n.mem(1).confirm_pending()); // the owed acknowledgement came back from Flash
    n.set_link(0, 1, true);
    n.run_ms(31000);
    lm_status_t st = 0;
    const uint64_t rop = n.join(1, 0x54, LM_JOIN_RESUME, &st);
    LM_CHECK_EQ(st, LM_STATUS_OK);
    LM_CHECK_EQ(n.wait_operation(1, rop, 30000), 0u);
    LM_CHECK(n.run_until([&] { return !n.mem(1).confirm_pending(); }, 10000, 5000));
    const root::Entry *e = n.ledger().find(n.id(1));
    LM_CHECK(e != nullptr && e->state == root::EntryState::Active && e->confirmed);
}

// ADR-002 P8: a node holds the joiner side or the root's ledger, never both (one storage by role; the other is an
// invariant failure to touch). The root's membership answers come from its identity alone, unchanged; the member API
// the root never had stays refused; a non-root node has no coordinator to plan with (as on an image without one).
LM_TEST("P8 sim: one membership object per role; the root's answers are unchanged, a leaf plans no channel") {
    JNet n(2);
    LM_CHECK_EQ(n.join_device(1, 0x55, 1, 1), 0u);
    const lm_membership_t r = n.membership(0);
    LM_CHECK_EQ(r.state, static_cast<uint32_t>(LM_ACTIVE));
    LM_CHECK_EQ(r.reason, 0u);
    LM_CHECK(std::memcmp(r.device.bytes, n.id(0).bytes.data(), 32) == 0);
    LM_CHECK(std::memcmp(r.domain.bytes, n.net.domain.bytes.data(), 16) == 0);
    LM_CHECK_EQ(r.state_since_mono_ms, 0ull); // (the root never ran a joiner: as before)
    lm_operation_t o{};
    o.struct_size = sizeof(o);
    o.abi_version = LM_ABI_VERSION;
    const lm_request_id_t req = rid(0x55);
    LM_CHECK_EQ(lm_get_request(n.ctx(0), &req, &o), LM_STATUS_NOT_FOUND); // the root joins nothing
    LM_CHECK_EQ(lm_get_request(n.ctx(1), &req, &o), LM_STATUS_OK);
    lm_status_t st = 0;
    LM_CHECK_EQ(n.join(0, 0x56, LM_JOIN_NEW, &st), 0ull);
    LM_CHECK_EQ(st, LM_STATUS_ROLE_NOT_ALLOWED);
    lm_operation_id_t op = 0;
    LM_CHECK_EQ(lm_leave(n.ctx(0), LM_LEAVE_DRAIN, 0, &op), LM_STATUS_ROLE_NOT_ALLOWED);
    const lm_membership_t d = n.membership(1);
    LM_CHECK_EQ(d.state, static_cast<uint32_t>(LM_ACTIVE));
    LM_CHECK_EQ(lm_channel_request(n.ctx(1), LM_CHANNEL_RECALCULATE, 0, &op), LM_STATUS_UNSUPPORTED);
    LM_CHECK(n.eng(0).role_job_pending() == false && n.eng(1).role_job_pending() == false);
}

LM_TEST("J08 HIL-F3: a board erased and given a new identity joins at once from the same MAC") {
    JNet n(2);
    LM_CHECK_EQ(n.join_device(1, 0x20, 1, 1), 0u);
    n.run_ms(5000);
    LM_CHECK(n.linked(0, 1));
    const DeviceId old = n.id(1);
    // The board is erased (esptool erase-flash) and provisioned with a new key: same node, same MAC.
    n.node(1).power_cut();
    n.node(1).store.wipe();
    n.node(1).store.power_restore();
    n.kits[1] = n.net.make_unjoined(101);
    n.provision_unjoined(1);
    n.boot(1);
    // Re-provisioning a board takes minutes; 31 s keep the root's one-full-handshake-per-MAC gate (touched by the old
    // device's last link handshake) out of this test: that interaction is HIL-F2's.
    n.run_ms(31000);
    LM_CHECK(n.eng(0).link().neighbors().find_device(old) != nullptr); // the root still holds the old session
    // HIL 2026-10-03: the root dropped every join carrier of a MAC that was an ordinary neighbour, for as long as the
    // old session lived (up to its 1 h key lifetime). The new identity must join within one ordinary join.
    LM_CHECK_EQ(n.join_device(1, 0x21, 1, 2), 0u);
    LM_CHECK_EQ(n.membership(1).state, static_cast<uint32_t>(LM_ACTIVE));
    const root::Entry *e = n.ledger().find(n.id(1));
    LM_CHECK(e != nullptr && e->state == root::EntryState::Active);
    LM_CHECK(n.eng(0).link().neighbors().find_device(old) == nullptr); // the stale session went with the new identity
    n.run_ms(5000);
    LM_CHECK(n.linked(0, 1));
    LM_CHECK_EQ(n.join_only_neighbors(0), 0u);
}

LM_TEST("J08 HIL-F3: join carriers from a live member's MAC are refused after verification and its session stays") {
    JNet n(2);
    LM_CHECK_EQ(n.join_device(1, 0x30, 1, 1), 0u);
    n.run_ms(5000);
    LM_CHECK(n.linked(0, 1));
    const link::Neighbor *before = n.eng(0).link().neighbors().find_device(n.id(1));
    LM_CHECK(before != nullptr);
    const Sha256Digest ctx = before != nullptr ? before->cur.ctx_hash : Sha256Digest{};
    // The member asks the root for a membership through the JOIN_ONLY handshake (its transfer path): same device.
    n.run_ms(31000); // past the per-MAC handshake gate, so the refusal is the identity check's
    lm_status_t st = 0;
    const uint64_t op = n.join(1, 0x31, LM_JOIN_TRANSFER_CANDIDATE, &st, 30000);
    if (st == LM_STATUS_OK) {
        (void)n.wait_operation(1, op, 40000);
    }
    const link::Neighbor *after = n.eng(0).link().neighbors().find_device(n.id(1));
    LM_CHECK(after != nullptr && after->cur.ctx_hash == ctx); // the ordinary session was never replaced
    LM_CHECK_EQ(n.join_only_neighbors(0), 0u);
    LM_CHECK_EQ(n.membership(1).state, static_cast<uint32_t>(LM_ACTIVE));
}

LM_TEST("measure: sizeof of the join/membership state") {
    std::printf("  [measure] sizeof(Membership)=%zu Ledger=%zu (entries %zu x %zu) JoinPipe=%zu Exchange=%zu LinkLayer=%zu\n"
                "            LocalIdentity=%zu Engine=%zu lm_context=%zu Neighbor=%zu\n",
                sizeof(member::Membership), sizeof(root::Ledger), root::k_ledger_slots, sizeof(root::Entry),
                sizeof(member::JoinPipe), sizeof(link::Exchange), sizeof(link::LinkLayer), sizeof(member::LocalIdentity),
                sizeof(Engine), sizeof(lm_context), sizeof(link::Neighbor));
}

LM_TEST_MAIN()
