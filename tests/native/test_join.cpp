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
    // Node 0 is the root (preapproved by default), 1..n-1 are provisioned but unjoined devices.
    explicit JNet(unsigned n, uint64_t seed = 31, bool boot_all = true)
        : net(seed), world(WorldOptions{seed, 0}), events(n), tickets(n) {
        for (unsigned i = 0; i < n; ++i) {
            NodeOptions o;
            o.role = i == 0 ? Role::Root : Role::Leaf;
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
        eng(0).ledger().set_join_mode(root::JoinMode::Preapproved);
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
    Status install_ticket(unsigned i, const Bytes &t) {
        lm_operation_id_t op = 0;
        const lm_status_t s = lm_install_control(ctx(i), 3, t.data(), t.size(), &op);
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
        const lm_status_t s = lm_install_control(ctx(0), 5, page.data(), page.size(), &op);
        if (s != LM_STATUS_OK) {
            return static_cast<Status>(s);
        }
        return wait_operation(0, op, 2000) == 0 ? Status::Ok : Status::Conflict;
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

LM_TEST("M06 leave: IMMEDIATE erases membership durably; DRAIN never turns into IMMEDIATE by itself; re-join uses a new generation") {
    JNet n(2);
    LM_CHECK_EQ(n.join_device(1, 0x30, 1, 1), 0u);
    n.run_ms(6000);
    LM_CHECK(n.linked(0, 1));
    // DRAIN with pending work that never settles: explicit failure at the deadline, still ACTIVE.
    static bool drained = false;
    drained = false;
    member::MembershipHooks hooks;
    hooks.drained = [](void *) { return drained; };
    n.mem(1).set_hooks(hooks);
    lm_operation_id_t op = 0;
    LM_CHECK_EQ(lm_leave(n.ctx(1), LM_LEAVE_DRAIN, 1500, &op), LM_STATUS_OK);
    LM_CHECK_EQ(n.membership(1).state, static_cast<uint32_t>(LM_LEAVING));
    LM_CHECK_EQ(n.wait_operation(1, op, 5000), static_cast<uint32_t>(Status::DeadlineUnreachable));
    LM_CHECK_EQ(n.membership(1).state, static_cast<uint32_t>(LM_ACTIVE));
    LM_CHECK(n.ledger().find(n.id(1))->state == root::EntryState::Active);
    // Once nothing is pending the same DRAIN succeeds.
    drained = true;
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
    // IMMEDIATE leave right away.
    n.run_ms(6000);
    LM_CHECK_EQ(lm_leave(n.ctx(1), LM_LEAVE_IMMEDIATE, 0, &op), LM_STATUS_OK);
    LM_CHECK_EQ(n.wait_operation(1, op, 5000), 0u);
    LM_CHECK_EQ(n.membership(1).state, static_cast<uint32_t>(LM_UNASSIGNED));
    // Leave of a non-member is NOT_FOUND (nothing to leave).
    LM_CHECK_EQ(lm_leave(n.ctx(1), LM_LEAVE_IMMEDIATE, 0, &op), LM_STATUS_NOT_FOUND);
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
    LM_CHECK_EQ(n.wait_operation(1, op, 30000), static_cast<uint32_t>(Status::AuthRejected));
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

// A ledger record as documented in src/root/ledger.cpp: confirmed u8 | assignment | membership | device |
// request 16 | hash 32 (no credential: a departed/foreign member of the table).
void craft_entry(SimStore &store, std::size_t slot, const DeviceId &dev, root::EntryState st, uint64_t assignment,
                 uint64_t membership) {
    std::array<uint8_t, 97> p{};
    Writer w{MutByteView{p}};
    w.u8(1);
    w.u64be(assignment);
    w.u64be(membership);
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

const char *mode_name(CutMode m) { return m == CutMode::Before ? "before" : (m == CutMode::Torn ? "torn" : "after"); }

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
    unsigned iterations = 0;
    unsigned recovered = 0;
    for (const unsigned target : {1U, 0U}) { // device store, then root store
        for (const CutMode mode : {CutMode::Before, CutMode::Torn, CutMode::After}) {
            for (uint64_t k = 0; k < 40; ++k) {
                const SweepOutcome r = run_cut(target, k, mode);
                if (!r.fired) {
                    break; // fewer store calls than k in a join: the sweep of this node/mode is complete
                }
                ++iterations;
                recovered += r.joined_after_cut ? 1 : 0;
                if (!r.ok) {
                    std::fprintf(stderr, "  sweep node=%s mode=%s k=%llu: %s\n", target == 0 ? "root" : "device",
                                 mode_name(mode), static_cast<unsigned long long>(k), r.why.c_str());
                }
                LM_CHECK(r.ok);
            }
        }
    }
    std::printf("  [measure] power-cut sweep: %u cut points, %u converged to ACTIVE+confirmed after the restart\n",
                iterations, recovered);
    LM_CHECK(iterations >= 30);
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
    unsigned iterations = 0;
    for (const unsigned target : {1U, 0U}) {
        for (const CutMode mode : {CutMode::Before, CutMode::Torn, CutMode::After}) {
            for (uint64_t k = 0; k < 40; ++k) {
                const SweepOutcome r = run_leave_cut(target, k, mode);
                if (!r.fired) {
                    break;
                }
                ++iterations;
                if (!r.ok) {
                    std::fprintf(stderr, "  leave sweep node=%s mode=%s k=%llu: %s\n", target == 0 ? "root" : "device",
                                 mode_name(mode), static_cast<unsigned long long>(k), r.why.c_str());
                }
                LM_CHECK(r.ok);
            }
        }
    }
    std::printf("  [measure] leave power-cut sweep: %u cut points\n", iterations);
    LM_CHECK(iterations >= 20);
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

LM_TEST("measure: sizeof of the join/membership state") {
    std::printf("  [measure] sizeof(Membership)=%zu Ledger=%zu (entries %zu x %zu) JoinPipe=%zu Exchange=%zu LinkLayer=%zu\n"
                "            LocalIdentity=%zu Engine=%zu lm_context=%zu Neighbor=%zu\n",
                sizeof(member::Membership), sizeof(root::Ledger), root::k_ledger_slots, sizeof(root::Entry),
                sizeof(member::JoinPipe), sizeof(link::Exchange), sizeof(link::LinkLayer), sizeof(member::LocalIdentity),
                sizeof(Engine), sizeof(lm_context), sizeof(link::Neighbor));
}

LM_TEST_MAIN()
