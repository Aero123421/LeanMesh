// meshsim commands of the join slice (S8): grant a device (TEST-ONLY fleet issuer signs its ticket and the
// root's expected entry), run join/resume/leave through the public C API, inspect membership and the root
// ledger, and inject power cuts at the store's durable boundaries. Bench only.
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <vector>

#include "core/wire/cbor.hpp"
#include "control.hpp"
#include "fleet.hpp"
#include "port/sim/sim_node.hpp"
#include "security/crypto.hpp"

namespace meshsim {

namespace {

std::string hex(lm::ByteView v) {
    static const char *const k = "0123456789abcdef";
    std::string s;
    for (uint8_t b : v) {
        s += k[b >> 4U];
        s += k[b & 15U];
    }
    return s;
}

std::string status_json(lm_status_t s, uint64_t op = 0) {
    char buf[128];
    std::snprintf(buf, sizeof buf, "{\"ok\":%s,\"status\":\"%s\",\"operation\":%" PRIu64 "}", s == 0 ? "true" : "false",
                  lm::status_name(static_cast<lm::Status>(s)), op);
    return buf;
}

lm_request_id_t request_id(uint64_t seed) {
    lm_request_id_t r{};
    for (std::size_t i = 0; i < 16; ++i) {
        r.bytes[i] = static_cast<uint8_t>(seed + i);
    }
    return r;
}

bool started(Sim &sim, uint16_t i) { return sim.world.node(i).ctx() != nullptr; }

} // namespace

std::string cmd_join_mode(Sim &sim, const Args &a) {
    if (a.size() != 2 || !started(sim, 0) || (a[1] != "closed" && a[1] != "external" && a[1] != "preapproved")) {
        return error("usage: join-mode closed|external|preapproved (root must be booted)");
    }
    sim.world.node(0).ctx()->engine.ledger().set_join_mode(a[1] == "closed"     ? lm::root::JoinMode::Closed
                                                            : a[1] == "external" ? lm::root::JoinMode::External
                                                                                 : lm::root::JoinMode::Preapproved);
    return "{\"ok\":true}";
}

// grant <node> <generation> <revision>: a fleet-signed AssignmentTicket for the node (installed on the node)
// and a fleet-signed ExpectedSet page granting exactly that ticket (installed on the root).
std::string cmd_grant(Sim &sim, const Args &a) {
    uint16_t i = 0;
    uint64_t gen = 0;
    uint64_t rev = 0;
    if (a.size() != 4 || !parse_node(sim, a[1], i) || i == 0 || !parse_u64(a[2], gen) || gen < 1 ||
        !parse_u64(a[3], rev) || rev < 1 || !started(sim, i) || !started(sim, 0)) {
        return error("usage: grant <node> <generation >= 1> <expected revision >= 1> (both nodes started)");
    }
    lm::fleet::Network &net = fleet_network(sim);
    // The ticket binds the device's *provisioned* DeviceCredential (signatures are randomised: take it from the node).
    const lm::member::LocalIdentity &ident = sim.world.node(i).ctx()->engine.identity();
    lm::fleet::Kit kit;
    kit.id = ident.self();
    kit.device_cose.assign(ident.device_cose().begin(), ident.device_cose().end());
    const lm::fleet::Bytes ticket = net.fleet.ticket(kit, lm::DomainId{}, net.domain, net.delegation_cose, 0, gen);
    lm::Sha256Digest grant{};
    if (lm::sec::sha256(lm::ByteView{ticket.data(), ticket.size()}, grant) != lm::Status::Ok) {
        return error("hash failed");
    }
    std::array<uint8_t, 512> buf{};
    lm::wire::CborWriter w{lm::MutByteView{buf}};
    w.array(4);
    w.uint(0);
    w.uint(1);
    w.bytes(lm::ByteView{grant});
    w.array(1);
    w.array(4);
    w.bytes(kit.id.view());
    w.uint(gen);
    w.bytes(lm::ByteView{grant});
    w.boolean(true);
    if (w.finish() != lm::Status::Ok) {
        return error("page encode failed");
    }
    lm::member::Envelope env;
    env.type = lm::member::k_type_expected_set;
    env.domain = net.domain;
    env.revision = rev;
    env.issuer = net.fleet.trust().key_id;
    env.request.bytes[0] = static_cast<uint8_t>(rev);
    const lm::fleet::Bytes page = net.fleet.sign(env, w.written());
    lm_operation_id_t op_t = 0;
    lm_operation_id_t op_e = 0;
    const lm_status_t st = lm_install_control(sim.world.node(i).ctx(), 3, ticket.data(), ticket.size(), &op_t);
    if (st != LM_STATUS_OK) {
        return status_json(st);
    }
    const lm_status_t se = lm_install_control(sim.world.node(0).ctx(), 5, page.data(), page.size(), &op_e);
    sim.world.node(i).notify();
    sim.world.node(0).notify();
    char out[192];
    std::snprintf(out, sizeof out, "{\"ok\":%s,\"status\":\"%s\",\"ticket_op\":%" PRIu64 ",\"expected_op\":%" PRIu64 "}",
                  se == LM_STATUS_OK ? "true" : "false", lm::status_name(static_cast<lm::Status>(se)), op_t, op_e);
    return out;
}

// join <node> <request seed> [new|resume] [budget_ms]
std::string cmd_join(Sim &sim, const Args &a) {
    uint16_t i = 0;
    uint64_t seed = 0;
    uint64_t budget = 0;
    if (a.size() < 3 || a.size() > 5 || !parse_node(sim, a[1], i) || !parse_u64(a[2], seed) || !started(sim, i) ||
        (a.size() > 3 && a[3] != "new" && a[3] != "resume") || (a.size() > 4 && !parse_u64(a[4], budget))) {
        return error("usage: join <node> <request seed> [new|resume] [budget_ms]");
    }
    lm_join_request_t r{};
    r.struct_size = sizeof(r);
    r.abi_version = LM_ABI_VERSION;
    r.request_id = request_id(seed);
    r.mode = a.size() > 3 && a[3] == "resume" ? LM_JOIN_RESUME : LM_JOIN_NEW;
    r.search_budget_ms = static_cast<uint32_t>(budget);
    lm_operation_id_t op = 0;
    const lm_status_t s = lm_join(sim.world.node(i).ctx(), &r, &op);
    sim.world.node(i).notify();
    return status_json(s, op);
}

// leave <node> drain|immediate <deadline_ms>
std::string cmd_leave(Sim &sim, const Args &a) {
    uint16_t i = 0;
    uint64_t deadline = 0;
    if (a.size() != 4 || !parse_node(sim, a[1], i) || !started(sim, i) || (a[2] != "drain" && a[2] != "immediate") ||
        !parse_u64(a[3], deadline)) {
        return error("usage: leave <node> drain|immediate <deadline_ms>");
    }
    lm_operation_id_t op = 0;
    const lm_status_t s = lm_leave(sim.world.node(i).ctx(), a[2] == "drain" ? LM_LEAVE_DRAIN : LM_LEAVE_IMMEDIATE,
                                   static_cast<uint32_t>(deadline), &op);
    sim.world.node(i).notify();
    return status_json(s, op);
}

std::string cmd_membership(Sim &sim, const Args &a) {
    uint16_t i = 0;
    if (a.size() != 2 || !parse_node(sim, a[1], i) || !started(sim, i)) {
        return error("usage: membership <node>");
    }
    lm_membership_t m{};
    m.struct_size = sizeof(m);
    m.abi_version = LM_ABI_VERSION;
    const lm_status_t s = lm_membership_get(sim.world.node(i).ctx(), &m);
    if (s != LM_STATUS_OK) {
        return status_json(s);
    }
    lm::Engine &e = sim.world.node(i).ctx()->engine;
    const bool joiner = e.config().role != lm::Role::Root; // the root holds no joiner side (ADR-002 P8)
    char buf[512];
    std::snprintf(buf, sizeof buf,
                  "{\"ok\":true,\"state\":%u,\"reason\":%u,\"assignment\":%" PRIu64 ",\"membership\":%" PRIu64
                  ",\"device\":\"%s\",\"domain\":\"%s\",\"prepared_record\":%s,\"confirm_pending\":%s,"
                  "\"phase\":%u}",
                  m.state, m.reason, m.assignment_generation, m.membership_generation,
                  hex(lm::ByteView{m.device.bytes, 32}).c_str(), hex(lm::ByteView{m.domain.bytes, 16}).c_str(),
                  joiner && e.membership().prepared_record() ? "true" : "false",
                  joiner && e.membership().confirm_pending() ? "true" : "false",
                  joiner ? static_cast<unsigned>(e.membership().phase()) : 0U);
    return buf;
}

std::string cmd_ledger(Sim &sim, const Args &a) {
    if (a.size() != 1 || !started(sim, 0)) {
        return error("usage: ledger (root must be booted)");
    }
    const lm::root::Ledger &l = sim.world.node(0).ctx()->engine.ledger();
    static const char *const k[] = {"free", "expected", "prepared", "active", "left", "aborted", "blocked"};
    std::string out = std::string("{\"ok\":true,\"ready\":") + (l.ready() ? "true" : "false") + ",\"entries\":[";
    bool first = true;
    for (std::size_t s = 0; s < lm::root::k_ledger_slots; ++s) {
        const lm::root::Entry &e = l.entry(s);
        if (e.state == lm::root::EntryState::Free) {
            continue;
        }
        char buf[320];
        std::snprintf(buf, sizeof buf,
                      "%s{\"device\":\"%s\",\"state\":\"%s\",\"address\":%u,\"assignment\":%" PRIu64
                      ",\"membership\":%" PRIu64 ",\"confirmed\":%s}",
                      first ? "" : ",", hex(e.device.view()).c_str(), k[static_cast<unsigned>(e.state)], e.address.value(),
                      e.assignment, e.membership, e.confirmed ? "true" : "false");
        out += buf;
        first = false;
    }
    char tail[256];
    std::snprintf(tail, sizeof tail,
                  "],\"prepared\":%" PRIu64 ",\"activated\":%" PRIu64 ",\"confirmed\":%" PRIu64 ",\"refused\":%" PRIu64
                  ",\"conflicts\":%" PRIu64 ",\"expected_revision\":%" PRIu64 "}",
                  l.stats().prepared, l.stats().activated, l.stats().confirmed, l.stats().refused, l.stats().conflicts,
                  l.expected_revision());
    return out + tail;
}

// events <node>: drains the application event queue as JSON.
std::string cmd_events(Sim &sim, const Args &a) {
    uint16_t i = 0;
    if (a.size() != 2 || !parse_node(sim, a[1], i) || !started(sim, i)) {
        return error("usage: events <node>");
    }
    std::string out = "{\"ok\":true,\"events\":[";
    bool first = true;
    for (int n = 0; n < 64; ++n) {
        lm_event_t ev{};
        ev.struct_size = sizeof(ev);
        ev.abi_version = LM_ABI_VERSION;
        if (lm_next_event(sim.world.node(i).ctx(), &ev, nullptr, 0, nullptr) != LM_STATUS_OK) {
            break;
        }
        char buf[160];
        std::snprintf(buf, sizeof buf, "%s{\"kind\":%u,\"reason\":%u,\"operation\":%" PRIu64 "}", first ? "" : ",", ev.kind,
                      ev.reason, ev.operation_id);
        out += buf;
        first = false;
    }
    return out + "]}";
}

// store-cut <node> <k> before|torn|after: the k-th mutating store call from now on (0 = next) is cut.
std::string cmd_store_cut(Sim &sim, const Args &a) {
    uint16_t i = 0;
    uint64_t k = 0;
    if (a.size() != 4 || !parse_node(sim, a[1], i) || !parse_u64(a[2], k) ||
        (a[3] != "before" && a[3] != "torn" && a[3] != "after")) {
        return error("usage: store-cut <node> <k> before|torn|after");
    }
    lm::sim::SimStore &st = sim.world.node(i).store;
    st.arm_cut(st.mutating_ops() + k, a[3] == "before" ? lm::sim::CutMode::Before
                                       : a[3] == "torn" ? lm::sim::CutMode::Torn
                                                        : lm::sim::CutMode::After);
    return "{\"ok\":true}";
}

// store-fired <node>: has the armed cut fired (the node's store is dead until store-restore)?
std::string cmd_store_fired(Sim &sim, const Args &a) {
    uint16_t i = 0;
    if (a.size() != 2 || !parse_node(sim, a[1], i)) {
        return error("usage: store-fired <node>");
    }
    return std::string("{\"ok\":true,\"cut_fired\":") + (sim.world.node(i).store.cut_fired() ? "true" : "false") + "}";
}

// store-restore <node>: power comes back (after `power-cut`): the store answers again. Reports whether a
// cut fired since it was armed.
std::string cmd_store_restore(Sim &sim, const Args &a) {
    uint16_t i = 0;
    if (a.size() != 2 || !parse_node(sim, a[1], i)) {
        return error("usage: store-restore <node>");
    }
    lm::sim::SimStore &st = sim.world.node(i).store;
    const bool fired = st.cut_fired();
    st.power_restore();
    return std::string("{\"ok\":true,\"cut_fired\":") + (fired ? "true" : "false") + "}";
}

} // namespace meshsim
