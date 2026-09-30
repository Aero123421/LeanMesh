// meshsim commands of the delivery slice (S9): static routes (the route resolver is the mesh
// slice's job), the root clock estimate, lm_send / operation queries / cancel / next message /
// application result through the public C API, and delivery counters. Bench only.
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <map>
#include <vector>

#include "control.hpp"
#include "port/sim/sim_node.hpp"

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

bool unhex(const std::string &s, std::vector<uint8_t> &out) {
    out.clear();
    if (s == "-") { // "-" is the empty payload on a whitespace-separated command line
        return true;
    }
    if (s.size() % 2 != 0) {
        return false;
    }
    for (std::size_t i = 0; i < s.size(); i += 2) {
        unsigned v = 0;
        if (std::sscanf(s.c_str() + i, "%2x", &v) != 1) {
            return false;
        }
        out.push_back(static_cast<uint8_t>(v));
    }
    return true;
}

std::string status_json(lm_status_t s, uint64_t op = 0) {
    char buf[128];
    std::snprintf(buf, sizeof buf, "{\"ok\":%s,\"status\":\"%s\",\"operation\":%" PRIu64 "}", s == 0 ? "true" : "false",
                  lm::status_name(static_cast<lm::Status>(s)), op);
    return buf;
}

bool running(Sim &sim, uint16_t i) { return sim.world.node(i).ctx() != nullptr; }

// The message reference of the last MESSAGE event each node took: `msg-report` answers it.
std::map<uint16_t, lm_message_ref_t> &last_message() {
    static std::map<uint16_t, lm_message_ref_t> m;
    return m;
}

} // namespace

// route <node> <dest_node> <hop_node>...   hops are node indices, the last one must be dest_node
std::string cmd_route(Sim &sim, const Args &a) {
    uint16_t i = 0;
    uint16_t dest = 0;
    if (a.size() < 4 || !parse_node(sim, a[1], i) || !parse_node(sim, a[2], dest) || !running(sim, i) ||
        a.size() - 3 > lm::wire::k_max_path) {
        return error("usage: route <node> <dest_node> <hop_node>... (nodes booted, started, members)");
    }
    lm::delivery::PathSpec ps;
    for (std::size_t k = 3; k < a.size(); ++k) {
        uint16_t hop = 0;
        if (!parse_node(sim, a[k], hop) || !running(sim, hop)) {
            return error("bad hop node");
        }
        ps.path[k - 3] = sim.world.node(hop).ctx()->engine.identity().member().address.value();
    }
    ps.len = static_cast<uint8_t>(a.size() - 3);
    ps.dest = lm::ShortAddr{ps.path[ps.len - 1U]};
    lm::Engine &e = sim.world.node(i).ctx()->engine;
    ps.term = e.identity().term(); // the node's current root term (ARCH2-D1)
    ps.revision = lm::PathRevision{1};
    const lm::Status st = e.delivery().install_route(sim.world.node(dest).ctx()->engine.identity().self(), ps,
                                                     lm::MonoTime::never());
    sim.world.node(i).notify();
    return status_json(static_cast<lm_status_t>(st));
}

// root-time <node|all> <term> <ms>   the node's root clock estimate (exact reading, as if just synced)
std::string cmd_root_time(Sim &sim, const Args &a) {
    uint64_t term = 0;
    uint64_t ms = 0;
    if (a.size() != 4 || !parse_u64(a[2], term) || !parse_u64(a[3], ms)) {
        return error("usage: root-time <node|all> <term> <ms>");
    }
    for (uint16_t i = 0; i < sim.world.node_count(); ++i) {
        if (a[1] != "all" && a[1] != std::to_string(i)) {
            continue;
        }
        if (!running(sim, i)) {
            continue;
        }
        lm::RootTimeBound b;
        b.term = lm::RootTerm{static_cast<uint32_t>(term)};
        b.earliest_ms = b.latest_ms = ms;
        b.valid = true;
        sim.world.node(i).ctx()->engine.set_root_time(b, sim.world.node(i).clock.now());
        sim.world.node(i).notify();
    }
    return "{\"ok\":true}";
}

// send <node> <dest_node|root> <best_effort|received|applied> <volatile|durable> <port> <root_term>
//      <expires_root_ms|0> <hex|->
std::string cmd_send(Sim &sim, const Args &a) {
    uint16_t i = 0;
    uint16_t dest = 0;
    uint64_t port = 0;
    uint64_t term = 0;
    uint64_t expires = 0;
    std::vector<uint8_t> payload;
    const bool root = a.size() > 2 && a[2] == "root";
    if (a.size() != 9 || !parse_node(sim, a[1], i) || (!root && !parse_node(sim, a[2], dest)) || !running(sim, i) ||
        !parse_u64(a[5], port) || !parse_u64(a[6], term) || !parse_u64(a[7], expires) || !unhex(a[8], payload)) {
        return error("usage: send <node> <dest_node|root> <best_effort|received|applied> <volatile|durable> <port> "
                     "<root_term> <expires_root_ms|0> <hex|->");
    }
    lm_send_request_t rq{};
    rq.struct_size = sizeof(rq);
    rq.abi_version = LM_ABI_VERSION;
    rq.destination.kind = root ? LM_DEST_ROOT_APP : LM_DEST_NODE;
    if (!root) {
        std::memcpy(rq.destination.node.bytes, sim.world.node(dest).ctx()->engine.identity().self().bytes.data(), 32);
    }
    rq.app_port = static_cast<uint16_t>(port);
    rq.delivery = a[3] == "best_effort" ? LM_BEST_EFFORT : (a[3] == "received" ? LM_RECEIVED : LM_APPLIED);
    rq.storage = a[4] == "durable" ? LM_DURABLE : LM_VOLATILE;
    rq.priority = LM_PRIORITY_NORMAL;
    rq.root_term = static_cast<uint32_t>(term);
    rq.expires_root_ms = expires;
    lm_operation_id_t op = 0;
    const lm_status_t st = lm_send(sim.world.node(i).ctx(), &rq, payload.data(), payload.size(), &op);
    sim.world.node(i).notify();
    return status_json(st, op);
}

// op <node> <operation_id>
std::string cmd_op(Sim &sim, const Args &a) {
    uint16_t i = 0;
    uint64_t id = 0;
    if (a.size() != 3 || !parse_node(sim, a[1], i) || !running(sim, i) || !parse_u64(a[2], id)) {
        return error("usage: op <node> <operation_id>");
    }
    lm_operation_t o{};
    o.struct_size = sizeof(o);
    o.abi_version = LM_ABI_VERSION;
    const lm_status_t st = lm_get_operation(sim.world.node(i).ctx(), id, &o);
    if (st != LM_STATUS_OK) {
        return status_json(st, id);
    }
    char buf[512];
    std::snprintf(buf, sizeof buf,
                  "{\"ok\":true,\"operation\":%" PRIu64 ",\"phase\":%u,\"outcome\":%u,\"reason\":%u,\"evidence_bits\":%u,"
                  "\"message_id\":\"%s\",\"intent_hash\":\"%s\"}",
                  o.operation_id, o.phase, o.outcome, o.reason, o.evidence_bits,
                  hex(lm::ByteView{o.message_id.bytes, 16}).c_str(), hex(lm::ByteView{o.intent_hash, 32}).c_str());
    return buf;
}

// msg-next <node>   the next MESSAGE / OPERATION event with its payload (STARTED etc. are skipped)
std::string cmd_msg_next(Sim &sim, const Args &a) {
    uint16_t i = 0;
    if (a.size() != 2 || !parse_node(sim, a[1], i) || !running(sim, i)) {
        return error("usage: msg-next <node>");
    }
    for (int guard = 0; guard < 64; ++guard) {
        lm_event_t ev{};
        ev.struct_size = sizeof(ev);
        ev.abi_version = LM_ABI_VERSION;
        std::vector<uint8_t> buf(4200); // a 4096 B object fits (FIX11-D11)
        size_t req = 0;
        const lm_status_t st = lm_next_event(sim.world.node(i).ctx(), &ev, buf.data(), buf.size(), &req);
        if (st != LM_STATUS_OK) {
            return "{\"ok\":true,\"event\":null}";
        }
        if (ev.kind != LM_EVENT_MESSAGE && ev.kind != LM_EVENT_OPERATION) {
            continue;
        }
        if (ev.kind == LM_EVENT_MESSAGE) {
            lm_message_ref_t ref{};
            ref.origin = ev.peer;
            ref.assignment_generation = ev.origin_assignment_generation;
            ref.id = ev.message_id;
            std::memcpy(ref.intent_hash, ev.intent_hash, 32);
            last_message()[i] = ref;
        }
        char head[256];
        std::snprintf(head, sizeof head, "{\"ok\":true,\"event\":{\"kind\":%u,\"reason\":%u,\"operation\":%" PRIu64
                                         ",\"port\":%u,\"peer\":\"",
                      ev.kind, ev.reason, ev.operation_id, ev.app_port);
        return std::string(head) + hex(lm::ByteView{ev.peer.bytes, 32}) + "\",\"message_id\":\"" +
               hex(lm::ByteView{ev.message_id.bytes, 16}) + "\",\"payload\":\"" + hex(lm::ByteView{buf.data(), req}) +
               "\"}}";
    }
    return "{\"ok\":true,\"event\":null}";
}

// msg-report <node> <applied|rejected|pending> <hex|->   answers the last message taken by msg-next
std::string cmd_msg_report(Sim &sim, const Args &a) {
    uint16_t i = 0;
    std::vector<uint8_t> result;
    if (a.size() != 4 || !parse_node(sim, a[1], i) || !running(sim, i) || !unhex(a[3], result) ||
        (a[2] != "applied" && a[2] != "rejected" && a[2] != "pending") || last_message().count(i) == 0) {
        return error("usage: msg-report <node> <applied|rejected|pending> <hex|-> (after msg-next)");
    }
    const uint32_t outcome = a[2] == "applied" ? LM_OUTCOME_APPLIED : (a[2] == "rejected" ? LM_OUTCOME_REJECTED : LM_OUTCOME_PENDING);
    lm_operation_id_t op = 0;
    const lm_message_ref_t ref = last_message()[i];
    const lm_status_t st =
        lm_report_application_result(sim.world.node(i).ctx(), &ref, outcome, result.data(), result.size(), &op);
    sim.world.node(i).notify();
    return status_json(st, op);
}

// msg-cancel <node> <operation_id>
std::string cmd_msg_cancel(Sim &sim, const Args &a) {
    uint16_t i = 0;
    uint64_t id = 0;
    if (a.size() != 3 || !parse_node(sim, a[1], i) || !running(sim, i) || !parse_u64(a[2], id)) {
        return error("usage: msg-cancel <node> <operation_id>");
    }
    const lm_status_t st = lm_cancel(sim.world.node(i).ctx(), id);
    sim.world.node(i).notify();
    return status_json(st, id);
}

// delivery <node>   counters of the delivery module (not device diagnostics)
std::string cmd_delivery(Sim &sim, const Args &a) {
    uint16_t i = 0;
    if (a.size() != 2 || !parse_node(sim, a[1], i) || !running(sim, i)) {
        return error("usage: delivery <node>");
    }
    lm::delivery::Delivery &d = sim.world.node(i).ctx()->engine.delivery();
    const lm::delivery::DeliveryStats &s = d.stats();
    const lm::delivery::HopStats &h = d.hop_stats();
    char buf[1024];
    std::snprintf(buf, sizeof buf,
                  "{\"ok\":true,\"ready\":%s,\"accepted\":%" PRIu64 ",\"rx_data\":%" PRIu64 ",\"rx_forward\":%" PRIu64
                  ",\"rx_dup_link\":%" PRIu64 ",\"rx_dup_end\":%" PRIu64 ",\"rx_busy\":%" PRIu64 ",\"rx_refused\":%" PRIu64
                  ",\"delivered\":%" PRIu64 ",\"receipts_sent\":%" PRIu64 ",\"receipts_rx\":%" PRIu64
                  ",\"rounds\":%" PRIu64 ",\"hop_frames\":%" PRIu64 ",\"hop_retransmits\":%" PRIu64
                  ",\"hop_rf_failed\":%" PRIu64 ",\"hop_local_busy\":%" PRIu64 ",\"hop_ack_busy\":%" PRIu64
                  ",\"hop_early_acks\":%" PRIu64 ",\"end_completed\":%" PRIu64 ",\"end_failed\":%" PRIu64
                  ",\"journal_live\":%zu}",
                  d.ready() ? "true" : "false", s.accepted, s.rx_data, s.rx_forward, s.rx_dup_link, s.rx_dup_end,
                  s.rx_busy, s.rx_refused, s.delivered, s.receipts_sent, s.receipts_rx, s.rounds, h.frames,
                  h.retransmits, h.rf_failed, h.local_busy, h.ack_busy, h.early_acks, d.end_stats().completed,
                  d.end_stats().failed, d.durable().live_count());
    return buf;
}

} // namespace meshsim
