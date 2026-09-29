// meshsim commands of the scheduler slice (S14): a burst generator for one node and the scheduler /
// admission counters. Bench only: the sends go through the public lm_send like an application's.
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <vector>

#include "control.hpp"
#include "port/sim/sim_node.hpp"

namespace meshsim {

// flood <node> <dest_node> <count> <bulk|normal|urgent> <bytes> <root_term> <expires_root_ms> [latest_key]
// `count` BEST_EFFORT VOLATILE sends to port 100 (LATEST with `latest_key` when given; the payload
// starts with the send index). Answers how many were accepted and why the others were not.
std::string cmd_flood(Sim &sim, const Args &a) {
    uint16_t i = 0;
    uint16_t dest = 0;
    uint64_t count = 0;
    uint64_t bytes = 0;
    uint64_t term = 0;
    uint64_t expires = 0;
    uint64_t key = 0;
    const bool latest = a.size() == 9;
    if ((a.size() != 8 && a.size() != 9) || !parse_node(sim, a[1], i) || !parse_node(sim, a[2], dest) ||
        !parse_u64(a[3], count) || !parse_u64(a[5], bytes) || !parse_u64(a[6], term) || !parse_u64(a[7], expires) ||
        (latest && !parse_u64(a[8], key)) || sim.world.node(i).ctx() == nullptr || count > 4096 || bytes > 134) {
        return error("usage: flood <node> <dest_node> <count> <bulk|normal|urgent> <bytes> <root_term> "
                     "<expires_root_ms> [latest_key]");
    }
    lm_send_request_t rq{};
    rq.struct_size = sizeof(rq);
    rq.abi_version = LM_ABI_VERSION;
    rq.destination.kind = LM_DEST_NODE;
    std::memcpy(rq.destination.node.bytes, sim.world.node(dest).ctx()->engine.identity().self().bytes.data(), 32);
    rq.app_port = 100;
    rq.delivery = LM_BEST_EFFORT;
    rq.storage = LM_VOLATILE;
    rq.priority = a[4] == "bulk" ? LM_PRIORITY_BULK : (a[4] == "urgent" ? LM_PRIORITY_URGENT : LM_PRIORITY_NORMAL);
    rq.queue_mode = latest ? LM_LATEST : LM_FIFO;
    rq.coalesce_key = latest ? key : 0;
    rq.root_term = static_cast<uint32_t>(term);
    rq.expires_root_ms = expires;
    uint64_t accepted = 0;
    uint64_t first_op = 0;
    uint64_t last_op = 0;
    lm_status_t last_refusal = LM_STATUS_OK;
    uint64_t refused = 0;
    std::vector<uint8_t> payload(bytes, 0);
    for (uint64_t n = 0; n < count; ++n) {
        if (!payload.empty()) {
            payload[0] = static_cast<uint8_t>(n);
        }
        lm_operation_id_t op = 0;
        const lm_status_t st = lm_send(sim.world.node(i).ctx(), &rq, payload.data(), payload.size(), &op);
        if (st == LM_STATUS_OK) {
            first_op = accepted == 0 ? op : first_op;
            last_op = op;
            ++accepted;
        } else {
            ++refused;
            last_refusal = st;
        }
    }
    sim.world.node(i).notify();
    char buf[256];
    std::snprintf(buf, sizeof buf,
                  "{\"ok\":true,\"accepted\":%" PRIu64 ",\"refused\":%" PRIu64 ",\"last_refusal\":\"%s\","
                  "\"first_op\":%" PRIu64 ",\"last_op\":%" PRIu64 "}",
                  accepted, refused, lm::status_name(static_cast<lm::Status>(last_refusal)), first_op, last_op);
    return buf;
}

// sched <node>   scheduler classes (frames, airtime, refusals), reserve/yield picks, tokens, TX pool
std::string cmd_sched(Sim &sim, const Args &a) {
    uint16_t i = 0;
    if (a.size() != 2 || !parse_node(sim, a[1], i) || sim.world.node(i).ctx() == nullptr) {
        return error("usage: sched <node>");
    }
    lm::Engine &e = sim.world.node(i).ctx()->engine;
    const lm::sched::Stats &s = e.sched().stats();
    const lm::delivery::DeliveryStats &d = e.delivery().stats();
    char buf[900];
    int n = std::snprintf(buf, sizeof buf, "{\"ok\":true,\"tokens_us\":%" PRId64 ",\"pool_in_use\":%zu,\"classes\":[",
                          e.sched().tokens_us(sim.world.node(i).clock.now()), e.frames().in_use());
    for (std::size_t c = 0; c < lm::sched::k_classes; ++c) {
        n += std::snprintf(buf + n, sizeof buf - static_cast<std::size_t>(n),
                           "%s{\"frames\":%" PRIu32 ",\"airtime_us\":%" PRIu64 ",\"refused\":%" PRIu32 "}",
                           c == 0 ? "" : ",", s.cls[c].frames, s.cls[c].airtime_us, s.cls[c].refused);
    }
    std::snprintf(buf + n, sizeof buf - static_cast<std::size_t>(n),
                  "],\"reserve_picks\":%" PRIu32 ",\"urgent_yields\":%" PRIu32 ",\"token_waits\":%" PRIu32
                  ",\"ack_charged_us\":%" PRIu64 ",\"superseded\":%" PRIu64 ",\"admit_refused\":%" PRIu64 "}",
                  s.reserve_picks, s.urgent_yields, s.token_waits, s.ack_charged_us, d.superseded, d.admit_refused);
    return buf;
}

} // namespace meshsim
