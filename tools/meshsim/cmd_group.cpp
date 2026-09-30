// meshsim commands of the group slice (S15): the root's group registry, a send to a group from any node,
// progress and per-target results, cancel. All through the public C API like an application; the
// per-target application side is msg-next / msg-report of the delivery slice. Bench only.
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "control.hpp"
#include "port/sim/sim_node.hpp"

namespace meshsim {

namespace {

std::string hex(const uint8_t *p, std::size_t n) {
    static const char *const k = "0123456789abcdef";
    std::string s;
    for (std::size_t i = 0; i < n; ++i) {
        s += k[p[i] >> 4U];
        s += k[p[i] & 15U];
    }
    return s;
}

std::string status_json(lm_status_t s, uint64_t op = 0) {
    char buf[128];
    std::snprintf(buf, sizeof buf, "{\"ok\":%s,\"status\":\"%s\",\"operation\":%" PRIu64 "}", s == 0 ? "true" : "false",
                  lm::status_name(static_cast<lm::Status>(s)), op);
    return buf;
}

// "3,5-9" or "all" (every node but the root, node 0)
bool node_list(Sim &sim, const std::string &s, std::vector<uint16_t> &out) {
    if (s == "all") {
        for (uint16_t i = 1; i < sim.world.node_count(); ++i) {
            out.push_back(i);
        }
        return true;
    }
    std::size_t pos = 0;
    while (pos < s.size()) {
        const std::size_t end = s.find(',', pos);
        const std::string part = s.substr(pos, end == std::string::npos ? std::string::npos : end - pos);
        const std::size_t dash = part.find('-');
        uint16_t a = 0;
        uint16_t b = 0;
        if (!parse_node(sim, part.substr(0, dash), a) ||
            !parse_node(sim, dash == std::string::npos ? part : part.substr(dash + 1), b) || b < a) {
            return false;
        }
        for (uint16_t i = a; i <= b; ++i) {
            out.push_back(i);
        }
        pos = end == std::string::npos ? s.size() : end + 1;
    }
    return !out.empty();
}

bool running(Sim &sim, uint16_t i) { return sim.world.node(i).ctx() != nullptr; }

} // namespace

// group-set <group_id> <expected_revision> <nodes>   the root (node 0) sets the members of a group
std::string cmd_group_set(Sim &sim, const Args &a) {
    uint64_t gid = 0;
    uint64_t rev = 0;
    std::vector<uint16_t> nodes;
    if (a.size() != 4 || !parse_u64(a[1], gid) || !parse_u64(a[2], rev) || !node_list(sim, a[3], nodes) || !running(sim, 0)) {
        return error("usage: group-set <group_id> <expected_revision> <nodes: 1,2,5-9|all> (root = node 0, started)");
    }
    std::vector<lm_device_id_t> ids(nodes.size());
    for (std::size_t k = 0; k < nodes.size(); ++k) {
        if (!running(sim, nodes[k])) {
            return error("member node is not started");
        }
        std::memcpy(ids[k].bytes, sim.world.node(nodes[k]).ctx()->engine.identity().self().bytes.data(), 32);
    }
    lm_operation_id_t op = 0;
    const lm_status_t st = lm_group_set(sim.world.node(0).ctx(), static_cast<uint32_t>(gid), rev, ids.data(), ids.size(), &op);
    sim.world.node(0).notify();
    return status_json(st, op);
}

// group-send <node> <group_id> <revision> <best_effort|received|applied> <root_term> <expires_root_ms> <bytes>
std::string cmd_group_send(Sim &sim, const Args &a) {
    uint16_t i = 0;
    uint64_t gid = 0;
    uint64_t rev = 0;
    uint64_t term = 0;
    uint64_t expires = 0;
    uint64_t bytes = 0;
    if (a.size() != 8 || !parse_node(sim, a[1], i) || !parse_u64(a[2], gid) || !parse_u64(a[3], rev) ||
        !parse_u64(a[5], term) || !parse_u64(a[6], expires) || !parse_u64(a[7], bytes) || bytes > 512 || !running(sim, i)) {
        return error("usage: group-send <node> <group_id> <revision> <best_effort|received|applied> <root_term> "
                     "<expires_root_ms> <bytes>");
    }
    lm_send_request_t rq{};
    rq.struct_size = sizeof(rq);
    rq.abi_version = LM_ABI_VERSION;
    rq.destination.kind = LM_DEST_GROUP;
    rq.destination.group_id = static_cast<uint32_t>(gid);
    rq.destination.group_revision = rev;
    rq.app_port = 100;
    rq.delivery = a[4] == "applied" ? LM_APPLIED : (a[4] == "received" ? LM_RECEIVED : LM_BEST_EFFORT);
    rq.storage = LM_VOLATILE;
    rq.priority = LM_PRIORITY_NORMAL;
    rq.queue_mode = LM_FIFO;
    rq.root_term = static_cast<uint32_t>(term);
    rq.expires_root_ms = expires;
    std::vector<uint8_t> payload(bytes, 0x47);
    lm_operation_id_t op = 0;
    const lm_status_t st = lm_send(sim.world.node(i).ctx(), &rq, payload.data(), payload.size(), &op);
    sim.world.node(i).notify();
    return status_json(st, op);
}

// group-progress <node> <operation>
std::string cmd_group_progress(Sim &sim, const Args &a) {
    uint16_t i = 0;
    uint64_t op = 0;
    if (a.size() != 3 || !parse_node(sim, a[1], i) || !parse_u64(a[2], op) || !running(sim, i)) {
        return error("usage: group-progress <node> <operation>");
    }
    lm_group_progress_t p{};
    p.struct_size = sizeof(p);
    p.abi_version = LM_ABI_VERSION;
    const lm_status_t st = lm_group_progress(sim.world.node(i).ctx(), op, &p);
    if (st != LM_STATUS_OK) {
        return status_json(st, op);
    }
    char buf[640];
    std::snprintf(buf, sizeof buf,
                  "{\"ok\":true,\"total\":%u,\"pending\":%u,\"submitted\":%u,\"received\":%u,\"applied\":%u,"
                  "\"rejected\":%u,\"expired\":%u,\"cancelled\":%u,\"indeterminate\":%u,\"superseded\":%u,"
                  "\"progress_revision\":%" PRIu64 ",\"token\":\"%s\",\"hash\":\"%s\"}",
                  p.total, p.pending, p.submitted, p.received, p.applied, p.rejected, p.expired, p.cancelled,
                  p.indeterminate, p.superseded, p.progress_revision, hex(p.snapshot_token, 16).c_str(),
                  hex(p.snapshot_hash, 32).c_str());
    return buf;
}

// group-targets <node> <operation> <offset>   one page (<= 16) of per-target results
std::string cmd_group_targets(Sim &sim, const Args &a) {
    uint16_t i = 0;
    uint64_t op = 0;
    uint64_t offset = 0;
    if (a.size() != 4 || !parse_node(sim, a[1], i) || !parse_u64(a[2], op) || !parse_u64(a[3], offset) || !running(sim, i)) {
        return error("usage: group-targets <node> <operation> <offset>");
    }
    lm_group_progress_t p{};
    p.struct_size = sizeof(p);
    p.abi_version = LM_ABI_VERSION;
    const lm_status_t ps = lm_group_progress(sim.world.node(i).ctx(), op, &p);
    if (ps != LM_STATUS_OK) {
        return status_json(ps, op);
    }
    std::vector<lm_group_target_t> page(16);
    size_t written = 0;
    uint32_t total = 0;
    const lm_status_t st = lm_group_targets(sim.world.node(i).ctx(), op, p.snapshot_token, static_cast<uint32_t>(offset),
                                            page.data(), page.size(), &written, &total);
    if (st != LM_STATUS_OK) {
        return status_json(st, op);
    }
    std::string out = "{\"ok\":true,\"total\":" + std::to_string(total) + ",\"targets\":[";
    for (std::size_t k = 0; k < written; ++k) {
        char buf[320];
        std::snprintf(buf, sizeof buf,
                      "%s{\"device\":\"%s\",\"assignment\":%" PRIu64 ",\"membership\":%" PRIu64
                      ",\"message_id\":\"%s\",\"phase\":%u,\"outcome\":%u,\"reason\":%u,\"evidence\":%u}",
                      k == 0 ? "" : ",", hex(page[k].device.bytes, 32).c_str(), page[k].assignment_generation,
                      page[k].membership_generation, hex(page[k].message_id.bytes, 16).c_str(), page[k].phase,
                      page[k].outcome, page[k].reason, page[k].evidence_bits);
        out += buf;
    }
    return out + "]}";
}

// group-cancel <node> <operation>
std::string cmd_group_cancel(Sim &sim, const Args &a) {
    uint16_t i = 0;
    uint64_t op = 0;
    if (a.size() != 3 || !parse_node(sim, a[1], i) || !parse_u64(a[2], op) || !running(sim, i)) {
        return error("usage: group-cancel <node> <operation>");
    }
    const lm_status_t st = lm_cancel(sim.world.node(i).ctx(), op);
    sim.world.node(i).notify();
    return status_json(st, op);
}

} // namespace meshsim
