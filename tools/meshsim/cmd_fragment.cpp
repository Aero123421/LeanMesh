// meshsim commands of the fragment slice (S12): messages and objects with a generated payload (a
// deterministic pattern instead of hex, so 4 KiB fits a command line), control objects to a device and
// their receiving sink, and fragment counters. Bench only.
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <vector>

#include "control.hpp"
#include "port/sim/sim_node.hpp"

namespace meshsim {

namespace {

std::vector<uint8_t> pattern(uint64_t seed, std::size_t len) {
    std::vector<uint8_t> b(len);
    for (std::size_t i = 0; i < len; ++i) {
        b[i] = static_cast<uint8_t>(seed * 31U + i * 7U + (i >> 8U));
    }
    return b;
}

bool running(Sim &sim, uint16_t i) { return sim.world.node(i).ctx() != nullptr; }

struct Control {
    std::array<uint8_t, 32> origin{};
    std::vector<uint8_t> payload;
};
std::map<uint16_t, std::deque<Control>> &inbox() {
    static std::map<uint16_t, std::deque<Control>> m;
    return m;
}

std::string hex32(const uint8_t *p) {
    static const char *const k = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < 32; ++i) {
        s += k[p[i] >> 4U];
        s += k[p[i] & 15U];
    }
    return s;
}

} // namespace

// gen-send <node> <dest_node> <best_effort|received|applied> <port> <root_term> <expires_root_ms> <len> <seed> <api|object>
std::string cmd_gen_send(Sim &sim, const Args &a) {
    uint16_t i = 0;
    uint16_t dest = 0;
    uint64_t port = 0;
    uint64_t term = 0;
    uint64_t expires = 0;
    uint64_t len = 0;
    uint64_t seed = 0;
    if (a.size() != 10 || !parse_node(sim, a[1], i) || !parse_node(sim, a[2], dest) || !running(sim, i) ||
        !parse_u64(a[4], port) || !parse_u64(a[5], term) || !parse_u64(a[6], expires) || !parse_u64(a[7], len) ||
        !parse_u64(a[8], seed) || len > 4200 || (a[9] != "api" && a[9] != "object")) {
        return error("usage: gen-send <node> <dest_node> <best_effort|received|applied> <port> <root_term> "
                     "<expires_root_ms> <len<=4200> <seed> <api|object>");
    }
    lm_send_request_t rq{};
    rq.struct_size = sizeof(rq);
    rq.abi_version = LM_ABI_VERSION;
    rq.destination.kind = LM_DEST_NODE;
    std::memcpy(rq.destination.node.bytes, sim.world.node(dest).ctx()->engine.identity().self().bytes.data(), 32);
    rq.app_port = static_cast<uint16_t>(port);
    rq.delivery = a[3] == "best_effort" ? LM_BEST_EFFORT : (a[3] == "received" ? LM_RECEIVED : LM_APPLIED);
    rq.storage = LM_VOLATILE;
    rq.priority = LM_PRIORITY_NORMAL;
    rq.root_term = static_cast<uint32_t>(term);
    rq.expires_root_ms = expires;
    const std::vector<uint8_t> payload = pattern(seed, len);
    lm_operation_id_t op = 0;
    const lm_status_t st = a[9] == "object" ? lm_send_object(sim.world.node(i).ctx(), &rq, payload.data(), payload.size(), &op)
                                            : lm_send(sim.world.node(i).ctx(), &rq, payload.data(), payload.size(), &op);
    sim.world.node(i).notify();
    char buf[160];
    std::snprintf(buf, sizeof buf, "{\"ok\":%s,\"status\":\"%s\",\"operation\":%" PRIu64 "}", st == 0 ? "true" : "false",
                  lm::status_name(static_cast<lm::Status>(st)), op);
    return buf;
}

// gen-next <node> <seed>   the next MESSAGE event: its length and whether the payload is the generated pattern
std::string cmd_gen_next(Sim &sim, const Args &a) {
    uint16_t i = 0;
    uint64_t seed = 0;
    if (a.size() != 3 || !parse_node(sim, a[1], i) || !running(sim, i) || !parse_u64(a[2], seed)) {
        return error("usage: gen-next <node> <seed>");
    }
    for (int guard = 0; guard < 64; ++guard) {
        lm_event_t ev{};
        ev.struct_size = sizeof(ev);
        ev.abi_version = LM_ABI_VERSION;
        std::vector<uint8_t> buf(4200);
        size_t req = 0;
        if (lm_next_event(sim.world.node(i).ctx(), &ev, buf.data(), buf.size(), &req) != LM_STATUS_OK) {
            return "{\"ok\":true,\"event\":null}";
        }
        if (ev.kind != LM_EVENT_MESSAGE) {
            continue;
        }
        buf.resize(req);
        char out[160];
        std::snprintf(out, sizeof out, "{\"ok\":true,\"event\":{\"port\":%u,\"length\":%zu,\"pattern_ok\":%s}}", ev.app_port,
                      req, buf == pattern(seed, req) ? "true" : "false");
        return out;
    }
    return "{\"ok\":true,\"event\":null}";
}

// send-control <node> <dest_node> <root_term> <expires_root_ms> <len> <seed>   internal control object (S12)
std::string cmd_send_control(Sim &sim, const Args &a) {
    uint16_t i = 0;
    uint16_t dest = 0;
    uint64_t term = 0;
    uint64_t expires = 0;
    uint64_t len = 0;
    uint64_t seed = 0;
    if (a.size() != 7 || !parse_node(sim, a[1], i) || !parse_node(sim, a[2], dest) || !running(sim, i) ||
        !parse_u64(a[3], term) || !parse_u64(a[4], expires) || !parse_u64(a[5], len) || !parse_u64(a[6], seed) || len > 4200) {
        return error("usage: send-control <node> <dest_node> <root_term> <expires_root_ms> <len> <seed>");
    }
    lm::delivery::ControlSendRequest rq;
    rq.dest = sim.world.node(dest).ctx()->engine.identity().self();
    rq.root_term = static_cast<uint32_t>(term);
    rq.expires_root_ms = expires;
    const std::vector<uint8_t> payload = pattern(seed, len);
    lm::Command cmd;
    cmd.kind = lm::CommandKind::SendControl;
    cmd.request = &rq;
    cmd.request_size = sizeof(rq);
    cmd.payload = lm::ByteView{payload.data(), payload.size()};
    lm::Engine &e = sim.world.node(i).ctx()->engine;
    const lm::Reply r = e.execute(cmd, sim.world.node(i).clock.now());
    sim.world.node(i).notify();
    char buf[160];
    std::snprintf(buf, sizeof buf, "{\"ok\":%s,\"status\":\"%s\",\"operation\":%" PRIu64 "}", r.status == lm::Status::Ok ? "true" : "false",
                  lm::status_name(r.status), r.operation_id);
    return buf;
}

// ctl-sink <node|all>   collect the control objects that complete at the node (until it is rebooted)
std::string cmd_ctl_sink(Sim &sim, const Args &a) {
    if (a.size() != 2) {
        return error("usage: ctl-sink <node|all>");
    }
    for (uint16_t i = 0; i < sim.world.node_count(); ++i) {
        if ((a[1] != "all" && a[1] != std::to_string(i)) || !running(sim, i)) {
            continue;
        }
        sim.world.node(i).ctx()->engine.delivery().set_control_sink(
            [](void *ctx, const lm::DeviceId &origin, const std::array<uint8_t, 16> &, lm::ByteView p, lm::MonoTime) {
                Control c;
                c.origin = origin.bytes;
                c.payload.assign(p.begin(), p.end());
                inbox()[static_cast<uint16_t>(reinterpret_cast<std::uintptr_t>(ctx))].push_back(std::move(c));
            },
            reinterpret_cast<void *>(static_cast<std::uintptr_t>(i)));
    }
    return "{\"ok\":true}";
}

// ctl-recv <node> <seed>   pop the oldest collected control object: length, origin, whether it is the pattern
std::string cmd_ctl_recv(Sim &sim, const Args &a) {
    uint16_t i = 0;
    uint64_t seed = 0;
    if (a.size() != 3 || !parse_node(sim, a[1], i) || !parse_u64(a[2], seed)) {
        return error("usage: ctl-recv <node> <seed>");
    }
    auto &q = inbox()[i];
    if (q.empty()) {
        return "{\"ok\":true,\"control\":null}";
    }
    const Control c = std::move(q.front());
    q.pop_front();
    char buf[256];
    std::snprintf(buf, sizeof buf, "{\"ok\":true,\"control\":{\"length\":%zu,\"origin\":\"%s\",\"pattern_ok\":%s}}", c.payload.size(),
                  hex32(c.origin.data()).c_str(), c.payload == pattern(seed, c.payload.size()) ? "true" : "false");
    return buf;
}

// frag <node>   fragment counters
std::string cmd_frag(Sim &sim, const Args &a) {
    uint16_t i = 0;
    if (a.size() != 2 || !parse_node(sim, a[1], i) || !running(sim, i)) {
        return error("usage: frag <node>");
    }
    const lm::delivery::FragStats &f = sim.world.node(i).ctx()->engine.delivery().frag_stats();
    char buf[512];
    std::snprintf(buf, sizeof buf,
                  "{\"ok\":true,\"rx\":%" PRIu64 ",\"rx_dup\":%" PRIu64 ",\"rx_conflict\":%" PRIu64 ",\"rx_busy\":%" PRIu64
                  ",\"rx_refused\":%" PRIu64 ",\"rx_expired\":%" PRIu64 ",\"completed\":%" PRIu64 ",\"tx\":%" PRIu64
                  ",\"bitmap_tx\":%" PRIu64 ",\"bitmap_rx\":%" PRIu64 ",\"control_rx\":%" PRIu64 "}",
                  f.rx, f.rx_dup, f.rx_conflict, f.rx_busy, f.rx_refused, f.rx_expired, f.completed, f.tx, f.bitmap_tx,
                  f.bitmap_rx, f.control_rx);
    return buf;
}

} // namespace meshsim
