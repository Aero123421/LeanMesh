// meshsim commands of the runtime slice: start/stop through the public C API, raw frame
// injection, TX-callback delay and the medium trace. Simulation bench only.
#include <cinttypes>
#include <cstdio>
#include <vector>

#include "control.hpp"
#include "leanmesh.h"
#include "port/sim/sim_node.hpp"

namespace meshsim {

namespace {

bool parse_hex(const std::string &s, std::vector<uint8_t> &out) {
    if (s.empty() || s.size() % 2 != 0 || s.size() / 2 > lm::port::k_max_frame_bytes) {
        return false;
    }
    out.clear();
    for (std::size_t i = 0; i < s.size(); i += 2) {
        unsigned v = 0;
        if (std::sscanf(s.c_str() + i, "%2x", &v) != 1) {
            return false;
        }
        out.push_back(static_cast<uint8_t>(v));
    }
    return true;
}

// "bcast" or a node index.
bool parse_dst(Sim &sim, const std::string &s, lm::MacAddr &mac) {
    if (s == "bcast") {
        mac = lm::MacAddr::broadcast();
        return true;
    }
    uint16_t n = 0;
    if (!parse_node(sim, s, n)) {
        return false;
    }
    mac = sim.world.node(n).radio.mac();
    return true;
}

std::string status_reply(lm::Status s) {
    return std::string("{\"ok\":") + (s == lm::Status::Ok ? "true" : "false") + ",\"status\":\"" +
           lm::status_name(s) + "\"}";
}

} // namespace

std::string cmd_start(Sim &sim, const Args &a) {
    uint16_t i = 0;
    if (a.size() != 2 || !parse_node(sim, a[1], i) || sim.world.node(i).ctx() == nullptr) {
        return error("usage: start <index> (node must be booted)");
    }
    return status_reply(static_cast<lm::Status>(lm_start(sim.world.node(i).ctx())));
}

std::string cmd_stop(Sim &sim, const Args &a) {
    uint16_t i = 0;
    if (a.size() != 2 || !parse_node(sim, a[1], i) || sim.world.node(i).ctx() == nullptr) {
        return error("usage: stop <index> (node must be booted)");
    }
    return status_reply(static_cast<lm::Status>(lm_stop(sim.world.node(i).ctx(), 0, nullptr)));
}

std::string cmd_inject(Sim &sim, const Args &a) {
    uint16_t via = 0;
    uint16_t src = 0;
    lm::MacAddr dst;
    std::vector<uint8_t> frame;
    if (a.size() != 5 || !parse_node(sim, a[1], via) || !parse_node(sim, a[2], src) ||
        !parse_dst(sim, a[3], dst) || !parse_hex(a[4], frame)) {
        return error("usage: inject <via> <src_node> <dst_node|bcast> <hex up to 250 bytes>");
    }
    sim.world.inject(sim.world.node(src).radio.mac(), via, dst, lm::ByteView{frame.data(), frame.size()});
    return "{\"ok\":true}";
}

std::string cmd_rawtx(Sim &sim, const Args &a) {
    uint16_t from = 0;
    lm::MacAddr dst;
    std::vector<uint8_t> frame;
    if (a.size() != 4 || !parse_node(sim, a[1], from) || !parse_dst(sim, a[2], dst) ||
        !parse_hex(a[3], frame)) {
        return error("usage: rawtx <from> <to|bcast> <hex up to 250 bytes>");
    }
    lm::sim::SimNode &n = sim.world.node(from);
    if (n.ctx() == nullptr) {
        return error("node is not powered");
    }
    lm::Engine &e = n.ctx()->engine;
    if (!dst.is_broadcast()) {
        lm::PeerHandle h;
        const lm::Status s = e.peers().acquire(n.radio, dst, lm::PeerClass::Regular, h);
        if (s != lm::Status::Ok) {
            return status_reply(s);
        }
    }
    const lm::Status s =
        e.transmit(dst, lm::ByteView{frame.data(), frame.size()}, 0, n.clock.now());
    n.notify();
    return status_reply(s);
}

std::string cmd_cb_delay(Sim &sim, const Args &a) {
    uint64_t ms = 0;
    uint16_t node = 0;
    if ((a.size() != 2 && a.size() != 3) || !parse_u64(a[1], ms) || ms > 10000 ||
        (a.size() == 3 && !parse_node(sim, a[2], node))) {
        return error("usage: cb-delay <ms 0..10000> [node]");
    }
    for (uint16_t i = 0; i < sim.world.node_count(); ++i) {
        if (a.size() == 2 || i == node) {
            sim.world.node(i).radio.tx_callback_delay_us = static_cast<uint32_t>(ms * 1000);
        }
    }
    return "{\"ok\":true}";
}

std::string cmd_trace(Sim &sim, const Args &a) {
    if (a.size() >= 2 && a[1] == "on") {
        uint64_t cap = 1024;
        if (a.size() == 3 && (!parse_u64(a[2], cap) || cap == 0 || cap > 65536)) {
            return error("capacity 1..65536");
        }
        sim.world.trace_enable(static_cast<std::size_t>(cap));
        return "{\"ok\":true}";
    }
    if (a.size() == 2 && a[1] == "off") {
        sim.world.trace_enable(0);
        return "{\"ok\":true}";
    }
    if (a.size() == 2 && a[1] == "dump") {
        static const char *const k_kinds[] = {"tx", "rx", "lost", "tx_done", "inject"};
        std::string out = "{\"ok\":true,\"overwritten\":" +
                          std::to_string(sim.world.trace_overwritten()) + ",\"entries\":[";
        bool first = true;
        for (const lm::sim::TraceEntry &e : sim.world.trace()) {
            char buf[160];
            std::snprintf(buf, sizeof buf,
                          "%s{\"t_us\":%" PRIu64 ",\"node\":%u,\"kind\":\"%s\",\"len\":%u,\"a\":%u,"
                          "\"b\":%u}",
                          first ? "" : ",", e.at_us, e.node, k_kinds[static_cast<unsigned>(e.kind)],
                          e.len, e.a, e.b);
            out += buf;
            first = false;
        }
        return out + "]}";
    }
    return error("usage: trace on [capacity] | off | dump");
}

} // namespace meshsim
