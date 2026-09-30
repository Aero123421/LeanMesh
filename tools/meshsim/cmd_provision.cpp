// meshsim commands of the identity/link slice: provision a node's sealed records from the
// TEST-ONLY fleet issuer, open a link session, inspect identity and link state. Bench only.
#include <cinttypes>
#include <cstdio>
#include <memory>

#include "control.hpp"
#include "fleet.hpp"
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

} // namespace

// The fleet + domain + root every command of this process shares (join commands build tickets from it).
lm::fleet::Network &fleet_network(Sim &sim) { return network(sim); }

namespace {

const char *identity_state(lm::member::LocalIdentity::State s) {
    static const char *const k[] = {"unloaded", "loading", "unprovisioned", "ready", "failed"};
    return k[static_cast<unsigned>(s)];
}

const char *phase_name(lm::link::Phase p) {
    static const char *const k[] = {"idle", "send_cred", "verify", "hs", "await_msg", "await_bind", "linger", "zombie"};
    return k[static_cast<unsigned>(p)];
}

} // namespace

// One fleet + domain + root per meshsim process, created on first use (shared with cmd_serial.cpp).
lm::fleet::Network &network(Sim &sim) {
    static std::unique_ptr<lm::fleet::Network> net;
    if (net == nullptr) {
        net = std::make_unique<lm::fleet::Network>(sim.world.options().seed);
    }
    return *net;
}

std::string cmd_provision(Sim &sim, const Args &a) {
    uint16_t i = 0;
    uint64_t addr = 0;
    if (a.size() < 3 || a.size() > 4 || !parse_node(sim, a[1], i) || !parse_u64(a[2], addr) ||
        addr < 1 || addr > 65534) {
        return error("usage: provision <node> <address 1..65534> [leaf|relay|root|unjoined]");
    }
    const std::string role = a.size() == 4 ? a[3] : "relay";
    lm::fleet::Network &net = network(sim);
    lm::fleet::NodeKit kit;
    if (role == "root") {
        kit = net.make_root();
    } else if (role == "unjoined") {
        kit = net.make_unjoined(i);
    } else if (role == "leaf" || role == "relay") {
        kit = net.make_node(i, static_cast<uint16_t>(addr), role == "leaf" ? 0 : 1);
    } else {
        return error("role: leaf|relay|root|unjoined");
    }
    lm::Status st = lm::fleet::provision(sim.world.node(i).store, net, kit, role != "unjoined");
    // The root lists every provisioned member ACTIVE (SEC-D2: it admits nobody else). Members provisioned
    // before the root are written by the root's provisioning, later ones here (before `start` of the root).
    static int root_node = -1;
    if (st == lm::Status::Ok && role == "root") {
        root_node = i;
    } else if (st == lm::Status::Ok && (role == "leaf" || role == "relay") && root_node >= 0) {
        st = lm::fleet::register_member(sim.world.node(static_cast<uint16_t>(root_node)).store, kit);
    }
    if (st != lm::Status::Ok) {
        return error(std::string("provision failed: ") + lm::status_name(st));
    }
    return "{\"ok\":true,\"device\":\"" + hex(kit.kit.id.view()) + "\"}";
}

std::string cmd_link_connect(Sim &sim, const Args &a) {
    uint16_t i = 0;
    uint16_t peer = 0;
    if (a.size() != 3 || !parse_node(sim, a[1], i) || !parse_node(sim, a[2], peer) ||
        sim.world.node(i).ctx() == nullptr) {
        return error("usage: link-connect <node> <peer_node> (node must be booted and started)");
    }
    lm::sim::SimNode &n = sim.world.node(i);
    const lm::Status s = n.ctx()->engine.link().connect(sim.world.node(peer).radio.mac(), n.clock.now());
    n.notify();
    return std::string("{\"ok\":") + (s == lm::Status::Ok ? "true" : "false") + ",\"status\":\"" +
           lm::status_name(s) + "\"}";
}

std::string cmd_link_status(Sim &sim, const Args &a) {
    uint16_t i = 0;
    if (a.size() != 2 || !parse_node(sim, a[1], i) || sim.world.node(i).ctx() == nullptr) {
        return error("usage: link-status <node>");
    }
    lm::Engine &e = sim.world.node(i).ctx()->engine;
    lm::link::LinkLayer &l = e.link();
    const lm::link::LinkStats &st = l.stats();
    std::string out = std::string("{\"ok\":true,\"identity\":\"") + identity_state(e.identity().state()) +
                      "\",\"member\":" + (e.identity().is_member() ? "true" : "false") +
                      ",\"phase\":\"" + phase_name(l.exchange().phase()) + "\",\"neighbors\":[";
    bool first = true;
    l.neighbors().for_each([&](lm::Handle, lm::link::Neighbor &n) {
        char buf[320];
        std::snprintf(buf, sizeof buf,
                      "%s{\"device\":\"%s\",\"address\":%u,\"active\":%s,\"rx_sid\":%u,\"tx_sid\":%u,"
                      "\"tx_used\":%" PRIu64 "}",
                      first ? "" : ",", hex(n.device.view()).c_str(), n.address.value(),
                      n.cur.active ? "true" : "false", n.cur.rx_sid, n.cur.tx_sid, n.cur.rec.tx_used());
        out += buf;
        first = false;
    });
    char buf[512];
    std::snprintf(buf, sizeof buf,
                  "],\"hs_started\":%" PRIu64 ",\"hs_completed\":%" PRIu64 ",\"hs_failed\":%" PRIu64
                  ",\"cred_rejected\":%" PRIu64 ",\"rx_unknown_sid\":%" PRIu64
                  ",\"rx_auth_fail\":%" PRIu64 ",\"rx_accepted\":%" PRIu64 "}",
                  st.hs_started, st.hs_completed, st.hs_failed, st.cred_rejected, st.rx_unknown_sid,
                  st.rx_auth_fail, st.rx_accepted);
    return out + buf;
}

} // namespace meshsim
