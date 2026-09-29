#include "control.hpp"

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <sstream>
#include <vector>

#include "port/sim/sim_node.hpp"

namespace meshsim {

std::string error(const std::string &msg) { return "{\"ok\":false,\"error\":\"" + msg + "\"}"; }

bool parse_u64(const std::string &s, uint64_t &out) {
    if (s.empty()) {
        return false;
    }
    char *end = nullptr;
    out = std::strtoull(s.c_str(), &end, 10);
    return end != nullptr && *end == '\0';
}

bool parse_node(Sim &sim, const std::string &s, uint16_t &out) {
    uint64_t v = 0;
    if (!parse_u64(s, v) || v >= sim.world.node_count()) {
        return false;
    }
    out = static_cast<uint16_t>(v);
    return true;
}

namespace {

std::string cmd_status(Sim &sim, const Args &) {
    char buf[256];
    std::snprintf(buf, sizeof buf,
                  "{\"ok\":true,\"now_us\":%" PRIu64
                  ",\"nodes\":%zu,\"clock\":\"%s\",\"serial_pty\":\"%s\"}",
                  sim.world.now_us(), sim.world.node_count(),
                  sim.clock == ClockMode::Virtual ? "virtual" : "realtime",
                  sim.pty != nullptr ? sim.pty->slave_path().c_str() : "");
    return buf;
}

std::string cmd_run(Sim &sim, const Args &a) {
    uint64_t ms = 0;
    if (sim.clock != ClockMode::Virtual) {
        return error("run requires --clock virtual");
    }
    if (a.size() != 2 || !parse_u64(a[1], ms)) {
        return error("usage: run <ms>");
    }
    sim.world.run_until(sim.world.now_us() + ms * 1000);
    return cmd_status(sim, a);
}

std::string cmd_node(Sim &sim, const Args &a) {
    uint16_t i = 0;
    if (a.size() != 2 || !parse_node(sim, a[1], i)) {
        return error("usage: node <index>");
    }
    lm::sim::SimNode &n = sim.world.node(i);
    const lm::Engine *e = n.engine();
    lm::EngineStats s{};
    if (e != nullptr) {
        s = e->stats();
    }
    lm::TxStats tx{};
    const char *radio_state = "off";
    if (e != nullptr) {
        tx = e->tx().stats();
        static const char *const k_names[] = {"stopped", "running", "recovering", "faulted"};
        radio_state = k_names[static_cast<unsigned>(e->radio_state())];
    }
    char buf[1024];
    std::snprintf(
        buf, sizeof buf,
        "{\"ok\":true,\"node\":%u,\"powered\":%s,\"epoch\":%u,\"role\":%u,\"steps\":%" PRIu64
        ",\"commands\":%" PRIu64 ",\"rx_frames\":%" PRIu64 ",\"rx_unhandled\":%" PRIu64
        ",\"tx_done_unmatched\":%" PRIu64 ",\"stale_job_completions\":%" PRIu64
        ",\"radio_on\":%s,\"radio_rx_dropped\":%u,\"store_slot_writes\":%" PRIu64
        ",\"radio_state\":\"%s\",\"radio_restarts\":%" PRIu64 ",\"tx_started\":%" PRIu64
        ",\"tx_mac_acked\":%" PRIu64 ",\"tx_rf_failed\":%" PRIu64 ",\"tx_unknown\":%" PRIu64
        ",\"tx_local_refused\":%" PRIu64 ",\"peers\":%zu}",
        i, n.powered() ? "true" : "false", n.epoch(), static_cast<unsigned>(n.options().role),
        s.steps, s.commands, s.rx_frames, s.rx_unhandled, s.tx_done_unmatched,
        s.stale_job_completions, n.radio.receiving() ? "true" : "false", n.radio.rx_dropped(),
        n.store.slot_writes(), radio_state, s.radio_restarts, tx.started, tx.mac_acked,
        tx.rf_failed, tx.unknown, tx.local_refused, n.radio.peer_count());
    return buf;
}

std::string cmd_link(Sim &sim, const Args &a) {
    uint16_t x = 0;
    uint16_t y = 0;
    if (a.size() < 4 || !parse_node(sim, a[1], x) || !parse_node(sim, a[2], y) || x == y ||
        (a[3] != "up" && a[3] != "down")) {
        return error("usage: link <a> <b> up|down [loss_permille] [delay_ms] [ack_loss_permille]");
    }
    lm::sim::LinkParams p;
    p.up = a[3] == "up";
    uint64_t v = 0;
    if (a.size() > 4) {
        if (!parse_u64(a[4], v) || v > 1000) {
            return error("loss_permille 0..1000");
        }
        p.loss_permille = static_cast<uint16_t>(v);
    }
    if (a.size() > 5) {
        if (!parse_u64(a[5], v) || v > 10000) {
            return error("delay_ms 0..10000");
        }
        p.delay_us = static_cast<uint32_t>(v * 1000);
    }
    if (a.size() > 6) {
        if (!parse_u64(a[6], v) || v > 1000) {
            return error("ack_loss_permille 0..1000");
        }
        p.ack_loss_permille = static_cast<uint16_t>(v);
    }
    sim.world.set_link(x, y, p);
    return "{\"ok\":true}";
}

std::string cmd_power_cut(Sim &sim, const Args &a) {
    uint16_t i = 0;
    if (a.size() != 2 || !parse_node(sim, a[1], i)) {
        return error("usage: power-cut <index>");
    }
    sim.world.node(i).power_cut();
    return "{\"ok\":true}";
}

std::string cmd_boot(Sim &sim, const Args &a) {
    uint16_t i = 0;
    if (a.size() != 2 || !parse_node(sim, a[1], i)) {
        return error("usage: boot <index>");
    }
    const lm::Status st = sim.world.node(i).boot();
    if (st != lm::Status::Ok) {
        return error(std::string("boot failed: ") + lm::status_name(st));
    }
    return "{\"ok\":true}";
}

std::string cmd_serial(Sim &sim, const Args &) {
    const lm::sim::SerialCounters &c = sim.world.node(0).serial;
    char buf[160];
    std::snprintf(buf, sizeof buf,
                  "{\"ok\":true,\"rx_bytes\":%" PRIu64 ",\"tx_bytes\":%" PRIu64 "}", c.rx_bytes,
                  c.tx_bytes);
    return buf;
}

std::string cmd_quit(Sim &sim, const Args &) {
    sim.quit = true;
    return "{\"ok\":true}";
}

struct Entry {
    const char *name;
    std::string (*fn)(Sim &, const Args &);
};

// [SLICE] Slices add commands here (one line each; handlers in cmd_<slice>.cpp).
const Entry k_commands[] = {
    {"status", cmd_status},       {"run", cmd_run},   {"node", cmd_node},     {"link", cmd_link},
    {"power-cut", cmd_power_cut}, {"boot", cmd_boot}, {"serial", cmd_serial}, {"quit", cmd_quit},
    {"start", cmd_start},         {"stop", cmd_stop}, {"inject", cmd_inject}, {"rawtx", cmd_rawtx},
    {"cb-delay", cmd_cb_delay},   {"trace", cmd_trace},
};

} // namespace

std::string execute(Sim &sim, const std::string &line) {
    std::istringstream in(line);
    Args args;
    for (std::string tok; in >> tok;) {
        args.push_back(tok);
    }
    if (args.empty()) {
        return error("empty command");
    }
    for (const Entry &e : k_commands) {
        if (args[0] == e.name) {
            return e.fn(sim, args);
        }
    }
    return error("unknown command");
}

void on_serial_rx(Sim &sim, const uint8_t * /*data*/, std::size_t len) {
    // [SLICE:S10 USB-SERIAL] hand the bytes to the root serial transport. Counted only until then.
    sim.world.node(0).serial.rx_bytes += len;
}

} // namespace meshsim
