// meshsim control protocol: one command per line on stdin, one JSON object per line on stdout.
// The first stdout line is {"event":"ready",...}. Every command gets exactly one reply line with
// "ok": true|false. Commands (the table in control.cpp is the reference):
//   status                                  world time, node count, clock mode, pty path
//   run <ms>                                advance virtual time (virtual clock mode only)
//   node <i>                                engine/radio/store counters of node i
//   link <a> <b> up|down [loss_permille] [delay_ms] [ack_loss_permille]
//   power-cut <i> | boot <i>                drop RAM state (store kept) / construct a fresh context
//   serial                                  bytes exchanged over the root pty
//   start <i> | stop <i>                    lm_start / lm_stop on node i (status name in reply)
//   inject <via> <src_node> <dst_node|bcast> <hex>   frame as if sent by src_node's MAC, heard by
//                                           the neighbours of <via> (attacker/replay tests)
//   rawtx <from> <to|bcast> <hex>           TEST ONLY: one raw frame through the owner's TX path
//   cb-delay <ms> [node]                    extra TX-done callback delay (all nodes or one)
//   trace on [capacity] | off | dump        bounded medium trace (default capacity 1024)
//   provision <node> <address> [leaf|relay|root|unjoined]   TEST-ONLY fleet issuer writes the sealed
//                                           identity records into the node's store (before `start`)
//   link-connect <node> <peer>              open a link session (EDHOC purpose 1) to a neighbour
//   link-status <node>                      identity state, neighbours/sessions, exchange phase
//   quit
// Stdout carries only protocol lines; diagnostics go to stderr.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "port/sim/sim_world.hpp"
#include "pty.hpp"

namespace meshsim {

enum class ClockMode { Virtual, Realtime };

struct Sim {
    lm::sim::World &world;
    ClockMode clock;
    Pty *pty; // nullptr without --serial-pty
    bool quit = false;
};

using Args = std::vector<std::string>;

// Helpers shared by the command files (cmd_<slice>.cpp).
std::string error(const std::string &msg);
bool parse_u64(const std::string &s, uint64_t &out);
bool parse_node(Sim &sim, const std::string &s, uint16_t &out);

// Commands of the runtime slice (cmd_runtime.cpp).
std::string cmd_start(Sim &sim, const Args &a);
std::string cmd_stop(Sim &sim, const Args &a);
std::string cmd_inject(Sim &sim, const Args &a);
std::string cmd_rawtx(Sim &sim, const Args &a);
std::string cmd_cb_delay(Sim &sim, const Args &a);
std::string cmd_trace(Sim &sim, const Args &a);

// Commands of the identity/link slice (cmd_provision.cpp).
std::string cmd_provision(Sim &sim, const Args &a);
std::string cmd_link_connect(Sim &sim, const Args &a);
std::string cmd_link_status(Sim &sim, const Args &a);

// --topology-file: one `link <a> <b> [loss_permille] [delay_ms] [ack_loss_permille]` per line,
// `#` starts a comment. False with `err` set on the first bad line (nothing is half-applied).
bool load_topology(lm::sim::World &world, const std::string &path, std::string &err);

// Executes one command line and returns the JSON reply (without newline).
std::string execute(Sim &sim, const std::string &line);

// Routes host->root serial bytes. Until the serial slice lands, bytes are counted only.
void on_serial_rx(Sim &sim, const uint8_t *data, std::size_t len);

} // namespace meshsim
