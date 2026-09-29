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
//   join-mode / grant / join / leave / membership / ledger / events / store-cut / store-fired /
//   store-restore                           the join slice (cmd_join.cpp): ticket + expected entry, lm_join,
//                                           lm_leave, membership state, root ledger, power-cut injection
//   serial-kit <path> [index]               TEST-ONLY: write the Host kit of fleet device 2000+index
//   serial-pair <node> [index]              seal the paired-host record (device 2000+index) on the root
//   serial-status                           root USB session state and counters
//   serial-drop                             simulate a USB detach/replug (root drops its session)
//   serial-reset                            reset the root MCU: power-cut + boot + start (new boot id)
//   route / root-time / send / op / msg-next / msg-report / msg-cancel / delivery   the delivery slice
//                                           (cmd_delivery.cpp): static route, root clock, lm_send, operation
//                                           state, next message + application result, counters
//   flood / sched                           the scheduler slice (cmd_sched.cpp): a burst of best-effort sends of one
//                                           class or LATEST key, scheduler + admission counters
//   gen-send / gen-next / send-control / ctl-sink / ctl-recv / frag   the fragment slice (cmd_fragment.cpp):
//                                           messages and objects with a generated payload, control objects
//                                           to a device and their sink, fragment counters
//   group-set / group-send / group-progress / group-targets / group-cancel   the group slice (cmd_group.cpp): the
//                                           root's group registry, lm_send to a group, progress, per-target
//                                           results, cancel
//   mesh <node>                             mesh state (Listen/Search/Attach/Ready/Root), parent, depth, root path and
//                                           counters of node i; on the root also the approved tree size (cmd_mesh.cpp)
//   quit
// Stdout carries only protocol lines; diagnostics go to stderr.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "fleet.hpp"
#include "port/sim/sim_world.hpp"

namespace lm::fleet {
class Network;
}
#include "pty.hpp"

namespace meshsim {

enum class ClockMode { Virtual, Realtime };

struct Sim {
    lm::sim::World &world;
    ClockMode clock;
    Pty *pty; // nullptr without --serial-pty
    bool quit = false;
    bool bridge = false; // --serial-bridge: the root runs the S13 Host bridge (else UNSUPPORTED replies)
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
// The process-wide test fleet (created by the first use); the serial commands mint Host kits from it.
lm::fleet::Network &network(Sim &sim);

// Commands of the USB serial slice (cmd_serial.cpp). serial_sync() attaches the root's serial
// adapter to node 0 after every (re)boot; it runs before every command.
std::string cmd_serial_kit(Sim &sim, const Args &a);
std::string cmd_serial_pair(Sim &sim, const Args &a);
std::string cmd_serial_status(Sim &sim, const Args &a);
std::string cmd_serial_drop(Sim &sim, const Args &a);
std::string cmd_serial_reset(Sim &sim, const Args &a);
void serial_sync(Sim &sim);
void serial_on_rx(Sim &sim, const uint8_t *data, std::size_t len);

// Commands of the join slice (cmd_join.cpp).
std::string cmd_join_mode(Sim &sim, const Args &a);
std::string cmd_grant(Sim &sim, const Args &a);
std::string cmd_join(Sim &sim, const Args &a);
std::string cmd_leave(Sim &sim, const Args &a);
std::string cmd_membership(Sim &sim, const Args &a);
std::string cmd_ledger(Sim &sim, const Args &a);
std::string cmd_events(Sim &sim, const Args &a);
std::string cmd_store_cut(Sim &sim, const Args &a);
std::string cmd_store_restore(Sim &sim, const Args &a);
std::string cmd_store_fired(Sim &sim, const Args &a);
lm::fleet::Network &fleet_network(Sim &sim);

// Commands of the delivery slice (cmd_delivery.cpp).
std::string cmd_route(Sim &sim, const Args &a);
std::string cmd_root_time(Sim &sim, const Args &a);
std::string cmd_send(Sim &sim, const Args &a);
std::string cmd_op(Sim &sim, const Args &a);
std::string cmd_msg_next(Sim &sim, const Args &a);
std::string cmd_msg_report(Sim &sim, const Args &a);
std::string cmd_msg_cancel(Sim &sim, const Args &a);
std::string cmd_delivery(Sim &sim, const Args &a);
// Commands of the mesh slice (cmd_mesh.cpp).
std::string cmd_mesh(Sim &sim, const Args &a);
// Commands of the power slice (cmd_power.cpp).
std::string cmd_power(Sim &sim, const Args &a);
std::string cmd_power_set(Sim &sim, const Args &a);
std::string cmd_sleep(Sim &sim, const Args &a);
std::string cmd_wake(Sim &sim, const Args &a);
// Commands of the channel slice (cmd_channel.cpp).
std::string cmd_channel(Sim &sim, const Args &a);

// Commands of the fragment slice (cmd_fragment.cpp).
std::string cmd_gen_send(Sim &sim, const Args &a);
std::string cmd_gen_next(Sim &sim, const Args &a);
std::string cmd_send_control(Sim &sim, const Args &a);
std::string cmd_ctl_sink(Sim &sim, const Args &a);
std::string cmd_ctl_recv(Sim &sim, const Args &a);
std::string cmd_frag(Sim &sim, const Args &a);

// Commands of the group slice (cmd_group.cpp).
std::string cmd_group_set(Sim &sim, const Args &a);
std::string cmd_group_send(Sim &sim, const Args &a);
std::string cmd_group_progress(Sim &sim, const Args &a);
std::string cmd_group_targets(Sim &sim, const Args &a);
std::string cmd_group_cancel(Sim &sim, const Args &a);

// Commands of the scheduler slice (cmd_sched.cpp).
std::string cmd_flood(Sim &sim, const Args &a);
std::string cmd_sched(Sim &sim, const Args &a);

// --topology-file: one `link <a> <b> [loss_permille] [delay_ms] [ack_loss_permille]` per line,
// `#` starts a comment. False with `err` set on the first bad line (nothing is half-applied).
bool load_topology(lm::sim::World &world, const std::string &path, std::string &err);

// Executes one command line and returns the JSON reply (without newline).
std::string execute(Sim &sim, const std::string &line);

// Routes host->root serial bytes. Until the serial slice lands, bytes are counted only.
void on_serial_rx(Sim &sim, const uint8_t *data, std::size_t len);

} // namespace meshsim
