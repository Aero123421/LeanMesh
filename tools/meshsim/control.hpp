// meshsim control protocol: one command per line on stdin, one JSON object per line on stdout.
// The first stdout line is {"event":"ready",...}. Every command gets exactly one reply line with
// "ok": true|false. Commands (the table in control.cpp is the reference):
//   status                                  world time, node count, clock mode, pty path
//   run <ms>                                advance virtual time (virtual clock mode only)
//   node <i>                                engine/radio/store counters of node i
//   link <a> <b> up|down [loss_permille] [delay_ms] [ack_loss_permille]
//   power-cut <i> | boot <i>                drop RAM state (store kept) / construct a fresh context
//   serial                                  bytes exchanged over the root pty
//   quit
// Stdout carries only protocol lines; diagnostics go to stderr.
#pragma once

#include <cstdint>
#include <string>

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

// Executes one command line and returns the JSON reply (without newline).
std::string execute(Sim &sim, const std::string &line);

// Routes host->root serial bytes. Until the serial slice lands, bytes are counted only.
void on_serial_rx(Sim &sim, const uint8_t *data, std::size_t len);

} // namespace meshsim
