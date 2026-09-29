// Diagnostics snapshot (S19, T19, docs/10 §6, docs/16, docs/18 §6).
//
// One pass over facts the owner already keeps: counters, table fill levels, the last platform readings.
// Nothing here runs on a timer, subscribes to anything or wakes the radio; a snapshot exists only while an
// `lm_diagnostics_get` / Host request is being answered (idle test: tests/native/test_diag.cpp).
//
// Rules (docs/10 §6): a value the build cannot know is UNKNOWN, not 0. Every group of values has a validity
// bit; an invalid value is zero in the C struct and ABSENT in the serial/Host maps. The three sources of a
// metric stay apart, so one number can never hide which layer produced it:
//   driver  what the platform reports (reset cause, heap, stack, callback ring)   Health port, bits 0..15
//   sdk     what the owner counts (frames, retries, peers, queues, channel)        bits 16..31
//   app     what concerns the application's own view (event queue, operations)     bits 32..47
// A local shortage (BUSY, no capacity) is `local_busy`; only a MAC failure is `rf_failures` (docs/03 §4).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/time.hpp"
#include "leanmesh.h"

namespace lm {
class Engine;
}

namespace lm::diag {

namespace valid {
// driver
inline constexpr uint64_t reset_reason = 1ULL << 0;
inline constexpr uint64_t heap = 1ULL << 1;
inline constexpr uint64_t stack = 1ULL << 2;
inline constexpr uint64_t owner_cpu = 1ULL << 3;
inline constexpr uint64_t rx_ring = 1ULL << 4;
// sdk
inline constexpr uint64_t counters = 1ULL << 16; // tx_frames, rx_frames, link_retries, rf_failures, local_busy
inline constexpr uint64_t peers = 1ULL << 17;
inline constexpr uint64_t tx_depth = 1ULL << 18;
inline constexpr uint64_t channel = 1ULL << 19;  // current channel, epoch, pending channel
inline constexpr uint64_t root_term = 1ULL << 20;
inline constexpr uint64_t interval = 1ULL << 21;
// app
inline constexpr uint64_t events = 1ULL << 32;   // application event queue: pending, lost
inline constexpr uint64_t operations = 1ULL << 33;
// Not measurable by this build, so they are never set: parent RSSI (not tracked), energy (no meter).
} // namespace valid

struct Snapshot {
    uint64_t validity = 0;
    // driver
    uint32_t reset_reason = 0;    // port::ResetReason
    uint32_t min_heap_bytes = 0;
    uint32_t stack_free_bytes = 0;
    uint64_t owner_cpu_us = 0;
    uint32_t rx_ring_depth = 0, rx_ring_dropped = 0;
    // sdk
    uint32_t root_term = 0, channel_epoch = 0, current_channel = 0, pending_channel = 0;
    uint32_t regular_peers = 0, transient_peers = 0, tx_depth = 0, radio_state = 0;
    uint64_t tx_frames = 0, rx_frames = 0, link_retries = 0, rf_failures = 0, local_busy = 0;
    uint64_t interval_us = 0;
    uint64_t mac_unknown = 0;     // TX results neither success nor loss (watchdog)
    // app
    uint32_t events_pending = 0;
    uint64_t events_lost = 0;
    uint32_t ops_active = 0, ops_uncommitted = 0, ops_owed = 0;
};

// Reads the engine (no writes). Owner thread only (the engine runs it inside execute()).
void collect(Engine &engine, MonoTime now, Snapshot &out);
// The C ABI struct: invalid values stay zero and their validity bit stays clear.
void to_abi(const Snapshot &s, lm_diagnostics_t &out);

// One row per feature of the capability manifest, plus the ones without an ABI bit (OTA). The facts are the
// build's own: `qualified` is never claimed by firmware (it needs hardware evidence, docs/18 §6; the generated
// build-records/scenario-coverage report carries the test evidence).
struct Feature {
    const char *name;
    uint64_t bit;      // LM_FEATURE_*; 0 = a feature without an ABI bit
    bool built;        // compiled into this image
    bool implemented;
    bool enabled;      // usable now on this node
    bool qualified;    // always false here
    const char *note;  // what a reader must not assume (nullptr: nothing to add)
};
inline constexpr std::size_t k_max_features = 12;
// Returns the number of rows written. `caps` is what lm_get_capabilities reported (the single source of the ABI
// bits); the OTA row is added from the build option.
std::size_t features(const lm_capabilities_t &caps, std::array<Feature, k_max_features> &out);

} // namespace lm::diag
