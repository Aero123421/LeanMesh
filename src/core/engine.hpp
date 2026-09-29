// The mesh owner (docs/02 §2). One Engine per node; every method runs on the owner thread.
// Inputs:  radio events and job completions (polled from the ports), commands (execute()), time.
// Outputs: radio transmissions and job submissions (through the ports), application events.
// step() never blocks and returns the earliest time it must run again; the platform loop sleeps
// until then or until a notification (RX, TX done, job done, command). No fixed polling tick
// (docs/02 §5, docs/20 §11).
//
// Feature modules (link, route, delivery, member, channel, power, root...) are added as members
// of Engine by their slices; see docs/IMPLEMENTATION.md §3 for the wiring rules.
#pragma once

#include <cstdint>

#include "core/command.hpp"
#include "core/events.hpp"
#include "core/jobs.hpp"
#include "core/ports.hpp"
#include "core/profile.hpp"
#include "core/time.hpp"

namespace lm {

struct Ports {
    port::Clock &clock;
    port::Radio &radio;
    port::Jobs &jobs;
    // port::Store is reached only through job bodies on the worker (JobEnv).
};

struct EngineConfig {
    Role role = Role::Leaf;
    bool object_transfer_enabled = false;
    uint32_t application_event_slots = 0;
};

// Owner-visible counters. Diagnostics expose them with validity bits; never reset silently.
struct EngineStats {
    uint64_t steps = 0;
    uint64_t commands = 0;
    uint64_t rx_frames = 0;
    uint64_t rx_unhandled = 0;      // frames with no consumer yet (dropped, never acted on)
    uint64_t tx_done_unmatched = 0; // TX completions not matching the in-flight token
    uint64_t stale_job_completions = 0;
};

// Maximum number of jobs in flight from one owner (public-key + Flash).
inline constexpr std::size_t k_job_table_entries = 4;
// Upper bound on application event slots (profile app_messages).
inline constexpr std::size_t k_max_app_events = k_build_limits.app_messages;
// Radio events handled per step() before yielding, to bound one owner pass (docs/16 p99 < 2 ms).
inline constexpr int k_max_radio_events_per_step = 8;

class Engine {
  public:
    Engine(const EngineConfig &config, Ports ports);
    Engine(const Engine &) = delete;
    Engine &operator=(const Engine &) = delete;

    // Owner thread only. Processes available inputs and due timers; returns the next wake time.
    MonoTime step(MonoTime now);

    // Owner thread only. Runs one command and writes its reply (caller blocked meanwhile).
    Reply execute(const Command &cmd, MonoTime now);

    [[nodiscard]] const EngineConfig &config() const { return config_; }
    [[nodiscard]] const EngineStats &stats() const { return stats_; }

  private:
    void on_radio_event(const port::RadioEvent &ev, MonoTime now);
    void on_job_completion(const port::JobCompletion &c, MonoTime now);
    [[nodiscard]] MonoTime next_deadline() const;

    Reply get_capabilities(const Command &cmd) const;
    Reply next_event(const Command &cmd);

    EngineConfig config_;
    Ports ports_;
    EngineStats stats_;
    JobTable<k_job_table_entries> jobs_;
    AppEventQueue<k_max_app_events> events_;
};

} // namespace lm
