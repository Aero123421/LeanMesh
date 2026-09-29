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
#include "core/radio/peer_registry.hpp"
#include "core/radio/tx_manager.hpp"
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
    // RF profile of this deployment (docs/03 §3). Unapproved by default: Start is then refused.
    port::RfProfile rf;
};

// Owner-visible counters. Diagnostics expose them with validity bits; never reset silently.
struct EngineStats {
    uint64_t steps = 0;
    uint64_t commands = 0;
    uint64_t rx_frames = 0;
    uint64_t rx_unhandled = 0;      // frames with no consumer yet (dropped, never acted on)
    uint64_t tx_done_unmatched = 0; // TX completions not matching the in-flight token
    uint64_t stale_job_completions = 0;
    uint64_t radio_restarts = 0;    // watchdog recoveries (new driver generation)
    uint64_t radio_faults = 0;      // recoveries that gave up (FAULT event)
};

// Maximum number of jobs in flight from one owner (public-key + Flash).
inline constexpr std::size_t k_job_table_entries = 4;
// Upper bound on application event slots (profile app_messages).
inline constexpr std::size_t k_max_app_events = k_build_limits.app_messages;
// Radio events handled per step() before yielding, to bound one owner pass (docs/16 p99 < 2 ms).
inline constexpr int k_max_radio_events_per_step = 8;

// The radio lifecycle the owner drives (Start/Stop commands and watchdog recovery).
enum class RadioState : uint8_t { Stopped, Running, Recovering, Faulted };

// Radio re-initialisation attempts after an unknown TX result before FAULT is reported.
inline constexpr int k_radio_recover_attempts = 3;
inline constexpr Duration k_radio_recover_backoff = Duration::from_ms(1000);

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
    [[nodiscard]] RadioState radio_state() const { return radio_state_; }
    [[nodiscard]] uint8_t channel() const { return channel_; }

    // Radio services for feature modules (owner thread only).
    // Transmits one frame (<= 250 B) to a registered peer or broadcast. The outcome arrives later
    // through the TX manager (on_tx_outcome). Busy = a TX is in flight or the driver has no room;
    // DriverResultUnknown = isolated after a watchdog. Neither is RF loss.
    [[nodiscard]] Status transmit(const MacAddr &dst, ByteView frame, uint32_t tag, MonoTime now);
    // Changes the channel with readback semantics of the port (channel plan slice).
    [[nodiscard]] Status set_channel(uint8_t channel);
    PeerRegistry &peers() { return peers_; }
    [[nodiscard]] const PeerRegistry &peers() const { return peers_; }
    [[nodiscard]] const TxManager &tx() const { return tx_; }

  private:
    void on_radio_event(const port::RadioEvent &ev, MonoTime now);
    void on_job_completion(const port::JobCompletion &c, MonoTime now);
    void on_tx_outcome(const TxOutcome &o, MonoTime now);
    [[nodiscard]] MonoTime next_deadline() const;

    Reply start_radio(MonoTime now);
    Reply stop_radio();
    [[nodiscard]] Status bring_up_radio();
    void recover_radio(MonoTime now);
    void emit(uint32_t kind, uint32_t reason);

    Reply get_capabilities(const Command &cmd) const;
    Reply next_event(const Command &cmd);

    EngineConfig config_;
    Ports ports_;
    EngineStats stats_;
    JobTable<k_job_table_entries> jobs_;
    AppEventQueue<k_max_app_events> events_;
    PeerRegistry peers_;
    TxManager tx_;
    RadioState radio_state_ = RadioState::Stopped;
    uint8_t channel_ = 0;
    int recover_attempts_ = 0;
    MonoTime recover_at_ = MonoTime::never();
    bool yield_ = false; // RX budget of the last step was exhausted: run again without sleeping
};

} // namespace lm
