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

#include "core/channel/channel.hpp"
#include "core/command.hpp"
#include "core/delivery/delivery.hpp"
#include "core/events.hpp"
#include "core/group/group.hpp"
#include "core/jobs.hpp"
#include "core/link/link_layer.hpp"
#include "core/member/membership.hpp"
#include "core/member/proxy.hpp"
#include "core/member/records.hpp"
#include "core/power/power.hpp"
#include "core/ports.hpp"
#include "core/profile.hpp"
#include "core/radio/peer_registry.hpp"
#include "core/radio/tx_manager.hpp"
#include "core/radio/tx_pool.hpp"
#include "core/sched/sched.hpp"
#include "core/route/mesh.hpp"
#include "core/serial_hook.hpp"
#include "core/time.hpp"
#include "root/channel_coordinator.hpp"
#include "root/groups.hpp"
#include "root/ledger.hpp"
#include "root/routes.hpp"

namespace lm {

struct Ports {
    port::Clock &clock;
    port::Radio &radio;
    port::Jobs &jobs;
    port::Pm *pm = nullptr; // [S16] optional: a build without it cannot sleep
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
// Asleep [S16]: the driver is off on purpose (sleep, or a wake the power budget denied); RAM state is kept.
enum class RadioState : uint8_t { Stopped, Running, Recovering, Faulted, Asleep };

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
    // Every transmission is charged to the scheduler's airtime bucket as `cls`; `queued` frames came
    // out of its DRR pick (HopTx), the others (HOP_ACK, handshake, join, discovery) are control-plane.
    [[nodiscard]] Status transmit(const MacAddr &dst, ByteView frame, uint32_t tag, MonoTime now,
                                  sched::Class cls = sched::Class::Control, bool queued = false);
    // Changes the channel with readback semantics of the port (channel plan slice).
    [[nodiscard]] Status set_channel(uint8_t channel);
    PeerRegistry &peers() { return peers_; }
    [[nodiscard]] const PeerRegistry &peers() const { return peers_; }
    [[nodiscard]] const TxManager &tx() const { return tx_; }
    // [S14] The node's one frame pool (queued frames and borrowed buffers) and the TX scheduler.
    [[nodiscard]] TxPool &frames() { return frames_; }
    [[nodiscard]] sched::Scheduler &sched() { return sched_; }
    [[nodiscard]] const sched::Scheduler &sched() const { return sched_; }
    // Registers/frees a driver peer through the registry (NoCapacity = local shortage, not loss).
    [[nodiscard]] Status acquire_peer(const MacAddr &mac, PeerClass cls, PeerHandle &out) {
        return peers_.acquire(ports_.radio, mac, cls, out);
    }
    [[nodiscard]] Status release_peer(PeerHandle h) { return peers_.release(ports_.radio, h); }
    // Job service: reserves a table entry and queues the body on the worker. The completion comes
    // back through on_job_completion() to `owner` with the same `slot`. Busy = table full or a
    // public-key job already running / worker queue full; the job then does not exist.
    [[nodiscard]] Status submit_job(JobOwner owner, Handle slot, JobClass cls, port::JobFn fn, void *arg);
    // CSPRNG bytes for SDK nonces, SIDs and jitter (never key material).
    void random(MutByteView out) { ports_.jobs.random(out); }
    // [SLICE:S5] identity and link layer.
    member::LocalIdentity &identity() { return ident_; }
    link::LinkLayer &link() { return link_; }
    // [SLICE:S9] end-to-end delivery (sessions, receipts, journal) and the app event queue.
    delivery::Delivery &delivery() { return delivery_; }
    // Queues an application event. False: the queue was full (a GAP will be reported).
    [[nodiscard]] bool push_event(const lm_event_t &ev) { return events_.push(ev); }
    void raise(uint32_t kind, uint32_t reason) { emit(kind, reason); }
    // Root clock estimate from the time slice: feeds deadline checks and credential leases.
    void set_root_time(const RootTimeBound &t, MonoTime now) {
        delivery_.set_root_time(t, now);
        link_.revalidate(delivery_.root_time(now), now); // SEC-D3: every session judged by its peer's lease again
    }
    // [SLICE:S8] membership: joiner/resume/leave on every device, the ledger on the root only.
    member::Membership &membership() { return membership_; }
    root::LedgerType &ledger() { return ledger_; }
    // Membership/operation events: like raise() but with the operation id and the peer they concern.
    void emit_event(uint32_t kind, uint32_t reason, uint64_t operation, const DeviceId *peer);
    // [SLICE:S11] mesh: parent search, registration, leases, path queries; the tree exists on the root only.
    route::Mesh &mesh() { return mesh_; }
    member::Proxy &proxy() { return proxy_; }
    // A transmission that never touched the radio (a frame handed to the join tunnel) is over.
    void complete_virtual_tx(uint32_t tag, port::TxResult result, MonoTime now) { on_tx_outcome(TxOutcome{tag, result, now}, now); }
    root::RoutesType &routes() { return routes_; }
    // [SLICE:S17] channel module (time, plan participant, recovery) on every node; the planner on the root only.
    channel::Channel &chan() { return chan_; }
    [[nodiscard]] const channel::Channel &chan() const { return chan_; }
    root::CoordinatorType &coordinator() { return coord_; }
    [[nodiscard]] const root::CoordinatorType &coordinator() const { return coord_; }
    // [SLICE:S15] group fan-out (every role) and the root's group registry (empty stand-in elsewhere).
    group::Fanout &group() { return group_; }
    root::GroupsType &groups() { return groups_; }
    [[nodiscard]] const root::GroupsType &groups() const { return groups_; }
    // [SLICE:S16] power modes, sleep tickets, poll/grant, mailbox parking (src/core/power).
    power::Power &power() { return power_; }
    [[nodiscard]] port::Pm *pm() const { return ports_.pm; }
    [[nodiscard]] MonoTime clock_now() const { return ports_.clock.now(); }
    // The driver goes off / comes back with RAM state kept (light sleep, a withheld radio); the peers are
    // registered again and the channel is kept. Owner thread only.
    void radio_sleep();
    void radio_wake(MonoTime now);
    // The platform woke the CPU (an interrupt, or the port returned from a blocking light sleep).
    void power_wake(const port::WakeInfo &w, MonoTime now) { power_.wake(w, now); }
    [[nodiscard]] bool crypto_busy() const { return jobs_.public_key_busy(); }
    [[nodiscard]] bool flash_busy() const { return jobs_.flash_busy(); }
    [[nodiscard]] bool jobs_busy() const { return jobs_.busy(); }
    // Time of the step() or command being processed (hooks called from RX handling use it).
    [[nodiscard]] MonoTime step_time() const { return step_now_; }
    // [SLICE:S10] Root-only USB serial adapter (src/serial); nullptr on leaf/relay. Not owned.
    void attach_serial(SerialHook *hook) { serial_ = hook; }

  private:
    void on_radio_event(const port::RadioEvent &ev, MonoTime now);
    void on_job_completion(const port::JobCompletion &c, MonoTime now);
    void on_tx_outcome(const TxOutcome &o, MonoTime now);
    [[nodiscard]] MonoTime next_deadline() const;

    Reply start_radio(MonoTime now);
    Reply stop_radio();
    void enter_fault();
    [[nodiscard]] Status bring_up_radio();
    void recover_radio(MonoTime now);
    void emit(uint32_t kind, uint32_t reason);

    Reply get_capabilities(const Command &cmd) const;
    Reply next_event(const Command &cmd, MonoTime now);
    static void rx_sink(void *ctx, const link::RxInfo &info, ByteView plain); // [SLICE:S9]
    static void discovery_sink(void *ctx, const MacAddr &src, ByteView body, MonoTime now); // [SLICE:S11]
    static bool proxy_sink(void *ctx, const port::RadioRx &rx, MonoTime now);               // [SLICE:S11]
    // [SLICE:S8] link::JoinHooks trampolines: the root routes to the ledger, everything else to the
    // membership module.
    [[nodiscard]] bool is_root() const { return k_root_capable && config_.role == Role::Root; }
    void wire_join_hooks();
    Reply execute_membership(const Command &cmd, MonoTime now);

    EngineConfig config_;
    Ports ports_;
    EngineStats stats_;
    JobTable<k_job_table_entries> jobs_;
    AppEventQueue<k_max_app_events> events_;
    PeerRegistry peers_;
    TxManager tx_;
    TxPool frames_;         // [S14] before every module that borrows from it
    sched::Scheduler sched_; // [S14]
    member::LocalIdentity ident_; // [SLICE:S5]
    link::LinkLayer link_{*this, ident_};
    delivery::Delivery delivery_{*this, ident_, link_}; // [SLICE:S9]
    MonoTime step_now_;                                 // [SLICE:S9] time of the running step()
    member::Membership membership_{*this};              // [SLICE:S8]
    root::LedgerType ledger_{*this};                    // [SLICE:S8] empty stand-in off the root
    route::Mesh mesh_{*this};                           // [SLICE:S11]
    root::RoutesType routes_{*this};                    // [SLICE:S11] empty stand-in off the root
    member::Proxy proxy_{*this};                        // [SLICE:S11] join tunnel (relay side and root side)
    power::Power power_{*this};                         // [SLICE:S16]
    channel::Channel chan_{*this};                      // [SLICE:S17]
    root::CoordinatorType coord_{*this};                // [SLICE:S17] empty stand-in off the root
    root::GroupsType groups_{*this};                    // [SLICE:S15] before the fan-out that reads it
    group::Fanout group_{*this};                        // [SLICE:S15]
    SerialHook *serial_ = nullptr; // [SLICE:S10]
    RadioState radio_state_ = RadioState::Stopped;
    uint8_t channel_ = 0;
    int recover_attempts_ = 0;
    MonoTime recover_at_ = MonoTime::never();
    bool yield_ = false; // RX budget of the last step was exhausted: run again without sleeping
};

} // namespace lm
