#include "core/engine.hpp"

#include <cstring>

#include "gen/registry.hpp"

namespace lm {

Engine::Engine(const EngineConfig &config, Ports ports) : config_(config), ports_(ports) {}

MonoTime Engine::step(MonoTime now) {
    ++stats_.steps;
    port::JobCompletion done;
    while (ports_.jobs.poll(done)) {
        on_job_completion(done, now);
    }
    port::RadioEvent ev;
    int handled = 0;
    while (handled < k_max_radio_events_per_step && ports_.radio.poll(ev)) {
        on_radio_event(ev, now);
        ++handled;
    }
    // Budget used up: more input may be queued, so ask to run again at once (not a poll: work
    // is known to be pending). Otherwise the next wake is a real deadline or an external event.
    yield_ = handled == k_max_radio_events_per_step;

    TxOutcome unknown;
    if (tx_.check_watchdog(now, unknown)) {
        on_tx_outcome(unknown, now);
        radio_state_ = RadioState::Recovering;
        recover_attempts_ = 0;
        recover_at_ = now;
    }
    if (radio_state_ == RadioState::Recovering && now >= recover_at_) {
        recover_radio(now);
    }
    return next_deadline();
}

void Engine::on_radio_event(const port::RadioEvent &ev, MonoTime now) {
    if (ev.kind == port::RadioEvent::Kind::Rx) {
        ++stats_.rx_frames;
        // [SLICE:S5 LINK] The link layer (header decode, SID lookup, AEAD open, kind dispatch)
        // consumes RX frames here. Until then frames are counted and dropped, never acted on.
        ++stats_.rx_unhandled;
        return;
    }
    TxOutcome out;
    if (!tx_.on_tx_done(ev.done, out)) {
        ++stats_.tx_done_unmatched;
        return;
    }
    on_tx_outcome(out, now);
}

void Engine::on_tx_outcome(const TxOutcome & /*o*/, MonoTime /*now*/) {
    // [SLICE:S5 LINK] link retry/RTO/quality: MacFailed is an RF-loss sample, MacAcked is not a
    // HOP_ACK, Unknown is neither (docs/03 §4). TxStats already separates the three.
}

void Engine::on_job_completion(const port::JobCompletion &c, MonoTime /*now*/) {
    JobOrigin origin;
    if (!jobs_.complete(c, origin)) {
        stats_.stale_job_completions = jobs_.stale_completions();
        return;
    }
    switch (origin.owner) {
    // [SLICE] case JobOwner::X: x_.on_job_done(origin.slot, c.status, now); return;
    case JobOwner::None:
    case JobOwner::Test:
        break;
    }
}

MonoTime Engine::next_deadline() const {
    MonoTime next = tx_.deadline();
    if (radio_state_ == RadioState::Recovering) {
        next = earliest(next, recover_at_);
    }
    // [SLICE] next = earliest(next, x_.deadline()); over module deadlines.
    if (yield_) {
        return MonoTime{0}; // "now or earlier": the platform loop steps again immediately
    }
    return next;
}

Status Engine::transmit(const MacAddr &dst, ByteView frame, uint32_t tag, MonoTime now) {
    if (radio_state_ == RadioState::Recovering || radio_state_ == RadioState::Faulted) {
        return Status::DriverResultUnknown;
    }
    if (radio_state_ != RadioState::Running) {
        return Status::Conflict; // radio not started (lm_start not completed)
    }
    if (!dst.is_broadcast() && !peers_.has(dst)) {
        return Status::InvalidArgument; // register the peer first (docs/03 §3)
    }
    return tx_.begin(ports_.radio, dst, frame, tag, now);
}

Status Engine::set_channel(uint8_t channel) {
    if (radio_state_ != RadioState::Running) {
        return Status::Conflict;
    }
    LM_TRY(ports_.radio.set_channel(channel));
    channel_ = channel;
    return Status::Ok;
}

void Engine::emit(uint32_t kind, uint32_t reason) {
    lm_event_t ev{};
    ev.struct_size = sizeof(ev);
    ev.abi_version = LM_ABI_VERSION;
    ev.kind = kind;
    ev.reason = reason;
    (void)events_.push(ev); // full queue: the queue itself records the GAP
}

// Radio bring-up in the order of docs/03 §3 happens inside Radio::start; the owner adds the
// broadcast peer and every registered peer (after a restart the driver table is empty).
Status Engine::bring_up_radio() {
    port::RfProfile profile = config_.rf;
    if (channel_ != 0) {
        profile.channel = channel_;
    }
    LM_TRY(ports_.radio.start(profile));
    channel_ = profile.channel;
    LM_TRY(ports_.radio.add_peer(MacAddr::broadcast()));
    LM_TRY(peers_.reapply(ports_.radio));
    tx_.reinitialised();
    return Status::Ok;
}

Reply Engine::start_radio(MonoTime /*now*/) {
    if (radio_state_ != RadioState::Stopped) {
        return Reply{Status::Conflict, 0, 0};
    }
    channel_ = 0; // a fresh start uses the profile channel
    const Status s = bring_up_radio();
    if (s != Status::Ok) {
        (void)ports_.radio.stop();
        return Reply{s, 0, 0};
    }
    radio_state_ = RadioState::Running;
    emit(LM_EVENT_STARTED, 0);
    return Reply{Status::Ok, 0, 0};
}

Reply Engine::stop_radio() {
    if (radio_state_ == RadioState::Stopped) {
        return Reply{Status::Ok, 0, 0};
    }
    // No operation exists yet that needs a drain (delivery slices add it): stop is immediate.
    const Status s = ports_.radio.stop();
    tx_.reinitialised();
    radio_state_ = RadioState::Stopped;
    recover_at_ = MonoTime::never();
    return Reply{s, 0, 0};
}

// Unknown TX result: the old driver instance may still call back. Stop it, start a new one (new
// driver generation, so no old callback can match) and register the peers again. Bounded retries;
// then FAULT and stay isolated until the application stops and starts the SDK (docs/03 §4).
void Engine::recover_radio(MonoTime now) {
    (void)ports_.radio.stop();
    if (bring_up_radio() == Status::Ok) {
        ++stats_.radio_restarts;
        radio_state_ = RadioState::Running;
        recover_at_ = MonoTime::never();
        return;
    }
    if (++recover_attempts_ >= k_radio_recover_attempts) {
        ++stats_.radio_faults;
        radio_state_ = RadioState::Faulted;
        recover_at_ = MonoTime::never();
        emit(LM_EVENT_FAULT, static_cast<uint32_t>(Status::DriverResultUnknown));
        return;
    }
    recover_at_ = now + k_radio_recover_backoff;
}

Reply Engine::execute(const Command &cmd, MonoTime now) {
    ++stats_.commands;
    switch (cmd.kind) {
    case CommandKind::GetCapabilities:
        return get_capabilities(cmd);
    case CommandKind::NextEvent:
        return next_event(cmd);
    case CommandKind::Start:
        return start_radio(now);
    case CommandKind::Stop:
        return stop_radio();
    case CommandKind::Destroy:
        return Reply{radio_state_ == RadioState::Stopped ? Status::Ok : Status::Busy, 0, 0};
    default:
        // Not implemented in this build: the operation does not exist (no fake success).
        return Reply{Status::Unsupported, 0, 0};
    }
}

Reply Engine::get_capabilities(const Command &cmd) const {
    if (cmd.response == nullptr || cmd.response_size != sizeof(lm_capabilities_t)) {
        return Reply{Status::InvalidArgument, 0, 0};
    }
    lm_capabilities_t caps{};
    caps.struct_size = sizeof(caps);
    caps.abi_version = LM_ABI_VERSION;
    // build/implemented/qualified/enabled are separate facts (docs/10 §6). Nothing is implemented
    // or qualified yet, so all feature bits are 0; slices set implemented bits as they land.
    caps.build_bits = 0;
    caps.implemented_bits = 0;
    caps.qualified_bits = 0;
    caps.enabled_bits = 0;
    caps.max_root_depth = gen::limits::root_depth;
    caps.max_path_hops = gen::limits::path_hops;
    caps.max_message_bytes = gen::limits::small_message_bytes;
    caps.max_object_bytes = config_.object_transfer_enabled ? gen::limits::object_bytes : 0;
    caps.max_members = limits_for(config_.role).members;
    caps.max_regular_peers = gen::limits::regular_peers;
    // Common lower bound for every supported path (40 hops): 136 - 2*40 (docs/09 §5, docs/10).
    caps.available_single_frame_bytes = 136 - 2 * gen::limits::path_hops;
    std::memcpy(cmd.response, &caps, sizeof(caps));
    return Reply{Status::Ok, 0, 0};
}

Reply Engine::next_event(const Command &cmd) {
    if (cmd.response == nullptr || cmd.response_size != sizeof(lm_event_t)) {
        return Reply{Status::InvalidArgument, 0, 0};
    }
    // When message payloads are added, check the caller's payload capacity BEFORE popping:
    // BufferTooSmall must not consume the event (docs/10 §2).
    lm_event_t ev{};
    if (!events_.pop(ev)) {
        // No event pending (decision: NOT_FOUND; see docs/IMPLEMENTATION.md §10).
        return Reply{Status::NotFound, 0, 0};
    }
    std::memcpy(cmd.response, &ev, sizeof(ev));
    return Reply{Status::Ok, 0, 0};
}

} // namespace lm
