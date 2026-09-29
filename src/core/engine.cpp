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
    for (int i = 0; i < k_max_radio_events_per_step && ports_.radio.poll(ev); ++i) {
        on_radio_event(ev, now);
    }
    return next_deadline();
}

void Engine::on_radio_event(const port::RadioEvent &ev, MonoTime /*now*/) {
    if (ev.kind == port::RadioEvent::Kind::Rx) {
        ++stats_.rx_frames;
        // [SLICE:S5 LINK] The link layer (header decode, SID lookup, AEAD open, kind dispatch)
        // consumes RX frames here. Until then frames are counted and dropped, never acted on.
        ++stats_.rx_unhandled;
        return;
    }
    // [SLICE:S3 RUNTIME] The single-TX manager matches ev.done.token with the in-flight record.
    ++stats_.tx_done_unmatched;
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
    // [SLICE] earliest(...) over module deadlines. No module timers exist yet.
    return MonoTime::never();
}

Reply Engine::execute(const Command &cmd, MonoTime /*now*/) {
    ++stats_.commands;
    switch (cmd.kind) {
    case CommandKind::GetCapabilities:
        return get_capabilities(cmd);
    case CommandKind::NextEvent:
        return next_event(cmd);
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
