#include "core/engine.hpp"

#include <cstring>

#include "gen/registry.hpp"

namespace lm {

namespace {
// [SLICE:S8] Join hook trampolines. The root answers joins from its ledger; every other role acts
// as a joiner. `ctx` is the Engine.
Engine &eng(void *ctx) { return *static_cast<Engine *>(ctx); }
bool root_role(const Engine &e) { return k_root_capable && e.config().role == Role::Root; }

bool hook_responder_open(void *ctx) { return root_role(eng(ctx)) && eng(ctx).ledger().responder_open(); }
bool hook_link_admit(void *ctx, const DeviceId &d, const member::MemberCredential &mc) {
    return !root_role(eng(ctx)) || eng(ctx).ledger().link_admit(d, mc);
}
void hook_session_up(void *ctx, bool initiator, const MacAddr &mac, const DeviceId &peer, ByteView bundle,
                     const Sha256Digest &peer_hash) {
    Engine &e = eng(ctx);
    if (root_role(e)) {
        if (!initiator) {
            e.ledger().session_up(mac, peer, peer_hash, e.step_time());
        }
    } else {
        e.membership().session_up(initiator, mac, peer, bundle, e.step_time());
    }
}
void hook_exchange_failed(void *ctx, Status why) {
    Engine &e = eng(ctx);
    if (!root_role(e)) {
        e.membership().exchange_failed(why, e.step_time());
    }
}
void hook_discovery(void *ctx, const MacAddr &src, const wire::BootstrapCarrier &c) {
    Engine &e = eng(ctx);
    if (root_role(e)) {
        e.ledger().discovery(src, c, e.step_time());
    } else if (c.object_kind == member::k_obj_join_hello) {
        e.proxy().answer_hello(c, e.step_time()); // [SLICE:S11] an attached relay offers to carry the join
    } else {
        e.membership().discovery(src, c, e.step_time());
    }
}
void hook_join_control(void *ctx, const link::RxInfo &info, ByteView plain) {
    Engine &e = eng(ctx);
    if (root_role(e)) {
        e.ledger().join_control(info, plain, e.step_time());
    } else {
        e.membership().join_control(info, plain, e.step_time());
    }
}
bool hook_link_control(void *ctx, const link::RxInfo &info, ByteView plain) {
    Engine &e = eng(ctx);
    return root_role(e) ? e.ledger().link_control(info, plain, e.step_time())
                        : e.membership().link_control(info, plain, e.step_time());
}
void hook_link_up(void *ctx, const DeviceId &peer, uint8_t role) {
    Engine &e = eng(ctx);
    e.mesh().on_link_up(peer, e.step_time()); // [SLICE:S11]
    if (!root_role(e)) {
        e.membership().link_up(peer, role, e.step_time());
    }
}
} // namespace

void Engine::wire_join_hooks() {
    link::JoinHooks &h = link_.join_hooks();
    h.ctx = this;
    h.responder_open = &hook_responder_open;
    h.link_admit = &hook_link_admit;
    h.session_up = &hook_session_up;
    h.exchange_failed = &hook_exchange_failed;
    h.discovery = &hook_discovery;
    h.join_control = &hook_join_control;
    h.link_control = &hook_link_control;
    h.link_up = &hook_link_up;
}

Engine::Engine(const EngineConfig &config, Ports ports) : config_(config), ports_(ports) {
    link_.set_sink(&Engine::rx_sink, this); // [SLICE:S9] DATA / HOP_ACK go to delivery
    wire_join_hooks();                      // [SLICE:S8]
    link_.set_discovery_sink(&Engine::discovery_sink, this); // [SLICE:S11] mesh beacons
    link_.set_proxy_sink(&Engine::proxy_sink, this);         // [SLICE:S11] frames of a joiner behind us
    mesh_.install();                                         // [SLICE:S11] delivery plug points
}

bool Engine::proxy_sink(void *ctx, const port::RadioRx &rx, MonoTime now) {
    return static_cast<Engine *>(ctx)->proxy_.from_joiner(rx, now);
}

void Engine::discovery_sink(void *ctx, const MacAddr &src, ByteView body, MonoTime now) {
    static_cast<Engine *>(ctx)->mesh_.on_beacon(src, body, now);
}

void Engine::rx_sink(void *ctx, const link::RxInfo &info, ByteView plain) {
    auto *e = static_cast<Engine *>(ctx);
    if (info.kind == wire::FrameKind::Route) { // [SLICE:S11] 1-hop routing control (probes)
        e->mesh_.on_route_frame(info, plain, e->step_now_);
        return;
    }
    e->delivery_.on_link_rx(info, plain, e->step_now_);
}

MonoTime Engine::step(MonoTime now) {
    ++stats_.steps;
    step_now_ = now;
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
    link_.on_timer(now); // [SLICE:S5] session expiry, rotation, exchange RTO: all real deadlines
    delivery_.on_timer(now); // [SLICE:S9] link retry, E2E rounds, exchange RTO, receipts
    if (is_root()) { // [SLICE:S8] join transactions, reservations, queued commits: real deadlines
        ledger_.on_timer(now);
    } else {
        membership_.on_timer(now);
    }
    mesh_.on_timer(now); // [SLICE:S11] discovery, attach, leases, beacons
    proxy_.on_timer(now);
    if (is_root()) {
        routes_.on_timer(now);
    }
    if (serial_ != nullptr) {
        serial_->on_step(now); // [SLICE:S10] port input and USB timers
    }
    return next_deadline();
}

void Engine::on_radio_event(const port::RadioEvent &ev, MonoTime now) {
    if (ev.kind == port::RadioEvent::Kind::Rx) {
        ++stats_.rx_frames;
        // [SLICE:S5 LINK] header decode, SID lookup, AEAD open, kind dispatch. A valid frame with no
        // consumer yet (discovery, join proxy, no sink) is counted, never acted on.
        if (!link_.on_rx(ev.rx, now)) {
            ++stats_.rx_unhandled;
        }
        return;
    }
    TxOutcome out;
    if (!tx_.on_tx_done(ev.done, out)) {
        ++stats_.tx_done_unmatched;
        return;
    }
    on_tx_outcome(out, now);
}

void Engine::on_tx_outcome(const TxOutcome &o, MonoTime now) {
    // [SLICE:S5 LINK] MacFailed is an RF-loss sample, MacAcked is not a HOP_ACK, Unknown is neither
    // (docs/03 §4). The exchange frees its TX slot and retransmits by RTO, not by outcome.
    link_.on_tx_outcome(o, now);
    delivery_.on_tx_outcome(o, now); // [SLICE:S9] its own tags; also pumps the next frame
    mesh_.on_tx_outcome(o, now); // [SLICE:S11] probe results (the only RF samples the mesh takes from beacons/probes)
    if (member::is_join_tag(o.tag)) { // [SLICE:S8]
        if (is_root()) {
            ledger_.on_tx_outcome(o, now);
        } else {
            membership_.on_tx_outcome(o, now);
        }
    }
}

Status Engine::submit_job(JobOwner owner, Handle slot, JobClass cls, port::JobFn fn, void *arg) {
    JobTicket t;
    LM_TRY(jobs_.reserve(owner, slot, cls, t));
    const Status s = ports_.jobs.submit(t.table_index, t.job_id, fn, arg);
    if (s != Status::Ok) {
        jobs_.cancel_unsubmitted(t);
    }
    return s;
}

void Engine::on_job_completion(const port::JobCompletion &c, MonoTime now) {
    JobOrigin origin;
    if (!jobs_.complete(c, origin)) {
        stats_.stale_job_completions = jobs_.stale_completions();
        return;
    }
    switch (origin.owner) {
    // [SLICE] case JobOwner::X: x_.on_job_done(origin.slot, c.status, now); return;
    case JobOwner::Serial:
        if (serial_ != nullptr) {
            serial_->on_job_done(origin.slot, c.status, now); // [SLICE:S10]
        }
        return;
    case JobOwner::Identity:
        ident_.on_job_done(c.status, origin.slot);
        if (ident_.state() == member::LocalIdentity::State::Ready) { // [SLICE:S8]
            if (is_root()) {
                ledger_.on_identity_ready(now);
            } else {
                membership_.on_identity_ready(now);
            }
        }
        if (serial_ != nullptr) {
            serial_->on_identity(now); // [SLICE:S10] the USB link needs the loaded identity
        }
        if (ident_.state() == member::LocalIdentity::State::Failed) {
            emit(LM_EVENT_FAULT, static_cast<uint32_t>(ident_.load_status()));
        }
        return;
    case JobOwner::Link:
        link_.on_job_done(origin.slot, c.status, now);
        return;
    case JobOwner::Join: // [SLICE:S8]
        membership_.on_job_done(origin.slot, c.status, now);
        return;
    case JobOwner::Ledger:
        ledger_.on_job_done(origin.slot, c.status, now);
        return;
    case JobOwner::Durable: // [SLICE:S9]
        delivery_.on_job_done(origin.owner, origin.slot, c.status, now);
        return;
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
    next = earliest(next, link_.deadline());
    next = earliest(next, delivery_.deadline()); // [SLICE:S9]
    next = earliest(next, is_root() ? ledger_.deadline() : membership_.deadline()); // [SLICE:S8]
    next = earliest(next, mesh_.deadline()); // [SLICE:S11]
    next = earliest(next, proxy_.deadline());
    if (is_root()) {
        next = earliest(next, routes_.deadline());
    }
    if (serial_ != nullptr) {
        next = earliest(next, serial_->deadline()); // [SLICE:S10]
    }
    if (yield_) {
        return MonoTime{0}; // "now or earlier": the platform loop steps again immediately
    }
    return next;
}

Status Engine::transmit(const MacAddr &dst, ByteView frame, uint32_t tag, MonoTime now, sched::Class cls,
                        bool queued) {
    if (radio_state_ == RadioState::Recovering || radio_state_ == RadioState::Faulted) {
        return Status::DriverResultUnknown;
    }
    if (radio_state_ != RadioState::Running) {
        return Status::Conflict; // radio not started (lm_start not completed)
    }
    if (k_root_capable && proxy_.owns(dst)) { // [SLICE:S11] a joiner behind a relay: through the tunnel, not the radio
        return proxy_.transmit(dst, frame, tag, now);
    }
    if (!dst.is_broadcast() && !peers_.has(dst)) {
        return Status::InvalidArgument; // register the peer first (docs/03 §3)
    }
    const Status st = tx_.begin(ports_.radio, dst, frame, tag, now);
    if (st == Status::Ok) {
        sched_.charge(cls, frame.size(), now, queued); // the one accounting point of the node's airtime
    }
    return st;
}

Status Engine::set_channel(uint8_t channel) {
    if (radio_state_ != RadioState::Running) {
        return Status::Conflict;
    }
    LM_TRY(ports_.radio.set_channel(channel));
    channel_ = channel;
    return Status::Ok;
}

void Engine::emit_event(uint32_t kind, uint32_t reason, uint64_t operation, const DeviceId *peer) {
    lm_event_t ev{};
    ev.struct_size = sizeof(ev);
    ev.abi_version = LM_ABI_VERSION;
    ev.kind = kind;
    ev.reason = reason;
    ev.operation_id = operation;
    if (peer != nullptr) {
        std::memcpy(ev.peer.bytes, peer->bytes.data(), 32);
    }
    (void)events_.push(ev);
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

Reply Engine::start_radio(MonoTime now) {
    if (radio_state_ != RadioState::Stopped) {
        return Reply{Status::Conflict, 0, 0};
    }
    channel_ = 0; // a fresh start uses the profile channel
    Status s = bring_up_radio();
    if (s == Status::Ok) {
        s = delivery_.start(now); // [SLICE:S9] boot incarnation, journal, durable recovery
    }
    if (s == Status::Ok) {
        s = ident_.begin_load(*this); // [SLICE:S5] identity/membership come from sealed records
        if (s != Status::Ok) {
            delivery_.stop();
        }
    }
    if (s != Status::Ok) {
        if (ports_.radio.stop() != Status::Ok) {
            enter_fault(); // half-started driver that cannot be torn down: callbacks may be live
        }
        return Reply{s, 0, 0};
    }
    radio_state_ = RadioState::Running;
    emit(LM_EVENT_STARTED, 0);
    if (serial_ != nullptr) {
        serial_->on_started(now); // [SLICE:S10]
    }
    return Reply{Status::Ok, 0, 0};
}

Reply Engine::stop_radio() {
    if (radio_state_ == RadioState::Stopped) {
        return Reply{Status::Ok, 0, 0};
    }
    // No operation exists yet that needs a drain (delivery slices add it): stop is immediate.
    if (serial_ != nullptr) {
        serial_->on_stop(); // [SLICE:S10] the USB session and its secrets go before the identity key
    }
    proxy_.stop();
    mesh_.stop(); // [SLICE:S11] candidates, leases and the tree go before the sessions they name
    routes_.stop();
    delivery_.stop(); // [SLICE:S9] operations, end sessions and their frames go before the link
    membership_.stop(); // [SLICE:S8] join session and borrowed buffers go back before link/identity
    ledger_.stop();
    link_.stop(); // [SLICE:S5] sessions and the exchange go first (their peers are still registered)
    frames_.clear(); // [S14] every owner returned its frames above; a leak would not survive a restart
    ident_.release();
    const Status s = ports_.radio.stop();
    if (s != Status::Ok) {
        // The driver may still call back into ring buffers: Stopped (and so lm_destroy) is only
        // allowed after a successful teardown. A later lm_stop retries (FIX1-D5).
        enter_fault();
        return Reply{s, 0, 0};
    }
    tx_.reinitialised();
    radio_state_ = RadioState::Stopped;
    recover_at_ = MonoTime::never();
    return Reply{Status::Ok, 0, 0};
}

void Engine::enter_fault() {
    if (radio_state_ == RadioState::Faulted) {
        return; // a retried stop() that fails again is not a new fault
    }
    ++stats_.radio_faults;
    radio_state_ = RadioState::Faulted;
    recover_at_ = MonoTime::never();
    emit(LM_EVENT_FAULT, static_cast<uint32_t>(Status::DriverResultUnknown));
}

// Unknown TX result: the old driver instance may still call back. Stop it, start a new one (new
// driver generation, so no old callback can match) and register the peers again. Bounded retries;
// then FAULT and stay isolated until the application stops and starts the SDK (docs/03 §4).
void Engine::recover_radio(MonoTime now) {
    Status s = ports_.radio.stop();
    if (s == Status::Ok) {
        s = bring_up_radio();
    }
    if (s == Status::Ok) {
        ++stats_.radio_restarts;
        radio_state_ = RadioState::Running;
        recover_at_ = MonoTime::never();
        return;
    }
    if (++recover_attempts_ >= k_radio_recover_attempts) {
        enter_fault();
        return;
    }
    recover_at_ = now + k_radio_recover_backoff;
}

Reply Engine::execute(const Command &cmd, MonoTime now) {
    ++stats_.commands;
    step_now_ = now; // hooks and completions reached from a command see the command's time
    switch (cmd.kind) {
    case CommandKind::GetCapabilities:
        return get_capabilities(cmd);
    case CommandKind::NextEvent:
        return next_event(cmd, now);
    case CommandKind::Start:
        return start_radio(now);
    case CommandKind::Stop:
        return stop_radio();
    case CommandKind::Destroy:
        return Reply{radio_state_ == RadioState::Stopped && !delivery_.job_pending() && !membership_.job_pending() &&
                             !ledger_.job_pending()
                         ? Status::Ok
                         : Status::Busy,
                     0, 0}; // [SLICE:S8] a cancelled join/ledger job still owns borrowed buffers
    case CommandKind::MembershipGet: // [SLICE:S8]
    case CommandKind::Join:
    case CommandKind::Leave:
    case CommandKind::InstallControl:
    case CommandKind::GetRequest:
    case CommandKind::RootJoinDecide:
        return execute_membership(cmd, now);
    case CommandKind::Send: // [SLICE:S9]
    case CommandKind::SendObject: // [SLICE:S12]
    case CommandKind::SendControl:
    case CommandKind::GetOperation:
    case CommandKind::GetMessage:
    case CommandKind::Cancel:
    case CommandKind::ReportApplicationResult:
    case CommandKind::PayloadCapacity:
    case CommandKind::RootHostSend: // [SLICE:S13]
    case CommandKind::RootHostStoreAck:
        return delivery_.execute(cmd, now);
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

Reply Engine::next_event(const Command &cmd, MonoTime now) {
    if (cmd.response == nullptr || cmd.response_size != sizeof(lm_event_t)) {
        return Reply{Status::InvalidArgument, 0, 0};
    }
    // [SLICE:S9] The payload capacity is checked BEFORE popping: BufferTooSmall must not consume
    // the event (docs/10 §2).
    const lm_event_t *front = events_.peek();
    if (front == nullptr) {
        // No event pending (decision: NOT_FOUND; see docs/IMPLEMENTATION.md §10).
        return Reply{Status::NotFound, 0, 0};
    }
    ByteView payload;
    const bool has_payload = delivery_.event_payload(*front, payload);
    if (has_payload && cmd.response_payload.size() < payload.size()) {
        return Reply{Status::BufferTooSmall, 0, payload.size()};
    }
    lm_event_t ev{};
    (void)events_.pop(ev);
    if (has_payload && !payload.empty()) {
        std::memcpy(cmd.response_payload.data(), payload.data(), payload.size());
    }
    std::memcpy(cmd.response, &ev, sizeof(ev));
    const std::size_t taken = has_payload ? payload.size() : 0;
    delivery_.on_event_taken(ev, now);  // the payload buffer is free again
    delivery_.flush_events(now);        // events that did not fit earlier follow
    return Reply{Status::Ok, 0, taken};
}

} // namespace lm
