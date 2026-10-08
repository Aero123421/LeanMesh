#include "core/engine.hpp"

#include <cstring>

#include "core/diag/diag.hpp"
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
Status hook_admission(void *ctx) {
    Engine &e = eng(ctx);
    if (root_role(e)) {
        return e.ledger().admission();
    }
    return e.membership().switching() ? Status::Busy : Status::Ok; // [S18] no session of the old domain now
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
void hook_discovery(void *ctx, const MacAddr &src, const wire::BootstrapCarrier &c, uint32_t hint) {
    Engine &e = eng(ctx);
    if (root_role(e)) {
        e.ledger().discovery(src, c, e.step_time());
    } else if (c.object_kind == member::k_obj_join_hello) {
        e.proxy().answer_hello(c, e.step_time()); // [SLICE:S11] an attached relay offers to carry the join
    } else {
        e.membership().discovery(src, c, hint, e.step_time());
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
    h.admission = &hook_admission;
    h.session_up = &hook_session_up;
    h.exchange_failed = &hook_exchange_failed;
    h.discovery = &hook_discovery;
    h.join_control = &hook_join_control;
    h.link_control = &hook_link_control;
    h.link_up = &hook_link_up;
    if (!is_root()) {
        // FIX8-D5 (review H10): the membership's leave hooks are the production wiring. DRAIN waits until no send is
        // open (delivery), new sends are refused meanwhile (the stop's own drain keeps its refusal), and a committed
        // leave ends every open send honestly (INDETERMINATE if it may have left, else CANCELLED_NOT_SENT). Before,
        // nothing installed them: DRAIN acted as IMMEDIATE and open sends stayed PENDING for ever.
        member::MembershipHooks m;
        m.ctx = this;
        m.drained = [](void *c) {
            Engine &e = *static_cast<Engine *>(c);
            return !e.sends_open() && e.mesh_.drained(e.step_now_);
        };
        m.refuse_sends = [](void *c, bool on) {
            Engine &e = *static_cast<Engine *>(c);
            e.delivery_.set_draining(on || e.draining_);
        };
        m.settle_pending = [](void *c) {
            Engine &e = *static_cast<Engine *>(c);
            e.delivery_.end_open_sends(e.step_now_);
        };
        membership().set_hooks(m);
    }
}

Engine::Engine(const EngineConfig &config, Ports ports) : config_(config), ports_(ports) {
    link_.set_sink(&Engine::rx_sink, this); // [SLICE:S9] DATA / HOP_ACK go to delivery
    wire_join_hooks();                      // [SLICE:S8]
    link_.set_discovery_sink(&Engine::discovery_sink, this); // [SLICE:S11] mesh beacons
    link_.set_proxy_sink(&Engine::proxy_sink, this);         // [SLICE:S11] frames of a joiner behind us
    mesh_.install();                                         // [SLICE:S11] delivery plug points
    group_.install();                                        // [SLICE:S15] child hooks and the control sink
    delivery_.set_control_sink(&Engine::control_sink, this); // [SLICE:S18] lifecycle objects first, then groups
}

// [SLICE:S18] A complete control object from `origin`: a signed MemberCredential (a renewal the root sends) is the
// membership's; everything else is the group fan-out's (GroupSnapshotV2 pages and requests, S15).
void Engine::control_sink(void *ctx, const DeviceId &origin, const std::array<uint8_t, 16> & /*mid*/, ByteView payload,
                          MonoTime now) {
    auto *e = static_cast<Engine *>(ctx);
    member::Envelope env;
    ByteView data;
    if (!e->is_root() && (member::peek_signed(payload, member::k_type_member_credential, env, data) == Status::Ok ||
                          member::peek_signed(payload, member::k_type_revoke, env, data) == Status::Ok)) {
        e->membership().on_lifecycle_object(origin, payload, now); // a renewal or a revocation notice
        return;
    }
    e->group_.on_control(origin, payload, now);
}

bool Engine::proxy_sink(void *ctx, const port::RadioRx &rx, MonoTime now) {
    return static_cast<Engine *>(ctx)->proxy_.from_joiner(rx, now);
}

void Engine::discovery_sink(void *ctx, const MacAddr &src, ByteView body, MonoTime now) {
    static_cast<Engine *>(ctx)->mesh_.on_beacon(src, body, now);
}

void Engine::rx_sink(void *ctx, const link::RxInfo &info, ByteView plain) {
    auto *e = static_cast<Engine *>(ctx);
    if (info.restricted) { // SEC-D3: application DATA while the peer's lease cannot be proven: later, not lost
        e->delivery_.hop().queue_ack(info.src, info.peer, info.counter, wire::HopAckStatus::Busy, 1000, e->step_now_);
        return;
    }
    if (info.kind == wire::FrameKind::Route) { // [SLICE:S11] 1-hop routing control (probes)
        e->mesh_.on_route_frame(info, plain, e->step_now_);
        return;
    }
    if (info.kind == wire::FrameKind::Power) { // [SLICE:S16] authenticated poll/grant with the neighbour
        e->power_.on_frame(info, plain, e->step_now_);
        return;
    }
    e->power_.on_child_frame(info.src, e->step_now_); // [SLICE:S16] a sleepy child that sends is awake
    if (info.kind == wire::FrameKind::Data && !info.duplicate) {
        e->power_.note_rx(e->step_now_); // [SLICE:S16] a new frame: a sleep ticket in hand is stale
    }
    e->delivery_.on_link_rx(info, plain, e->step_now_);
}

MonoTime Engine::step(MonoTime now) {
    ++stats_.steps;
    step_now_ = now;
    if (power_.asleep()) { // [SLICE:S16] a sleeping owner does one thing: wake at its own timer
        const MonoTime d = power_.step_asleep(now);
        if (power_.asleep()) {
            return d;
        }
    }
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
        ledger().on_timer(now);
    } else {
        membership().on_timer(now);
    }
    power_.on_timer(now); // [SLICE:S16] episode/window ends, poll retry, mailbox expiry, ticket
    if (step_now_ != now) {
        return step_now_; // Woke advanced the clock: rerun all timers in a fresh pass
    }
    if (power_.asleep()) { // this very step put the node to sleep: nothing else may run on a stopped radio
        return next_deadline();
    }
    mesh_.on_timer(now); // [SLICE:S11] discovery, attach, leases, beacons
    proxy_.on_timer(now);
    group_.on_timer(now); // [SLICE:S15] dispatch, snapshot fetch, progress
    chan_.on_timer(now);  // [SLICE:S17] clock, plan guard and switch, recovery scan, survey visit
    if (is_root()) {
        coord_.on_timer(now); // [SLICE:S17]
    }
    if (is_root()) {
        routes_.on_timer(now);
    }
    if (serial_ != nullptr) {
        serial_->on_step(now); // [SLICE:S10] port input and USB timers
    }
    power_.after_step(now); // [SLICE:S16] sleep-prepare progress, radio-time accounting, PM locks
    if (step_now_ != now) {
        return step_now_; // after_step may also cross a synchronous sleep boundary
    }
    if (restart_pending_ && !jobs_.busy()) { // [SLICE:S18] a committed transfer/handover: boot into the new domain
        restart_pending_ = false;
        // FIX8-D14 (review L4): a restart that cannot bring the node up again is reported, never silent.
        if (stop_radio().status == Status::Ok) { // (a stop that fails is a fault already: enter_fault)
            const Status st = start_radio(now).status;
            if (st != Status::Ok && radio_state_ != RadioState::Faulted) {
                emit(LM_EVENT_FAULT, static_cast<uint32_t>(st));
            }
        }
    }
    drain_step(now);
    return next_deadline();
}

void Engine::on_radio_event(const port::RadioEvent &ev, MonoTime now) {
    if (ev.kind == port::RadioEvent::Kind::Rx) {
        ++stats_.rx_frames;
        mesh_.on_radio_rx(ev.rx); // parent RSSI (diagnostics): a field of the frame the driver callback already carried
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
    chan_.on_tx_outcome(o, now); // [SLICE:S17] survey probes
    mesh_.on_tx_outcome(o, now); // [SLICE:S11] probe results (the only RF samples the mesh takes from beacons/probes)
    if (member::is_join_tag(o.tag)) { // [SLICE:S8]
        if (is_root()) {
            ledger().on_tx_outcome(o, now);
        } else {
            membership().on_tx_outcome(o, now);
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
    case JobOwner::Power: // [SLICE:S16]
        power_.on_job_done(origin.slot, c.status, now);
        return;
    case JobOwner::Identity:
        ident_.on_job_done(c.status, origin.slot);
        if (ident_.state() == member::LocalIdentity::State::Ready) { // [SLICE:S8]
            power_.on_identity_ready(now); // [SLICE:S16] the power policy record, before anything runs on it
            chan_.on_identity_ready(now); // [SLICE:S17] the stored channel is applied before the mesh starts
            if (is_root()) {
                ledger().on_identity_ready(now);
            } else {
                membership().on_identity_ready(now);
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
    case JobOwner::Join: // [SLICE:S8] (only the joiner side submits these, the ledger only on the root: P8)
        if (!is_root()) {
            membership().on_job_done(origin.slot, c.status, now);
        }
        return;
    case JobOwner::Ledger:
        if (is_root()) {
            ledger().on_job_done(origin.slot, c.status, now);
        }
        return;
    case JobOwner::Channel: // [SLICE:S17]
        chan_.on_job_done(origin.slot, c.status, now);
        return;
    case JobOwner::Group: // [SLICE:S15]
        group_.on_job_done(origin.slot, c.status, now);
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
    if (power_.asleep()) {
        return power_.deadline(); // [SLICE:S16] asleep: nothing else may wake the owner
    }
    MonoTime next = tx_.deadline();
    next = earliest(next, power_.deadline()); // [SLICE:S16]
    if (radio_state_ == RadioState::Recovering) {
        next = earliest(next, recover_at_);
    }
    if (draining_) {
        next = earliest(next, drain_until_);
    }
    // [SLICE] next = earliest(next, x_.deadline()); over module deadlines.
    next = earliest(next, link_.deadline());
    next = earliest(next, delivery_.deadline()); // [SLICE:S9]
    next = earliest(next, is_root() ? roles_.b().deadline() : roles_.a().deadline()); // [SLICE:S8]
    next = earliest(next, mesh_.deadline()); // [SLICE:S11]
    next = earliest(next, proxy_.deadline());
    next = earliest(next, group_.deadline()); // [SLICE:S15]
    next = earliest(next, chan_.deadline());  // [SLICE:S17]
    if (is_root()) {
        next = earliest(next, coord_.deadline());
    }
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
    if (radio_state_ == RadioState::Asleep) {
        return Status::Busy; // [SLICE:S16] the driver is off on purpose: local, never RF loss
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
    if (!queued && !sched_.admit_direct(frame.size(), now)) {
        return Status::Busy; // FIX4-D3: direct traffic is bounded by the airtime bucket too; the caller retries later
    }
    const Status st = tx_.begin(ports_.radio, dst, frame, tag, now);
    if (st == Status::Ok) {
        sched_.charge(cls, frame.size(), now, queued); // the one accounting point of the node's airtime
    }
    return st;
}

void Engine::on_new_term(MonoTime now) {
    delivery_.invalidate_routes(); // routes of the old term (a lookup would refuse them anyway)
    delivery_.hop().pump(now);     // FIX6-D1: ready frames are checked against the new term now (Aborted -> EXPIRED / INDETERMINATE)
    mesh_.on_term(now);
    chan_.on_term(now);
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
    if ((operation & member::k_op_tag) != 0) { // a control operation: its status stays queryable after the event is taken
        if (kind == LM_EVENT_OPERATION) {
            // A control operation whose durable result is unknown (RECOVERY_REQUIRED, STORAGE_FAILURE) is
            // INDETERMINATE, never "rejected" (S18-D11, as the Host maps it; FIX8: leave, policy, group set, installs).
            const bool unknown = reason == static_cast<uint32_t>(Status::RecoveryRequired) ||
                                 reason == static_cast<uint32_t>(Status::StorageFailure);
            const uint8_t outcome = reason == 0 ? LM_OUTCOME_APPLIED
                                    : unknown   ? LM_OUTCOME_INDETERMINATE
                                                : LM_OUTCOME_REJECTED;
            note_ctl_op(operation, true, outcome, reason);
        } else if (kind == LM_EVENT_MEMBERSHIP) {
            note_ctl_op(operation, false, LM_OUTCOME_PENDING, 0); // accepted, in progress (never downgrades a final record)
        }
    }
    (void)events_.push(ev);
}

void Engine::note_ctl_op(uint64_t id, bool final, uint8_t outcome, uint32_t reason) {
    const uint64_t now_ms = step_now_.to_ms();
    CtlOp *slot = nullptr;
    for (CtlOp &r : ctl_ops_) {
        if (r.id == id) {
            slot = &r;
            break;
        }
    }
    if (slot == nullptr) { // a free slot, else the oldest finished record, else the oldest of all
        for (CtlOp &r : ctl_ops_) {
            const bool better = slot == nullptr || (slot->id != 0 && (r.id == 0 || (r.final && !slot->final) ||
                                                                     (r.final == slot->final && static_cast<int32_t>(r.seq - slot->seq) < 0)));
            slot = better ? &r : slot;
        }
        *slot = CtlOp{};
        slot->id = id;
        slot->accepted_ms = now_ms;
    }
    if (slot->final && !final) {
        return;
    }
    slot->final = final;
    slot->outcome = outcome;
    slot->reason = reason;
    slot->last_ms = now_ms;
    slot->seq = ++ctl_seq_;
}

Reply Engine::get_ctl_op(uint64_t id, lm_operation_t &out) const {
    for (const CtlOp &r : ctl_ops_) {
        if (r.id != 0 && r.id == id) {
            out = lm_operation_t{};
            out.struct_size = sizeof(out);
            out.abi_version = LM_ABI_VERSION;
            out.operation_id = id;
            out.phase = r.final ? 3U : 1U;
            out.outcome = r.outcome;
            out.reason = r.reason;
            out.accepted_mono_ms = r.accepted_ms;
            out.last_evidence_mono_ms = r.last_ms;
            return Reply{Status::Ok, id, 0};
        }
    }
    return Reply{Status::NotFound, 0, 0};
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
        s = ident_.begin_load(*this); // [SLICE:S5] identity/membership come from sealed records
    }
    if (s == Status::Ok) {
        // [SLICE:S9] boot incarnation, journal, durable recovery. Its job borrows the node's one record memory
        // (ADR-002 P4), which the identity load above holds first: it runs once the identity has it back.
        s = delivery_.start(now);
        if (s != Status::Ok) {
            ident_.release();
        }
    }
    if (s != Status::Ok) {
        if (ports_.radio.stop() != Status::Ok) {
            enter_fault(); // half-started driver that cannot be torn down: callbacks may be live
        }
        return Reply{s, 0, 0};
    }
    radio_state_ = RadioState::Running;
    if (first_start_.is_never()) {
        first_start_ = now; // [SLICE:S19]
    }
    power_.on_start(now); // [SLICE:S16] boot facts and budgets; the policy record loads with the identity
    emit(LM_EVENT_STARTED, 0);
    if (serial_ != nullptr) {
        serial_->on_started(now); // [SLICE:S10]
    }
    return Reply{Status::Ok, 0, 0};
}

// lm_stop(drain_ms): with nothing open, or drain_ms == 0, the stop happens inside the call (operation 0). Otherwise new
// sends are refused and the open ones get drain_ms to end on their own; the returned operation is the stop itself.
Reply Engine::begin_stop(uint32_t drain_ms, MonoTime now) {
    if (draining_) {
        return Reply{Status::Ok, stop_op_, 0}; // repeated: the same drain, its deadline unchanged
    }
    if (radio_state_ == RadioState::Stopped || drain_ms == 0 || !sends_open()) {
        return stop_radio();
    }
    draining_ = true;
    stop_op_ = next_control_op();
    drain_until_ = now + Duration::from_ms(drain_ms);
    delivery_.set_draining(true);
    note_ctl_op(stop_op_, false, LM_OUTCOME_PENDING, 0);
    return Reply{Status::Ok, stop_op_, 0};
}

bool Engine::sends_open() const { return delivery_.has_open_sends() || group_.has_open(); }

void Engine::drain_step(MonoTime now) {
    if (draining_ && (!sends_open() || now >= drain_until_)) {
        (void)stop_radio(); // what is still open at the deadline is ended INDETERMINATE there
    }
}

Reply Engine::stop_radio() {
    if (radio_state_ == RadioState::Stopped) {
        return Reply{Status::Ok, 0, 0};
    }
    const bool drained = draining_ && !sends_open();
    // Open sends are ended honestly below (a drain has already given them its time).
    if (serial_ != nullptr) {
        serial_->on_stop(); // [SLICE:S10] the USB session and its secrets go before the identity key
    }
    group_.end_for_stop(step_now_); // FIX13-D2: group operations and their targets end with a result before the pools go
    delivery_.end_pending_for_stop(step_now_); // FIX9-D4: no open send disappears without its final event
    coord_.stop(); // [SLICE:S17]
    chan_.stop();
    group_.stop(); // [SLICE:S15] payload buffers go back before delivery drops its pools
    groups_.stop();
    power_.stop(); // [SLICE:S16] PM locks off, children/tickets forgotten
    proxy_.stop();
    mesh_.stop(); // [SLICE:S11] candidates, leases and the tree go before the sessions they name
    routes_.stop();
    delivery_.stop(); // [SLICE:S9] operations, end sessions and their frames go before the link
    // The bodies these events announce went with the pools: the application must not read a payload_bytes it can no
    // longer get. A recovered durable message is announced anew. (Finished operations keep their result bytes.)
    events_.withdraw([](const lm_event_t &e) { return e.kind == LM_EVENT_MESSAGE; }); // finished operations stay queryable
    if (is_root()) { // [SLICE:S8] join sessions and borrowed buffers go back before link/identity
        ledger().stop();
    } else {
        membership().stop();
    }
    link_.stop(); // [SLICE:S5] sessions and the exchange go first (their peers are still registered)
    frames_.clear(); // [S14] every owner returned its frames above; a leak would not survive a restart
    ident_.release();
    const Status s = radio_state_ == RadioState::Asleep ? Status::Ok : ports_.radio.stop(); // [S16] already off
    if (draining_) { // the stop operation ends with the stop: APPLIED = everything ended in time, INDETERMINATE = cut short
        draining_ = false;
        delivery_.set_draining(false);
        const uint32_t why = s != Status::Ok ? static_cast<uint32_t>(s) : drained ? 0U : static_cast<uint32_t>(Status::Expired);
        const uint8_t out = s != Status::Ok ? LM_OUTCOME_REJECTED : drained ? LM_OUTCOME_APPLIED : LM_OUTCOME_INDETERMINATE;
        emit_event(LM_EVENT_OPERATION, why, stop_op_, nullptr);
        note_ctl_op(stop_op_, true, out, why); // after the event: its own outcome (APPLIED/REJECTED by reason) is refined
    }
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
    if (group::Fanout::wants(cmd)) { // [SLICE:S15] a send to a group, a group operation id, the group API
        const Reply r = group_.execute(cmd, now);
        if (cmd.kind == CommandKind::GroupSet && r.status == Status::Ok && (r.operation_id & member::k_op_tag) != 0) {
            note_ctl_op(r.operation_id, false, LM_OUTCOME_PENDING, 0); // FIX8-D10: queryable until durable
        }
        return r;
    }
    switch (cmd.kind) {
    case CommandKind::GetCapabilities:
        return get_capabilities(cmd);
    case CommandKind::DiagnosticsSnapshot:
        if (cmd.response == nullptr || cmd.response_size != sizeof(diag::Snapshot)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        diag::collect(*this, now, *static_cast<diag::Snapshot *>(cmd.response));
        return Reply{Status::Ok, 0, 0};
    case CommandKind::DiagnosticsGet: { // [SLICE:S19] answered from what the owner already keeps: no timer, no wake
        if (cmd.response == nullptr || cmd.response_size != sizeof(lm_diagnostics_t)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        diag::Snapshot snap;
        diag::collect(*this, now, snap);
        diag::to_abi(snap, *static_cast<lm_diagnostics_t *>(cmd.response));
        return Reply{Status::Ok, 0, 0};
    }
    case CommandKind::RootTimeGet: { // [ARCH2-D1] valid only for the term this node's frames carry
        if (cmd.response == nullptr || cmd.response_size != sizeof(lm_root_time_t)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        const RootTimeBound b = delivery_.root_time(now);
        auto &out = *static_cast<lm_root_time_t *>(cmd.response);
        out.valid = b.valid && ident_.is_member() && b.term == ident_.term() ? 1U : 0U;
        // FIX8-D13 (review L5): the identity's fields are the load job's while it runs: read only once Ready.
        out.root_term = out.valid != 0 ? b.term.value()
                        : ident_.state() == member::LocalIdentity::State::Ready ? ident_.term().value()
                                                                              : 0U;
        out.earliest_root_ms = out.valid != 0 ? b.earliest_ms : 0;
        out.latest_root_ms = out.valid != 0 ? b.latest_ms : 0;
        return Reply{Status::Ok, 0, 0};
    }
    case CommandKind::NextEvent:
        return next_event(cmd, now);
    case CommandKind::Start:
        return start_radio(now);
    case CommandKind::Stop: {
        const auto *drain_ms = static_cast<const uint32_t *>(cmd.request);
        return begin_stop(drain_ms != nullptr && cmd.request_size == sizeof(uint32_t) ? *drain_ms : 0U, now);
    }
    case CommandKind::Destroy:
        // Any job still in the table (identity load, link exchange, USB verify, ...) owns memory of this context and its
        // completion would be credited to whatever runs next in the same workspace: destroy waits for it (FIX9-D2).
        return Reply{radio_state_ == RadioState::Stopped && !jobs_.busy() && !delivery_.job_pending() && !role_job_pending() &&
                             !group_.job_pending() && !chan_.job_pending() && !power_.job_pending()
                         ? Status::Ok
                         : Status::Busy,
                     0, 0}; // [SLICE:S8] a cancelled join/ledger job still owns borrowed buffers
    case CommandKind::MembershipGet: // [SLICE:S8]
    case CommandKind::ConnectivityGet:
    case CommandKind::PolicyGet:
    case CommandKind::PolicySet:
    case CommandKind::Join:
    case CommandKind::Leave:
    case CommandKind::InstallControl:
    case CommandKind::GetRequest:
    case CommandKind::RootJoinDecide:
    case CommandKind::TransferNonce: { // [SLICE:S18]
        const Reply r = execute_membership(cmd, now);
        if (r.status == Status::Ok && (r.operation_id & member::k_op_tag) != 0) {
            note_ctl_op(r.operation_id, false, LM_OUTCOME_PENDING, 0); // visible to lm_get_operation from now on
        }
        return r;
    }
    case CommandKind::GetOperation: { // lifecycle / group-set / stop operations are answered here (FIX9-D9)
        const auto *id = static_cast<const uint64_t *>(cmd.request);
        if (id != nullptr && cmd.request_size == sizeof(uint64_t) && (*id & member::k_op_tag) != 0 &&
            cmd.response != nullptr && cmd.response_size == sizeof(lm_operation_t)) {
            return get_ctl_op(*id, *static_cast<lm_operation_t *>(cmd.response));
        }
        return delivery_.execute(cmd, now);
    }
    case CommandKind::Send: // [SLICE:S9]
    case CommandKind::SendObject: // [SLICE:S12]
    case CommandKind::SendControl:
    case CommandKind::Cancel:
    case CommandKind::ReportApplicationResult:
    case CommandKind::PayloadCapacity:
    case CommandKind::RootHostSend: // [SLICE:S13]
    case CommandKind::RootHostStoreAck:
        return delivery_.execute(cmd, now);
    case CommandKind::PowerPolicyGet: // [SLICE:S16]
    case CommandKind::PowerPolicySet:
    case CommandKind::PowerGet:
    case CommandKind::SleepPrepare:
    case CommandKind::SleepPrepareEx:
    case CommandKind::SleepTicketGet:
    case CommandKind::SleepAbort:
        return power_.execute(cmd, now);
    case CommandKind::SleepEnter:
        // FIX10-D8: a command is run before the step that would receive what is queued. Authenticated input that arrived
        // after the ticket was issued is handled first (it makes the ticket stale) and is never dropped by the radio stop.
        if (!drain_radio(now)) {
            power_.note_state_change();
        }
        return power_.execute(cmd, now);
    case CommandKind::ChannelRequest: { // [SLICE:S17] lm_channel_request (request: {action, expected_revision})
        const auto *rq = static_cast<const std::array<uint64_t, 2> *>(cmd.request);
        if (rq == nullptr || cmd.request_size != sizeof(*rq)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        // Only the root plans: another role answers as an image without the coordinator does (P8: it has no ledger).
        if (!is_root()) {
            return Reply{Status::Unsupported, 0, 0};
        }
        const Reply r = coord_.request(static_cast<uint32_t>((*rq)[0]), (*rq)[1], now);
        if (r.status == Status::Ok && (r.operation_id & member::k_op_tag) != 0) {
            note_ctl_op(r.operation_id, false, LM_OUTCOME_PENDING, 0); // FIX12-D5: queryable until the record is durable
        }
        return r;
    }
    case CommandKind::RootLedgerBackup: { // [ISSUE5] begin / read a page of the root's ledger backup
        if (!is_root() || cmd.request == nullptr || cmd.request_size != sizeof(LedgerBackupRequest)) {
            return Reply{is_root() ? Status::InvalidArgument : Status::Unsupported, 0, 0};
        }
        const auto &rq = *static_cast<const LedgerBackupRequest *>(cmd.request);
        if (rq.get == 0) {
            const uint64_t op = next_control_op();
            const Status s = ledger().backup_begin(op, now);
            if (s == Status::Ok) {
                note_ctl_op(op, false, LM_OUTCOME_PENDING, 0); // queryable until its event is taken
            }
            return Reply{s, s == Status::Ok ? op : 0, 0};
        }
        if (cmd.response == nullptr || cmd.response_size != sizeof(root::LedgerType::BackupPage)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        return Reply{ledger().backup_get(rq.seq, rq.index, *static_cast<root::LedgerType::BackupPage *>(cmd.response), now),
                     0, 0};
    }
    case CommandKind::RootLedgerRestore: { // [ISSUE5] restore a ledger onto this replacement root, one step per command
        if (!is_root() || cmd.request == nullptr || cmd.request_size != sizeof(LedgerRestoreRequest)) {
            return Reply{is_root() ? Status::InvalidArgument : Status::Unsupported, 0, 0};
        }
        const auto &rq = *static_cast<const LedgerRestoreRequest *>(cmd.request);
        const uint64_t op = next_control_op();
        Status s = Status::InvalidArgument;
        if (rq.step == 0) {
            s = ledger().restore_handover(cmd.payload, op, now);
        } else if (rq.step == 1) {
            s = ledger().restore_header(cmd.payload, op, now);
        } else if (rq.step == 2) {
            s = ledger().restore_element(rq.element, op, now);
        }
        if (s == Status::Ok) {
            note_ctl_op(op, false, LM_OUTCOME_PENDING, 0);
        }
        return Reply{s, s == Status::Ok ? op : 0, 0};
    }
    case CommandKind::GetMessage: { // [SLICE:S15] the Host's group send is found by its MessageId, too
        const Reply r = delivery_.execute(cmd, now);
        return r.status == Status::NotFound ? group_.execute(cmd, now) : r;
    }
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
    caps.build_bits = LM_FEATURE_GROUP_FANOUT_V2; // [SLICE:S15]
    caps.implemented_bits = LM_FEATURE_GROUP_FANOUT_V2;
    caps.qualified_bits = 0;
    caps.enabled_bits = LM_FEATURE_GROUP_FANOUT_V2;
    // [SLICE:S19] Small messages (512 B) exist on every build. The 4 KiB object lane is compiled only with
    // LM_OBJECT_TRANSFER and is enabled by the application's config; a build without it reports neither bit.
    constexpr uint64_t k_small = LM_FEATURE_SMALL_MESSAGE;
    caps.build_bits |= k_small;
    caps.implemented_bits |= k_small;
    caps.enabled_bits |= k_small;
    if (delivery::k_object_capable) {
        caps.build_bits |= LM_FEATURE_OBJECT_4K;
        caps.implemented_bits |= LM_FEATURE_OBJECT_4K;
        caps.enabled_bits |= config_.object_transfer_enabled ? LM_FEATURE_OBJECT_4K : 0;
    }
    // [SLICE:S16] The power modes are built and implemented; they are enabled only where the platform has a sleep
    // port, and qualified nowhere (no HIL). RTC secure resume is reserved: implemented and enabled stay false.
    constexpr uint64_t k_power = LM_FEATURE_POWER_REPORT_ONLY | LM_FEATURE_POWER_WINDOWED_RX | LM_FEATURE_RAM_SESSION_RETAIN;
    caps.build_bits |= k_power;
    caps.implemented_bits |= k_power;
    caps.enabled_bits |= ports_.pm != nullptr ? k_power : 0;
    caps.max_root_depth = gen::limits::root_depth;
    caps.max_path_hops = gen::limits::path_hops;
    caps.max_message_bytes = gen::limits::small_message_bytes;
    caps.max_object_bytes = config_.object_transfer_enabled ? gen::limits::object_bytes : 0;
    caps.max_members = limits_for(config_.role).members;
    caps.max_regular_peers = gen::limits::regular_peers;
    // Common lower bound for every supported path (40 hops): 136 - 2*40 (docs/09 §5, docs/10).
    caps.available_single_frame_bytes = 136 - 2 * gen::limits::path_hops;
    // [SLICE:S17] The channel module is in every image; it is enabled where it runs (the bench can switch it off).
    // qualified_bits stay 0 until the RF tests pass.
    caps.build_bits |= LM_FEATURE_AUTO_CHANNEL;
    caps.implemented_bits |= LM_FEATURE_AUTO_CHANNEL;
    caps.enabled_bits |= chan_.enabled() ? LM_FEATURE_AUTO_CHANNEL : 0;
    // [SLICE:S18] Every image moves its membership by a signed transfer and follows a RootHandover; the commissioning
    // window is a root's admission rule (root-capable images, enabled on the root). Qualified nowhere yet (no HIL).
    constexpr uint64_t k_lifecycle = LM_FEATURE_SIGNED_TRANSFER | LM_FEATURE_ROOT_HANDOVER;
    caps.build_bits |= k_lifecycle | (k_root_capable ? LM_FEATURE_COMMISSIONING_WINDOW : 0);
    caps.implemented_bits |= k_lifecycle | (k_root_capable ? LM_FEATURE_COMMISSIONING_WINDOW : 0);
    caps.enabled_bits |= k_lifecycle | (config_.role == Role::Root ? LM_FEATURE_COMMISSIONING_WINDOW : 0);
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
    ByteView payload;
    bool has_payload = false;
    // An event that announces a body must hand it out: one whose body is gone is withdrawn (one GAP), never returned
    // with a payload_bytes that no bytes back.
    while (front != nullptr) {
        has_payload = delivery_.event_payload(*front, payload);
        const bool needs = front->kind == LM_EVENT_MESSAGE || (front->kind == LM_EVENT_OPERATION && front->payload_bytes > 0);
        if (has_payload || !needs) {
            break;
        }
        const uint64_t seq = front->event_sequence;
        events_.withdraw([seq](const lm_event_t &e) { return e.event_sequence == seq; });
        front = events_.peek();
    }
    if (front == nullptr) {
        // No event pending (decision: NOT_FOUND; see docs/IMPLEMENTATION.md §10).
        return Reply{Status::NotFound, 0, 0};
    }
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
