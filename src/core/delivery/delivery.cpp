// Delivery: shared helpers, lifecycle, timers, events and the command entry point. The origin
// (delivery_tx.cpp), the destination/relay (delivery_rx.cpp) and the journal glue
// (delivery_durable.cpp) are split by who acts, not by size.
#include "core/delivery/delivery.hpp"

#include <algorithm>
#include <cstring>

#include "core/engine.hpp"

namespace lm::delivery {
namespace {

constexpr int64_t k_drift_ppm = 500; // qualified clock drift bound (config channel.qualified_clock_drift_ppm)

lm_message_id_t abi_mid(const std::array<uint8_t, 16> &b) {
    lm_message_id_t m{};
    std::memcpy(m.bytes, b.data(), 16);
    return m;
}

lm_device_id_t abi_dev(const DeviceId &d) {
    lm_device_id_t x{};
    std::memcpy(x.bytes, d.bytes.data(), 32);
    return x;
}

} // namespace

Delivery::Delivery(Engine &engine, member::LocalIdentity &identity, link::LinkLayer &link)
    : engine_(engine), identity_(identity), link_(link), hop_(engine, link), durable_(engine) {
    HopTx::Hooks hh;
    hh.ctx = this;
    hh.may_send = &hop_may_send;
    hh.done = &hop_done;
    hop_.set_hooks(hh);
    link::EndPort ep; // end sessions are set up by the node's single exchange in end mode
    ep.ctx = this;
    ep.sessions = &sessions_;
    ep.root_time = &exchange_root_time;
    ep.send = &exchange_send;
    ep.done = &exchange_done;
    link_.exchange().set_end_port(ep);
    Durable::Hooks dh;
    dh.ctx = this;
    dh.fill = &durable_fill;
    dh.done = &durable_done;
    dh.boot_done = &durable_boot_done;
    dh.read_done = &durable_read_done;
    durable_.set_hooks(dh);
}

// ---- small helpers ----
RootTerm Delivery::local_term() const {
    return identity_.is_member() ? identity_.term() : RootTerm{};
}

ShortAddr Delivery::self_addr() const {
    return identity_.is_member() ? identity_.member().address : ShortAddr{};
}

void Delivery::refresh_bound(MonoTime now) {
    bound_ = anchor_;
    if (!anchor_.valid || now < anchor_at_) {
        return;
    }
    const int64_t elapsed_us = (now - anchor_at_).us;
    const auto adv = static_cast<uint64_t>(elapsed_us / 1000);
    const auto slack = static_cast<uint64_t>(elapsed_us * k_drift_ppm / 1'000'000 / 1000) + 1;
    bound_.earliest_ms = anchor_.earliest_ms + (adv > slack ? adv - slack : 0);
    bound_.latest_ms = anchor_.latest_ms + adv + slack;
}

DeadlineCheck Delivery::deadline_state(uint64_t expires, uint32_t term) const {
    if (expires == 0) {
        return DeadlineCheck::Before; // no deadline (only RECEIVED+DURABLE records may have none)
    }
    return check_deadline(bound_, RootTime{RootTerm{term}, expires});
}

// A deadline this node puts on its own frames must be of the term those frames carry (the node's current term,
// ARCH2-D1): a deadline of another term would be read on the wrong clock at every hop and at the destination.
DeadlineCheck Delivery::own_deadline(uint64_t expires, uint32_t term) const {
    if (expires != 0 && term != local_term().value()) {
        return DeadlineCheck::Uncertain;
    }
    return deadline_state(expires, term);
}

MonoTime Delivery::local_deadline(uint64_t expires, uint32_t term, MonoTime now) const {
    if (expires == 0 || !bound_.valid || bound_.term.value() != term) {
        return MonoTime::never();
    }
    const uint64_t ms = expires > bound_.earliest_ms ? expires - bound_.earliest_ms : 0;
    return now + Duration::from_ms(static_cast<int64_t>(ms));
}

void Delivery::set_root_time(const RootTimeBound &t, MonoTime now) {
    anchor_ = t;
    anchor_at_ = now;
    refresh_bound(now);
    link_.set_root_time(t);
    // Every operation re-checks its deadline against the new estimate (a restarted root ends the
    // time base of the old deadlines at once).
    Handle hs[k_actives];
    std::size_t n = 0;
    for (std::size_t i = 0; i < k_actives; ++i) {
        const Handle h = actives_.handle_at(i);
        if (actives_.get(h) != nullptr) {
            hs[n++] = h;
        }
    }
    for (std::size_t i = 0; i < n; ++i) {
        drive(hs[i], now);
    }
}

Op *Delivery::find_op(uint64_t id) {
    for (Op &o : ops_) {
        if (o.used && o.id == id) {
            return &o;
        }
    }
    return nullptr;
}

Op *Delivery::find_op_by_message(const DeviceId &dest, const std::array<uint8_t, 16> &mid) {
    for (Op &o : ops_) {
        if (o.used && !o.report && o.dest == dest && to_bytes(o.mid) == mid) {
            return &o;
        }
    }
    return nullptr;
}

Op *Delivery::alloc_op() {
    Op *victim = nullptr;
    for (Op &o : ops_) {
        if (!o.used) {
            return &o;
        }
        if (o.phase == Phase::Final && o.active.is_none() &&
            (victim == nullptr || static_cast<int32_t>(o.seq - victim->seq) < 0)) {
            victim = &o;
        }
    }
    if (victim != nullptr) {
        *victim = Op{};
    }
    return victim; // nullptr: every slot is a live operation (NO_CAPACITY, nothing dropped)
}

void Delivery::fill_operation(const Op &op, lm_operation_t &out) const {
    out = lm_operation_t{};
    out.struct_size = sizeof(out);
    out.abi_version = LM_ABI_VERSION;
    out.operation_id = op.id;
    out.message_id = abi_mid(to_bytes(op.mid));
    out.phase = static_cast<uint32_t>(op.phase);
    out.outcome = op.outcome;
    out.reason = op.reason;
    out.evidence_bits = op.evidence;
    std::memcpy(out.intent_hash, op.hash.data(), 32);
    out.accepted_mono_ms = op.accepted_ms;
    out.last_evidence_mono_ms = op.last_evidence_ms;
}

void Delivery::note_evidence(Op &op, uint32_t bits, MonoTime now) {
    op.evidence |= bits;
    op.last_evidence_ms = now.to_ms();
}

void Delivery::emit_op_event(const Op &op, MonoTime now) {
    if (op.group) { // [S15] a group target reports to its group, never to the application queue
        if (group_.child != nullptr && op.phase == Phase::Final) {
            group_.child(group_.ctx, op, now);
        }
        return;
    }
    lm_event_t ev{};
    ev.struct_size = sizeof(ev);
    ev.abi_version = LM_ABI_VERSION;
    ev.kind = LM_EVENT_OPERATION;
    ev.reason = op.reason;
    ev.observed_mono_ms = now.to_ms();
    ev.operation_id = op.id;
    ev.peer = abi_dev(op.dest);
    ev.message_id = abi_mid(to_bytes(op.mid));
    ev.origin_assignment_generation = op.assignment;
    std::memcpy(ev.intent_hash, op.hash.data(), 32);
    ev.app_port = op.port;
    ev.payload_bytes = op.result_len;
    (void)engine_.push_event(ev); // a full queue records a GAP; get_operation resynchronises
}

// Sets the final outcome. Definite evidence (applied/rejected) is never replaced by weaker
// knowledge; an unknown outcome (indeterminate/expired) may still be upgraded by a late receipt.
void Delivery::finalize(Op &op, uint8_t outcome, uint32_t reason, MonoTime now) {
    op.phase = Phase::Final;
    op.outcome = outcome;
    op.reason = reason;
    op.last_evidence_ms = now.to_ms();
    emit_op_event(op, now);
}

// ---- lifecycle ----
Status Delivery::start(MonoTime now) {
    ready_ = false;
    recovering_ = false;
    return durable_.begin_boot(now);
}

// lm_stop does not wait for receipts (FIX9-D4): every send still open gets its final event now. A send that may have
// left the node, or whose journal record survives to be sent after the restart, is INDETERMINATE (a recovered message
// gets a new operation); one that provably never left and has no record ends CANCELLED_NOT_SENT. Never a silent drop.
void Delivery::end_open_sends(MonoTime now) {
    for (Op &o : ops_) {
        if (!o.used || o.report || o.phase == Phase::Final || o.active.is_none()) {
            continue; // (a durable cancel waiting for its retire ends by itself)
        }
        if (left_node(o.active, o)) {
            finalize_active(o.active, LM_OUTCOME_INDETERMINATE, static_cast<uint32_t>(Status::CancelTooLate), now);
        } else {
            (void)cancel(o.id, now);
        }
    }
}

void Delivery::end_pending_for_stop(MonoTime now) {
    for (Op &o : ops_) {
        if (!o.used || o.report || o.group || o.phase == Phase::Final) {
            continue;
        }
        const bool may_be_out = !o.active.is_none() ? left_node(o.active, o)
                                                     : (o.evidence & (ev::sent | ev::persisted)) != 0;
        // FIX13-D1: a durable send whose journal Put is queued or submitted may finish after the stop (the persisted
        // bit comes only with its completion) and is then recovered and sent: it is treated as persisted.
        const Active *a = actives_.get(o.active);
        const bool journaled = (o.evidence & ev::persisted) != 0 || (a != nullptr && a->durable);
        if (may_be_out || journaled) {
            finalize(o, LM_OUTCOME_INDETERMINATE, static_cast<uint32_t>(Status::CancelTooLate), now);
        } else {
            finalize(o, LM_OUTCOME_CANCELLED_NOT_SENT, 0, now);
        }
    }
}

void Delivery::stop() {
    hop_.clear(); // the exchange itself stops with the link layer (Engine::stop_radio)
    durable_.stop();
    for (std::size_t i = 0; i < k_actives; ++i) {
        (void)actives_.release(actives_.handle_at(i));
    }
    for (std::size_t i = 0; i < k_in_entries; ++i) {
        (void)in_.release(in_.handle_at(i));
    }
    lives_ = {};
    for (std::size_t i = 0; i < k_build_limits.app_messages; ++i) {
        (void)msgs_.release(msgs_.handle_at(i));
    }
    for (Op &o : ops_) { // finished operations stay queryable across the stop (a result, an outcome the application awaits)
        if (!o.used || o.phase != Phase::Final) {
            o = Op{};
        } else {
            o.active = Handle{};
        }
    }
    draining_ = false;
    routes_.clear();
    accepted_ = {};
    frag_.reset(); // [S12] reassembly slots (their pool buffers went above); the control sink stays
    out_j_ = {};
    out_retire_ = {};
    out_cancel_op_ = {};
    out_cancel_reason_ = {};
    in_j_ = {};
    sessions_.clear();
    ready_ = false;
    recovering_ = false;
    retry_kick_ = MonoTime::never();
    slot_wait_ = false;
    // mesh_ stays: the hooks belong to the engine's modules, which outlive a start/stop cycle
}

void Delivery::on_tx_outcome(const TxOutcome &o, MonoTime now) {
    refresh_bound(now);
    hop_.on_tx_outcome(o, now);
}

void Delivery::on_job_done(JobOwner owner, Handle slot, Status s, MonoTime now) {
    refresh_bound(now);
    if (owner == JobOwner::Durable) {
        durable_.on_job_done(slot, s, now);
    }
}

void Delivery::on_timer(MonoTime now) {
    refresh_bound(now);
    durable_.pump(now); // P4: a journal job that waited for the record memory runs once it is back
    hop_.on_timer(now);
    frag_expire(now); // [S12]
    if (slot_wait_ && !link_.exchange().busy()) {
        slot_wait_ = false; // a link/join exchange ended: sends waiting for the slot go on
        kick_all_waiting(now);
        if (mesh_.slot_free != nullptr) {
            mesh_.slot_free(mesh_.ctx, now); // [S11]
        }
    }
    if (now >= retry_kick_) {
        retry_kick_ = MonoTime::never();
        for (std::size_t i = 0; i < k_in_entries; ++i) {
            const Handle ih = in_.handle_at(i);
            InEntry *e = in_.get(ih);
            const InLive *l = e != nullptr ? live_of(*e) : nullptr;
            if (l != nullptr && e->durable && !l->commit_wanted && l->persisted_version < l->version) {
                want_in_commit(ih, *e, now); // the worker queue was full: ask again
            }
        }
        for (uint16_t i = 0; i < k_actives; ++i) {
            if (out_retire_[i]) {
                request_retire(i, now);
            }
        }
        kick_all_waiting(now);
    }
    Handle due[k_actives];
    std::size_t n = 0;
    for (std::size_t i = 0; i < k_actives; ++i) {
        const Handle h = actives_.handle_at(i);
        const Active *a = actives_.get(h);
        if (a != nullptr && a->next_at <= now && n < k_actives) {
            due[n++] = h;
        }
    }
    for (std::size_t i = 0; i < n; ++i) {
        drive(due[i], now);
    }
    flush_events(now);
}

MonoTime Delivery::deadline() const {
    if (slot_wait_ && !link_.exchange().busy()) {
        return MonoTime{0}; // known pending work (the slot is free), not a poll
    }
    MonoTime next = earliest(earliest(hop_.deadline(), retry_kick_), earliest(frag_deadline(), durable_.deadline()));
    for (std::size_t i = 0; i < k_actives; ++i) {
        const Active *a = actives_.get(actives_.handle_at(i));
        if (a != nullptr) {
            next = earliest(next, a->next_at);
        }
    }
    return next;
}

// ---- events ----
bool Delivery::event_payload(const lm_event_t &ev, ByteView &out) const {
    if (ev.kind == LM_EVENT_MESSAGE) {
        DeviceId origin;
        std::array<uint8_t, 16> mid{};
        std::memcpy(origin.bytes.data(), ev.peer.bytes, 32);
        std::memcpy(mid.data(), ev.message_id.bytes, 16);
        for (std::size_t i = 0; i < k_in_entries; ++i) {
            const InEntry *e = in_.get(in_.handle_at(i));
            if (e != nullptr && e->st == InEntry::St::Held && e->origin == origin && e->mid == mid &&
                e->assignment == ev.origin_assignment_generation) {
                const InLive *l = live_of(*e);
                if (l == nullptr) {
                    return false;
                }
                if (l->obj) { // [S12] a received object stays in the object buffer until it is taken
                    out = ByteView{frag_.obj_buf.data(), l->len};
                    return true;
                }
                const MsgBuf *b = msgs_.get(l->msg);
                if (b == nullptr) {
                    return false;
                }
                out = ByteView{b->data.data(), l->len};
                return true;
            }
        }
        return false;
    }
    if (ev.kind == LM_EVENT_OPERATION && ev.payload_bytes > 0) {
        for (const Op &o : ops_) {
            if (o.used && o.id == ev.operation_id) {
                out = ByteView{o.result.data(), o.result_len};
                return true;
            }
        }
    }
    return false;
}

void Delivery::queue_message_event(Handle h, InEntry &e, MonoTime now) {
    InLive *lp = live_of(e); // a record that is announced holds its payload, so it has a live slot
    if (lp == nullptr) {
        return;
    }
    InLive &l = *lp;
    lm_event_t ev{};
    ev.struct_size = sizeof(ev);
    ev.abi_version = LM_ABI_VERSION;
    ev.kind = LM_EVENT_MESSAGE;
    ev.reason = l.recovered ? 1U : 0U; // 1: recovered after a restart, the application may have seen it
    ev.observed_mono_ms = now.to_ms();
    ev.peer = abi_dev(e.origin);
    ev.message_id = abi_mid(e.mid);
    ev.origin_assignment_generation = e.assignment;
    std::memcpy(ev.intent_hash, e.hash.data(), 32);
    ev.app_port = l.port;
    ev.payload_bytes = l.len;
    l.event_owed = !engine_.push_event(ev);
    (void)h;
}

void Delivery::on_event_taken(const lm_event_t &ev, MonoTime now) {
    if (ev.kind != LM_EVENT_MESSAGE) {
        return;
    }
    DeviceId origin;
    std::array<uint8_t, 16> mid{};
    std::memcpy(origin.bytes.data(), ev.peer.bytes, 32);
    std::memcpy(mid.data(), ev.message_id.bytes, 16);
    for (std::size_t i = 0; i < k_in_entries; ++i) {
        const Handle h = in_.handle_at(i);
        InEntry *e = in_.get(h);
        if (e == nullptr || e->st != InEntry::St::Held || e->origin != origin || e->mid != mid ||
            e->assignment != ev.origin_assignment_generation) {
            continue;
        }
        if (host_gate_) {
            return; // [S13-D11] the Host has not stored it yet: the payload (and a durable message's journal
                    // record) stay in the pool and are read from there at every (re)send until HOST_STORE_ACK
        }
        finish_take(h, *e, now);
        return;
    }
}

void Delivery::finish_take(Handle h, InEntry &e, MonoTime now) {
    InLive *lp = live_of(e);
    if (lp == nullptr) {
        return;
    }
    InLive &l = *lp;
    (void)msgs_.release(l.msg);
    l.msg = Handle{};
    frag_.obj_held = frag_.obj_held && !l.obj; // [S12] the object buffer is free again
    l.obj = false;
    e.st = InEntry::St::Delivered;
    l.len = 0;
    if (e.durable && e.delivery != LM_APPLIED) {
        // Marker: the application has it, the payload is no longer kept. An APPLIED message keeps
        // its journal record until the application reports a result, so a power cut in between
        // brings it back (flagged "recovered") for reconciliation instead of losing it.
        ++l.version;
        want_in_commit(h, e, now);
    }
    settle(e); // nothing left to do for a volatile message that needs no result
}

void Delivery::flush_events(MonoTime now) {
    for (;;) {
        InEntry *best = nullptr;
        uint32_t best_arrival = 0;
        Handle bh;
        for (std::size_t i = 0; i < k_in_entries; ++i) {
            const Handle h = in_.handle_at(i);
            InEntry *e = in_.get(h);
            const InLive *l = e != nullptr ? live_of(*e) : nullptr;
            if (l != nullptr && l->event_owed && e->st == InEntry::St::Held &&
                (best == nullptr || static_cast<int32_t>(l->arrival - best_arrival) < 0)) {
                best = e;
                best_arrival = l->arrival;
                bh = h;
            }
        }
        if (best == nullptr) {
            return;
        }
        queue_message_event(bh, *best, now);
        if (live_of(*best)->event_owed) {
            return; // still full
        }
    }
}

// ---- routes ----
Status Delivery::install_route(const DeviceId &dest, const PathSpec &route, MonoTime expires) {
    if (!identity_.is_member()) {
        return Status::AuthPending;
    }
    route::CachedRoute r;
    r.destination = route.dest;
    r.device = dest;
    r.root_term = route.term;
    r.revision = route.revision;
    r.len = route.len;
    r.path = route.path;
    return routes_.put(self_addr(), r, expires); // InvalidArgument / Conflict (older revision)
}

// The reverse of an authenticated route from `s`'s peer (rx_reply_) is a route to that peer:
// receipts and answers go back the way the traffic came when nothing newer is known.
void Delivery::learn_route(const EndSession &s) {
    route::CachedRoute r;
    r.destination = rx_reply_.dest;
    r.device = s.peer;
    r.root_term = rx_reply_.term;
    r.revision = rx_reply_.revision;
    r.len = rx_reply_.len;
    r.path = rx_reply_.path;
    (void)routes_.learn(self_addr(), r, s.valid_until); // a malformed path is simply not learned
}

bool Delivery::route_for(const DeviceId &dest, PathSpec &out, MonoTime now) {
    if (mesh_.route_of != nullptr) { // [S11] own root path / root topology first: they are the fresh ones
        const Status m = mesh_.route_of(mesh_.ctx, dest, out, now);
        if (m == Status::Ok) {
            return true;
        }
        if (m == Status::Busy) {
            return false; // known destination, no usable path while the mesh repairs: wait, don't guess
        }
    }
    route::CachedRoute r;
    if (routes_.lookup(dest, local_term(), now, r) != Status::Ok) {
        if (mesh_.want_route != nullptr) {
            mesh_.want_route(mesh_.ctx, dest, now); // [S11] ask the root (rate-limited there)
        }
        return false; // none, or a stale term / lease: the resolver must supply a new one
    }
    out.origin = self_addr();
    out.dest = r.destination;
    out.len = r.len;
    out.path = r.path;
    out.term = r.root_term;
    out.revision = r.revision;
    return true;
}

link::Neighbor *Delivery::neighbor_at(uint16_t addr) {
    link::Neighbor *found = nullptr;
    link_.neighbors().for_each([&](Handle, link::Neighbor &n) {
        if (found == nullptr && n.cur.active && n.address.value() == addr) {
            found = &n;
        }
    });
    return found;
}

// Frames a sealed end record for `ps` and queues it (docs/09 §3). The route header and path are
// written right before the record in a pool frame borrowed for the call (P9).
bool Delivery::build_and_send(const PathSpec &ps, ByteView record, OwnerKind kind, Handle owner, MonoTime now,
                              Status &why) {
    Lease scratch{engine_.frames()};
    if (!scratch.ok()) {
        why = Status::NoCapacity; // every pool frame is in use: local shortage, retried shortly
        return false;
    }
    const std::size_t room = route_room(ps.len);
    if (ps.len < 1 || ps.len > wire::k_max_path || room + record.size() > Lease::size()) {
        why = Status::PayloadTooLarge;
        return false;
    }
    std::memcpy(scratch.data() + room, record.data(), record.size());
    return build_and_send(ps, scratch, record.size(), kind, owner, now, why);
}

bool Delivery::build_and_send(const PathSpec &ps, Lease &scratch, std::size_t record_len, OwnerKind kind,
                              Handle owner, MonoTime now, Status &why) {
    const std::size_t hdr_len = route_room(ps.len);
    if (ps.len < 1 || ps.len > wire::k_max_path || hdr_len + record_len > Lease::size()) {
        why = Status::PayloadTooLarge;
        return false;
    }
    std::size_t rlen = 0;
    why = wire::encode_route(ps.header(), MutByteView{scratch.data(), hdr_len}, rlen);
    if (why != Status::Ok) {
        return false;
    }
    link::Neighbor *nb = neighbor_at(ps.first_hop());
    if (nb == nullptr) {
        why = Status::NoRoute; // no link session with the first hop
        return false;
    }
    const ByteView plain{scratch.data(), hdr_len + record_len};
    Handle fh;
    TxFrame *f = hop_.reserve(fh, record_class(plain.subspan(hdr_len, record_len)), nb->mac);
    if (f == nullptr) {
        // [S16] a full mailbox of a sleeping next hop waits for its wake (backoff), it does not poll the pool
        why = engine_.power().child_asleep(nb->mac, now) ? Status::PeerAsleep : Status::NoCapacity;
        return false; // TX pool full or the class limit: local shortage, never an RF loss
    }
    why = link_.seal(nb->device, wire::FrameKind::Data, plain, f->frame, now);
    if (why != Status::Ok) {
        hop_.release(fh);
        return false;
    }
    hop_.submit(fh, kind, owner, nb->mac, now);
    return true;
}

// ---- command entry point ----
Reply Delivery::execute(const Command &cmd, MonoTime now) {
    refresh_bound(now);
    switch (cmd.kind) {
    case CommandKind::Send:
        if (cmd.request == nullptr || cmd.request_size != sizeof(lm_send_request_t)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        return send(*static_cast<const lm_send_request_t *>(cmd.request), cmd.payload, now);
    case CommandKind::Cancel:
        if (cmd.request == nullptr || cmd.request_size != sizeof(lm_operation_id_t)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        return cancel(*static_cast<const lm_operation_id_t *>(cmd.request), now);
    case CommandKind::GetOperation:
        if (cmd.request == nullptr || cmd.response == nullptr || cmd.response_size != sizeof(lm_operation_t)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        return get_operation(*static_cast<const lm_operation_id_t *>(cmd.request),
                             *static_cast<lm_operation_t *>(cmd.response));
    case CommandKind::GetMessage:
        if (cmd.request == nullptr || cmd.response == nullptr || cmd.response_size != sizeof(lm_operation_t)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        return get_message(*static_cast<const lm_message_ref_t *>(cmd.request),
                           *static_cast<lm_operation_t *>(cmd.response));
    case CommandKind::ReportApplicationResult:
        if (cmd.request == nullptr || cmd.request_size != sizeof(ReportRequest)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        return report_result(*static_cast<const ReportRequest *>(cmd.request), cmd.payload, now);
    case CommandKind::RootHostSend: // [S13]
        if (cmd.request == nullptr || cmd.request_size != sizeof(HostSendRequest)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        return host_send(*static_cast<const HostSendRequest *>(cmd.request), cmd.payload, now);
    case CommandKind::RootHostStoreAck:
        if (cmd.request == nullptr || cmd.request_size != sizeof(HostStoreAckRequest)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        return Reply{host_store_ack(*static_cast<const HostStoreAckRequest *>(cmd.request), now), 0, 0};
    case CommandKind::SendObject: // [S12]
        if (cmd.request == nullptr || cmd.request_size != sizeof(lm_send_request_t)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        return send_mode(SendMode::Object, *static_cast<const lm_send_request_t *>(cmd.request), cmd.payload, now);
    case CommandKind::SendControl:
        if (cmd.request == nullptr || cmd.request_size != sizeof(ControlSendRequest)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        return send_control(*static_cast<const ControlSendRequest *>(cmd.request), cmd.payload, now);
    case CommandKind::PayloadCapacity:
        if (cmd.request == nullptr || cmd.request_size != sizeof(CapacityRequest)) {
            return Reply{Status::InvalidArgument, 0, 0};
        }
        return payload_capacity(*static_cast<CapacityRequest *>(const_cast<void *>(cmd.request)), now);
    default:
        return Reply{Status::Unsupported, 0, 0};
    }
}

} // namespace lm::delivery
