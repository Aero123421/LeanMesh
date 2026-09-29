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
    : engine_(engine), identity_(identity), link_(link), hop_(engine, link),
      exchange_(engine, identity, sessions_, end_policy_, bound_), durable_(engine) {
    HopTx::Hooks hh;
    hh.ctx = this;
    hh.may_send = &hop_may_send;
    hh.done = &hop_done;
    hop_.set_hooks(hh);
    EndTransport et;
    et.ctx = this;
    et.record_buf = MutByteView{tx_scratch_.data() + k_rec_off, k_record_bytes};
    et.send = &exchange_send;
    et.done = &exchange_done;
    exchange_.set_transport(et);
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
    return identity_.is_member() ? identity_.member().root_term : RootTerm{};
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
    lm_event_t ev{};
    ev.struct_size = sizeof(ev);
    ev.abi_version = LM_ABI_VERSION;
    ev.kind = LM_EVENT_OPERATION;
    ev.reason = op.reason;
    ev.observed_mono_ms = now.to_ms();
    ev.operation_id = op.id;
    ev.peer = abi_dev(op.dest);
    ev.message_id = abi_mid(to_bytes(op.mid));
    ev.origin_assignment_generation = identity_.is_member() ? identity_.member().assignment.value() : 0;
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
    (void)now;
    ready_ = false;
    recovering_ = false;
    return durable_.begin_boot();
}

void Delivery::stop() {
    exchange_.stop();
    hop_.clear();
    durable_.stop();
    for (std::size_t i = 0; i < k_actives; ++i) {
        (void)actives_.release(actives_.handle_at(i));
    }
    for (std::size_t i = 0; i < k_in_entries; ++i) {
        (void)in_.release(in_.handle_at(i));
    }
    for (std::size_t i = 0; i < k_build_limits.app_messages; ++i) {
        (void)msgs_.release(msgs_.handle_at(i));
    }
    ops_ = {};
    routes_ = {};
    accepted_ = {};
    out_j_ = {};
    out_retire_ = {};
    in_j_ = {};
    sessions_.clear();
    ready_ = false;
    recovering_ = false;
    retry_kick_ = MonoTime::never();
}

void Delivery::on_tx_outcome(const TxOutcome &o, MonoTime now) {
    refresh_bound(now);
    hop_.on_tx_outcome(o, now);
}

void Delivery::on_job_done(JobOwner owner, Handle slot, Status s, MonoTime now) {
    refresh_bound(now);
    if (owner == JobOwner::EndExchange) {
        exchange_.on_job_done(slot, s, now);
    } else if (owner == JobOwner::Durable) {
        durable_.on_job_done(slot, s, now);
    }
}

void Delivery::on_timer(MonoTime now) {
    refresh_bound(now);
    hop_.on_timer(now);
    exchange_.on_timer(now);
    if (now >= retry_kick_) {
        retry_kick_ = MonoTime::never();
        for (std::size_t i = 0; i < k_in_entries; ++i) {
            const Handle ih = in_.handle_at(i);
            InEntry *e = in_.get(ih);
            if (e != nullptr && e->durable && !e->commit_wanted && e->persisted_version < e->version) {
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
    MonoTime next = earliest(hop_.deadline(), exchange_.deadline());
    next = earliest(next, retry_kick_);
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
            if (e != nullptr && e->st == InEntry::St::Held && e->origin == origin && e->mid == mid) {
                const MsgBuf *b = msgs_.get(e->msg);
                if (b == nullptr) {
                    return false;
                }
                out = ByteView{b->data.data(), e->len};
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
    lm_event_t ev{};
    ev.struct_size = sizeof(ev);
    ev.abi_version = LM_ABI_VERSION;
    ev.kind = LM_EVENT_MESSAGE;
    ev.reason = e.recovered ? 1U : 0U; // 1: recovered after a restart, the application may have seen it
    ev.observed_mono_ms = now.to_ms();
    ev.peer = abi_dev(e.origin);
    ev.message_id = abi_mid(e.mid);
    ev.origin_assignment_generation = e.origin_assignment;
    std::memcpy(ev.intent_hash, e.hash.data(), 32);
    ev.app_port = e.port;
    ev.payload_bytes = e.len;
    e.event_owed = !engine_.push_event(ev);
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
        if (e == nullptr || e->st != InEntry::St::Held || e->origin != origin || e->mid != mid) {
            continue;
        }
        (void)msgs_.release(e->msg);
        e->msg = Handle{};
        e->st = InEntry::St::Delivered;
        e->len = 0;
        if (e->durable && e->delivery != LM_APPLIED) {
            // Marker: the application has it, the payload is no longer kept. An APPLIED message keeps
            // its journal record until the application reports a result, so a power cut in between
            // brings it back (flagged "recovered") for reconciliation instead of losing it.
            ++e->version;
            want_in_commit(h, *e, now);
        }
        return;
    }
}

void Delivery::flush_events(MonoTime now) {
    for (;;) {
        InEntry *best = nullptr;
        Handle bh;
        for (std::size_t i = 0; i < k_in_entries; ++i) {
            const Handle h = in_.handle_at(i);
            InEntry *e = in_.get(h);
            if (e != nullptr && e->event_owed && e->st == InEntry::St::Held &&
                (best == nullptr || static_cast<int32_t>(e->arrival - best->arrival) < 0)) {
                best = e;
                bh = h;
            }
        }
        if (best == nullptr) {
            return;
        }
        queue_message_event(bh, *best, now);
        if (best->event_owed) {
            return; // still full
        }
    }
}

// ---- routes ----
Status Delivery::install_route(const DeviceId &dest, const PathSpec &route, MonoTime expires) {
    if (!identity_.is_member()) {
        return Status::AuthPending;
    }
    PathSpec r = route;
    r.origin = self_addr();
    if (r.len < 1 || r.len > wire::k_max_path || r.dest.value() != r.path[r.len - 1U] ||
        wire::validate_simple_path(r.origin.value(), r.path.data(), r.len) != Status::Ok) {
        return Status::InvalidArgument;
    }
    RouteEntry *pick = nullptr;
    for (RouteEntry &e : routes_) {
        if (e.used && e.dest == dest) {
            if (e.route.term == r.term && r.revision < e.route.revision) {
                return Status::Conflict; // never replace a route by an older revision
            }
            pick = &e;
            break;
        }
    }
    for (RouteEntry &e : routes_) {
        if (pick == nullptr && !e.used) {
            pick = &e;
        }
    }
    if (pick == nullptr) {
        pick = &routes_[0];
        for (RouteEntry &e : routes_) {
            if (static_cast<int32_t>(e.last_use - pick->last_use) < 0) {
                pick = &e;
            }
        }
    }
    *pick = RouteEntry{true, dest, r, expires, ++route_tick_};
    return Status::Ok;
}

bool Delivery::route_for(const DeviceId &dest, PathSpec &out, MonoTime now) {
    for (RouteEntry &e : routes_) {
        if (!e.used || e.dest != dest) {
            continue;
        }
        if (e.route.term != local_term() || !(now < e.expires)) {
            e = RouteEntry{}; // stale term or lease: the resolver must supply a new one
            return false;
        }
        e.last_use = ++route_tick_;
        out = e.route;
        out.origin = self_addr();
        return true;
    }
    return false;
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

// Frames a sealed end record for `ps` and queues it (docs/09 §3). The route header is written
// right before the record in the shared TX buffer (no copy of the record when it was built there).
bool Delivery::build_and_send(const PathSpec &ps, ByteView record, OwnerKind kind, Handle owner,
                              MonoTime now, Status &why) {
    const std::size_t hdr_len = wire::k_route_header_bytes + 2U * ps.len;
    if (ps.len < 1 || ps.len > wire::k_max_path || record.size() > k_record_bytes) {
        why = Status::PayloadTooLarge;
        return false;
    }
    uint8_t *const rec_at = tx_scratch_.data() + k_rec_off;
    if (record.data() != rec_at) {
        std::memmove(rec_at, record.data(), record.size());
    }
    uint8_t *const start = rec_at - hdr_len;
    std::size_t rlen = 0;
    why = wire::encode_route(ps.header(), MutByteView{start, hdr_len}, rlen);
    if (why != Status::Ok) {
        return false;
    }
    link::Neighbor *nb = neighbor_at(ps.first_hop());
    if (nb == nullptr) {
        why = Status::NoRoute; // no link session with the first hop
        return false;
    }
    Handle fh;
    TxFrame *f = hop_.reserve(fh);
    if (f == nullptr) {
        why = Status::NoCapacity; // TX pool full: local shortage, never an RF loss
        return false;
    }
    why = link_.seal(nb->device, wire::FrameKind::Data, ByteView{start, hdr_len + record.size()}, f->frame, now);
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
