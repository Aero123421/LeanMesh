// Delivery, origin side: acceptance (lm_send), the send state machine (route -> end session ->
// sealed end record -> routed frame), E2E rounds, cancel, receipts, operation queries.
#include <cstring>

#include "core/delivery/delivery.hpp"
#include "core/engine.hpp"

namespace lm::delivery {
namespace {

constexpr Duration k_result_poll = Duration::from_s(10); // after END_RECEIVED: ask again for the result
constexpr Duration k_retry_base = Duration::from_ms(500);
constexpr Duration k_retry_max = Duration::from_s(30);
constexpr Duration k_shortage_retry = Duration::from_ms(50); // TX pool full: local, retried shortly
constexpr Duration k_no_deadline_pause = Duration::from_s(60);
constexpr uint8_t k_max_refusals = 3;

Reply reply(Status s, uint64_t op = 0) { return Reply{s, op, 0}; }

} // namespace

Duration Delivery::retry_delay(const Active &a) const {
    Duration d = k_retry_base;
    for (uint8_t i = 0; i < a.backoff && d < k_retry_max; ++i) {
        d = Duration{d.us * 2};
    }
    return d < k_retry_max ? d : k_retry_max;
}

bool Delivery::left_node(Handle h, const Op &op) const {
    return (op.evidence & ev::sent) != 0 || hop_.has_left(OwnerKind::Out, h);
}

// ---- acceptance ----
Reply Delivery::send(const lm_send_request_t &rq, ByteView payload, MonoTime now) {
    if (!identity_.is_member()) {
        return reply(Status::AuthPending);
    }
    if (!ready_) {
        return reply(durable_.failed() ? Status::RecoveryRequired : Status::Busy);
    }
    if (rq.reserved != 0 || rq.reserved2 != 0 || rq.delivery > LM_APPLIED || rq.storage > LM_DURABLE ||
        rq.priority >= LM_PRIORITY_CONTROL || rq.strict_single_frame > 1 || rq.app_port == 0 ||
        rq.app_port > 65534) {
        return reply(Status::InvalidArgument); // CONTROL is not selectable through the public API
    }
    if (rq.queue_mode != LM_FIFO) {
        return reply(Status::Unsupported); // LATEST coalescing belongs to the scheduler slice
    }
    DeviceId dest;
    switch (rq.destination.kind) {
    case LM_DEST_NODE:
        if (rq.destination.group_id != 0 || rq.destination.group_revision != 0) {
            return reply(Status::InvalidArgument);
        }
        std::memcpy(dest.bytes.data(), rq.destination.node.bytes, 32);
        break;
    case LM_DEST_ROOT_APP:
        dest = identity_.delegation().root;
        break;
    case LM_DEST_GROUP:
        return reply(Status::Unsupported);
    default:
        return reply(Status::InvalidArgument);
    }
    if (dest == identity_.self() || dest.is_zero()) {
        return reply(Status::InvalidArgument);
    }
    if (payload.size() > k_msg_bytes) {
        return reply(Status::PayloadTooLarge);
    }
    // One frame only until the fragment slice exists (S9-D3): the payload must fit the longest
    // single-frame path any node may have, or the known route of this destination.
    std::size_t cap = wire::data_capacity(1);
    PathSpec known;
    if (route_for(dest, known, now)) {
        cap = wire::data_capacity(known.len);
    }
    if (payload.size() > cap) {
        return reply(Status::PayloadTooLarge);
    }
    const bool finite = rq.expires_root_ms != 0;
    if (!finite) {
        if (rq.delivery != LM_RECEIVED || rq.storage != LM_DURABLE) {
            return reply(Status::InvalidArgument); // a command without a deadline is not allowed
        }
    } else {
        if (rq.root_term == 0) {
            return reply(Status::InvalidArgument);
        }
        switch (deadline_state(rq.expires_root_ms, rq.root_term)) {
        case DeadlineCheck::After:
            return reply(Status::Expired);
        case DeadlineCheck::Uncertain:
            return reply(Status::TimeUncertain); // the receiver could not prove it either
        case DeadlineCheck::Before:
            break;
        }
    }
    std::size_t durable_load = 0;
    for (std::size_t i = 0; i < k_actives; ++i) {
        const Active *x = actives_.get(actives_.handle_at(i));
        durable_load += (x != nullptr && x->durable) ? 1U : 0U;
    }
    if (rq.storage == LM_DURABLE && durable_load >= k_build_limits.durable_pending) {
        return reply(Status::NoCapacity);
    }

    Op *op = alloc_op();
    if (op == nullptr) {
        return reply(Status::NoCapacity);
    }
    const Handle mb = msgs_.acquire();
    if (mb.is_none()) {
        return reply(Status::NoCapacity);
    }
    const Handle ah = actives_.acquire();
    if (ah.is_none()) {
        (void)msgs_.release(mb);
        return reply(Status::NoCapacity);
    }
    IntentFields f;
    f.origin = identity_.self();
    f.target = dest;
    f.domain = identity_.delegation().domain;
    f.app_port = rq.app_port;
    f.delivery = static_cast<uint8_t>(rq.delivery);
    f.storage = static_cast<uint8_t>(rq.storage);
    f.priority = static_cast<uint8_t>(rq.priority);
    f.root_term = rq.root_term;
    f.expires_root_ms = rq.expires_root_ms;
    f.payload = payload;
    Sha256Digest hash{};
    const Status hs = intent_hash(f, hash);
    if (hs != Status::Ok) {
        (void)msgs_.release(mb);
        (void)actives_.release(ah);
        return reply(hs);
    }
    Active *a = actives_.get(ah);
    a->durable = rq.storage == LM_DURABLE;
    if (a->durable && !alloc_jslot(out_j_, a->jslot)) {
        (void)msgs_.release(mb);
        (void)actives_.release(ah);
        return reply(Status::NoCapacity);
    }
    MsgBuf *buf = msgs_.get(mb);
    if (!payload.empty()) {
        std::memcpy(buf->data.data(), payload.data(), payload.size());
    }
    *op = Op{};
    op->used = true;
    op->id = next_op_id_++;
    op->seq = ++op_tick_;
    op->mid = MessageId{durable_.incarnation(), next_seq_++};
    op->dest = dest;
    op->port = rq.app_port;
    op->delivery = static_cast<uint8_t>(rq.delivery);
    op->storage = static_cast<uint8_t>(rq.storage);
    op->priority = static_cast<uint8_t>(rq.priority);
    op->term = finite ? rq.root_term : 0;
    op->expires = rq.expires_root_ms;
    op->hash = hash;
    op->evidence = ev::accepted;
    op->accepted_ms = now.to_ms();
    op->last_evidence_ms = op->accepted_ms;
    op->active = ah;
    a->op = op_index(*op);
    a->msg = mb;
    a->len = static_cast<uint16_t>(payload.size());
    ++stats_.accepted;
    if (a->durable) {
        a->st = Active::St::Persisting;
        want_out_commit(ah, *a, now);
    }
    const uint64_t id = op->id;
    drive(ah, now);
    return reply(Status::Ok, id);
}

// ---- the send state machine ----
void Delivery::finalize_active(Handle h, uint8_t outcome, uint32_t reason, MonoTime now) {
    Active *a = actives_.get(h);
    if (a == nullptr) {
        return;
    }
    Op &op = ops_[a->op];
    if (hop_.has_left(OwnerKind::Out, h)) {
        note_evidence(op, ev::sent, now); // a fact the hop layer knows, even if its completion is pending
    }
    finalize(op, outcome, reason, now);
    retire_active(h, true, now);
}

void Delivery::retire_active(Handle h, bool persist_retire, MonoTime now) {
    Active *a = actives_.get(h);
    if (a == nullptr) {
        return;
    }
    (void)hop_.withdraw(OwnerKind::Out, h); // frames that already left stop being retransmitted
    (void)msgs_.release(a->msg);
    ops_[a->op].active = Handle{};
    const bool durable = a->durable;
    const uint16_t jslot = a->jslot;
    (void)actives_.release(h);
    if (durable) {
        // The journal slot stays reserved until the retire is durable: a new message never shares an
        // id with a record that may still be live, and a retire that could not be queued is repeated
        // (a cancelled or finished message must not come back after a restart).
        if (persist_retire) {
            out_retire_[jslot] = true;
            request_retire(jslot, now);
        } else {
            out_j_[jslot] = false;
        }
    }
}

void Delivery::drive(Handle h, MonoTime now) {
    Active *a = actives_.get(h);
    if (a == nullptr) {
        return;
    }
    Op &op = ops_[a->op];
    a->next_at = MonoTime::never();
    const MonoTime dl = local_deadline(op.expires, op.term, now);

    // 1. Deadline first: before the first send and before every retry (never extended).
    if (op.expires != 0) {
        const DeadlineCheck dc = deadline_state(op.expires, op.term);
        if (dc != DeadlineCheck::Before) {
            const bool left = left_node(h, op);
            if (dc == DeadlineCheck::After) {
                ++stats_.expired;
                finalize_active(h, left ? LM_OUTCOME_INDETERMINATE : LM_OUTCOME_EXPIRED,
                                static_cast<uint32_t>(Status::Expired), now);
            } else if (bound_.valid && bound_.term.value() != op.term) {
                // The root restarted: the time base of this deadline is gone. Nothing is re-issued
                // under a new term (docs/08 §5); a sent message is unknown, an unsent one is void.
                ++stats_.expired;
                finalize_active(h, left ? LM_OUTCOME_INDETERMINATE : LM_OUTCOME_EXPIRED,
                                static_cast<uint32_t>(Status::TimeUncertain), now);
            } else {
                op.reason = static_cast<uint32_t>(Status::TimeUncertain); // wait for a clock bound
                if (bound_.valid) {
                    // The estimate straddles the deadline: look again when its earliest edge gets there.
                    const uint64_t wait_ms = op.expires > bound_.earliest_ms ? op.expires - bound_.earliest_ms + 1 : 1;
                    a->next_at = now + Duration::from_ms(static_cast<int64_t>(wait_ms < 1000 ? wait_ms : 1000));
                }
            }
            return;
        }
    }
    if (a->cancelled) { // cancel after the frame left: no more sends, only the receipts we may still get
        if (now >= a->round_at) {
            finalize_active(h, LM_OUTCOME_INDETERMINATE, static_cast<uint32_t>(Status::CancelTooLate), now);
        } else {
            a->next_at = a->round_at;
        }
        return;
    }
    // Round timer.
    if (a->st == Active::St::WaitReceipt) {
        if (now < a->round_at) {
            a->next_at = earliest(a->round_at, dl);
            return;
        }
        round_ended(h, *a, op, now, false);
        a = actives_.get(h);
        if (a == nullptr || !a->next_at.is_never()) {
            return; // finished, or paced (the next attempt is at next_at)
        }
    }
    if (a->st == Active::St::Sending) {
        a->next_at = dl; // a frame is queued or on air: the hop layer reports back
        return;
    }

    // 2. Persistence: a DURABLE message goes out only after its journal commit.
    if (a->durable && a->persisted_version < a->version) {
        a->st = Active::St::Persisting;
        if (!a->commit_wanted) {
            want_out_commit(h, *a, now);
        }
        a->next_at = a->commit_wanted ? dl : earliest(now + k_shortage_retry, dl);
        return;
    }
    // 3. Route.
    PathSpec ps;
    if (!route_for(op.dest, ps, now)) {
        a->st = Active::St::WaitRoute;
        op.reason = static_cast<uint32_t>(Status::NoRoute);
        ++stats_.send_wait_route;
        a->next_at = earliest(now + retry_delay(*a), dl);
        if (a->backoff < 8) {
            ++a->backoff;
        }
        return;
    }
    if (a->len > wire::data_capacity(ps.len)) {
        finalize_active(h, LM_OUTCOME_REJECTED, static_cast<uint32_t>(Status::PayloadTooLarge), now);
        return;
    }
    // 4. End session.
    EndSession *s = sessions_.find_peer(op.dest);
    if (s == nullptr || s->suspect || !s->rec.active() || !(now < s->valid_until)) {
        a->st = Active::St::WaitSession;
        request_exchange(*a, op, ps, now);
        return;
    }
    // 5. End record: sealed once per (session, root term); a retry sends the same ciphertext.
    if (a->record_len == 0 || a->record_term != ps.term.value() || a->record_epoch != s->epoch) {
        wire::EndHeader eh;
        eh.message_id = to_bytes(op.mid);
        eh.app_port = op.port;
        eh.record_kind = wire::RecordKind::Data;
        eh.flags = wire::make_end_flags(static_cast<wire::Delivery>(op.delivery),
                                        static_cast<wire::Priority>(op.priority), op.storage == LM_DURABLE);
        eh.expires_root_ms = op.expires;
        const MsgBuf *buf = msgs_.get(a->msg);
        std::size_t len = 0;
        const Status st = seal_end_record(*s, s->tx_sid, ps.term, eh, ByteView{buf->data.data(), a->len},
                                          MutByteView{a->record}, len);
        if (st != Status::Ok) {
            // Refresh needed (2^24 records) or a local fault: get a new session, do not guess.
            s->suspect = true;
            a->st = Active::St::WaitSession;
            request_exchange(*a, op, ps, now);
            return;
        }
        a->record_len = static_cast<uint16_t>(len);
        a->record_term = ps.term.value();
        a->record_epoch = s->epoch;
    }
    sessions_.touch(*s);
    // 6. Frame. The state is set first: the hop layer may report back from inside submit().
    Status why = Status::Ok;
    const bool opens_round = a->new_round;
    a->hops = ps.len;
    a->st = Active::St::Sending;
    a->next_at = dl;
    op.phase = Phase::Sending;
    if (opens_round) {
        a->new_round = false;
        ++a->round;
        ++stats_.rounds;
    }
    if (!build_and_send(ps, ByteView{a->record.data(), a->record_len}, OwnerKind::Out, h, now, why)) {
        a = actives_.get(h);
        if (a == nullptr) {
            return;
        }
        if (opens_round) {
            a->new_round = true;
            --a->round;
            --stats_.rounds;
        }
        op.phase = Phase::Pending;
        if (why == Status::PayloadTooLarge) {
            finalize_active(h, LM_OUTCOME_REJECTED, static_cast<uint32_t>(why), now);
        } else if (why == Status::NoCapacity) {
            a->st = Active::St::WaitRoute; // local shortage (TX pool): retried shortly, not a failure
            a->next_at = earliest(now + k_shortage_retry, dl);
        } else {
            a->st = Active::St::WaitRoute; // no link session with the first hop yet
            op.reason = static_cast<uint32_t>(why);
            a->next_at = earliest(now + retry_delay(*a), dl);
            if (a->backoff < 8) {
                ++a->backoff;
            }
        }
    }
}

// The last round got no (complete) answer. After this returns the active either waits at next_at
// (paced), is finished, or has st == WaitRoute and drive() builds the next frame.
void Delivery::round_ended(Handle h, Active &a, Op &op, MonoTime now, bool link_failed) {
    a.new_round = true;
    a.st = Active::St::WaitRoute;
    if ((op.evidence & ev::end_received) != 0 && op.delivery == LM_APPLIED) {
        // Stored at the destination; only the application's result is missing. Ask again slowly:
        // a duplicate makes the destination repeat its newest receipt (which may have been lost).
        a.new_round = false;
        if (link_failed) {
            a.next_at = now + k_result_poll;
        }
        return;
    }
    if (a.round < k_e2e_rounds) {
        if (link_failed) {
            a.next_at = now + Duration::from_ms(200);
        }
        return;
    }
    if (op.expires == 0) { // durable history data without a deadline: never given up, only paced
        a.round = 0;
        a.next_at = now + k_no_deadline_pause;
        op.reason = static_cast<uint32_t>(Status::NoRoute);
        return;
    }
    // No receipt in any round: unreachable, or the peer lost its session. The message may still
    // have arrived: INDETERMINATE (never "not delivered"). The next message renews the session.
    if (EndSession *s = sessions_.find_peer(op.dest)) {
        s->suspect = true;
    }
    finalize_active(h, LM_OUTCOME_INDETERMINATE, static_cast<uint32_t>(Status::NoRoute), now);
}

void Delivery::kick_dest(const DeviceId &dest, MonoTime now) {
    Handle hs[k_actives];
    std::size_t n = 0;
    for (std::size_t i = 0; i < k_actives; ++i) {
        const Handle h = actives_.handle_at(i);
        const Active *a = actives_.get(h);
        if (a != nullptr && (a->st == Active::St::WaitRoute || a->st == Active::St::WaitSession) &&
            ops_[a->op].dest == dest) {
            hs[n++] = h;
        }
    }
    for (std::size_t i = 0; i < n; ++i) {
        Active *a = actives_.get(hs[i]);
        if (a != nullptr) {
            a->backoff = 0;
            drive(hs[i], now);
        }
    }
}

void Delivery::kick_all_waiting(MonoTime now) {
    Handle hs[k_actives];
    std::size_t n = 0;
    for (std::size_t i = 0; i < k_actives; ++i) {
        const Handle h = actives_.handle_at(i);
        const Active *a = actives_.get(h);
        if (a != nullptr && (a->st == Active::St::WaitRoute || a->st == Active::St::WaitSession)) {
            hs[n++] = h;
        }
    }
    for (std::size_t i = 0; i < n; ++i) {
        drive(hs[i], now);
    }
}

// ---- end sessions ----
void Delivery::request_exchange(Active &a, Op &op, const PathSpec &ps, MonoTime now) {
    const MonoTime dl = local_deadline(op.expires, op.term, now);
    if (exchange_.busy()) {
        a.next_at = dl; // woken by the exchange completion
        return;
    }
    const Status st = exchange_.start_initiator(op.dest, ps, now);
    if (st == Status::Ok) {
        a.next_at = dl;
        return;
    }
    op.reason = static_cast<uint32_t>(st);
    a.next_at = earliest(now + retry_delay(a), dl);
    if (a.backoff < 8) {
        ++a.backoff;
    }
}

Status Delivery::exchange_send(void *ctx, const PathSpec &route, ByteView record, Handle owner, MonoTime now) {
    auto *d = static_cast<Delivery *>(ctx);
    Status why = Status::Ok;
    return d->build_and_send(route, record, OwnerKind::Exchange, owner, now, why) ? Status::Ok : why;
}

void Delivery::exchange_done(void *ctx, const DeviceId &peer, Status st, MonoTime now) {
    static_cast<Delivery *>(ctx)->on_exchange_done(peer, st, now);
}

void Delivery::on_exchange_done(const DeviceId &peer, Status st, MonoTime now) {
    if (st == Status::Ok) {
        kick_dest(peer, now);
        kick_all_waiting(now);
        return;
    }
    for (std::size_t i = 0; i < k_actives; ++i) {
        Active *a = actives_.get(actives_.handle_at(i));
        if (a != nullptr && a->st == Active::St::WaitSession && ops_[a->op].dest == peer) {
            Op &op = ops_[a->op];
            op.reason = static_cast<uint32_t>(st);
            if (a->backoff < 8) {
                ++a->backoff;
            }
            a->next_at = earliest(now + retry_delay(*a), local_deadline(op.expires, op.term, now));
        }
    }
    kick_all_waiting(now); // other peers' messages may proceed now that the slot is free
}

// ---- hop layer glue ----
Status Delivery::hop_may_send(void *ctx, const TxFrame &f, MonoTime now) {
    return static_cast<Delivery *>(ctx)->may_send(f, now);
}

void Delivery::hop_done(void *ctx, const FrameDone &f, HopEnd end, MonoTime now) {
    static_cast<Delivery *>(ctx)->on_frame_done(f, end, now);
}

// Asked before the first send and before every retransmission of a frame.
Status Delivery::may_send(const TxFrame &f, MonoTime now) {
    refresh_bound(now);
    switch (f.kind) {
    case OwnerKind::Out: {
        const Active *a = actives_.get(f.owner);
        if (a == nullptr || a->cancelled) {
            return Status::Conflict;
        }
        const Op &op = ops_[a->op];
        if (op.expires != 0 && deadline_state(op.expires, op.term) != DeadlineCheck::Before) {
            return Status::Expired; // never re-sent past the original deadline
        }
        return Status::Ok;
    }
    case OwnerKind::Exchange:
        return exchange_.alive(f.owner) ? Status::Ok : Status::Conflict;
    default:
        return Status::Ok;
    }
}

void Delivery::on_frame_done(const FrameDone &f, HopEnd end, MonoTime now) {
    refresh_bound(now);
    if (f.kind == OwnerKind::Exchange) {
        exchange_.on_frame_done(f.owner, end, now);
        return;
    }
    if (f.kind != OwnerKind::Out) {
        return; // receipts and forwarded frames: nobody waits for them
    }
    Active *a = actives_.get(f.owner);
    if (a == nullptr) {
        return; // finished meanwhile: an abandoned frame ended
    }
    Op &op = ops_[a->op];
    if (f.left) {
        note_evidence(op, ev::sent, now);
    }
    if (a->st != Active::St::Sending) {
        return;
    }
    switch (end) {
    case HopEnd::Accepted:
        note_evidence(op, ev::hop_accepted, now);
        a->backoff = 0;
        a->refusals = 0;
        if (op.delivery == LM_BEST_EFFORT) {
            finalize_active(f.owner, LM_OUTCOME_SUBMITTED, 0, now); // sent evidence only
            return;
        }
        a->st = Active::St::WaitReceipt;
        op.phase = Phase::WaitingReceipt;
        a->round_at = ((op.evidence & ev::end_received) != 0 && op.delivery == LM_APPLIED)
                          ? now + k_result_poll
                          : now + round_timeout(a->hops);
        a->next_at = earliest(a->round_at, local_deadline(op.expires, op.term, now));
        return;
    case HopEnd::Failed:
        // Three link attempts without HOP_ACK: RF loss samples. The frame may still have arrived.
        if (op.delivery == LM_BEST_EFFORT) {
            finalize_active(f.owner, LM_OUTCOME_INDETERMINATE, static_cast<uint32_t>(Status::NoRoute), now);
            return;
        }
        round_ended(f.owner, *a, op, now, true);
        return;
    case HopEnd::Rejected:
        // The next hop refused (no route/session/capacity there): not RF loss. When the next hop
        // is the destination itself the usual cause is a peer that lost its end session (restart):
        // renew the session. Otherwise the route is suspect: ask for a new one. Give up after a few.
        if (a->hops == 1) {
            if (EndSession *s = sessions_.find_peer(op.dest)) {
                s->suspect = true;
            }
        } else {
            for (RouteEntry &r : routes_) {
                if (r.used && r.dest == op.dest) {
                    r = RouteEntry{};
                }
            }
        }
        if (++a->refusals > k_max_refusals) {
            finalize_active(f.owner, LM_OUTCOME_REJECTED, static_cast<uint32_t>(Status::NoRoute), now);
            return;
        }
        a->st = Active::St::WaitRoute;
        op.reason = static_cast<uint32_t>(Status::NoRoute);
        a->next_at = earliest(now + retry_delay(*a), local_deadline(op.expires, op.term, now));
        if (a->backoff < 8) {
            ++a->backoff;
        }
        return;
    case HopEnd::Aborted:
        a->st = Active::St::WaitRoute; // deadline/cancel: drive() decides what the operation is now
        drive(f.owner, now);
        return;
    }
}

// ---- receipts (origin) ----
void Delivery::on_receipt(const EndSession &s, const OpenedEnd &o, MonoTime now) {
    Receipt r;
    if (decode_receipt(o.view(), r) != Status::Ok || o.header.message_id != r.message_id) {
        return;
    }
    Op *op = find_op_by_message(s.peer, r.message_id);
    if (op == nullptr || op->hash != r.intent_hash) {
        ++stats_.receipts_unknown; // history evicted, or a receipt for a message we never sent
        return;
    }
    ++stats_.receipts_rx;
    // A later stage carries the earlier ones: the destination attests that it stored the message
    // before its application acknowledged, applied or refused it (S9-D5).
    uint32_t bits = 0;
    uint8_t candidate = 0xFF; // 0xFF: no outcome change (application pending)
    uint32_t reason = 0;
    switch (r.evidence) {
    case ReceiptEv::EndReceived:
        bits = ev::end_received;
        candidate = LM_OUTCOME_RECEIVED;
        break;
    case ReceiptEv::AppPending:
        bits = ev::end_received | ev::app_pending;
        break;
    case ReceiptEv::AppApplied:
        bits = ev::end_received | ev::app_applied;
        candidate = LM_OUTCOME_APPLIED;
        break;
    case ReceiptEv::AppRejected:
        bits = ev::end_received | ev::app_rejected;
        candidate = LM_OUTCOME_REJECTED;
        reason = r.reason;
        break;
    case ReceiptEv::Refused:
        bits = ev::refused;
        candidate = LM_OUTCOME_REJECTED;
        reason = r.reason;
        break;
    case ReceiptEv::Expired:
        bits = ev::refused;
        candidate = LM_OUTCOME_EXPIRED;
        reason = static_cast<uint32_t>(Status::Expired);
        break;
    case ReceiptEv::Indeterminate:
        candidate = LM_OUTCOME_INDETERMINATE;
        break;
    }
    note_evidence(*op, bits, now);
    if (r.result_len > 0 && (r.evidence == ReceiptEv::AppApplied || r.evidence == ReceiptEv::AppRejected)) {
        op->result_len = r.result_len;
        op->result = r.result;
    }
    const Handle ah = op->active;
    if (!ah.is_none() && actives_.get(ah) != nullptr) {
        Active &a = *actives_.get(ah);
        if (candidate == 0xFF) {
            return; // application pending: the newest evidence is recorded, the wait continues
        }
        if (candidate == LM_OUTCOME_RECEIVED && op->delivery == LM_APPLIED) {
            op->phase = Phase::WaitingReceipt; // stored; now only the application's result is awaited
            a.st = Active::St::WaitReceipt;
            a.round_at = now + k_result_poll;
            a.next_at = earliest(a.round_at, local_deadline(op->expires, op->term, now));
            (void)hop_.withdraw(OwnerKind::Out, ah); // no more DATA rounds for this message
            return;
        }
        finalize_active(ah, candidate, reason, now);
        return;
    }
    // Late receipt for an operation that is already final (D03): history and evidence are kept,
    // and unknown outcomes are resolved, but definite ones are never rolled back or replaced.
    ++stats_.receipts_late;
    if (candidate == 0xFF) {
        return;
    }
    const bool unknown = op->outcome == LM_OUTCOME_INDETERMINATE || op->outcome == LM_OUTCOME_EXPIRED;
    const bool refine = op->outcome == LM_OUTCOME_RECEIVED && op->delivery == LM_APPLIED &&
                        (candidate == LM_OUTCOME_APPLIED || candidate == LM_OUTCOME_REJECTED);
    if (unknown || refine) {
        op->outcome = candidate;
        op->reason = reason;
        op->phase = Phase::Final;
        emit_op_event(*op, now);
    }
}

// ---- cancel / queries ----
Reply Delivery::cancel(uint64_t op_id, MonoTime now) {
    Op *op = find_op(op_id);
    if (op == nullptr) {
        return reply(Status::NotFound);
    }
    if (op->phase == Phase::Final || op->active.is_none()) {
        return reply(Status::CancelTooLate);
    }
    const Handle h = op->active;
    Active *a = actives_.get(h);
    if (a == nullptr) {
        return reply(Status::CancelTooLate);
    }
    if (!left_node(h, *op)) {
        // Nothing left this node (waiting for a route/session/persistence, or queued): a cancel is
        // exact. A durable commit that already happened is retired by finalize_active().
        finalize_active(h, LM_OUTCOME_CANCELLED_NOT_SENT, 0, now);
        return reply(Status::Ok, op_id);
    }
    // The frame may have arrived. No more retransmissions and no new rounds, but late evidence is
    // still collected until the round timer; a cancel is not an undo at the far end.
    a->cancelled = true;
    (void)hop_.withdraw(OwnerKind::Out, h);
    a->st = Active::St::WaitReceipt;
    a->round_at = now + round_timeout(a->hops == 0 ? 1U : a->hops);
    a->next_at = a->round_at;
    op->phase = Phase::WaitingReceipt;
    return reply(Status::CancelTooLate, op_id);
}

Reply Delivery::get_operation(uint64_t op_id, lm_operation_t &out) {
    const Op *op = find_op(op_id);
    if (op == nullptr) {
        return reply(Status::NotFound);
    }
    fill_operation(*op, out);
    return reply(Status::Ok, op_id);
}

Reply Delivery::get_message(const lm_message_ref_t &ref, lm_operation_t &out) {
    DeviceId origin;
    std::memcpy(origin.bytes.data(), ref.origin.bytes, 32);
    std::array<uint8_t, 16> mid{};
    std::memcpy(mid.data(), ref.id.bytes, 16);
    Sha256Digest hash{};
    std::memcpy(hash.data(), ref.intent_hash, 32);
    if (origin == identity_.self()) {
        if (identity_.is_member() && ref.assignment_generation != identity_.member().assignment.value()) {
            return reply(Status::NotFound);
        }
        for (const Op &o : ops_) {
            if (o.used && !o.report && to_bytes(o.mid) == mid && o.hash == hash) {
                fill_operation(o, out);
                return reply(Status::Ok, o.id);
            }
        }
        return reply(Status::NotFound);
    }
    // A message received here: the destination's own record (outcome = what this node knows).
    const InEntry *e = find_in(origin, mid);
    if (e == nullptr || e->hash != hash) {
        return reply(Status::NotFound);
    }
    out = lm_operation_t{};
    out.struct_size = sizeof(out);
    out.abi_version = LM_ABI_VERSION;
    out.message_id = ref.id;
    out.phase = static_cast<uint32_t>(Phase::Final);
    out.evidence_bits = ev::end_received;
    switch (e->st) {
    case InEntry::St::Applied:
        out.outcome = LM_OUTCOME_APPLIED;
        out.evidence_bits |= ev::app_applied;
        break;
    case InEntry::St::AppRejected:
        out.outcome = LM_OUTCOME_REJECTED;
        out.evidence_bits |= ev::app_rejected;
        break;
    case InEntry::St::Committing:
        out.outcome = LM_OUTCOME_PENDING;
        out.evidence_bits = 0;
        out.phase = static_cast<uint32_t>(Phase::Pending);
        break;
    default:
        out.outcome = LM_OUTCOME_RECEIVED;
        break;
    }
    std::memcpy(out.intent_hash, e->hash.data(), 32);
    return reply(Status::Ok);
}

Reply Delivery::payload_capacity(CapacityRequest &rq, MonoTime now) {
    DeviceId dest;
    switch (rq.dest.kind) {
    case LM_DEST_NODE:
        std::memcpy(dest.bytes.data(), rq.dest.node.bytes, 32);
        break;
    case LM_DEST_ROOT_APP:
        dest = identity_.delegation().root;
        break;
    case LM_DEST_GROUP:
        return reply(Status::Unsupported);
    default:
        return reply(Status::InvalidArgument);
    }
    PathSpec ps;
    if (!identity_.is_member() || !route_for(dest, ps, now)) {
        return reply(Status::NoRoute);
    }
    rq.single_frame_bytes = static_cast<uint32_t>(wire::data_capacity(ps.len));
    rq.path_hops = ps.len;
    return reply(Status::Ok);
}

} // namespace lm::delivery
