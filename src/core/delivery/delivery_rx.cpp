// Delivery, RX side: HOP_ACK, relaying (docs/04 §4), the destination's end-record handling with
// the dedup/receipt cache, receipts, and the application's result report.
#include <cstring>

#include "core/codec.hpp"
#include "core/delivery/delivery.hpp"
#include "core/engine.hpp"

namespace lm::delivery {
namespace {

constexpr uint16_t k_busy_retry_ms = 200;

Reply reply(Status s, uint64_t op = 0) { return Reply{s, op, 0}; }

} // namespace

// ---- link duplicates ----
bool Delivery::seen_accepted(const MacAddr &mac, uint64_t counter) const {
    for (const Accepted &a : accepted_) {
        if (a.used && a.counter == counter && a.mac == mac) {
            return true;
        }
    }
    return false;
}

void Delivery::note_accepted(const MacAddr &mac, uint64_t counter) {
    Accepted *slot = &accepted_[0];
    for (Accepted &a : accepted_) {
        if (!a.used) {
            slot = &a;
            break;
        }
        if (static_cast<int32_t>(a.order - slot->order) < 0) {
            slot = &a;
        }
    }
    *slot = Accepted{true, mac, counter, ++accepted_tick_};
}

// ---- entry from the link layer ----
void Delivery::on_link_rx(const link::RxInfo &info, ByteView plain, MonoTime now) {
    refresh_bound(now);
    switch (info.kind) {
    case wire::FrameKind::HopAck: {
        wire::HopAck ack;
        if (wire::decode_hop_ack(plain, ack) == Status::Ok) {
            (void)hop_.on_ack(info.src, ack, now);
        }
        break;
    }
    case wire::FrameKind::Data:
        on_data(info, plain, now);
        break;
    default:
        ++stats_.rx_unsupported; // ROUTE / CONTROL / POWER belong to later slices
        break;
    }
}

void Delivery::on_data(const link::RxInfo &info, ByteView plain, MonoTime now) {
    if (!identity_.is_member()) {
        return;
    }
    using A = wire::HopAckStatus;
    wire::RouteHeader h;
    ByteView record;
    if (wire::decode_route(plain, h, record) != Status::Ok) {
        hop_.queue_ack(info.src, info.peer, info.counter, A::Rejected, 0, now);
        return;
    }
    if (info.duplicate && seen_accepted(info.src, info.counter)) {
        // The sender did not see our HOP_ACK: answer again, do not process the frame again.
        ++stats_.rx_dup_link;
        hop_.queue_ack(info.src, info.peer, info.counter, A::Accepted, 0, now);
        return;
    }
    wire::RouteHeader next = h;
    const route::Decision d = route::decide_forward(next, self_addr(), info.address, local_term());
    switch (d.action) {
    case route::Action::Drop:
        ++stats_.rx_drop_route;
        hop_.queue_ack(info.src, info.peer, info.counter, A::Rejected, 0, now);
        break;
    case route::Action::Forward:
        forward(info, next, record, now);
        break;
    case route::Action::Deliver:
        deliver(info, h, record, now);
        run_post(now);
        break;
    }
}

// ---- relay ----
void Delivery::forward(const link::RxInfo &info, wire::RouteHeader &h, ByteView record, MonoTime now) {
    using A = wire::HopAckStatus;
    auto answer = [&](A st, uint16_t retry) {
        hop_.queue_ack(info.src, info.peer, info.counter, st, retry, now);
        if (st == A::Accepted) {
            note_accepted(info.src, info.counter);
        }
    };
    wire::EndHeader eh;
    ByteView sealed;
    if (wire::decode_end_record(record, eh, sealed) != Status::Ok && record.size() < wire::k_end_header_bytes) {
        answer(A::Rejected, 0);
        return;
    }
    // A frame that is provably past its deadline is not carried further (uncertain time is).
    if (record.size() >= wire::k_end_header_bytes) {
        Reader r{record.subspan(32, 8)};
        const uint64_t expires = r.u64be();
        if (expires != 0 && deadline_state(expires, h.root_term) == DeadlineCheck::After) {
            ++stats_.expired;
            answer(A::Rejected, 0);
            return;
        }
    }
    link::Neighbor *nb = neighbor_at(h.path[h.next_index]);
    if (nb == nullptr) {
        answer(A::Rejected, 0); // no session with the next hop: the origin re-resolves the route
        return;
    }
    std::array<uint8_t, wire::k_max_frame_bytes> body{};
    std::size_t rlen = 0;
    if (wire::encode_route(h, MutByteView{body}, rlen) != Status::Ok ||
        rlen + record.size() > body.size() - wire::k_link_header_bytes - wire::k_tag_bytes) {
        answer(A::Rejected, 0);
        return;
    }
    std::memcpy(body.data() + rlen, record.data(), record.size());
    Handle fh;
    TxFrame *f = hop_.reserve(fh);
    if (f == nullptr) {
        ++stats_.rx_busy; // our buffer, not RF loss: the sender waits and repeats the same frame
        answer(A::Busy, k_busy_retry_ms);
        return;
    }
    const Status st = link_.seal(nb->device, wire::FrameKind::Data, ByteView{body.data(), rlen + record.size()},
                                 f->frame, now);
    if (st != Status::Ok) {
        hop_.release(fh);
        answer(A::Rejected, 0);
        return;
    }
    ++stats_.rx_forward;
    answer(A::Accepted, 0);
    hop_.submit(fh, OwnerKind::Forward, Handle{}, nb->mac, now);
}

// ---- destination ----
// Decides what an incoming end record is and answers the hop; the work that follows (receipts,
// events, journal writes) runs in run_post() after this frame is gone, so the owner stack never
// holds both. Working state lives in members (rx_open_, rx_reply_, post_), not on the stack.
void Delivery::deliver(const link::RxInfo &info, const wire::RouteHeader &h, ByteView record, MonoTime now) {
    using A = wire::HopAckStatus;
    A ack = A::Rejected;
    uint16_t retry_ms = 0;
    post_ = Post{};
    rx_reply_ = reverse_route(h, self_addr());
    wire::EndHeader &eh = rx_open_.header;
    ByteView sealed;
    EndSession *s = nullptr;
    if (wire::decode_end_record(record, eh, sealed) != Status::Ok) {
        // malformed: refused
    } else if (eh.end_sid == k_handshake_sid) {
        if (eh.record_kind == wire::RecordKind::Control && eh.app_port == 0) {
            ack = A::Accepted; // unauthenticated handshake carrier: EDHOC authenticates it (S9-D2)
            post_.k = Post::K::Carrier;
            post_.carrier = record.subspan(wire::k_end_header_bytes, eh.plaintext_length);
        }
    } else if ((s = sessions_.find_rx_sid(eh.end_sid)) == nullptr) {
        ++stats_.rx_no_session;
    } else if (rx_reply_.dest != s->peer_addr || !(now < s->valid_until)) {
        ++stats_.rx_auth_fail; // the route does not start at the session's peer, or the keys are old
    } else {
        const Status st = open_end_record(*s, RootTerm{h.root_term}, record, rx_open_);
        if (st == Status::Ok) {
            s->reply = rx_reply_;
            s->reply_valid = true;
            s->suspect = false;
            sessions_.touch(*s);
            post_.session = s;
            switch (rx_open_.header.record_kind) {
            case wire::RecordKind::Data:
                on_end_data(*s, h.root_term, now, ack, retry_ms);
                break;
            case wire::RecordKind::Receipt:
                s->rec.accept(rx_open_.header.end_counter);
                ack = A::Accepted;
                post_.k = Post::K::Receipt;
                break;
            default:
                ++stats_.rx_unsupported; // fragment / bitmap / control: later slices
                break;
            }
        } else if (st == Status::Replay && rx_open_.verdict == sec::ReplayVerdict::Duplicate) {
            // An authentic record we already accepted at the end level: never applied twice.
            ack = A::Accepted;
            if (rx_open_.header.record_kind == wire::RecordKind::Data) {
                post_.session = s;
                mark_resend(s->peer, rx_open_.header.message_id);
            }
        } else {
            ++stats_.rx_auth_fail;
        }
    }
    hop_.queue_ack(info.src, info.peer, info.counter, ack, retry_ms, now);
    if (ack == A::Accepted) {
        note_accepted(info.src, info.counter);
    }
}

// The message is known here: answer with the newest receipt state (once per repeat).
void Delivery::mark_resend(const DeviceId &origin, const std::array<uint8_t, 16> &mid) {
    for (std::size_t i = 0; i < k_in_entries; ++i) {
        const Handle h = in_.handle_at(i);
        const InEntry *e = in_.get(h);
        if (e != nullptr && e->mid == mid && e->origin == origin) {
            ++stats_.rx_dup_end;
            post_.k = Post::K::Resend;
            post_.in = h;
            return;
        }
    }
}

void Delivery::run_post(MonoTime now) {
    const Post::K k = post_.k;
    post_.k = Post::K::None;
    switch (k) {
    case Post::K::None:
        break;
    case Post::K::Carrier:
        exchange_.on_carrier(rx_reply_, rx_open_.header, post_.carrier, rx_open_, now);
        break;
    case Post::K::Receipt:
        on_receipt(*post_.session, rx_open_, now);
        break;
    case Post::K::Resend: {
        InEntry *e = in_.get(post_.in);
        if (e != nullptr && e->delivery != LM_BEST_EFFORT && e->st != InEntry::St::Committing) {
            const ReceiptEv v = e->st == InEntry::St::Applied      ? ReceiptEv::AppApplied
                                : e->st == InEntry::St::AppRejected ? ReceiptEv::AppRejected
                                : e->app_pending                    ? ReceiptEv::AppPending
                                                                    : ReceiptEv::EndReceived;
            send_receipt(*e, v, 0, now);
        }
        break;
    }
    case Post::K::Refuse:
        if (rx_open_.header.delivery() != wire::Delivery::BestEffort) {
            send_receipt_for(post_.session->peer, rx_open_.header.message_id, post_.hash, post_.ev, post_.reason, 1,
                             rx_open_.header.expires_root_ms, ByteView{}, now);
        }
        break;
    case Post::K::NewVolatile: {
        InEntry *e = in_.get(post_.in);
        if (e != nullptr) {
            if (e->delivery != LM_BEST_EFFORT) {
                send_receipt(*e, ReceiptEv::EndReceived, 0, now);
            }
            queue_message_event(post_.in, *e, now);
            ++stats_.delivered;
        }
        break;
    }
    case Post::K::NewDurable: {
        InEntry *e = in_.get(post_.in);
        if (e != nullptr) {
            e->due_ev = static_cast<uint8_t>(ReceiptEv::EndReceived);
            e->due_version = e->version;
            want_in_commit(post_.in, *e, now);
        }
        break;
    }
    }
}

void Delivery::on_end_data(EndSession &s, uint32_t route_term, MonoTime now, wire::HopAckStatus &ack,
                           uint16_t &retry_ms) {
    using A = wire::HopAckStatus;
    const OpenedEnd &o = rx_open_;
    const wire::EndHeader &eh = o.header;
    Post &post = post_;
    if (!ready_ || recovering_) {
        ++stats_.rx_busy;
        ack = A::Busy; // our records are not loaded yet: the sender repeats, nothing is lost
        retry_ms = k_busy_retry_ms;
        return;
    }
    const bool finite = eh.expires_root_ms != 0;
    if (!finite && !(eh.delivery() == wire::Delivery::Received && eh.durable())) {
        ++stats_.rx_refused; // no-deadline commands are not allowed (docs/08 §5): refuse, do not act
        s.rec.accept(eh.end_counter);
        ack = A::Accepted;
        post.k = Post::K::Refuse;
        post.ev = ReceiptEv::Refused;
        post.reason = static_cast<uint32_t>(Status::InvalidArgument);
        return;
    }
    IntentFields f;
    f.origin = s.peer;
    f.target = identity_.self();
    f.domain = identity_.delegation().domain;
    f.app_port = eh.app_port;
    f.delivery = static_cast<uint8_t>(eh.delivery());
    f.storage = eh.durable() ? 1 : 0;
    f.priority = static_cast<uint8_t>(eh.priority());
    f.root_term = route_term;
    f.expires_root_ms = eh.expires_root_ms;
    f.payload = o.view();
    Sha256Digest hash{};
    if (intent_hash(f, hash) != Status::Ok) {
        return; // Rejected
    }
    if (InEntry *e = find_in(s.peer, eh.message_id)) {
        // A new end counter for a message we know (the origin re-sealed it, e.g. after a new session).
        s.rec.accept(eh.end_counter);
        ack = A::Accepted;
        if (e->hash != hash) {
            ++stats_.rx_refused;
            post.k = Post::K::Refuse;
            post.ev = ReceiptEv::Refused;
            post.reason = static_cast<uint32_t>(Status::Conflict); // same id, different intent
            post.hash = hash;
            return;
        }
        mark_resend(s.peer, eh.message_id);
        return;
    }
    if (finite) {
        const DeadlineCheck dc = deadline_state(eh.expires_root_ms, route_term);
        if (dc != DeadlineCheck::Before) {
            // Refused with evidence: the destination must prove the deadline is not over.
            ++stats_.rx_refused;
            s.rec.accept(eh.end_counter);
            ack = A::Accepted;
            post.k = Post::K::Refuse;
            post.hash = hash;
            if (dc == DeadlineCheck::After) {
                post.ev = ReceiptEv::Expired;
                post.reason = static_cast<uint32_t>(Status::Expired);
            } else {
                post.ev = ReceiptEv::Refused;
                post.reason = static_cast<uint32_t>(Status::TimeUncertain);
            }
            return;
        }
    }
    std::size_t durable_load = 0;
    for (std::size_t i = 0; i < k_in_entries; ++i) {
        const InEntry *x = in_.get(in_.handle_at(i));
        durable_load += (x != nullptr && x->durable && x->st != InEntry::St::Delivered &&
                         x->st != InEntry::St::Applied && x->st != InEntry::St::AppRejected)
                            ? 1U
                            : 0U;
    }
    if (eh.durable() && durable_load >= k_build_limits.durable_pending) {
        ++stats_.rx_refused;
        s.rec.accept(eh.end_counter);
        ack = A::Accepted;
        post.k = Post::K::Refuse;
        post.ev = ReceiptEv::Refused;
        post.reason = static_cast<uint32_t>(Status::NoCapacity); // new durable intake refused, not dropped
        post.hash = hash;
        return;
    }
    // Buffers are reserved before the HOP_ACK says ACCEPTED (docs/08 §6): no room -> BUSY.
    const Handle mb = msgs_.acquire();
    if (mb.is_none()) {
        ++stats_.rx_busy;
        ack = A::Busy;
        retry_ms = k_busy_retry_ms;
        return;
    }
    const Handle ih = alloc_in();
    if (ih.is_none()) {
        (void)msgs_.release(mb);
        ++stats_.rx_busy;
        ack = A::Busy;
        retry_ms = k_busy_retry_ms;
        return;
    }
    InEntry *e = in_.get(ih);
    e->origin = s.peer;
    e->mid = eh.message_id;
    e->hash = hash;
    e->origin_assignment = s.peer_assignment.value();
    e->expires = eh.expires_root_ms;
    e->term = route_term;
    e->port = eh.app_port;
    e->len = static_cast<uint16_t>(o.len);
    e->delivery = static_cast<uint8_t>(eh.delivery());
    e->priority = static_cast<uint8_t>(eh.priority());
    e->durable = eh.durable();
    e->msg = mb;
    e->last_use = ++in_tick_;
    e->arrival = ++arrival_;
    e->st = e->durable ? InEntry::St::Committing : InEntry::St::Held;
    if (e->durable && !alloc_jslot(in_j_, e->jslot)) {
        (void)msgs_.release(mb);
        (void)in_.release(ih);
        ++stats_.rx_busy;
        ack = A::Busy;
        retry_ms = k_busy_retry_ms;
        return;
    }
    if (o.len > 0) {
        std::memcpy(msgs_.get(mb)->data.data(), o.plain.data(), o.len);
    }
    s.rec.accept(eh.end_counter);
    ack = A::Accepted;
    ++stats_.rx_data;
    post.in = ih;
    post.k = e->durable ? Post::K::NewDurable : Post::K::NewVolatile;
    (void)now;
}

// ---- dedup cache ----
InEntry *Delivery::find_in(const DeviceId &origin, const std::array<uint8_t, 16> &mid) {
    for (std::size_t i = 0; i < k_in_entries; ++i) {
        InEntry *e = in_.get(in_.handle_at(i));
        if (e != nullptr && e->mid == mid && e->origin == origin) {
            e->last_use = ++in_tick_;
            return e;
        }
    }
    return nullptr;
}

// A free entry, or the least recently used *finished* one. Live entries (uncommitted, held for the
// application, awaiting a journal write) are never recycled: full means BUSY, not amnesia.
Handle Delivery::alloc_in() {
    Handle h = in_.acquire();
    if (!h.is_none()) {
        return h;
    }
    Handle victim;
    const InEntry *best = nullptr;
    for (std::size_t i = 0; i < k_in_entries; ++i) {
        const Handle c = in_.handle_at(i);
        const InEntry *e = in_.get(c);
        const bool finished = e != nullptr &&
                              (e->st == InEntry::St::Delivered || e->st == InEntry::St::Applied ||
                               e->st == InEntry::St::AppRejected) &&
                              !e->commit_wanted && e->persisted_version >= e->version && !e->event_owed;
        if (finished && (best == nullptr || static_cast<int32_t>(e->last_use - best->last_use) < 0)) {
            best = e;
            victim = c;
        }
    }
    if (victim.is_none()) {
        return Handle{};
    }
    if (best->durable) {
        in_j_[best->jslot] = false; // its record stays as dedup memory until a new one overwrites it
    }
    (void)in_.release(victim);
    return in_.acquire();
}

// ---- receipts (destination) ----
void Delivery::send_receipt(InEntry &e, ReceiptEv ev, uint32_t reason, MonoTime now) {
    send_receipt_for(e.origin, e.mid, e.hash, ev, reason, ++e.receipt_seq, e.expires,
                     ByteView{e.result.data(), e.result_len}, now);
}

void Delivery::send_receipt_for(const DeviceId &origin, const std::array<uint8_t, 16> &mid, const Sha256Digest &hash,
                                ReceiptEv ev, uint32_t reason, uint32_t seq, uint64_t expires, ByteView result,
                                MonoTime now) {
    EndSession *s = sessions_.find_peer(origin);
    PathSpec ps;
    if (s == nullptr || !s->rec.active() || !(now < s->valid_until)) {
        ++stats_.receipts_dropped; // no session: the origin's next round asks again
        return;
    }
    if (s->reply_valid) {
        ps = s->reply;
        ps.origin = self_addr();
    } else if (!route_for(origin, ps, now)) {
        ++stats_.receipts_dropped;
        return;
    }
    Receipt r;
    r.message_id = mid;
    r.intent_hash = hash;
    r.evidence = ev;
    r.reason = reason;
    r.sequence = seq;
    r.result_len = static_cast<uint8_t>(result.size() > k_result_bytes ? k_result_bytes : result.size());
    if (r.result_len > 0) {
        std::memcpy(r.result.data(), result.data(), r.result_len);
    }
    // Plaintext in the first 96 B of the shared TX buffer, the sealed record after it.
    uint8_t *const rec_at = tx_scratch_.data() + k_rec_off;
    std::size_t plen = 0;
    if (encode_receipt(r, MutByteView{tx_scratch_.data(), k_rec_off}, plen) != Status::Ok ||
        plen > wire::data_capacity(ps.len)) {
        ++stats_.receipts_dropped; // does not fit one frame at this depth: needs the fragment slice
        return;
    }
    wire::EndHeader eh;
    eh.message_id = mid;
    eh.app_port = 0;
    eh.record_kind = wire::RecordKind::Receipt;
    eh.flags = wire::make_end_flags(wire::Delivery::BestEffort, wire::Priority::Control, false);
    eh.expires_root_ms = expires;
    std::size_t rlen = 0;
    Status st = seal_end_record(*s, s->tx_sid, ps.term, eh, ByteView{tx_scratch_.data(), plen},
                                MutByteView{rec_at, k_record_bytes}, rlen);
    if (st != Status::Ok || !build_and_send(ps, ByteView{rec_at, rlen}, OwnerKind::Receipt, Handle{}, now, st)) {
        ++stats_.receipts_dropped; // TX pool full or no link: never blocks the owner, never RF loss
        retry_kick_ = earliest(retry_kick_, now + Duration::from_ms(100));
        return;
    }
    ++stats_.receipts_sent;
}

// ---- application result ----
Reply Delivery::report_result(const ReportRequest &rq, ByteView result, MonoTime now) {
    if (!identity_.is_member() || !ready_) {
        return reply(ready_ ? Status::AuthPending : Status::Busy);
    }
    if (result.size() > k_result_bytes ||
        (rq.outcome != LM_OUTCOME_APPLIED && rq.outcome != LM_OUTCOME_REJECTED &&
         rq.outcome != LM_OUTCOME_PENDING)) {
        return reply(Status::InvalidArgument);
    }
    DeviceId origin;
    std::array<uint8_t, 16> mid{};
    Sha256Digest hash{};
    std::memcpy(origin.bytes.data(), rq.ref.origin.bytes, 32);
    std::memcpy(mid.data(), rq.ref.id.bytes, 16);
    std::memcpy(hash.data(), rq.ref.intent_hash, 32);
    Handle h;
    InEntry *e = nullptr;
    for (std::size_t i = 0; i < k_in_entries; ++i) {
        InEntry *x = in_.get(in_.handle_at(i));
        if (x != nullptr && x->mid == mid && x->origin == origin) {
            e = x;
            h = in_.handle_at(i);
        }
    }
    if (e == nullptr) {
        return reply(Status::NotFound);
    }
    if (e->hash != hash) {
        return reply(Status::Conflict);
    }
    if (e->delivery != LM_APPLIED) {
        return reply(Status::InvalidArgument); // only APPLIED messages have an application result
    }
    if (e->st == InEntry::St::Committing || e->st == InEntry::St::Held) {
        return reply(Status::Conflict); // the application has not taken the message yet
    }
    const bool final_state = e->st == InEntry::St::Applied || e->st == InEntry::St::AppRejected;
    const uint8_t want = rq.outcome == LM_OUTCOME_APPLIED ? static_cast<uint8_t>(InEntry::St::Applied)
                                                          : static_cast<uint8_t>(InEntry::St::AppRejected);
    if (final_state) {
        const bool same = rq.outcome != LM_OUTCOME_PENDING && static_cast<uint8_t>(e->st) == want &&
                          e->result_len == result.size() &&
                          (result.empty() || std::memcmp(e->result.data(), result.data(), result.size()) == 0);
        return same ? reply(Status::Ok) : reply(Status::Conflict); // an outcome is never changed
    }
    Op *op = alloc_op();
    if (op == nullptr) {
        return reply(Status::NoCapacity);
    }
    *op = Op{};
    op->used = true;
    op->report = true;
    op->id = next_op_id_++;
    op->seq = ++op_tick_;
    op->dest = origin;
    op->mid = to_message_id(mid); // the origin's message id (this is the destination's record)
    op->hash = hash;
    op->port = e->port;
    op->delivery = e->delivery;
    op->outcome = static_cast<uint8_t>(rq.outcome);
    op->phase = Phase::Final;
    op->evidence = ev::accepted;
    op->accepted_ms = op->last_evidence_ms = now.to_ms();
    if (rq.outcome == LM_OUTCOME_PENDING) {
        e->app_pending = true;
        op->phase = Phase::Pending;
        send_receipt(*e, ReceiptEv::AppPending, 0, now);
        return reply(Status::Ok, op->id);
    }
    e->app_pending = false;
    e->st = static_cast<InEntry::St>(want);
    e->result_len = static_cast<uint8_t>(result.size());
    if (!result.empty()) {
        std::memcpy(e->result.data(), result.data(), result.size());
    }
    const ReceiptEv rev = rq.outcome == LM_OUTCOME_APPLIED ? ReceiptEv::AppApplied : ReceiptEv::AppRejected;
    if (e->durable) {
        // The result is persisted before the receipt that claims it (accepted != persisted != sent).
        e->due_ev = static_cast<uint8_t>(rev);
        e->due_version = ++e->version;
        want_in_commit(h, *e, now);
    } else {
        send_receipt(*e, rev, 0, now);
    }
    return reply(Status::Ok, op->id);
}

} // namespace lm::delivery
