// Fragmentation and reassembly (docs/09 §6), see fragment.hpp for the model. Everything runs on the
// mesh owner; no allocation, every slot/buffer bounded, every timeout fixed at reservation.
#include <algorithm>
#include <cstring>

#include "core/delivery/delivery.hpp"
#include "core/engine.hpp"

namespace lm::delivery {
namespace {

constexpr uint16_t k_busy_retry_ms = 200;
constexpr Duration k_small_timeout = Duration::from_ms(static_cast<int64_t>(gen::defaults::delivery::small_reassembly_ms));
constexpr Duration k_object_timeout =
    Duration::from_ms(static_cast<int64_t>(gen::defaults::delivery::object_reassembly_ms));

unsigned first_missing(const uint8_t *bm, unsigned nq) {
    unsigned q = 0;
    while (q < nq && bit_get(bm, q)) {
        ++q;
    }
    return q;
}

// The bitmap of a transfer that has been received completely.
wire::TransferBitmap full_bitmap(unsigned total) {
    wire::TransferBitmap b;
    for (unsigned q = 0; q < quanta_of(total); ++q) {
        bit_set(b.bitmap.data(), q);
    }
    return b;
}

} // namespace

// ---- payload lanes ----
bool Delivery::object_enabled() const { return k_object_capable && engine_.config().object_transfer_enabled; }

bool Delivery::lane_free(Lane lane) const {
    if (lane == Lane::Control) {
        return !frag_.ctl_tx && frag_.slots[k_small_slots].st == RxSlot::St::Free;
    }
    if (lane == Lane::Object) {
        return k_object_capable && !frag_.obj_tx && !frag_.obj_held &&
               frag_.slots[k_small_slots + 1].st == RxSlot::St::Free;
    }
    return true;
}

ByteView Delivery::active_payload(const Active &a) const {
    switch (a.lane) {
    case Lane::Control:
        return ByteView{frag_.ctl_buf.data(), a.len};
    case Lane::Object:
        return ByteView{frag_.obj_buf.data(), a.len};
    case Lane::Pool:
        break;
    }
    const MsgBuf *b = msgs_.get(a.msg);
    return b != nullptr ? ByteView{b->data.data(), a.len} : ByteView{};
}

void Delivery::free_lane(const Active &a) {
    frag_.ctl_tx = frag_.ctl_tx && a.lane != Lane::Control;
    frag_.obj_tx = frag_.obj_tx && a.lane != Lane::Object;
}

Reply Delivery::send_mode(SendMode m, const lm_send_request_t &rq, ByteView payload, MonoTime now) {
    send_mode_ = m; // consulted by send() at the size/lane rules; never left set
    const Reply r = send(rq, payload, now);
    send_mode_ = SendMode::Api;
    return r;
}

Reply Delivery::send_control(const ControlSendRequest &c, ByteView payload, MonoTime now) {
    lm_send_request_t rq{};
    rq.struct_size = sizeof(rq);
    rq.abi_version = LM_ABI_VERSION;
    rq.destination.kind = LM_DEST_NODE;
    std::memcpy(rq.destination.node.bytes, c.dest.bytes.data(), 32);
    rq.delivery = LM_BEST_EFFORT; // completes when every fragment is confirmed; no receipt exists
    rq.storage = LM_VOLATILE;
    rq.priority = LM_PRIORITY_CONTROL;
    rq.queue_mode = LM_FIFO;
    rq.root_term = c.root_term;
    rq.expires_root_ms = c.expires_root_ms;
    return send_mode(SendMode::Control, rq, payload, now);
}

// ---- origin: the next fragment ----
// Seals the next fragment of `a` into the shared TX buffer. `parked`: nothing is sent now (window
// full, or everything is sent and confirmed) and the state/timers say what to wait for.
Status Delivery::seal_fragment(Active &a, Op &op, EndSession &s, const PathSpec &ps, ByteView &record, bool &parked,
                               MonoTime now) {
    const std::size_t chunk = wire::fragment_chunk(ps.len);
    if (chunk == 0) {
        return Status::InvalidArgument;
    }
    const unsigned qc = static_cast<unsigned>(chunk / wire::k_fragment_quantum);
    const unsigned nq = quanta_of(a.len);
    uint8_t *bm = a.acked.data();
    const unsigned missing = first_missing(bm, nq);
    const bool all = missing >= nq;
    if (a.new_round) { // a stalled round is repeated from the first missing fragment (or polls with the first)
        a.cursor = all ? 0 : static_cast<uint16_t>(missing * wire::k_fragment_quantum);
    }
    unsigned q = a.cursor / wire::k_fragment_quantum;
    while (!(all && a.new_round) && q < nq && bit_get(bm, q)) {
        ++q;
    }
    unsigned open = 0; // fragments sent and not yet confirmed
    for (unsigned i = 0; i < std::min(q, nq); ++i) {
        open += bit_get(bm, i) ? 0U : 1U;
    }
    if (!a.new_round && (q >= nq || open >= k_frag_window * qc)) {
        a.st = Active::St::WaitReceipt;
        op.phase = Phase::WaitingReceipt;
        a.hops = ps.len;
        a.round_at = now + round_timeout(ps.len);
        a.next_at = earliest(a.round_at, local_deadline(op.expires, op.term, now));
        parked = true;
        return Status::Ok;
    }
    const std::size_t off = std::size_t{q} * wire::k_fragment_quantum;
    const std::size_t len = std::min<std::size_t>(chunk, a.len - off);
    wire::FragmentPrefix p;
    p.total_len = a.len;
    p.offset = static_cast<uint16_t>(off);
    p.fragment_len = static_cast<uint16_t>(len);
    p.original_kind = a.control ? wire::RecordKind::Control : wire::RecordKind::Data;
    p.object_class = a.control ? wire::ObjectClass::Control
                               : (a.len > k_msg_bytes ? wire::ObjectClass::Object : wire::ObjectClass::Small);
    p.intent_hash = op.hash;
    LM_TRY(wire::encode_fragment_prefix(p, MutByteView{frag_plain_.data(), wire::k_fragment_prefix_bytes}));
    std::memcpy(frag_plain_.data() + wire::k_fragment_prefix_bytes, active_payload(a).data() + off, len);
    wire::EndHeader eh;
    eh.message_id = to_bytes(op.mid);
    eh.app_port = op.port;
    eh.record_kind = wire::RecordKind::Fragment;
    eh.flags = wire::make_end_flags(static_cast<wire::Delivery>(op.delivery), static_cast<wire::Priority>(op.priority),
                                    op.storage == LM_DURABLE);
    eh.expires_root_ms = op.expires;
    // A fragmented send never keeps a whole-message record: its fragments are sealed into the send's own
    // record buffer, one at a time (the hop layer holds the sealed frame it queued).
    uint8_t *const rec_at = a.record.data();
    std::size_t rlen = 0;
    LM_TRY(seal_end_record(s, s.tx_sid, ps.term, eh,
                           ByteView{frag_plain_.data(), wire::k_fragment_prefix_bytes + len},
                           MutByteView{rec_at, k_record_bytes}, rlen));
    a.cursor = static_cast<uint16_t>(off + len);
    record = ByteView{rec_at, rlen};
    ++frag_.stats.tx;
    return Status::Ok;
}

// A TRANSFER_BITMAP from the destination: merge it, then continue, wait for the receipt, or finish.
void Delivery::on_bitmap(const EndSession &s, const OpenedEnd &o, MonoTime now) {
    wire::TransferBitmap bm;
    Op *op = find_op_by_message(s.peer, o.header.message_id);
    if (decode_transfer_bitmap(o.view(), bm) != Status::Ok || op == nullptr || op->active.is_none()) {
        return;
    }
    const Handle h = op->active;
    Active *a = actives_.get(h);
    if (a == nullptr || !a->xfer) {
        return;
    }
    ++frag_.stats.bitmap_rx;
    const unsigned nq = quanta_of(a->len);
    bool progress = false;
    for (unsigned q = 0; q < nq; ++q) {
        if (bit_get(bm.bitmap.data(), q) && !bit_get(a->acked.data(), q)) {
            bit_set(a->acked.data(), q);
            progress = true;
        }
    }
    if (!progress) {
        return; // nothing new: the stall timer keeps running
    }
    a->round = 1; // progress: the stalled-round count starts over (the deadline never does)
    a->new_round = false;
    if (first_missing(a->acked.data(), nq) >= nq) { // the destination has every byte
        if (op->delivery == LM_BEST_EFFORT || a->control) {
            finalize_active(h, LM_OUTCOME_SUBMITTED, 0, now); // transfer evidence only, no receipt exists
        } else if (a->st != Active::St::Sending) {
            (void)hop_.withdraw(OwnerKind::Out, h);
            a->st = Active::St::WaitReceipt;
            op->phase = Phase::WaitingReceipt;
            a->round_at = now + round_timeout(a->hops == 0 ? 1U : a->hops);
            a->next_at = earliest(a->round_at, local_deadline(op->expires, op->term, now));
        }
        return;
    }
    if (a->st == Active::St::WaitReceipt) { // the window opened: the next fragment goes out from on_timer()
        a->st = Active::St::WaitRoute;
        a->next_at = now;
    }
}

// ---- destination: reassembly ----
uint8_t *Delivery::frag_have(RxSlot &slot) {
    return (k_object_capable && &slot == &frag_.slots[k_small_slots + 1]) ? frag_.obj_have.data() : slot.have.data();
}

uint8_t *Delivery::frag_buf(RxSlot &slot) {
    if (&slot == &frag_.slots[k_small_slots]) {
        return frag_.ctl_buf.data();
    }
    if (k_object_capable && &slot == &frag_.slots[k_small_slots + 1]) {
        return frag_.obj_buf.data();
    }
    MsgBuf *b = msgs_.get(slot.msg);
    return b != nullptr ? b->data.data() : nullptr;
}

void Delivery::frag_release(RxSlot &slot) {
    (void)msgs_.release(slot.msg);
    slot = RxSlot{};
}

void Delivery::frag_expire(MonoTime now) {
    for (RxSlot &slot : frag_.slots) {
        if (slot.st == RxSlot::St::Filling && slot.until <= now) {
            ++frag_.stats.rx_expired; // a stalled transfer frees its buffer; the sender's rounds start over
            frag_release(slot);
        }
    }
}

MonoTime Delivery::frag_deadline() const {
    MonoTime next = MonoTime::never();
    for (const RxSlot &slot : frag_.slots) {
        if (slot.st == RxSlot::St::Filling) {
            next = earliest(next, slot.until);
        }
    }
    return next;
}

// Reserves the slot and its buffer for a new transfer: the first authenticated fragment fixes
// length, meaning, hash and lifetime (docs/09 §6). Receipts and control objects have their own slot
// and buffer, so a full message lane never blocks them. nullptr: BUSY.
RxSlot *Delivery::frag_alloc(const wire::FragmentPrefix &p, const wire::EndHeader &eh, uint32_t term,
                             const EndSession &s, MonoTime now) {
    frag_expire(now);
    const bool data = p.original_kind == wire::RecordKind::Data;
    RxSlot *slot = nullptr;
    Handle mb;
    if (!data) {
        slot = &frag_.slots[k_small_slots];
        if (slot->st != RxSlot::St::Free || frag_.ctl_tx) {
            return nullptr;
        }
    } else if (p.object_class == wire::ObjectClass::Object) {
        slot = &frag_.slots[k_small_slots + 1]; // only reachable when the object lane is built
        if (slot->st != RxSlot::St::Free || frag_.obj_tx || frag_.obj_held) {
            return nullptr;
        }
    } else {
        RxSlot *oldest_bulk = nullptr;
        for (std::size_t i = 0; i < k_small_slots; ++i) {
            RxSlot &c = frag_.slots[i];
            if (c.st == RxSlot::St::Free) {
                slot = &c;
                break;
            }
            const bool bulk = ((c.flags >> 2U) & 3U) == static_cast<uint8_t>(wire::Priority::Bulk);
            if (bulk && (oldest_bulk == nullptr || static_cast<int32_t>(c.last_use - oldest_bulk->last_use) < 0)) {
                oldest_bulk = &c;
            }
        }
        if (slot == nullptr && oldest_bulk != nullptr && eh.priority() != wire::Priority::Bulk) {
            frag_release(*oldest_bulk); // an old bulk reassembly goes first (docs/08 §8)
            slot = oldest_bulk;
        }
        if (slot == nullptr) {
            return nullptr;
        }
        mb = msgs_.acquire();
        if (mb.is_none()) {
            return nullptr;
        }
    }
    *slot = RxSlot{};
    slot->st = RxSlot::St::Filling;
    slot->cls = p.object_class;
    slot->kind = p.original_kind;
    slot->flags = eh.flags;
    slot->total = p.total_len;
    slot->port = eh.app_port;
    slot->sid = s.rx_sid;
    slot->epoch = s.epoch;
    slot->term = term;
    slot->last_use = ++frag_.tick;
    slot->expires = eh.expires_root_ms;
    slot->mid = eh.message_id;
    slot->hash = p.intent_hash;
    slot->msg = mb;
    if (k_object_capable && slot == &frag_.slots[k_small_slots + 1]) {
        frag_.obj_have = {};
    }
    const bool long_lived = data ? p.object_class == wire::ObjectClass::Object : p.original_kind == wire::RecordKind::Control;
    // Never extended by later fragments or retries, and never past the message's own deadline.
    slot->until = earliest(now + (long_lived ? k_object_timeout : k_small_timeout),
                           local_deadline(eh.expires_root_ms, term, now));
    return slot;
}

// Accepted + refusal receipt (the transfer is discarded; nothing partial reaches anyone).
void Delivery::frag_refuse(EndSession &s, const Sha256Digest &hash, ReceiptEv ev, Status why, wire::HopAckStatus &ack) {
    ++frag_.stats.rx_refused;
    s.rec.accept(rx_open_.header.end_counter);
    ack = wire::HopAckStatus::Accepted;
    post_.k = Post::K::Refuse;
    post_.ev = ev;
    post_.reason = static_cast<uint32_t>(why);
    post_.hash = hash;
}

void Delivery::on_end_fragment(EndSession &s, uint32_t term, MonoTime now, wire::HopAckStatus &ack,
                               uint16_t &retry_ms) {
    using A = wire::HopAckStatus;
    const wire::EndHeader &eh = rx_open_.header;
    wire::FragmentPrefix p;
    ByteView bytes;
    if (wire::decode_fragment(rx_open_.view(), p, bytes) != Status::Ok) {
        return; // Rejected
    }
    const bool data = p.original_kind == wire::RecordKind::Data;
    const bool receipt = p.original_kind == wire::RecordKind::Receipt;
    const bool small = p.object_class == wire::ObjectClass::Small;
    // Data is Small (<= 512) or Object; receipts and control objects are class Control on port 0.
    if (data ? (p.object_class == wire::ObjectClass::Control || small != (p.total_len <= k_msg_bytes))
             : (p.object_class != wire::ObjectClass::Control || eh.app_port != 0)) {
        return; // Rejected: not a transfer this protocol defines
    }
    if (data ? !data_gate(s, eh, ack, retry_ms) : (!ready_ || recovering_)) {
        if (!data) {
            ++stats_.rx_busy;
            ack = A::Busy;
            retry_ms = k_busy_retry_ms;
        }
        return;
    }
    if (p.original_kind == wire::RecordKind::Control && eh.expires_root_ms == 0) {
        return frag_refuse(s, p.intent_hash, ReceiptEv::Refused, Status::InvalidArgument, ack); // no control without a deadline
    }
    if (p.object_class == wire::ObjectClass::Object && !object_enabled()) {
        return frag_refuse(s, p.intent_hash, ReceiptEv::Refused, Status::Unsupported, ack);
    }
    if (!data && p.total_len > k_control_bytes) {
        return frag_refuse(s, p.intent_hash, ReceiptEv::Refused,
                           data ? Status::PayloadTooLarge : Status::NoCapacity, ack);
    }
    // A transfer that already completed here.
    bool done = false;
    if (data) {
        if (const InEntry *e = find_in(s.peer, s.peer_assignment.value(), eh.message_id)) {
            s.rec.accept(eh.end_counter);
            ack = A::Accepted;
            if (e->hash != p.intent_hash) {
                ++frag_.stats.rx_conflict;
                post_.k = Post::K::Refuse;
                post_.ev = ReceiptEv::Refused;
                post_.reason = static_cast<uint32_t>(Status::Conflict);
                post_.hash = p.intent_hash;
                return;
            }
            mark_resend(s.peer, s.peer_assignment.value(), eh.message_id); // the newest receipt again
            done = true;
        }
    } else if (p.original_kind == wire::RecordKind::Control) {
        done = find_control_done(s, eh.message_id, p.intent_hash) != nullptr;
        if (done) {
            s.rec.accept(eh.end_counter);
            ack = A::Accepted;
        }
    }
    if (done) {
        ++frag_.stats.rx_dup;
        post_.bitmap = full_bitmap(p.total_len); // the sender may stop: everything is here
        post_.bitmap_owed = true;
        return;
    }
    // The transfer's slot, or a new one.
    RxSlot *slot = nullptr;
    for (RxSlot &c : frag_.slots) {
        if (c.st == RxSlot::St::Filling && c.sid == s.rx_sid && c.epoch == s.epoch && c.mid == eh.message_id) {
            slot = &c;
        }
    }
    if (slot != nullptr) {
        if (slot->hash != p.intent_hash || slot->total != p.total_len || slot->kind != p.original_kind ||
            slot->cls != p.object_class || slot->flags != eh.flags || slot->port != eh.app_port ||
            slot->expires != eh.expires_root_ms || slot->term != term) {
            ++frag_.stats.rx_conflict; // not the transfer the first fragment described
            frag_release(*slot);
            frag_refuse(s, p.intent_hash, ReceiptEv::Refused, Status::Conflict, ack);
            return;
        }
    } else {
        if (eh.expires_root_ms != 0) {
            const DeadlineCheck dc = deadline_state(eh.expires_root_ms, term);
            if (dc != DeadlineCheck::Before) {
                frag_refuse(s, p.intent_hash, dc == DeadlineCheck::After ? ReceiptEv::Expired : ReceiptEv::Refused,
                            dc == DeadlineCheck::After ? Status::Expired : Status::TimeUncertain, ack);
                return;
            }
        }
        slot = frag_alloc(p, eh, term, s, now);
        if (slot == nullptr) {
            ++frag_.stats.rx_busy;
            ack = A::Busy; // no slot or buffer: the sender waits, nothing is lost
            retry_ms = k_busy_retry_ms;
            return;
        }
    }
    uint8_t *const buf = frag_buf(*slot);
    uint8_t *const have = frag_have(*slot);
    // Same offset, other bytes: the transfer is void and nothing of it is ever delivered (D09).
    const unsigned q0 = p.offset / wire::k_fragment_quantum;
    const unsigned nfq = quanta_of(p.fragment_len);
    for (unsigned i = 0; i < nfq; ++i) {
        const std::size_t n = std::min<std::size_t>(wire::k_fragment_quantum, p.fragment_len - i * wire::k_fragment_quantum);
        if (bit_get(have, q0 + i) &&
            std::memcmp(buf + (q0 + i) * wire::k_fragment_quantum, bytes.data() + i * wire::k_fragment_quantum, n) != 0) {
            ++frag_.stats.rx_conflict;
            const Sha256Digest hash = slot->hash;
            frag_release(*slot);
            frag_refuse(s, hash, ReceiptEv::Refused, Status::Conflict, ack);
            return;
        }
    }
    uint8_t fresh[8];
    unsigned n_fresh = 0;
    for (unsigned i = 0; i < nfq; ++i) {
        if (!bit_get(have, q0 + i)) {
            const std::size_t n =
                std::min<std::size_t>(wire::k_fragment_quantum, p.fragment_len - i * wire::k_fragment_quantum);
            std::memcpy(buf + (q0 + i) * wire::k_fragment_quantum, bytes.data() + i * wire::k_fragment_quantum, n);
            bit_set(have, q0 + i);
            fresh[n_fresh++] = static_cast<uint8_t>(q0 + i);
        }
    }
    slot->last_use = ++frag_.tick;
    const unsigned nq = quanta_of(slot->total);
    auto current_bitmap = [&] {
        wire::TransferBitmap b;
        std::memcpy(b.bitmap.data(), have, (k_object_capable && slot == &frag_.slots[k_small_slots + 1]) ? 32U : 8U);
        b.credit = static_cast<uint8_t>(k_frag_window);
        return b;
    };
    if (n_fresh == 0) { // nothing new: the sender did not see our bitmap (or repeats a round)
        ++frag_.stats.rx_dup;
        s.rec.accept(eh.end_counter);
        ack = A::Accepted;
        if (!receipt) {
            post_.bitmap = current_bitmap();
            post_.bitmap_owed = true;
        }
        return;
    }
    ++frag_.stats.rx;
    if (first_missing(have, nq) >= nq) {
        frag_complete(*slot, s, term, now, ack, retry_ms, fresh, n_fresh);
        return;
    }
    s.rec.accept(eh.end_counter);
    ack = A::Accepted;
    if (!receipt && ++slot->unacked >= 2) { // a bitmap for every second new fragment keeps the window moving
        slot->unacked = 0;
        post_.bitmap = current_bitmap();
        post_.bitmap_owed = true;
    }
}

// Every byte is here: verify the hash the first fragment promised, then dispatch exactly once.
void Delivery::frag_complete(RxSlot &slot, EndSession &s, uint32_t route_term, MonoTime now, wire::HopAckStatus &ack,
                             uint16_t &retry_ms, const uint8_t *fresh, unsigned n_fresh) {
    using A = wire::HopAckStatus;
    const wire::EndHeader &eh = rx_open_.header;
    const ByteView payload{frag_buf(slot), slot.total};
    Sha256Digest hash{};
    if (slot.kind == wire::RecordKind::Data) {
        const Status hs = intent_hash(rx_fields(s, eh, route_term, payload), hash);
        if (hs != Status::Ok || hash != slot.hash) {
            const Sha256Digest promised = slot.hash;
            frag_release(slot);
            frag_refuse(s, promised, ReceiptEv::Refused, Status::InvalidArgument, ack); // not the message it claimed
            return;
        }
        const Lane lane = slot.cls == wire::ObjectClass::Object ? Lane::Object : Lane::Pool;
        admit_data(s, route_term, payload, lane, slot.msg, hash, now, ack, retry_ms);
        if (ack == A::Busy) { // no entry or journal slot yet: the last fragment counts as not received
            for (unsigned i = 0; i < n_fresh; ++i) {
                frag_have(slot)[fresh[i] / 8U] = static_cast<uint8_t>(frag_have(slot)[fresh[i] / 8U] & ~(1U << (fresh[i] % 8U)));
            }
            ++frag_.stats.rx_busy;
            return;
        }
        ++frag_.stats.completed;
        if (post_.k == Post::K::NewVolatile || post_.k == Post::K::NewDurable) {
            slot.msg = Handle{}; // the payload now belongs to the entry
            frag_.obj_held = frag_.obj_held || lane == Lane::Object;
        }
        post_.bitmap = full_bitmap(slot.total);
        post_.bitmap_owed = true;
        frag_release(slot);
        return;
    }
    if (object_hash(s.peer, identity_.self(), identity_.delegation().domain, slot.kind, slot.flags, slot.term,
                    slot.expires, payload, hash) != Status::Ok ||
        hash != slot.hash) {
        s.rec.accept(eh.end_counter);
        ack = A::Accepted;
        frag_release(slot); // authentic but not what it promised: dropped, the sender's rounds end
        return;
    }
    ControlDone *done = nullptr;
    if (slot.kind == wire::RecordKind::Control && (done = free_control_done()) == nullptr) {
        for (unsigned i = 0; i < n_fresh; ++i) { // FIX4-D4: every entry is live: the last fragment counts as not received
            frag_have(slot)[fresh[i] / 8U] = static_cast<uint8_t>(frag_have(slot)[fresh[i] / 8U] & ~(1U << (fresh[i] % 8U)));
        }
        ++frag_.stats.rx_busy;
        ack = A::Busy;
        retry_ms = k_busy_retry_ms;
        return;
    }
    s.rec.accept(eh.end_counter);
    ack = A::Accepted;
    ++frag_.stats.completed;
    post_.free_slot = static_cast<uint8_t>(&slot - frag_.slots.data() + 1);
    post_.carrier = payload;
    if (slot.kind == wire::RecordKind::Receipt) {
        post_.k = Post::K::Receipt; // receipts are repeated by the origin's E2E rounds, no bitmap
        return;
    }
    post_.k = Post::K::Control;
    done->used = true;
    done->term = slot.term;
    done->assignment = s.peer_assignment.value();
    done->expires = slot.expires;
    done->origin = s.peer;
    done->mid = eh.message_id;
    done->hash = hash;
    post_.bitmap = full_bitmap(slot.total);
    post_.bitmap_owed = true;
}

// A completed control object is live until its deadline is provably over, or its root term ended (a retry from an
// older term is refused on arrival anyway, so it can never be dispatched again).
bool Delivery::control_done_live(const ControlDone &c) const {
    if (!c.used) {
        return false;
    }
    if (bound_.valid && bound_.term.value() != c.term) {
        return false;
    }
    return deadline_state(c.expires, c.term) != DeadlineCheck::After;
}

const ControlDone *Delivery::find_control_done(const EndSession &s, const std::array<uint8_t, 16> &mid,
                                               const Sha256Digest &hash) const {
    for (const ControlDone &c : frag_.done) {
        if (control_done_live(c) && c.assignment == s.peer_assignment.value() && c.mid == mid && c.hash == hash &&
            c.origin == s.peer) {
            return &c;
        }
    }
    return nullptr;
}

ControlDone *Delivery::free_control_done() {
    for (ControlDone &c : frag_.done) {
        if (!control_done_live(c)) {
            c = ControlDone{};
            return &c;
        }
    }
    return nullptr;
}

// ---- destination: answers ----
void Delivery::send_bitmap(EndSession &s, const wire::EndHeader &hdr, const wire::TransferBitmap &bm, MonoTime now) {
    PathSpec ps;
    if (!s.rec.active() || !(now < s.valid_until) || !route_for(s.peer, ps, now)) {
        return; // the origin's next fragment or round asks again
    }
    std::array<uint8_t, wire::k_transfer_bitmap_body> plain{};
    Lease scratch{engine_.frames()};
    if (!scratch.ok() || wire::encode_transfer_bitmap(bm, MutByteView{plain}) != Status::Ok) {
        return; // no pool frame: the origin's next fragment or round asks again
    }
    wire::EndHeader eh;
    eh.message_id = hdr.message_id;
    eh.record_kind = wire::RecordKind::TransferBitmap;
    eh.flags = wire::make_end_flags(wire::Delivery::BestEffort, wire::Priority::Control, false);
    eh.expires_root_ms = hdr.expires_root_ms;
    std::size_t rlen = 0;
    Status st = seal_end_record(s, s.tx_sid, ps.term, eh, ByteView{plain}, record_area(scratch, ps.len), rlen);
    if (st == Status::Ok && build_and_send(ps, scratch, rlen, OwnerKind::Receipt, Handle{}, now, st)) {
        ++frag_.stats.bitmap_tx;
    }
}

// A receipt that does not fit one frame at this depth: its fragments, once each. The origin's next
// E2E round makes us send the newest receipt again, and its slot keeps what already arrived.
Status Delivery::send_receipt_fragments(EndSession &s, const PathSpec &ps, const std::array<uint8_t, 16> &mid,
                                        ByteView plain, uint64_t expires, MonoTime now) {
    std::array<uint8_t, k_receipt_max> &rp = frag_.receipt; // the shared TX buffer is overwritten by every frame sent
    if (plain.size() > rp.size()) {
        return Status::PayloadTooLarge;
    }
    std::memcpy(rp.data(), plain.data(), plain.size());
    const uint8_t flags = wire::make_end_flags(wire::Delivery::BestEffort, wire::Priority::Control, false);
    wire::FragmentPrefix p;
    p.total_len = static_cast<uint16_t>(plain.size());
    p.original_kind = wire::RecordKind::Receipt;
    p.object_class = wire::ObjectClass::Control;
    LM_TRY(object_hash(identity_.self(), s.peer, identity_.delegation().domain, wire::RecordKind::Receipt, flags,
                       ps.term.value(), expires, ByteView{rp.data(), plain.size()}, p.intent_hash));
    const std::size_t chunk = wire::fragment_chunk(ps.len);
    if (chunk == 0) {
        return Status::InvalidArgument;
    }
    Lease scratch{engine_.frames()}; // one build frame for every fragment of this receipt
    if (!scratch.ok()) {
        return Status::NoCapacity;
    }
    for (std::size_t off = 0; off < plain.size(); off += chunk) {
        const std::size_t len = std::min(chunk, plain.size() - off);
        p.offset = static_cast<uint16_t>(off);
        p.fragment_len = static_cast<uint16_t>(len);
        LM_TRY(wire::encode_fragment_prefix(p, MutByteView{frag_plain_.data(), wire::k_fragment_prefix_bytes}));
        std::memcpy(frag_plain_.data() + wire::k_fragment_prefix_bytes, rp.data() + off, len);
        wire::EndHeader eh;
        eh.message_id = mid;
        eh.record_kind = wire::RecordKind::Fragment;
        eh.flags = flags;
        eh.expires_root_ms = expires;
        std::size_t rlen = 0;
        LM_TRY(seal_end_record(s, s.tx_sid, ps.term, eh, ByteView{frag_plain_.data(), wire::k_fragment_prefix_bytes + len},
                               record_area(scratch, ps.len), rlen));
        Status st = Status::Ok;
        if (!build_and_send(ps, scratch, rlen, OwnerKind::Receipt, Handle{}, now, st)) {
            return st;
        }
        ++frag_.stats.tx;
    }
    return Status::Ok;
}

} // namespace lm::delivery
