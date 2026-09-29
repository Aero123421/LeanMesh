// Delivery <-> journal glue: what a durable send / reception persists, when a receipt may claim it,
// and how the records come back after a restart (docs/12 §3, §4).
//
//   out record  the accepted DURABLE message: written before the first send, retired at the end
//   in record   the destination's copy: written before END_RECEIVED; the application's result
//               replaces the payload; a RECEIVED-only message drops its payload when taken
//
// After a power cut a record is authoritative: an unfinished send resumes under a fresh end
// session with the same MessageId and the ORIGINAL deadline; a reception that the application may
// or may not have handled comes back as a MESSAGE event flagged "recovered" (reason 1) - never
// silently as new, never as exactly-once.
#include <cstring>

#include "core/codec.hpp"
#include "core/delivery/delivery.hpp"
#include "core/engine.hpp"

namespace lm::delivery {
namespace {

constexpr uint8_t k_rec_version = 1;
constexpr uint8_t k_kind_out = 1;
constexpr uint8_t k_kind_in = 2;
constexpr std::size_t k_out_fixed = 4 + 2 + 4 + 8 + 32 + 16 + 32 + 2;
constexpr std::size_t k_in_fixed = 4 + 2 + 4 + 8 + 32 + 16 + 32 + 8 + 4 + 1 + k_result_bytes + 2;

} // namespace

Active *Delivery::find_active_j(uint32_t jslot, uint32_t gen, Handle &h) {
    for (std::size_t i = 0; i < k_actives; ++i) {
        h = actives_.handle_at(i);
        Active *a = actives_.get(h);
        if (a != nullptr && a->durable && a->jslot == jslot && h.generation == gen) {
            return a;
        }
    }
    return nullptr;
}

InEntry *Delivery::find_in_j(uint32_t jslot, uint32_t gen, Handle &h) {
    for (std::size_t i = 0; i < k_in_entries; ++i) {
        h = in_.handle_at(i);
        InEntry *e = in_.get(h);
        if (e != nullptr && e->durable && e->jslot == jslot && h.generation == gen) {
            return e;
        }
    }
    return nullptr;
}

void Delivery::request_retire(uint16_t jslot, MonoTime now) {
    DurableReq r;
    r.op = DurableReq::Op::Retire;
    r.id = k_id_out | jslot;
    if (!durable_.enqueue(r, now)) {
        retry_kick_ = earliest(retry_kick_, now + Duration::from_ms(50)); // queue full: asked again
    }
}

void Delivery::want_out_commit(Handle h, Active &a, MonoTime now) {
    DurableReq r;
    r.op = DurableReq::Op::Put;
    r.id = k_id_out | a.jslot;
    r.gen = h.generation;
    r.version = a.version;
    a.commit_wanted = durable_.enqueue(r, now);
}

void Delivery::want_in_commit(Handle h, InEntry &e, MonoTime now) {
    DurableReq r;
    r.op = DurableReq::Op::Put;
    r.id = k_id_in | e.jslot;
    r.gen = h.generation;
    InLive *lp = live_of(e); // only a record with work to do is written
    if (lp == nullptr) {
        return;
    }
    InLive &l = *lp;
    r.version = l.version;
    l.commit_wanted = durable_.enqueue(r, now);
    if (!l.commit_wanted) {
        retry_kick_ = earliest(retry_kick_, now + Duration::from_ms(50)); // worker queue full: again soon
    }
}

// Builds the record of one slot from its current state (the newest state always wins).
Status Delivery::durable_fill(void *ctx, const DurableReq &req, MutByteView out, std::size_t &len) {
    auto *d = static_cast<Delivery *>(ctx);
    const uint32_t slot = req.id & 0x00FFFFFFU;
    Writer w{out};
    Handle h;
    if ((req.id & 0xFF000000U) == k_id_out) {
        const Active *a = d->find_active_j(slot, req.gen, h);
        if (a == nullptr) {
            return Status::NotFound; // finished meanwhile: its retire follows
        }
        const Op &op = d->ops_[a->op];
        w.u8(k_rec_version);
        w.u8(k_kind_out);
        w.u8(static_cast<uint8_t>(op.delivery | (op.priority << 2U)));
        w.u8(0);
        w.u16be(op.port);
        w.u32be(op.term);
        w.u64be(op.expires);
        w.bytes(op.dest.view());
        w.bytes(ByteView{to_bytes(op.mid)});
        w.bytes(ByteView{op.hash});
        w.u16be(a->len);
        w.bytes(ByteView{d->msgs_.get(a->msg)->data.data(), a->len});
        len = w.size();
        return w.finish();
    }
    InEntry *e = d->find_in_j(slot, req.gen, h);
    const InLive *l = e != nullptr ? d->live_of(*e) : nullptr;
    if (l == nullptr) {
        return Status::NotFound;
    }
    const bool with_payload = e->st == InEntry::St::Committing || e->st == InEntry::St::Held;
    const InEntry::St shown = e->st == InEntry::St::Committing ? InEntry::St::Held : e->st;
    w.u8(k_rec_version);
    w.u8(k_kind_in);
    w.u8(static_cast<uint8_t>(shown));
    w.u8(static_cast<uint8_t>(e->delivery | (l->priority << 2U) | (l->app_pending ? 0x10U : 0U)));
    w.u16be(l->port);
    w.u32be(l->term);
    w.u64be(e->expires);
    w.bytes(e->origin.view());
    w.bytes(ByteView{e->mid});
    w.bytes(ByteView{e->hash});
    w.u64be(l->origin_assignment);
    w.u32be(e->receipt_seq);
    w.u8(e->result_len);
    w.bytes(ByteView{e->result});
    w.u16be(with_payload ? l->len : 0);
    if (with_payload) {
        w.bytes(ByteView{d->msgs_.get(l->msg)->data.data(), l->len});
    }
    len = w.size();
    return w.finish();
}

void Delivery::durable_done(void *ctx, const DurableReq &req, Status st, MonoTime now) {
    auto *d = static_cast<Delivery *>(ctx);
    d->refresh_bound(now);
    if (req.op == DurableReq::Op::Retire) {
        const uint32_t rslot = req.id & 0x00FFFFFFU;
        if ((req.id & 0xFF000000U) == k_id_out && rslot < k_actives) {
            if (st == Status::Ok || st == Status::NotFound) { // NotFound: never written, as good as retired
                d->out_retire_[rslot] = false;
                d->out_j_[rslot] = false;
            } else {
                d->retry_kick_ = earliest(d->retry_kick_, now + Duration::from_s(1)); // storage trouble: try again
            }
        }
        return;
    }
    ++d->stats_.journal_puts;
    const uint32_t slot = req.id & 0x00FFFFFFU;
    Handle h;
    if ((req.id & 0xFF000000U) == k_id_out) {
        Active *a = d->find_active_j(slot, req.gen, h);
        if (a == nullptr) {
            return;
        }
        Op &op = d->ops_[a->op];
        a->commit_wanted = st == Status::Ok && req.version < a->version;
        if (st == Status::Ok) {
            a->persisted_version = req.version > a->persisted_version ? req.version : a->persisted_version;
            d->note_evidence(op, ev::persisted, now); // durable: only now may the first frame go out
            d->drive(h, now);
        } else if (st == Status::Busy) {
            a->next_at = now + Duration::from_ms(50); // worker queue full: ask again
        } else {
            // Never sent from here. NO_CAPACITY is a definite refusal (nothing was written); after a
            // storage fault the record may or may not have landed, so the outcome is unknown, not
            // "rejected" (a restart may still find it).
            d->finalize_active(h, st == Status::NoCapacity ? LM_OUTCOME_REJECTED : LM_OUTCOME_INDETERMINATE,
                               static_cast<uint32_t>(st), now);
        }
        return;
    }
    InEntry *e = d->find_in_j(slot, req.gen, h);
    InLive *l = e != nullptr ? d->live_of(*e) : nullptr;
    if (l == nullptr) {
        return;
    }
    l->commit_wanted = st == Status::Ok && req.version < l->version; // a newer write is queued
    if (st == Status::Busy) {
        d->want_in_commit(h, *e, now);
        return;
    }
    const uint8_t due = l->due_ev;
    const bool due_now = due != 0xFF && (st != Status::Ok || req.version >= l->due_version);
    if (st == Status::Ok) {
        l->persisted_version = req.version > l->persisted_version ? req.version : l->persisted_version;
    }
    if (e->st == InEntry::St::Committing) {
        if (st != Status::Ok) {
            // The message could not be stored as declared: refuse it with evidence, keep nothing.
            const DeviceId origin = e->origin;
            const auto mid = e->mid;
            const Sha256Digest hash = e->hash;
            const uint64_t expires = e->expires;
            const bool ack = e->delivery != LM_BEST_EFFORT;
            (void)d->msgs_.release(l->msg);
            d->in_j_[e->jslot] = false;
            d->drop_live(*e);
            (void)d->in_.release(h);
            ++d->stats_.rx_refused;
            if (ack) {
                d->send_receipt_for(origin, mid, hash, ReceiptEv::Refused, static_cast<uint32_t>(st), 1, expires,
                                    ByteView{}, now);
            }
            return;
        }
        e->st = InEntry::St::Held; // durable: END_RECEIVED and the application event may follow
    }
    if (due_now) {
        l->due_ev = 0xFF;
        if (static_cast<ReceiptEv>(due) == ReceiptEv::EndReceived) {
            if (d->gate_receipt(*e)) {
                e->gated = true; // [S13] the Host's DB commit is the terminal store: HOST_STORE_ACK sends it
            } else if (e->delivery != LM_BEST_EFFORT) {
                d->send_receipt(*e, ReceiptEv::EndReceived, 0, now);
            }
            d->queue_message_event(h, *e, now);
            ++d->stats_.delivered;
        } else {
            // The application's result is durable (or could not be made so): claim it now.
            d->send_receipt(*e, static_cast<ReceiptEv>(due), 0, now);
        }
    }
    d->settle(*e); // the marker / result is durable and nothing else is owed: the live slot goes back
}

// ---- boot and recovery ----
void Delivery::durable_boot_done(void *ctx, Status st, MonoTime now) {
    auto *d = static_cast<Delivery *>(ctx);
    if (st != Status::Ok) {
        d->ready_ = false;
        d->engine_.raise(LM_EVENT_FAULT, static_cast<uint32_t>(st)); // fail closed: never "no history"
        return;
    }
    d->recovering_ = true;
    d->recover_pos_ = 0;
    d->recover_total_ = d->durable_.live_count();
    d->recover_next(now);
}

void Delivery::recover_next(MonoTime now) {
    while (recovering_ && recover_pos_ < recover_total_) {
        const uint32_t id = durable_.live_id(recover_pos_++);
        if (durable_.read(id) == Status::Ok) {
            return; // the completion continues the walk
        }
        recovering_ = false;
        engine_.raise(LM_EVENT_FAULT, static_cast<uint32_t>(Status::Busy));
        return;
    }
    if (!recovering_) {
        return;
    }
    recovering_ = false;
    ready_ = true;
    kick_all_waiting(now);
    flush_events(now);
}

void Delivery::durable_read_done(void *ctx, uint32_t id, Status st, ByteView record, MonoTime now) {
    auto *d = static_cast<Delivery *>(ctx);
    if (st != Status::Ok || record.size() < 4 || record[0] != k_rec_version) {
        d->recovering_ = false;
        d->engine_.raise(LM_EVENT_FAULT, static_cast<uint32_t>(st == Status::Ok ? Status::StorageFailure : st));
        return;
    }
    const uint32_t slot = id & 0x00FFFFFFU;
    if (record[1] == k_kind_out && (id & 0xFF000000U) == k_id_out) {
        d->recovered_out(slot, record, now);
    } else if (record[1] == k_kind_in && (id & 0xFF000000U) == k_id_in) {
        d->recovered_in(slot, record, now);
    } else {
        d->recovering_ = false;
        d->engine_.raise(LM_EVENT_FAULT, static_cast<uint32_t>(Status::StorageFailure));
        return;
    }
    d->recover_next(now);
}

void Delivery::recovered_out(uint32_t slot, ByteView rec, MonoTime now) {
    Reader r{rec};
    (void)r.u8();
    (void)r.u8();
    const uint8_t flags = r.u8();
    (void)r.u8();
    Op *op = alloc_op();
    const Handle mb = msgs_.acquire();
    const Handle ah = actives_.acquire();
    if (op == nullptr || mb.is_none() || ah.is_none() || slot >= k_actives || out_j_[slot] ||
        rec.size() < k_out_fixed) {
        if (!mb.is_none()) {
            (void)msgs_.release(mb);
        }
        if (!ah.is_none()) {
            (void)actives_.release(ah);
        }
        recovering_ = false;
        engine_.raise(LM_EVENT_FAULT, static_cast<uint32_t>(Status::NoCapacity)); // never dropped silently
        return;
    }
    *op = Op{};
    op->used = true;
    op->id = next_op_id_++;
    op->seq = ++op_tick_;
    op->delivery = flags & 3U;
    op->priority = static_cast<uint8_t>((flags >> 2U) & 3U);
    op->storage = LM_DURABLE;
    op->port = r.u16be();
    op->term = r.u32be();
    op->expires = r.u64be();
    r.copy_to(op->dest.bytes);
    std::array<uint8_t, 16> mid{};
    r.copy_to(mid);
    op->mid = to_message_id(mid);
    r.copy_to(op->hash);
    const uint16_t len = r.u16be();
    const ByteView payload = r.bytes(len);
    if (!r.ok() || len > k_msg_bytes) {
        (void)msgs_.release(mb);
        (void)actives_.release(ah);
        *op = Op{};
        recovering_ = false;
        engine_.raise(LM_EVENT_FAULT, static_cast<uint32_t>(Status::StorageFailure));
        return;
    }
    op->evidence = ev::accepted | ev::persisted; // what the journal proves; nothing about sending
    op->accepted_ms = op->last_evidence_ms = now.to_ms();
    op->active = ah;
    Active *a = actives_.get(ah);
    a->op = op_index(*op);
    a->msg = mb;
    a->len = len;
    a->durable = true;
    a->recovered = true;
    a->jslot = static_cast<uint16_t>(slot);
    a->persisted_version = a->version; // already durable
    out_j_[slot] = true;
    if (len > 0) {
        std::memcpy(msgs_.get(mb)->data.data(), payload.data(), len);
    }
    a->st = Active::St::WaitRoute; // needs a route, a fresh end session and, if it has one, a clock bound
}

void Delivery::recovered_in(uint32_t slot, ByteView rec, MonoTime now) {
    Reader r{rec};
    (void)r.u8();
    (void)r.u8();
    const uint8_t state = r.u8();
    const uint8_t flags = r.u8();
    const Handle ih = in_.acquire();
    if (ih.is_none() || slot >= k_in_entries || in_j_[slot] || rec.size() < k_in_fixed || state < 1 ||
        state > 4 || state == static_cast<uint8_t>(InEntry::St::Committing)) {
        if (!ih.is_none()) {
            (void)in_.release(ih);
        }
        recovering_ = false;
        engine_.raise(LM_EVENT_FAULT, static_cast<uint32_t>(Status::NoCapacity));
        return;
    }
    InEntry *e = in_.get(ih);
    e->st = static_cast<InEntry::St>(state);
    e->durable = true;
    e->jslot = static_cast<uint16_t>(slot);
    e->delivery = flags & 3U;
    const auto priority = static_cast<uint8_t>((flags >> 2U) & 3U);
    const bool app_pending = (flags & 0x10U) != 0;
    const uint16_t port = r.u16be();
    const uint32_t term = r.u32be();
    e->expires = r.u64be();
    r.copy_to(e->origin.bytes);
    r.copy_to(e->mid);
    r.copy_to(e->hash);
    const uint64_t assignment = r.u64be();
    e->receipt_seq = r.u32be();
    e->result_len = r.u8();
    r.copy_to(e->result);
    const uint16_t len = r.u16be();
    const ByteView payload = r.bytes(len);
    if (!r.ok() || len > k_msg_bytes || e->result_len > k_result_bytes) {
        (void)in_.release(ih);
        recovering_ = false;
        engine_.raise(LM_EVENT_FAULT, static_cast<uint32_t>(Status::StorageFailure));
        return;
    }
    in_j_[slot] = true;
    e->last_use = ++in_tick_;
    // A held payload or an owed result is work: it gets a live slot. The other states are dedup memory.
    if (e->st == InEntry::St::Held || (e->st == InEntry::St::Delivered && e->delivery == LM_APPLIED)) {
        InLive *l = take_live(*e);
        Handle mb;
        if (l != nullptr && e->st == InEntry::St::Held) {
            mb = msgs_.acquire();
        }
        if (l == nullptr || (e->st == InEntry::St::Held && mb.is_none())) {
            drop_live(*e);
            (void)in_.release(ih);
            in_j_[slot] = false;
            recovering_ = false;
            engine_.raise(LM_EVENT_FAULT, static_cast<uint32_t>(Status::NoCapacity));
            return;
        }
        l->priority = priority;
        l->app_pending = app_pending;
        l->port = port;
        l->term = term;
        l->origin_assignment = assignment;
        l->persisted_version = l->version; // durable already
        l->arrival = ++arrival_;
        if (e->st == InEntry::St::Held) {
            l->msg = mb;
            l->len = len;
            if (len > 0) {
                std::memcpy(msgs_.get(mb)->data.data(), payload.data(), len);
            }
            l->recovered = true; // the application may have handled it before the power cut
            l->event_owed = true; // re-queued by flush_events() once recovery is over
            e->gated = gate_receipt(*e); // [S13] the Host may not have stored it: its ACK releases it
        }
    }
    (void)now;
}

} // namespace lm::delivery
