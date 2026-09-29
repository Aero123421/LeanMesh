#include "core/delivery/hop.hpp"

#include <algorithm>

#include "core/engine.hpp"

namespace lm::delivery {
namespace {

constexpr Duration k_pump_retry = Duration::from_ms(20); // radio refused locally: try again shortly
constexpr Duration k_rto_min = Duration::from_ms(static_cast<int64_t>(gen::defaults::delivery::rto_min_ms));
constexpr Duration k_rto_max = Duration::from_ms(static_cast<int64_t>(gen::defaults::delivery::rto_max_ms));
constexpr Duration k_busy_min = Duration::from_ms(20);
constexpr Duration k_busy_max = Duration::from_ms(2000);

Duration clamp(Duration d, Duration lo, Duration hi) { return d < lo ? lo : (d > hi ? hi : d); }

} // namespace

TxFrame *HopTx::reserve(Handle &h) {
    h = frames_.acquire();
    return h.is_none() ? nullptr : frames_.get(h);
}

void HopTx::submit(Handle h, OwnerKind kind, Handle owner, const MacAddr &mac, MonoTime now) {
    TxFrame *f = frames_.get(h);
    if (f == nullptr || f->st != TxFrame::St::Reserved) {
        return;
    }
    f->kind = kind;
    f->owner = owner;
    f->mac = mac;
    f->st = TxFrame::St::Ready;
    f->not_before = now;
    f->order = ++order_;
    pump(now);
}

void HopTx::queue_ack(const MacAddr &mac, const DeviceId &peer, uint64_t counter, wire::HopAckStatus st,
                      uint16_t retry_after_ms, MonoTime now) {
    PendingAck a;
    a.mac = mac;
    a.peer = peer;
    a.counter = counter;
    a.status = st;
    a.retry_after_ms = retry_after_ms;
    if (!acks_.push(a)) {
        ++stats_.acks_dropped; // the sender's RTO repeats the frame; we then answer again
        return;
    }
    pump(now);
}

Duration HopTx::rto_for(uint8_t attempts) const {
    Duration d = rto_;
    for (uint8_t i = 1; i < attempts && d < k_rto_max; ++i) {
        d = Duration{d.us * 2};
    }
    return clamp(d, k_rto_min, k_rto_max);
}

void HopTx::rtt_sample(Duration r) {
    const int64_t s = r.us;
    if (!rtt_valid_) {
        srtt_us_ = s;
        rttvar_us_ = s / 2;
        rtt_valid_ = true;
    } else {
        const int64_t err = srtt_us_ > s ? srtt_us_ - s : s - srtt_us_;
        rttvar_us_ = (3 * rttvar_us_ + err) / 4;
        srtt_us_ = (7 * srtt_us_ + s) / 8;
    }
    rto_ = clamp(Duration{srtt_us_ + 4 * rttvar_us_}, k_rto_min, k_rto_max);
}

void HopTx::finish(Handle h, TxFrame &f, HopEnd end, MonoTime now) {
    FrameDone d;
    d.kind = f.kind;
    d.owner = f.owner;
    d.mac = f.mac;
    d.attempts = f.attempts;
    d.left = f.left;
    d.counter = f.frame.counter;
    frames_.release(h);
    if (hooks_.done != nullptr && d.kind != OwnerKind::None) {
        hooks_.done(hooks_.ctx, d, end, now);
    }
}

void HopTx::apply_ack(Handle h, TxFrame &f, wire::HopAckStatus st, uint16_t retry_after_ms, MonoTime now) {
    switch (st) {
    case wire::HopAckStatus::Accepted:
        if (f.attempts == 1 && f.busy_defers == 0 && now >= f.handoff_at) {
            rtt_sample(now - f.handoff_at); // Karn: only unambiguous samples
        }
        finish(h, f, HopEnd::Accepted, now);
        return;
    case wire::HopAckStatus::Rejected:
        ++stats_.ack_rejected;
        finish(h, f, HopEnd::Rejected, now);
        return;
    case wire::HopAckStatus::Busy:
        // The next hop is out of buffers: its capacity, not RF loss. Defer without using an attempt.
        ++stats_.ack_busy;
        if (f.abandoned || ++f.busy_defers > k_max_busy_defers) {
            finish(h, f, HopEnd::Failed, now);
            return;
        }
        if (f.attempts > 0) {
            --f.attempts; // the peer had no buffer: this hand-off does not count as a link attempt
        }
        f.after_busy = true;
        f.st = TxFrame::St::Ready;
        f.rto_at = MonoTime::never();
        f.not_before = now + clamp(Duration::from_ms(retry_after_ms), k_busy_min, k_busy_max);
        f.order = ++order_;
        return;
    }
}

bool HopTx::on_ack(const MacAddr &src, const wire::HopAck &ack, MonoTime now) {
    for (std::size_t i = 0; i < k_frames; ++i) {
        const Handle h = frames_.handle_at(i);
        TxFrame *f = frames_.get(h);
        if (f == nullptr || f->st == TxFrame::St::Reserved || !f->left ||
            f->frame.counter != ack.acked_link_counter || f->mac != src) {
            continue;
        }
        // Matched by (peer, link counter), whatever the TX callback did yet: an ACK that beats the
        // driver callback (D10) still belongs to this frame and to no later one. The callback,
        // when it comes, finds no frame with its sequence and only frees the radio.
        if (f->st == TxFrame::St::OnAir) {
            ++stats_.early_acks;
        }
        apply_ack(h, *f, ack.status, ack.retry_after_ms, now);
        pump(now);
        return true;
    }
    ++stats_.ack_unmatched;
    return false;
}

void HopTx::on_tx_outcome(const TxOutcome &o, MonoTime now) {
    if ((o.tag & 0xFFFF0000U) == k_tag_frame) {
        const auto seq = static_cast<uint16_t>(o.tag & 0xFFFFU);
        for (std::size_t i = 0; i < k_frames; ++i) {
            const Handle h = frames_.handle_at(i);
            TxFrame *f = frames_.get(h);
            if (f == nullptr || f->st != TxFrame::St::OnAir || f->air_seq != seq) {
                continue;
            }
            if (o.result == port::TxResult::MacFailed) {
                ++stats_.rf_failed; // the only RF-loss sample
            } else if (o.result == port::TxResult::Unknown) {
                ++stats_.tx_unknown;
            }
            f->st = TxFrame::St::WaitAck;
            f->rto_at = now + rto_for(f->attempts);
            break;
        }
    }
    pump(now);
}

void HopTx::on_timer(MonoTime now) {
    for (std::size_t i = 0; i < k_frames; ++i) {
        const Handle h = frames_.handle_at(i);
        TxFrame *f = frames_.get(h);
        if (f == nullptr || f->st != TxFrame::St::WaitAck || now < f->rto_at) {
            continue;
        }
        if (f->attempts >= k_link_attempts || f->abandoned) {
            finish(h, *f, HopEnd::Failed, now);
            continue;
        }
        f->st = TxFrame::St::Ready; // retransmit the same bytes (deadline is re-checked in pump)
        f->rto_at = MonoTime::never();
        f->not_before = now;
        f->order = ++order_;
    }
    if (now >= retry_at_) {
        retry_at_ = MonoTime::never();
    }
    pump(now);
}

MonoTime HopTx::deadline() const {
    MonoTime next = retry_at_;
    for (std::size_t i = 0; i < k_frames; ++i) {
        const TxFrame *f = frames_.get(frames_.handle_at(i));
        if (f == nullptr) {
            continue;
        }
        if (f->st == TxFrame::St::WaitAck) {
            next = earliest(next, f->rto_at);
        } else if (f->st == TxFrame::St::Ready && !(f->not_before <= now_)) {
            next = earliest(next, f->not_before);
        }
    }
    return next;
}

void HopTx::pump(MonoTime now) {
    now_ = now;
    if (in_pump_) {
        pump_again_ = true;
        return;
    }
    in_pump_ = true;
    do {
        pump_again_ = false;
        bool progress = true;
        while (progress) {
            bool sent = false;
            progress = false;
            pump_once(now, sent, progress);
            if (sent) {
                break; // one physical TX in flight: the outcome pumps again
            }
        }
    } while (pump_again_);
    in_pump_ = false;
}

void HopTx::pump_once(MonoTime now, bool &sent, bool &progress) {
    if (engine_.tx().in_flight()) {
        sent = true; // wait for the outcome event, no timer needed
        return;
    }
    if (const PendingAck *front = acks_.front()) {
        PendingAck a = *front;
        wire::HopAck ack;
        ack.acked_link_counter = a.counter;
        ack.status = a.status;
        ack.credit = 0;
        ack.retry_after_ms = a.retry_after_ms;
        std::array<uint8_t, wire::k_hop_ack_body_bytes> plain{};
        std::size_t plen = 0;
        Status st = wire::encode_hop_ack(ack, MutByteView{plain}, plen);
        if (st == Status::Ok) {
            st = link_.seal(a.peer, wire::FrameKind::HopAck, ByteView{plain.data(), plen}, ack_buf_, now);
        }
        if (st == Status::Ok) {
            st = engine_.transmit(a.mac, ack_buf_.view(), k_tag_ack | ack_seq_, now);
        }
        if (st == Status::Busy || st == Status::DriverResultUnknown || is_local_resource_error(st)) {
            ++stats_.local_busy;
            retry_at_ = now + k_pump_retry;
            sent = true;
            return;
        }
        (void)acks_.pop(a); // sent, or unsendable (no session any more): the sender retries the DATA
        ++ack_seq_;
        progress = true;
        if (st == Status::Ok) {
            ++stats_.acks_sent;
            sent = true;
        }
        return;
    }
    Handle best;
    TxFrame *pick = nullptr;
    for (std::size_t i = 0; i < k_frames; ++i) {
        const Handle h = frames_.handle_at(i);
        TxFrame *f = frames_.get(h);
        if (f != nullptr && f->st == TxFrame::St::Ready && f->not_before <= now &&
            (pick == nullptr || static_cast<int32_t>(f->order - pick->order) < 0)) {
            pick = f;
            best = h;
        }
    }
    if (pick == nullptr) {
        return;
    }
    if (pick->abandoned || (hooks_.may_send != nullptr && hooks_.may_send(hooks_.ctx, *pick, now) != Status::Ok)) {
        ++stats_.aborted;
        finish(best, *pick, HopEnd::Aborted, now);
        progress = true;
        return;
    }
    const uint16_t seq = ++air_seq_;
    const Status st = engine_.transmit(pick->mac, pick->frame.view(), k_tag_frame | seq, now);
    if (st == Status::Busy || st == Status::DriverResultUnknown || is_local_resource_error(st)) {
        ++stats_.local_busy; // not an attempt, not a loss (Busy, NO_MEM, isolated radio)
        retry_at_ = now + k_pump_retry;
        sent = true;
        return;
    }
    if (st != Status::Ok) {
        finish(best, *pick, HopEnd::Failed, now);
        progress = true;
        return;
    }
    pick->air_seq = seq;
    pick->st = TxFrame::St::OnAir;
    pick->handoff_at = now;
    ++pick->attempts;
    ++stats_.frames;
    if (pick->after_busy) {
        ++stats_.busy_resends;
    } else if (pick->left) {
        ++stats_.retransmits;
    }
    pick->left = true;
    pick->after_busy = false;
    sent = true;
}

bool HopTx::has_left(OwnerKind kind, Handle owner) const {
    for (std::size_t i = 0; i < k_frames; ++i) {
        const TxFrame *f = frames_.get(frames_.handle_at(i));
        if (f != nullptr && f->kind == kind && f->owner == owner && f->left) {
            return true;
        }
    }
    return false;
}

bool HopTx::withdraw(OwnerKind kind, Handle owner) {
    bool none_left = true;
    for (std::size_t i = 0; i < k_frames; ++i) {
        const Handle h = frames_.handle_at(i);
        TxFrame *f = frames_.get(h);
        if (f == nullptr || f->kind != kind || f->owner != owner) {
            continue;
        }
        if (!f->left) {
            frames_.release(h);
        } else {
            f->abandoned = true;
            none_left = false;
        }
    }
    return none_left;
}

void HopTx::clear() {
    for (std::size_t i = 0; i < k_frames; ++i) {
        (void)frames_.release(frames_.handle_at(i));
    }
    PendingAck a;
    while (acks_.pop(a)) {
    }
    retry_at_ = MonoTime::never();
}

} // namespace lm::delivery
