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

HopTx::HopTx(Engine &engine, link::LinkLayer &link)
    : engine_(engine), link_(link), pool_(engine.frames()), frames_(engine.frames().slots()) {}

TxFrame *HopTx::reserve(Handle &h, sched::Class cls, const MacAddr &mac) {
    // [S16] a sleeping child's mailbox has its own caps (per child, total); CONTROL always finds room.
    TxFrame *f = cls != sched::Class::Control && !engine_.power().mailbox_admit(mac, engine_.step_time())
                     ? nullptr
                     : pool_.reserve(h, cls, mac);
    if (f == nullptr) {
        engine_.sched().note_refused(cls); // class limit, per-peer cap or pool full: local, not RF
    }
    return f;
}

void HopTx::submit(Handle h, OwnerKind kind, Handle owner, const MacAddr &mac, MonoTime now) {
    TxFrame *f = frames_.get(h);
    if (f == nullptr || f->st != TxFrame::St::Reserved) {
        return;
    }
    f->kind = kind;
    f->set_owner(owner);
    f->mac = mac;
    f->st = TxFrame::St::Ready;
    f->at = now;
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
    d.owner = f.owner();
    d.mac = f.mac;
    d.attempts = f.attempts;
    d.left = f.has(TxFrame::Left);
    d.counter = f.frame.counter();
    frames_.release(h);
    if (hooks_.done != nullptr && d.kind != OwnerKind::None) {
        hooks_.done(hooks_.ctx, d, end, now);
    }
}

void HopTx::apply_ack(Handle h, TxFrame &f, wire::HopAckStatus st, uint16_t retry_after_ms, MonoTime now) {
    switch (st) {
    case wire::HopAckStatus::Accepted:
        if (f.attempts == 1 && f.busy_defers == 0) {
            // Karn: only unambiguous samples. The hand-off time is kept as 16 bits of milliseconds.
            const auto ms = static_cast<uint16_t>(static_cast<uint16_t>(now.to_ms()) - f.handoff_ms);
            rtt_sample(Duration::from_ms(ms));
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
        if (f.has(TxFrame::Abandoned) || ++f.busy_defers > k_max_busy_defers) {
            finish(h, f, HopEnd::Failed, now);
            return;
        }
        if (f.attempts > 0) {
            --f.attempts; // the peer had no buffer: this hand-off does not count as a link attempt
        }
        f.set(TxFrame::AfterBusy);
        f.st = TxFrame::St::Ready;
        f.at = now + clamp(Duration::from_ms(retry_after_ms), k_busy_min, k_busy_max);
        f.order = ++order_;
        return;
    }
}

bool HopTx::on_ack(const MacAddr &src, const wire::HopAck &ack, MonoTime now) {
    for (std::size_t i = 0; i < k_frames; ++i) {
        const Handle h = frames_.handle_at(i);
        TxFrame *f = frames_.get(h);
        if (f == nullptr || f->st == TxFrame::St::Reserved || !f->has(TxFrame::Left) ||
            f->frame.counter() != ack.acked_link_counter || f->mac != src) {
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
            f->at = now + rto_for(f->attempts);
            break;
        }
    }
    pump(now);
}

void HopTx::on_timer(MonoTime now) {
    for (std::size_t i = 0; i < k_frames; ++i) {
        const Handle h = frames_.handle_at(i);
        TxFrame *f = frames_.get(h);
        if (f == nullptr || f->st != TxFrame::St::WaitAck || now < f->at) {
            continue;
        }
        if (f->attempts > 0 && engine_.power().child_asleep(f->mac, now)) {
            --f->attempts; // [S16] the child's window closed while the frame waited: sleep, not loss
        }
        if (f->attempts >= k_link_attempts || f->has(TxFrame::Abandoned)) {
            finish(h, *f, HopEnd::Failed, now);
            continue;
        }
        f->st = TxFrame::St::Ready; // retransmit the same bytes (deadline is re-checked in pump)
        f->at = now;
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
        if (f->st == TxFrame::St::WaitAck || (f->st == TxFrame::St::Ready && !(f->at <= now_))) {
            next = earliest(next, f->at);
        }
    }
    return next;
}

void HopTx::pump(MonoTime now) {
    now_ = now;
    if (engine_.radio_state() == RadioState::Asleep) {
        return; // [S16] the driver is off on purpose: frames wait, nothing polls
    }
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

// True: this step is spent on the ACK (sent, or a local shortage armed a retry). False: the airtime bucket refuses it
// for now (retry_at_ is armed); the caller may still serve a queued frame.
bool HopTx::send_ack(MonoTime now, bool &sent, bool &progress) {
    if (const PendingAck *front = acks_.front()) {
        PendingAck a = *front;
        constexpr std::size_t k_ack_frame = wire::k_link_header_bytes + wire::k_hop_ack_body_bytes + wire::k_tag_bytes;
        if (!engine_.sched().admit_direct(k_ack_frame, now)) {
            ++stats_.local_busy; // the bucket, not RF: the ACK waits for the refill, the sender's RTO repeats meanwhile
            retry_at_ = earliest(retry_at_, engine_.sched().direct_wake(k_ack_frame, now));
            return false;
        }
        wire::HopAck ack;
        ack.acked_link_counter = a.counter;
        ack.status = a.status;
        ack.credit = 0;
        ack.retry_after_ms = a.retry_after_ms;
        std::array<uint8_t, wire::k_hop_ack_body_bytes> plain{};
        std::size_t plen = 0;
        Lease buf{pool_}; // the seal buffer is a pool frame borrowed for this one ACK (P9)
        Status st = buf.ok() ? wire::encode_hop_ack(ack, MutByteView{plain}, plen) : Status::NoCapacity;
        if (st == Status::Ok) {
            st = link_.seal(a.peer, wire::FrameKind::HopAck, ByteView{plain.data(), plen}, buf.buf(), now);
        }
        if (st == Status::Ok) { // bounded by the bucket floor (FIX4-D3) but not queued behind data: the ACK frees the sender's buffer
            st = engine_.transmit(a.mac, buf.buf().view(), k_tag_ack | ack_seq_, now, sched::Class::Control, false);
        }
        if (st == Status::Busy || st == Status::DriverResultUnknown || is_local_resource_error(st)) {
            ++stats_.local_busy;
            retry_at_ = now + k_pump_retry;
            sent = true;
            return true;
        }
        (void)acks_.pop(a); // sent, or unsendable (no session any more): the sender retries the DATA
        ++ack_seq_;
        progress = true;
        if (st == Status::Ok) {
            ++stats_.acks_sent;
            ++ack_run_;
            sent = true;
        }
        return true;
    }
    return true;
}

void HopTx::pump_once(MonoTime now, bool &sent, bool &progress) {
    if (engine_.tx().in_flight()) {
        sent = true; // wait for the outcome event, no timer needed
        return;
    }
    // The oldest ready frame of every class is what the scheduler chooses between. A frame the owner
    // withdrew ends at once: it needs no airtime.
    std::array<Handle, sched::k_classes> head{};
    std::array<uint16_t, sched::k_classes> head_bytes{};
    for (std::size_t i = 0; i < k_frames; ++i) {
        const Handle h = frames_.handle_at(i);
        TxFrame *f = frames_.get(h);
        if (f == nullptr || f->st != TxFrame::St::Ready || !(f->at <= now)) {
            continue;
        }
        if (f->has(TxFrame::Abandoned)) {
            ++stats_.aborted;
            finish(h, *f, HopEnd::Aborted, now);
            progress = true;
            return;
        }
        // [S16] A sleepy child's frames wait for its poll (window, credit). A frame sealed under a link session that
        // was replaced while it waited cannot be opened any more: it ends, and its origin sends the original again.
        if (!engine_.power().deliverable(f->mac, now, !f->has(TxFrame::Left))) {
            continue;
        }
        if (!f->has(TxFrame::Left) && engine_.power().child_known(f->mac, now)) {
            const link::Neighbor *nb = link_.neighbors().find_mac(f->mac);
            Reader sid{ByteView{f->frame.bytes.data() + wire::layout::link::link_sid_offset, 4}};
            if (nb == nullptr || !nb->cur.active || nb->cur.tx_sid != sid.u32be()) {
                ++stats_.aborted;
                finish(h, *f, HopEnd::Aborted, now);
                progress = true;
                return;
            }
        }
        const auto c = static_cast<std::size_t>(f->cls);
        const TxFrame *cur = frames_.get(head[c]);
        if (cur == nullptr || static_cast<int16_t>(f->order - cur->order) < 0) {
            head[c] = h;
            head_bytes[c] = f->frame.len;
        }
    }
    sched::Class cls = sched::Class::Control;
    MonoTime wake;
    bool ready = false;
    for (uint16_t b : head_bytes) {
        ready = ready || b != 0;
    }
    // FIX4-D3: HOP_ACKs go first (they free the sender's buffer), but at most k_ack_run_max in a row while a queued frame
    // that may go waits, and only while the bucket admits them (urgent debt at most). A queued frame that cannot go
    // (hold, tokens) does not keep an ACK back.
    const bool ack_due = acks_.front() != nullptr;
    if (!ready) {
        ack_run_ = 0; // nothing queued waits behind the ACKs
    }
    if (ack_due && ack_run_ < k_ack_run_max && send_ack(now, sent, progress)) {
        return;
    }
    if (!ready) {
        return;
    }
    if (!engine_.sched().pick(head_bytes, now, cls, wake)) {
        // The cap is reached and the queued frames wait for tokens: they are served next, not another ACK. (A hold
        // is not their fault: the ACK goes.)
        if (ack_due && ack_run_ >= k_ack_run_max && engine_.sched().held(now) && send_ack(now, sent, progress)) {
            return;
        }
        retry_at_ = earliest(retry_at_, wake); // airtime tokens: the frame waits, nothing is lost
        sent = true;
        return;
    }
    const Handle best = head[static_cast<std::size_t>(cls)];
    TxFrame *pick = frames_.get(best);
    if (pick == nullptr) {
        return;
    }
    if (hooks_.may_send != nullptr && hooks_.may_send(hooks_.ctx, *pick, now) != Status::Ok) {
        ++stats_.aborted;
        finish(best, *pick, HopEnd::Aborted, now);
        progress = true;
        return;
    }
    const uint16_t seq = ++air_seq_;
    const Status st = engine_.transmit(pick->mac, pick->frame.view(), k_tag_frame | seq, now, pick->cls, true);
    if (st == Status::Busy || st == Status::Conflict || st == Status::DriverResultUnknown || is_local_resource_error(st)) {
        ++stats_.local_busy; // not an attempt, not a loss (Busy, NO_MEM, isolated radio, radio not started: FIX9-D7)
        retry_at_ = now + k_pump_retry;
        sent = true;
        return;
    }
    if (st != Status::Ok) {
        finish(best, *pick, HopEnd::Failed, now);
        progress = true;
        return;
    }
    ack_run_ = 0;
    pick->air_seq = seq;
    pick->st = TxFrame::St::OnAir;
    pick->at = MonoTime::never();
    pick->handoff_ms = static_cast<uint16_t>(now.to_ms());
    ++pick->attempts;
    ++stats_.frames;
    if (pick->has(TxFrame::AfterBusy)) {
        ++stats_.busy_resends;
    } else if (pick->has(TxFrame::Left)) {
        ++stats_.retransmits;
    }
    if (!pick->has(TxFrame::Left)) {
        engine_.power().note_handoff(pick->mac); // [S16] one unit of the child's credit per frame, not per retry
    }
    if (pick->kind == OwnerKind::Out) {
        engine_.power().note_uplink(now); // [S16] its answer may come within the receive window after it
    }
    pick->set(TxFrame::Left);
    pick->set(TxFrame::AfterBusy, false);
    sent = true;
}

bool HopTx::has_left(OwnerKind kind, Handle owner) const {
    for (std::size_t i = 0; i < k_frames; ++i) {
        const TxFrame *f = frames_.get(frames_.handle_at(i));
        if (f != nullptr && f->kind == kind && f->owner() == owner && f->has(TxFrame::Left)) {
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
        if (f == nullptr || f->kind != kind || f->owner() != owner) {
            continue;
        }
        if (!f->has(TxFrame::Left)) {
            frames_.release(h);
        } else {
            f->set(TxFrame::Abandoned);
            none_left = false;
        }
    }
    return none_left;
}

std::size_t HopTx::queued_for(const MacAddr &mac) const {
    std::size_t n = 0;
    for (std::size_t i = 0; i < k_frames; ++i) {
        const TxFrame *f = frames_.get(frames_.handle_at(i));
        n += (f != nullptr && f->kind != OwnerKind::Borrowed && f->mac == mac) ? 1U : 0U;
    }
    return n;
}

std::size_t HopTx::expire_parked(const MacAddr &mac, MonoTime now) {
    std::size_t n = 0;
    for (std::size_t i = 0; i < k_frames; ++i) {
        const Handle h = frames_.handle_at(i);
        TxFrame *f = frames_.get(h);
        const bool ours = f != nullptr && f->mac == mac && f->st == TxFrame::St::Ready && !f->has(TxFrame::Left) &&
                          (f->kind == OwnerKind::Forward || f->kind == OwnerKind::Receipt || f->kind == OwnerKind::Mesh);
        if (ours) {
            ++stats_.aborted;
            finish(h, *f, HopEnd::Aborted, now);
            ++n;
        }
    }
    return n;
}

void HopTx::clear() {
    for (std::size_t i = 0; i < k_frames; ++i) {
        const Handle h = frames_.handle_at(i);
        const TxFrame *f = frames_.get(h);
        if (f != nullptr && f->kind != OwnerKind::Borrowed) {
            (void)frames_.release(h); // borrowed buffers belong to their borrowers (Engine::stop_radio sweeps)
        }
    }
    PendingAck a;
    while (acks_.pop(a)) {
    }
    retry_at_ = MonoTime::never();
}

} // namespace lm::delivery
