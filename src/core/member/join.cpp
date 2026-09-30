#include "core/member/join.hpp"

#include <algorithm>
#include <cstring>

#include "core/engine.hpp"

namespace lm::member {
namespace {

constexpr Duration k_retry = Duration::from_ms(20); // radio busy: a chunk is waiting (local condition)

} // namespace

void JoinPipe::bind(const MacAddr &mac, const DeviceId &peer, uint32_t domain_hint) {
    reset();
    mac_ = mac;
    peer_ = peer;
    hint_ = domain_hint;
    bound_ = true;
}

MutByteView JoinPipe::stage() {
    if (engine_ == nullptr) {
        return MutByteView{};
    }
    TxFrame *f = engine_->frames().get(stage_h_);
    if (f == nullptr) {
        f = engine_->frames().borrow(stage_h_); // stale after a node stop: a fresh frame
    }
    return f != nullptr ? MutByteView{f->frame.bytes} : MutByteView{};
}

void JoinPipe::send_staged(std::size_t len, MonoTime now) {
    const TxFrame *f = engine_ != nullptr ? engine_->frames().get(stage_h_) : nullptr;
    if (f != nullptr && len <= f->frame.bytes.size()) {
        send(ByteView{f->frame.bytes.data(), len}, now);
    }
}

void JoinPipe::reset() {
    if (engine_ != nullptr) {
        (void)engine_->frames().release(stage_h_); // the staged object is gone with the session
    }
    stage_h_ = Handle{};
    bound_ = false;
    tx_obj_ = ByteView{};
    tx_off_ = 0;
    tx_id_ = 0;
    attempts_ = 0;
    tx_active_ = false;
    tx_inflight_ = false;
    rto_at_ = MonoTime::never();
    retry_at_ = MonoTime::never();
    rx_id_ = 0;
    rx_done_ = false;
    rx_total_ = rx_len_ = 0;
    ack_id_ = 0;
    error_ = Status::Ok;
}

void JoinPipe::send(ByteView object, MonoTime now) {
    tx_obj_ = object;
    tx_id_ = static_cast<uint8_t>(tx_id_ == 255 ? 1 : tx_id_ + 1);
    tx_off_ = 0;
    attempts_ = 1;
    tx_active_ = !object.empty();
    rto_at_ = MonoTime::never();
    retry_at_ = MonoTime::never();
    pump(now);
}

void JoinPipe::pump(MonoTime now) {
    if (!bound_ || tx_inflight_ || (!retry_at_.is_never() && now < retry_at_)) {
        return; // [S11] the inter-fragment gap / busy radio: on_timer pumps again then
    }
    std::array<uint8_t, k_join_chunk_header + k_join_chunk_bytes> buf{};
    std::size_t len = 0;
    JoinChunk c;
    std::size_t n = 0;
    if (ack_id_ != 0) { // acknowledging what we received comes before our own data
        c.object_id = ack_id_;
        c.ack = true;
    } else if (tx_active_ && tx_off_ < tx_obj_.size()) {
        n = std::min<std::size_t>(k_join_chunk_bytes, tx_obj_.size() - tx_off_);
        c.object_id = tx_id_;
        c.total = static_cast<uint16_t>(tx_obj_.size());
        c.offset = static_cast<uint16_t>(tx_off_);
        c.bytes = tx_obj_.subspan(tx_off_, n);
    } else {
        return;
    }
    Status st = encode_chunk(c, MutByteView{buf}, len);
    link::SealedFrame f;
    if (st == Status::Ok) {
        st = engine_->link().seal_join(peer_, hint_, ByteView{buf.data(), len}, f, now);
    }
    if (st == Status::Ok) {
        st = engine_->transmit(mac_, f.view(), tag_base_ | tx_seq_, now);
    }
    if (st == Status::Busy || st == Status::DriverResultUnknown) {
        retry_at_ = now + k_retry; // radio occupied/isolated: not an RF loss, not an attempt
        return;
    }
    if (st != Status::Ok) {
        tx_active_ = false; // session gone, expired or the object is malformed: the owner is told
        ack_id_ = 0;
        error_ = st;
        return;
    }
    ++tx_seq_;
    ++frames_sent_;
    tx_inflight_ = true;
    retry_at_ = MonoTime::never();
    if (c.ack) {
        ack_id_ = 0;
    } else {
        tx_off_ += n;
    }
}

void JoinPipe::on_tx_outcome(const TxOutcome &o, MonoTime now) {
    if (!owns_tag(o.tag)) {
        return;
    }
    tx_inflight_ = false;
    if (tx_active_ && tx_off_ >= tx_obj_.size() && rto_at_.is_never()) {
        rto_at_ = now + engine_->link().policy().rto; // whole object is out: wait for the answer
    }
    const Duration gap = engine_->link().policy().tx_gap;
    if (gap.us > 0 && (tx_active_ || ack_id_ != 0)) {
        retry_at_ = now + gap; // [S11] a relay in the path needs a moment per frame
        return;
    }
    pump(now);
}

Status JoinPipe::on_timer(MonoTime now) {
    if (now >= retry_at_) {
        retry_at_ = MonoTime::never();
        pump(now);
    }
    if (tx_active_ && now >= rto_at_) {
        if (attempts_ >= engine_->link().policy().max_attempts) {
            acked();
            return Status::Expired;
        }
        ++attempts_;
        tx_off_ = 0;
        rto_at_ = MonoTime::never();
        pump(now);
    }
    const Status e = error_;
    error_ = Status::Ok;
    return e;
}

JoinPipe::Feed JoinPipe::feed(ByteView chunk_plain, MutByteView buf, ByteView &object, MonoTime now) {
    JoinChunk c;
    if (decode_chunk(chunk_plain, c) != Status::Ok) {
        return Feed::Ignored;
    }
    if (c.ack) {
        if (tx_active_ && c.object_id == tx_id_) {
            acked(); // the peer has the whole object: no more retransmissions
        }
        return Feed::Acked;
    }
    if (c.object_id == rx_id_ && rx_done_) {
        ack_id_ = c.object_id; // it did not see our ack (or our answer): acknowledge again
        pump(now);
        return Feed::Duplicate;
    }
    if (c.offset == 0 && c.bytes.size() == c.total) {
        rx_id_ = c.object_id;
        rx_done_ = true;
        object = c.bytes;
        ack_id_ = c.object_id;
        pump(now);
        return Feed::Object;
    }
    if (c.offset == 0) { // first chunk, or the sender restarted the same object
        if (buf.size() < c.total) {
            return Feed::NeedBuffer;
        }
        rx_id_ = c.object_id;
        rx_done_ = false;
        rx_total_ = c.total;
        rx_len_ = 0;
    } else if (c.object_id != rx_id_ || rx_done_ || c.total != rx_total_ || c.offset != rx_len_ ||
               buf.size() < rx_total_) {
        return Feed::Ignored; // out of order, repeated or foreign: the sender repeats the object
    }
    std::memcpy(buf.data() + rx_len_, c.bytes.data(), c.bytes.size());
    rx_len_ = static_cast<uint16_t>(rx_len_ + c.bytes.size());
    if (rx_len_ < rx_total_) {
        return Feed::Partial;
    }
    rx_done_ = true;
    object = ByteView{buf.data(), rx_total_};
    ack_id_ = c.object_id;
    pump(now);
    return Feed::Object;
}

} // namespace lm::member
