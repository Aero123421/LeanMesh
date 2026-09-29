#include "serial/root_usb.hpp"

#include <algorithm>
#include <cstring>

#include "core/wire/cbor.hpp"
#include "core/wire/cbor_reader.hpp"

namespace lm::serial {

RootUsb::RootUsb(Engine &engine, ByteStream &out, uint64_t boot_id)
    : engine_(engine), out_(out), link_(UsbRole::Root, *this, this, boot_id, false) {}

void RootUsb::on_started(MonoTime now) {
    now_ = now;
    started_ = true;
    try_open(now); // the identity is still loading at start: on_identity() opens the link
}

void RootUsb::on_stop() {
    started_ = false;
    link_.close();
    link_.unconfigure();
    replies_.clear();
    paired_ok_ = false;
}

void RootUsb::on_identity(MonoTime now) {
    now_ = now;
    try_open(now);
}

void RootUsb::on_job_done(Handle slot, Status job_status, MonoTime now) {
    now_ = now;
    link_.on_job_done(slot, job_status, now);
}

// Needs a Ready identity: key, credential, trust anchor, the verified RootDelegation and the paired
// Host, all read by the identity load job (one set of records, one job).
void RootUsb::try_open(MonoTime now) {
    const member::LocalIdentity &id = engine_.identity();
    if (!started_ || id.state() != member::LocalIdentity::State::Ready || link_.configured()) {
        return;
    }
    const Status ps = id.paired_host_status();
    if (ps != Status::Ok && ps != Status::NotFound) {
        ++stats_.load_failures; // unreadable pairing record is not "unpaired" (docs/12 §2)
        return;
    }
    UsbKit kit;
    kit.key = id.key();
    kit.ccs = id.ccs();
    kit.device_cose = id.device_cose();
    kit.delegation_cose = id.delegation_cose();
    kit.trust = id.trust();
    kit.self = id.self();
    kit.domain = id.delegation().domain;
    kit.paired = ps == Status::Ok ? id.paired_host() : DeviceId{}; // all zero: no DeviceId matches
    paired_ok_ = ps == Status::Ok;
    if (link_.configure(kit) != Status::Ok) {
        ++stats_.load_failures; // no delegation (not part of a domain): nothing to prove to a Host
        return;
    }
    link_.open(now);
    link_.pump_now(now);
}

void RootUsb::on_bytes(ByteView bytes, MonoTime now) {
    now_ = now;
    if (link_.configured()) {
        link_.on_bytes(bytes, now);
    }
}

void RootUsb::on_disconnect(MonoTime now) {
    now_ = now;
    replies_.clear();
    if (link_.configured() && started_) {
        link_.open(now); // closes the old session (results of it are refused from now on)
    }
}

void RootUsb::on_step(MonoTime now) {
    now_ = now;
    // Bounded drain per step (docs/16: owner p99 < 2 ms); the rest is reported by deadline().
    std::array<uint8_t, 256> chunk{};
    for (int i = 0; i < 4; ++i) {
        const std::size_t n = out_.read(MutByteView{chunk});
        if (n == 0) {
            break;
        }
        on_bytes(ByteView{chunk.data(), n}, now);
    }
    if (link_.deadline() <= now) {
        link_.on_timer(now);
    }
    if (bridge_ != nullptr) {
        bridge_->on_step(now);
    }
}

// ---- UsbSink ----
void RootUsb::on_session(bool up, uint32_t gen, UsbDown why) {
    if (!up) {
        replies_.clear(); // replies computed for the old session are never sent on a new one
    }
    if (bridge_ != nullptr) {
        bridge_->on_session(up, gen, why);
    }
}

void RootUsb::on_record(SerialKind kind, uint8_t lane, uint32_t frame_bytes, ByteView payload,
                        uint32_t gen) {
    if (bridge_ != nullptr) {
        bridge_->on_record(kind, lane, frame_bytes, payload, gen);
        return;
    }
    // Default until the bridge exists: a well-formed REQUEST gets UNSUPPORTED. Its credit is
    // returned only once the reply left, so pending replies never exceed the data-lane window.
    Pending p;
    p.lane = lane;
    p.frame_bytes = frame_bytes;
    bool ok = kind == SerialKind::Request;
    if (ok) {
        wire::CborReader r{payload};
        (void)r.array(3, 3);
        const ByteView id = r.bstr(16, 16);
        (void)r.uint_in(1, 15);
        (void)r.skip_item(); // params: shape is the method's business
        ok = r.finish() == Status::Ok;
        if (ok) {
            std::copy(id.begin(), id.end(), p.request_id.begin());
        }
    }
    if (!ok || !replies_.push(p)) {
        ++stats_.replies_dropped;
        link_.release(lane, 1, frame_bytes, now_);
        return;
    }
    flush_replies();
}

void RootUsb::on_tx_ready() {
    if (bridge_ != nullptr) {
        bridge_->on_tx_ready();
        return;
    }
    flush_replies();
}

void RootUsb::flush_replies() {
    while (const Pending *p = replies_.front()) {
        std::array<uint8_t, 48> buf{};
        wire::CborWriter w{MutByteView{buf}};
        w.array(4);
        w.bytes(ByteView{p->request_id});
        w.uint(static_cast<uint32_t>(Status::Unsupported));
        w.null();
        w.null();
        const Status st = link_.send(SerialKind::Response, link_.session_gen(), w.written(), now_);
        if (st == Status::Busy) {
            return; // no credit / TX busy: on_tx_ready() retries
        }
        const Pending done = *p;
        Pending discard;
        (void)replies_.pop(discard);
        if (st == Status::Ok) {
            ++stats_.unsupported_replies;
        } else {
            ++stats_.replies_dropped;
        }
        link_.release(done.lane, 1, done.frame_bytes, now_);
    }
}

} // namespace lm::serial
