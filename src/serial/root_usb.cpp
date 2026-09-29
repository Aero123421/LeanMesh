#include "serial/root_usb.hpp"

#include <algorithm>
#include <cstring>

#include "core/wire/cbor.hpp"
#include "core/wire/cbor_reader.hpp"
#include "serial/pairing.hpp"

namespace lm::serial {
namespace {

constexpr uint16_t k_load_slot = 1; // Handle index of the load job (index 0 is the link's own)

} // namespace

RootUsb::RootUsb(Engine &engine, ByteStream &out, uint64_t boot_id)
    : engine_(engine), out_(out), link_(UsbRole::Root, *this, this, boot_id, false) {}

// Worker: the two records the USB session needs beyond the identity: the fleet-signed RootDelegation
// that goes to the Host in CredR, and the paired Host. A missing paired-host record is a valid state
// (unpaired root: every Host is refused); a read error is not "unpaired" (docs/12 §2).
Status RootUsb::load_entry(port::JobEnv &env, void *arg) {
    auto *l = static_cast<Load *>(arg);
    l->rec.op = store::RecordJob::Op::Load;
    l->rec.id = store::rec::root_delegation;
    LM_TRY(store::record_load(env.store, l->rec));
    LM_TRY(copy_bytes(MutByteView{l->delegation}, ByteView{l->rec.payload.data(), l->rec.payload_len}));
    l->delegation_len = l->rec.payload_len;
    l->rec.id = k_rec_paired_host;
    const Status ps = store::record_load(env.store, l->rec);
    l->paired_ok = false;
    if (ps == Status::Ok && l->rec.payload_len == l->paired.bytes.size() &&
        l->rec.state == k_paired_state_active) {
        std::copy_n(l->rec.payload.begin(), l->paired.bytes.size(), l->paired.bytes.begin());
        l->paired_ok = true;
    } else if (ps != Status::NotFound && ps != Status::Ok) {
        return ps;
    }
    return Status::Ok;
}

void RootUsb::on_started(MonoTime now) {
    now_ = now;
    started_ = true;
    if (load_in_flight_) {
        load_stale_ = false; // the running job's records are what this start needs too
        return;
    }
    loaded_ = false;
    load_ = Load{};
    const Handle slot{k_load_slot, ++load_gen_ == 0 ? ++load_gen_ : load_gen_};
    if (engine_.submit_job(JobOwner::Serial, slot, JobClass::Flash, &load_entry, &load_) == Status::Ok) {
        load_in_flight_ = true;
    } else {
        ++stats_.load_failures; // worker queue full at start: the USB link stays down, mesh unaffected
    }
}

void RootUsb::on_stop() {
    started_ = false;
    link_.close();
    link_.unconfigure();
    replies_.clear();
    loaded_ = false;
    paired_ok_ = false;
    if (load_in_flight_) {
        load_stale_ = true;
    }
}

void RootUsb::on_identity(MonoTime now) {
    now_ = now;
    try_open(now);
}

void RootUsb::on_job_done(Handle slot, Status job_status, MonoTime now) {
    now_ = now;
    if (slot.index != k_load_slot) {
        link_.on_job_done(slot, job_status, now);
        return;
    }
    load_in_flight_ = false;
    if (!started_ || load_stale_) {
        load_stale_ = false;
        if (started_) {
            on_started(now); // stopped and started again meanwhile: read the records afresh
        }
        return;
    }
    if (job_status != Status::Ok) {
        ++stats_.load_failures;
        return;
    }
    loaded_ = true;
    paired_ok_ = load_.paired_ok;
    try_open(now);
}

// Needs the loaded records and a Ready identity (key, credential, trust anchor, delegation).
void RootUsb::try_open(MonoTime now) {
    const member::LocalIdentity &id = engine_.identity();
    if (!started_ || !loaded_ || id.state() != member::LocalIdentity::State::Ready || link_.configured()) {
        return;
    }
    UsbKit kit;
    kit.key = id.key();
    kit.ccs = id.ccs();
    kit.device_cose = id.device_cose();
    kit.delegation_cose = ByteView{load_.delegation.data(), load_.delegation_len};
    kit.trust = id.trust();
    kit.self = id.self();
    kit.domain = id.delegation().domain;
    kit.paired = load_.paired; // all zero when unpaired: no DeviceId is zero, so nobody matches
    if (link_.configure(kit) == Status::Ok) {
        link_.open(now);
        link_.pump_now(now);
    }
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
