#include "hostnative/host_usb.hpp"

#include <sys/random.h>

#include <algorithm>
#include <cstring>

#include "core/member/records.hpp"
#include "core/wire/cbor_reader.hpp"
#include "security/crypto.hpp"
#include "security/identity.hpp"
#include "store/record.hpp"

namespace lm::hostnative {
namespace {

// The library has no Flash: the job body never touches the Store on the Host side.
class NoStore final : public port::Store {
  public:
    Status slot_read(uint16_t, uint8_t, MutByteView, std::size_t &) override { return Status::StorageFailure; }
    Status slot_write(uint16_t, uint8_t, ByteView) override { return Status::StorageFailure; }
    Status slot_erase(uint16_t, uint8_t) override { return Status::StorageFailure; }
    uint32_t journal_segment_bytes() const override { return 0; }
    uint32_t journal_segments() const override { return 0; }
    Status journal_read(uint32_t, MutByteView) override { return Status::StorageFailure; }
    Status journal_write(uint32_t, ByteView) override { return Status::StorageFailure; }
    Status journal_erase(uint32_t) override { return Status::StorageFailure; }
};

} // namespace

HostUsb::HostUsb(uint64_t boot_id)
    : link_(serial::UsbRole::Host, *this, this, boot_id, false) {
    (void)sec::crypto_init();
}

Status HostUsb::load_kit(ByteView kit) {
    LM_TRY(wire::cbor_validate(kit));
    wire::CborReader r{kit};
    (void)r.array(4, 4);
    (void)r.uint_in(1, 1);
    const ByteView identity = r.bstr(1, store::k_max_payload);
    const ByteView trust_rec = r.bstr(1, store::k_max_payload);
    const ByteView domain = r.bstr(16, 16);
    LM_TRY(r.finish());

    ByteView scalar;
    ByteView dcose;
    LM_TRY(member::decode_identity(identity, scalar, dcose));
    member::TrustAnchor trust;
    LM_TRY(member::decode_trust(trust_rec, trust));
    LM_TRY(sec::import_signing_key(scalar, key_));
    member::DeviceCredential dc;
    LM_TRY(member::check_device_credential(trust, dcose, dc));
    sec::PublicKey pub;
    LM_TRY(sec::public_key_of(key_, pub));
    if (pub.x != dc.key.x || pub.y != dc.key.y) {
        return Status::AuthRejected; // the credential names another key than the one stored
    }
    LM_TRY(sec::ccs_encode(ByteView{dc.serial.data(), dc.serial_len}, dc.key, MutByteView{ccs_}, ccs_len_));
    device_cose_.assign(dcose.begin(), dcose.end());
    self_ = dc.device;

    serial::UsbKit k;
    k.key = key_;
    k.ccs = ByteView{ccs_.data(), ccs_len_};
    k.device_cose = ByteView{device_cose_.data(), device_cose_.size()};
    k.trust = trust;
    k.self = dc.device;
    std::copy(domain.begin(), domain.end(), k.domain.bytes.begin());
    return link_.configure(k);
}

void HostUsb::open(MonoTime now) {
    link_.open(now);
    run_jobs(now);
}

void HostUsb::close() {
    link_.close();
    events_.clear();
    tx_.clear();
}

void HostUsb::feed(ByteView bytes, MonoTime now) {
    link_.on_bytes(bytes, now);
    run_jobs(now);
}

void HostUsb::tick(MonoTime now) {
    link_.on_timer(now);
    run_jobs(now);
}

// A job created by the last call runs now, on this thread; its completion may create the next one.
void HostUsb::run_jobs(MonoTime now) {
    static NoStore store;
    for (int i = 0; i < 16 && have_job_; ++i) {
        const PendingJob j = job_;
        have_job_ = false;
        port::JobEnv env{store};
        const Status st = j.fn(env, j.arg);
        link_.on_job_done(j.slot, st, now);
    }
}

Status HostUsb::send(gen::SerialKind kind, uint32_t gen, ByteView payload, MonoTime now) {
    const Status st = link_.send(kind, gen, payload, now);
    run_jobs(now);
    return st;
}

std::size_t HostUsb::take_tx(MutByteView out) {
    const std::size_t n = std::min(out.size(), tx_.size());
    if (n > 0) {
        std::memcpy(out.data(), tx_.data(), n);
        tx_.erase(tx_.begin(), tx_.begin() + static_cast<std::ptrdiff_t>(n));
    }
    return n;
}

bool HostUsb::next_event(HostEvent &out, MonoTime now) {
    if (events_.empty()) {
        return false;
    }
    out = std::move(events_.front());
    events_.pop_front();
    if (out.kind == HostEvent::Kind::Record) {
        link_.release(static_cast<uint8_t>(out.lane), 1, out.frame_bytes, now); // consumed by Python
    }
    return true;
}

void HostUsb::push(HostEvent &&e) {
    if (events_.size() >= k_max_events) {
        ++events_dropped_;
        return;
    }
    events_.push_back(std::move(e));
}

std::size_t HostUsb::write(ByteView out) {
    const std::size_t room = k_max_tx_bytes - std::min(k_max_tx_bytes, tx_.size());
    const std::size_t n = std::min(room, out.size());
    tx_.insert(tx_.end(), out.begin(), out.begin() + static_cast<std::ptrdiff_t>(n));
    return n;
}

void HostUsb::random(MutByteView out) {
    std::size_t done = 0;
    while (done < out.size()) {
        const ssize_t n = ::getrandom(out.data() + done, out.size() - done, 0);
        if (n > 0) {
            done += static_cast<std::size_t>(n);
        }
    }
}

Status HostUsb::submit(Handle slot, JobClass, port::JobFn fn, void *arg) {
    if (have_job_) {
        return Status::Busy;
    }
    job_ = PendingJob{slot, fn, arg};
    have_job_ = true;
    return Status::Ok;
}

void HostUsb::on_session(bool up, uint32_t gen, serial::UsbDown why) {
    HostEvent e;
    e.kind = up ? HostEvent::Kind::SessionUp : HostEvent::Kind::SessionDown;
    e.gen = gen;
    e.aux = static_cast<uint32_t>(why);
    push(std::move(e));
}

void HostUsb::on_record(gen::SerialKind kind, uint8_t lane, uint32_t frame_bytes, ByteView payload,
                        uint32_t gen) {
    HostEvent e;
    e.kind = HostEvent::Kind::Record;
    e.gen = gen;
    e.aux = static_cast<uint32_t>(kind);
    e.lane = lane;
    e.frame_bytes = frame_bytes;
    e.payload.assign(payload.begin(), payload.end());
    push(std::move(e));
}

void HostUsb::on_tx_ready() {
    HostEvent e;
    e.kind = HostEvent::Kind::TxReady;
    push(std::move(e));
}

} // namespace lm::hostnative
