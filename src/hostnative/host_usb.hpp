// Host side of the USB serial session for the Python service (decision D5/D6): the same UsbLink
// state machine as the root, in the Host role, behind a small C API (lmh_api.cpp). Python keeps
// the port, threads and policy; framing, COBS, EDHOC purpose 3, AEAD records, credits and timers
// run here so there is exactly one implementation of the protocol (docs/06 §2: no Python EDHOC).
//
// Threading: one serial thread calls everything. Slow jobs (P-256) run inline on that thread right
// after the call that created them, so no other thread and no lock exists in this library.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <vector>

#include "core/bytes.hpp"
#include "serial/usb_link.hpp"

namespace lm::hostnative {

struct HostEvent {
    enum class Kind : uint32_t { SessionUp = 1, SessionDown = 2, Record = 3, TxReady = 4 };
    Kind kind = Kind::TxReady;
    uint32_t gen = 0;
    uint32_t aux = 0;         // SessionDown: UsbDown; Record: SerialKind
    uint32_t lane = 0;
    uint32_t frame_bytes = 0;
    std::vector<uint8_t> payload; // Record
};

class HostUsb final : private serial::UsbEnv, private serial::UsbSink {
  public:
    // Bounds: the data-lane window (16) + the control lane (2) records that may be unread, plus a
    // few lifecycle events. Overflow cannot happen while the peer honours credits; if it does the
    // session is dropped (never silently losing a record).
    static constexpr std::size_t k_max_events = 32;
    static constexpr std::size_t k_max_tx_bytes = 128 * 1024;

    explicit HostUsb(uint64_t boot_id);
    ~HostUsb() { link_.close(); } // sink callbacks touch the queues below: close while they exist
    HostUsb(const HostUsb &) = delete;
    HostUsb &operator=(const HostUsb &) = delete;

    // Kit file (CBOR [1, identity record payload, fleet_trust record payload, domain16]); see
    // tools/meshsim `serial-pair`. Ok = configured.
    [[nodiscard]] Status load_kit(ByteView kit);

    void open(MonoTime now);
    void close();
    void feed(ByteView bytes, MonoTime now);
    void tick(MonoTime now);
    [[nodiscard]] MonoTime deadline() const { return link_.deadline(); }
    // Encoded bytes queued for the port (pull; nothing is written from inside the library).
    // The port write may be partial (FIX2-D14): peek copies, consume drops exactly what the OS accepted.
    // take_tx = peek + consume (tests that have no port).
    [[nodiscard]] std::size_t peek_tx(MutByteView out) const;
    void consume_tx(std::size_t n);
    [[nodiscard]] std::size_t take_tx(MutByteView out) {
        const std::size_t n = peek_tx(out);
        consume_tx(n);
        return n;
    }
    // peek copies the oldest event without consuming it; next_event consumes it (and, for a
    // record, returns its credit).
    [[nodiscard]] bool peek_event(HostEvent &out) const {
        if (events_.empty()) {
            return false;
        }
        out = events_.front();
        return true;
    }
    [[nodiscard]] bool next_event(HostEvent &out, MonoTime now);
    [[nodiscard]] Status send(gen::SerialKind kind, uint32_t gen, ByteView payload, MonoTime now);
    [[nodiscard]] serial::UsbLink &link() { return link_; }
    [[nodiscard]] uint64_t events_dropped() const { return events_dropped_; }
    [[nodiscard]] const DeviceId &self() const { return self_; }

  private:
    std::size_t write(ByteView out) override;
    void random(MutByteView out) override;
    Status submit(Handle slot, JobClass cls, port::JobFn fn, void *arg) override;
    sec::HandshakeSlot *slot_acquire() override { return &hs_; }
    void slot_release() override {}
    void on_session(bool up, uint32_t gen, serial::UsbDown why) override;
    void on_record(gen::SerialKind kind, uint8_t lane, uint32_t frame_bytes, ByteView payload,
                   uint32_t gen) override;
    void on_tx_ready() override;
    void run_jobs(MonoTime now);
    void push(HostEvent &&e);

    struct PendingJob {
        Handle slot;
        port::JobFn fn = nullptr;
        void *arg = nullptr;
    };

    serial::UsbLink link_;
    sec::HandshakeSlot hs_; // no mesh exchange on the Host: its own slot
    std::array<uint8_t, 32> scalar_{};
    sec::KeyHandle key_;
    std::array<uint8_t, sec::k_ccs_max_bytes> ccs_{};
    std::size_t ccs_len_ = 0;
    std::vector<uint8_t> device_cose_;
    DeviceId self_;
    std::vector<uint8_t> tx_;
    std::deque<HostEvent> events_;
    PendingJob job_;
    bool have_job_ = false;
    uint64_t events_dropped_ = 0;
};

} // namespace lm::hostnative
