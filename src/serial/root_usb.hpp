// Root-side USB serial adapter: one UsbLink (EDHOC responder) wired to the mesh owner through the
// SerialHook (decision D5). The platform creates it for the ROOT role only, gives it the raw byte
// stream of the USB port and feeds it the bytes the port received; everything else (handshake jobs,
// timers, HELLO schedule, credits, PING) is driven by the owner.
//
// Until the bridge slice (S13) attaches a UsbSink, REQUEST records are answered with a RESPONSE
// carrying UNSUPPORTED: the method does not exist yet, and nothing is faked (docs/19 §4).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/engine.hpp"
#include "core/ring.hpp"
#include "core/serial_hook.hpp"
#include "serial/usb_link.hpp"
#include "store/record.hpp"

namespace lm::serial {

// Non-blocking byte sink of the port (pty in meshsim, USB-Serial/JTAG on IDF).
class ByteStream {
  public:
    [[nodiscard]] virtual std::size_t write(ByteView out) = 0;
    // Bytes the port received and not yet handed to the owner (IDF: filled by the port task).
    // The sim does not use it: meshsim calls RootUsb::on_bytes() directly on the owner thread.
    [[nodiscard]] virtual std::size_t read(MutByteView) { return 0; }
    [[nodiscard]] virtual bool input_pending() const { return false; }

  protected:
    ~ByteStream() = default;
};

struct RootUsbStats {
    uint64_t unsupported_replies = 0;
    uint64_t replies_dropped = 0; // queue full or session gone: the Host reconciles by GET_REQUEST
    uint64_t load_failures = 0;
};

class RootUsb final : public SerialHook, private UsbEnv, private UsbSink {
  public:
    static constexpr std::size_t k_pending_replies = 16; // = the data-lane window (usb_link.hpp)

    // `boot_id` identifies this gateway boot in HELLO (the boot incarnation once it is exposed).
    RootUsb(Engine &engine, ByteStream &out, uint64_t boot_id);
    RootUsb(const RootUsb &) = delete;
    RootUsb &operator=(const RootUsb &) = delete;
    ~RootUsb() { link_.close(); } // while the members the sink callbacks touch are still alive

    // Owner thread: bytes received from the port.
    void on_bytes(ByteView bytes, MonoTime now);
    // Port unplugged / reset seen by the platform: the session is gone, HELLO restarts.
    void on_disconnect(MonoTime now);

    // Bridge plug point (S13): sees every record of the ACTIVE session and its lifecycle.
    void set_bridge(UsbSink *bridge) { bridge_ = bridge; }
    [[nodiscard]] UsbLink &link() { return link_; }
    [[nodiscard]] const UsbLink &link() const { return link_; }
    [[nodiscard]] const RootUsbStats &stats() const { return stats_; }
    [[nodiscard]] bool paired() const { return paired_ok_; }

    // SerialHook
    void on_started(MonoTime now) override;
    void on_stop() override;
    void on_identity(MonoTime now) override;
    void on_job_done(Handle slot, Status job_status, MonoTime now) override;
    void on_step(MonoTime now) override;
    [[nodiscard]] MonoTime deadline() const override {
        // Input left over from a bounded drain is known pending work, not a poll.
        return out_.input_pending() ? MonoTime{0} : link_.deadline();
    }

  private:
    // UsbEnv
    std::size_t write(ByteView out) override { return out_.write(out); }
    void random(MutByteView out) override { engine_.random(out); }
    Status submit(Handle slot, JobClass cls, port::JobFn fn, void *arg) override {
        return engine_.submit_job(JobOwner::Serial, slot, cls, fn, arg);
    }
    // UsbSink
    void on_session(bool up, uint32_t gen, UsbDown why) override;
    void on_record(SerialKind kind, uint8_t lane, uint32_t frame_bytes, ByteView payload,
                   uint32_t gen) override;
    void on_tx_ready() override;

    struct Load { // one worker job's memory (zombie rule: untouched until its completion)
        store::RecordJob rec;
        std::array<uint8_t, member::k_max_delegation_cose> delegation{};
        std::size_t delegation_len = 0;
        DeviceId paired;
        bool paired_ok = false;
    };
    struct Pending {
        std::array<uint8_t, 16> request_id{};
        uint8_t lane = 0;
        uint32_t frame_bytes = 0;
    };

    static Status load_entry(port::JobEnv &env, void *arg);
    void try_open(MonoTime now);
    void flush_replies();

    Engine &engine_;
    ByteStream &out_;
    UsbLink link_;
    UsbSink *bridge_ = nullptr;
    RootUsbStats stats_{};
    MonoTime now_{0};

    bool started_ = false;
    bool load_in_flight_ = false;
    bool load_stale_ = false; // stop/start while the job ran: its result is not used
    bool loaded_ = false;
    bool paired_ok_ = false;
    uint32_t load_gen_ = 0;
    Load load_;
    BoundedQueue<Pending, k_pending_replies> replies_;
};

} // namespace lm::serial
