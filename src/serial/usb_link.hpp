// USB serial session (docs/09 §9, docs/19 §3-§6, protocol/serial.cddl). One state machine for both
// ends of the cable: the root (EDHOC responder, runs on the mesh owner) and the Host's native
// helper (EDHOC initiator, runs on the Host's serial thread). The role only decides who sends
// which handshake object; framing, records, credits, PING and teardown are identical.
//
//   HELLO (unauthenticated, session 0)   [1, device, boot, caps, nonce, active_session]
//   EDHOC objects (unauthenticated)      [kind, body]: CredI, CredR, Msg1..Msg4
//   ACTIVE records (AEAD, purpose 3)     REQUEST / RESPONSE / EVENT / CREDIT / PING
//
// Handshake: the Host sends its DeviceCredential (CredI); the root checks it against the fleet
// trust anchor and the ONE host DeviceId it is paired with (decision D6, sealed record at
// provisioning) and answers with its DeviceCredential + RootDelegation (CredR); the Host checks
// both against its fleet trust anchor and domain. Then EDHOC method 0 / suite 3 (message_4
// mandatory), keys for purpose 3, and a key confirmation: the Host's first protected record is a
// PING, the root's answer is a PING reply. Only then is the session ACTIVE; until that moment an
// existing ACTIVE session keeps working, so a bogus attempt cannot end a live session.
//
// Every public-key step is a slow job (Env::submit): on the root it is an Engine job, so the single
// P-256 slot also covers USB (decision D5); the Host's helper runs the same job body inline.
// Memory: one 8230 B decode buffer (records are decrypted in place there) and one encoded TX
// buffer; nothing else queues (docs/19 §6). Owner thread only (root) / one serial thread (Host).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/ids.hpp"
#include "core/jobs.hpp"
#include "core/member/credentials.hpp"
#include "core/pool.hpp"
#include "core/time.hpp"
#include "core/wire/serial_header.hpp"
#include "security/handshake.hpp"
#include "security/record.hpp"
#include "serial/cobs.hpp"

namespace lm::serial {

using gen::SerialKind;

enum class UsbRole : uint8_t { Root, Host };

// Why a session (or the link) ended. Distinct from RF/mesh reasons (docs/03 §4).
enum class UsbDown : uint8_t {
    Closed,    // local close (engine stop, port lost)
    Replaced,  // a newer authenticated session took over
    Aead,      // AEAD failure or counter regression on the active session (docs/19 §5)
    Silence,   // nothing authenticated received for 15 s
    Credit,    // the peer broke the credit contract
    Peer,      // a violation of the record grammar by an authenticated peer
    Expired,   // key lifetime (1 h) ended without a replacement
};

// ---- credits (docs/19 §5) ----
struct LaneWindow {
    uint32_t frames;
    uint32_t bytes;
};
inline constexpr uint8_t k_lane_data = 0;
inline constexpr uint8_t k_lane_control = 1;
inline constexpr uint8_t k_lane_none = 0xFF;
inline constexpr std::array<LaneWindow, 2> k_windows{{{16, 32768}, {2, 2048}}};
// A RESPONSE whose decoded record fits the control window travels on the reserved control lane;
// everything else that consumes credit (REQUEST, EVENT, larger RESPONSE) shares the data lane. HELLO,
// EDHOC, CREDIT and PING are exempt (else credit could never be returned).
inline constexpr std::size_t k_control_record_max = 2048;

[[nodiscard]] constexpr std::size_t decoded_size(std::size_t payload) {
    return wire::k_serial_header_bytes + payload + sec::k_aead_tag_bytes + wire::k_serial_crc_bytes;
}
[[nodiscard]] constexpr uint8_t lane_of(SerialKind k, std::size_t decoded) {
    if (k == SerialKind::Response && decoded <= k_control_record_max) {
        return k_lane_control;
    }
    return (k == SerialKind::Request || k == SerialKind::Response || k == SerialKind::Event)
               ? k_lane_data
               : k_lane_none;
}

struct UsbTiming {
    Duration ping_period = Duration::from_s(5);
    Duration silence = Duration::from_s(15);
    Duration hello_fast = Duration::from_s(1); // first 10 HELLOs, then doubling up to hello_max
    uint32_t hello_fast_tries = 10;
    Duration hello_max = Duration::from_s(30);
    Duration attempt = Duration::from_s(4);     // whole handshake, both ends
    Duration key_lifetime = Duration::from_s(3600);  // docs/06 §7
    Duration key_rotate = Duration::from_s(3000);    // the Host starts a fresh handshake
    Duration attempt_gate = Duration::from_s(1); // min interval between handshakes started/accepted
    Duration hello_reply_gate = Duration::from_ms(250);
    Duration tx_retry = Duration::from_ms(5);   // only while a partial write is pending
    Duration job_retry = Duration::from_ms(20); // public-key slot busy (link exchange running)
};

// Local identity for the handshake (copied by configure()).
struct UsbKit {
    sec::KeyHandle key;
    ByteView ccs;
    ByteView device_cose;     // own DeviceCredential
    ByteView delegation_cose; // root only: own RootDelegation
    member::TrustAnchor trust;
    DeviceId self;
    DomainId domain; // root: own domain; Host: expected domain (all zero = the one the root proves)
    DeviceId paired; // root only: the one paired Host
};

class UsbEnv {
  public:
    // Non-blocking; returns the bytes accepted (partial writes are retried by the link).
    [[nodiscard]] virtual std::size_t write(ByteView out) = 0;
    virtual void random(MutByteView out) = 0;
    // Queues `fn(arg)` on the slow-job worker; the completion must reach
    // UsbLink::on_job_done(slot, status, now). Busy = worker/slot unavailable (job does not exist).
    [[nodiscard]] virtual Status submit(Handle slot, JobClass cls, port::JobFn fn, void *arg) = 0;
    // The handshake memory of one attempt (decision S13-D10, ARCH-D1: one HandshakeSlot per node). The
    // root lends the node's exchange slot; nullptr = taken, and the caller is then first in line (other
    // exchanges are refused until slot_release()). The Host helper has a slot of its own.
    [[nodiscard]] virtual sec::HandshakeSlot *slot_acquire() = 0;
    // Gives the slot back (and cancels a reservation). Only after its job completed.
    virtual void slot_release() = 0;

  protected:
    ~UsbEnv() = default;
};

// Writes a record's plaintext straight into the link's transmit buffer (no second copy of it).
class PayloadWriter {
  public:
    // Fills `out` (its size is the record limit) and sets `len`. Called at send time, possibly again
    // after a Busy: it may consume state only when it also remembers it (the bridge keeps its events).
    [[nodiscard]] virtual Status write(MutByteView out, std::size_t &len) = 0;

  protected:
    ~PayloadWriter() = default;
};

// PayloadWriter around a callable `Status(MutByteView out, std::size_t &len)`.
template <class F> class WriterFn final : public PayloadWriter {
  public:
    explicit WriterFn(F f) : f_(f) {}
    Status write(MutByteView out, std::size_t &len) override { return f_(out, len); }

  private:
    F f_;
};

class UsbSink {
  public:
    // ACTIVE reached (up) or ended. `gen` identifies the session; results computed for another
    // generation are refused by send(): nothing of an old session is applied to a new one.
    virtual void on_session(bool up, uint32_t gen, UsbDown why) = 0;
    // REQUEST/RESPONSE/EVENT of the active session. `payload` is valid only during the call. The
    // credit (lane, bytes) stays outstanding until UsbLink::release() (auto_release: immediately).
    virtual void on_record(SerialKind kind, uint8_t lane, uint32_t frame_bytes, ByteView payload,
                           uint32_t gen) = 0;
    // The TX buffer became free after a Busy from send().
    virtual void on_tx_ready() {}

  protected:
    ~UsbSink() = default;
};

struct UsbStats {
    uint64_t rx_bytes = 0;
    uint64_t rx_frames = 0;       // decoded frames that passed CRC/header checks
    uint64_t rx_cobs_bad = 0;     // truncated/overflowing frames dropped at a delimiter
    uint64_t rx_overflow = 0;     // more than 8230 decoded bytes
    uint64_t rx_bad_frame = 0;    // CRC / length / magic
    uint64_t rx_unsupported = 0;  // unknown version or kind
    uint64_t rx_unknown_session = 0;
    uint64_t rx_auth_fail = 0;
    uint64_t rx_replay = 0;
    uint64_t rx_malformed = 0;    // authentic but not the expected CBOR
    uint64_t rx_credit_violation = 0;
    uint64_t rx_hello = 0;
    uint64_t rx_edhoc_dropped = 0; // unexpected/duplicate/busy handshake object
    uint64_t tx_frames = 0;
    uint64_t tx_partial = 0;       // writes the port accepted only in part
    uint64_t tx_credit_blocked = 0; // send() refused for lack of credit (local flow control)
    uint64_t hs_started = 0;
    uint64_t hs_failed = 0;
    uint64_t hs_rejected = 0;      // credential chain / pairing refused
    uint64_t sessions = 0;         // ACTIVE transitions
    uint64_t pings_rx = 0;
};

class UsbLink {
  public:
    static constexpr uint32_t k_caps = 1; // bit0: usb-record-v1
    static constexpr std::size_t k_rx_bytes = gen::limits::serial_decoded_bytes;
    static constexpr std::size_t k_plain_bytes = gen::limits::serial_payload_bytes;
    static constexpr std::size_t k_tx_bytes = k_cobs_headroom + gen::limits::serial_decoded_bytes + 2;
    static constexpr std::size_t k_cred_bytes = 960;
    static constexpr std::size_t k_send_max = 6144; // RESPONSE / EVENT plaintext limit (docs/19 §3)

    UsbLink(UsbRole role, UsbEnv &env, UsbSink *sink, uint64_t boot_id, bool auto_release);
    UsbLink(const UsbLink &) = delete;
    UsbLink &operator=(const UsbLink &) = delete;
    ~UsbLink() { close(); }

    // Copies the kit. Busy while a handshake is running.
    [[nodiscard]] Status configure(const UsbKit &kit);
    [[nodiscard]] bool configured() const { return configured_; }
    // Forgets the kit (engine stop: the key handle it named is gone). Call after close().
    void unconfigure() {
        configured_ = false;
        key_ = sec::KeyHandle{};
    }
    // Line is up: (re)starts the HELLO schedule. close(): line down / engine stop; drops sessions,
    // wipes secrets (a job in flight keeps its memory reserved until its completion).
    void open(MonoTime now);
    void close();

    void on_bytes(ByteView bytes, MonoTime now);
    // Sends whatever is pending (HELLO right after open()).
    void pump_now(MonoTime now) { pump(now); }
    void on_timer(MonoTime now);
    void on_job_done(Handle slot, Status job_status, MonoTime now);
    [[nodiscard]] MonoTime deadline() const;
    // Runs the armed job body (worker thread on the root, the caller for the Host helper).
    [[nodiscard]] static Status job_entry(port::JobEnv &env, void *arg);
    [[nodiscard]] bool job_busy() const { return job_ != Job::None; }

    // REQUEST / RESPONSE / EVENT of the session `gen`. Conflict: that session is gone (never
    // re-addressed to the new one). Busy: TX buffer occupied or no credit (local flow control).
    [[nodiscard]] Status send(SerialKind kind, uint32_t gen, ByteView payload, MonoTime now);
    // send() with the plaintext produced by `w` directly in the transmit buffer and sealed in place.
    // Same results as send(); a writer error is returned as it is. `now` is the send time.
    [[nodiscard]] Status send_built(SerialKind kind, uint32_t gen, PayloadWriter &w, MonoTime now);
    // Returns receive credit for records the sink consumed.
    void release(uint8_t lane, uint32_t frames, uint32_t bytes, MonoTime now);

    [[nodiscard]] bool active() const { return act_ >= 0; }
    [[nodiscard]] uint32_t session_gen() const { return gen_; }
    [[nodiscard]] uint32_t session_id() const { return act_ >= 0 ? keys_[act_].sid : 0; }
    [[nodiscard]] const DeviceId &peer_device() const { return active_peer_; }
    [[nodiscard]] const DomainId &peer_domain() const { return active_domain_; }
    [[nodiscard]] const UsbStats &stats() const { return stats_; }
    [[nodiscard]] bool tx_free() const { return tx_len_ == 0; }
    [[nodiscard]] Status last_failure() const { return last_failure_; }
    [[nodiscard]] UsbRole role() const { return role_; }
    // Outstanding (unreleased) receive credit and unused send credit, for tests and diagnostics.
    [[nodiscard]] uint64_t rx_outstanding_frames(uint8_t lane) const;
    [[nodiscard]] uint64_t tx_available_frames(uint8_t lane) const;
    void set_timing(const UsbTiming &t) { timing_ = t; }

  private:
    enum class Phase : uint8_t { Idle, AwaitCred, Verify, Hs, AwaitMsg, AwaitBind, Zombie };
    enum class Job : uint8_t { None, Verify, Hs };
    enum class Obj : uint8_t { CredI = 1, CredR = 2, Msg1 = 3, Msg2 = 4, Msg3 = 5, Msg4 = 6 };

    struct Keys {
        sec::RecordSession rec;
        Sha256Digest ctx_hash{};
        uint32_t sid = 0;
        bool valid = false;
        void wipe() {
            rec.wipe();
            ctx_hash = Sha256Digest{};
            sid = 0;
            valid = false;
        }
    };
    struct TxLane {
        uint64_t grant_frames = 0, grant_bytes = 0, used_frames = 0, used_bytes = 0;
    };
    struct RxLane {
        uint64_t consumed_frames = 0, consumed_bytes = 0;
        uint64_t released_frames = 0, released_bytes = 0;
        uint64_t sent_frames = 0, sent_bytes = 0; // last cumulative grant put on the wire
    };
    struct Peer { // written by the verify job, read by the owner after its completion
        DeviceId device;
        DomainId domain;
        std::array<uint8_t, sec::k_ccs_max_bytes> ccs{};
        std::size_t ccs_len = 0;
        Sha256Digest cred_hash{};
    };

    // framing
    void handle_frame(MonoTime now);
    void handle_hello(ByteView payload, MonoTime now);
    void handle_edhoc(uint32_t sid, ByteView payload, MonoTime now);
    void handle_auth(const wire::SerialHeader &h, ByteView header18, ByteView body, MonoTime now);
    void handle_active(int slot, const wire::SerialHeader &h, ByteView plain, uint32_t frame_bytes,
                       MonoTime now);
    [[nodiscard]] Status emit(SerialKind kind, uint32_t sid, Keys *keys, ByteView payload, MonoTime now);
    void pump(MonoTime now);
    [[nodiscard]] bool flush(MonoTime now);
    [[nodiscard]] bool pump_one(MonoTime now);
    [[nodiscard]] bool credit_due(uint8_t lane) const;
    [[nodiscard]] Status emit_control(SerialKind kind, ByteView payload, MonoTime now);

    // handshake
    void start_attempt(MonoTime now);
    void begin_attempt(uint32_t sid, MonoTime now);
    void abort_attempt(Status why, MonoTime now);
    void stage(Obj kind, ByteView body, bool hold);
    [[nodiscard]] Status start_job(Job job, sec::HsStep step, ByteView input, MonoTime now);
    void after_verify(MonoTime now);
    void retry_job(MonoTime now);
    void release_slot();
    void maybe_start_attempt(MonoTime now);
    void after_hs(MonoTime now);
    void finish_keys(MonoTime now);
    [[nodiscard]] Status make_context();
    [[nodiscard]] Status verify_body();
    [[nodiscard]] Status build_own_cred();
    void promote(MonoTime now);
    void teardown(UsbDown why, MonoTime now);

    // session
    void reset_ledgers();
    [[nodiscard]] bool tx_room(uint8_t lane, std::size_t decoded) const;
    void note_rx(MonoTime now) { last_rx_ = now; }

    UsbRole role_;
    UsbEnv &env_;
    UsbSink *sink_;
    uint64_t boot_id_;
    bool auto_release_;
    UsbTiming timing_{};
    UsbStats stats_{};

    // kit copy
    bool configured_ = false;
    sec::KeyHandle key_;
    std::array<uint8_t, sec::k_ccs_max_bytes> ccs_{};
    std::size_t ccs_len_ = 0;
    std::array<uint8_t, k_cred_bytes> own_cred_{};
    std::size_t own_cred_len_ = 0;
    Sha256Digest own_hash_{};
    member::TrustAnchor trust_;
    DeviceId self_;
    DomainId domain_;
    DeviceId paired_;

    // link state
    bool open_ = false;
    uint32_t hello_tries_ = 0;
    MonoTime hello_at_ = MonoTime::never();
    MonoTime hello_reply_at_ = MonoTime{0};
    bool hello_reply_due_ = false;
    MonoTime retry_at_ = MonoTime::never();
    bool hello_due_ = false;
    bool send_blocked_ = false; // send() said Busy: tell the sink when it may retry

    // handshake state
    Phase phase_ = Phase::Idle;
    Job job_ = Job::None;
    bool job_deferred_ = false; // armed but the worker was busy: retried at job_retry_at_
    bool slot_wait_ = false;    // the credentials verified, the node's handshake slot is still taken
    MonoTime job_retry_at_ = MonoTime::never();
    sec::HsStep hs_step_ = sec::HsStep::None;
    Handle handle_;
    uint32_t handle_gen_ = 0;
    Obj expect_ = Obj::CredI;
    uint32_t cand_sid_ = 0;
    MonoTime attempt_deadline_ = MonoTime::never();
    MonoTime last_attempt_ = MonoTime{0};
    bool attempt_seen_ = false;
    bool attempt_wanted_ = false; // Host: a root HELLO asked for a handshake
    MonoTime next_attempt_at_ = MonoTime{0};
    uint32_t fail_streak_ = 0;
    Status last_failure_ = Status::Ok;
    std::array<uint8_t, k_cred_bytes> cred_rx_{};
    std::size_t cred_rx_len_ = 0;
    Peer peer_;
    sec::HandshakeSlot *hs_ = nullptr; // borrowed from the env for one attempt (UsbEnv::slot_acquire)
    sec::SessionContext ctx_{};
    Sha256Digest ctx_hash_{};
    std::array<uint8_t, 8 + k_cred_bytes> stage_{};
    std::size_t stage_len_ = 0;
    bool stage_hold_ = false;
    bool bind_ping_due_ = false; // Host: first protected record (PING) still to send

    // sessions: keys_[act_] is ACTIVE, keys_[cand_] the candidate under confirmation
    std::array<Keys, 2> keys_{};
    int act_ = -1;
    int cand_ = -1;
    uint32_t gen_ = 0;
    DeviceId active_peer_;
    DomainId active_domain_;
    std::array<TxLane, 2> tx_lane_{};
    std::array<RxLane, 2> rx_lane_{};
    MonoTime last_rx_ = MonoTime{0};
    MonoTime last_tx_ = MonoTime{0};
    MonoTime born_ = MonoTime{0}; // ACTIVE since
    std::array<uint8_t, 16> ping_nonce_{};
    bool ping_out_ = false;    // a PING of ours awaits its reply
    bool ping_due_ = false;
    bool ping_reply_due_ = false;
    std::array<uint8_t, 16> ping_reply_nonce_{};
    bool tx_ready_due_ = false;

    // buffers
    std::array<uint8_t, k_rx_bytes> rx_{}; // decoded frame (a record's plaintext replaces it)
    std::array<uint8_t, k_tx_bytes> tx_{};
    std::size_t tx_off_ = 0;
    std::size_t tx_len_ = 0;
    CobsDecoder dec_{MutByteView{rx_}};
};

} // namespace lm::serial
