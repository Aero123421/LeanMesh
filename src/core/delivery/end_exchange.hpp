// End-session establishment (EDHOC purpose 2, docs/06 §4-§9) between two members that are not
// neighbours. Same message flow as the link exchange (credential bundle swap, EDHOC m1..m4,
// SESSION_BIND/ACK) but every object travels as routed end-to-end frames over the source route:
//
//   handshake carrier  end record with end_sid = k_handshake_sid, kind CONTROL, port 0, plaintext
//                      [object kind u8, total u16, offset u16, body], tag field zero (S9-D2). It is
//                      only authenticated hop by hop; EDHOC and the credential chain authenticate the
//                      peers, and nothing here reaches the application.
//   SESSION_BIND/ACK   the record sealed under the new keys (header SID = the sender's own reserved
//                      SID, S5-D3), carried as carrier objects 7/8 so that it can be fragmented: it is
//                      117 B, more than a 40-hop frame carries (56 B).
//
// One exchange at a time (single P-256 slot). The initiator repeats an object every RTO up to 3
// times within 30 s; the responder only answers repeats from its staged frames. Public-key work
// runs as worker jobs (zombie rule: memory stays reserved until the completion is polled).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/delivery/end_session.hpp"
#include "core/delivery/hop.hpp"
#include "core/delivery/route_spec.hpp"
#include "core/jobs.hpp"
#include "core/member/records.hpp"
#include "core/wire/transfer.hpp"
#include "security/handshake.hpp"

namespace lm {
class Engine;
}

namespace lm::delivery {

struct EndPolicy {
    Duration key_lifetime = Duration::from_s(3600);    // docs/06 §7 (1 h or 2^24 records)
    Duration handshake_gate = Duration::from_s(30);    // docs/06 §8: one full handshake / peer
    Duration exchange_deadline = Duration::from_s(30); // registry session_binding.timeout_ms
    Duration linger = Duration::from_s(10);            // responder keeps its ACK for bind repeats
    uint8_t max_attempts = 3;                          // registry session_binding.max_attempts
};

struct EndStats {
    uint64_t started = 0;
    uint64_t completed = 0;
    uint64_t failed = 0;
    uint64_t rate_limited = 0;
    uint64_t busy_drop = 0;  // a CredI arrived while the single slot was in use
    uint64_t retransmits = 0;
    uint64_t cred_rejected = 0;
    uint64_t bind_bad = 0;
    uint64_t send_deferred = 0; // TX pool full / radio busy at a fragment: retried, never lost
};

// What the exchange needs from the delivery module.
struct EndTransport {
    void *ctx = nullptr;
    // Buffer for the record being built (owned by the delivery module, valid for the exchange's life).
    MutByteView record_buf;
    // Sends one built end record along `route`. NoCapacity/Busy: retry shortly.
    Status (*send)(void *ctx, const PathSpec &route, ByteView record, Handle owner, MonoTime now) = nullptr;
    // The exchange with `peer` ended: Ok = a session was installed.
    void (*done)(void *ctx, const DeviceId &peer, Status st, MonoTime now) = nullptr;
};

// Scratch/handshake memory. Kept in one struct so it can be shared with the link exchange later.
struct EndHsMem {
    sec::HandshakeSlot hs;
    std::array<uint8_t, member::k_max_bundle> rx{};
    std::array<uint8_t, sec::k_edhoc_max_message> stage{};
};

enum class EndPhase : uint8_t { Idle, SendCred, Verify, Hs, AwaitMsg, AwaitBind, Linger, Zombie };

class EndExchange {
  public:
    EndExchange(Engine &engine, member::LocalIdentity &identity, EndSessions &sessions,
                const EndPolicy &policy, const RootTimeBound &root_time)
        : engine_(engine), identity_(identity), sessions_(sessions), policy_(policy),
          root_time_(root_time) {}
    EndExchange(const EndExchange &) = delete;
    EndExchange &operator=(const EndExchange &) = delete;

    void set_transport(const EndTransport &t) { tr_ = t; }

    // Initiator toward `peer` over `route`. AuthPending (not a member), Busy (slot in use),
    // RateLimited (< gate since the last full handshake with this peer).
    [[nodiscard]] Status start_initiator(const DeviceId &peer, const PathSpec &route, MonoTime now);
    // Owner: a handshake carrier record arrived (end_sid == k_handshake_sid); `reply` is the reverse
    // of the route it came over.
    void on_carrier(const PathSpec &reply, const wire::EndHeader &h, ByteView plain, OpenedEnd &scratch,
                    MonoTime now);
    void on_job_done(Handle slot, Status s, MonoTime now);
    void on_frame_done(Handle owner, HopEnd end, MonoTime now);
    void on_timer(MonoTime now);
    [[nodiscard]] MonoTime deadline() const;
    void stop();

    // Frames of the exchange may go out only while it is alive (checked by the hop layer).
    [[nodiscard]] bool alive(Handle owner) const { return owner == owner_ && phase_ != EndPhase::Idle && phase_ != EndPhase::Zombie; }
    [[nodiscard]] bool busy() const { return phase_ != EndPhase::Idle && phase_ != EndPhase::Linger; }
    [[nodiscard]] bool job_pending() const { return job_ != Job::None; }
    [[nodiscard]] EndPhase phase() const { return phase_; }
    [[nodiscard]] bool initiator() const { return initiator_; }
    [[nodiscard]] const DeviceId &peer() const { return peer_; }
    [[nodiscard]] Status last_failure() const { return last_failure_; }
    [[nodiscard]] Handle owner_handle() const { return owner_; }
    [[nodiscard]] const EndStats &stats() const { return stats_; }

  private:
    enum class Job : uint8_t { None, Verify, Hs };
    enum class Obj : uint8_t { CredI = 1, CredR = 2, Msg1 = 3, Msg2 = 4, Msg3 = 5, Msg4 = 6, Bind = 7, BindAck = 8 };
    static constexpr std::size_t k_bind_record_max = 192; // sealed SESSION_BIND[/ACK] record (117 B in practice)

    struct PeerState {
        member::DeviceCredential dc;
        member::MemberCredential mc;
        std::array<uint8_t, sec::k_ccs_max_bytes> ccs{};
        std::size_t ccs_len = 0;
        Sha256Digest mc_hash{};
    };
    struct VerifyInput {
        member::TrustAnchor trust;
        member::RootDelegation delegation;
    };
    struct Gate {
        DeviceId peer;
        MonoTime at;
        bool used = false;
    };

    void abort(Status why);
    void finish_idle();
    [[nodiscard]] Status begin_common(const DeviceId *peer, MonoTime now);
    static Status job_entry(port::JobEnv &env, void *arg);
    static Status verify_body(EndExchange &x);
    [[nodiscard]] Status run_verify();
    [[nodiscard]] Status run_hs(sec::HsStep step, ByteView input = ByteView{});
    void after_verify(MonoTime now);
    void after_hs(MonoTime now);
    void finish_keys(MonoTime now);
    void on_obj(const PathSpec &reply, Obj kind, uint16_t total, uint16_t offset, ByteView body,
                MonoTime now);
    void obj_complete(const PathSpec &reply, Obj kind, OpenedEnd &scratch, MonoTime now);
    void handle_bind(const PathSpec &reply, ByteView record, OpenedEnd &scratch, MonoTime now);
    [[nodiscard]] Status make_context(sec::SessionContext &ctx) const;
    [[nodiscard]] Status install_session(MonoTime now);

    // transmit side: one object = fragments sent one after the other, each after the previous
    // HOP_ACCEPTED (window 1, bounded TX pool use)
    void send_object(Obj kind, ByteView data, bool retransmit);
    void pump(MonoTime now);
    [[nodiscard]] Status send_bind(bool ack, MonoTime now);
    void arm_rto(MonoTime now);
    [[nodiscard]] Duration rto() const;
    [[nodiscard]] bool gate_allow(const DeviceId &p, MonoTime now) const;
    void gate_touch(const DeviceId &p, MonoTime now);
    void gate_forget(const DeviceId &p);
    [[nodiscard]] Status alloc_sid(uint32_t &sid);
    [[nodiscard]] const PathSpec &route() const { return route_; }

    Engine &engine_;
    member::LocalIdentity &identity_;
    EndSessions &sessions_;
    const EndPolicy &policy_;
    const RootTimeBound &root_time_;
    EndTransport tr_;
    EndStats stats_;
    std::array<Gate, 4> gate_{};

    EndPhase phase_ = EndPhase::Idle;
    bool initiator_ = false;
    DeviceId peer_;      // known from the start (initiator) or after credentials (responder)
    bool peer_known_ = false;
    PathSpec route_;     // initiator: resolved route; responder: reverse of the latest carrier
    std::array<uint8_t, 16> xid_{};
    std::array<uint8_t, 16> rx_xid_{};
    MonoTime now_;
    MonoTime deadline_ = MonoTime::never();
    MonoTime hard_deadline_ = MonoTime::never();
    MonoTime rto_at_ = MonoTime::never();
    MonoTime retry_at_ = MonoTime::never();
    uint8_t attempts_ = 0;
    Obj expect_ = Obj::CredR;
    Status last_failure_ = Status::Ok;

    Job job_ = Job::None;
    sec::HsStep hs_step_ = sec::HsStep::None;
    Handle owner_;       // identity of this exchange for jobs and frames
    uint32_t owner_gen_ = 0;

    EndHsMem mem_;
    std::size_t rx_len_ = 0;
    std::size_t rx_total_ = 0;
    Obj rx_kind_ = Obj::CredR;
    PeerState peer_state_;
    VerifyInput vin_;

    // outgoing object
    bool tx_active_ = false;
    Obj tx_kind_ = Obj::CredI;
    const uint8_t *tx_data_ = nullptr;
    std::size_t tx_len_ = 0;
    std::size_t tx_off_ = 0;
    bool tx_inflight_ = false;
    uint64_t tx_seq_ = 0;
    std::size_t stage_len_ = 0;
    Obj staged_ = Obj::Msg1;
    std::array<uint8_t, 192> bind_rec_{}; // SESSION_BIND / ACK record kept for byte-identical repeats
    std::size_t bind_len_ = 0;

    sec::SessionContext ctx_{};
    Sha256Digest ctx_hash_{};
    EndSession pend_;
    std::array<uint8_t, 16> bind_nonce_{};
};

} // namespace lm::delivery
