// One link exchange in flight: credential swap, EDHOC (purpose 1) and SESSION_BIND with a
// neighbour (docs/06 §4-§9). The owner drives the state machine; every public-key step runs as a
// slow job on the worker (Verify = the peer's credential chain, Hs = one EDHOC step).
//
// Wire objects, all in the bootstrap carrier of frame kind EDHOC at SID 0 (plain, S5-D1):
//   CredI  initiator's bundle [DeviceCredential, MemberCredential], fragmented 160 B, in order
//   CredR  responder's bundle (sent after it verified CredI)
//   Msg1..Msg4  EDHOC messages, one fragment each (< 160 B in this profile)
// then two protected records (frame kind EDHOC, SID != 0): SESSION_BIND from the initiator and
// SESSION_BIND_ACK from the responder. No ordinary frame is accepted before both sides finished
// (the session is only installed in the neighbour table after SESSION_BIND[_ACK] was verified).
//
// One exchange at a time (single P-256 slot, docs/06 §8). The initiator retransmits the same bytes
// every RTO up to 3 times within 30 s; the responder only answers duplicates from its cache.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/jobs.hpp"
#include "core/link/neighbors.hpp"
#include "core/link/seal.hpp"
#include "core/member/join_wire.hpp"
#include "core/member/records.hpp"
#include "core/radio/tx_manager.hpp"
#include "core/wire/frame.hpp"
#include "core/wire/transfer.hpp"
#include "security/handshake.hpp"

namespace lm {
class Engine;
}

namespace lm::link {

struct LinkPolicy {
    Duration key_lifetime = Duration::from_s(3600);     // docs/06 §7: 1 h or 2^24 packets
    Duration rotate_lower_id = Duration::from_s(3000);  // the lower DeviceId starts rotation
    Duration rotate_higher_id = Duration::from_s(3300); // the other side only as a fallback
    uint64_t rotate_records = sec::k_max_records_per_key - (1ULL << 20);
    Duration prev_grace = Duration::from_s(10);         // old session receives this long (S5-D6)
    Duration handshake_gate = Duration::from_s(30);     // docs/06 §8: one full handshake / peer
    Duration exchange_deadline = Duration::from_s(30);  // registry session_binding.timeout_ms
    Duration rto = Duration::from_ms(1000);
    uint8_t max_attempts = 3;                           // registry session_binding.max_attempts
    Duration join_session_life = Duration::from_s(420); // [S8-D1] JOIN_ONLY: approval 300 s + prepared 120 s
};

struct LinkStats {
    uint64_t rx_frames = 0;
    uint64_t rx_malformed = 0;      // structural decode failure
    uint64_t rx_wrong_domain = 0;
    uint64_t rx_no_identity = 0;    // device is not a member: link traffic is not accepted
    uint64_t rx_unknown_sid = 0;    // no session for (MAC, SID): old SID after a reboot lands here
    uint64_t rx_expired = 0;        // session past its key lifetime / grace
    uint64_t rx_auth_fail = 0;      // AEAD tag mismatch
    uint64_t rx_replay_dup = 0;     // authentic duplicate (delivered to the sink flagged)
    uint64_t rx_replay_old = 0;     // outside the window
    uint64_t rx_accepted = 0;
    uint64_t rx_no_consumer = 0;
    uint64_t tx_sealed = 0;
    uint64_t tx_refused = 0;        // no session / refresh required
    uint64_t tx_frames_hs = 0;      // exchange frames handed to the radio
    uint64_t tx_local_busy = 0;     // radio busy/isolated: local condition, never RF loss
    uint64_t tx_rf_failed = 0;      // MacFailed samples of exchange frames
    uint64_t hs_started = 0;        // as initiator or responder
    uint64_t hs_completed = 0;
    uint64_t hs_failed = 0;
    uint64_t hs_rate_limited = 0;
    uint64_t hs_busy_drop = 0;      // a CredI arrived while the single slot was in use
    uint64_t hs_retransmits = 0;
    uint64_t cred_rejected = 0;     // peer credential chain refused
    uint64_t cred_time_uncertain = 0;
    uint64_t bind_bad = 0;          // SESSION_BIND[_ACK] failed a check
    uint64_t sessions_replaced = 0;
    uint64_t sessions_expired = 0;
    uint64_t rotations_started = 0;
};

// Minimum interval between full handshakes with one MAC (docs/06 §8). Bounded, LRU replacement:
// the gate limits load, it is not an authorisation record.
class RateGate {
  public:
    [[nodiscard]] bool allow(const MacAddr &mac, MonoTime now, Duration min) const;
    void touch(const MacAddr &mac, MonoTime now);
    void forget(const MacAddr &mac); // an attempt we abandoned (glare yield) must not gate the peer

  private:
    struct Entry {
        MacAddr mac;
        MonoTime at;
        bool used = false;
    };
    std::array<Entry, 4> entries_{};
};

// [S8] Extension points of the join/membership slice (docs/07 §4). All owner-side, all optional:
// a null function means "not a root / no join support in this build" and the link layer behaves
// exactly as before. `ctx` is the module the Engine wired in.
struct RxInfo;
struct JoinHooks {
    void *ctx = nullptr;
    // Root: may a JOIN_PROXY handshake from an unjoined device start now (policy + a free slot)?
    bool (*responder_open)(void *ctx) = nullptr;
    // Root: a link handshake with an ACTIVE-credential member: does the ledger still list it as
    // ACTIVE with exactly this membership generation? (Left/revoked devices are refused.)
    bool (*link_admit)(void *ctx, const DeviceId &device, const member::MemberCredential &mc) = nullptr;
    // The JOIN_ONLY session exists (both roles). `peer_bundle` (joiner: [DC, RootDelegation] as the
    // root sent it) aliases the exchange scratch and is valid only during the call.
    // `peer_dc_hash` = SHA-256 of the peer's DeviceCredential COSE (bound into the session context).
    void (*session_up)(void *ctx, bool initiator, const MacAddr &mac, const DeviceId &peer,
                       ByteView peer_bundle, const Sha256Digest &peer_dc_hash) = nullptr;
    // The joiner's exchange ended without a session (why != Ok).
    void (*exchange_failed)(void *ctx, Status why) = nullptr;
    // JOIN_PROXY carriers that are not an exchange object (hello / offer discovery).
    void (*discovery)(void *ctx, const MacAddr &src, const wire::BootstrapCarrier &c) = nullptr;
    // Authenticated CONTROL frame of a JOIN_ONLY session / of an ordinary link session.
    void (*join_control)(void *ctx, const RxInfo &info, ByteView plain) = nullptr;
    bool (*link_control)(void *ctx, const RxInfo &info, ByteView plain) = nullptr;
    // An ordinary link session with `peer` was installed (fresh or rotated).
    void (*link_up)(void *ctx, const DeviceId &peer, uint8_t role) = nullptr;
};

// What the exchange needs from its layer: all owner-side and outliving the exchange.
struct LinkShared {
    Engine &engine;
    const LinkPolicy &policy;
    LinkStats &stats;
    Neighbors &neighbors;
    member::LocalIdentity &identity;
    RateGate &gate;
    RootTimeBound root_time; // fed by the time slice; invalid means "unknown" (S5-D5)
    JoinHooks join;          // [S8]
};

// [S8] What a joiner learns from the root during the credential swap (written by the verify job,
// read by the owner after its completion). Owned by the membership module.
struct JoinPeerOut {
    member::RootDelegation delegation;
    Sha256Digest delegation_hash{};
    bool known = false;
};

enum class ObjKind : uint8_t { CredI = 1, CredR = 2, Msg1 = 3, Msg2 = 4, Msg3 = 5, Msg4 = 6 };
enum class Phase : uint8_t { Idle, SendCred, Verify, Hs, AwaitMsg, AwaitBind, Linger, Zombie };
// [S8-D1] Link = ordinary purpose-1 session (frames of kind EDHOC). JoinInit/JoinResp = the JOIN_ONLY
// handshake of an unjoined device with the root (carriers of kind JOIN_PROXY, docs/IMPLEMENTATION D3).
// One exchange slot, one HandshakeSlot: joins borrow the link exchange instead of adding a second.
enum class Mode : uint8_t { Link, JoinInit, JoinResp };

class Exchange {
  public:
    explicit Exchange(LinkShared &shared) : s_(shared) {}
    Exchange(const Exchange &) = delete;
    Exchange &operator=(const Exchange &) = delete;
    ~Exchange() { wipe(); }

    // Initiator. AuthPending (not a member), Busy (an exchange or a cancelled job holds the slot),
    // RateLimited (< 30 s since the last full handshake with this MAC), NoCapacity (peer table).
    [[nodiscard]] Status start_initiator(const MacAddr &mac, MonoTime now);

    // [S8] Joiner (identity Ready, not a member): JOIN_ONLY handshake with the root at `mac`.
    // `out` receives the root's verified delegation; it must outlive the exchange (zombie rule).
    // AuthPending: not Ready / already a member. Busy/RateLimited/NoCapacity as start_initiator().
    [[nodiscard]] Status start_join(const MacAddr &mac, JoinPeerOut *out, MonoTime now);
    // [S8] The 1024 B credential buffer doubles as the join modules' reassembly/object buffer while
    // the exchange is idle. While lent the exchange counts as busy (a link handshake gets Busy, an
    // incoming CredI is dropped: local shortage, never RF loss). Empty view when busy.
    [[nodiscard]] MutByteView lend_scratch();
    void return_scratch() { lent_ = false; }
    [[nodiscard]] Mode mode() const { return mode_; }

    // Owner, SID-0 bootstrap carrier body (EDHOC kind for links, JOIN_PROXY kind for joins).
    void on_bootstrap(const MacAddr &src, ByteView carrier, MonoTime now, bool via_join = false);
    // Owner, encrypted EDHOC-kind frame (SESSION_BIND / ACK). True when the exchange consumed it.
    [[nodiscard]] bool on_bind_frame(const MacAddr &src, const wire::LinkHeader &h, ByteView frame,
                                     MonoTime now);
    void on_job_done(Handle slot, Status job_status, MonoTime now);
    void on_tx_outcome(const TxOutcome &o, MonoTime now);
    void on_timer(MonoTime now);
    [[nodiscard]] MonoTime deadline() const;
    // Engine stop: aborts, wipes, and keeps the memory reserved while a job is in flight.
    void stop();

    // The slot is taken. A lingering responder (only keeping its ACK for bind retransmits) is free:
    // a new exchange replaces it and forgets the cached ACK.
    [[nodiscard]] bool busy() const { return (phase_ != Phase::Idle && phase_ != Phase::Linger) || lent_; }
    [[nodiscard]] Phase phase() const { return phase_; }
    [[nodiscard]] bool initiator() const { return initiator_; }
    [[nodiscard]] Status last_failure() const { return last_failure_; }
    static constexpr uint32_t k_tag_base = 0x4C4B0000; // tx tag of exchange frames ("LK")
    [[nodiscard]] static bool is_link_tag(uint32_t tag) { return (tag & 0xFFFF0000U) == k_tag_base; }

  private:
    enum class Job : uint8_t { None, Verify, Hs };
    enum class Tx : uint8_t { None, Cred, Frame };

    struct PeerState {
        member::DeviceCredential dc;
        member::MemberCredential mc;
        std::size_t mc_off = 0; // MemberCredential COSE inside rx_
        std::size_t mc_len = 0;
        std::array<uint8_t, sec::k_ccs_max_bytes> ccs{};
        std::size_t ccs_len = 0;
        Sha256Digest mc_hash{};
    };

    struct VerifyInput { // copied at submit: the worker never reads owner-mutable state
        member::TrustAnchor trust;
        member::RootDelegation delegation;
    };

    [[nodiscard]] Status begin_common(const MacAddr &mac, bool initiator, MonoTime now);
    [[nodiscard]] uint32_t hint() const;
    [[nodiscard]] Neighbor *installed();
    [[nodiscard]] Status install_join_session(MonoTime now);
    [[nodiscard]] Status build_join_response();
    void abort(Status why);
    void peer_state_reset();
    void finish_idle();
    void wipe();

    void on_cred(const MacAddr &src, const wire::BootstrapCarrier &c, ObjKind kind, MonoTime now,
                 bool via_join);
    void on_msg(const MacAddr &src, const wire::BootstrapCarrier &c, ObjKind kind, MonoTime now);
    void cred_complete(ObjKind kind, MonoTime now);
    void switch_to_responder();

    [[nodiscard]] Status run_verify();
    [[nodiscard]] Status run_hs(sec::HsStep step, ByteView input = ByteView{});
    void after_verify(MonoTime now);
    void after_hs(MonoTime now);
    void start_hs_initiator(MonoTime now);
    void finish_keys(MonoTime now);
    static Status job_entry(port::JobEnv &env, void *arg);
    static Status verify_body(Exchange &x);
    static Status verify_join_body(Exchange &x);
    [[nodiscard]] Status make_join_context(sec::SessionContext &ctx) const;

    [[nodiscard]] Status make_context(sec::SessionContext &ctx) const;
    [[nodiscard]] Status alloc_sid(uint32_t &sid);
    [[nodiscard]] Status seal_bind(SessionKeys &k, const std::array<uint8_t, 16> &nonce);
    [[nodiscard]] bool check_bind_body(ByteView plain, uint32_t header_sid, uint32_t &sid,
                                       std::array<uint8_t, 16> &nonce) const;
    [[nodiscard]] Status install_session(MonoTime now);
    void stage_frame(ObjKind kind, ByteView body);
    void send_object(Tx mode, ObjKind kind, bool retransmit);
    void pump(MonoTime now);
    void arm_rto(MonoTime now);
    [[nodiscard]] Status build_plain(ObjKind kind, uint16_t total, uint16_t offset, ByteView body,
                                     MutByteView out, std::size_t &len) const;
    [[nodiscard]] Status build_cred_fragment(MutByteView out, std::size_t &len) const;
    [[nodiscard]] ByteView own_bundle() const {
        switch (mode_) {
        case Mode::JoinInit:
            return s_.identity.device_cose(); // CredI of a joiner is its DeviceCredential alone
        case Mode::JoinResp:
            return ByteView{rx_.data(), own_len_}; // [DC, RootDelegation], built after verify
        case Mode::Link:
            break;
        }
        return s_.identity.bundle();
    }

    LinkShared &s_;
    Phase phase_ = Phase::Idle;
    Mode mode_ = Mode::Link;
    bool lent_ = false;           // rx_ is borrowed by a join module
    JoinPeerOut *join_out_ = nullptr;
    std::size_t own_len_ = 0;     // JoinResp: length of the bundle staged in rx_
    bool initiator_ = false;
    MacAddr mac_;
    PeerHandle peer_;
    bool peer_transient_ = false;
    std::array<uint8_t, 16> xid_{};
    MonoTime deadline_ = MonoTime::never();      // current: the earliest of the phase limits
    MonoTime hard_deadline_ = MonoTime::never(); // whole exchange, 30 s from its start
    MonoTime rto_at_ = MonoTime::never();
    MonoTime retry_at_ = MonoTime::never(); // radio busy: the pending frame is tried again then
    uint8_t attempts_ = 0;
    ObjKind expect_ = ObjKind::CredR;
    Status last_failure_ = Status::Ok;

    Job job_ = Job::None;
    sec::HsStep hs_step_ = sec::HsStep::None;
    Handle handle_;
    uint32_t handle_gen_ = 0;
    bool cancelled_ = false;

    // peer credential bundle (in-order reassembly) and its verified content
    std::array<uint8_t, member::k_max_bundle> rx_{};
    std::size_t rx_len_ = 0;
    std::size_t rx_total_ = 0;
    std::array<uint8_t, 16> rx_xid_{};
    ObjKind rx_kind_ = ObjKind::CredR;
    PeerState peer_state_;
    VerifyInput vin_;

    // transmit side
    Tx tx_ = Tx::None;
    ObjKind tx_kind_ = ObjKind::CredI;
    std::size_t tx_off_ = 0;
    bool tx_inflight_ = false;
    uint16_t tx_seq_ = 0;
    std::array<uint8_t, wire::k_max_frame_bytes> last_{}; // frame kept for retransmission
    std::size_t last_len_ = 0;

    // handshake + session under construction
    sec::HandshakeSlot hs_;
    sec::SessionContext ctx_{};
    Sha256Digest ctx_hash_{};
    SessionKeys pend_;
    std::array<uint8_t, 16> bind_nonce_{};
    uint32_t peer_sid_ = 0;
};

} // namespace lm::link
