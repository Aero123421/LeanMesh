// The node's single handshake exchange (docs/06 §2 "1つのハンドシェイク", §4-§9): credential swap,
// EDHOC (method 0, suite 3, message_4 mandatory) and SESSION_BIND/ACK, for every session that is
// set up over the mesh. The mode names the purpose and the carrier; the state machine is the same:
//   Mode::Link      purpose 1 with a neighbour. Carriers: 1-hop bootstrap frames of kind EDHOC (SID
//   0). Mode::JoinInit  the JOIN_ONLY handshake of an unjoined device with the root (kind
//   JOIN_PROXY, Mode::JoinResp  decision S8-D1); exchange_join.cpp. Mode::End       purpose 2 with
//   a member that is not a neighbour: every object travels as an
//                   unauthenticated end record (end_sid k_handshake_sid) over the source route,
//                   sent and acknowledged hop by hop by the delivery module (S9-D2);
//                   exchange_end.cpp.
// One exchange at a time and one HandshakeSlot: at most one handshake is in progress on a node
// (docs/06 §8 "同時P-256 jobs1"; decision ARCH-D1). A request while the slot is taken gets Busy and
// its owner retries; a foreign carrier is dropped (a local shortage, never RF loss).
//
// Objects (the same kinds for every carrier):
//   CredI  initiator's bundle ([DeviceCredential, MemberCredential]; a joiner: its
//   DeviceCredential) CredR  responder's bundle (sent after it verified CredI; the root to a
//   joiner: [DC, RootDelegation]) Msg1..Msg4  EDHOC messages (one 1-hop frame each; split over end
//   records when the route is long) Bind/BindAck  SESSION_BIND / SESSION_BIND_ACK sealed under the
//   new keys. On a link they are a
//                 protected frame of kind EDHOC (SID != 0); on a route the sealed end record is
//                 carried as objects 7/8 because it is longer than a 40-hop frame (S9-D2).
// No ordinary frame or record is accepted before both sides finished: the session is installed
// (neighbour table / end-session table) only after SESSION_BIND[_ACK] was verified.
//
// Retransmission: the initiator repeats the whole current object every RTO (link 1 s, end the round
// timeout of the route) at most 3 times within 30 s; the responder only answers repeats from what
// it staged. Every public-key step is a worker job (Verify = the peer's credential chain, Hs = one
// EDHOC step); the exchange's memory stays reserved until the completion is polled (zombie rule).
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

#include "core/delivery/end_session.hpp"
#include "core/delivery/route_spec.hpp"
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

// Timing of the exchange (all modes) and of link-session lifetime.
struct LinkPolicy {
    Duration key_lifetime =
        Duration::from_s(3600); // docs/06 §7: 1 h or 2^24 packets (link and end)
    Duration rotate_lower_id = Duration::from_s(3000);  // the lower DeviceId starts rotation
    Duration rotate_higher_id = Duration::from_s(3300); // the other side only as a fallback
    uint64_t rotate_records = sec::k_max_records_per_key - (1ULL << 20);
    Duration prev_grace = Duration::from_s(10);        // old session receives this long (S5-D6)
    Duration handshake_gate = Duration::from_s(30);    // docs/06 §8: one full handshake / peer
    Duration exchange_deadline = Duration::from_s(30); // registry session_binding.timeout_ms
    Duration rto = Duration::from_ms(1000); // 1-hop carriers (end mode: route round timeout)
    uint8_t max_attempts = 3;               // registry session_binding.max_attempts
    Duration tx_gap{};                      // [S11] pause between streamed fragments (a joiner behind a relay)
    Duration join_session_life =
        Duration::from_s(420);             // [S8-D1] JOIN_ONLY: approval 300 s + prepared 120 s
    Duration linger = Duration::from_s(5); // responder keeps its ACK for bind repeats (1 hop)
    Duration end_linger = Duration::from_s(10); // the same over a route
};

struct LinkStats {
    uint64_t rx_frames = 0;
    uint64_t rx_malformed = 0; // structural decode failure
    uint64_t rx_wrong_domain = 0;
    uint64_t rx_no_identity = 0; // device is not a member: link traffic is not accepted
    uint64_t rx_unknown_sid = 0; // no session for (MAC, SID): old SID after a reboot lands here
    uint64_t rx_expired = 0;     // session past its key lifetime / grace
    uint64_t rx_auth_fail = 0;   // AEAD tag mismatch
    uint64_t rx_replay_dup = 0;  // authentic duplicate (delivered to the sink flagged)
    uint64_t rx_replay_old = 0;  // outside the window
    uint64_t rx_accepted = 0;
    uint64_t rx_inadmissible = 0; // authentic, but failed the minimum checks: the window did not move
    uint64_t rx_lease_restricted = 0; // application DATA over a time-uncertain session (SEC-D3)
    uint64_t tx_lease_restricted = 0;
    uint64_t sessions_lease_expired = 0; // closed because the peer's lease is provably over (SEC-D3)
    uint64_t rx_no_consumer = 0;
    uint64_t tx_sealed = 0;
    uint64_t tx_refused = 0;    // no session / refresh required
    uint64_t tx_frames_hs = 0;  // exchange frames handed to the radio
    uint64_t tx_local_busy = 0; // radio busy/isolated: local condition, never RF loss
    uint64_t tx_rf_failed = 0;  // MacFailed samples of exchange frames
    uint64_t hs_started = 0;    // as initiator or responder
    uint64_t hs_completed = 0;
    uint64_t hs_failed = 0;
    uint64_t hs_rate_limited = 0;
    uint64_t hs_busy_drop = 0; // a carrier arrived while the single slot was in use
    uint64_t hs_retransmits = 0;
    uint64_t cred_rejected = 0; // peer credential chain refused
    uint64_t cred_time_uncertain = 0;
    uint64_t bind_bad = 0; // SESSION_BIND[_ACK] failed a check
    uint64_t sessions_replaced = 0;
    uint64_t sessions_expired = 0;
    uint64_t rotations_started = 0;
};

// Handshake counters of the end mode (Delivery::end_stats()).
struct EndStats {
    uint64_t started = 0;
    uint64_t completed = 0;
    uint64_t failed = 0;
    uint64_t rate_limited = 0;
    uint64_t busy_drop = 0; // a carrier arrived while the single slot was in use
    uint64_t retransmits = 0;
    uint64_t cred_rejected = 0;
    uint64_t cred_time_uncertain = 0;
    uint64_t bind_bad = 0;
    uint64_t send_deferred = 0; // TX pool full / radio busy at a fragment: retried, never lost
    uint64_t lease_expired = 0; // sessions closed because the peer's lease is provably over (SEC-D3)
};

// Minimum interval between full handshakes with one peer (docs/06 §8): keyed by MAC for links, by
// DeviceId for end sessions. Bounded, LRU replacement: the gate limits load, it authorises nothing.
template <class Key> class RateGate {
  public:
    [[nodiscard]] bool allow(const Key &k, MonoTime now, Duration min) const {
        for (const Entry &e : entries_) {
            if (e.used && e.key == k) {
                return now - e.at >= min;
            }
        }
        return true;
    }
    void touch(const Key &k, MonoTime now) {
        Entry *slot = nullptr;
        for (Entry &e : entries_) {
            if (e.used && e.key == k) {
                slot = &e;
                break;
            }
            if (!e.used && slot == nullptr) {
                slot = &e;
            }
        }
        if (slot == nullptr) {
            slot = &*std::min_element(entries_.begin(), entries_.end(),
                                      [](const Entry &a, const Entry &b) { return a.at < b.at; });
        }
        *slot = Entry{k, now, true};
    }
    // An attempt we abandoned (glare yield) must not gate the peer.
    void forget(const Key &k) {
        for (Entry &e : entries_) {
            if (e.used && e.key == k) {
                e = Entry{};
            }
        }
    }

  private:
    struct Entry {
        Key key;
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
    // Root (SEC-D2): a Link or End session with a verified member, whichever side started it: does the
    // ledger list it ACTIVE with exactly this address, assignment and membership? (Everyone else: yes.)
    bool (*link_admit)(void *ctx, const DeviceId &device,
                       const member::MemberCredential &mc) = nullptr;
    // Root (SEC-D2): can admission be decided at all? Busy while the ledger is not loaded yet, RecoveryRequired
    // when it is lost. Until Ok no Link/End exchange is started or answered: this node's state, not the peer's.
    Status (*admission)(void *ctx) = nullptr;
    // The JOIN_ONLY session exists (both roles). `peer_bundle` (joiner: [DC, RootDelegation] as the
    // root sent it) aliases the exchange scratch and is valid only during the call.
    // `peer_dc_hash` = SHA-256 of the peer's DeviceCredential COSE (bound into the session
    // context).
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

// [S9] What the delivery module lends the exchange for end mode (it owns end sessions and routed
// frames). Without it (null functions) start_end() is Unsupported and end carriers are ignored.
struct EndPort {
    void *ctx = nullptr;
    delivery::EndSessions *sessions = nullptr;
    // The root clock estimate advanced to `now` (credential lease check).
    RootTimeBound (*root_time)(void *ctx, MonoTime now) = nullptr;
    // Sends one built end record along `route`. Busy/NoCapacity: retried shortly (never RF loss).
    Status (*send)(void *ctx, const delivery::PathSpec &route, ByteView record, Handle owner,
                   MonoTime now) = nullptr;
    // The end exchange with `peer` ended: Ok = a session was installed.
    void (*done)(void *ctx, const DeviceId &peer, Status st, MonoTime now) = nullptr;
};

// What the exchange needs from its layer: all owner-side and outliving the exchange.
struct LinkShared {
    Engine &engine;
    const LinkPolicy &policy;
    LinkStats &stats;
    Neighbors &neighbors;
    member::LocalIdentity &identity;
    RateGate<MacAddr> &gate;
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

enum class ObjKind : uint8_t {
    CredI = 1,
    CredR = 2,
    Msg1 = 3,
    Msg2 = 4,
    Msg3 = 5,
    Msg4 = 6,
    Bind = 7,
    BindAck = 8
};
enum class Phase : uint8_t { Idle, SendCred, Verify, Hs, AwaitMsg, AwaitBind, Linger, Zombie };
enum class Mode : uint8_t { Link, JoinInit, JoinResp, End };

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
    // the exchange is idle. While lent the exchange counts as busy (a handshake gets Busy, an
    // incoming CredI is dropped: local shortage, never RF loss). Empty view when busy.
    [[nodiscard]] MutByteView lend_scratch();
    void return_scratch() { lent_ = false; }
    // [S13, decision S13-D10] The HandshakeSlot of an idle exchange, lent to the root's USB link for
    // one EDHOC attempt (one slot per node, ARCH-D1). nullptr = taken: the caller is then first in line
    // (usb_reserved_: no new initiator and no new foreign CredI takes the slot) until return_slot().
    // The lender holds it, and job_pending() reports it, until its worker job completed.
    [[nodiscard]] sec::HandshakeSlot *lend_slot();
    void return_slot() { slot_lent_ = usb_reserved_ = false; }
    [[nodiscard]] Mode mode() const { return mode_; }

    // [S9] End mode: installed once by the delivery module.
    void set_end_port(const EndPort &p) { end_ = p; }
    // Initiator of an end session with `peer` over `route` (reverse routes answer). AuthPending
    // (not a member), Busy, RateLimited (per peer DeviceId), InvalidArgument, Unsupported (no
    // port).
    [[nodiscard]] Status start_end(const DeviceId &peer, const delivery::PathSpec &route,
                                   MonoTime now);
    // A handshake carrier record arrived (end_sid == k_handshake_sid); `reply` is the reverse of
    // its route, `scratch` memory to open a sealed bind record in.
    void on_end_carrier(const delivery::PathSpec &reply, const wire::EndHeader &h, ByteView plain,
                        delivery::OpenedEnd &scratch, MonoTime now);
    // The hop layer finished an end-carrier frame of this exchange (`accepted` = HOP_ACCEPTED).
    void on_end_frame_done(Handle owner, bool accepted, MonoTime now);
    // Frames of an end exchange may go out only while it is alive (asked by the hop layer).
    [[nodiscard]] bool end_alive(Handle owner) const {
        return mode_ == Mode::End && owner == handle_ && phase_ != Phase::Idle &&
               phase_ != Phase::Zombie;
    }
    [[nodiscard]] const EndStats &end_stats() const { return end_stats_; }
    // SEC-D3: the end sessions judged by their peers' leases again (LinkLayer::revalidate).
    void revalidate_end(const RootTimeBound &bound, MonoTime now);

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
    [[nodiscard]] bool busy() const {
        return (phase_ != Phase::Idle && phase_ != Phase::Linger) || lent_ || slot_lent_ || usb_reserved_;
    }
    // A worker job still runs on the exchange's memory (also after stop(): lm_destroy must wait).
    [[nodiscard]] bool job_pending() const { return job_ != Job::None || slot_lent_; }
    [[nodiscard]] Phase phase() const { return phase_; }
    [[nodiscard]] bool initiator() const { return initiator_; }
    [[nodiscard]] Status last_failure() const { return last_failure_; }
    static constexpr uint32_t k_tag_base = 0x4C4B0000; // tx tag of exchange frames ("LK")
    [[nodiscard]] static bool is_link_tag(uint32_t tag) {
        return (tag & 0xFFFF0000U) == k_tag_base;
    }

  private:
    enum class Job : uint8_t { None, Verify, Hs };
    // Who carried a fragment: a 1-hop frame (EDHOC or JOIN_PROXY kind) or a routed end record.
    enum class Family : uint8_t { Link, Join, End };
    enum class Count : uint8_t {
        Started,
        Completed,
        Failed,
        RateLimited,
        Retransmit,
        CredRejected,
        TimeUncertain,
        BindBad
    };
    // The staged object: an EDHOC message, a sealed 1-hop bind frame (<= 250 B) or a bind record.
    static constexpr std::size_t k_stage_bytes = wire::k_max_frame_bytes; // one pool frame
    // A sealed SESSION_BIND[_ACK] end record (117 B in practice).
    static constexpr std::size_t k_bind_record_max = 192;
    static constexpr std::size_t k_end_obj_header = member::k_join_chunk_header;
    // SESSION_BIND[_ACK] = [k_bind_version, ctx_hash, receiver_sid, nonce16] (docs/06 §9).
    static constexpr uint8_t k_bind_version = 1;

    struct Origin {
        Family family = Family::Link;
        MacAddr mac;                               // Link, Join
        const delivery::PathSpec *reply = nullptr; // End: the reverse of the carrier's route
        delivery::OpenedEnd *scratch = nullptr;    // End: where a bind record is opened
    };
    struct Frag { // one carrier fragment of an object, whatever carried it
        std::array<uint8_t, 16> xid{};
        ObjKind kind = ObjKind::CredI;
        uint16_t total = 0;
        uint16_t offset = 0;
        ByteView body;
    };
    struct PeerState {
        member::DeviceCredential dc;
        member::MemberCredential mc;
        std::array<uint8_t, sec::k_ccs_max_bytes> ccs{};
        std::size_t ccs_len = 0;
        Sha256Digest mc_hash{}; // join modes: SHA-256 of the peer's DeviceCredential COSE
    };
    struct VerifyInput { // copied at submit: the worker never reads owner-mutable state
        member::TrustAnchor trust;
        member::RootDelegation delegation;
    };

    [[nodiscard]] static Family family_of(Mode m) {
        return m == Mode::End ? Family::End : (m == Mode::Link ? Family::Link : Family::Join);
    }
    [[nodiscard]] Family family() const { return family_of(mode_); }
    [[nodiscard]] bool same_peer(const Origin &o) const {
        return o.family == Family::End ? o.reply->dest == route_.dest : o.mac == mac_;
    }
    void count(Count c);
    void busy_drop(Family f) {
        ++(f == Family::End ? end_stats_.busy_drop : s_.stats.hs_busy_drop);
    }
    [[nodiscard]] Status admission() const {
        return s_.join.admission != nullptr ? s_.join.admission(s_.join.ctx) : Status::Ok;
    }

    // lifecycle (exchange.cpp)
    void begin_common(Mode mode, bool initiator, MonoTime now);
    [[nodiscard]] Status acquire_link_peer(const MacAddr &mac);
    [[nodiscard]] Status start_1hop(Mode mode, const MacAddr &mac, MonoTime now);
    [[nodiscard]] uint32_t hint() const;
    void abort(Status why);
    void finish_idle();
    void wipe();

    // receive (exchange_io.cpp)
    void on_fragment(const Frag &f, const Origin &o, MonoTime now);
    [[nodiscard]] bool start_responder(const Frag &f, const Origin &o, MonoTime now);
    void obj_complete(ObjKind kind, ByteView obj, const Origin &o, MonoTime now);
    void switch_to_responder(const Origin &o);
    void resp_message_1(ByteView msg1, MonoTime now);

    // jobs and owner-side steps (exchange.cpp)
    [[nodiscard]] Status run_verify();
    [[nodiscard]] Status run_hs(sec::HsStep step, ByteView input = ByteView{});
    void after_verify(MonoTime now);
    [[nodiscard]] Status admit_peer(bool first, DeadlineCheck *lease = nullptr);
    void after_hs(MonoTime now);
    void start_hs(sec::HsRole role, ByteView msg1, MonoTime now);
    [[nodiscard]] Status stage(ObjKind kind, ByteView bytes);
    // The staged object lives in a frame borrowed from the node's pool while the exchange is active (P9).
    [[nodiscard]] FrameBuf *stage_buf();
    void stage_release();
    void finish_keys(MonoTime now);
    static Status job_entry(port::JobEnv &env, void *arg);
    static Status verify_body(Exchange &x);
    [[nodiscard]] Status make_context(sec::SessionContext &ctx) const;
    [[nodiscard]] Status alloc_sid(uint32_t &sid);

    // link session binding (exchange.cpp)
    [[nodiscard]] Status seal_bind(SessionKeys &k, const std::array<uint8_t, 16> &nonce);
    [[nodiscard]] bool check_bind_body(ByteView plain, uint32_t header_sid, uint32_t &sid,
                                       std::array<uint8_t, 16> &nonce) const;
    [[nodiscard]] Status install_session(MonoTime now, DeadlineCheck lease);
    [[nodiscard]] Neighbor *installed();

    // join mode (exchange_join.cpp)
    static Status verify_join_body(Exchange &x);
    [[nodiscard]] Status build_join_response();
    [[nodiscard]] Status make_join_context(sec::SessionContext &ctx) const;
    [[nodiscard]] Status install_join_session(MonoTime now);

    // end mode (exchange_end.cpp)
    [[nodiscard]] RootTimeBound root_time(MonoTime now) const;
    [[nodiscard]] Status seal_end_bind(sec::RecordSession &rec, const Sha256Digest &ctx_hash,
                                       uint32_t own_sid);
    void on_end_bind(ByteView record, const Origin &o, MonoTime now);
    [[nodiscard]] Status install_end_session(MonoTime now, DeadlineCheck lease);
    [[nodiscard]] Status send_end_chunk(ByteView obj, MonoTime now);

    // transmit (exchange_io.cpp)
    void send_object(ObjKind kind, bool retransmit);
    [[nodiscard]] ByteView tx_object() const;
    void pump(MonoTime now);
    [[nodiscard]] Status send_link_chunk(ByteView obj, MonoTime now);
    void arm_rto(MonoTime now);
    [[nodiscard]] Status build_plain(ObjKind kind, uint16_t total, uint16_t offset, ByteView body,
                                     MutByteView out, std::size_t &len) const;
    [[nodiscard]] ByteView own_bundle() const {
        switch (mode_) {
        case Mode::JoinInit:
            return s_.identity.device_cose(); // CredI of a joiner is its DeviceCredential alone
        case Mode::JoinResp:
            return ByteView{rx_.data(), own_len_}; // [DC, RootDelegation], built after verify
        case Mode::Link:
        case Mode::End:
            break;
        }
        return s_.identity.bundle();
    }

    LinkShared &s_;
    EndPort end_;
    EndStats end_stats_;
    RateGate<DeviceId> end_gate_;
    Phase phase_ = Phase::Idle;
    Mode mode_ = Mode::Link;
    bool lent_ = false; // rx_ is borrowed by a join module
    bool slot_lent_ = false;     // hs_ is borrowed by the USB link
    bool usb_reserved_ = false;  // the USB link waits for the slot
    JoinPeerOut *join_out_ = nullptr;
    std::size_t own_len_ = 0; // JoinResp: length of the bundle staged in rx_
    bool initiator_ = false;
    MacAddr mac_; // 1-hop modes: the peer's MAC and driver registration
    PeerHandle peer_;
    bool peer_transient_ = false;
    DeviceId peer_id_; // end mode: the requested (initiator) or verified (responder) peer
    bool peer_known_ = false;
    delivery::PathSpec
        route_; // end mode: initiator's route, responder's reverse of the latest carrier
    std::array<uint8_t, 16> xid_{};
    MonoTime deadline_ = MonoTime::never();      // current: the earliest of the phase limits
    MonoTime hard_deadline_ = MonoTime::never(); // whole exchange, 30 s from its start
    MonoTime rto_at_ = MonoTime::never();
    MonoTime retry_at_ =
        MonoTime::never(); // radio/TX pool busy: the pending fragment is tried again then
    uint8_t attempts_ = 0;
    ObjKind expect_ = ObjKind::CredR;
    Status last_failure_ = Status::Ok;

    Job job_ = Job::None;
    sec::HsStep hs_step_ = sec::HsStep::None;
    Handle handle_; // identity of this exchange for jobs and routed frames
    uint32_t handle_gen_ = 0;
    bool cancelled_ = false;

    // peer object reassembly (in order) and the verified credentials
    std::array<uint8_t, member::k_max_bundle> rx_{};
    std::size_t rx_len_ = 0;
    std::size_t rx_total_ = 0;
    std::array<uint8_t, 16> rx_xid_{};
    ObjKind rx_kind_ = ObjKind::CredR;
    PeerState peer_state_;
    VerifyInput vin_;

    // transmit side: the current object and the staged copy repeats are made from
    bool tx_active_ = false;
    ObjKind tx_kind_ = ObjKind::CredI;
    std::size_t tx_off_ = 0;
    bool tx_inflight_ = false;
    uint64_t tx_seq_ = 0;
    Handle stage_h_; // pool frame holding the EDHOC message, or the sealed bind frame/record
    std::size_t stage_len_ = 0;
    ObjKind staged_ = ObjKind::Msg1;

    // handshake + session under construction
    sec::HandshakeSlot hs_;
    sec::SessionContext ctx_{};
    Sha256Digest ctx_hash_{};
    SessionKeys pend_;
    std::array<uint8_t, 16> bind_nonce_{};
};

} // namespace lm::link
