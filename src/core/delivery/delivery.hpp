// Delivery (docs/08): the origin and destination halves of every application message, on the mesh
// owner. Ownership of state:
//   Op       one per lm_send / lm_report_application_result: evidence bits, phase, outcome (history is
//            kept while slots allow, so late receipts still find their operation, D03)
//   Active   a send in progress: message buffer, sealed end record (never re-encrypted with a used
//            counter), timers, journal version
//   InEntry  the dedup/receipt cache: one per message received (or recovered), bounded, terminal
//            entries are recycled least-recently-used, live ones never
//   HopTx    TX frames and link retry;  EndSessions  end keys (set up by the node's single
//            exchange, link::Exchange in end mode);  Durable  the journal
// Nothing here blocks or allocates: public-key work and Flash are worker jobs whose completions are
// matched by (job id, slot generation).
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

#include "core/command.hpp"
#include "core/delivery/durable.hpp"
#include "core/delivery/end_session.hpp"
#include "core/delivery/fragment.hpp"
#include "core/delivery/hop.hpp"
#include "core/delivery/route_spec.hpp"
#include "core/delivery/types.hpp"
#include "core/link/link_layer.hpp"
#include "core/pool.hpp"
#include "core/route/forward.hpp"
#include "core/route/path_cache.hpp"

namespace lm {
class Engine;
}

namespace lm::delivery {

inline constexpr std::size_t k_ops = k_build_limits.app_messages * 2;
inline constexpr std::size_t k_actives = k_build_limits.app_messages;
inline constexpr std::size_t k_in_entries = k_build_limits.receipts;
// [S11-D9, ADR-002 P6] The root derives every path it sends on from its topology; its cache only holds the
// reverse routes learned from traffic of nodes the tree does not know yet, so 8 entries instead of one per member.
inline constexpr std::size_t k_routes = k_root_capable ? 8 : k_build_limits.path_cache;
inline constexpr std::size_t k_accepted_ring = 8;
inline constexpr std::size_t k_record_bytes = wire::k_end_header_bytes + wire::data_capacity(1) + wire::k_tag_bytes;
// Build frame of an outgoing routed record (a borrowed pool frame): route header and path, then the record.
[[nodiscard]] constexpr std::size_t route_room(std::size_t hops) { return wire::k_route_header_bytes + 2U * hops; }
// Where a record for a `hops`-hop frame is sealed into a build frame (never past the frame's end).
[[nodiscard]] inline MutByteView record_area(Lease &l, std::size_t hops) {
    const std::size_t room = route_room(hops);
    return MutByteView{l.data() + room, std::min(k_record_bytes, Lease::size() - room)};
}

struct MsgBuf {
    std::array<uint8_t, k_msg_bytes> data{};
};

// lm_report_application_result carries the message reference and the outcome in one request.
struct ReportRequest {
    lm_message_ref_t ref;
    uint32_t outcome = 0;
};
// [S13] The Host is the root's application over USB: it picks the MessageId (so it can reconcile after
// a crash by MessageId alone) and computes the intent_hash; the root recomputes it and refuses a
// mismatch. Same id + same hash = the same operation (idempotent), same id + other hash = CONFLICT.
struct HostSendRequest {
    lm_send_request_t rq;
    std::array<uint8_t, 16> mid{};
    Sha256Digest hash{};
};
// Root only: what a Host acknowledgement names (docs/19 §4 HOST_STORE_ACK).
struct HostStoreAckRequest {
    DeviceId origin;
    uint64_t assignment = 0; // the origin's assignment_generation: part of the message identity
    std::array<uint8_t, 16> mid{};
    Sha256Digest hash{};
};
// [S11] What the mesh module (src/core/route/mesh.*, src/root/routes.*, src/core/member/proxy.*) plugs
// into delivery: its own control lane and route knowledge. All optional (null = not installed).
struct MeshHooks {
    void *ctx = nullptr;
    // An authenticated CONTROL record (app_port 0) of an end session with `peer`. `reply` is the
    // reverse of the route it came along (the only way back to a node the tree does not know yet).
    void (*control)(void *ctx, const DeviceId &peer, const PathSpec &reply, ByteView body, MonoTime now) = nullptr;
    // A join-tunnel carrier (end_sid k_tunnel_sid): unauthenticated hop by hop, opaque to relays.
    void (*tunnel)(void *ctx, const PathSpec &reply, ByteView plain, MonoTime now) = nullptr;
    // An end exchange with `peer` ended (Ok: a session was installed).
    void (*session)(void *ctx, const DeviceId &peer, Status st, MonoTime now) = nullptr;
    // A routed frame finished at the hop layer (any owner): link quality, repair, tunnel progress.
    void (*frame_done)(void *ctx, const FrameDone &f, HopEnd end, MonoTime now) = nullptr;
    // Route the mesh knows without a cache entry (own root path, root topology). Ok: filled; Busy:
    // known destination, no usable path now (a repair runs): wait; anything else: ask the cache.
    Status (*route_of)(void *ctx, const DeviceId &dest, PathSpec &out, MonoTime now) = nullptr;
    // Nothing resolves `dest`: the mesh may ask the root (rate-limited on its side).
    void (*want_route)(void *ctx, const DeviceId &dest, MonoTime now) = nullptr;
    // The single exchange slot is free again (after want_slot()).
    void (*slot_free)(void *ctx, MonoTime now) = nullptr;
};

struct CapacityRequest {
    lm_destination_t dest;
    uint32_t single_frame_bytes = 0;
    uint32_t path_hops = 0;
};

struct Op {
    bool used = false;
    uint64_t id = 0;
    uint32_t seq = 0; // eviction order (oldest final goes first)
    MessageId mid;
    DeviceId dest;
    uint16_t port = 0;
    uint8_t delivery = 0;
    uint8_t storage = 0;
    uint8_t priority = 0;
    uint32_t term = 0;
    uint64_t expires = 0;
    Sha256Digest hash{};
    Phase phase = Phase::Pending;
    uint8_t outcome = LM_OUTCOME_PENDING;
    uint32_t reason = 0;
    uint32_t evidence = 0;
    uint64_t accepted_ms = 0;
    uint64_t last_evidence_ms = 0;
    uint8_t result_len = 0;
    std::array<uint8_t, k_result_bytes> result{};
    Handle active; // none once the send is over
    bool report = false; // created by lm_report_application_result, not a send
    bool group = false;  // [S15] one target of a group operation: its events are the group's
};

// [S15] What the group fan-out plugs into delivery: a child's outcome changed (final, or a late upgrade),
// and the generations of the peer an end session was made with (false: not the target the snapshot names).
struct GroupHooks {
    void *ctx = nullptr;
    void (*child)(void *ctx, const Op &op, MonoTime now) = nullptr;
    bool (*gate)(void *ctx, const Op &op, uint64_t assignment, uint64_t membership) = nullptr;
};

struct Active {
    enum class St : uint8_t { Persisting, WaitRoute, WaitSession, Sending, WaitReceipt };
    uint16_t op = 0;
    St st = St::Persisting;
    Handle msg;      // payload buffer (pool)
    uint16_t len = 0;
    bool durable = false;
    bool cancelled = false;
    bool recovered = false;
    uint16_t jslot = 0;             // journal record id = k_id_out | jslot (durable only)
    uint32_t version = 1;           // record version; persisted_version >= version = durable
    uint32_t persisted_version = 0;
    bool commit_wanted = false;
    uint8_t round = 0;              // E2E rounds started
    bool new_round = true;          // the next frame opens a new round (the last one ended)
    uint8_t hops = 0;               // path length of the last frame (sizes the round timer)
    uint8_t refusals = 0;           // first hop refused (no route/session/capacity there)
    uint8_t backoff = 0;            // consecutive waits for route/session (grows the retry delay)
    bool latest = false;            // [S14] queue_mode LATEST: replaced by a newer send of the same key while unsent
    uint64_t key = 0;               // [S14] coalesce_key (with the destination and app_port: docs/08 §1)
    MonoTime next_at = MonoTime::never();
    MonoTime round_at = MonoTime::never(); // WaitReceipt: when the current E2E round gives up
    // [S12] fragmented send: FRAGMENT records cut from the payload lane, confirmed by TRANSFER_BITMAPs
    bool xfer = false;    // sent as fragments (too big for a frame on this path, or an object)
    bool strict = false;  // strict_single_frame: never fragmented
    bool control = false; // a control object: no receipt, done when every fragment is confirmed
    Lane lane = Lane::Pool;
    uint16_t cursor = 0;  // next offset to send
    std::array<uint8_t, k_bitmap_bytes> acked{};
    uint16_t record_len = 0;
    uint32_t record_term = 0;
    uint32_t record_epoch = 0;
    std::array<uint8_t, k_record_bytes> record{};
};

// The dedup/receipt cache (P1). An InEntry is what a duplicate needs to be answered: the key (origin,
// message id), the intent hash, the outcome and the result. It lives as long as the cache remembers.
// What a record still has to do - hold the payload, write the journal, tell the application, wait for
// its result - is held in an InLive slot (there are app_messages + k_live_slack of them); a record
// with nothing left to do gives its slot back (settle()) and is then only recycled, oldest first.
inline constexpr uint8_t k_no_live = 0xFF;
inline constexpr std::size_t k_live_slack = 2; // commits of taken messages still in flight while new ones arrive
inline constexpr std::size_t k_in_live = k_build_limits.app_messages + k_live_slack;

struct InEntry {
    enum class St : uint8_t { Committing, Held, Delivered, Applied, AppRejected };
    St st = St::Committing;
    uint8_t delivery = 0;
    bool durable = false;
    bool gated = false;           // [S13] END_RECEIVED withheld until the Host's HOST_STORE_ACK
    uint8_t result_len = 0;
    uint8_t live = k_no_live;     // index into Delivery::lives_ while the record has work to do
    uint16_t jslot = 0;           // journal record id = k_id_in | jslot (durable only)
    uint32_t receipt_seq = 0;
    uint32_t last_use = 0;
    uint64_t expires = 0;
    uint64_t assignment = 0;      // origin's assignment_generation: part of the message identity (docs/08 §2)
    DeviceId origin;
    std::array<uint8_t, 16> mid{};
    Sha256Digest hash{};
    std::array<uint8_t, k_result_bytes> result{};
};

struct InLive {
    bool used = false;
    bool app_pending = false;     // the application acknowledged without a result yet
    bool event_owed = false;      // MESSAGE event not queued yet (queue was full)
    bool obj = false;             // [S12] the payload is the received object in the object buffer
    bool recovered = false;       // came back from the journal: the application may have seen it
    bool commit_wanted = false;
    uint8_t priority = 0;
    uint8_t due_ev = 0xFF;        // receipt to send once the commit of due_version is durable
    uint16_t port = 0;
    uint16_t len = 0;
    uint32_t term = 0;
    uint32_t version = 1;
    uint32_t persisted_version = 0;
    uint32_t due_version = 0;
    uint32_t arrival = 0;         // MESSAGE events are re-queued in arrival order
    Handle msg;                   // payload buffer while Committing/Held
};

struct DeliveryStats {
    uint64_t accepted = 0;
    uint64_t rx_data = 0;          // end DATA records delivered to this node
    uint64_t rx_forward = 0;
    uint64_t rx_drop_route = 0;    // forwarding checks failed (docs/04 §4)
    uint64_t rx_dup_link = 0;      // authentic link duplicates (our ACK was lost)
    uint64_t rx_dup_end = 0;       // end-level duplicates answered from the cache
    uint64_t rx_no_session = 0;
    uint64_t rx_auth_fail = 0;
    uint64_t rx_unsupported = 0;   // record kinds owned by later slices (fragment, bitmap, control)
    uint64_t rx_busy = 0;          // answered BUSY: our buffers, not RF loss
    uint64_t rx_refused = 0;       // refused with a receipt (expired, conflict, no capacity ...)
    uint64_t delivered = 0;        // MESSAGE events created (never twice for one message)
    uint64_t receipts_sent = 0;
    uint64_t receipts_dropped = 0; // TX pool full: the origin's next round asks again
    uint64_t receipts_rx = 0;
    uint64_t receipts_late = 0;    // for an operation that was already final
    uint64_t receipts_unknown = 0;
    uint64_t rounds = 0;           // E2E rounds started
    uint64_t expired = 0;
    uint64_t send_wait_route = 0;
    uint64_t superseded = 0;       // [S14] LATEST sends replaced before anything left the node
    uint64_t admit_refused = 0;    // [S14] sends refused by the class share of the operation slots
    uint64_t journal_puts = 0;
};

// [S16] What a sleep would cut (Delivery::settle_state, src/core/power/delivery_power.cpp).
struct Settle {
    uint16_t active = 0;      // sends in progress
    uint16_t uncommitted = 0; // journal records not durable yet
    uint16_t owed = 0;        // received messages whose event the application has not taken
};

class Delivery {
  public:
    Delivery(Engine &engine, member::LocalIdentity &identity, link::LinkLayer &link);
    Delivery(const Delivery &) = delete;
    Delivery &operator=(const Delivery &) = delete;

    // ---- owner wiring (Engine calls these) ----
    // Boot job (incarnation, journal) then recovery of durable records. Busy while an older job
    // still owns the memory.
    [[nodiscard]] Status start(MonoTime now);
    void stop();
    void on_link_rx(const link::RxInfo &info, ByteView plain, MonoTime now);
    void on_tx_outcome(const TxOutcome &o, MonoTime now);
    void on_job_done(JobOwner owner, Handle slot, Status s, MonoTime now);
    void on_timer(MonoTime now);
    [[nodiscard]] MonoTime deadline() const;
    [[nodiscard]] Reply execute(const Command &cmd, MonoTime now);
    [[nodiscard]] bool job_pending() const {
        return durable_.job_pending() || link_.exchange().job_pending();
    }

    // Root clock estimate (fed by the time slice). Re-drives operations waiting on it.
    void set_root_time(const RootTimeBound &t, MonoTime now);

    // ---- events / payload of lm_next_event ----
    // Payload of a MESSAGE or OPERATION event. False: none (event without payload, or gone).
    [[nodiscard]] bool event_payload(const lm_event_t &ev, ByteView &out) const;
    // The application took the event: MESSAGE -> Delivered (buffer freed, marker persisted).
    void on_event_taken(const lm_event_t &ev, MonoTime now);
    // Queue space appeared: re-queue MESSAGE events that did not fit.
    void flush_events(MonoTime now);

    // ---- [S13] root <-> Host bridge (delivery_host.cpp) ----
    // With the gate on, a DURABLE RECEIVED message addressed to this (root) node is confirmed to its
    // origin (END_RECEIVED) and released only by host_store_ack(): the terminal store is the Host's DB,
    // not the root's journal. Off (default): the root's own journal commit is the terminal store.
    void set_host_gate(bool on) { host_gate_ = on; }
    [[nodiscard]] Status host_store_ack(const HostStoreAckRequest &rq, MonoTime now);
    // The root clock estimate advanced to `now` (the Host derives root deadlines from it).
    [[nodiscard]] RootTimeBound root_time(MonoTime now);

    // ---- [S12] control objects and fragments (fragment.cpp) ----
    // The sink gets every complete control object once (the group/policy slices consume them).
    void set_control_sink(ControlSink sink, void *ctx) {
        frag_.sink = sink;
        frag_.sink_ctx = ctx;
    }
    [[nodiscard]] const FragStats &frag_stats() const { return frag_.stats; }
    // ---- [S15] group fan-out plug points (delivery_group.cpp) ----
    // A group target is an ordinary send with a MessageId the group reserved (a repeated call with the
    // same id is the same operation) whose events and generation check belong to the group.
    void set_group_hooks(const GroupHooks &h) { group_ = h; }
    [[nodiscard]] Reply send_child(const lm_send_request_t &rq, ByteView payload, const std::array<uint8_t, 16> &mid,
                                   MonoTime now);
    [[nodiscard]] bool probe(const DeviceId &dest, const std::array<uint8_t, 16> &mid, lm_operation_t &out);
    [[nodiscard]] Reply cancel_child(const DeviceId &dest, const std::array<uint8_t, 16> &mid, MonoTime now);
    // Ok / Expired / TimeUncertain, as a send with this deadline would be judged now.
    [[nodiscard]] Status deadline_status(uint64_t expires, uint32_t term);
    struct SeqBlock {
        uint64_t incarnation = 0;
        uint64_t first = 0;
    };
    // n consecutive message sequences of this boot (no other message gets one of them).
    [[nodiscard]] SeqBlock reserve_sequences(uint32_t n);
    [[nodiscard]] Pool<MsgBuf, k_build_limits.app_messages> &messages() { return msgs_; }
    // ---- [S11] mesh plug points (delivery_mesh.cpp) ----
    void set_mesh(const MeshHooks &h) { mesh_ = h; }
    [[nodiscard]] bool has_session(const DeviceId &peer, MonoTime now);
    // Starts an end session with `peer` along `route`. Conflict: a usable one exists. Busy: the node's
    // single exchange slot is taken (want_slot() asks to be told when it is free).
    [[nodiscard]] Status start_session(const DeviceId &peer, const PathSpec &route, MonoTime now);
    void want_slot() { slot_wait_ = true; }
    [[nodiscard]] const EndSession *end_session_at(ShortAddr a) { return sessions_.find_addr(a); }
    // One CONTROL record (<= 96 B) sealed under the end session with `peer`, sent along `route`.
    // AuthPending: no usable session. Every call seals with a fresh counter (never a reused nonce).
    [[nodiscard]] Status send_control(const DeviceId &peer, const PathSpec &route, ByteView body, MonoTime now);
    // A routed record that is not end-authenticated (join tunnel carriers). NoRoute/NoCapacity as
    // for any frame; `owner` comes back in the hook's FrameDone.
    [[nodiscard]] Status send_routed(const PathSpec &route, ByteView record, OwnerKind kind, Handle owner,
                                     MonoTime now);
    // Paths changed (repair, new lease): sends that waited for a route go on now.
    void routes_changed(MonoTime now) { kick_all_waiting(now); }
    void invalidate_routes() { routes_.clear(); }

    // ---- [S16] power (delivery_power.cpp) ----
    [[nodiscard]] Settle settle_state() const;
    [[nodiscard]] Duration min_key_life(MonoTime now) const; // shortest remaining key life of any session
    void sleep_gap(Duration gap);                            // waiting timers do not run into a sleep

    // ---- routes (S11 resolves them; until then a bench/provisioning call) ----
    [[nodiscard]] Status install_route(const DeviceId &dest, const PathSpec &route, MonoTime expires);
    void drop_routes() { routes_.clear(); }

    // ---- inspection (tests, diagnostics) ----
    [[nodiscard]] const DeliveryStats &stats() const { return stats_; }
    [[nodiscard]] const HopStats &hop_stats() const { return hop_.stats(); }
    [[nodiscard]] const link::EndStats &end_stats() const { return link_.exchange().end_stats(); }
    [[nodiscard]] EndSessions &sessions() { return sessions_; }
    [[nodiscard]] HopTx &hop() { return hop_; }
    [[nodiscard]] Durable &durable() { return durable_; }
    [[nodiscard]] const link::Exchange &exchange() const { return link_.exchange(); }
    [[nodiscard]] bool ready() const { return ready_; }
    [[nodiscard]] std::size_t in_entries() const { return in_.in_use(); }
    [[nodiscard]] std::size_t free_msg_buffers() const { return msgs_.capacity() - msgs_.in_use(); }

  private:
    struct Accepted {
        bool used = false;
        MacAddr mac;
        uint64_t counter = 0;
        uint32_t order = 0;
    };
    // Work that must run after the HOP_ACK is queued (the ACK goes out before any frame it causes).
    struct Post {
        enum class K : uint8_t { None, Carrier, Receipt, Resend, Refuse, NewVolatile, NewDurable, Bitmap, Control, MeshControl, Tunnel } k = K::None; // [S11] MeshControl, Tunnel
        Handle in;
        ReceiptEv ev = ReceiptEv::Refused;
        uint32_t reason = 0;
        Sha256Digest hash{};
        ByteView carrier;
        EndSession *session = nullptr;
        uint8_t free_slot = 0;   // [S12] reassembly slot to free once the payload was used (index + 1)
        bool bitmap_owed = false; // [S12] answer with `bitmap` after this frame
        wire::TransferBitmap bitmap;
    };
    struct FrameCtx { // what an incoming DATA frame is, after decoding
        const link::RxInfo *info = nullptr;
        wire::RouteHeader route;
        ByteView record; // end record inside the plaintext
        ByteView plain;  // link plaintext (route header + path + record)
    };

    // -- helpers (delivery.cpp) --
    void refresh_bound(MonoTime now);
    [[nodiscard]] RootTerm local_term() const;
    [[nodiscard]] ShortAddr self_addr() const;
    [[nodiscard]] Op *find_op(uint64_t id);
    [[nodiscard]] Op *find_op_by_message(const DeviceId &dest, const std::array<uint8_t, 16> &mid);
    [[nodiscard]] Op *alloc_op();
    [[nodiscard]] uint16_t op_index(const Op &o) const { return static_cast<uint16_t>(&o - ops_.data()); }
    void note_evidence(Op &op, uint32_t bits, MonoTime now);
    void finalize(Op &op, uint8_t outcome, uint32_t reason, MonoTime now);
    void emit_op_event(const Op &op, MonoTime now);
    void retire_active(Handle h, bool persist_retire, MonoTime now);
    void fill_operation(const Op &op, lm_operation_t &out) const;
    [[nodiscard]] bool route_for(const DeviceId &dest, PathSpec &out, MonoTime now);
    void learn_route(const EndSession &s);
    // The frame of a routed record is built in a pool frame borrowed for the call (P9): route header and
    // path first, the record right after. A caller that sealed its record into its own scratch frame at
    // route_room(hops) passes that frame and the record length and nothing is copied.
    [[nodiscard]] bool build_and_send(const PathSpec &ps, Lease &scratch, std::size_t record_len, OwnerKind kind,
                                      Handle owner, MonoTime now, Status &why);
    [[nodiscard]] bool build_and_send(const PathSpec &ps, ByteView record, OwnerKind kind, Handle owner,
                                      MonoTime now, Status &why);
    [[nodiscard]] link::Neighbor *neighbor_at(uint16_t addr);
    [[nodiscard]] DeadlineCheck deadline_state(uint64_t expires, uint32_t term) const;
    [[nodiscard]] MonoTime local_deadline(uint64_t expires, uint32_t term, MonoTime now) const;

    // -- admission and LATEST coalescing (delivery_sched.cpp) [S14] --
    // Ok = the request may proceed; `victim` is the unsent LATEST send it replaces (none otherwise).
    [[nodiscard]] Reply admit_send(const lm_send_request_t &rq, const DeviceId &dest, Handle &victim);
    void supersede(Handle victim, uint64_t by_op, MonoTime now);

    // -- origin (delivery_tx.cpp) --
    [[nodiscard]] Reply send(const lm_send_request_t &rq, ByteView payload, MonoTime now);
    [[nodiscard]] Reply send_impl(const lm_send_request_t &rq, ByteView payload, MonoTime now); // [S14] send() counts refusals
    [[nodiscard]] Reply host_send(const HostSendRequest &rq, ByteView payload, MonoTime now); // delivery_host.cpp
    [[nodiscard]] bool gate_receipt(const InEntry &e) const {
        return host_gate_ && e.durable && e.delivery == LM_RECEIVED;
    }
    void finish_take(Handle h, InEntry &e, MonoTime now);
    [[nodiscard]] Reply cancel(uint64_t op_id, MonoTime now);
    [[nodiscard]] Reply get_operation(uint64_t op_id, lm_operation_t &out);
    [[nodiscard]] Reply get_message(const lm_message_ref_t &ref, lm_operation_t &out);
    [[nodiscard]] Reply payload_capacity(CapacityRequest &rq, MonoTime now);
    void drive(Handle h, MonoTime now);
    void kick_dest(const DeviceId &dest, MonoTime now);
    void kick_all_waiting(MonoTime now);
    void finalize_active(Handle h, uint8_t outcome, uint32_t reason, MonoTime now);
    void round_ended(Handle h, Active &a, Op &op, MonoTime now, bool link_failed);
    [[nodiscard]] bool left_node(Handle h, const Op &op) const;
    [[nodiscard]] Duration retry_delay(const Active &a) const;
    void on_frame_done(const FrameDone &f, HopEnd end, MonoTime now);
    [[nodiscard]] Status may_send(const TxFrame &f, MonoTime now);
    void on_receipt(const EndSession &s, const std::array<uint8_t, 16> &mid, ByteView payload, MonoTime now);
    void request_exchange(Active &a, Op &op, const PathSpec &ps, MonoTime now);
    void on_exchange_done(const DeviceId &peer, Status st, MonoTime now);
    static Status exchange_send(void *ctx, const PathSpec &route, ByteView record, Handle owner, MonoTime now);
    static void exchange_done(void *ctx, const DeviceId &peer, Status st, MonoTime now);
    static RootTimeBound exchange_root_time(void *ctx, MonoTime now);
    static Status hop_may_send(void *ctx, const TxFrame &f, MonoTime now);
    static void hop_done(void *ctx, const FrameDone &f, HopEnd end, MonoTime now);

    // -- destination + relay (delivery_rx.cpp) --
    void on_hop_ack(const link::RxInfo &info, ByteView plain, MonoTime now);
    void on_data(const link::RxInfo &info, ByteView plain, MonoTime now);
    void forward(const link::RxInfo &info, wire::RouteHeader &h, ByteView record, MonoTime now);
    void deliver(const link::RxInfo &info, const wire::RouteHeader &h, ByteView record, MonoTime now);
    void on_end_data(EndSession &s, uint32_t route_term, MonoTime now, wire::HopAckStatus &ack,
                     uint16_t &retry_ms);
    void run_post(MonoTime now);
    void mark_resend(const DeviceId &origin, uint64_t assignment, const std::array<uint8_t, 16> &mid);
    void send_receipt(InEntry &e, ReceiptEv ev, uint32_t reason, MonoTime now);
    void send_receipt_for(const DeviceId &origin, const std::array<uint8_t, 16> &mid, const Sha256Digest &hash,
                          ReceiptEv ev, uint32_t reason, uint32_t seq, uint64_t expires, ByteView result,
                          MonoTime now);
    [[nodiscard]] InEntry *find_in(const DeviceId &origin, uint64_t assignment, const std::array<uint8_t, 16> &mid);
    [[nodiscard]] Handle alloc_in();
    // live slots of the dedup cache (P1)
    [[nodiscard]] InLive *live_of(InEntry &e) { return e.live == k_no_live ? nullptr : &lives_[e.live]; }
    [[nodiscard]] const InLive *live_of(const InEntry &e) const {
        return e.live == k_no_live ? nullptr : &lives_[e.live];
    }
    [[nodiscard]] InLive *take_live(InEntry &e);
    void drop_live(InEntry &e);
    void settle(InEntry &e);
    void queue_message_event(Handle h, InEntry &e, MonoTime now);
    void want_in_commit(Handle h, InEntry &e, MonoTime now);
    [[nodiscard]] Reply report_result(const ReportRequest &rq, ByteView result, MonoTime now);
    [[nodiscard]] bool seen_accepted(const MacAddr &mac, uint64_t counter) const;
    void note_accepted(const MacAddr &mac, uint64_t counter);

    // -- fragments (fragment.cpp) [S12] --
    enum class SendMode : uint8_t { Api, Object, Control };
    [[nodiscard]] Reply send_mode(SendMode m, const lm_send_request_t &rq, ByteView payload, MonoTime now);
    [[nodiscard]] Reply send_control(const ControlSendRequest &rq, ByteView payload, MonoTime now);
    [[nodiscard]] bool object_enabled() const;
    [[nodiscard]] bool lane_free(Lane lane) const;
    [[nodiscard]] ByteView active_payload(const Active &a) const;
    void free_lane(const Active &a);
    [[nodiscard]] Status seal_fragment(Active &a, Op &op, EndSession &s, const PathSpec &ps, ByteView &record,
                                       bool &parked, MonoTime now);
    void transmit(Handle h, ByteView record, const PathSpec &ps, MonoTime now);
    void on_end_fragment(EndSession &s, uint32_t route_term, MonoTime now, wire::HopAckStatus &ack,
                         uint16_t &retry_ms);
    void on_bitmap(const EndSession &s, const OpenedEnd &o, MonoTime now);
    void frag_refuse(EndSession &s, const Sha256Digest &hash, ReceiptEv ev, Status why, wire::HopAckStatus &ack);
    void frag_release(RxSlot &slot);
    [[nodiscard]] bool control_done_live(const ControlDone &c) const;
    [[nodiscard]] const ControlDone *find_control_done(const EndSession &s, const std::array<uint8_t, 16> &mid,
                                                       const Sha256Digest &hash) const;
    [[nodiscard]] ControlDone *free_control_done();
    void frag_expire(MonoTime now);
    [[nodiscard]] RxSlot *frag_alloc(const wire::FragmentPrefix &p, const wire::EndHeader &eh, uint32_t term,
                                     const EndSession &s, MonoTime now);
    [[nodiscard]] uint8_t *frag_have(RxSlot &slot);
    [[nodiscard]] uint8_t *frag_buf(RxSlot &slot);
    void frag_complete(RxSlot &slot, EndSession &s, uint32_t route_term, MonoTime now, wire::HopAckStatus &ack,
                       uint16_t &retry_ms, const uint8_t *fresh, unsigned n_fresh);
    void send_bitmap(EndSession &s, const wire::EndHeader &hdr, const wire::TransferBitmap &bm, MonoTime now);
    [[nodiscard]] Status send_receipt_fragments(EndSession &s, const PathSpec &ps, const std::array<uint8_t, 16> &mid,
                                                ByteView plain, uint64_t expires, MonoTime now);
    [[nodiscard]] MonoTime frag_deadline() const;
    // shared with the single-frame path (delivery_rx.cpp)
    [[nodiscard]] IntentFields rx_fields(const EndSession &s, const wire::EndHeader &eh, uint32_t route_term,
                                         ByteView payload) const;
    [[nodiscard]] bool data_gate(EndSession &s, const wire::EndHeader &eh, wire::HopAckStatus &ack, uint16_t &retry_ms);
    void admit_data(EndSession &s, uint32_t route_term, ByteView payload, Lane lane, Handle held,
                    const Sha256Digest &hash, MonoTime now, wire::HopAckStatus &ack, uint16_t &retry_ms);

    // -- durable glue (delivery_durable.cpp) --
    static Status durable_fill(void *ctx, const DurableReq &req, MutByteView out, std::size_t &len);
    static void durable_done(void *ctx, const DurableReq &req, Status st, MonoTime now);
    static void durable_boot_done(void *ctx, Status st, MonoTime now);
    static void durable_read_done(void *ctx, uint32_t id, Status st, ByteView record, MonoTime now);
    void want_out_commit(Handle h, Active &a, MonoTime now);
    void request_retire(uint16_t jslot, MonoTime now);
    [[nodiscard]] Active *find_active_j(uint32_t jslot, uint32_t gen, Handle &h);
    [[nodiscard]] InEntry *find_in_j(uint32_t jslot, uint32_t gen, Handle &h);
    template <std::size_t N> [[nodiscard]] static bool alloc_jslot(std::array<bool, N> &used, uint16_t &out) {
        for (std::size_t i = 0; i < N; ++i) {
            if (!used[i]) {
                used[i] = true;
                out = static_cast<uint16_t>(i);
                return true;
            }
        }
        return false;
    }
    void recover_next(MonoTime now);
    void recovered_out(uint32_t slot, ByteView rec, MonoTime now);
    void recovered_in(uint32_t slot, ByteView rec, MonoTime now);

    Engine &engine_;
    member::LocalIdentity &identity_;
    link::LinkLayer &link_;
    DeliveryStats stats_;
    RootTimeBound anchor_;   // last estimate given by the time slice ...
    MonoTime anchor_at_;     // ... and when (local monotonic)
    RootTimeBound bound_;    // the estimate advanced to `now` (widened by the clock drift bound)
    EndSessions sessions_;
    HopTx hop_;
    Durable durable_;

    Pool<MsgBuf, k_build_limits.app_messages> msgs_;
    Pool<Active, k_actives> actives_;
    Pool<InEntry, k_in_entries> in_;
    std::array<InLive, k_in_live> lives_{};
    std::array<Op, k_ops> ops_{};
    route::PathCache<k_routes> routes_; // the node's route table (S11 fills it, tests install)
    std::array<Accepted, k_accepted_ring> accepted_{};
    // Working memory of the RX and TX paths, kept out of the owner stack (docs/02: 4 KiB task).
    OpenedEnd rx_open_;
    PathSpec rx_reply_;
    Post post_;
    std::array<bool, k_actives> out_j_{};   // journal slots of durable sends (held until the retire is durable)
    std::array<bool, k_actives> out_retire_{}; // retire of that slot still to be written
    std::array<bool, k_in_entries> in_j_{}; // journal slots of durable receptions

    FragState frag_;
    SendMode send_mode_ = SendMode::Api; // [S12] set only while send_mode() runs send()
    std::array<uint8_t, wire::data_capacity(1)> frag_plain_{}; // prefix + bytes of the fragment being sealed
    const HostSendRequest *host_tag_ = nullptr; // set only while host_send() runs send()
    const std::array<uint8_t, 16> *child_mid_ = nullptr; // [S15] set only while send_child() runs send()
    GroupHooks group_;
    bool host_gate_ = false;
    bool ready_ = false;
    bool recovering_ = false;
    std::size_t recover_pos_ = 0;
    std::size_t recover_total_ = 0;
    uint64_t next_op_id_ = 1;
    uint64_t next_seq_ = 1;
    uint32_t op_tick_ = 0;
    uint32_t in_tick_ = 0;
    uint32_t arrival_ = 0;
    uint32_t accepted_tick_ = 0;
    MonoTime retry_kick_ = MonoTime::never(); // TX pool was full: try the receipts/frames again
    bool slot_wait_ = false; // a send waits for the node's single exchange slot (any mode)
    MeshHooks mesh_;         // [S11]
};

} // namespace lm::delivery
