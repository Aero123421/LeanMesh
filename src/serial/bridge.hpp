// Root side of the Host bridge (S13, docs/19 §4-§7, protocol/serial.cddl): the 15 serial methods mapped
// onto the device core, and the root -> Host event stream. It is the root's application executor (D5):
// it runs on the mesh owner as the sink of the ACTIVE USB session and calls Engine::execute() directly,
// so it needs no OwnerCall and no thread of its own.
//
// Ownership and limits (no queue is unbounded; nothing is copied into a second buffer):
//   pending_  replies owed for REQUEST records (<= the data-lane window; a request's credit returns when
//             its reply left). It holds the method's status and small inputs of the result; the result
//             itself is written into the USB transmit buffer when the reply is sent (read-only methods
//             read the core at that moment)
//   ring_     events taken from the engine's app queue and not yet settled by the Host (8 slots). A slot
//             is a reference: the event header only. The body, and a MESSAGE's payload (which the core
//             keeps in its message pool until HOST_STORE_ACK, S13-D11), is built into the transmit buffer
//             at every (re)send. A MESSAGE settles only at HOST_STORE_ACK (the Host's DB commit,
//             docs/11 §5); every other event at EVENT_ACK. Unsettled events are sent again on a new
//             session and on a slow timer. When the ring is full the bridge stops taking events: the
//             engine's own queue then bounds them and reports a GAP, the Host reconciles by GET_MESSAGE.
//             Nothing is dropped silently.
// Evidence is never invented: a result carries what the core reports (accepted / persisted / sent /
// HOP_ACCEPTED / END_RECEIVED / APP_*) and methods whose module does not exist answer UNSUPPORTED.
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "core/engine.hpp"
#include "core/ring.hpp"
#include "serial/root_usb.hpp"

namespace lm::serial {

struct BridgeStats {
    uint64_t requests = 0;
    uint64_t malformed = 0;       // dropped: not a well-formed REQUEST envelope
    uint64_t replies = 0;
    uint64_t replies_dropped = 0; // session gone or reply queue full: the Host reconciles
    uint64_t events_queued = 0;
    uint64_t events_sent = 0;
    uint64_t events_resent = 0;
    uint64_t events_settled = 0;
    uint64_t events_gone = 0;     // a MESSAGE whose payload the core no longer holds: not sent, GET_MESSAGE
    uint64_t host_store_acks = 0;
    uint64_t send_accepted = 0;
    uint64_t send_refused = 0;
};

// What a snapshot result needs of lm_operation_t (the rest is not on the wire).
struct OpSnap {
    uint32_t phase = 0;
    uint32_t reason = 0;
    uint32_t outcome = 0;
    uint32_t evidence_bits = 0;
    std::array<uint8_t, 16> message_id{};
    std::array<uint8_t, 32> intent_hash{};

    static OpSnap of(const lm_operation_t &o) {
        OpSnap s;
        s.phase = o.phase;
        s.reason = o.reason;
        s.outcome = o.outcome;
        s.evidence_bits = o.evidence_bits;
        std::memcpy(s.message_id.data(), o.message_id.bytes, 16);
        std::memcpy(s.intent_hash.data(), o.intent_hash, 32);
        return s;
    }
};

// The part of lm_event_t an event's body is built from: what a ring slot keeps (a reference, not the payload).
struct EvRef {
    uint32_t kind = 0;
    uint32_t reason = 0;
    uint64_t operation = 0;
    uint64_t assignment = 0; // origin_assignment_generation
    uint16_t app_port = 0;
    std::array<uint8_t, 32> peer{};
    std::array<uint8_t, 16> message_id{};
    std::array<uint8_t, 32> intent_hash{};

    static EvRef of(const lm_event_t &e) {
        EvRef r;
        r.kind = e.kind;
        r.reason = e.reason;
        r.operation = e.operation_id;
        r.assignment = e.origin_assignment_generation;
        r.app_port = e.app_port;
        std::memcpy(r.peer.data(), e.peer.bytes, 32);
        std::memcpy(r.message_id.data(), e.message_id.bytes, 16);
        std::memcpy(r.intent_hash.data(), e.intent_hash, 32);
        return r;
    }
    // For the core's lookups (Delivery::event_payload names a MESSAGE by kind, origin, assignment generation and MessageId).
    [[nodiscard]] lm_event_t event() const {
        lm_event_t e{};
        e.struct_size = sizeof(e);
        e.abi_version = LM_ABI_VERSION;
        e.kind = kind;
        e.origin_assignment_generation = assignment;
        std::memcpy(e.peer.bytes, peer.data(), 32);
        std::memcpy(e.message_id.bytes, message_id.data(), 16);
        return e;
    }
};

class Bridge final : public BridgeHook {
  public:
    static constexpr std::size_t k_ring = 8;
    static constexpr std::size_t k_pending = RootUsb::k_pending_replies;
    static constexpr Duration k_event_retry = Duration::from_s(5);

    Bridge(Engine &engine, RootUsb &usb, uint64_t boot_id);
    Bridge(const Bridge &) = delete;
    Bridge &operator=(const Bridge &) = delete;
    // Detaches from the adapter only: the engine may already be gone (a reset of the root).
    ~Bridge() { usb_.set_bridge(nullptr); }

    // BridgeHook
    void on_session(bool up, uint32_t gen, UsbDown why) override;
    void on_record(SerialKind kind, uint8_t lane, uint32_t frame_bytes, ByteView payload, uint32_t gen) override;
    void on_tx_ready() override { flush(); }
    void on_step(MonoTime now) override;
    [[nodiscard]] MonoTime deadline() const override;

    [[nodiscard]] const BridgeStats &stats() const { return stats_; }
    [[nodiscard]] std::size_t ring_used() const;
    [[nodiscard]] uint64_t boot_id() const { return boot_; }

  private:
    enum class Result : uint8_t { None, Snapshot, Ack, Caps, Nodes, Request, Targets, Diag, BackupPage };
    struct Pending {
        std::array<uint8_t, 16> request_id{};
        uint8_t lane = 0;
        uint32_t frame_bytes = 0;
        Status status = Status::Unsupported;
        bool has_op = false;
        uint64_t op = 0;
        Result result = Result::None;
        bool has_filter = false; // NODE_QUERY: `filter` names one device
        struct GroupPage { // Targets: which page of which group operation (S15)
            std::array<uint8_t, 16> token;
            uint32_t offset;
            uint32_t limit;
        };
        struct BackupAt { // BackupPage: which page of which backup (ISSUE5)
            uint64_t seq;
            uint32_t index;
        };
        union {
            OpSnap snap;                      // Snapshot, Request
            std::array<uint8_t, 32> filter;   // Nodes
            GroupPage page;                   // Targets
            BackupAt backup;                  // BackupPage
        };
        Pending() : snap() {}
    };
    struct Slot {
        bool used = false;
        bool acked = false;       // EVENT_ACK covered it
        bool stored = false;      // MESSAGE: HOST_STORE_ACK arrived
        uint32_t sent_gen = 0;    // session generation it was last sent under (0: not sent)
        MonoTime sent_at = MonoTime::never();
        uint64_t seq = 0;
        EvRef ev;                 // the reference: MESSAGE payloads stay in the core's message pool
    };

    // request handling (bridge_methods.cpp)
    void handle(Pending &p, uint64_t method, ByteView params);
    void m_send(Pending &p, ByteView params);
    void m_get_message(Pending &p, ByteView params);
    void m_cancel(Pending &p, ByteView params);
    void m_join_decide(Pending &p, ByteView params);
    void m_install(Pending &p, ByteView params);
    void m_node_query(Pending &p, ByteView params);
    void m_host_store_ack(Pending &p, ByteView params);
    void m_event_ack(Pending &p, ByteView params);
    void m_get_request(Pending &p, ByteView params);
    void m_channel(Pending &p, ByteView params); // [S17] CHANNEL_ACTION
    void m_policy_set(Pending &p, ByteView params); // HIL-F5: 17 POLICY_SET (the root's join mode)
    void m_backup_begin(Pending &p, ByteView params);   // ISSUE5: 18 LEDGER_BACKUP_BEGIN
    void m_backup_get(Pending &p, ByteView params);     // 19 LEDGER_BACKUP_GET
    void m_restore(Pending &p, uint64_t method, ByteView params); // 20 HANDOVER, 21 HEADER, 22 RECORD of a LEDGER_RESTORE
    void m_group_set(Pending &p, ByteView params);
    void m_group_targets(Pending &p, ByteView params);
    void m_unsupported(Pending &p, uint64_t method, ByteView params);
    [[nodiscard]] Reply run(CommandKind kind, const void *request, std::size_t request_size,
                            ByteView payload = ByteView{}, void *response = nullptr,
                            std::size_t response_size = 0);
    void snapshot_of(Pending &p, uint64_t op);

    // reply / event encoding and transmission (bridge.cpp)
    [[nodiscard]] Status write_reply(const Pending &p, MutByteView out, std::size_t &len);
    [[nodiscard]] Status write_event(Slot &s, bool take, MutByteView out, std::size_t &len);
    [[nodiscard]] std::size_t encode_result(const Pending &p, MutByteView out);
    void flush();
    void flush_replies();
    void flush_events();
    [[nodiscard]] Slot *free_slot();
    void settle(Slot &s);

    Engine &engine_;
    RootUsb &usb_;
    uint64_t boot_;
    BridgeStats stats_{};
    bool active_ = false;
    uint32_t gen_ = 0;
    bool in_flush_ = false;
    bool work_due_ = false; // a command ran or a session changed: look at the event queue again
    uint64_t next_seq_ = 1;
    BoundedQueue<Pending, k_pending> pending_;
    std::array<Slot, k_ring> ring_{};
};

} // namespace lm::serial
