// Root side of the Host bridge (S13, docs/19 §4-§7, protocol/serial.cddl): the 15 serial methods mapped
// onto the device core, and the root -> Host event stream. It is the root's application executor (D5):
// it runs on the mesh owner as the sink of the ACTIVE USB session and calls Engine::execute() directly,
// so it needs no OwnerCall and no thread of its own.
//
// Ownership and limits (no queue is unbounded):
//   pending_  replies owed for REQUEST records (<= the data-lane window; a request's credit returns when
//             its reply left); results of read-only methods are computed when the reply is sent
//   ring_     events taken from the engine's app queue and not yet settled by the Host (8 slots).
//             A MESSAGE settles only at HOST_STORE_ACK (the Host's DB commit, docs/11 §5); every other
//             event at EVENT_ACK. Unsettled events are sent again on a new session and on a slow timer.
//             When the ring is full the bridge stops taking events: the engine's own queue then bounds
//             them and reports a GAP, the Host reconciles by GET_MESSAGE. Nothing is dropped silently.
// Evidence is never invented: a result carries what the core reports (accepted / persisted / sent /
// HOP_ACCEPTED / END_RECEIVED / APP_*) and methods whose module does not exist answer UNSUPPORTED.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

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
    uint64_t host_store_acks = 0;
    uint64_t send_accepted = 0;
    uint64_t send_refused = 0;
};

class Bridge final : public BridgeHook {
  public:
    static constexpr std::size_t k_ring = 8;
    static constexpr std::size_t k_pending = RootUsb::k_pending_replies;
    static constexpr std::size_t k_event_body = 736;
    static constexpr std::size_t k_scratch = 4608;
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
    enum class Result : uint8_t { None, Snapshot, Ack, Caps, Nodes, Request };
    struct Pending {
        std::array<uint8_t, 16> request_id{};
        uint8_t lane = 0;
        uint32_t frame_bytes = 0;
        Status status = Status::Unsupported;
        bool has_op = false;
        uint64_t op = 0;
        Result result = Result::None;
        lm_operation_t snap{};
        bool has_filter = false;
        std::array<uint8_t, 32> filter{};   // NODE_QUERY
        std::array<uint8_t, 16> request{};  // GET_REQUEST
    };
    struct Slot {
        bool used = false;
        bool acked = false;       // EVENT_ACK covered it
        bool needs_store = false; // MESSAGE: settles only at HOST_STORE_ACK
        bool stored = false;
        uint32_t sent_gen = 0;    // session generation it was last sent under (0: not sent)
        MonoTime sent_at = MonoTime::never();
        uint64_t seq = 0;
        uint32_t kind = 0;
        uint16_t len = 0;
        std::array<uint8_t, 32> origin{};
        std::array<uint8_t, 16> mid{};
        std::array<uint8_t, k_event_body> body{};
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
    void m_unsupported(Pending &p, uint64_t method, ByteView params);
    [[nodiscard]] Reply run(CommandKind kind, const void *request, std::size_t request_size,
                            ByteView payload = ByteView{}, void *response = nullptr,
                            std::size_t response_size = 0);
    void snapshot_of(Pending &p, uint64_t op);

    // reply / event encoding and transmission (bridge.cpp)
    [[nodiscard]] std::size_t encode_result(const Pending &p, MutByteView out);
    void flush();
    void flush_replies();
    void flush_events();
    void drain_events();
    void take_event(const lm_event_t &ev, ByteView payload);
    [[nodiscard]] Slot *free_slot();
    void settle(Slot &s);
    [[nodiscard]] Status send_record(SerialKind kind, ByteView head, ByteView body);

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
    std::array<uint8_t, k_scratch> scratch_{};
    std::array<uint8_t, 512> ev_payload_{};
};

} // namespace lm::serial
