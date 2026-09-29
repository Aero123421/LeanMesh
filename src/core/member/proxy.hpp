// Join proxy (docs/07 §3-§4, decision S11-D3): an unjoined device that cannot reach the root joins through
// a member relay any number of hops away. The relay is a dumb pipe. The device talks to it exactly as to
// a root at one hop (same JOIN_PROXY carriers, same JOIN_ONLY session frames); the relay wraps each of the
// device's frames into routed tunnel records, the root unwraps them and feeds them to its link layer as
// if they had come from a radio, and answers the same way back. EDHOC is between device and root, so the
// relay learns and decides nothing (J01: no approval authority; a relay may drop or delay, not forge).
//
//   record  end record, end_sid k_tunnel_sid, kind CONTROL, port 0, plaintext = joiner MAC (6) | JoinChunk
//           (the one in-order chunk codec, ARCH-D3), tag field zero; hop by hop HOP_ACKed like every routed
//           frame, one chunk in flight, so a 250 B frame crosses 20 hops as three chunks.
//   buffers one outgoing and one incoming frame (250 B each) per node, shared by all tunnels; a busy pipe
//           refuses (radio Busy to the sender, or a dropped frame the joiner's retransmission repeats).
//   tables  `join_slots` joiner MACs (relay 2, root 4). A slot opened by an unauthenticated CredI start is unproven:
//           it lives k_proxy_preauth from its start whatever the joiner sends, one start per k_proxy_start_gap is
//           taken for all sources, and a full table gives its oldest unproven slot to a new start. It becomes a
//           tunnel with the 420 s idle life only once the root answered (relay: an authenticated downlink record;
//           root: its own join machinery sends to the MAC). Review finding 2: spoofed MACs cannot hold the slots.
// Nothing here keeps a secret or a decision. Owner thread only.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/delivery/delivery.hpp"
#include "core/member/join_wire.hpp"
#include "core/ports.hpp"
#include "core/radio/peer_registry.hpp"

namespace lm {
class Engine;
}

namespace lm::member {

// A leaf build can never relay (build_supports): its tunnel keeps no buffers.
inline constexpr bool k_proxy_built = build_supports(Role::Relay);
inline constexpr std::size_t k_proxy_entries = k_proxy_built ? k_build_limits.join_slots : 1;
inline constexpr std::size_t k_proxy_frame = k_proxy_built ? port::k_max_frame_bytes : 1;
inline constexpr uint32_t k_tag_proxy = 0x4A560000;   // "JV": TX completion of a frame handed to a joiner
inline constexpr Duration k_proxy_idle = Duration::from_s(420); // JOIN_ONLY session life (approval + prepared)
inline constexpr Duration k_proxy_preauth = Duration::from_s(30); // the exchange's own deadline (session_binding)
inline constexpr Duration k_proxy_start_gap = Duration::from_s(1);
inline constexpr std::size_t k_proxy_mac = 6;

class Proxy {
  public:
    explicit Proxy(Engine &engine) : engine_(engine) {}
    Proxy(const Proxy &) = delete;
    Proxy &operator=(const Proxy &) = delete;

    void stop();
    void on_timer(MonoTime now);
    [[nodiscard]] MonoTime deadline() const;

    // ---- relay side ----
    // A frame from a device that is not a neighbour (unicast to us). True: consumed (forwarded or dropped).
    [[nodiscard]] bool from_joiner(const port::RadioRx &rx, MonoTime now);
    // A joiner's broadcast hello: offer to relay (rate-limited; only an attached relay answers).
    void answer_hello(const wire::BootstrapCarrier &hello, MonoTime now);

    // ---- both sides ----
    void on_record(const delivery::PathSpec &reply, ByteView plain, MonoTime now);
    void on_frame_done(const delivery::FrameDone &f, delivery::HopEnd end, MonoTime now);

    // ---- root side: frames the join machinery sends to a joiner's MAC ----
    [[nodiscard]] bool owns(const MacAddr &mac) const;
    [[nodiscard]] Status transmit(const MacAddr &mac, ByteView frame, uint32_t tag, MonoTime now);

    struct Stats {
        uint64_t up = 0, down = 0, dropped_busy = 0, dropped_full = 0, lost = 0;
    };
    [[nodiscard]] const Stats &stats() const { return stats_; }
    [[nodiscard]] std::size_t entries() const;

  private:
    struct Entry {
        bool used = false;
        MacAddr mac;
        uint16_t proxy_addr = 0; // root side: the relay this joiner is behind
        PeerHandle peer;         // relay side: transient driver registration to transmit to the joiner
        MonoTime last{};
        MonoTime born{};
        bool proven = false;     // the root answered this joiner (see the header comment)
        [[nodiscard]] MonoTime expiry() const { return proven ? last + k_proxy_idle : born + k_proxy_preauth; }
    };
    struct Out { // the frame being carried through the route
        bool active = false, inflight = false;
        std::array<uint8_t, k_proxy_frame> bytes{};
        std::size_t len = 0, off = 0;
        MacAddr mac;
        uint16_t dest = 0; // root side: relay address
        uint8_t id = 0;
        uint32_t tag = 0;  // root side: TX tag the join machinery waits for
    };
    struct In { // the frame being assembled from the route (or waiting for the radio)
        bool active = false, ready = false;
        std::array<uint8_t, k_proxy_frame> bytes{};
        std::size_t len = 0, total = 0;
        MacAddr mac;
        uint8_t id = 0;
    };

    [[nodiscard]] bool is_root() const;
    [[nodiscard]] Entry *find(const MacAddr &mac);
    [[nodiscard]] Entry *add(const MacAddr &mac, MonoTime now);
    void free_entry(Entry &e);
    [[nodiscard]] bool route_to(uint16_t dest, delivery::PathSpec &out, MonoTime now);
    void pump_out(MonoTime now);
    void finish_out(bool ok, MonoTime now);
    void deliver_in(MonoTime now);
    void start_out(const MacAddr &mac, ByteView frame, uint16_t dest, uint32_t tag, MonoTime now, bool defer);

    Engine &engine_;
    std::array<Entry, k_proxy_entries> table_{};
    Out out_;
    In in_;
    Stats stats_;
    uint64_t seq_ = 0;
    uint8_t next_id_ = 1;
    MonoTime retry_at_ = MonoTime::never();
    MonoTime last_offer_{};
    MonoTime next_start_{}; // the next unproven slot may open then (one bucket for all sources)
    MonoTime outcome_at_ = MonoTime::never(); // root: the TX result of the last frame is reported then
    uint32_t outcome_tag_ = 0;
    bool outcome_ok_ = false;
};

} // namespace lm::member
