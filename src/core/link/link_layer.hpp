// The link layer of the mesh owner: RX path (header -> domain -> (MAC, SID) -> AEAD -> replay
// commit -> dispatch), TX seal, session lifetime/rotation timers and the node's single handshake
// exchange (link, join and end modes; exchange.hpp). Owner thread only; public-key work runs in
// worker jobs.
//
// Frames that need no session (DISCOVERY, JOIN_PROXY) are not handled here (consumers come with
// the join/mesh slices). Authenticated payloads of the session kinds (DATA, HOP_ACK, ROUTE,
// CONTROL, POWER) go to the RxSink; without a sink they are counted and dropped.
#pragma once

#include <cstdint>

#include "core/link/exchange.hpp"
#include "core/link/neighbors.hpp"
#include "core/link/seal.hpp"

namespace lm::link {

struct RxInfo {
    wire::FrameKind kind = wire::FrameKind::Data;
    MacAddr src;
    DeviceId peer;      // full identity behind the session
    ShortAddr address;  // lookup hint of that peer (never an identity)
    uint64_t counter = 0;
    // Authentic duplicate (already accepted): re-ACK it if the protocol says so, never re-apply.
    bool duplicate = false;
    // SEC-D3: application DATA over a session whose peer lease cannot be proven yet. A sink never applies or
    // forwards it (the engine answers BUSY: a local condition of this node, not RF loss).
    bool restricted = false;
};
using RxSink = void (*)(void *ctx, const RxInfo &info, ByteView plain);

class LinkLayer {
  public:
    LinkLayer(Engine &engine, member::LocalIdentity &identity)
        : identity_(identity), shared_{engine, policy_, stats_, neighbors_, identity, gate_, {}, {}},
          exchange_(shared_) {}

    // ---- owner wiring (Engine calls these) ----
    // False: a valid frame nobody consumes yet (counted as unhandled by the engine).
    [[nodiscard]] bool on_rx(const port::RadioRx &rx, MonoTime now);
    void on_tx_outcome(const TxOutcome &o, MonoTime now) { exchange_.on_tx_outcome(o, now); }
    void on_job_done(Handle slot, Status s, MonoTime now) { exchange_.on_job_done(slot, s, now); }
    void on_timer(MonoTime now);
    [[nodiscard]] MonoTime deadline() const;
    void stop(); // radio stop: exchange aborted, sessions wiped, peers released
    // [S8] an unjoined device may receive the frames of its own JOIN_ONLY handshake/session.

    // ---- services for other modules ----
    // Opens a session with the neighbour at `mac` (initiator). Conflict when a live session exists
    // and `replace` is false; other errors as Exchange::start_initiator().
    [[nodiscard]] Status connect(const MacAddr &mac, MonoTime now, bool replace = false);
    // Seals one frame for the neighbour with a live session. AuthPending: no session yet.
    // SessionRefreshRequired: key lifetime over. The bytes are what a retransmission sends again.
    [[nodiscard]] Status seal(const DeviceId &peer, wire::FrameKind kind, ByteView plain,
                              SealedFrame &out, MonoTime now);
    // Seals one frame for `peer` and hands it to the radio for `mac` (Engine::transmit: `tag`, charged as CONTROL).
    // The first failure of either step is the result (AuthPending / Busy / DriverResultUnknown ...).
    [[nodiscard]] Status send_sealed(const DeviceId &peer, const MacAddr &mac, wire::FrameKind kind, ByteView plain,
                                     uint32_t tag, MonoTime now);
    // Closes every session with `peer` (revocation, leave). No message is sent.
    [[nodiscard]] Status close(const DeviceId &peer);
    // SEC-D3: the root-time estimate changed (`bound` is the one for `now`). Every session is judged by its peer's
    // lease again: provably over ends it, provable caps its life at the lease and lifts the restriction,
    // unprovable restricts it. Link and end sessions alike.
    void revalidate(const RootTimeBound &bound, MonoTime now);

    // ---- [S8] JOIN_ONLY sessions (docs/07 §4) ----
    // Seals one join control object (frame kind CONTROL) for the JOIN_ONLY session of `peer`. Only
    // this call can use such a session; seal() never sees it. `domain_hint` is the target domain the
    // joiner learned from the root's delegation. AuthPending: no session. Expired: session over.
    [[nodiscard]] Status seal_join(const DeviceId &peer, uint32_t domain_hint, ByteView plain,
                                   SealedFrame &out, MonoTime now);
    // Ends the JOIN_ONLY session of `peer` (join done/failed): keys wiped, transient peer released.
    [[nodiscard]] Status close_join(const DeviceId &peer);
    [[nodiscard]] JoinHooks &join_hooks() { return shared_.join; }
    // A finished admission (JOIN_ONLY handshake, then ACTIVE) and the first ordinary handshake with the
    // same peer are one admission, not two full handshakes in 30 s (decision S8-D6).
    void forget_handshake_gate(const MacAddr &mac) { gate_.forget(mac); }
    [[nodiscard]] Exchange &exchange() { return exchange_; }

    void set_sink(RxSink sink, void *ctx) {
        sink_ = sink;
        sink_ctx_ = ctx;
    }
    // [S11] DISCOVERY frames (SID 0 hints and beacons) go to the mesh; they authorise nothing.
    // [S11] A frame of a device that is not a neighbour (a joiner behind us): true = the relay took it.
    using ProxySink = bool (*)(void *ctx, const port::RadioRx &rx, MonoTime now);
    void set_proxy_sink(ProxySink sink, void *ctx) {
        proxy_sink_ = sink;
        proxy_ctx_ = ctx;
    }
    using DiscoverySink = void (*)(void *ctx, const MacAddr &src, ByteView body, MonoTime now);
    void set_discovery_sink(DiscoverySink sink, void *ctx) {
        disc_sink_ = sink;
        disc_ctx_ = ctx;
    }
    void set_root_time(const RootTimeBound &t) { shared_.root_time = t; }
    // No rotation starts before `until` (the renewals after a root restart must not rotate every link at once).
    void hold_rotations(MonoTime until) { rotation_retry_ = rotation_retry_ < until ? until : rotation_retry_; }
    LinkPolicy &policy() { return policy_; }
    [[nodiscard]] const LinkPolicy &policy() const { return policy_; }
    [[nodiscard]] const LinkStats &stats() const { return stats_; }
    Neighbors &neighbors() { return neighbors_; }
    [[nodiscard]] const Neighbors &neighbors() const { return neighbors_; }
    [[nodiscard]] const Exchange &exchange() const { return exchange_; }

  private:
    [[nodiscard]] bool deliver(const Neighbor &n, const wire::LinkHeader &h, const Opened &op,
                               bool duplicate, bool restricted = false);
    // SEC-D11: may this fresh authentic frame's counter enter the replay window?
    [[nodiscard]] bool admissible(const Neighbor &n, wire::FrameKind kind, ByteView plain) const;
    [[nodiscard]] MonoTime rotation_time(const Neighbor &n) const;
    [[nodiscard]] bool has_join_session() {
        bool any = false;
        neighbors_.for_each([&](Handle, Neighbor &n) { any = any || n.join_only; });
        return any;
    }

    member::LocalIdentity &identity_;
    LinkPolicy policy_;
    LinkStats stats_;
    Neighbors neighbors_;
    RateGate<MacAddr> gate_;
    LinkShared shared_;
    Exchange exchange_;
    RxSink sink_ = nullptr;
    void *sink_ctx_ = nullptr;
    ProxySink proxy_sink_ = nullptr;
    void *proxy_ctx_ = nullptr;
    DiscoverySink disc_sink_ = nullptr;
    void *disc_ctx_ = nullptr;
    MonoTime rotation_retry_ = MonoTime{0};
};

} // namespace lm::link
