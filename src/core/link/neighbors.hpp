// Authenticated one-hop neighbours and their link sessions (docs/06 §5-§7, docs/09 §2).
//
// A Neighbor is a peer whose credentials were verified and with which a link session (EDHOC
// purpose 1 + SESSION_BIND) exists (`cur`, TX and RX). A replaced session only receives for a short
// grace, so frames already in the air under the old key are not lost and no overlap is unbounded
// (S10). The replaced sessions of all neighbours share two grace slots (S11-D8, P2: rotations are
// rare and 10 s long); when both are busy the one that ends first is dropped.
// Identity of a frame's sender = (MAC, SID) -> session -> full DeviceId. The SID is a receiver-
// assigned handle and never authorises anything alone; AEAD under the session key does.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/ids.hpp"
#include "core/pool.hpp"
#include "core/profile.hpp"
#include "core/radio/peer_registry.hpp"
#include "core/time.hpp"
#include "security/record.hpp"

namespace lm::link {

inline constexpr std::size_t k_max_neighbors = k_build_limits.neighbors;

struct SessionKeys {
    sec::RecordSession rec;
    Sha256Digest ctx_hash{};
    uint32_t rx_sid = 0; // assigned by us: the peer puts it in frames sent to us
    uint32_t tx_sid = 0; // assigned by the peer: we put it in frames sent to it
    MonoTime born;
    MonoTime valid_until = MonoTime::never(); // key lifetime for cur, grace end for prev
    bool active = false;

    void wipe() {
        rec.wipe();
        *this = SessionKeys{};
    }
};

struct Neighbor {
    MacAddr mac;
    DeviceId device;
    ShortAddr address; // lookup hint from the verified MemberCredential, never an identity
    AssignmentGen assignment;
    MembershipGen membership;
    uint8_t role = 0;
    PeerHandle peer;
    SessionKeys cur;
    // SEC-D3: the peer credential's lease. While it cannot be proven (no root time yet) the session carries no
    // application DATA in either direction (SDK control, e.g. time sync and registration, passes).
    RootTime lease;
    bool lease_uncertain = false;
    bool rotate_wanted = false; // tx record threshold reached (seal() sets it)
    // [S8-D1] JOIN_ONLY session (docs/06 §4 membership 0): carries the join control objects only,
    // never DATA/ROUTE, never rotates, and is invisible to find_device(). One per joining device.
    bool join_only = false;
};

class Neighbors {
  public:
    using Table = Pool<Neighbor, k_max_neighbors>;

    // Ordinary link neighbours only: a JOIN_ONLY entry of the same device is not returned.
    [[nodiscard]] Neighbor *find_device(const DeviceId &d);
    [[nodiscard]] const Neighbor *find_device(const DeviceId &d) const;
    // [S8-D1] The JOIN_ONLY entry of `d` (nullptr when none).
    [[nodiscard]] Neighbor *find_join(const DeviceId &d);
    // Ordinary link neighbours only (JOIN_ONLY entries are looked up by SID / find_join()).
    [[nodiscard]] Neighbor *find_mac(const MacAddr &m);
    // The neighbour at `mac` that has a session (cur or prev) whose rx SID is `sid`.
    [[nodiscard]] Neighbor *by_rx_sid(const MacAddr &mac, uint32_t sid, SessionKeys *&which);
    // Session of `mac` whose peer-assigned SID is `sid` (SESSION_BIND retransmissions).
    [[nodiscard]] Neighbor *by_tx_sid(const MacAddr &mac, uint32_t sid);
    [[nodiscard]] bool sid_in_use(uint32_t sid) const;

    // A replaced session keeps receiving until `until` (receive-only, shared slots).
    void retire(const MacAddr &mac, SessionKeys &&old, MonoTime until);
    [[nodiscard]] bool has_grace(const MacAddr &mac) const;

    // Allocates the neighbour entry (NoCapacity when the table is full: nothing is evicted).
    [[nodiscard]] Neighbor *acquire();
    void remove(Neighbor &n);

    // Drops sessions past their deadline and neighbours without any session. Peer handles of
    // removed neighbours are appended to `released` (the caller frees them with the driver).
    std::size_t sweep(MonoTime now, PeerHandle *released, std::size_t cap);
    [[nodiscard]] MonoTime next_expiry() const;

    template <class F> void for_each(F &&f) { table_.for_each(f); }
    [[nodiscard]] std::size_t count() const { return table_.in_use(); }

  private:
    static constexpr std::size_t k_grace_slots = 2;
    struct Grace {
        MacAddr mac;
        SessionKeys keys;
    };
    Table table_;
    std::array<Grace, k_grace_slots> grace_{};
};

} // namespace lm::link
