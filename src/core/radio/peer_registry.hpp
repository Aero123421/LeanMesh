// Owner-side registry of the driver's ESP-NOW peers (docs/03 §2): 16 regular + 3 transient
// (Join/repair) + 1 broadcast = 20. The classes never borrow from each other, so a repair burst
// cannot evict a regular neighbour and a full regular set cannot block a Join handoff.
// A slot is addressed by (class, Handle{index, generation}); a stale handle from before a
// release/reuse resolves to nothing. Registering a peer costs a driver call; a failure of that call
// or a full class is reported as a local resource error and never as RF loss.
#pragma once

#include <array>
#include <cstdint>

#include "core/ids.hpp"
#include "core/pool.hpp"
#include "core/ports.hpp"
#include "gen/registry.hpp"

namespace lm {

enum class PeerClass : uint8_t { Regular, Transient };

struct PeerHandle {
    PeerClass cls = PeerClass::Regular;
    Handle slot;
    [[nodiscard]] bool is_none() const { return slot.is_none(); }
};

class PeerRegistry {
  public:
    static constexpr std::size_t k_regular = gen::limits::regular_peers;
    static constexpr std::size_t k_transient = gen::limits::transient_peers;
    static_assert(k_regular + k_transient + gen::limits::broadcast_peers == 20, "docs/03 §2");

    // Registers `mac` with the driver and reserves a slot in `cls`. Idempotent for the same MAC in
    // the same class (returns the existing handle); Conflict when the MAC lives in the other class;
    // NoCapacity when the class is full (nothing is evicted); InvalidArgument for broadcast.
    [[nodiscard]] Status acquire(port::Radio &radio, const MacAddr &mac, PeerClass cls,
                                 PeerHandle &out);
    // Removes the peer from the driver, then frees the slot. Stale handles: NotFound. When the
    // driver refuses the removal the slot stays reserved (no leak, no reuse) and the error returns.
    [[nodiscard]] Status release(port::Radio &radio, PeerHandle h);
    // Join/repair handoff: a transient peer becomes a regular neighbour without touching the driver.
    // NoCapacity keeps the transient reservation so the caller can retry or release it.
    [[nodiscard]] Status promote(PeerHandle transient, PeerHandle &regular_out);
    // After a radio re-initialisation the driver is empty: register every live peer again.
    [[nodiscard]] Status reapply(port::Radio &radio) const;
    // Radio stopped: forget nothing (owners keep their handles) but there is no driver state.

    [[nodiscard]] bool has(const MacAddr &mac) const;
    [[nodiscard]] bool valid(PeerHandle h) const;
    [[nodiscard]] const MacAddr *mac_of(PeerHandle h) const;
    [[nodiscard]] std::size_t regular_count() const { return regular_.in_use(); }
    [[nodiscard]] std::size_t transient_count() const { return transient_.in_use(); }

  private:
    struct Entry {
        MacAddr mac;
    };
    [[nodiscard]] bool find(const MacAddr &mac, PeerHandle &out) const;

    Pool<Entry, k_regular> regular_;
    Pool<Entry, k_transient> transient_;
};

} // namespace lm
