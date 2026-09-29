// Bounded cache of resolved source routes for application destinations (docs/04 §2: leaf 4,
// relay 4, root 64 entries): the node's one route table (the delivery module sends by it; ARCH-D4).
// Full: the least recently used entry is replaced (a cache miss only costs a ROUTE_QUERY). An entry
// is valid only for its root_term, its local expiry and until an address on it changes membership
// (invalidate_addr). A route older than the cached revision of the same destination never replaces
// it. Sends are addressed by DeviceId, so an entry may also name the destination's identity.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/ids.hpp"
#include "core/status.hpp"
#include "core/time.hpp"
#include "gen/registry.hpp"

namespace lm::route {

struct CachedRoute {
    ShortAddr destination{};
    DeviceId device{}; // the destination's identity when known (all zero: address only)
    RootTerm root_term{};
    PathRevision revision{};
    uint8_t len = 0;
    std::array<uint16_t, gen::limits::path_hops> path{}; // origin's next hop .. destination
};

template <std::size_t N> class PathCache {
  public:
    static constexpr std::size_t capacity() { return N; }

    // InvalidArgument: not a simple path ending at `destination` (self is excluded by the caller
    // via `self`). Conflict: an entry of the same term already has a newer revision.
    [[nodiscard]] Status put(ShortAddr self, const CachedRoute &r, MonoTime expires);
    // A route learned from traffic (the reverse of an authenticated record's path): stored only
    // when no entry of the same term is at least as new, so what traffic showed never downgrades
    // a resolved route or shortens its lifetime.
    [[nodiscard]] Status learn(ShortAddr self, const CachedRoute &r, MonoTime expires);
    // NotFound when absent, from another root_term, or expired (the entry is dropped then).
    [[nodiscard]] Status lookup(ShortAddr destination, RootTerm term, MonoTime now,
                                CachedRoute &out);
    [[nodiscard]] Status lookup(const DeviceId &device, RootTerm term, MonoTime now,
                                CachedRoute &out);
    void invalidate_destination(ShortAddr destination);
    void invalidate_device(const DeviceId &device);
    // Drops every route that uses `a` as hop or destination (membership_generation change).
    void invalidate_addr(ShortAddr a);
    void clear() { // slot by slot: no whole-table temporary on the owner stack (root: 64 routes)
        for (Slot &s : slots_) {
            s = Slot{};
        }
        tick_ = 0;
    }
    [[nodiscard]] std::size_t size() const;

  private:
    struct Slot {
        bool used = false;
        uint32_t last_use = 0;
        MonoTime expires{};
        CachedRoute route{};
    };
    // One entry per destination: same address, or same (known) identity.
    [[nodiscard]] static bool same_destination(const CachedRoute &a, const CachedRoute &b) {
        return a.destination == b.destination || (!b.device.is_zero() && a.device == b.device);
    }
    template <class Match>
    Status lookup_if(Match match, RootTerm term, MonoTime now, CachedRoute &out);

    std::array<Slot, N> slots_{};
    uint32_t tick_ = 0;
};

Status check_cache_route(ShortAddr self, const CachedRoute &r);

template <std::size_t N>
Status PathCache<N>::put(ShortAddr self, const CachedRoute &r, MonoTime expires) {
    LM_TRY(check_cache_route(self, r));
    Slot *target = nullptr;
    for (Slot &s : slots_) {
        if (s.used && same_destination(s.route, r) && s.route.root_term == r.root_term &&
            r.revision < s.route.revision) {
            return Status::Conflict;
        }
    }
    for (Slot &s : slots_) {
        if (s.used && same_destination(s.route, r)) {
            s = Slot{}; // the destination moved or got a newer route: one entry remains
        }
        if (target == nullptr && !s.used) {
            target = &s;
        }
    }
    if (target == nullptr) {
        target = &slots_[0];
        for (Slot &s : slots_) {
            // Wrap-safe age comparison.
            if (static_cast<int32_t>(s.last_use - target->last_use) < 0) {
                target = &s;
            }
        }
    }
    *target = Slot{true, ++tick_, expires, r};
    return Status::Ok;
}

template <std::size_t N>
Status PathCache<N>::learn(ShortAddr self, const CachedRoute &r, MonoTime expires) {
    for (const Slot &s : slots_) {
        if (s.used && same_destination(s.route, r) && s.route.root_term == r.root_term &&
            !(s.route.revision < r.revision)) {
            return Status::Ok;
        }
    }
    return put(self, r, expires);
}

template <std::size_t N>
template <class Match>
Status PathCache<N>::lookup_if(Match match, RootTerm term, MonoTime now, CachedRoute &out) {
    for (Slot &s : slots_) {
        if (!s.used || !match(s.route)) {
            continue;
        }
        if (s.route.root_term != term || now >= s.expires) {
            s = Slot{};
            return Status::NotFound;
        }
        s.last_use = ++tick_;
        out = s.route;
        return Status::Ok;
    }
    return Status::NotFound;
}

template <std::size_t N>
Status PathCache<N>::lookup(ShortAddr destination, RootTerm term, MonoTime now, CachedRoute &out) {
    const auto match = [&](const CachedRoute &r) { return r.destination == destination; };
    return lookup_if(match, term, now, out);
}

template <std::size_t N>
Status PathCache<N>::lookup(const DeviceId &device, RootTerm term, MonoTime now, CachedRoute &out) {
    const auto match = [&](const CachedRoute &r) { return !device.is_zero() && r.device == device; };
    return lookup_if(match, term, now, out);
}

template <std::size_t N> void PathCache<N>::invalidate_destination(ShortAddr destination) {
    for (Slot &s : slots_) {
        if (s.used && s.route.destination == destination) {
            s = Slot{};
        }
    }
}

template <std::size_t N> void PathCache<N>::invalidate_device(const DeviceId &device) {
    for (Slot &s : slots_) {
        if (s.used && !device.is_zero() && s.route.device == device) {
            s = Slot{};
        }
    }
}

template <std::size_t N> void PathCache<N>::invalidate_addr(ShortAddr a) {
    for (Slot &s : slots_) {
        if (!s.used) {
            continue;
        }
        bool hit = s.route.destination == a;
        for (std::size_t i = 0; i < s.route.len && !hit; ++i) {
            hit = s.route.path[i] == a.value();
        }
        if (hit) {
            s = Slot{};
        }
    }
}

template <std::size_t N> std::size_t PathCache<N>::size() const {
    std::size_t n = 0;
    for (const Slot &s : slots_) {
        n += s.used ? 1U : 0U;
    }
    return n;
}

} // namespace lm::route
