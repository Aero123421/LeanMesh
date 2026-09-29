// A resolved source route from this node to one destination (docs/04 §2, docs/09 §3). The
// route header of every frame is built from it; the same shape describes the reverse of a received
// route, which is how a destination answers without any lookup.
#pragma once

#include <array>
#include <cstdint>

#include "core/ids.hpp"
#include "core/wire/frame.hpp"

namespace lm::delivery {

struct PathSpec {
    ShortAddr origin; // this node
    ShortAddr dest;   // last entry of `path`
    uint8_t len = 0;
    std::array<uint16_t, wire::k_max_path> path{}; // origin's next hop .. dest
    RootTerm term;
    PathRevision revision;

    [[nodiscard]] uint16_t first_hop() const { return len > 0 ? path[0] : 0; }
    [[nodiscard]] wire::RouteHeader header() const {
        wire::RouteHeader h;
        h.origin = origin.value();
        h.final = dest.value();
        h.path_len = len;
        h.next_index = 0;
        h.budget = len;
        h.root_term = term.value();
        h.path_revision = revision.value();
        h.path = path;
        return h;
    }
};

// The way back for a frame that arrived with `h` at its final node `self` (h.path ends at self).
[[nodiscard]] inline PathSpec reverse_route(const wire::RouteHeader &h, ShortAddr self) {
    PathSpec r;
    r.origin = self;
    r.dest = ShortAddr{h.origin};
    r.len = h.path_len;
    // path' = path[len-2] .. path[0], origin
    for (unsigned i = 0; i + 1 < h.path_len; ++i) {
        r.path[i] = h.path[h.path_len - 2U - i];
    }
    r.path[h.path_len - 1U] = h.origin;
    r.term = RootTerm{h.root_term};
    r.revision = PathRevision{h.path_revision};
    return r;
}

} // namespace lm::delivery
