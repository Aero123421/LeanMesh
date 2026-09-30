// Source route between two nodes from their root paths (docs/04 §1: the path of two members is the
// join of their paths at the lowest common ancestor, 0..40 edges). Pure: the root uses it on its
// topology chains, a node on its own root path and the answer of a ROUTE_QUERY (S11-D5).
#pragma once

#include <cstddef>
#include <cstdint>

#include "core/status.hpp"

namespace lm::route {

// `a` and `b` are root paths, root first and the node itself last (root's own path is [root]).
// `out` receives the route from a's node to b's node: origin excluded, destination last. Both
// chains must start at the same root. InvalidArgument for empty chains or a == b, NoCapacity for
// an `out` that is too small.
[[nodiscard]] inline Status stitch_route(const uint16_t *a, std::size_t na, const uint16_t *b,
                                         std::size_t nb, uint16_t *out, std::size_t cap,
                                         std::size_t &n) {
    if (na == 0 || nb == 0 || a[0] != b[0] || (na == nb && a[na - 1] == b[nb - 1])) {
        return Status::InvalidArgument;
    }
    std::size_t lca = 0; // index of the lowest common ancestor in both chains
    while (lca + 1 < na && lca + 1 < nb && a[lca + 1] == b[lca + 1]) {
        ++lca;
    }
    n = 0;
    for (std::size_t i = na - 1; i-- > lca;) { // a's parent up to the LCA
        if (n == cap) {
            return Status::NoCapacity;
        }
        out[n++] = a[i];
    }
    for (std::size_t i = lca + 1; i < nb; ++i) { // down to b
        if (n == cap) {
            return Status::NoCapacity;
        }
        out[n++] = b[i];
    }
    return Status::Ok;
}

} // namespace lm::route
