#include "root/topology.hpp"

#include <algorithm>

#include "core/wire/frame.hpp"
#include "gen/defaults.hpp"

namespace lm::root {

namespace {

using Chain = std::array<uint16_t, k_max_depth + 1>;

void fill_grant(const Chain &chain, std::size_t n, uint16_t self, bool append_self,
                uint32_t revision, uint64_t lease_expires_ms, RouteGrant &out) {
    out = RouteGrant{};
    std::copy(chain.begin(), chain.begin() + static_cast<std::ptrdiff_t>(n), out.path.begin());
    out.len = static_cast<uint8_t>(n);
    if (append_self) {
        out.path[out.len++] = self;
    }
    out.revision = PathRevision{revision};
    out.lease_expires_ms = lease_expires_ms;
}

} // namespace

uint8_t Topology::find_addr(uint16_t addr) const {
    if (addr == root_addr_.value()) {
        return k_root;
    }
    for (std::size_t i = 0; i < nodes_.size(); ++i) {
        if (nodes_[i].used && nodes_[i].addr == addr) {
            return static_cast<uint8_t>(i);
        }
    }
    return k_none;
}

uint8_t Topology::find_id(const DeviceId &id) const {
    for (std::size_t i = 0; i < nodes_.size(); ++i) {
        if (nodes_[i].used && nodes_[i].id == id) {
            return static_cast<uint8_t>(i);
        }
    }
    return k_none;
}

uint32_t Topology::revision_of(uint8_t idx) const { return idx == k_root ? 0U : nodes_[idx].revision; }

Status Topology::chain(uint8_t idx, const uint64_t *now, Chain &out, std::size_t &n) const {
    Chain rev{};
    std::size_t steps = 0;
    for (uint8_t cur = idx; cur != k_root; cur = nodes_[cur].parent) {
        if (cur == k_none || !nodes_[cur].active) {
            return Status::NoRoute;
        }
        if (now != nullptr && *now >= nodes_[cur].lease_expires_ms) {
            return Status::NoRoute;
        }
        if (steps >= k_max_depth) {
            return Status::RecoveryRequired; // a link chain deeper than 20 must never exist
        }
        rev[steps++] = nodes_[cur].addr;
    }
    out[0] = root_addr_.value();
    for (std::size_t i = 0; i < steps; ++i) {
        out[i + 1] = rev[steps - 1 - i];
    }
    n = steps + 1;
    return Status::Ok;
}

std::size_t Topology::distance_below(uint8_t node, uint8_t ancestor) const {
    uint8_t cur = node;
    for (std::size_t d = 1; d <= nodes_.size(); ++d) {
        const uint8_t p = nodes_[cur].active ? nodes_[cur].parent : k_none;
        if (p == ancestor) {
            return d;
        }
        if (p == k_root || p == k_none) {
            return 0;
        }
        cur = p;
    }
    return 0;
}

std::size_t Topology::subtree_height(uint8_t self) const {
    std::size_t h = 0;
    for (std::size_t j = 0; j < nodes_.size(); ++j) {
        if (nodes_[j].used && j != self) {
            h = std::max(h, distance_below(static_cast<uint8_t>(j), self));
        }
    }
    return h;
}

Status Topology::check_attach(uint8_t self, uint8_t parent) const {
    std::size_t depth = 0;
    for (uint8_t cur = parent; cur != k_root; cur = nodes_[cur].parent) {
        if (cur == self) {
            return Status::Conflict; // the parent hangs below the node: would close a cycle
        }
        if (cur == k_none || !nodes_[cur].active) {
            return Status::NoRoute;
        }
        if (++depth > k_max_depth) {
            return Status::Conflict;
        }
    }
    return depth + 1 + subtree_height(self) > k_max_depth ? Status::Conflict : Status::Ok;
}

Status Topology::bump_revision(uint32_t &out) {
    if (revision_ == UINT32_MAX) {
        return Status::RecoveryRequired; // stop before wrap; management recovery (docs/04 §7)
    }
    out = ++revision_;
    return Status::Ok;
}

Status Topology::bump_subtree(uint8_t idx) {
    uint32_t rev = 0;
    bool taken = false;
    for (std::size_t j = 0; j < nodes_.size(); ++j) {
        if (nodes_[j].used && j != idx && distance_below(static_cast<uint8_t>(j), idx) != 0) {
            if (!taken) {
                LM_TRY(bump_revision(rev));
                taken = true;
            }
            nodes_[j].revision = rev;
        }
    }
    return Status::Ok;
}

void Topology::unattach_children(uint8_t idx) {
    for (Node &n : nodes_) {
        if (n.active && n.parent == idx) {
            n.active = false;
            n.parent = k_none;
        }
        if (n.pending && n.pending_parent == idx) {
            n.pending = false;
        }
    }
}

Status Topology::admit(const DeviceId &id, ShortAddr addr, AssignmentGen ag, MembershipGen mg) {
    if (!is_valid_short_addr(addr) || addr == root_addr_ || id.is_zero()) {
        return Status::InvalidArgument;
    }
    const uint8_t at = find_addr(addr.value());
    const uint8_t same = find_id(id);
    if (same != k_none && same != at) {
        return Status::Conflict;
    }
    uint8_t slot = at;
    if (at != k_none) {
        const Node &old = nodes_[at];
        if (old.id == id && old.assignment == ag && old.membership == mg) {
            return Status::Ok;
        }
        if (old.id == id && (ag < old.assignment || mg < old.membership)) {
            return Status::Conflict;
        }
        unattach_children(at); // the address now means another generation: old links are void
    } else {
        for (std::size_t i = 0; i < nodes_.size() && slot == k_none; ++i) {
            slot = nodes_[i].used ? k_none : static_cast<uint8_t>(i);
        }
        if (slot == k_none) {
            return Status::NoCapacity;
        }
    }
    nodes_[slot] = Node{};
    nodes_[slot].used = true;
    nodes_[slot].addr = addr.value();
    nodes_[slot].id = id;
    nodes_[slot].assignment = ag;
    nodes_[slot].membership = mg;
    return Status::Ok;
}

Status Topology::remove(ShortAddr addr) {
    const uint8_t at = find_addr(addr.value());
    if (at == k_none || at == k_root) {
        return Status::NotFound;
    }
    unattach_children(at);
    nodes_[at] = Node{};
    return Status::Ok;
}

Status Topology::begin_term(RootTerm term) {
    if (term <= term_) {
        return Status::Conflict;
    }
    term_ = term;
    revision_ = 0;
    for (Node &n : nodes_) {
        const Node kept = n;
        n = Node{};
        n.used = kept.used;
        n.addr = kept.addr;
        n.id = kept.id;
        n.assignment = kept.assignment;
        n.membership = kept.membership;
    }
    return Status::Ok;
}

Status Topology::register_route(const RouteRequest &req, uint64_t now, RouteGrant &out) {
    if (req.term != term_) {
        return Status::NetworkMismatch;
    }
    const uint8_t idx = find_id(req.device);
    if (idx == k_none) {
        return Status::NotFound;
    }
    Node &node = nodes_[idx];
    if (req.assignment != node.assignment || req.membership != node.membership) {
        return Status::TargetGenerationChanged;
    }
    const std::size_t n = req.candidate_len;
    const uint16_t *cand = req.candidate_path;
    if (cand == nullptr || n < 2 || n > k_max_depth + 1 || cand[0] != root_addr_.value() ||
        cand[n - 1] != node.addr || req.parent.value() != cand[n - 2] ||
        wire::validate_simple_path(root_addr_.value(), cand + 1, n - 1) != Status::Ok) {
        return Status::InvalidArgument;
    }
    const uint8_t pidx = find_addr(req.parent.value());
    if (pidx == k_none) {
        return Status::NoRoute;
    }
    // The child built its candidate from an advertisement; only the parent's current approved
    // path counts, so a stale advertisement is refused here instead of trusted (rank is no proof).
    Chain parent_path{};
    std::size_t plen = 0;
    LM_TRY(chain(pidx, &now, parent_path, plen));
    if (plen + 1 != n || !std::equal(cand, cand + plen, parent_path.begin())) {
        return Status::NoRoute;
    }
    if (node.has_seq && req.request_sequence < node.last_seq) {
        return Status::Conflict;
    }
    if (node.has_seq && req.request_sequence == node.last_seq) {
        // Query after a lost ACK: same request, same answer, no new revision.
        if (node.pending && node.pending_parent == pidx) {
            fill_grant(parent_path, plen, node.addr, true, node.pending_revision,
                       node.pending_expires_ms, out);
            return Status::Ok;
        }
        if (!node.pending && node.active && node.parent == pidx) {
            fill_grant(parent_path, plen, node.addr, true, node.revision, node.lease_expires_ms,
                       out);
            return Status::Ok;
        }
        return Status::Conflict;
    }
    LM_TRY(check_attach(idx, pidx));
    uint32_t rev = 0;
    LM_TRY(bump_revision(rev));
    node.pending = true;
    node.pending_parent = pidx;
    node.pending_revision = rev;
    node.pending_parent_revision = revision_of(pidx);
    node.pending_expires_ms = now + gen::defaults::routing::lease_ms;
    node.has_seq = true;
    node.last_seq = req.request_sequence;
    fill_grant(parent_path, plen, node.addr, true, rev, node.pending_expires_ms, out);
    return Status::Ok;
}

Status Topology::confirm_ready(const DeviceId &id, RootTerm term, PathRevision revision,
                               uint64_t now) {
    if (term != term_) {
        return Status::NetworkMismatch;
    }
    const uint8_t idx = find_id(id);
    if (idx == k_none) {
        return Status::NotFound;
    }
    Node &node = nodes_[idx];
    if (!node.pending) {
        return node.active && node.revision == revision.value() ? Status::Ok : Status::Conflict;
    }
    if (node.pending_revision != revision.value()) {
        return Status::Conflict;
    }
    const uint8_t p = node.pending_parent;
    Status st = now >= node.pending_expires_ms ? Status::Expired : Status::Ok;
    if (st == Status::Ok && p != k_root &&
        (!nodes_[p].active || nodes_[p].revision != node.pending_parent_revision)) {
        st = Status::NoRoute; // the parent's own path moved since the grant
    }
    if (st == Status::Ok) {
        st = check_attach(idx, p);
    }
    if (st != Status::Ok) {
        node.pending = false;
        return st;
    }
    node.parent = p;
    node.active = true;
    node.pending = false;
    node.revision = node.pending_revision;
    node.lease_expires_ms = now + gen::defaults::routing::lease_ms;
    // Descendants keep their links but their path (through this node) changed.
    return bump_subtree(idx);
}

Status Topology::renew(const DeviceId &id, uint64_t now, RouteGrant &out) {
    const uint8_t idx = find_id(id);
    if (idx == k_none) {
        return Status::NotFound;
    }
    Chain path{};
    std::size_t len = 0;
    LM_TRY(chain(idx, &now, path, len));
    nodes_[idx].lease_expires_ms = now + gen::defaults::routing::lease_ms;
    fill_grant(path, len, 0, false, nodes_[idx].revision, nodes_[idx].lease_expires_ms, out);
    return Status::Ok;
}

void Topology::expire(uint64_t now) {
    for (Node &n : nodes_) {
        if (n.pending && now >= n.pending_expires_ms) {
            n.pending = false;
        }
        if (n.active && now >= n.lease_expires_ms) {
            n.active = false; // children stay attached to it and return with it
            n.parent = k_none;
        }
    }
}

Status Topology::path_from_root(ShortAddr node, uint64_t now, RouteGrant &out) const {
    const uint8_t idx = find_addr(node.value());
    if (idx == k_none) {
        return Status::NotFound;
    }
    Chain path{};
    std::size_t len = 0;
    LM_TRY(chain(idx, &now, path, len));
    fill_grant(path, len, 0, false, revision_of(idx),
               idx == k_root ? 0U : nodes_[idx].lease_expires_ms, out);
    return Status::Ok;
}

Status Topology::route_between(ShortAddr src, ShortAddr dst, uint64_t now, SourceRoute &out) const {
    const uint8_t si = find_addr(src.value());
    const uint8_t di = find_addr(dst.value());
    if (si == k_none || di == k_none) {
        return Status::NotFound;
    }
    if (si == di) {
        return Status::InvalidArgument;
    }
    Chain a{};
    Chain b{};
    std::size_t na = 0;
    std::size_t nb = 0;
    LM_TRY(chain(si, &now, a, na));
    LM_TRY(chain(di, &now, b, nb));
    std::size_t lca = 0; // index of the lowest common ancestor in both chains
    while (lca + 1 < na && lca + 1 < nb && a[lca + 1] == b[lca + 1]) {
        ++lca;
    }
    out = SourceRoute{};
    for (std::size_t i = na - 1; i-- > lca;) { // src's parent up to the LCA
        out.path[out.len++] = a[i];
    }
    for (std::size_t i = lca + 1; i < nb; ++i) { // down to dst
        out.path[out.len++] = b[i];
    }
    out.revision = PathRevision{std::max(revision_of(si), revision_of(di))};
    return Status::Ok;
}

Status Topology::parent_of(ShortAddr node, ShortAddr &parent) const {
    const uint8_t idx = find_addr(node.value());
    if (idx == k_none || idx == k_root || !nodes_[idx].active) {
        return Status::NotFound;
    }
    parent = nodes_[idx].parent == k_root ? root_addr_ : ShortAddr{nodes_[nodes_[idx].parent].addr};
    return Status::Ok;
}

} // namespace lm::root
