// Root-owned approved tree (docs/04 §3, §5, §7). Only the root holds the whole topology; it
// approves parent links one request at a time against the current tree, so concurrent parent
// choices on stale advertisements can never put a cycle into the approved tree (R03).
//
// State per member (bounded table, profile root members = 64, owner: the root mesh owner). The
// table holds routing state only: the member's identity (DeviceId, generations) lives in the ledger
// entry of the same short address (S11-D9, P6: no second DeviceId table); the route service checks
// them there and keeps this table in step through admit/remove/reset.
//   Admitted  the ledger lists the address as an Active member but it has no approved parent. It
//             never appears on a path.
//   Active    approved parent link, path_revision and a lease. Paths are derived on demand from
//             the parent links (root -> ... -> node), so a subtree move needs no per-descendant
//             path rewrite and no path storage.
// A register request becomes *pending* (revision granted, tree unchanged) and only ROUTE_READY
// from the node applies it; the old link keeps serving until then. Both steps run the same
// attach check on the current tree (parent chain fully Active and free of the node, depth of the
// node's whole subtree <= root_depth 20), so partial application of concurrent moves stays
// acyclic. Invariants that need no time: depth <= 20, LCA path <= 40, no duplicate address.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/ids.hpp"
#include "core/status.hpp"
#include "gen/profiles.hpp"
#include "gen/registry.hpp"

namespace lm::root {

inline constexpr std::size_t k_max_members = gen::k_profile_root.members;
inline constexpr std::size_t k_max_depth = gen::limits::root_depth;
inline constexpr std::size_t k_max_route = gen::limits::path_hops;

struct RouteRequest {
    ShortAddr node{}; // the registering member (its DeviceId and generations were checked by the caller)
    RootTerm term{};
    ShortAddr parent{};
    const uint16_t *candidate_path = nullptr; // root first, device last (control.cddl route-register)
    std::size_t candidate_len = 0;            // 2..21
    uint32_t request_sequence = 0;
};

// route-lease body: canonical path root -> device (root and device included).
struct RouteGrant {
    PathRevision revision{};
    uint8_t len = 0;
    std::array<uint16_t, k_max_depth + 1> path{};
    uint64_t lease_expires_ms = 0;
};

// A source route between two members (or the root): origin excluded, destination last.
struct SourceRoute {
    PathRevision revision{}; // max revision of both ends; changes when a node on the path moves
    uint8_t len = 0;
    std::array<uint16_t, k_max_route> path{};
};

class Topology {
  public:
    Topology(ShortAddr root_addr, RootTerm term) : root_addr_(root_addr), term_(term) {}

    // Ledger side (via the route service). admit: the address is an Active member of membership
    // generation `gen` (low 32 bits, a change detector and not an identity); idempotent for the same
    // generation, another generation resets the slot; InvalidArgument for the root address or an
    // invalid one, NoCapacity when the table is full. reset: the address now means another membership
    // generation: its approved link and its direct children's links are void, the slot stays
    // admitted. remove: the member is gone.
    [[nodiscard]] Status admit(ShortAddr addr, uint32_t gen = 0);
    // Re-initialises in place (no whole-table temporary on the owner stack): root address, term.
    void init(ShortAddr root_addr, RootTerm term);
    [[nodiscard]] Status reset(ShortAddr addr);
    [[nodiscard]] Status remove(ShortAddr addr);
    // New root_term (must be larger): every approved link is dropped, membership stays.
    [[nodiscard]] Status begin_term(RootTerm term);

    // NetworkMismatch (term), NotFound (address not admitted), Conflict (older or
    // different replay of a sequence, cycle, depth), InvalidArgument (path shape), NoRoute
    // (parent not usable or the candidate path is stale). Same sequence + same content: the same
    // grant again (ACK lost), no new revision.
    [[nodiscard]] Status register_route(const RouteRequest &req, uint64_t now_root_ms,
                                        RouteGrant &out);
    // ROUTE_READY: applies the pending link. Repeating it for the applied revision is Ok.
    // NoRoute: the parent changed since the grant; the pending request is dropped (re-register).
    [[nodiscard]] Status confirm_ready(ShortAddr node, RootTerm term, PathRevision revision,
                                       uint64_t now_root_ms);
    // Lease refresh for an Active member; returns the current canonical path.
    // `lease_ms` 0 = the default lease; the power module asks for the longer lease of a sleepy member (S16).
    [[nodiscard]] Status renew(ShortAddr node, uint64_t now_root_ms, RouteGrant &out, uint64_t lease_ms = 0);
    // Drops leases and pending requests that ran out; the members stay Admitted.
    void expire(uint64_t now_root_ms);
    // Earliest lease/pending expiry (UINT64_MAX: none): the route service's only timer.
    [[nodiscard]] uint64_t next_expiry_ms() const;
    // Direct and indirect descendants of `node`: calls f(addr) for each Active one (bounded scan of
    // the table). Used to push a moved subtree its new paths.
    template <class F> void for_each_descendant(ShortAddr node, F &&f) const {
        const uint8_t idx = find_addr(node.value());
        for (std::size_t j = 0; idx != k_none && j < nodes_.size(); ++j) {
            if (nodes_[j].used && j != idx && distance_below(static_cast<uint8_t>(j), idx) != 0) {
                f(ShortAddr{nodes_[j].addr});
            }
        }
    }
    [[nodiscard]] bool is_admitted(ShortAddr addr) const {
        const uint8_t i = find_addr(addr.value());
        return i != k_none && i != k_root;
    }

    // Tree-path between two Active members / the root (lowest common ancestor join).
    [[nodiscard]] Status route_between(ShortAddr src, ShortAddr dst, uint64_t now_root_ms,
                                       SourceRoute &out) const;
    [[nodiscard]] Status path_from_root(ShortAddr node, uint64_t now_root_ms, RouteGrant &out) const;
    // Revision of an Active member's approved path (NotFound otherwise).
    [[nodiscard]] Status path_revision(ShortAddr node, PathRevision &out) const;
    // Approved parent of an Active member (NotFound otherwise); the root itself has none.
    [[nodiscard]] Status parent_of(ShortAddr node, ShortAddr &parent) const;

    [[nodiscard]] RootTerm term() const { return term_; }
    [[nodiscard]] ShortAddr root_addr() const { return root_addr_; }

  private:
    static constexpr uint8_t k_root = 0xFE; // parent index of a depth-1 node
    static constexpr uint8_t k_none = 0xFF; // no approved parent
    static_assert(k_max_members < k_root, "member index space");

    struct Node {
        bool used = false;
        bool active = false;
        bool pending = false;
        bool has_seq = false;
        uint8_t parent = k_none;
        uint8_t pending_parent = k_none;
        uint32_t revision = 0;
        uint32_t pending_revision = 0;
        uint32_t pending_parent_revision = 0;
        uint32_t last_seq = 0;
        uint16_t addr = 0;
        uint32_t gen = 0;
        uint64_t lease_expires_ms = 0;
        uint64_t pending_expires_ms = 0;
    };

    [[nodiscard]] uint8_t find_addr(uint16_t addr) const; // k_root, index or k_none
    [[nodiscard]] uint32_t revision_of(uint8_t idx) const;
    // Root-first chain of a node whose whole ancestry is Active (leases checked when `now` set).
    [[nodiscard]] Status chain(uint8_t idx, const uint64_t *now,
                               std::array<uint16_t, k_max_depth + 1> &out, std::size_t &n) const;
    // Depth the node would get under `parent`, or an error; also bounds the subtree below `self`.
    [[nodiscard]] Status check_attach(uint8_t self, uint8_t parent) const;
    [[nodiscard]] std::size_t subtree_height(uint8_t self) const;
    [[nodiscard]] Status bump_revision(uint32_t &out);
    void unattach_children(uint8_t idx);
    [[nodiscard]] Status bump_subtree(uint8_t idx);
    // Distance in parent links from `node` up to `ancestor`; 0 when it is no descendant.
    [[nodiscard]] std::size_t distance_below(uint8_t node, uint8_t ancestor) const;

    ShortAddr root_addr_;
    RootTerm term_;
    uint32_t revision_ = 0;
    std::array<Node, k_max_members> nodes_{};
};

} // namespace lm::root
