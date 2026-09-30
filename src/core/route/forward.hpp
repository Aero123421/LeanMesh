// Per-hop forwarding decision of docs/04 §4. Pure and stateless: a relay holds no route table, the
// packet carries the source route. The caller has already authenticated the link frame (AEAD,
// session/domain/peer generation, replay commit) and decoded the routed body with
// wire::decode_route. This function only decides Deliver / Forward / Drop and advances the header;
// re-sealing with the next link key and the ROUTE_STALE reply for an unestablished next peer are
// the caller's (delivery slice) job. A drop is never turned into a DATA flood.
#pragma once

#include <cstdint>

#include "core/ids.hpp"
#include "core/wire/frame.hpp"

namespace lm::route {

enum class Action : uint8_t { Deliver, Forward, Drop };

enum class DropReason : uint8_t {
    None,
    BadIndex,       // next_index >= path_len or path_len outside 1..40
    NotSelf,        // path[next_index] is not this node
    WrongPrevious,  // link peer is not origin (index 0) / path[index-1]
    NoBudget,       // total_budget == 0 or inconsistent with the remaining hops
    NotSimple,      // zero/broadcast address, duplicate, or origin inside the path
    FinalMismatch,  // last path entry differs from final
    OriginIsSelf,   // a packet we originated came back
};

struct Decision {
    Action action = Action::Drop;
    DropReason reason = DropReason::None;
    ShortAddr next_hop{}; // valid for Forward
};

// `header` is updated in place only for Forward: next_index += 1, budget -= 1. Deliver leaves it
// untouched (the end record is consumed by the delivery layer). The root_term of the header is not a forwarding
// condition (docs/04 §4): it names the clock of the end record's deadline, which the relay judges separately (a term it
// does not know is TIME_UNCERTAIN, never a drop), and a node that has not learnt the root's new term yet must still
// reach the root to learn it (docs/04 §7 "新termでsession/pathを再同期").
[[nodiscard]] Decision decide_forward(wire::RouteHeader &header, ShortAddr self, ShortAddr previous_sender);

// docs/04 §3 step 4: a candidate's root path (root first, candidate last, `n` entries) extended by
// `self` must stay simple and within root_depth 20. InvalidArgument: empty, zero/broadcast or
// duplicate address, or `self` already on it; NetworkMismatch: an older root_term (a newer one is a hint the caller
// may try: the root's answer then tells it the term with authority); Expired: the
// advertisement is past its lease; NoRoute: joining would make depth 21.
[[nodiscard]] Status check_candidate_path(ShortAddr self, const uint16_t *path, std::size_t n,
                                          RootTerm advertised_term, RootTerm local_term,
                                          bool expired);

} // namespace lm::route
