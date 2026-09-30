#include "core/route/forward.hpp"

namespace lm::route {

namespace {
Decision drop(DropReason r) { return Decision{Action::Drop, r, ShortAddr{}}; }
} // namespace

Decision decide_forward(wire::RouteHeader &h, ShortAddr self, ShortAddr previous_sender) {
    if (h.path_len < 1 || h.path_len > wire::k_max_path || h.next_index >= h.path_len) {
        return drop(DropReason::BadIndex);
    }
    if (h.origin == self.value()) {
        return drop(DropReason::OriginIsSelf);
    }
    if (h.path[h.next_index] != self.value()) {
        return drop(DropReason::NotSelf);
    }
    const uint16_t expected_prev = h.next_index == 0 ? h.origin : h.path[h.next_index - 1U];
    if (previous_sender.value() != expected_prev) {
        return drop(DropReason::WrongPrevious);
    }
    if (h.budget == 0 || h.budget != h.path_len - h.next_index) {
        return drop(DropReason::NoBudget);
    }
    if (wire::validate_simple_path(h.origin, h.path.data(), h.path_len) != Status::Ok) {
        return drop(DropReason::NotSimple);
    }
    if (h.path[h.path_len - 1U] != h.final) {
        return drop(DropReason::FinalMismatch);
    }
    if (h.next_index + 1U == h.path_len) {
        return Decision{Action::Deliver, DropReason::None, ShortAddr{}};
    }
    ++h.next_index;
    --h.budget;
    return Decision{Action::Forward, DropReason::None, ShortAddr{h.path[h.next_index]}};
}

Status check_candidate_path(ShortAddr self, const uint16_t *path, std::size_t n,
                            RootTerm advertised_term, RootTerm local_term, bool expired) {
    if (n == 0 || n > wire::k_max_path) {
        return Status::InvalidArgument;
    }
    if (advertised_term < local_term) {
        return Status::NetworkMismatch; // a tree of a term the root has left
    }
    if (expired) {
        return Status::Expired;
    }
    // Simple path with `self` as origin: also rejects a path that contains self.
    if (wire::validate_simple_path(self.value(), path, n) != Status::Ok) {
        return Status::InvalidArgument;
    }
    // n entries root..candidate: this node would sit at depth n.
    return n > gen::limits::root_depth ? Status::NoRoute : Status::Ok;
}

} // namespace lm::route
