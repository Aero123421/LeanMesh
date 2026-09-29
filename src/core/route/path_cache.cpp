#include "core/route/path_cache.hpp"

#include "core/wire/frame.hpp"

namespace lm::route {

Status check_cache_route(ShortAddr self, const CachedRoute &r) {
    if (r.len < 1 || r.len > wire::k_max_path || r.path[r.len - 1U] != r.destination.value()) {
        return Status::InvalidArgument;
    }
    return wire::validate_simple_path(self.value(), r.path.data(), r.len) == Status::Ok
               ? Status::Ok
               : Status::InvalidArgument;
}

} // namespace lm::route
