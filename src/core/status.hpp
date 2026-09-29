// Status codes. The enum is generated from protocol/registry.json and statically checked against
// the LM_STATUS_* values of api/leanmesh.h (gen/registry.hpp), so the ABI, the registry and the
// core cannot drift. Status is [[nodiscard]]: never drop an error or turn it into success (docs/10
// §7).
#pragma once

#include "gen/registry.hpp"

namespace lm {

using Status = gen::Status;
using gen::status_name;

[[nodiscard]] constexpr bool is_ok(Status s) { return s == Status::Ok; }
[[nodiscard]] constexpr lm_status_t to_abi(Status s) { return static_cast<lm_status_t>(s); }

// Local resource errors are never RF-loss samples (docs/03 §4, AGENTS.md).
[[nodiscard]] constexpr bool is_local_resource_error(Status s) {
    return s == Status::Busy || s == Status::NoCapacity || s == Status::RateLimited;
}

} // namespace lm

// Propagates a non-OK Status to the caller.
#define LM_TRY(expr)                                                                               \
    do {                                                                                           \
        const ::lm::Status lm_try_status_ = (expr);                                                \
        if (lm_try_status_ != ::lm::Status::Ok) {                                                  \
            return lm_try_status_;                                                                 \
        }                                                                                          \
    } while (0)
