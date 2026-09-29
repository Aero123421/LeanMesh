// The object behind the opaque lm_context_t. It is placement-constructed in the caller's
// workspace (lm_workspace_required / lm_init); no heap allocation after initialisation (docs/10
// §2).
#pragma once

#include <cstddef>
#include <cstdint>

#include "core/command.hpp"
#include "core/engine.hpp"
#include "leanmesh.h"

struct lm_context {
    static constexpr uint32_t k_magic = 0x4C4D4358; // "LMCX"

    lm_context(const lm::EngineConfig &cfg, lm::Ports ports, lm::OwnerCall &owner_call)
        : engine(cfg, ports), owner(owner_call) {}

    uint32_t magic = k_magic;
    lm::Engine engine; // touched only on the owner thread
    lm::OwnerCall &owner;
};

namespace lm::capi {

// Validates a caller-initialised ABI struct header: abi_version must be LM_ABI_VERSION
// (Unsupported otherwise) and struct_size must equal this build's sizeof exactly
// (InvalidArgument otherwise). v0.2 never guesses a size (docs/10 §1).
[[nodiscard]] Status check_abi(uint32_t struct_size, uint32_t abi_version, std::size_t expected);

// Validates lm_config_t against this build (role support, bounds, reserved fields).
[[nodiscard]] Status validate_config(const lm_config_t *config);

// Platform-independent construction used by lm_init (IDF) and by meshsim/native tests, which
// supply their own ports and owner-call mechanism.
[[nodiscard]] Status init_context(void *workspace, std::size_t bytes, const lm_config_t *config,
                                  Ports ports, OwnerCall &owner_call, lm_context_t **out);

} // namespace lm::capi
