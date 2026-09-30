// Role and capacity profile. Capacities come only from config/profiles.json (gen/profiles.hpp).
// A build selects a *maximum* profile at compile time (LM_BUILD_PROFILE_{LEAF,RELAY,ROOT,SIM}); a
// node's runtime role may use that profile or a smaller one. The role changes capacity only, never
// security, join or frame interpretation (docs/16 §1).
#pragma once

#include <cstdint>

#include "gen/profiles.hpp"
#include "leanmesh.h"

namespace lm {

enum class Role : uint8_t {
    Leaf = LM_ROLE_LEAF,
    Relay = LM_ROLE_RELAY,
    Root = LM_ROLE_ROOT,
};

using ProfileLimits = gen::ProfileLimits;

#if defined(LM_BUILD_PROFILE_LEAF)
inline constexpr ProfileLimits k_build_limits = gen::k_profile_leaf;
inline constexpr Role k_build_max_role = Role::Leaf;
#elif defined(LM_BUILD_PROFILE_RELAY)
inline constexpr ProfileLimits k_build_limits = gen::k_profile_relay;
inline constexpr Role k_build_max_role = Role::Relay;
#elif defined(LM_BUILD_PROFILE_ROOT) || defined(LM_BUILD_PROFILE_SIM)
// SIM: one native binary runs every role; arrays are sized for the root (the elementwise maximum).
inline constexpr ProfileLimits k_build_limits = gen::k_profile_root;
inline constexpr Role k_build_max_role = Role::Root;
#else
#error "define one of LM_BUILD_PROFILE_LEAF/RELAY/ROOT/SIM"
#endif

// Root code (topology, ledger, fan-out coordinator, serial bridge) exists only in root-capable
// builds (docs/02 §4 "roleでコンパイル時除去").
inline constexpr bool k_root_capable = k_build_max_role == Role::Root;

[[nodiscard]] constexpr const ProfileLimits &limits_for(Role r) {
    return r == Role::Root ? gen::k_profile_root
                           : (r == Role::Relay ? gen::k_profile_relay : gen::k_profile_leaf);
}

// Whether this build can run `r` (a leaf build cannot become a relay or root).
[[nodiscard]] constexpr bool build_supports(Role r) {
    return static_cast<uint8_t>(r) <= static_cast<uint8_t>(k_build_max_role);
}

// Root >= relay >= leaf for the capacities used to size arrays.
static_assert(gen::k_profile_root.neighbors >= gen::k_profile_relay.neighbors &&
                  gen::k_profile_relay.neighbors >= gen::k_profile_leaf.neighbors,
              "profiles.json neighbors");
static_assert(gen::k_profile_root.tx_frames >= gen::k_profile_relay.tx_frames &&
                  gen::k_profile_relay.tx_frames >= gen::k_profile_leaf.tx_frames,
              "profiles.json tx_frames");
static_assert(gen::k_profile_root.rx_frames >= gen::k_profile_relay.rx_frames &&
                  gen::k_profile_relay.rx_frames >= gen::k_profile_leaf.rx_frames,
              "profiles.json rx_frames");
static_assert(gen::k_profile_root.end_sessions >= gen::k_profile_relay.end_sessions &&
                  gen::k_profile_relay.end_sessions >= gen::k_profile_leaf.end_sessions,
              "profiles.json end_sessions");

} // namespace lm
