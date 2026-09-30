// POWER frame kind 8 plaintexts (docs/09 "spec0.2", protocol/power.cddl, registry power_frames).
// Fixed binary: poll 28 B, grant 24 B, always under the link AEAD; no route/end envelope.
#pragma once

#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/status.hpp"

namespace lm::wire {

inline constexpr uint8_t k_power_poll_subtype = 1;
inline constexpr uint8_t k_power_grant_subtype = 2;
inline constexpr uint8_t k_power_version = 1;

struct PowerPoll {
    uint16_t rx_credit = 0;
    uint64_t poll_nonce = 0; // >= 1
    uint32_t revision_hint = 0;
    uint32_t planned_interval_ms = 0; // <= 86400000
    uint16_t window_ms = 0;           // >= 1
};

struct PowerGrant {
    uint16_t pending_frames = 0;
    uint64_t poll_nonce = 0; // >= 1
    uint32_t window_ttl_ms = 0; // 1..65535
    uint16_t granted_credit = 0;
    uint32_t reason = 0;
};

// First plaintext byte: 1 poll, 2 grant, 0 when empty.
[[nodiscard]] uint8_t power_subtype(ByteView plain);
// Unsupported: version != 1. BadFrame: other malformation (flags/reserved != 0, ranges, length).
[[nodiscard]] Status decode_power_poll(ByteView plain, PowerPoll &out);
[[nodiscard]] Status decode_power_grant(ByteView plain, PowerGrant &out);
[[nodiscard]] Status encode_power_poll(const PowerPoll &p, MutByteView out, std::size_t &len);
[[nodiscard]] Status encode_power_grant(const PowerGrant &g, MutByteView out, std::size_t &len);

// The pure part of the grant semantic check: nonce echo, credit <= requested, TTL <= poll window.
[[nodiscard]] Status check_grant_against_poll(const PowerPoll &poll, const PowerGrant &grant);

} // namespace lm::wire
