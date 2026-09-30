// Wire objects of the power module that are not in the spec's fixed POWER frames:
//   Report  a device's schedule hint to the root (CONTROL end record of the node<->root end session, the
//           compact mesh-record form of S11-D1, opcode 0xEE). It is a hint about availability, never
//           authority: no lease, no authorisation and no wake fact follow from it alone (docs/20 §4).
//   policy record payload (sealed record rec::power_policy).
#pragma once

#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/power/policy.hpp"
#include "core/status.hpp"
#include "core/wire/power_frame.hpp"

namespace lm::power {

inline constexpr uint8_t k_op_report = 0xEE; // = route::Op::Power (0xE6..0xED belong to the channel module)
inline constexpr uint8_t k_quality_unknown = 0, k_quality_estimated = 1, k_quality_bounded = 2; // diagnostics enum

struct Report {
    uint8_t mode = 0;
    uint8_t quality = k_quality_unknown;
    uint8_t kind = LM_SLEEP_LIGHT;
    uint32_t policy_revision = 0; // low 32 bits, a lookup hint (docs/09 revision-hint)
    uint32_t interval_ms = 0;     // planned wake interval (0 = none known)
    uint32_t earliest_ms = 0;     // next wake, relative to the moment the report was made
    uint32_t latest_ms = 0;
};
[[nodiscard]] Status encode(const Report &r, MutByteView out, std::size_t &len);
[[nodiscard]] Status decode(ByteView body, Report &out);

// What the root remembers per member (by ledger slot = short address - 2): 24 bytes.
struct MemberPower {
    bool valid = false;
    uint8_t mode = 0, quality = 0, kind = 0;
    uint32_t policy_rev = 0;
    uint32_t interval_s = 0, earliest_s = 0, latest_s = 0, reported_s = 0; // root clock, seconds
};

inline constexpr std::size_t k_policy_record_bytes = 1 + 8 + 2 + 15 * 4;
[[nodiscard]] Status encode_policy(const Policy &p, MutByteView out, std::size_t &len);
[[nodiscard]] Status decode_policy(ByteView in, Policy &out);

} // namespace lm::power
