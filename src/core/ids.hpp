// Identities and generations as distinct types. AGENTS.md: Identity, assignment_generation,
// membership_generation, root_term, channel_epoch, link_session, end_session and application
// binding are never interchangeable, so each has its own type and they do not convert.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"

namespace lm {

// Counter-like value with a unique Tag. Only same-tag comparison is allowed.
template <class Tag, class Rep> class Tagged {
  public:
    using rep_type = Rep;
    constexpr Tagged() = default;
    constexpr explicit Tagged(Rep v) : v_(v) {}
    [[nodiscard]] constexpr Rep value() const { return v_; }

    friend constexpr bool operator==(Tagged a, Tagged b) { return a.v_ == b.v_; }
    friend constexpr bool operator!=(Tagged a, Tagged b) { return a.v_ != b.v_; }
    friend constexpr bool operator<(Tagged a, Tagged b) { return a.v_ < b.v_; }
    friend constexpr bool operator<=(Tagged a, Tagged b) { return a.v_ <= b.v_; }
    friend constexpr bool operator>(Tagged a, Tagged b) { return a.v_ > b.v_; }
    friend constexpr bool operator>=(Tagged a, Tagged b) { return a.v_ >= b.v_; }

  private:
    Rep v_{};
};

// Largest value of a CBOR u63 field (control.cddl). Generations stop before wrap (docs/04 §7).
inline constexpr uint64_t k_u63_max = 0x7FFFFFFFFFFFFFFFULL;

// Monotone successor that refuses to wrap: RecoveryRequired at the limit, never back to 0.
template <class T>
[[nodiscard]] constexpr bool next_generation(T current, typename T::rep_type limit, T &out) {
    if (current.value() >= limit) {
        return false;
    }
    out = T{static_cast<typename T::rep_type>(current.value() + 1)};
    return true;
}

struct RootTermTag;
struct AssignmentGenTag;
struct MembershipGenTag;
struct ChannelEpochTag;
struct PathRevisionTag;
struct DelegationGenTag;
struct PolicyRevisionTag;
struct LinkSidTag;
struct EndSidTag;
struct ShortAddrTag;
struct BootIncarnationTag;

using RootTerm = Tagged<RootTermTag, uint32_t>;           // per root boot, persistent (docs/04 §7)
using AssignmentGen = Tagged<AssignmentGenTag, uint64_t>; // u63, fleet assignment (docs/07 §8)
using MembershipGen = Tagged<MembershipGenTag, uint64_t>; // u63, domain membership
using ChannelEpoch = Tagged<ChannelEpochTag, uint32_t>;   // docs/05 §1, independent of root_term
using PathRevision = Tagged<PathRevisionTag, uint32_t>;
using DelegationGen = Tagged<DelegationGenTag, uint64_t>;   // RootDelegation generation
using PolicyRevision = Tagged<PolicyRevisionTag, uint64_t>; // u63, CAS revision
using LinkSid = Tagged<LinkSidTag, uint32_t>; // receiver-assigned local handle; never authorization
using EndSid = Tagged<EndSidTag, uint32_t>;
using ShortAddr = Tagged<ShortAddrTag, uint16_t>; // 1..65534 lookup hint; never an Identity
using BootIncarnation = Tagged<BootIncarnationTag, uint64_t>;

[[nodiscard]] constexpr bool is_valid_short_addr(ShortAddr a) {
    return a.value() != 0 && a.value() != 0xFFFF;
}

// Full-width identifiers. Authorization always uses the full value (docs/06 §3).
template <std::size_t N, class Tag> struct FixedId {
    std::array<uint8_t, N> bytes{};

    static constexpr std::size_t size() { return N; }
    [[nodiscard]] ByteView view() const { return ByteView{bytes.data(), N}; }
    [[nodiscard]] bool is_zero() const {
        for (uint8_t b : bytes) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }
    friend bool operator==(const FixedId &a, const FixedId &b) { return a.bytes == b.bytes; }
    friend bool operator!=(const FixedId &a, const FixedId &b) { return a.bytes != b.bytes; }
    // Bytewise lexicographic order: the stable tie-break of docs/04 §6.
    friend bool operator<(const FixedId &a, const FixedId &b) { return a.bytes < b.bytes; }
};

struct DeviceIdTag;
struct DomainIdTag;
struct FleetIdTag;
struct RequestIdTag;
struct GrantIdTag;
struct PlanIdTag;

using DeviceId = FixedId<32, DeviceIdTag>; // SHA-256(deterministic CBOR COSE_Key)
using DomainId = FixedId<16, DomainIdTag>;
using FleetId = FixedId<16, FleetIdTag>;
using RequestId = FixedId<16, RequestIdTag>;
using GrantId = FixedId<16, GrantIdTag>;
using PlanId = FixedId<16, PlanIdTag>;
using Sha256Digest = std::array<uint8_t, 32>;

// MessageId128 = origin incarnation64 || local sequence64 (docs/08 §2). Only meaningful together
// with the origin DeviceId and assignment generation (lm_message_ref_t).
struct MessageId {
    uint64_t incarnation = 0;
    uint64_t sequence = 0;
    friend bool operator==(const MessageId &a, const MessageId &b) {
        return a.incarnation == b.incarnation && a.sequence == b.sequence;
    }
    friend bool operator!=(const MessageId &a, const MessageId &b) { return !(a == b); }
};

struct MacAddr {
    std::array<uint8_t, 6> bytes{};
    friend bool operator==(const MacAddr &a, const MacAddr &b) { return a.bytes == b.bytes; }
    friend bool operator!=(const MacAddr &a, const MacAddr &b) { return a.bytes != b.bytes; }
    [[nodiscard]] bool is_broadcast() const {
        for (uint8_t b : bytes) {
            if (b != 0xFF) {
                return false;
            }
        }
        return true;
    }
    static constexpr MacAddr broadcast() { return MacAddr{{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}}; }
};

} // namespace lm
