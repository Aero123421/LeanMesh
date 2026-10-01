// Wire objects of the mesh control plane (docs/04 §3, §6). Pure codecs: no state, no crypto.
//   Beacon    DISCOVERY frame (SID 0, unauthenticated hint, docs/09 D3): who I am in the tree.
//   Probe     control-body type 16 inside a link-AEAD ROUTE frame (1 hop): reachability and credit.
//   Mesh records (REGISTER / LEASE / READY / QUERY / ANSWER): CONTROL end records of the node<->root
//             end session, in a compact fixed binary form (decision S11-D1: the CBOR control-body of
//             types 13..15 is 200+ B and cannot cross more than one hop in the single frame that
//             exists before S12; the first byte 0xE1..0xE5 cannot start a CBOR control-body, which
//             begins with 0x87).
// Every decoder validates all fields and rejects trailing bytes.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/ids.hpp"
#include "core/status.hpp"
#include "core/wire/frame.hpp"

namespace lm::route {

inline constexpr std::size_t k_max_root_path = 21; // root .. node, control.cddl [1*21 address]
inline constexpr uint8_t k_beacon_version = 1;
inline constexpr uint8_t k_beacon_accepting = 1; // relay-capable and attached: may become a parent
inline constexpr uint8_t k_beacon_solicit = 2;   // "who can be my parent?" (listen-first hint request)

struct Beacon {
    uint8_t flags = 0;
    uint32_t term = 0;
    uint32_t revision = 0; // path_revision of the sender's approved path (0 for the root)
    uint8_t n = 0;         // path entries, root first and the sender last; 0 = none (a solicit)
    std::array<uint16_t, k_max_root_path> path{};
};
// Whole DISCOVERY link frame for `domain_hint` (the domain hint of the deployment).
[[nodiscard]] Status encode_beacon(const Beacon &b, uint32_t domain_hint, MutByteView out, std::size_t &len);
[[nodiscard]] Status decode_beacon(ByteView body, Beacon &out);

struct Probe {
    std::array<uint8_t, 16> nonce{};
    uint16_t sender = 0;
    uint16_t receiver = 0;
    bool reply = false;
    uint8_t credit = 0; // free TX capacity of the sender, 0..255 (never a loss sample)
    uint64_t membership = 0;
};
// Plaintext of the ROUTE frame: control-body(type 16) with `issuer` = sender identity.
[[nodiscard]] Status encode_probe(const Probe &p, const DomainId &domain, const DeviceId &issuer,
                                  MutByteView out, std::size_t &len);
[[nodiscard]] Status decode_probe(ByteView plain, Probe &out, DeviceId &issuer);

enum class Op : uint8_t {
    Register = 0xE1,
    Lease = 0xE2,
    Ready = 0xE3,
    Query = 0xE4,
    Answer = 0xE5,
    DrainRequest = 0xEF,
    DrainStatus = 0xF0,
    DrainNotice = 0xF1,
    Power = 0xEE /* S16; 0xE6..0xED are the channel module's */
};

// Authenticated end-control: the root snapshots children and refuses new attachments to the relay.
struct DrainRequest {
    uint32_t sequence = 0, remaining_ms = 0;
    uint8_t cancel = 0;
};
struct DrainStatus {
    uint32_t sequence = 0, term = 0;
    Status status = Status::Busy;
    uint8_t cancel = 0;
};
struct DrainNotice {
    uint32_t term = 0;
    uint16_t relay = 0;
};

struct Register { // node -> root: "approve this parent for me"
    uint32_t sequence = 0;
    uint16_t parent = 0;
    uint32_t parent_revision = 0; // the parent's path revision the node saw (stale = NoRoute)
    uint32_t term = 0;
};
struct Ready { // node -> root: the granted revision is applied; repeated as the lease renewal
    uint32_t term = 0;
    uint32_t revision = 0;
    // [S18] The authorisation lease of the node's MemberCredential (root ms of `term`): the root renews the
    // credential when it is near its end (docs/06 §7). A claim about the sender only: it costs the root at most
    // one signature per member per minute, it authorises nothing.
    uint64_t credential_lease_ms = 0;
};
struct LeaseRec { // root -> node
    Status status = Status::Ok; // Ok = a grant; anything else = the reason of a refusal
    bool push = false;          // unsolicited update of a moved subtree
    uint32_t term = 0;
    uint32_t revision = 0;
    uint32_t lease_ms = 0;
    uint32_t expected_revision = 0; // low 32 bits of the root's expected-list revision (a hint)
    uint8_t n = 0;                  // path root .. node
    std::array<uint16_t, k_max_root_path> path{};
};
struct Query {
    uint8_t qid = 0;
    DeviceId dest;
    uint32_t known_revision = 0;
};
struct Answer {
    uint8_t qid = 0;
    Status status = Status::Ok;
    uint16_t dest = 0;
    uint32_t revision = 0;
    uint8_t n = 0; // path root .. dest
    std::array<uint16_t, k_max_root_path> path{};
};

// Register, Ready, LeaseRec, Query, Answer: one layout per record (mesh_wire.cpp), used both ways. decode() rejects
// trailing bytes and out-of-range fields (BadFrame) and leaves `out` untouched then.
template <class M> [[nodiscard]] Status encode(const M &m, MutByteView out, std::size_t &len);
template <class M> [[nodiscard]] Status decode(ByteView body, M &out);
// True when the first byte is a mesh opcode (anything else is somebody else's control body).
[[nodiscard]] bool is_mesh_record(ByteView body);

// A root path must be simple (no zero/broadcast, no duplicate) and 1..21 long.
[[nodiscard]] bool path_ok(const uint16_t *p, std::size_t n);

} // namespace lm::route
