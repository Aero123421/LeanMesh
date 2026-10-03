// ISSUE5: the signed header of a ledger backup and the hash chain over its records (control.cddl 34, docs/12 §5, docs/21 §8).
//
// A backup is the root's durable ledger state - the manifest and every entry record (0x100 + slot), plus the revocation
// floors, the group registry and the join policy when they exist - taken as one consistent cut and signed by the root that
// holds it. None of these records holds a secret: an entry is the device's id, its generations, the request id and hashes
// and the MemberCredential COSE the root issued (public by construction); the floors, groups and policy are numbers and
// ids. The root's private key, its identity record and the sessions are never part of it.
//
// The signature is one: the header (type 34) fixes which records exist (entry mask, extras) and their content by a hash
// chain, so a record is authenticated as it arrives and before it is written, with O(1) memory on the receiving root.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/ids.hpp"
#include "core/status.hpp"
#include "store/record.hpp"

namespace lm::root::backup {

inline constexpr uint8_t k_extra_floors = 1;
inline constexpr uint8_t k_extra_groups = 2;
inline constexpr uint8_t k_extra_policy = 4;
// The ledger's slots and the id of its first entry record (root/ledger.hpp k_ledger_slots, k_rec_ledger_base; backup.cpp
// asserts that they agree: this header is also what the Host-side tools include without the ledger).
inline constexpr std::size_t k_slots = 64;
inline constexpr uint16_t k_entry_base = 0x100;
// floors + groups + policy + every ledger slot + the manifest.
inline constexpr std::size_t k_max_elements = 3 + k_slots + 1;
// The signed COSE of a header: issue_signed's own bound for a credential-class object (control body <= 1024 B).
inline constexpr std::size_t k_cose_max = 1024;

struct Header {
    uint64_t seq = 0;             // 1.. (persisted by the root before it signs)
    uint32_t term = 0;            // the signing root's term
    uint64_t generation = 0;      // its delegation generation
    ByteView delegation;          // its RootDelegation COSE (decode: a view into the decoded data)
    uint64_t change = 0;          // the root's durable-write count at the scan
    uint64_t entries = 0;         // bit i: ledger slot i is part of the backup
    uint8_t extras = 0;           // k_extra_*
    Sha256Digest head{};          // hash chain head H(1)

    [[nodiscard]] std::size_t count() const;
};

// control-data of type 34 (control.cddl): the item the envelope carries.
[[nodiscard]] Status encode_header(const Header &h, MutByteView out, std::size_t &len);
[[nodiscard]] Status decode_header(ByteView data, Header &out);

// The record id of element `index` (0-based) in the canonical order: floors, groups, policy, the masked entries by slot,
// the manifest. 0: `index` is past the end.
[[nodiscard]] uint16_t element_id(const Header &h, std::size_t index);

// H(i) = SHA256("LMBK1" || id u16be || state u8 || len u16be || payload || next); `next` is H(i+1), zero after the last.
// `out` may be `next` itself. Worker or test code (hashing a record's size).
[[nodiscard]] Status link(uint16_t id, uint8_t state, ByteView payload, const Sha256Digest &next, Sha256Digest &out);

} // namespace lm::root::backup
