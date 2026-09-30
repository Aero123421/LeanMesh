// Sealed 2-slot records with a separate commit marker (docs/12 §2, decision D19).
//
// Layout of one slot blob (big endian):
//   magic4 "LMR1" | schema2 | state1 | reserved1 | generation8 | payload_len4 | SHA256(payload)32
//   | payload | CRC32(all preceding bytes)                                     (header 52 B, +4)
// Commit marker, stored under `record | k_marker_flag` in the same slot index:
//   magic4 "LMK1" | record2 | slot1 | state1 | generation8 | SHA256(payload)32 | CRC32   (52 B)
//
// A slot is COMMITTED only when its record parses (CRC + hash) AND the marker of the same slot
// index names the same record id, generation and hash. Commit order (each step durable before the
// next; Ok is returned only after the last):
//   1. write the record to the non-active slot   2. read back + verify
//   3. write marker[target]                       4. read back the marker
// The target's old marker (generation < active) may still exist while step 1 is torn: it names a
// generation below the active one, so it is neither evidence nor a match for the new record.
// A cut before step 3 completes leaves the previous committed record as the only valid state,
// and a cut after it leaves the new one. A valid marker whose record cannot be produced (or a
// record generation higher than every valid one) is evidence that a higher generation existed:
// the record is QUARANTINED (RecoveryRequired) and is never rolled back silently.
// Read errors are StorageFailure, never NotFound ("unprovisioned").
// Confidentiality: secret payloads must be sealed by the caller/port (NVS encryption); this layer
// gives crash consistency, not tamper resistance.
//
// All functions do Flash I/O and therefore run only in worker job bodies (`record_job`).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/ports.hpp"

namespace lm::store {

inline constexpr uint16_t k_marker_flag = 0x8000; // record ids are 0..0x7FFF
inline constexpr uint16_t k_schema = 1;
inline constexpr std::size_t k_header_bytes = 52;
inline constexpr std::size_t k_crc_bytes = 4;
inline constexpr std::size_t k_marker_bytes = 52;
// Largest sealed payload; larger state is split over several record ids by its owner.
inline constexpr std::size_t k_max_payload = 672; // >= k_journal_max_payload: the journal stages in a RecordJob's buffers
inline constexpr std::size_t k_max_blob = k_header_bytes + k_max_payload + k_crc_bytes;

// Record ids (the NVS key space). 0 is invalid.
namespace rec {
inline constexpr uint16_t boot_incarnation = 1;
inline constexpr uint16_t identity = 2;
inline constexpr uint16_t fleet_trust = 3;
inline constexpr uint16_t membership = 4;
inline constexpr uint16_t membership_prepared = 5;
inline constexpr uint16_t assignment_high_water = 6;
inline constexpr uint16_t channel_plan = 7;
inline constexpr uint16_t policy = 8;                // FIX8-D12: the root's join mode (version | mode | change count)
inline constexpr uint16_t root_ledger = 9;
inline constexpr uint16_t revocation_floors = 10; // S5: member/records.cpp
inline constexpr uint16_t root_delegation = 11;   // S5: fleet-signed RootDelegation COSE object
inline constexpr uint16_t assignment_ticket = 12; // S8: signed AssignmentTicket, verbatim
inline constexpr uint16_t paired_host = 13;       // S10: the root's one paired Host DeviceId (D6)
inline constexpr uint16_t power_policy = 14;      // S16: the node's PowerPolicy (docs/12 §5: a typed sealed record)
inline constexpr uint16_t discovery_scope = 15;   // SEC-Da: the optional DiscoveryScopeKey (32 B, factory)
inline constexpr uint16_t ota_state = 16;         // S19: the OTA rollback state (only written by an image built with LM_OTA)
inline constexpr uint16_t root_handover = 17;     // S18: the fleet's RootHandover that retired this root (verbatim)
inline constexpr uint16_t pending_delegation = 18; // S18: the RootDelegation of a transfer/handover target, until it is live
inline constexpr uint16_t commissioning_window = 19; // S18: window id 16 || reservations made u8 (docs/21 §2 budget)
inline constexpr uint16_t root_groups = 20;          // FIX8-D10: the root's group registry (api/SEMANTICS.md: durable)
// One owner per NVS key: two records on one id overwrite and misread each other (ARCH-D7 and SEC-Da each found
// such a collision). Every id above is listed here; the ledger's entries use 0x100 + slot.
inline constexpr uint16_t k_all[] = {boot_incarnation, identity, fleet_trust, membership, membership_prepared,
                                     assignment_high_water, channel_plan, policy, root_ledger, revocation_floors,
                                     root_delegation, assignment_ticket, paired_host, power_policy, discovery_scope, ota_state,
                                     root_handover, pending_delegation, commissioning_window, root_groups};
constexpr bool all_distinct() {
    for (std::size_t i = 0; i < std::size(k_all); ++i) {
        if (k_all[i] == 0 || k_all[i] >= 0x100) {
            return false;
        }
        for (std::size_t j = i + 1; j < std::size(k_all); ++j) {
            if (k_all[i] == k_all[j]) {
                return false;
            }
        }
    }
    return true;
}
static_assert(all_distinct(), "record ids: unique, non-zero, below the ledger's 0x100");
} // namespace rec
inline constexpr uint8_t k_paired_host_active = 1; // record state of an installed pairing

// One worker job's whole memory: payload in/out plus the read/verify scratch. The owner keeps it
// untouched until the completion is polled (docs/IMPLEMENTATION.md §3 zombie rule).
struct RecordJob {
    enum class Op : uint8_t { Load, Commit, Recover };
    Op op = Op::Load;
    uint16_t id = 0;
    uint8_t state = 0;             // Commit/Recover in, Load out (owner-defined meaning)
    uint32_t payload_len = 0;      // Commit/Recover in, Load out
    uint64_t generation = 0;       // out: generation loaded or committed
    uint64_t evidence = 0;         // out on RecoveryRequired: highest committed generation proven
    std::array<uint8_t, k_max_payload> payload{};
    std::array<uint8_t, k_max_blob> scratch{};

    // Sets up the next job on this memory (Load: state and payload_len are outputs; Commit/Recover: inputs).
    void arm(Op o, uint16_t record, uint8_t st = 0, std::size_t len = 0) {
        op = o;
        id = record;
        state = st;
        payload_len = static_cast<uint32_t>(len);
    }
};

// Load: Ok (payload/state/generation valid) | NotFound (never committed) | RecoveryRequired
// (quarantined, `evidence` set) | StorageFailure (a read error left the state unknown).
[[nodiscard]] Status record_load(port::Store &store, RecordJob &job);
// Commit: writes generation+1 (wrap refused). RecoveryRequired while quarantined.
[[nodiscard]] Status record_commit(port::Store &store, RecordJob &job);
// Recover: like Commit but allowed while quarantined, using evidence+1. The caller must already
// have verified a fleet-signed recovery object (docs/12 §2); this layer cannot.
[[nodiscard]] Status record_recover(port::Store &store, RecordJob &job);

// port::JobFn for RecordJob (dispatches on job.op).
[[nodiscard]] Status record_job(port::JobEnv &env, void *arg);

// Boot incarnation: persisted (durable Ok) before the caller may use it (docs/12 §1, AGENTS.md).
// A missing record is a virgin device only while no identity record exists. Provisioning MUST
// commit rec::boot_incarnation (payload u64be(0)) before rec::identity; if the counter is missing
// on a provisioned device the advance returns RecoveryRequired instead of restarting at 1.
// `job` is the caller's record memory (P4: the node's one RecordJob, lent for this job); `incarnation`
// is written only when the new value is durable.
[[nodiscard]] Status boot_incarnation_advance(port::Store &store, RecordJob &job, uint64_t &incarnation);

} // namespace lm::store
