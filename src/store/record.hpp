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
inline constexpr std::size_t k_max_payload = 512;
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
inline constexpr uint16_t policy = 8;
inline constexpr uint16_t root_ledger = 9;
} // namespace rec

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
struct BootJob {
    RecordJob rec;
    uint64_t incarnation = 0; // out: new value, valid only when the job status is Ok
};
[[nodiscard]] Status boot_incarnation_advance(port::Store &store, BootJob &job);
[[nodiscard]] Status boot_job(port::JobEnv &env, void *arg);

} // namespace lm::store
