// Optional OTA, software part (S19, T23; docs/13 §6, docs/12, protocol/control.cddl "ota-manifest").
//
// Build-optional: everything in ota.cpp exists only when the image is built with LM_OTA (Kconfig LEANMESH_OTA, off by
// default; the native bench has it on). Off, no code and no buffer is linked and the capability row says "not built".
//
// What is here: the signed manifest check, the persistent rollback state and its pure transitions, and the boot
// decision. What is NOT here: transfer of image blocks (the object engine), the flash writer, the boot-target switch and
// the IDF rollback calls - those sit behind `OtaPort` (src/port/idf/idf_ota.* compiles them; nothing runs them) - and
// no engine wiring, so no C API and no capability bit enables it. Real power-cut and rollback evidence (O01, O03)
// needs hardware; the sim sweep of the state record below proves only the record's own crash consistency.
//
// The order that keeps a device bootable (docs/13 §6, E07):
//   Idle -> Staged   the manifest passed; the inactive slot is being written. Boot target untouched.
//   Staged -> Armed  the written image's SHA-256 matched. Committed BEFORE the boot target is switched (write-ahead).
//   Armed -> Pending the new image is running, not yet confirmed. The rollback window is open: no irreversible storage
//                    migration (migration_allowed), the security-version floor is NOT raised.
//   Pending -> Idle  self test passed: the image is marked valid FIRST, then the floor is raised and committed. A cut
//                    between the two leaves Pending with a valid image, which on_boot finishes (idempotent).
// Any state may fall back to Idle without raising the floor (RolledBack, Abandon); the floor never moves down.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/ids.hpp"
#include "core/member/credentials.hpp"
#include "core/status.hpp"

namespace lm::ota {

inline constexpr uint8_t k_type_manifest = 26; // registry control_types OTAManifest
inline constexpr std::size_t k_block_bytes = 4096;
inline constexpr std::size_t k_max_image_bytes = 1'900'544; // config/partitions_4m.csv ota_0/ota_1 (0x1d0000)
inline constexpr std::size_t k_text_max = 32;

enum class Soc : uint8_t { Esp32c3 = 1, Esp32s3 = 2, Esp32c5 = 3, Esp32c6 = 4 };

struct Manifest {
    Soc soc = Soc::Esp32c3;
    std::array<char, k_text_max> board{};
    uint8_t board_len = 0;
    uint32_t image_bytes = 0;
    Sha256Digest image_sha{};
    std::array<char, k_text_max> version{};
    uint8_t version_len = 0;
    uint32_t security_version = 0;
    uint32_t schema_min = 0, schema_max = 0;
    uint32_t loader_min = 0;
};

// What the running image and board are, from the build and the port (never from the manifest).
struct Device {
    Soc soc = Soc::Esp32c3;
    ByteView board;              // board family string
    uint32_t running_security = 0; // security_version of the running image
    uint32_t storage_schema = 0; // the record schema the store holds now (store::k_schema)
    uint32_t loader = 0;         // loader/bootloader generation
    uint32_t slot_bytes = 0;     // size of the inactive OTA slot; 0 = the layout has no OTA slot
};

enum class Reject : uint8_t { None, NoSlot, Signature, Format, Soc, Board, TooBig, Downgrade, Schema, Loader, Retry };

// Verifies (public-key work: a worker job) and checks. Nothing is written and no state moves whatever the outcome.
//   AuthRejected  signature / issuer / envelope wrong, or a security_version below the floor (a downgrade)
//   BadFrame      not a well-formed manifest
//   Unsupported   another SoC or board, no OTA slot (OTA_UNSUPPORTED), image larger than the slot, storage schema
//                 outside the image's range, loader too old
//   Conflict      this image (by its SHA-256, so a re-signed copy too) already failed here
struct Check {
    Status status = Status::Ok;
    Reject why = Reject::None;
};
class State;
[[nodiscard]] Check check_manifest(const member::TrustAnchor &trust, ByteView cose, const Device &dev,
                                   const State &state, Manifest &out, Sha256Digest &manifest_hash);

enum class Phase : uint8_t { Idle = 0, Staged = 1, Armed = 2, Pending = 3 };

class State {
  public:
    static constexpr uint8_t k_version = 1;
    static constexpr std::size_t k_encoded_bytes = 4 + 4 + 4 + 32 + 32 + 32; // header, floor, candidate, 3 hashes

    [[nodiscard]] Phase phase() const { return phase_; }
    [[nodiscard]] uint8_t slot() const { return slot_; }
    [[nodiscard]] uint32_t floor() const { return floor_; }           // highest confirmed security_version
    [[nodiscard]] uint32_t candidate() const { return candidate_; }   // of the staged image
    [[nodiscard]] const Sha256Digest &manifest() const { return manifest_; }
    [[nodiscard]] const Sha256Digest &image() const { return image_; }
    [[nodiscard]] const Sha256Digest &failed() const { return failed_; }   // SHA-256 of the last image that failed here
    [[nodiscard]] bool has_failed() const { return has_failed_; }

    // ---- transitions (pure; the caller commits the returned state before acting on it) ----
    // Idle -> Staged. Busy while another update is in progress. Conflict for an image that failed before.
    [[nodiscard]] Status stage(const Manifest &m, const Sha256Digest &manifest_hash, uint8_t inactive_slot);
    // Staged -> Armed: the image written to the slot hashed to the manifest's SHA-256.
    [[nodiscard]] Status arm();
    // Armed -> Pending: the new image is running (first boot after the switch). Committed before its self test starts.
    [[nodiscard]] Status boot_new();
    // Pending -> Idle with the floor raised to the candidate. Only after the image was marked valid.
    [[nodiscard]] Status confirm();
    // Any state -> Idle, floor unchanged; a Pending/Armed image is remembered as failed (never retried by itself).
    void abandon(bool remember_failed);

    // Irreversible storage migrations are forbidden while a rollback is still possible.
    [[nodiscard]] bool migration_allowed() const { return phase_ == Phase::Idle || phase_ == Phase::Staged; }

    // ---- record payload (store::rec::ota_state) ----
    [[nodiscard]] Status encode(MutByteView out, std::size_t &len) const;
    [[nodiscard]] static Status decode(ByteView in, State &out); // BadFrame for anything but a well-formed record

  private:
    Phase phase_ = Phase::Idle;
    uint8_t slot_ = 0;
    uint32_t floor_ = 0;
    uint32_t candidate_ = 0;
    Sha256Digest manifest_{}, image_{}, failed_{};
    bool has_failed_ = false;
};

// Facts the port reads at boot.
struct BootFacts {
    uint8_t running_slot = 0;
    bool running_pending_verify = false; // the bootloader has not been told this image is good
    bool running_marked_invalid = false; // rolled back or aborted by the bootloader
};

enum class BootAction : uint8_t {
    None,         // Idle: nothing to do
    Restart,      // Staged: the transfer was cut; erase the slot and start over (or wait for a new manifest)
    Abandon,      // Armed but the old image still runs: the boot target never switched
    SelfTest,     // Pending and the new image is running unconfirmed: run the minimal test, then mark valid
    Finalize,     // Pending, new image already valid: only the floor commit is missing
    RolledBack,   // Pending but the old image runs again: the bootloader rolled back
};
[[nodiscard]] BootAction on_boot(const State &state, const BootFacts &facts);

// The flash side, owned by the platform. Nothing in this module calls it except through a caller that has committed
// the matching state first. IDF: src/port/idf/idf_ota.* (compile-only here).
class OtaPort {
  public:
    virtual uint32_t inactive_slot_bytes() = 0;
    virtual uint8_t inactive_slot() = 0;
    virtual Status begin(uint32_t image_bytes) = 0;                 // erase in small steps
    virtual Status write(uint32_t offset, ByteView block) = 0;      // one 4096 B block
    virtual Status verify(const Sha256Digest &expected) = 0;        // read back and hash the written image
    virtual Status set_boot_next() = 0;                             // only after Staged -> Armed is committed
    virtual BootFacts boot_facts() = 0;
    virtual Status mark_valid() = 0;                                // cancel rollback
    virtual Status rollback() = 0;                                  // mark invalid and reboot to the old image

  protected:
    ~OtaPort() = default;
};

} // namespace lm::ota
