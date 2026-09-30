// ESP-IDF Store port: sealed-record slots as NVS blobs (partitions `identity` for identity/trust
// records, `state` for the rest), journal as the raw `journal` partition (config/partitions_*.csv).
// Only the slow-job worker may call it (docs/02 §2): NVS commits and sector erases stall the
// flash cache, so the owner and the radio callbacks never touch it.
//
// init() never formats or erases a partition that fails to open: that would turn a read error into
// "unprovisioned" and wipe identity (docs/12 §2). Erasing is a provisioning action, not part of
// the SDK.
// FIX8-D7 (review H12): the identity record holds the device's private key and discovery_scope the DiscoveryScopeKey
// (secret payloads, docs/12 §2); NVS partitions are not covered by flash encryption. With CONFIG_NVS_ENCRYPTION both
// SDK partitions are mounted encrypted (XTS-AES) with the keys of the registered NVS security scheme (nvs_sec_provider:
// the HMAC eFuse key or the flash-encrypted nvs_keys partition). The SDK only reads those keys and never creates them:
// creating them is provisioning (an eFuse write, the nvs_keys partition: the product's key custody), so a missing key
// is StorageFailure (fail closed), never a plaintext mount. A build without NVS encryption does not compile unless
// CONFIG_LEANMESH_ALLOW_PLAINTEXT_SECRETS acknowledges it (development only). The mode is fixed for a product's life:
// IDF erases (purges) the entries a mount cannot read, so records written in the other mode are LOST at the first mount
// of an image of the other mode (a member then reads as unprovisioned, a root's ledger as RECOVERY_REQUIRED). This port
// does not detect it: provisioning writes the partitions in the mode of the firmware, and no update changes the mode.
#pragma once

#include <cstdint>

#include "core/ports.hpp"
#include "esp_partition.h"

namespace lm::idf {

class IdfStore final : public port::Store {
  public:
    // Opens both NVS partitions and locates the journal partition. StorageFailure otherwise.
    [[nodiscard]] Status init();

    [[nodiscard]] Status slot_read(uint16_t record, uint8_t slot, MutByteView out,
                                   std::size_t &len) override;
    [[nodiscard]] Status slot_write(uint16_t record, uint8_t slot, ByteView data) override;
    [[nodiscard]] Status slot_erase(uint16_t record, uint8_t slot) override;

    [[nodiscard]] uint32_t journal_segment_bytes() const override { return k_segment_bytes; }
    [[nodiscard]] uint32_t journal_segments() const override { return segments_; }
    [[nodiscard]] Status journal_read(uint32_t offset, MutByteView out) override;
    [[nodiscard]] Status journal_write(uint32_t offset, ByteView data) override;
    [[nodiscard]] Status journal_erase(uint32_t segment) override;

  private:
    static constexpr uint32_t k_segment_bytes = 4096; // one flash sector
    const esp_partition_t *journal_ = nullptr;
    uint32_t segments_ = 0;
    bool ready_ = false;
};

} // namespace lm::idf
