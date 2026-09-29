// ESP-IDF Store port: sealed-record slots as NVS blobs (partitions `identity` for identity/trust
// records, `state` for the rest), journal as the raw `journal` partition (config/partitions_*.csv).
// Only the slow-job worker may call it (docs/02 §2): NVS commits and sector erases stall the
// flash cache, so the owner and the radio callbacks never touch it.
//
// init() never formats or erases a partition that fails to open: that would turn a read error into
// "unprovisioned" and wipe identity (docs/12 §2). Erasing is a provisioning action, not part of
// the SDK. NVS encryption (nvs_keys) is not enabled here: it needs the product's key-custody
// decision (docs/12 §2), so secret payloads are protected only as far as the flash itself is.
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
