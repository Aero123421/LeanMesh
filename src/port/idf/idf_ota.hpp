// ESP-IDF OTA hooks (S19, T23): the flash side of src/core/ota behind ota::OtaPort. Built only with LM_OTA
// (Kconfig LEANMESH_OTA). COMPILE-ONLY in this release: nothing calls it (no transfer, no engine wiring), and no
// image was ever written, verified or booted through it. Whether esp_ota_* reaches a bootable, rollback-safe state
// after a power cut on a real Flash is exactly what O01/O03 must show on hardware.
#pragma once

#if defined(LM_OTA)

#include "core/ota/ota.hpp"
#include "esp_ota_ops.h"

namespace lm::idf {

class IdfOta final : public ota::OtaPort {
  public:
    uint32_t inactive_slot_bytes() override;
    uint8_t inactive_slot() override;
    Status begin(uint32_t image_bytes) override;
    Status write(uint32_t offset, ByteView block) override;
    Status verify(const Sha256Digest &expected) override;
    Status set_boot_next() override;
    ota::BootFacts boot_facts() override;
    Status mark_valid() override;
    Status rollback() override;

  private:
    const esp_partition_t *target_ = nullptr;
    esp_ota_handle_t handle_ = 0;
    uint32_t image_bytes_ = 0;
    uint8_t block_[ota::k_block_bytes]; // read-back buffer of verify(): exists only in an image built with LM_OTA
};

} // namespace lm::idf

#endif
