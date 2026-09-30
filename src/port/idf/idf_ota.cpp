#include "port/idf/idf_ota.hpp"

#if defined(LM_OTA)

#include <algorithm>

#include "esp_partition.h"
#include "security/crypto.hpp"

namespace lm::idf {

namespace {

// Slot number = position in the ota_N subtype range.
uint8_t slot_of(const esp_partition_t *p) {
    return p != nullptr && p->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_1 ? 1 : 0;
}

Status map(esp_err_t e) {
    switch (e) {
    case ESP_OK:
        return Status::Ok;
    case ESP_ERR_INVALID_ARG:
    case ESP_ERR_INVALID_SIZE:
        return Status::InvalidArgument;
    case ESP_ERR_NO_MEM:
        return Status::NoCapacity;
    case ESP_ERR_NOT_FOUND:
        return Status::NotFound;
    default:
        return Status::StorageFailure; // a flash or bootloader error: never mapped to success
    }
}

struct ReadCtx {
    const esp_partition_t *part;
    uint8_t *buf;
    uint32_t total;
    Status err;
};

ByteView read_chunk(void *c, std::size_t index) {
    auto *ctx = static_cast<ReadCtx *>(c);
    const uint32_t off = static_cast<uint32_t>(index) * ota::k_block_bytes;
    const uint32_t n = std::min<uint32_t>(ota::k_block_bytes, ctx->total - off);
    if (esp_partition_read(ctx->part, off, ctx->buf, n) != ESP_OK) {
        ctx->err = Status::StorageFailure;
        return ByteView{};
    }
    return ByteView{ctx->buf, n};
}

} // namespace

uint32_t IdfOta::inactive_slot_bytes() {
    const esp_partition_t *p = esp_ota_get_next_update_partition(nullptr);
    return p == nullptr ? 0 : p->size; // 0: the layout has no second app slot (OTA_UNSUPPORTED)
}

uint8_t IdfOta::inactive_slot() { return slot_of(esp_ota_get_next_update_partition(nullptr)); }

Status IdfOta::begin(uint32_t image_bytes) {
    target_ = esp_ota_get_next_update_partition(nullptr);
    if (target_ == nullptr || image_bytes == 0 || image_bytes > target_->size) {
        return Status::Unsupported;
    }
    image_bytes_ = image_bytes;
    return map(esp_ota_begin(target_, image_bytes, &handle_));
}

Status IdfOta::write(uint32_t offset, ByteView block) {
    if (target_ == nullptr || offset + block.size() > image_bytes_) {
        return Status::InvalidArgument;
    }
    return map(esp_ota_write_with_offset(handle_, block.data(), block.size(), offset));
}

Status IdfOta::verify(const Sha256Digest &expected) {
    if (target_ == nullptr) {
        return Status::InvalidArgument;
    }
    LM_TRY(map(esp_ota_end(handle_))); // the bootloader's own image validation
    ReadCtx ctx{target_, block_, image_bytes_, Status::Ok};
    Sha256Digest got{};
    const std::size_t blocks = (image_bytes_ + ota::k_block_bytes - 1) / ota::k_block_bytes;
    LM_TRY(sec::sha256_chunks(&read_chunk, &ctx, blocks, got));
    LM_TRY(ctx.err);
    return sec::ct_equal(ByteView{got}, ByteView{expected}) ? Status::Ok : Status::AuthRejected;
}

Status IdfOta::set_boot_next() {
    return target_ == nullptr ? Status::InvalidArgument : map(esp_ota_set_boot_partition(target_));
}

ota::BootFacts IdfOta::boot_facts() {
    ota::BootFacts f;
    const esp_partition_t *running = esp_ota_get_running_partition();
    f.running_slot = slot_of(running);
    esp_ota_img_states_t st = ESP_OTA_IMG_UNDEFINED;
    if (running != nullptr && esp_ota_get_state_partition(running, &st) == ESP_OK) {
        f.running_pending_verify = st == ESP_OTA_IMG_PENDING_VERIFY;
        f.running_marked_invalid = st == ESP_OTA_IMG_INVALID || st == ESP_OTA_IMG_ABORTED;
    }
    return f;
}

Status IdfOta::mark_valid() { return map(esp_ota_mark_app_valid_cancel_rollback()); }

Status IdfOta::rollback() { return map(esp_ota_mark_app_invalid_rollback_and_reboot()); }

} // namespace lm::idf

#endif // LM_OTA
