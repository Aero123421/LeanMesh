#include "port/idf/idf_store.hpp"

#include <array>
#include <cstdio>

#include "esp_partition.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "sdkconfig.h"
#include "security/crypto.hpp"

#if !CONFIG_NVS_ENCRYPTION && !CONFIG_LEANMESH_ALLOW_PLAINTEXT_SECRETS
// FIX8-D7: the device's private key never goes to a plaintext NVS partition unless a development build says so.
#error "LeanMesh keeps the device key in NVS: enable CONFIG_NVS_ENCRYPTION (development: LEANMESH_ALLOW_PLAINTEXT_SECRETS)"
#endif

namespace lm::idf {
namespace {

constexpr const char *k_identity_partition = "identity";
constexpr const char *k_state_partition = "state";
constexpr const char *k_journal_partition = "journal";
constexpr const char *k_namespace = "lm";
constexpr uint16_t k_marker_flag = 0x8000; // same key space as src/store/record.hpp

const char *partition_for(uint16_t record) {
    const uint16_t id = record & static_cast<uint16_t>(~k_marker_flag);
    return (id == 2 || id == 3) ? k_identity_partition : k_state_partition; // identity, fleet_trust
}

struct Key {
    std::array<char, 16> text{};
    explicit Key(uint16_t record, uint8_t slot) {
        std::snprintf(text.data(), text.size(), "%c%04x.%u", (record & k_marker_flag) ? 'm' : 'r',
                      static_cast<unsigned>(record & 0x7FFFU), static_cast<unsigned>(slot));
    }
};

// RAII NVS handle; open failure is a storage failure, never "empty".
class Nvs {
  public:
    Nvs(uint16_t record, nvs_open_mode_t mode) {
        err_ = nvs_open_from_partition(partition_for(record), k_namespace, mode, &h_);
    }
    ~Nvs() {
        if (err_ == ESP_OK) {
            nvs_close(h_);
        }
    }
    Nvs(const Nvs &) = delete;
    Nvs &operator=(const Nvs &) = delete;
    [[nodiscard]] esp_err_t error() const { return err_; }
    [[nodiscard]] nvs_handle_t handle() const { return h_; }

  private:
    nvs_handle_t h_ = 0;
    esp_err_t err_ = ESP_FAIL;
};

// One SDK partition mounted by the SDK itself: a mount made earlier by someone else (maybe without encryption) is ended
// first, so the one in use is surely this one.
bool mount(const char *label, nvs_sec_cfg_t *keys) {
    (void)nvs_flash_deinit_partition(label); // (ESP_ERR_NVS_NOT_INITIALIZED: nothing was mounted)
    return keys != nullptr ? nvs_flash_secure_init_partition(label, keys) == ESP_OK
                           : nvs_flash_init_partition(label) == ESP_OK;
}

} // namespace

Status IdfStore::init() {
    ready_ = false;
#if CONFIG_NVS_ENCRYPTION
    // The XTS keys of the registered scheme; never generated here (provisioning). They leave RAM right after the mounts
    // (NVS keeps its own copy in the partitions' cipher contexts).
    nvs_sec_cfg_t keys{};
    nvs_sec_scheme_t *scheme = nvs_flash_get_default_security_scheme();
    bool ok = scheme != nullptr && nvs_flash_read_security_cfg_v2(scheme, &keys) == ESP_OK;
    ok = ok && mount(k_identity_partition, &keys) && mount(k_state_partition, &keys);
    sec::secure_zero(MutByteView{reinterpret_cast<uint8_t *>(&keys), sizeof(keys)});
#else
    // Acknowledged development build: plaintext.
    const bool ok = mount(k_identity_partition, nullptr) && mount(k_state_partition, nullptr);
#endif
    if (!ok) {
        return Status::StorageFailure;
    }
    journal_ = esp_partition_find_first(ESP_PARTITION_TYPE_ANY, ESP_PARTITION_SUBTYPE_ANY,
                                        k_journal_partition);
    if (journal_ == nullptr || journal_->size < 3U * k_segment_bytes) {
        return Status::StorageFailure;
    }
    segments_ = journal_->size / k_segment_bytes;
    ready_ = true;
    return Status::Ok;
}

Status IdfStore::slot_read(uint16_t record, uint8_t slot, MutByteView out, std::size_t &len) {
    len = 0;
    if (!ready_) {
        return Status::StorageFailure;
    }
    Nvs nvs(record, NVS_READONLY);
    if (nvs.error() == ESP_ERR_NVS_NOT_FOUND) {
        return Status::NotFound; // namespace not created yet: nothing was ever written
    }
    if (nvs.error() != ESP_OK) {
        return Status::StorageFailure;
    }
    const Key key(record, slot);
    size_t size = 0;
    esp_err_t err = nvs_get_blob(nvs.handle(), key.text.data(), nullptr, &size);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        return Status::NotFound;
    }
    if (err != ESP_OK) {
        return Status::StorageFailure;
    }
    if (size > out.size()) {
        return Status::BufferTooSmall;
    }
    err = nvs_get_blob(nvs.handle(), key.text.data(), out.data(), &size);
    if (err != ESP_OK) {
        return Status::StorageFailure;
    }
    len = size;
    return Status::Ok;
}

Status IdfStore::slot_write(uint16_t record, uint8_t slot, ByteView data) {
    if (!ready_ || slot > 1) {
        return slot > 1 ? Status::InvalidArgument : Status::StorageFailure;
    }
    Nvs nvs(record, NVS_READWRITE);
    if (nvs.error() != ESP_OK) {
        return Status::StorageFailure;
    }
    const Key key(record, slot);
    if (nvs_set_blob(nvs.handle(), key.text.data(), data.data(), data.size()) != ESP_OK ||
        nvs_commit(nvs.handle()) != ESP_OK) {
        return Status::StorageFailure;
    }
    return Status::Ok; // committed; src/store additionally reads back and hashes
}

Status IdfStore::slot_erase(uint16_t record, uint8_t slot) {
    if (!ready_) {
        return Status::StorageFailure;
    }
    Nvs nvs(record, NVS_READWRITE);
    if (nvs.error() != ESP_OK) {
        return Status::StorageFailure;
    }
    const Key key(record, slot);
    const esp_err_t err = nvs_erase_key(nvs.handle(), key.text.data());
    if (err != ESP_OK && err != ESP_ERR_NVS_NOT_FOUND) {
        return Status::StorageFailure;
    }
    return nvs_commit(nvs.handle()) == ESP_OK ? Status::Ok : Status::StorageFailure;
}

Status IdfStore::journal_read(uint32_t offset, MutByteView out) {
    if (!ready_ || offset > journal_->size || out.size() > journal_->size - offset) {
        return Status::InvalidArgument;
    }
    return esp_partition_read(journal_, offset, out.data(), out.size()) == ESP_OK
               ? Status::Ok
               : Status::StorageFailure;
}

Status IdfStore::journal_write(uint32_t offset, ByteView data) {
    if (!ready_ || offset > journal_->size || data.size() > journal_->size - offset) {
        return Status::InvalidArgument;
    }
    if (esp_partition_write(journal_, offset, data.data(), data.size()) != ESP_OK) {
        return Status::StorageFailure;
    }
    std::array<uint8_t, 64> back{}; // durable = programmed and read back equal
    for (std::size_t done = 0; done < data.size(); done += back.size()) {
        const std::size_t n = data.size() - done < back.size() ? data.size() - done : back.size();
        if (esp_partition_read(journal_, offset + done, back.data(), n) != ESP_OK ||
            !bytes_equal(ByteView{back.data(), n}, data.subspan(done, n))) {
            return Status::StorageFailure;
        }
    }
    return Status::Ok;
}

Status IdfStore::journal_erase(uint32_t segment) {
    if (!ready_ || segment >= segments_) {
        return Status::InvalidArgument;
    }
    return esp_partition_erase_range(journal_, segment * k_segment_bytes, k_segment_bytes) == ESP_OK
               ? Status::Ok
               : Status::StorageFailure;
}

} // namespace lm::idf
