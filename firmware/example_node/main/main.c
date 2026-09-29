/*
 * LeanMesh SDK-linked sample (docs/16 "SDKをlinkした同一サンプル").
 * The SDK's IDF port now owns the radio bring-up that firmware/baseline_espnow does by hand
 * (netif, Wi-Fi STA, ESP-NOW LR250, callbacks). The sample keeps NVS init, then calls the public C
 * API: lm_init (builds the context, starts the owner and worker tasks, no RF), lm_start (radio up).
 *
 * Only entry points implemented in this build are called. With the default Kconfig the RF profile
 * is NOT approved, so lm_start reports RF_PROFILE_UNAPPROVED and the radio stays off (docs/03 §3).
 */
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "leanmesh.h"
#include "nvs_flash.h"

static const char *TAG = "lm_example";

void app_main(void) {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "default nvs partition unavailable: %s", esp_err_to_name(err));
    }

    lm_config_t config;
    lm_workspace_size_t ws;
    lm_status_t st = lm_config_init(&config, sizeof config);
    if (st == LM_STATUS_OK) {
        st = lm_workspace_required(&config, &ws);
    }
    if (st != LM_STATUS_OK) {
        ESP_LOGE(TAG, "leanmesh config rejected: %u", (unsigned)st);
        return;
    }
    ESP_LOGI(TAG, "leanmesh workspace: %u bytes, align %u", (unsigned)ws.bytes,
             (unsigned)ws.alignment);
    void *workspace = heap_caps_aligned_alloc(ws.alignment, ws.bytes, MALLOC_CAP_INTERNAL);
    if (workspace == NULL) {
        ESP_LOGE(TAG, "workspace allocation failed");
        return;
    }
    lm_context_t *ctx = NULL;
    st = lm_init(workspace, ws.bytes, &config, &ctx);
    if (st != LM_STATUS_OK) {
        ESP_LOGE(TAG, "lm_init failed: %u", (unsigned)st);
        return;
    }
    st = lm_start(ctx);
    if (st != LM_STATUS_OK) {
        ESP_LOGE(TAG, "lm_start refused: %u (13 = RF profile unapproved)", (unsigned)st);
        return;
    }
    lm_event_t ev = {.struct_size = sizeof ev, .abi_version = LM_ABI_VERSION};
    if (lm_next_event(ctx, &ev, NULL, 0, NULL) == LM_STATUS_OK) {
        ESP_LOGI(TAG, "event kind %u", (unsigned)ev.kind);
    }
}
