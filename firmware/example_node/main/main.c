/*
 * LeanMesh SDK-linked sample (docs/16 "SDKをlinkした同一サンプル").
 * Same radio bring-up as firmware/baseline_espnow, then the public C API. Only entry points that
 * are implemented in this build are called; the sample grows as slices land (lm_init/lm_start
 * replace the manual bring-up once the IDF port owns the radio).
 */
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_now.h"
#include "esp_wifi.h"
#include "leanmesh.h"
#include "nvs_flash.h"

static const char *TAG = "lm_example";

void app_main(void) {
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_now_init());

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
}
