/*
 * BENCH / FIELD TEST ONLY: firmware/field_node, see ../CMakeLists.txt and docs/field/protocol.md.
 *
 * An unprovisioned board answers the provisioning console of firmware/hil_node (shared: firmware/common/bench_console;
 * tools/hil/hil.py provision leaf|relay drives it). A provisioned board runs field_app.c by itself: join, telemetry,
 * ping, display. A NVS counter counts the boots.
 */
#include <stdint.h>

#include "bench_console.h"
#include "field_app.h"
#include "leanmesh_bench.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

#if CONFIG_FIELD_HUB75
#define NODE_ROLE_NAME "display"
#elif CONFIG_LEANMESH_PROFILE_RELAY
#define NODE_ROLE_NAME "relay"
#else
#define NODE_ROLE_NAME "leaf"
#endif

/* The boot counter (u16, wraps): read, add one, write back. A NVS error leaves it at 0. */
static uint16_t boot_counter_bump(void) {
    nvs_handle_t h;
    uint16_t boots = 0;
    if (nvs_open("field", NVS_READWRITE, &h) != ESP_OK) return 0;
    (void)nvs_get_u16(h, "boot", &boots);
    ++boots;
    if (nvs_set_u16(h, "boot", boots) != ESP_OK || nvs_commit(h) != ESP_OK) boots = 0;
    nvs_close(h);
    return boots;
}

void app_main(void) {
    bc_board_init();
    esp_err_t err = nvs_flash_init(); /* the default "nvs" partition (Wi-Fi/PHY data), plaintext on a bench board */
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }
    uint32_t state = 0;
    if (lmb_state(&state) != LM_STATUS_OK || state != LMB_PROVISIONED) {
        bc_provisioning_console(NODE_ROLE_NAME); /* never returns */
    }
    field_app_run(boot_counter_bump()); /* never returns */
}
