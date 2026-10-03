/* The 64x32 HUB75 panel of the display build (CONFIG_FIELD_HUB75), see field_display.h.

   Board: Seengreat RGB Matrix HUB75 S3 (ESP32-S3-WROOM-1-N16R8), panel 64x32 with FM6124 drivers. The panel library is
   ESP32-HUB75-MatrixPanel-DMA (MIT, main/idf_component.yml), built without Adafruit GFX (NO_GFX); on the S3 it clocks
   the panel with the LCD_CAM peripheral and GDMA, so no CPU time goes into the refresh. All calls come from the
   application task (field_app.c). */
#include <new>

#include "ESP32-HUB75-MatrixPanel-I2S-DMA.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "sdkconfig.h"

extern "C" {
#include "field_display.h"
}

namespace {

constexpr char kTag[] = "field_display";
constexpr uint8_t kBrightness = CONFIG_FIELD_HUB75_BRIGHTNESS; /* of 255 */

MatrixPanel_I2S_DMA *s_panel;
uint16_t s_frame[FIELD_PANEL_H][FIELD_PANEL_W];

} // namespace

extern "C" bool field_display_present(void) { return true; }

extern "C" bool field_display_init(void) {
    if (s_panel != nullptr) {
        return true;
    }
    /* r1 g1 b1 r2 g2 b2 | a b c d e | lat oe clk: fixed on the board. */
    const HUB75_I2S_CFG::i2s_pins pins = {5, 4, 6, 15, 7, 17, 8, 18, 10, 9, 16, 11, 13, 12};
    HUB75_I2S_CFG cfg(FIELD_PANEL_W, FIELD_PANEL_H, 1, pins, HUB75_I2S_CFG::FM6124, HUB75_I2S_CFG::TYPE138,
                      true /* double buffer: a frame appears whole */, HUB75_I2S_CFG::HZ_8M, DEFAULT_LAT_BLANKING,
                      false /* clkphase: what worked in the bring-up of this board */);
    MatrixPanel_I2S_DMA *panel = new (std::nothrow) MatrixPanel_I2S_DMA(cfg);
    if (panel == nullptr || !panel->begin()) {
        ESP_LOGE(kTag, "panel init failed");
        delete panel;
        return false;
    }
    panel->setBrightness8(kBrightness);
    panel->clearScreen();
    s_panel = panel;
    return true;
}

extern "C" bool field_display_show(const field_view_t *view) {
    if (s_panel == nullptr) {
        return false;
    }
    field_render(view, s_frame);
    s_panel->clearScreen();
    for (int y = 0; y < FIELD_PANEL_H; ++y) {
        for (int x = 0; x < FIELD_PANEL_W; ++x) {
            if (s_frame[y][x] != FIELD_RGB565_BLACK) {
                s_panel->drawPixel(x, y, s_frame[y][x]);
            }
        }
    }
    s_panel->flipDMABuffer();
    vTaskDelay(pdMS_TO_TICKS(40)); /* two refresh periods (>= 60 Hz): the frame is on the panel when this returns */
    return true;
}
