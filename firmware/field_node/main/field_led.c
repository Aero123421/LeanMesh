/* Status LED; see field_led.h. */
#include "field_led.h"

#include "driver/gpio.h"
#include "sdkconfig.h"

#if !CONFIG_FIELD_LED_NONE

#if CONFIG_FIELD_LED_ACTIVE_LOW
#define LED_ON_LEVEL 0
#else
#define LED_ON_LEVEL 1
#endif

static field_led_mode_t s_mode = FIELD_LED_OFF;
static int s_level = -1; /* -1: not written yet */

static void write(bool on) {
    const int level = on ? LED_ON_LEVEL : !LED_ON_LEVEL;
    if (level != s_level) {
        s_level = level;
        gpio_set_level((gpio_num_t)CONFIG_FIELD_LED_GPIO, (uint32_t)level);
    }
}

void field_led_init(void) {
    gpio_config_t io = {.pin_bit_mask = 1ULL << CONFIG_FIELD_LED_GPIO, .mode = GPIO_MODE_OUTPUT};
    gpio_config(&io);
    write(false);
}

void field_led_set(field_led_mode_t mode) {
    s_mode = mode;
    if (mode != FIELD_LED_BLINK) {
        write(mode == FIELD_LED_ON);
    }
}

void field_led_tick(uint64_t now_ms) {
    if (s_mode == FIELD_LED_BLINK) {
        write((now_ms / 500) % 2 == 0);
    }
}

#else /* no LED */

void field_led_init(void) {}
void field_led_set(field_led_mode_t mode) { (void)mode; }
void field_led_tick(uint64_t now_ms) { (void)now_ms; }

#endif
