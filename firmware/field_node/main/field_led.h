#ifndef FIELD_LED_H
#define FIELD_LED_H
/* Optional status LED (Kconfig FIELD_LED): off = not a member / lost, blinking = joining, on = reachable.
   Without an LED (FIELD_LED_NONE) every call does nothing. */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { FIELD_LED_OFF, FIELD_LED_BLINK, FIELD_LED_ON } field_led_mode_t;

void field_led_init(void);
void field_led_set(field_led_mode_t mode);
/* Toggles a blinking LED every 500 ms. Called from the application loop (every 50 ms): no timer, no task. */
void field_led_tick(uint64_t now_ms);

#ifdef __cplusplus
}
#endif
#endif
