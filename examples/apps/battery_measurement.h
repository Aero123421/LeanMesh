/* Example application 2 (docs/17 G6): periodic battery measurement. Uses only api/leanmesh.h and libc.
   Wire format on port BATTERY_PORT: version(1) | sequence u32 BE | millivolts u16 BE | percent u8 (8 bytes with a
   reserved zero). Only the newest reading matters, so it is sent LATEST + BEST_EFFORT + VOLATILE with one coalesce key:
   a reading that never left the node is replaced by the next one, and no deadline-less history is created. */
#ifndef BATTERY_MEASUREMENT_H
#define BATTERY_MEASUREMENT_H
#include "leanmesh.h"
#ifdef __cplusplus
extern "C" {
#endif

#define BATTERY_PORT 200u
#define BATTERY_READING_BYTES 8u

typedef struct {
 uint32_t sequence;
 uint64_t last_report_ms; /* platform monotonic ms of the last report */
 uint32_t interval_ms;
 int reported_once;
} battery_t;

void battery_init(battery_t *b, uint32_t interval_ms);
/* True when a report is due at the platform time `now_ms` (the caller sleeps until then; the SDK is not polled). */
int battery_due(const battery_t *b, uint64_t now_ms);
/* Sends one reading to the root application (the Host); it is worth sending for `ttl_ms` only. Its deadline comes
   from the node's root clock (lm_root_time_get): without an estimate of the current root term it is TIME_UNCERTAIN. */
lm_status_t battery_report(lm_context_t *ctx, battery_t *b, uint64_t now_ms, uint32_t ttl_ms, uint16_t millivolts,
                           uint8_t percent, lm_operation_id_t *operation);
size_t battery_encode(uint8_t out[BATTERY_READING_BYTES], uint32_t sequence, uint16_t millivolts, uint8_t percent);
#ifdef __cplusplus
}
#endif
#endif
