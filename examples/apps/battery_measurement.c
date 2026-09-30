#include "battery_measurement.h"
#include <string.h>

void battery_init(battery_t *b, uint32_t interval_ms) {
 memset(b, 0, sizeof *b);
 b->interval_ms = interval_ms;
}

int battery_due(const battery_t *b, uint64_t now_ms) {
 return !b->reported_once || now_ms - b->last_report_ms >= b->interval_ms;
}

size_t battery_encode(uint8_t out[BATTERY_READING_BYTES], uint32_t sequence, uint16_t millivolts, uint8_t percent) {
 out[0] = 1u;
 out[1] = (uint8_t)(sequence >> 24u);
 out[2] = (uint8_t)(sequence >> 16u);
 out[3] = (uint8_t)(sequence >> 8u);
 out[4] = (uint8_t)sequence;
 out[5] = (uint8_t)(millivolts >> 8u);
 out[6] = (uint8_t)millivolts;
 out[7] = percent;
 return BATTERY_READING_BYTES;
}

lm_status_t battery_report(lm_context_t *ctx, battery_t *b, uint64_t now_ms, uint32_t ttl_ms, uint16_t millivolts,
                           uint8_t percent, lm_operation_id_t *operation) {
 uint8_t reading[BATTERY_READING_BYTES];
 lm_root_time_t t;
 memset(&t, 0, sizeof t);
 t.struct_size = sizeof t;
 t.abi_version = LM_ABI_VERSION;
 const lm_status_t ts = lm_root_time_get(ctx, &t);
 if (ts != LM_STATUS_OK) {
  return ts;
 }
 if (!t.valid) {
  return LM_STATUS_TIME_UNCERTAIN; /* no root clock of the current term yet: no provable deadline */
 }
 lm_send_request_t r;
 memset(&r, 0, sizeof r);
 r.struct_size = sizeof r;
 r.abi_version = LM_ABI_VERSION;
 r.destination.kind = LM_DEST_ROOT_APP;
 r.app_port = BATTERY_PORT;
 r.delivery = LM_BEST_EFFORT;
 r.storage = LM_VOLATILE;
 r.priority = LM_PRIORITY_BULK;
 r.queue_mode = LM_LATEST;
 r.coalesce_key = 1u;
 r.root_term = t.root_term;
 r.expires_root_ms = t.earliest_root_ms + ttl_ms; /* from the earliest reading: never longer than asked */
 (void)battery_encode(reading, b->sequence + 1u, millivolts, percent);
 const lm_status_t st = lm_send(ctx, &r, reading, sizeof reading, operation);
 if (st == LM_STATUS_OK) { /* the sequence counts accepted reports only */
  ++b->sequence;
  b->last_report_ms = now_ms;
  b->reported_once = 1;
 }
 return st;
}
