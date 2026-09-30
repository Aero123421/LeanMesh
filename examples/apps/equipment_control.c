#include "equipment_control.h"
#include <string.h>

void equipment_init(equipment_t *eq, int (*drive)(void *, uint8_t), void *user) {
 memset(eq, 0, sizeof *eq);
 eq->drive = drive;
 eq->user = user;
}

size_t equipment_encode(uint8_t out[EQUIPMENT_COMMAND_BYTES], uint32_t revision, uint8_t on) {
 out[0] = 1u;
 out[1] = (uint8_t)'S';
 out[2] = (uint8_t)(revision >> 24u);
 out[3] = (uint8_t)(revision >> 16u);
 out[4] = (uint8_t)(revision >> 8u);
 out[5] = (uint8_t)revision;
 out[6] = on;
 return EQUIPMENT_COMMAND_BYTES;
}

static void result_bytes(uint8_t r[5], uint32_t revision, uint8_t on) {
 r[0] = (uint8_t)(revision >> 24u);
 r[1] = (uint8_t)(revision >> 16u);
 r[2] = (uint8_t)(revision >> 8u);
 r[3] = (uint8_t)revision;
 r[4] = on;
}

/* One command. Returns the outcome to report; *result holds the typed answer. */
static uint32_t apply(equipment_t *eq, const uint8_t *p, size_t n, uint8_t result[5]) {
 if (n != EQUIPMENT_COMMAND_BYTES || p[0] != 1u || p[1] != (uint8_t)'S' || p[6] > 1u) {
  result_bytes(result, eq->revision, eq->on);
  return LM_OUTCOME_REJECTED; /* malformed: nothing was touched */
 }
 const uint32_t rev = ((uint32_t)p[2] << 24u) | ((uint32_t)p[3] << 16u) | ((uint32_t)p[4] << 8u) | p[5];
 if (rev < eq->revision || (rev == eq->revision && p[6] != eq->on)) {
  result_bytes(result, eq->revision, eq->on);
  return LM_OUTCOME_REJECTED; /* an old or conflicting revision never overrides a newer state */
 }
 if (rev == eq->revision && rev != 0u) {
  result_bytes(result, eq->revision, eq->on);
  return LM_OUTCOME_APPLIED; /* the same command again: already applied, the driver is not touched twice */
 }
 if (eq->drive(eq->user, p[6]) != 0) {
  result_bytes(result, eq->revision, eq->on);
  return LM_OUTCOME_REJECTED; /* the driver did not confirm: report the truth, not the wish */
 }
 eq->revision = rev;
 eq->on = p[6];
 result_bytes(result, eq->revision, eq->on);
 return LM_OUTCOME_APPLIED;
}

unsigned equipment_poll(lm_context_t *ctx, equipment_t *eq) {
 unsigned answered = 0;
 for (;;) {
  lm_event_t ev;
  uint8_t payload[512]; /* the largest message; a smaller buffer would leave the event queued */
  size_t needed = 0;
  memset(&ev, 0, sizeof ev);
  ev.struct_size = sizeof ev;
  ev.abi_version = LM_ABI_VERSION;
  if (lm_next_event(ctx, &ev, payload, sizeof payload, &needed) != LM_STATUS_OK) {
   return answered;
  }
  if (ev.kind != LM_EVENT_MESSAGE || ev.app_port != EQUIPMENT_PORT) {
   continue;
  }
  uint8_t result[5];
  const uint32_t outcome = apply(eq, payload, needed, result);
  lm_message_ref_t ref;
  memset(&ref, 0, sizeof ref);
  ref.origin = ev.peer;
  ref.assignment_generation = ev.origin_assignment_generation;
  ref.id = ev.message_id;
  memcpy(ref.intent_hash, ev.intent_hash, sizeof ref.intent_hash);
  if (lm_report_application_result(ctx, &ref, outcome, result, sizeof result, NULL) == LM_STATUS_OK) {
   ++answered;
   if (outcome == LM_OUTCOME_APPLIED) {
    ++eq->applied;
   } else {
    ++eq->rejected;
   }
  }
 }
}
