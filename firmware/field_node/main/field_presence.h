#ifndef FIELD_PRESENCE_H
#define FIELD_PRESENCE_H
#include "field_proto.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Pure C boundary of the exact KG detector; acquisition task is sole owner.
   FIELD_TOF=1 builds the detector; FIELD_TOF=0 has no KG dependency and always
   reports disabled/no sensor. No NVS: ToF boot starts unlearned, reconnect keeps
   the current background. A failed relearn waits for fresh reevaluation. */
void field_presence_begin(bool enabled, uint64_t now);
void field_presence_ready(bool ready);
bool field_presence_learn(uint64_t now);
void field_presence_sample(uint64_t now, uint16_t mm, uint8_t mapped_status);
void field_presence_tick(uint64_t now);
void field_presence_capture(uint64_t now, field_presence_snapshot_t *out);
#ifdef __cplusplus
}
#endif
#endif
