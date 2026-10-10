#ifndef FIELD_ACQUISITION_H
#define FIELD_ACQUISITION_H
#include "field_control.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct {
    uint32_t key_dropped, sensor_errors, key_errors;
    uint32_t k3_presses, learning_busy;
    field_learning_feedback_t learning_feedback;
} field_acquisition_stats_t;
bool field_acquisition_start(void);
void field_acquisition_latest(field_presence_snapshot_t *out, field_acquisition_stats_t *stats);
bool field_acquisition_key(field_key_event_t *out);
/* Main acknowledges only a successful DMA frame carrying this result token. */
void field_acquisition_feedback_shown(uint32_t token, uint64_t now);
#ifdef __cplusplus
}
#endif
#endif
