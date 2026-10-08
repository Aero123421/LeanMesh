#ifndef BENCH_RECOVERY_H
#define BENCH_RECOVERY_H
#include "leanmesh.h"
#include <stdbool.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    bool faulted, running;
    uint32_t peers;
    uint64_t rx_frames, tx_frames, unicast_acked;
} bc_radio_sample_t;
typedef struct {
    uint32_t rx_at_ms;
    uint64_t rx_frames, ack_base;
    bool heard;
} bc_radio_watch_t;
enum { BC_RADIO_NO_FAULT = 0, BC_RADIO_FAULT = LM_STATUS_DRIVER_RESULT_UNKNOWN, BC_RADIO_RX_STALL = 256 };
bool bc_is_radio_fault(uint32_t reason);
/* ROOT app only, once a second. A silent/absent/sleeping peer supplies no successful unicast evidence. */
uint32_t bc_radio_watch(bc_radio_watch_t *watch, const bc_radio_sample_t *sample, uint32_t now_ms);
lm_status_t bc_radio_restart(lm_context_t *ctx, lm_status_t *stopped);
#ifdef __cplusplus
}
#endif
#endif
