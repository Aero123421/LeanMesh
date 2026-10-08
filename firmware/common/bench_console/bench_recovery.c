#include "bench_recovery.h"

bool bc_is_radio_fault(uint32_t reason) { return reason == LM_STATUS_DRIVER_RESULT_UNKNOWN; }

uint32_t bc_radio_watch(bc_radio_watch_t *w, const bc_radio_sample_t *s, uint32_t now) {
    if (s->faulted) return BC_RADIO_FAULT;
    if (!s->running || s->peers == 0 || s->rx_frames != w->rx_frames || !w->heard) {
        w->rx_at_ms = now;
        w->rx_frames = s->rx_frames;
        w->ack_base = s->unicast_acked;
        w->heard = s->running && s->peers != 0 && s->rx_frames != 0;
        return BC_RADIO_NO_FAULT;
    }
    if ((uint32_t)(now - w->rx_at_ms) >= 120000 && s->unicast_acked - w->ack_base >= 3) {
        *w = (bc_radio_watch_t){0};
        return BC_RADIO_RX_STALL;
    }
    return BC_RADIO_NO_FAULT;
}

lm_status_t bc_radio_restart(lm_context_t *ctx, lm_status_t *stopped) {
    *stopped = lm_stop(ctx, 0, NULL);
    return *stopped == LM_STATUS_OK ? lm_start(ctx) : *stopped;
}
