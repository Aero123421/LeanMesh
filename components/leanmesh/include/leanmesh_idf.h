#ifndef LEANMESH_IDF_H
#define LEANMESH_IDF_H
/* ESP-IDF port extension of the LeanMesh SDK (not part of the C ABI of api/leanmesh.h). */
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Optional, defined by the application (the SDK declares it weak; without a definition nothing is held back).
   Asked when a WINDOWED_RX window closes, before the radio is stopped: true holds this light sleep (LM_SLEEP_LIGHT)
   back - the node stays awake with its radio and sessions, its next window still opens on time (it polls its parent
   as usual) and the SDK asks again when that window closes. For a board's
   maintenance path: a held button, or a USB-Serial/JTAG host attached (light sleep stops that port, so a sleeping
   board can neither be read nor flashed). Called on the SDK's owner task: return at once, no blocking, no SDK call.
   It does not change the power policy and never lowers a docs/06 condition. */
bool lm_idf_sleep_veto(uint8_t sleep_kind);

/* Why the previous boot ended, when the SDK itself restarted the chip (field diagnostics, HIL 2026-10-04). Kept in RTC
   memory: it survives a software reset, not a power loss (the chip's reset reason then says power-on). */
#define LM_IDF_RESTART_RADIO_STALL 1u /* a TX completion never came, even 2 s after the 1 s watchdog: driver not drained */
typedef struct {
    uint32_t cause;     /* LM_IDF_RESTART_* */
    uint32_t uptime_ms; /* how long that boot had run */
    uint32_t detail;    /* RADIO_STALL: how long the TX completion had been outstanding, ms */
} lm_idf_restart_t;
/* true and *out filled when the previous boot ended in such a restart; false otherwise. Any task, any time. */
bool lm_idf_last_restart(lm_idf_restart_t *out);

/* Radio facts since boot (field diagnostics). Any task. */
typedef struct {
    uint32_t tx_done_max_ms; /* the longest time from a TX to its completion */
    uint32_t tx_late;        /* completions that took 1 s or longer */
    uint32_t tx_stall_waits; /* radio recoveries that found a completion overdue (watchdog) */
} lm_idf_radio_stats_t;
void lm_idf_radio_stats(lm_idf_radio_stats_t *out);

#ifdef __cplusplus
}
#endif
#endif
