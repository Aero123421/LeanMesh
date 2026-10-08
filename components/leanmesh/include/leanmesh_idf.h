#ifndef LEANMESH_IDF_H
#define LEANMESH_IDF_H
/* ESP-IDF port extension of the LeanMesh SDK (not part of the C ABI of api/leanmesh.h). */
#include <stdbool.h>
#include <stdint.h>
#include "leanmesh.h"

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
#define LM_IDF_RESTART_RADIO_STALL 1u /* a TX completion never came, even 2 s after the 3 s watchdog: driver not drained */
#define LM_IDF_RESTART_RADIO_RECOVERY 2u
typedef struct {
    uint32_t uptime_ms, reason, status, attempts, tx_frames, rx_frames;
    bool previous_boot;
} lm_idf_recovery_t;
typedef struct {
    uint32_t cause;     /* LM_IDF_RESTART_* */
    uint32_t uptime_ms; /* how long that boot had run */
    uint32_t detail;    /* RADIO_STALL: how long the TX completion had been outstanding, ms */
    lm_idf_recovery_t recovery;
} lm_idf_restart_t;
/* true and *out filled when the previous boot ended in such a restart; false otherwise. Any task, any time. */
bool lm_idf_last_restart(lm_idf_restart_t *out);

/* Radio facts since boot (field diagnostics). Any task. */
typedef struct {
    uint32_t tx_done_max_ms; /* the longest time from a TX to its completion */
    uint32_t tx_late;        /* completions that took 1 s or longer */
    uint32_t tx_stall_waits; /* radio recoveries that found a completion overdue (watchdog) */
    bool tx_power_valid;
    int16_t tx_power_qdbm; /* driver readback, quarter dBm; the requested ceiling may be higher */
} lm_idf_radio_stats_t;
void lm_idf_radio_stats(lm_idf_radio_stats_t *out);

typedef struct {
    bool faulted, running;
    uint32_t peers;
    uint64_t rx_frames, tx_frames, unicast_acked;
} lm_idf_radio_health_t;
/* Owner snapshot; does not consume the Host's event queue. */
lm_status_t lm_idf_radio_health(lm_context_t *ctx, lm_idf_radio_health_t *out);
void lm_idf_record_radio_recovery(uint32_t reason, lm_status_t status, uint64_t tx_frames, uint64_t rx_frames);
void lm_idf_finish_radio_recovery(lm_status_t status);
bool lm_idf_last_radio_recovery(lm_idf_recovery_t *out);
/* Saves the reason/status/counters in RTC before rebooting. */
void lm_idf_restart_radio_recovery(void);

#ifdef __cplusplus
}
#endif
#endif
