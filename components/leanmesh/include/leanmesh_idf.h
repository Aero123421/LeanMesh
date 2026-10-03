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

#ifdef __cplusplus
}
#endif
#endif
