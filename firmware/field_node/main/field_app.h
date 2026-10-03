#ifndef FIELD_APP_H
#define FIELD_APP_H
/* The autonomous part of the field node (docs/field/protocol.md): starts the mesh of a provisioned board, joins by itself,
   sends telemetry, answers pings and display commands, keeps the status LED and the panel. Never returns. */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* `boot_count`: the NVS boot counter of this boot (main.c). */
void field_app_run(uint16_t boot_count) __attribute__((noreturn));

#ifdef __cplusplus
}
#endif
#endif
