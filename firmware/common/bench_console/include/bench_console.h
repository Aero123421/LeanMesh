#ifndef BENCH_CONSOLE_H
#define BENCH_CONSOLE_H
/* BENCH / HIL ONLY: the line console on the USB-Serial/JTAG port and the provisioning console of an unprovisioned
   board, shared by firmware/hil_node and firmware/field_node (one console, one provisioning protocol: tools/hil/hil.py
   drives both). Needs CONFIG_LEANMESH_BENCH_PROVISIONING (leanmesh_bench.h). Never a product component.

   One command per line, one answer line starting with "OK" or "ERR"; other lines are logs and events. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "freertos/FreeRTOS.h"
#include "leanmesh.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Every byte goes through the USB-Serial/JTAG driver, so logs and answers never interleave mid-line. */
void bc_out(const char *s);
void bc_outf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
/* A log line that never waits: dropped when no USB host is attached (no SOF) or the TX buffer is full. For a loop that must
   not stall on a host that is attached but not reading. Answers to a command use bc_out / bc_outf. */
void bc_logf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void bc_out_hex(const uint8_t *b, size_t n);
void bc_console_init(void);
/* One complete line (without CR/LF), or NULL when none ended within `ticks` in total (a time budget for the whole call, not
   per byte) or within 512 bytes of input; a partial line is kept for the next call. The pointer stays valid until the
   next call. A line longer than 4095 bytes is dropped whole and answered "ERR <INVALID_ARGUMENT>" at its CR/LF. */
char *bc_console_line(TickType_t ticks);
/* Hex token -> bytes. Returns the length, or -1. */
int bc_unhex(const char *tok, uint8_t *dst, size_t cap);
/* "OK" for LM_STATUS_OK, else "ERR <status>". */
void bc_answer(lm_status_t st);

/* The console of an unprovisioned board (mesh never started); never returns. Commands: info | keygen |
   prov-leaf <trust88> <device_cose> <ticket> | prov-root ... | reboot (hex arguments). A successful prov-* restarts the
   board. `role_name` is only printed ("leaf", "relay", "root", "display"). */
void bc_provisioning_console(const char *role_name) __attribute__((noreturn));

/* Sets the power policy of a started node back to ALWAYS_RX when it is not (a WINDOWED/REPORT_ONLY policy light-sleeps
   the chip, and light sleep stops the USB-Serial/JTAG port: no console, no esptool). Returns true when the node reads
   ALWAYS_RX. Retries for about 2 s: the policy change is asynchronous. */
bool bc_force_always_rx(lm_context_t *ctx);

/* Board overlay (Kconfig HIL_XIAO_C6_*, bench boards only): the antenna path before the radio ever starts. Call it first
   in app_main. Does nothing for a board without an overlay. */
void bc_board_init(void);

#ifdef __cplusplus
}
#endif
#endif
