/* BENCH / HIL ONLY: see include/bench_console.h. Moved out of firmware/hil_node/main/main.c unchanged in behaviour. */
#include "bench_console.h"
#include "bench_line.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "driver/gpio.h"
#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "esp_system.h"
#include "freertos/task.h"
#include "leanmesh_bench.h"
#include "sdkconfig.h"

#define CONSOLE_LINE_MAX 4096
#define BLOB_MAX 1024

/* A call returns after this many bytes even when the input never pauses and never ends a line. */
#define CONSOLE_BYTES_PER_CALL 512

static char s_line[CONSOLE_LINE_MAX];
static bc_line_t s_asm = {.buf = s_line, .cap = sizeof s_line};
static uint8_t s_blob[2][BLOB_MAX];
static const char *s_role_name = "";

void bc_out(const char *s) { usb_serial_jtag_write_bytes(s, strlen(s), pdMS_TO_TICKS(200)); }

void bc_logf(const char *fmt, ...) {
    if (!usb_serial_jtag_is_connected()) return; /* nobody can be reading */
    char buf[384];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    /* No wait: a host that is attached but not reading (port not open) leaves the TX buffer full, and a write that waits
       then costs its whole timeout. A full buffer drops the line. */
    usb_serial_jtag_write_bytes(buf, strlen(buf), 0);
}

void bc_outf(const char *fmt, ...) {
    char buf[384];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    bc_out(buf);
}

void bc_out_hex(const uint8_t *b, size_t n) {
    static const char d[] = "0123456789abcdef";
    char buf[129];
    while (n > 0) {
        size_t k = n > 64 ? 64 : n;
        for (size_t i = 0; i < k; ++i) {
            buf[2 * i] = d[b[i] >> 4];
            buf[2 * i + 1] = d[b[i] & 15];
        }
        buf[2 * k] = '\0';
        bc_out(buf);
        b += k;
        n -= k;
    }
}

void bc_console_init(void) {
    usb_serial_jtag_driver_config_t cfg = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
    cfg.rx_buffer_size = 4096;
    cfg.tx_buffer_size = 1024;
    if (usb_serial_jtag_driver_install(&cfg) == ESP_OK) {
        usb_serial_jtag_vfs_use_driver(); /* stdout (ESP_LOG) through the same driver */
    }
}

/* `ticks` is the whole budget of the call (not per byte): input that never pauses, or never ends a line, cannot keep the
   caller inside. The line in progress stays in s_asm for the next call. portMAX_DELAY waits for a line without a time
   bound, but still hands control back after CONSOLE_BYTES_PER_CALL bytes. */
char *bc_console_line(TickType_t ticks) {
    const TickType_t start = xTaskGetTickCount();
    TickType_t wait = ticks;
    uint8_t c;
    for (int taken = 0; taken < CONSOLE_BYTES_PER_CALL && usb_serial_jtag_read_bytes(&c, 1, wait) == 1; ++taken) {
        switch (bc_line_feed(&s_asm, c)) {
        case BC_LINE_READY:
            return s_line;
        case BC_LINE_OVERFLOW:
            bc_answer(LM_STATUS_INVALID_ARGUMENT); /* the line was too long: dropped whole, answered once */
            break;
        case BC_LINE_PENDING:
            break;
        }
        if (ticks != portMAX_DELAY) {
            const TickType_t used = xTaskGetTickCount() - start;
            if (used >= ticks) {
                break;
            }
            wait = ticks - used;
        }
    }
    return NULL;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int bc_unhex(const char *tok, uint8_t *dst, size_t cap) {
    size_t n = tok != NULL ? strlen(tok) : 0;
    if (n == 0 || n % 2 != 0 || n / 2 > cap) return -1;
    for (size_t i = 0; i < n / 2; ++i) {
        int h = hexval(tok[2 * i]), l = hexval(tok[2 * i + 1]);
        if (h < 0 || l < 0) return -1;
        dst[i] = (uint8_t)(h << 4 | l);
    }
    return (int)(n / 2);
}

void bc_answer(lm_status_t st) {
    if (st == LM_STATUS_OK) {
        bc_out("OK\n");
    } else {
        bc_outf("ERR %u\n", (unsigned)st);
    }
}

/* ---- provisioning console (unprovisioned board, mesh never started) ---- */

static void print_key(const lmb_key_t *k) {
    bc_out(" pub=");
    bc_out_hex(k->public_key, sizeof k->public_key);
    bc_out(" id=");
    bc_out_hex(k->device_id, sizeof k->device_id);
}

static void prov_command(char *line) {
    char *save = NULL;
    const char *cmd = strtok_r(line, " ", &save);
    if (cmd == NULL) return;
    if (strcmp(cmd, "info") == 0) {
        uint32_t state = 0;
        lm_status_t st = lmb_state(&state);
        if (st != LM_STATUS_OK) {
            bc_answer(st);
            return;
        }
        bc_outf("OK state=%u role=%s", (unsigned)state, s_role_name);
        lmb_key_t k;
        if (state == LMB_KEY_PENDING && lmb_keygen(&k) == LM_STATUS_OK) print_key(&k);
        bc_out("\n");
    } else if (strcmp(cmd, "keygen") == 0) {
        lmb_key_t k;
        lm_status_t st = lmb_keygen(&k);
        if (st != LM_STATUS_OK) {
            bc_answer(st);
            return;
        }
        bc_out("OK");
        print_key(&k);
        bc_out("\n");
    } else if (strcmp(cmd, "prov-leaf") == 0 || strcmp(cmd, "prov-root") == 0) {
        const bool root = strcmp(cmd, "prov-root") == 0;
        uint8_t trust[88];
        uint8_t host[32];
        int nt = bc_unhex(strtok_r(NULL, " ", &save), trust, sizeof trust);
        int nd = bc_unhex(strtok_r(NULL, " ", &save), s_blob[0], BLOB_MAX);
        int nx = bc_unhex(strtok_r(NULL, " ", &save), s_blob[1], BLOB_MAX);
        int nh = root ? bc_unhex(strtok_r(NULL, " ", &save), host, sizeof host) : 32;
        /* prov-root takes an optional first term: the REPLACEMENT root of a failed one (no ledger, issue #5). */
        const char *term_tok = root ? strtok_r(NULL, " ", &save) : NULL;
        const unsigned long first_term = term_tok != NULL ? strtoul(term_tok, NULL, 10) : 0;
        if (nt != 88 || nd <= 0 || nx <= 0 || nh != 32 || (term_tok != NULL && (first_term < 2 || first_term > 0xFFFFFFFFUL))) {
            bc_answer(LM_STATUS_INVALID_ARGUMENT);
            return;
        }
        lm_status_t st = !root ? lmb_provision_leaf(trust, s_blob[0], (size_t)nd, s_blob[1], (size_t)nx)
                         : term_tok != NULL
                             ? lmb_provision_replacement_root(trust, s_blob[0], (size_t)nd, s_blob[1], (size_t)nx, host,
                                                              (uint32_t)first_term)
                             : lmb_provision_root(trust, s_blob[0], (size_t)nd, s_blob[1], (size_t)nx, host);
        bc_answer(st);
        if (st == LM_STATUS_OK) {
            vTaskDelay(pdMS_TO_TICKS(200));
            esp_restart(); /* the mesh starts from the committed records, with a clean USB driver state */
        }
    } else if (strcmp(cmd, "reboot") == 0) {
        bc_out("OK\n");
        vTaskDelay(pdMS_TO_TICKS(100));
        esp_restart();
    } else {
        bc_answer(LM_STATUS_UNSUPPORTED);
    }
}

void bc_provisioning_console(const char *role_name) {
    s_role_name = role_name;
    bc_console_init();
    bc_outf("HIL provisioning console (%s): info | keygen | prov-leaf | prov-root [first_term: replacement] | reboot\n",
            role_name);
    for (;;) {
        char *line = bc_console_line(portMAX_DELAY);
        if (line != NULL) prov_command(line);
    }
}

bool bc_force_always_rx(lm_context_t *ctx) {
    for (int i = 0; i < 200; ++i) {
        lm_power_policy_t p = {.struct_size = sizeof p, .abi_version = LM_ABI_VERSION};
        lm_operation_id_t op = 0;
        if (lm_power_policy_get(ctx, &p) == LM_STATUS_OK) {
            if (p.mode == LM_POWER_ALWAYS_RX) return true;
            const uint64_t rev = p.revision;
            p.mode = LM_POWER_ALWAYS_RX;
            p.wake_interval_ms = p.rx_window_ms = p.max_rx_window_ms = 0; /* ALWAYS_RX has no windows: fields must be 0 */
            p.revision = rev + 1;
            (void)lm_power_policy_set(ctx, &p, rev, &op);
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    return false;
}

/* Board overlay (Kconfig HIL_XIAO_C6_*): the antenna path before the radio ever starts. */
void bc_board_init(void) {
#if CONFIG_HIL_XIAO_C6_RF_SWITCH
    gpio_config_t io = {.pin_bit_mask = (1ULL << 3) | (1ULL << 14), .mode = GPIO_MODE_OUTPUT};
    gpio_config(&io);
    gpio_set_level(3, 0); /* RF switch power on */
    vTaskDelay(pdMS_TO_TICKS(100));
#if CONFIG_HIL_XIAO_C6_EXTERNAL_ANTENNA
    gpio_set_level(14, 1);
#else
    gpio_set_level(14, 0); /* on-board ceramic antenna */
#endif
#endif
}
