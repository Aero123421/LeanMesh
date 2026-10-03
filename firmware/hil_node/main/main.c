/*
 * BENCH / HIL ONLY: firmware of the first hardware runs (Issue #6). See ../CMakeLists.txt.
 *
 * Line console on the USB-Serial/JTAG port (one command per line, one answer line starting with "OK" or "ERR";
 * other lines are logs and events). The PC side is tools/hil/hil.py.
 *   any state        info | reboot
 *   not provisioned  keygen | prov-leaf <trust88> <device_cose> <ticket> | prov-root <trust88> <device_cose>
 *                    <delegation> <host_id>                                        (hex arguments)
 *   leaf/relay, provisioned (mesh running)
 *                    status | join [noretry] | send root <text> | send <device_id hex> <text> | op <id> | stop | start
 * A provisioned ROOT starts the mesh and leaves the port to the Host's USB session: it has no console then.
 * Events of a leaf/relay are printed as "EV ..." lines. No product logic, no polling inside the SDK: this app polls
 * its own event queue every 50 ms while it waits for console input.
 */
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "driver/gpio.h"
#include "esp_heap_caps.h"
#include "esp_random.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "leanmesh.h"
#include "leanmesh_bench.h"
#include "nvs_flash.h"
#include "sdkconfig.h"

#if CONFIG_LEANMESH_PROFILE_ROOT
#define HIL_ROLE LM_ROLE_ROOT
#define HIL_ROLE_NAME "root"
#elif CONFIG_LEANMESH_PROFILE_RELAY
#define HIL_ROLE LM_ROLE_RELAY
#define HIL_ROLE_NAME "relay"
#else
#define HIL_ROLE LM_ROLE_LEAF
#define HIL_ROLE_NAME "leaf"
#endif

#define CONSOLE_LINE_MAX 4096
#define BLOB_MAX 1024

static char s_line[CONSOLE_LINE_MAX];
static size_t s_line_len;
static uint8_t s_blob[3][BLOB_MAX];
static uint8_t s_payload[LM_MAX_MESSAGE_BYTES];
static lm_context_t *s_ctx;

/* ---- console I/O: the USB-Serial/JTAG driver for every byte, so logs and answers never interleave mid-line ---- */

static void out(const char *s) { usb_serial_jtag_write_bytes(s, strlen(s), pdMS_TO_TICKS(200)); }

static void outf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void outf(const char *fmt, ...) {
    char buf[384];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    out(buf);
}

static void out_hex(const uint8_t *b, size_t n) {
    static const char d[] = "0123456789abcdef";
    char buf[129];
    while (n > 0) {
        size_t k = n > 64 ? 64 : n;
        for (size_t i = 0; i < k; ++i) {
            buf[2 * i] = d[b[i] >> 4];
            buf[2 * i + 1] = d[b[i] & 15];
        }
        buf[2 * k] = '\0';
        out(buf);
        b += k;
        n -= k;
    }
}

static void console_init(void) {
    usb_serial_jtag_driver_config_t cfg = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
    cfg.rx_buffer_size = 4096;
    cfg.tx_buffer_size = 1024;
    if (usb_serial_jtag_driver_install(&cfg) == ESP_OK) {
        usb_serial_jtag_vfs_use_driver(); /* stdout (ESP_LOG) through the same driver */
    }
}

/* One complete line (without CR/LF) or NULL after `ticks` without one. */
static char *console_line(TickType_t ticks) {
    uint8_t c;
    while (usb_serial_jtag_read_bytes(&c, 1, ticks) == 1) {
        ticks = pdMS_TO_TICKS(20);
        if (c == '\r' || c == '\n') {
            if (s_line_len == 0) {
                continue;
            }
            s_line[s_line_len] = '\0';
            s_line_len = 0;
            return s_line;
        }
        if (s_line_len + 1 < CONSOLE_LINE_MAX) {
            s_line[s_line_len++] = (char)c;
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

/* Hex token -> bytes. Returns the length, or -1. */
static int unhex(const char *tok, uint8_t *dst, size_t cap) {
    size_t n = tok != NULL ? strlen(tok) : 0;
    if (n == 0 || n % 2 != 0 || n / 2 > cap) return -1;
    for (size_t i = 0; i < n / 2; ++i) {
        int h = hexval(tok[2 * i]), l = hexval(tok[2 * i + 1]);
        if (h < 0 || l < 0) return -1;
        dst[i] = (uint8_t)(h << 4 | l);
    }
    return (int)(n / 2);
}

static void answer(lm_status_t st) {
    if (st == LM_STATUS_OK) {
        out("OK\n");
    } else {
        outf("ERR %u\n", (unsigned)st);
    }
}

/* ---- provisioning console (unprovisioned board, mesh never started) ---- */

static void print_key(const lmb_key_t *k) {
    out(" pub=");
    out_hex(k->public_key, sizeof k->public_key);
    out(" id=");
    out_hex(k->device_id, sizeof k->device_id);
}

static void prov_command(char *line) {
    char *save = NULL;
    const char *cmd = strtok_r(line, " ", &save);
    if (cmd == NULL) return;
    if (strcmp(cmd, "info") == 0) {
        uint32_t state = 0;
        lm_status_t st = lmb_state(&state);
        if (st != LM_STATUS_OK) {
            answer(st);
            return;
        }
        outf("OK state=%u role=%s", (unsigned)state, HIL_ROLE_NAME);
        lmb_key_t k;
        if (state == LMB_KEY_PENDING && lmb_keygen(&k) == LM_STATUS_OK) print_key(&k);
        out("\n");
    } else if (strcmp(cmd, "keygen") == 0) {
        lmb_key_t k;
        lm_status_t st = lmb_keygen(&k);
        if (st != LM_STATUS_OK) {
            answer(st);
            return;
        }
        out("OK");
        print_key(&k);
        out("\n");
    } else if (strcmp(cmd, "prov-leaf") == 0 || strcmp(cmd, "prov-root") == 0) {
        const bool root = strcmp(cmd, "prov-root") == 0;
        uint8_t trust[88];
        uint8_t host[32];
        int nt = unhex(strtok_r(NULL, " ", &save), trust, sizeof trust);
        int nd = unhex(strtok_r(NULL, " ", &save), s_blob[0], BLOB_MAX);
        int nx = unhex(strtok_r(NULL, " ", &save), s_blob[1], BLOB_MAX);
        int nh = root ? unhex(strtok_r(NULL, " ", &save), host, sizeof host) : 32;
        if (nt != 88 || nd <= 0 || nx <= 0 || nh != 32) {
            answer(LM_STATUS_INVALID_ARGUMENT);
            return;
        }
        lm_status_t st = root ? lmb_provision_root(trust, s_blob[0], (size_t)nd, s_blob[1], (size_t)nx, host)
                              : lmb_provision_leaf(trust, s_blob[0], (size_t)nd, s_blob[1], (size_t)nx);
        answer(st);
        if (st == LM_STATUS_OK) {
            vTaskDelay(pdMS_TO_TICKS(200));
            esp_restart(); /* the mesh starts from the committed records, with a clean USB driver state */
        }
    } else if (strcmp(cmd, "reboot") == 0) {
        out("OK\n");
        vTaskDelay(pdMS_TO_TICKS(100));
        esp_restart();
    } else {
        answer(LM_STATUS_UNSUPPORTED);
    }
}

static void provisioning_console(void) {
    console_init();
    out("HIL provisioning console (" HIL_ROLE_NAME "): info | keygen | prov-leaf | prov-root | reboot\n");
    for (;;) {
        char *line = console_line(portMAX_DELAY);
        if (line != NULL) prov_command(line);
    }
}

/* ---- running mesh (leaf/relay console) ---- */

static void print_id(const char *label, const uint8_t *b, size_t n) {
    out(label);
    out_hex(b, n);
}

static void print_event(const lm_event_t *e, size_t payload_len) {
    outf("EV kind=%u reason=%u op=%llu seq=%llu", (unsigned)e->kind, (unsigned)e->reason,
         (unsigned long long)e->operation_id, (unsigned long long)e->event_sequence);
    if (e->kind == LM_EVENT_MESSAGE) {
        outf(" port=%u bytes=%u", (unsigned)e->app_port, (unsigned)e->payload_bytes);
        print_id(" from=", e->peer.bytes, 8);
        out(" text=\"");
        for (size_t i = 0; i < payload_len; ++i) {
            char c[2] = {(s_payload[i] >= 0x20 && s_payload[i] < 0x7f) ? (char)s_payload[i] : '.', 0};
            out(c);
        }
        out("\"");
    }
    out("\n");
}

static void join_ended(const lm_event_t *e);

static void pump_events(void) {
    for (int i = 0; i < 8; ++i) {
        lm_event_t e = {.struct_size = sizeof e, .abi_version = LM_ABI_VERSION};
        size_t need = 0;
        lm_status_t st = lm_next_event(s_ctx, &e, s_payload, sizeof s_payload, &need);
        if (st != LM_STATUS_OK) return;
        print_event(&e, e.kind == LM_EVENT_MESSAGE && e.payload_bytes <= sizeof s_payload ? e.payload_bytes : 0);
        join_ended(&e);
    }
}

static void cmd_status(void) {
    lm_membership_t m = {.struct_size = sizeof m, .abi_version = LM_ABI_VERSION};
    lm_connectivity_t c = {.struct_size = sizeof c, .abi_version = LM_ABI_VERSION};
    lm_diagnostics_t d = {.struct_size = sizeof d, .abi_version = LM_ABI_VERSION};
    lm_root_time_t t = {.struct_size = sizeof t, .abi_version = LM_ABI_VERSION};
    lm_status_t sm = lm_membership_get(s_ctx, &m);
    lm_status_t sc = lm_connectivity_get(s_ctx, &c);
    lm_status_t sd = lm_diagnostics_get(s_ctx, &d);
    lm_status_t st = lm_root_time_get(s_ctx, &t);
    outf("OK role=%s membership=%u(st%u) reason=%u assign=%llu memb=%llu conn=%u(st%u) depth=%u", HIL_ROLE_NAME,
         (unsigned)m.state, (unsigned)sm, (unsigned)m.reason, (unsigned long long)m.assignment_generation,
         (unsigned long long)m.membership_generation, (unsigned)c.state, (unsigned)sc, (unsigned)c.root_depth);
    outf(" root_ms=%llu..%llu", (unsigned long long)t.earliest_root_ms, (unsigned long long)t.latest_root_ms);
    outf(" term=%u time_valid=%u(st%u) chan=%u peers=%u tx=%llu rx=%llu rf_fail=%llu heap_min=%u stack_free=%u(st%u)",
         (unsigned)t.root_term, (unsigned)t.valid, (unsigned)st, (unsigned)d.current_channel,
         (unsigned)d.regular_peers, (unsigned long long)d.tx_frames, (unsigned long long)d.rx_frames,
         (unsigned long long)d.rf_failures, (unsigned)d.min_heap_bytes, (unsigned)d.stack_free_bytes, (unsigned)sd);
    print_id(" id=", m.device.bytes, sizeof m.device.bytes);
    print_id(" domain=", m.domain.bytes, sizeof m.domain.bytes);
    out("\n");
}

/* join: a new join, asked again by the app when the SDK ends it as EXPIRED/BUSY/RATE_LIMITED (up to 5 times, 2..6 s
   apart). The SDK caps one search at 30 s (membership_ops.cpp), which equals its one-full-handshake-per-peer gate:
   a joiner whose first handshake a busy root dropped cannot ask that root again within the same search. */
static lm_operation_id_t s_join_op;
static int s_join_retries;
static TickType_t s_join_again_at;

static lm_status_t join_once(void) {
    lm_join_request_t r = {.struct_size = sizeof r, .abi_version = LM_ABI_VERSION, .mode = LM_JOIN_NEW};
    esp_fill_random(r.request_id.bytes, sizeof r.request_id.bytes);
    lm_status_t st = lm_join(s_ctx, &r, &s_join_op);
    if (st == LM_STATUS_OK) {
        outf("JOIN op=%llu request=", (unsigned long long)s_join_op);
        out_hex(r.request_id.bytes, sizeof r.request_id.bytes);
        out("\n");
    }
    return st;
}

static void cmd_join(char *save) {
    const char *arg = strtok_r(NULL, " ", &save);
    s_join_retries = arg != NULL && strcmp(arg, "noretry") == 0 ? 0 : 5; /* noretry: the SDK's own result */
    s_join_again_at = 0;
    lm_status_t st = join_once();
    if (st != LM_STATUS_OK) {
        answer(st);
        return;
    }
    outf("OK op=%llu\n", (unsigned long long)s_join_op);
}

/* The join operation ended: ask again if the reason is a local/transient one. */
static void join_ended(const lm_event_t *e) {
    if (s_join_op == 0 || e->kind != LM_EVENT_OPERATION || e->operation_id != s_join_op) return;
    const bool transient = e->reason == LM_STATUS_EXPIRED || e->reason == LM_STATUS_BUSY ||
                           e->reason == LM_STATUS_RATE_LIMITED;
    s_join_op = 0;
    if (transient && s_join_retries > 0) {
        --s_join_retries;
        s_join_again_at = xTaskGetTickCount() + pdMS_TO_TICKS(2000 + esp_random() % 4000);
        outf("JOIN ended (%u): asking again soon, %d retries left\n", (unsigned)e->reason, s_join_retries);
    }
}

static void join_timer(void) {
    if (s_join_again_at != 0 && (int32_t)(xTaskGetTickCount() - s_join_again_at) >= 0) {
        s_join_again_at = 0;
        lm_status_t st = join_once();
        if (st != LM_STATUS_OK) outf("JOIN again refused: %u\n", (unsigned)st);
    }
}

static void cmd_send(char *save) {
    const char *dst = strtok_r(NULL, " ", &save);
    const char *text = save; /* the rest of the line */
    if (dst == NULL || text == NULL || *text == '\0' || strlen(text) > LM_MAX_MESSAGE_BYTES) {
        answer(LM_STATUS_INVALID_ARGUMENT);
        return;
    }
    lm_send_request_t r = {.struct_size = sizeof r, .abi_version = LM_ABI_VERSION};
    if (strcmp(dst, "root") == 0) {
        r.destination.kind = LM_DEST_ROOT_APP;
    } else {
        r.destination.kind = LM_DEST_NODE;
        if (unhex(dst, r.destination.node.bytes, sizeof r.destination.node.bytes) != 32) {
            answer(LM_STATUS_INVALID_ARGUMENT);
            return;
        }
    }
    r.app_port = 100;
    r.priority = LM_PRIORITY_NORMAL;
    r.queue_mode = LM_FIFO;
    lm_root_time_t t = {.struct_size = sizeof t, .abi_version = LM_ABI_VERSION};
    if (lm_root_time_get(s_ctx, &t) == LM_STATUS_OK && t.valid) {
        r.delivery = LM_RECEIVED; /* a deadline 60 s ahead on the root clock */
        r.storage = LM_VOLATILE;
        r.root_term = t.root_term;
        r.expires_root_ms = t.earliest_root_ms + 60000;
    } else {
        r.delivery = LM_RECEIVED; /* no root clock yet: durable history data, the only kind without a deadline */
        r.storage = LM_DURABLE;
    }
    lm_operation_id_t op = 0;
    lm_status_t st = lm_send(s_ctx, &r, (const uint8_t *)text, strlen(text), &op);
    if (st != LM_STATUS_OK) {
        answer(st);
        return;
    }
    outf("OK op=%llu\n", (unsigned long long)op);
}

static void cmd_op(char *save) {
    const char *id = strtok_r(NULL, " ", &save);
    lm_operation_t o = {.struct_size = sizeof o, .abi_version = LM_ABI_VERSION};
    lm_status_t st = id != NULL ? lm_get_operation(s_ctx, strtoull(id, NULL, 10), &o) : LM_STATUS_INVALID_ARGUMENT;
    if (st != LM_STATUS_OK) {
        answer(st);
        return;
    }
    outf("OK phase=%u outcome=%u reason=%u evidence=0x%x\n", (unsigned)o.phase, (unsigned)o.outcome,
         (unsigned)o.reason, (unsigned)o.evidence_bits);
}

/* power                 the power snapshot
   power windowed|always  the node's power policy (config/power.windowed.json values for WINDOWED_RX) */
static void cmd_power(char *save) {
    const char *mode = strtok_r(NULL, " ", &save);
    if (mode != NULL) {
        lm_power_policy_t p = {.struct_size = sizeof p, .abi_version = LM_ABI_VERSION};
        lm_status_t st = lm_power_policy_get(s_ctx, &p);
        if (st != LM_STATUS_OK) {
            answer(st);
            return;
        }
        const uint64_t rev = p.revision;
        if (strcmp(mode, "windowed") == 0) {
            p.mode = LM_POWER_WINDOWED_RX;
            p.wake_interval_ms = 5000;
            p.rx_window_ms = 250;
            p.max_rx_window_ms = 1500;
            p.awake_budget_ms = 15000;
        } else if (strcmp(mode, "always") == 0) {
            p.mode = LM_POWER_ALWAYS_RX;
        } else {
            answer(LM_STATUS_INVALID_ARGUMENT);
            return;
        }
        p.revision = rev + 1;
        lm_operation_id_t op = 0;
        st = lm_power_policy_set(s_ctx, &p, rev, &op);
        if (st != LM_STATUS_OK) {
            answer(st);
            return;
        }
        outf("OK op=%llu revision=%llu\n", (unsigned long long)op, (unsigned long long)p.revision);
        return;
    }
    lm_power_snapshot_t ps = {.struct_size = sizeof ps, .abi_version = LM_ABI_VERSION};
    lm_status_t st = lm_power_get(s_ctx, &ps);
    if (st != LM_STATUS_OK) {
        answer(st);
        return;
    }
    outf("OK mode=%u state=%u rev=%llu radio_on_us=%llu cpu_us=%llu episodes=%llu polls=%llu missed=%llu "
         "handshakes=%llu flash=%llu valid=0x%llx\n",
         (unsigned)ps.mode, (unsigned)ps.state, (unsigned long long)ps.policy_revision,
         (unsigned long long)ps.radio_on_us, (unsigned long long)ps.cpu_active_us,
         (unsigned long long)ps.episode_count, (unsigned long long)ps.polls, (unsigned long long)ps.missed_windows,
         (unsigned long long)ps.handshake_count, (unsigned long long)ps.flash_commits,
         (unsigned long long)ps.validity_bits);
}

static void run_command(char *line) {
    char *save = NULL;
    const char *cmd = strtok_r(line, " ", &save);
    if (cmd == NULL) return;
    if (strcmp(cmd, "info") == 0) {
        outf("OK state=%u role=%s\n", (unsigned)LMB_PROVISIONED, HIL_ROLE_NAME);
    } else if (strcmp(cmd, "status") == 0) {
        cmd_status();
    } else if (strcmp(cmd, "join") == 0) {
        cmd_join(save);
    } else if (strcmp(cmd, "send") == 0) {
        cmd_send(save);
    } else if (strcmp(cmd, "power") == 0) {
        cmd_power(save);
    } else if (strcmp(cmd, "debug") == 0) {
        static char dbg[768];
        lm_status_t st = lmb_debug(s_ctx, dbg, sizeof dbg);
        if (st == LM_STATUS_OK) {
            out("OK ");
            out(dbg);
            out("\n");
        } else {
            answer(st);
        }
    } else if (strcmp(cmd, "stop") == 0) { /* the radio goes off: this node stops taking part (a bench "power off") */
        lm_operation_id_t op = 0;
        answer(lm_stop(s_ctx, 0, &op));
    } else if (strcmp(cmd, "start") == 0) {
        answer(lm_start(s_ctx));
    } else if (strcmp(cmd, "op") == 0) {
        cmd_op(save);
    } else if (strcmp(cmd, "reboot") == 0) {
        out("OK\n");
        vTaskDelay(pdMS_TO_TICKS(100));
        esp_restart();
    } else {
        answer(LM_STATUS_UNSUPPORTED);
    }
}

static lm_status_t start_mesh(void) {
    lm_config_t config;
    lm_workspace_size_t ws;
    lm_status_t st = lm_config_init(&config, sizeof config);
    if (st != LM_STATUS_OK) return st;
    config.role = HIL_ROLE;
    st = lm_workspace_required(&config, &ws);
    if (st != LM_STATUS_OK) return st;
    void *workspace = heap_caps_aligned_alloc(ws.alignment, ws.bytes, MALLOC_CAP_INTERNAL);
    if (workspace == NULL) return LM_STATUS_NO_CAPACITY;
    st = lm_init(workspace, ws.bytes, &config, &s_ctx);
    if (st != LM_STATUS_OK) return st;
    return lm_start(s_ctx);
}

/* Board overlay (Kconfig HIL_XIAO_C6_*): the antenna path before the radio ever starts. */
static void board_init(void) {
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

void app_main(void) {
    board_init();
    esp_err_t err = nvs_flash_init(); /* the default "nvs" partition (Wi-Fi/PHY data), plaintext on a bench board */
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }
    uint32_t state = 0;
    if (lmb_state(&state) != LM_STATUS_OK || state != LMB_PROVISIONED) {
        provisioning_console(); /* never returns */
    }
#if CONFIG_LEANMESH_PROFILE_ROOT
    /* The USB port belongs to the Host session from here on (src/serial/idf_serial.cpp installs its driver). */
    if (start_mesh() != LM_STATUS_OK) {
        vTaskDelay(pdMS_TO_TICKS(5000));
        esp_restart(); /* no console to report on: retry from a clean boot */
    }
#else
    console_init();
    /* Safe mode: a WINDOWED/REPORT_ONLY policy light-sleeps the chip, and light sleep stops the USB-Serial/JTAG port
       (no console, no esptool). "safe" within 10 s of boot puts the node back to ALWAYS_RX before it can sleep (a PC needs a few
       seconds to enumerate the port again after a reset). */
    bool safe = false;
    for (int tick = 0; !safe && tick < 100; ++tick) {
        if (tick % 10 == 0) out("HIL: send 'safe' within 10 s to force ALWAYS_RX\n");
        char *l = console_line(pdMS_TO_TICKS(100));
        safe = l != NULL && strcmp(l, "safe") == 0;
    }
    lm_status_t st = start_mesh();
    for (int i = 0; safe && st == LM_STATUS_OK && i < 200; ++i) {
        lm_power_policy_t p = {.struct_size = sizeof p, .abi_version = LM_ABI_VERSION};
        lm_operation_id_t op = 0;
        if (lm_power_policy_get(s_ctx, &p) == LM_STATUS_OK) {
            if (p.mode == LM_POWER_ALWAYS_RX) {
                out("HIL safe: ALWAYS_RX\n");
                break;
            }
            const uint64_t rev = p.revision;
            p.mode = LM_POWER_ALWAYS_RX;
            p.revision = rev + 1;
            (void)lm_power_policy_set(s_ctx, &p, rev, &op);
        }
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    outf("HIL %s: mesh start %s (%u)\n", HIL_ROLE_NAME, st == LM_STATUS_OK ? "OK" : "FAILED", (unsigned)st);
    if (st != LM_STATUS_OK) {
        for (;;) {
            char *line = console_line(portMAX_DELAY);
            if (line != NULL && strncmp(line, "reboot", 6) == 0) esp_restart();
            if (line != NULL) answer(st);
        }
    }
    for (;;) {
        char *line = console_line(pdMS_TO_TICKS(50));
        if (line != NULL) run_command(line);
        pump_events();
        join_timer();
    }
#endif
}
