/*
 * BENCH / HIL ONLY: firmware of the first hardware runs (Issue #6). See ../CMakeLists.txt.
 *
 * Line console on the USB-Serial/JTAG port (one command per line, one answer line starting with "OK" or "ERR";
 * other lines are logs and events). The PC side is tools/hil/hil.py.
 *   any state        info | reboot
 *   not provisioned  keygen | prov-leaf <trust88> <device_cose> <ticket> | prov-root <trust88> <device_cose>
 *                    <delegation> <host_id>                                        (hex arguments)
 *   leaf/relay, provisioned (mesh running)
 *                    status | join [transfer] [noretry] | send root <text> | send <device_id hex> <text> | op <id> | stop | start
 *                    nonce | ticket <hex>        (transfer, docs/07 §8: the device's transfer nonce; install a fleet-signed
 *                                                 AssignmentTicket, control type 3; then "join transfer")
 *                    install <control type> <signed object hex>   (lm_install_control: e.g. 31, the fleet's RootHandover)
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
#include "bench_console.h"
#include "bench_recovery.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_random.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "leanmesh.h"
#include "leanmesh_bench.h"
#include "leanmesh_idf.h"
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

#define BLOB_MAX 1024

static uint8_t s_blob[BLOB_MAX]; /* install: a signed control object */
static uint8_t s_payload[LM_MAX_MESSAGE_BYTES];
static lm_context_t *s_ctx;


/* ---- running mesh (leaf/relay console) ---- */

static void print_id(const char *label, const uint8_t *b, size_t n) {
    bc_out(label);
    bc_out_hex(b, n);
}

static void print_event(const lm_event_t *e, size_t payload_len) {
    bc_outf("EV kind=%u reason=%u op=%llu seq=%llu", (unsigned)e->kind, (unsigned)e->reason,
            (unsigned long long)e->operation_id, (unsigned long long)e->event_sequence);
    if (e->kind == LM_EVENT_MESSAGE) {
        bc_outf(" port=%u bytes=%u", (unsigned)e->app_port, (unsigned)e->payload_bytes);
        print_id(" from=", e->peer.bytes, 8);
        bc_out(" text=\"");
        for (size_t i = 0; i < payload_len; ++i) {
            char c[2] = {(s_payload[i] >= 0x20 && s_payload[i] < 0x7f) ? (char)s_payload[i] : '.', 0};
            bc_out(c);
        }
        bc_out("\"");
    }
    bc_out("\n");
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
    bc_outf("OK role=%s membership=%u(st%u) reason=%u assign=%llu memb=%llu conn=%u(st%u) depth=%u", HIL_ROLE_NAME,
            (unsigned)m.state, (unsigned)sm, (unsigned)m.reason, (unsigned long long)m.assignment_generation,
            (unsigned long long)m.membership_generation, (unsigned)c.state, (unsigned)sc, (unsigned)c.root_depth);
    bc_outf(" root_ms=%llu..%llu", (unsigned long long)t.earliest_root_ms, (unsigned long long)t.latest_root_ms);
    bc_outf(" term=%u time_valid=%u(st%u) chan=%u peers=%u tx=%llu rx=%llu rf_fail=%llu heap_min=%u stack_free=%u(st%u)",
            (unsigned)t.root_term, (unsigned)t.valid, (unsigned)st, (unsigned)d.current_channel,
            (unsigned)d.regular_peers, (unsigned long long)d.tx_frames, (unsigned long long)d.rx_frames,
            (unsigned long long)d.rf_failures, (unsigned)d.min_heap_bytes, (unsigned)d.stack_free_bytes, (unsigned)sd);
    print_id(" id=", m.device.bytes, sizeof m.device.bytes);
    print_id(" domain=", m.domain.bytes, sizeof m.domain.bytes);
    bc_out("\n");
}

/* join: a new join, asked again by the app when the SDK ends it as EXPIRED/BUSY/RATE_LIMITED (up to 5 times, 2..6 s
   apart). The SDK caps one search at 30 s (membership_ops.cpp), which equals its one-full-handshake-per-peer gate:
   a joiner whose first handshake a busy root dropped cannot ask that root again within the same search.
   join transfer: the same for LM_JOIN_TRANSFER_CANDIDATE (a member looks for the root its installed ticket names). */
static lm_operation_id_t s_join_op;
static int s_join_retries;
static TickType_t s_join_again_at;
static uint32_t s_join_mode = LM_JOIN_NEW; /* `join transfer`: the handover / transfer path of a member (docs/07 section 8) */

static lm_status_t join_once(void) {
    lm_join_request_t r = {.struct_size = sizeof r, .abi_version = LM_ABI_VERSION, .mode = s_join_mode};
    esp_fill_random(r.request_id.bytes, sizeof r.request_id.bytes);
    lm_status_t st = lm_join(s_ctx, &r, &s_join_op);
    if (st == LM_STATUS_OK) {
        bc_outf("JOIN op=%llu request=", (unsigned long long)s_join_op);
        bc_out_hex(r.request_id.bytes, sizeof r.request_id.bytes);
        bc_out("\n");
    }
    return st;
}

static void cmd_join(char *save) {
    s_join_mode = LM_JOIN_NEW;
    s_join_retries = 5;
    for (const char *arg = strtok_r(NULL, " ", &save); arg != NULL; arg = strtok_r(NULL, " ", &save)) {
        if (strcmp(arg, "noretry") == 0) {
            s_join_retries = 0; /* the SDK's own result */
        } else if (strcmp(arg, "transfer") == 0) {
            s_join_mode = LM_JOIN_TRANSFER_CANDIDATE;
        } else {
            bc_answer(LM_STATUS_INVALID_ARGUMENT);
            return;
        }
    }
    s_join_again_at = 0;
    lm_status_t st = join_once();
    if (st != LM_STATUS_OK) {
        bc_answer(st);
        return;
    }
    bc_outf("OK op=%llu\n", (unsigned long long)s_join_op);
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
        bc_outf("JOIN ended (%u): asking again soon, %d retries left\n", (unsigned)e->reason, s_join_retries);
    }
}

static void join_timer(void) {
    if (s_join_again_at != 0 && (int32_t)(xTaskGetTickCount() - s_join_again_at) >= 0) {
        s_join_again_at = 0;
        lm_status_t st = join_once();
        if (st != LM_STATUS_OK) bc_outf("JOIN again refused: %u\n", (unsigned)st);
    }
}

/* nonce: the device's outstanding transfer nonce (docs/07 §8; RAM only: a restart voids it). A mode-0 ticket names it. */
static void cmd_nonce(void) {
    uint8_t nonce[16];
    lm_status_t st = lm_transfer_nonce_get(s_ctx, nonce);
    if (st != LM_STATUS_OK) {
        bc_answer(st);
        return;
    }
    bc_out("OK nonce=");
    bc_out_hex(nonce, sizeof nonce);
    bc_out("\n");
}

/* A signed control object for this node (lm_install_control). How the install ended is its operation (`op <id>`, EV
   kind=3). */
static void install_object(uint32_t type, const char *hex) {
    int n = bc_unhex(hex, s_blob, BLOB_MAX);
    if (n <= 0) {
        bc_answer(LM_STATUS_INVALID_ARGUMENT);
        return;
    }
    lm_operation_id_t op = 0;
    lm_status_t st = lm_install_control(s_ctx, type, s_blob, (size_t)n, &op);
    if (st != LM_STATUS_OK) {
        bc_answer(st);
        return;
    }
    bc_outf("OK op=%llu\n", (unsigned long long)op);
}

/* ticket <hex>: a fleet-signed AssignmentTicket (control type 3) for this member's transfer. */
static void cmd_ticket(char *save) { install_object(3, strtok_r(NULL, " ", &save)); }

/* install <type> <hex>: any signed control object. A member stores the fleet's RootHandover (31) this way (its own
   evidence that the domain's root changed) and then asks `join transfer`. */
static void cmd_install(char *save) {
    const char *type = strtok_r(NULL, " ", &save);
    if (type == NULL) {
        bc_answer(LM_STATUS_INVALID_ARGUMENT);
        return;
    }
    install_object((uint32_t)strtoul(type, NULL, 10), strtok_r(NULL, " ", &save));
}

static void cmd_send(char *save) {
    const char *dst = strtok_r(NULL, " ", &save);
    const char *text = save; /* the rest of the line */
    if (dst == NULL || text == NULL || *text == '\0' || strlen(text) > LM_MAX_MESSAGE_BYTES) {
        bc_answer(LM_STATUS_INVALID_ARGUMENT);
        return;
    }
    lm_send_request_t r = {.struct_size = sizeof r, .abi_version = LM_ABI_VERSION};
    if (strcmp(dst, "root") == 0) {
        r.destination.kind = LM_DEST_ROOT_APP;
    } else {
        r.destination.kind = LM_DEST_NODE;
        if (bc_unhex(dst, r.destination.node.bytes, sizeof r.destination.node.bytes) != 32) {
            bc_answer(LM_STATUS_INVALID_ARGUMENT);
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
        bc_answer(st);
        return;
    }
    bc_outf("OK op=%llu\n", (unsigned long long)op);
}

static void cmd_op(char *save) {
    const char *id = strtok_r(NULL, " ", &save);
    lm_operation_t o = {.struct_size = sizeof o, .abi_version = LM_ABI_VERSION};
    lm_status_t st = id != NULL ? lm_get_operation(s_ctx, strtoull(id, NULL, 10), &o) : LM_STATUS_INVALID_ARGUMENT;
    if (st != LM_STATUS_OK) {
        bc_answer(st);
        return;
    }
    bc_outf("OK phase=%u outcome=%u reason=%u evidence=0x%x\n", (unsigned)o.phase, (unsigned)o.outcome,
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
            bc_answer(st);
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
            p.mode = LM_POWER_ALWAYS_RX; /* ALWAYS_RX has no windows: their fields must be 0 (policy.cpp validate) */
            p.wake_interval_ms = p.rx_window_ms = p.max_rx_window_ms = 0;
        } else {
            bc_answer(LM_STATUS_INVALID_ARGUMENT);
            return;
        }
        p.revision = rev + 1;
        lm_operation_id_t op = 0;
        st = lm_power_policy_set(s_ctx, &p, rev, &op);
        if (st != LM_STATUS_OK) {
            bc_answer(st);
            return;
        }
        bc_outf("OK op=%llu revision=%llu\n", (unsigned long long)op, (unsigned long long)p.revision);
        return;
    }
    lm_power_snapshot_t ps = {.struct_size = sizeof ps, .abi_version = LM_ABI_VERSION};
    lm_status_t st = lm_power_get(s_ctx, &ps);
    if (st != LM_STATUS_OK) {
        bc_answer(st);
        return;
    }
    bc_outf("OK mode=%u state=%u rev=%llu radio_on_us=%llu cpu_us=%llu episodes=%llu polls=%llu missed=%llu "
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
        bc_outf("OK state=%u role=%s\n", (unsigned)LMB_PROVISIONED, HIL_ROLE_NAME);
    } else if (strcmp(cmd, "status") == 0) {
        cmd_status();
    } else if (strcmp(cmd, "join") == 0) {
        cmd_join(save);
    } else if (strcmp(cmd, "nonce") == 0) {
        cmd_nonce();
    } else if (strcmp(cmd, "ticket") == 0) {
        cmd_ticket(save);
    } else if (strcmp(cmd, "send") == 0) {
        cmd_send(save);
    } else if (strcmp(cmd, "install") == 0) {
        cmd_install(save);
    } else if (strcmp(cmd, "power") == 0) {
        cmd_power(save);
    } else if (strcmp(cmd, "debug") == 0) {
        static char dbg[1024];
        lm_status_t st = lmb_debug(s_ctx, dbg, sizeof dbg);
        if (st == LM_STATUS_OK) {
            bc_out("OK ");
            bc_out(dbg);
            bc_out("\n");
        } else {
            bc_answer(st);
        }
    } else if (strcmp(cmd, "stop") == 0) { /* the radio goes off: this node stops taking part (a bench "power off") */
        lm_operation_id_t op = 0;
        bc_answer(lm_stop(s_ctx, 0, &op));
    } else if (strcmp(cmd, "start") == 0) {
        bc_answer(lm_start(s_ctx));
    } else if (strcmp(cmd, "op") == 0) {
        cmd_op(save);
    } else if (strcmp(cmd, "reboot") == 0) {
        bc_out("OK\n");
        vTaskDelay(pdMS_TO_TICKS(100));
        esp_restart();
    } else {
        bc_answer(LM_STATUS_UNSUPPORTED);
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

/* HIL-F7: a board on a PC's USB-Serial/JTAG port does not light-sleep (light sleep stops that port: no console, no
   esptool). Off the PC (a power bank) WINDOWED_RX sleeps as configured. */
bool lm_idf_sleep_veto(uint8_t sleep_kind) {
    (void)sleep_kind;
    return usb_serial_jtag_is_connected();
}

#if CONFIG_LEANMESH_PROFILE_ROOT
/* The root application owns recovery; the Host only reports diagnostics. USB remains a binary Host stream. */
static void root_watch(void) {
    bc_radio_watch_t watch = {0};
    uint32_t window_ms = 0, recoveries = 0;
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        lm_idf_radio_health_t h;
        if (lm_idf_radio_health(s_ctx, &h) != LM_STATUS_OK) continue;
        const bc_radio_sample_t sample = {h.faulted, h.running, h.peers, h.rx_frames, h.tx_frames, h.unicast_acked};
        const uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
        const uint32_t reason = bc_radio_watch(&watch, &sample, now);
        if (reason == BC_RADIO_NO_FAULT) continue;
        if ((uint32_t)(now - window_ms) >= 120000) {
            window_ms = now;
            recoveries = 0;
        }
        lm_status_t stopped = LM_STATUS_OK;
        lm_idf_record_radio_recovery(reason, LM_STATUS_DRIVER_RESULT_UNKNOWN, h.tx_frames, h.rx_frames);
        const lm_status_t started = ++recoveries <= 3 ? bc_radio_restart(s_ctx, &stopped) : LM_STATUS_RECOVERY_REQUIRED;
        lm_idf_finish_radio_recovery(started);
        if (started != LM_STATUS_OK) lm_idf_restart_radio_recovery();
    }
}
#endif

void app_main(void) {
    bc_board_init();
    esp_err_t err = nvs_flash_init(); /* the default "nvs" partition (Wi-Fi/PHY data), plaintext on a bench board */
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        nvs_flash_erase();
        nvs_flash_init();
    }
    uint32_t state = 0;
    if (lmb_state(&state) != LM_STATUS_OK || state != LMB_PROVISIONED) {
        bc_provisioning_console(HIL_ROLE_NAME); /* never returns */
    }
#if CONFIG_LEANMESH_PROFILE_ROOT
    /* The USB port belongs to the Host session from here on (src/serial/idf_serial.cpp installs its driver). */
    if (start_mesh() != LM_STATUS_OK) {
        vTaskDelay(pdMS_TO_TICKS(5000));
        esp_restart(); /* no console to report on: retry from a clean boot */
    }
    root_watch();
#else
    bc_console_init();
    /* Safe mode: a WINDOWED/REPORT_ONLY policy light-sleeps the chip, and light sleep stops the USB-Serial/JTAG port
       (no console, no esptool). "safe" within 10 s of boot puts the node back to ALWAYS_RX before it can sleep (a PC needs a few
       seconds to enumerate the port again after a reset). */
    bool safe = false;
    for (int tick = 0; !safe && tick < 100; ++tick) {
        if (tick % 10 == 0) bc_out("HIL: send 'safe' within 10 s to force ALWAYS_RX\n");
        char *l = bc_console_line(pdMS_TO_TICKS(100));
        safe = l != NULL && strcmp(l, "safe") == 0;
    }
    lm_status_t st = start_mesh();
    if (safe && st == LM_STATUS_OK && bc_force_always_rx(s_ctx)) bc_out("HIL safe: ALWAYS_RX\n");
    bc_outf("HIL %s: mesh start %s (%u)\n", HIL_ROLE_NAME, st == LM_STATUS_OK ? "OK" : "FAILED", (unsigned)st);
    if (st != LM_STATUS_OK) {
        for (;;) {
            char *line = bc_console_line(portMAX_DELAY);
            if (line != NULL && strncmp(line, "reboot", 6) == 0) esp_restart();
            if (line != NULL) bc_answer(st);
        }
    }
    for (;;) {
        char *line = bc_console_line(pdMS_TO_TICKS(50));
        if (line != NULL) run_command(line);
        pump_events();
        join_timer();
    }
#endif
}
