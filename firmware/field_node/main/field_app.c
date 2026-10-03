/*
 * BENCH / FIELD TEST ONLY: the autonomous node application of the field test kit; see field_app.h and
 * docs/field/protocol.md. One task (the main task): the loop waits at most 50 ms for a console line, drains the SDK's
 * event queue, and every second looks at the membership and the connectivity (join, LED, panel). Telemetry is due
 * every 10 s; nothing here polls faster than the 50 ms event drain and nothing runs inside an SDK callback.
 *
 * Console after provisioning (nothing depends on it):
 *   info | status | field | join | ev [on|off] | safe | reboot
 */
#include "field_app.h"

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "bench_console.h"
#include "driver/usb_serial_jtag.h"
#include "esp_heap_caps.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "field_display.h"
#include "field_led.h"
#include "field_proto.h"
#include "field_render.h"
#include "leanmesh.h"
#include "leanmesh_bench.h"
#include "nvs.h"
#include "sdkconfig.h"

#if CONFIG_LEANMESH_PROFILE_ROOT
#error "field_node is a relay or leaf image (the root is firmware/hil_node)"
#endif
#if CONFIG_FIELD_HUB75 && !CONFIG_LEANMESH_PROFILE_RELAY
#error "the display build is a relay (CONFIG_LEANMESH_PROFILE_RELAY)"
#endif

#if CONFIG_FIELD_HUB75
#define NODE_ROLE LM_ROLE_RELAY
#define NODE_FIELD_ROLE FIELD_ROLE_DISPLAY
#elif CONFIG_LEANMESH_PROFILE_RELAY
#define NODE_ROLE LM_ROLE_RELAY
#define NODE_FIELD_ROLE FIELD_ROLE_RELAY
#else
#define NODE_ROLE LM_ROLE_LEAF
#define NODE_FIELD_ROLE FIELD_ROLE_LEAF
#endif

#if CONFIG_IDF_TARGET_ESP32S3
#define NODE_CHIP FIELD_CHIP_ESP32S3
#elif CONFIG_IDF_TARGET_ESP32C3
#define NODE_CHIP FIELD_CHIP_ESP32C3
#elif CONFIG_IDF_TARGET_ESP32C6
#define NODE_CHIP FIELD_CHIP_ESP32C6
#else
#define NODE_CHIP FIELD_CHIP_OTHER
#endif

#ifndef LM_DIAGNOSTICS_VALID_PARENT_RSSI /* api/leanmesh.h of the SDK that tracks the parent RSSI names it */
#define LM_DIAGNOSTICS_VALID_PARENT_RSSI (UINT64_C(1) << 22u)
#endif

#define LOOP_MS 50
#define LINK_TICK_MS 1000
#define REPORT_RETRY_SLOTS 4
#define REPORT_RETRY_MS 10000

static const char k_nvs_ns[] = "field";
static const char k_nvs_display[] = "disp"; /* the display command last applied, in its own wire format */

typedef struct {
    bool used;
    lm_message_ref_t ref;
    uint32_t outcome;
    uint64_t give_up_ms;
} pending_report_t;

static struct {
    lm_context_t *ctx;
    uint16_t boot_count;
    bool ev_print;
    uint64_t link_at_ms;
    bool refresh_now;
    /* link snapshot of the last LINK_TICK */
    lm_membership_t m;
    lm_connectivity_t c;
    field_link_t link;
    /* join */
    lm_operation_id_t join_op; /* 0: none outstanding */
    uint64_t join_at_ms;       /* the next ask is due */
    unsigned join_asks;        /* asks since the last ACTIVE */
    /* telemetry */
    uint32_t seq;
    uint64_t tele_at_ms;
    bool was_reachable;
    field_telemetry_t last;
    bool last_valid;
    lm_status_t last_send_status;
    uint32_t sent, refused;
    /* application results */
    uint32_t pings, display_cmds, display_rejected;
    pending_report_t pending[REPORT_RETRY_SLOTS];
    /* display */
    bool disp_valid, disp_forbid, render_fault;
    uint32_t disp_seq;
    field_view_t shown;
    bool shown_valid;
} g;

static uint8_t s_payload[LM_MAX_MESSAGE_BYTES];

/* Log lines (not console answers) are written only while a USB host is attached: without one the TX buffer of the
   USB-Serial/JTAG port fills up and every further write would wait for its timeout. */
#define say(...)                                         \
    do {                                                 \
        if (usb_serial_jtag_is_connected()) bc_outf(__VA_ARGS__); \
    } while (0)

static uint64_t now_ms(void) { return (uint64_t)(esp_timer_get_time() / 1000); }

/* ---- display state in NVS ---- */

static void display_load(void) {
    nvs_handle_t h;
    if (nvs_open(k_nvs_ns, NVS_READONLY, &h) != ESP_OK) return;
    uint8_t blob[FIELD_DISPLAY_CMD_BYTES];
    size_t len = sizeof blob;
    field_display_cmd_t cmd;
    if (nvs_get_blob(h, k_nvs_display, blob, &len) == ESP_OK && field_display_decode(blob, len, &cmd)) {
        g.disp_valid = true;
        g.disp_forbid = cmd.state == FIELD_DISPLAY_FORBID;
        g.disp_seq = cmd.seq;
    }
    nvs_close(h);
}

static bool display_store(void) {
    uint8_t blob[FIELD_DISPLAY_CMD_BYTES] = {FIELD_PROTO_VERSION, g.disp_forbid ? FIELD_DISPLAY_FORBID : FIELD_DISPLAY_USABLE,
                                             (uint8_t)(g.disp_seq >> 24), (uint8_t)(g.disp_seq >> 16),
                                             (uint8_t)(g.disp_seq >> 8), (uint8_t)g.disp_seq};
    nvs_handle_t h;
    if (nvs_open(k_nvs_ns, NVS_READWRITE, &h) != ESP_OK) return false;
    bool ok = nvs_set_blob(h, k_nvs_display, blob, sizeof blob) == ESP_OK && nvs_commit(h) == ESP_OK;
    nvs_close(h);
    return ok;
}

/* ---- results the application reports for a received message ---- */

static lm_message_ref_t ref_of(const lm_event_t *e) {
    lm_message_ref_t r = {0};
    r.origin = e->peer;
    r.assignment_generation = e->origin_assignment_generation;
    r.id = e->message_id;
    memcpy(r.intent_hash, e->intent_hash, sizeof r.intent_hash);
    return r;
}

static bool transient(lm_status_t st) {
    return st == LM_STATUS_BUSY || st == LM_STATUS_NO_CAPACITY || st == LM_STATUS_AUTH_PENDING;
}

/* A result the SDK cannot take right now (BUSY / NO_CAPACITY) is asked again every loop for REPORT_RETRY_MS; the table is
   fixed, a full table drops the result (the sender then sees no APP_APPLIED, which is the truth). */
static void report(const lm_event_t *e, uint32_t outcome) {
    const lm_message_ref_t ref = ref_of(e);
    const lm_status_t st = lm_report_application_result(g.ctx, &ref, outcome, NULL, 0, NULL);
    if (st == LM_STATUS_OK || !transient(st)) {
        if (st != LM_STATUS_OK) say("FIELD report port=%u outcome=%u refused: %u\n", (unsigned)e->app_port, (unsigned)outcome, (unsigned)st);
        return;
    }
    for (int i = 0; i < REPORT_RETRY_SLOTS; ++i) {
        if (!g.pending[i].used) {
            g.pending[i] = (pending_report_t){true, ref, outcome, now_ms() + REPORT_RETRY_MS};
            return;
        }
    }
    say("FIELD report dropped: retry table full\n");
}

static void retry_reports(uint64_t now) {
    for (int i = 0; i < REPORT_RETRY_SLOTS; ++i) {
        pending_report_t *p = &g.pending[i];
        if (!p->used) continue;
        const lm_status_t st = lm_report_application_result(g.ctx, &p->ref, p->outcome, NULL, 0, NULL);
        if (st == LM_STATUS_OK || !transient(st) || now >= p->give_up_ms) p->used = false;
    }
}

/* ---- link view, panel, LED ---- */

static field_view_t current_view(void) {
    field_view_t v = {.link = g.link, .root_depth = FIELD_UNKNOWN_U8, .parent_rssi_dbm = FIELD_RSSI_UNKNOWN,
                      .state_valid = g.disp_valid, .forbid = g.disp_forbid};
    if (g.link == FIELD_LINK_REACHABLE) {
        v.root_depth = field_depth8(g.c.root_depth, (g.c.validity_bits & LM_CONNECTIVITY_VALID_ROOT_DEPTH) != 0);
        lm_diagnostics_t d = {.struct_size = sizeof d, .abi_version = LM_ABI_VERSION};
        if (lm_diagnostics_get(g.ctx, &d) == LM_STATUS_OK) {
            v.parent_rssi_dbm = field_rssi8(d.parent_rssi_dbm, (d.validity_bits & LM_DIAGNOSTICS_VALID_PARENT_RSSI) != 0);
        }
    }
    return v;
}

static bool same_view(const field_view_t *a, const field_view_t *b) {
    return a->link == b->link && a->root_depth == b->root_depth && a->parent_rssi_dbm == b->parent_rssi_dbm &&
           a->state_valid == b->state_valid && a->forbid == b->forbid;
}

static void draw_if_changed(void) {
    if (!field_display_present()) return;
    const field_view_t v = current_view();
    if (g.shown_valid && same_view(&v, &g.shown) && !g.render_fault) return;
    g.render_fault = !field_display_show(&v);
    if (!g.render_fault) {
        g.shown = v;
        g.shown_valid = true;
    }
}

/* ---- join ---- */

static bool join_blocked(void) { return g.m.state == LM_MEMBER_REVOKED || g.m.state == LM_QUARANTINED; }

static void join_ask(uint64_t now) {
    lm_join_request_t r = {.struct_size = sizeof r, .abi_version = LM_ABI_VERSION, .mode = LM_JOIN_NEW};
    esp_fill_random(r.request_id.bytes, sizeof r.request_id.bytes);
    lm_operation_id_t op = 0;
    const lm_status_t st = lm_join(g.ctx, &r, &op);
    ++g.join_asks;
    if (st == LM_STATUS_OK) {
        g.join_op = op;
        say("FIELD join ask %u op=%llu\n", g.join_asks, (unsigned long long)op);
    } else {
        g.join_at_ms = now + 1000ull * field_join_backoff_s(g.join_asks - 1);
        say("FIELD join ask %u refused: %u, again in %u s\n", g.join_asks, (unsigned)st,
                (unsigned)field_join_backoff_s(g.join_asks - 1));
    }
}

/* An ACTIVE member re-attaches by the SDK itself: nothing to ask. Any other state asks lm_join(NEW) when no ask is
   outstanding; after one ended the next waits 5, 10, 20, 40, 60, 60 ... s (the SDK ends one search after 30 s). A
   revoked or quarantined node stops asking. */
static void join_tick(uint64_t now) {
    if (g.m.state == LM_ACTIVE) {
        g.join_op = 0;
        g.join_asks = 0;
        g.join_at_ms = 0;
        return;
    }
    if (join_blocked()) return;
    if (g.join_op != 0) {
        lm_operation_t o = {.struct_size = sizeof o, .abi_version = LM_ABI_VERSION};
        if (lm_get_operation(g.ctx, g.join_op, &o) == LM_STATUS_OK && o.phase != LM_PHASE_FINAL) return;
        g.join_op = 0; /* ended (or no longer known) */
        g.join_at_ms = now + 1000ull * field_join_backoff_s(g.join_asks - 1);
        return;
    }
    if (now >= g.join_at_ms) join_ask(now);
}

/* ---- telemetry ---- */

static void telemetry_send(uint64_t now) {
    lm_root_time_t t = {.struct_size = sizeof t, .abi_version = LM_ABI_VERSION};
    if (lm_root_time_get(g.ctx, &t) != LM_STATUS_OK || !t.valid) {
        g.tele_at_ms = now + 1000; /* no valid root time: nothing is sent, look again in a second */
        return;
    }
    lm_diagnostics_t d = {.struct_size = sizeof d, .abi_version = LM_ABI_VERSION};
    const bool dv = lm_diagnostics_get(g.ctx, &d) == LM_STATUS_OK;
    const bool counters = dv && (d.validity_bits & FIELD_DIAG_VALID_COUNTERS) != 0;
    const bool rssi = dv && (d.validity_bits & LM_DIAGNOSTICS_VALID_PARENT_RSSI) != 0;
    const bool depth = (g.c.validity_bits & LM_CONNECTIVITY_VALID_ROOT_DEPTH) != 0;

    field_telemetry_t f = {0};
    f.role = NODE_FIELD_ROLE;
    f.chip = NODE_CHIP;
    f.flags = (uint8_t)((g.disp_valid ? FIELD_FLAG_DISPLAY_VALID : 0) | (g.disp_valid && g.disp_forbid ? FIELD_FLAG_DISPLAY_FORBID : 0) |
                        (g.render_fault ? FIELD_FLAG_RENDER_FAULT : 0));
    f.seq = g.seq + 1;
    f.uptime_s = (uint32_t)(now / 1000);
    f.boot_count = g.boot_count;
    f.reset_reason = field_reset_reason8(d.last_reset_reason, dv && (d.validity_bits & FIELD_DIAG_VALID_RESET_REASON) != 0);
    f.root_depth = field_depth8(g.c.root_depth, depth);
    f.parent_rssi_dbm = field_rssi8(d.parent_rssi_dbm, rssi);
    f.interval_s = FIELD_TELEMETRY_INTERVAL_S;
    f.tx_frames = field_counter32(d.tx_frames, counters);
    f.rx_frames = field_counter32(d.rx_frames, counters);
    f.rf_failures = field_counter32(d.rf_failures, counters);
    f.local_busy = field_counter32(d.local_busy, counters);
    f.min_heap_bytes = field_counter32(d.min_heap_bytes, dv && (d.validity_bits & FIELD_DIAG_VALID_HEAP) != 0);
    f.display_seq = g.disp_valid ? g.disp_seq : 0;

    uint8_t wire[FIELD_TELEMETRY_BYTES];
    field_telemetry_encode(&f, wire);
    lm_send_request_t r = {.struct_size = sizeof r, .abi_version = LM_ABI_VERSION};
    r.destination.kind = LM_DEST_ROOT_APP;
    r.app_port = FIELD_PORT_TELEMETRY;
    r.delivery = LM_BEST_EFFORT;
    r.storage = LM_VOLATILE;
    r.priority = LM_PRIORITY_NORMAL;
    r.queue_mode = LM_FIFO;
    r.root_term = t.root_term;
    r.expires_root_ms = t.earliest_root_ms + FIELD_TELEMETRY_DEADLINE_MS;
    lm_operation_id_t op = 0;
    g.last_send_status = lm_send(g.ctx, &r, wire, sizeof wire, &op);
    if (g.last_send_status == LM_STATUS_OK) {
        g.seq = f.seq; /* a sequence number is spent only on an accepted send: a gap at the root is then a real loss */
        ++g.sent;
        g.last = f;
        g.last_valid = true;
    } else {
        ++g.refused; /* a local refusal (BUSY, NO_CAPACITY, TIME_UNCERTAIN ...) is not a lost frame */
    }
    g.tele_at_ms = now + field_telemetry_delay_ms(esp_random());
}

/* ---- the 1 Hz look at the link ---- */

static void link_tick(uint64_t now) {
    g.m = (lm_membership_t){.struct_size = sizeof g.m, .abi_version = LM_ABI_VERSION};
    g.c = (lm_connectivity_t){.struct_size = sizeof g.c, .abi_version = LM_ABI_VERSION};
    if (lm_membership_get(g.ctx, &g.m) != LM_STATUS_OK || lm_connectivity_get(g.ctx, &g.c) != LM_STATUS_OK) return;
    if (join_blocked()) {
        g.link = FIELD_LINK_REVOKED;
    } else if (g.m.state != LM_ACTIVE) {
        g.link = FIELD_LINK_JOINING;
    } else {
        g.link = g.c.state == LM_REACHABLE ? FIELD_LINK_REACHABLE : FIELD_LINK_LOST;
    }
    field_led_set(g.link == FIELD_LINK_REACHABLE ? FIELD_LED_ON : g.link == FIELD_LINK_JOINING ? FIELD_LED_BLINK : FIELD_LED_OFF);
    join_tick(now);
    draw_if_changed();
    const bool reachable = g.link == FIELD_LINK_REACHABLE;
    if (reachable && !g.was_reachable) g.tele_at_ms = now; /* the first telemetry right after REACHABLE (also after a loss) */
    g.was_reachable = reachable;
}

/* ---- received messages ---- */

static void display_command(const lm_event_t *e, const uint8_t *p, size_t n) {
    field_display_cmd_t cmd;
    if (!field_display_present() || !field_display_decode(p, n, &cmd)) {
        ++g.display_rejected;
        report(e, LM_OUTCOME_REJECTED); /* not a display build, or a message this node cannot read */
        return;
    }
    field_view_t v = current_view();
    v.state_valid = true;
    v.forbid = cmd.state == FIELD_DISPLAY_FORBID;
    if (!field_display_show(&v)) {
        g.render_fault = true;
        ++g.display_rejected;
        report(e, LM_OUTCOME_REJECTED); /* cannot draw */
        return;
    }
    g.render_fault = false;
    g.disp_valid = true;
    g.disp_forbid = v.forbid;
    g.disp_seq = cmd.seq;
    g.shown = v;
    g.shown_valid = true;
    ++g.display_cmds;
    if (!display_store()) say("FIELD display state not stored in NVS\n"); /* it is on the panel; a restart shows the old one */
    report(e, LM_OUTCOME_APPLIED); /* the frame is on the panel */
}

static void on_message(const lm_event_t *e, size_t n) {
    switch (e->app_port) {
    case FIELD_PORT_PING: {
        uint32_t round = 0;
        const bool ok = field_ping_decode(s_payload, n, &round);
        if (ok) ++g.pings;
        report(e, ok ? LM_OUTCOME_APPLIED : LM_OUTCOME_REJECTED);
        break;
    }
    case FIELD_PORT_DISPLAY:
        display_command(e, s_payload, n);
        break;
    default:
        break; /* not a field message: nothing to report */
    }
}

static void pump_events(void) {
    for (int i = 0; i < 16; ++i) {
        lm_event_t e = {.struct_size = sizeof e, .abi_version = LM_ABI_VERSION};
        size_t need = 0;
        if (lm_next_event(g.ctx, &e, s_payload, sizeof s_payload, &need) != LM_STATUS_OK) return;
        if (g.ev_print) {
            say("EV kind=%u reason=%u op=%llu seq=%llu port=%u bytes=%u\n", (unsigned)e.kind, (unsigned)e.reason,
                    (unsigned long long)e.operation_id, (unsigned long long)e.event_sequence, (unsigned)e.app_port,
                    (unsigned)e.payload_bytes);
        }
        if (e.kind == LM_EVENT_MESSAGE && e.payload_bytes <= sizeof s_payload) {
            on_message(&e, e.payload_bytes);
        } else if (e.kind == LM_EVENT_MEMBERSHIP || e.kind == LM_EVENT_CONNECTIVITY) {
            g.refresh_now = true;
        }
    }
}

/* ---- console ---- */

static void print_id(const char *label, const uint8_t *b, size_t n) {
    bc_out(label);
    bc_out_hex(b, n);
}

static void cmd_status(void) {
    lm_diagnostics_t d = {.struct_size = sizeof d, .abi_version = LM_ABI_VERSION};
    lm_root_time_t t = {.struct_size = sizeof t, .abi_version = LM_ABI_VERSION};
    const lm_status_t sd = lm_diagnostics_get(g.ctx, &d);
    const lm_status_t st = lm_root_time_get(g.ctx, &t);
    bc_outf("OK membership=%u reason=%u assign=%llu memb=%llu conn=%u depth=%u link=%u", (unsigned)g.m.state, (unsigned)g.m.reason,
            (unsigned long long)g.m.assignment_generation, (unsigned long long)g.m.membership_generation, (unsigned)g.c.state,
            (unsigned)g.c.root_depth, (unsigned)g.link);
    bc_outf(" time_valid=%u(st%u) term=%u chan=%u peers=%u tx=%llu rx=%llu rf_fail=%llu busy=%llu rssi=%d heap_min=%u(st%u)",
            (unsigned)t.valid, (unsigned)st, (unsigned)t.root_term, (unsigned)d.current_channel, (unsigned)d.regular_peers,
            (unsigned long long)d.tx_frames, (unsigned long long)d.rx_frames, (unsigned long long)d.rf_failures,
            (unsigned long long)d.local_busy, (int)d.parent_rssi_dbm, (unsigned)d.min_heap_bytes, (unsigned)sd);
    print_id(" id=", g.m.device.bytes, sizeof g.m.device.bytes);
    bc_out("\n");
}

static void cmd_field(void) {
    const field_telemetry_t *f = &g.last;
    bc_outf("OK sent=%u refused=%u last_status=%u joins=%u pings=%u display_ok=%u display_rejected=%u render_fault=%u", (unsigned)g.sent,
            (unsigned)g.refused, (unsigned)g.last_send_status, g.join_asks, (unsigned)g.pings, (unsigned)g.display_cmds,
            (unsigned)g.display_rejected, (unsigned)g.render_fault);
    if (g.last_valid) {
        bc_outf(" seq=%u uptime=%u boot=%u reset=%u depth=%u rssi=%d tx=%u rx=%u rf_fail=%u busy=%u heap_min=%u dseq=%u flags=%u",
                (unsigned)f->seq, (unsigned)f->uptime_s, (unsigned)f->boot_count, (unsigned)f->reset_reason, (unsigned)f->root_depth,
                (int)f->parent_rssi_dbm, (unsigned)f->tx_frames, (unsigned)f->rx_frames, (unsigned)f->rf_failures,
                (unsigned)f->local_busy, (unsigned)f->min_heap_bytes, (unsigned)f->display_seq, (unsigned)f->flags);
    }
    bc_out("\n");
}

static void run_command(char *line) {
    char *save = NULL;
    const char *cmd = strtok_r(line, " ", &save);
    if (cmd == NULL) return;
    if (strcmp(cmd, "info") == 0) {
        bc_outf("OK state=%u role=%s\n", (unsigned)LMB_PROVISIONED,
                NODE_FIELD_ROLE == FIELD_ROLE_DISPLAY ? "display" : NODE_FIELD_ROLE == FIELD_ROLE_RELAY ? "relay" : "leaf");
    } else if (strcmp(cmd, "status") == 0) {
        cmd_status();
    } else if (strcmp(cmd, "field") == 0) {
        cmd_field();
    } else if (strcmp(cmd, "join") == 0) { /* ask now (a bench shortcut past the backoff) */
        g.join_at_ms = 0;
        bc_out("OK\n");
    } else if (strcmp(cmd, "ev") == 0) {
        const char *arg = strtok_r(NULL, " ", &save);
        g.ev_print = arg == NULL ? !g.ev_print : strcmp(arg, "on") == 0;
        bc_outf("OK ev=%u\n", (unsigned)g.ev_print);
    } else if (strcmp(cmd, "safe") == 0) { /* hil_node's boot window command: a field node is always ALWAYS_RX */
        bc_out("OK\n");
    } else if (strcmp(cmd, "reboot") == 0) {
        bc_out("OK\n");
        vTaskDelay(pdMS_TO_TICKS(100));
        esp_restart();
    } else {
        bc_answer(LM_STATUS_UNSUPPORTED);
    }
}

/* ---- start ---- */

static lm_status_t start_mesh(void) {
    lm_config_t config;
    lm_workspace_size_t ws;
    lm_status_t st = lm_config_init(&config, sizeof config);
    if (st != LM_STATUS_OK) return st;
    config.role = NODE_ROLE;
    st = lm_workspace_required(&config, &ws);
    if (st != LM_STATUS_OK) return st;
    void *workspace = heap_caps_aligned_alloc(ws.alignment, ws.bytes, MALLOC_CAP_INTERNAL);
    if (workspace == NULL) return LM_STATUS_NO_CAPACITY;
    st = lm_init(workspace, ws.bytes, &config, &g.ctx);
    if (st != LM_STATUS_OK) return st;
    return lm_start(g.ctx);
}

void field_app_run(uint16_t boot_count) {
    g.boot_count = boot_count;
    g.tele_at_ms = UINT64_MAX;
    g.link = FIELD_LINK_JOINING;
    bc_console_init();
    field_led_init();
    field_led_set(FIELD_LED_BLINK);
    display_load();

    const lm_status_t st = start_mesh();
    /* A WINDOWED/REPORT_ONLY policy would light-sleep the chip and take the USB console with it; the field test runs
       ALWAYS_RX. (hil_node waits 10 s for a `safe` line first; a field node does not wait.) */
    const bool always_rx = st == LM_STATUS_OK && bc_force_always_rx(g.ctx);
    /* The panel comes after the SDK's workspace: if memory is short the panel fails (render fault), not the mesh. */
    if (field_display_present()) {
        g.render_fault = !field_display_init();
        if (!g.render_fault) draw_if_changed();
    }
    bc_outf("FIELD %s: mesh start %s (%u) always_rx=%u boot=%u\n",
            NODE_FIELD_ROLE == FIELD_ROLE_DISPLAY ? "display" : NODE_FIELD_ROLE == FIELD_ROLE_RELAY ? "relay" : "leaf",
            st == LM_STATUS_OK ? "OK" : "FAILED", (unsigned)st, (unsigned)always_rx, (unsigned)g.boot_count);
    if (st != LM_STATUS_OK) {
        field_led_set(FIELD_LED_OFF);
        for (;;) {
            char *line = bc_console_line(portMAX_DELAY);
            if (line != NULL && strncmp(line, "reboot", 6) == 0) esp_restart();
            if (line != NULL) bc_answer(st);
        }
    }
    for (;;) {
        char *line = bc_console_line(pdMS_TO_TICKS(LOOP_MS));
        if (line != NULL) run_command(line);
        pump_events();
        const uint64_t now = now_ms();
        retry_reports(now);
        if (g.refresh_now || now >= g.link_at_ms) {
            g.refresh_now = false;
            g.link_at_ms = now + LINK_TICK_MS;
            link_tick(now);
        }
        if (g.was_reachable && now >= g.tele_at_ms) telemetry_send(now);
        field_led_tick(now);
    }
}
