/* Field test kit wire formats and pure rules; see field_proto.h. */
#include "field_proto.h"

#include <string.h>

static void put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put32(uint8_t *p, uint32_t v) {
    put16(p, (uint16_t)(v >> 16));
    put16(p + 2, (uint16_t)v);
}

static uint16_t get16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

static uint32_t get32(const uint8_t *p) { return ((uint32_t)get16(p) << 16) | get16(p + 2); }

static void put64(uint8_t *p, uint64_t v) {
    put32(p, (uint32_t)(v >> 32));
    put32(p + 4, (uint32_t)v);
}

static uint64_t get64(const uint8_t *p) { return ((uint64_t)get32(p) << 32) | get32(p + 4); }

static bool presence_structure(const field_presence_snapshot_t *s) {
    return s != NULL && s->boot_id != 0 && s->seq != 0 && s->presence <= FIELD_PRESENCE_OCCUPIED &&
        s->learning <= FIELD_LEARN_NO_SENSOR && (s->flags & ~7u) == 0 && (s->fault_bits & ~7u) == 0 &&
        s->k3_result <= FIELD_K3_UNCONFIRMED &&
        (s->distance_mm == UINT16_MAX || (s->distance_mm >= 100 && s->distance_mm <= 4000)) &&
        (s->background_mm == UINT16_MAX || (s->background_mm >= 100 && s->background_mm <= 4000)) &&
        (s->background_mm != UINT16_MAX || s->noise_mm == 0);
}

bool field_presence_encode(const field_presence_snapshot_t *s, uint8_t out[FIELD_PRESENCE_BYTES]) {
    if (out == NULL || !presence_structure(s)) return false;
    memset(out, 0, FIELD_PRESENCE_BYTES);
    out[0] = FIELD_PROTO_VERSION;
    out[1] = s->presence;
    out[2] = s->learning;
    out[3] = s->flags;
    put64(out + 4, s->boot_id);
    put32(out + 12, s->seq);
    put32(out + 16, s->capture_ms);
    put16(out + 20, s->sample_age_ms);
    put16(out + 22, s->distance_mm);
    put16(out + 24, s->background_mm);
    put16(out + 26, s->noise_mm);
    put32(out + 28, s->learn_request);
    put32(out + 32, s->fault_bits);
    put32(out + 36, s->k3_seq);
    out[40] = s->k3_result;
    return true;
}

bool field_presence_decode(const uint8_t *in, size_t n, field_presence_snapshot_t *s) {
    if (in == NULL || s == NULL || n != FIELD_PRESENCE_BYTES || in[0] != FIELD_PROTO_VERSION ||
        in[41] != 0 || in[42] != 0 || in[43] != 0) return false;
    field_presence_snapshot_t v = {0};
    v.presence = in[1];
    v.learning = in[2];
    v.flags = in[3];
    v.boot_id = get64(in + 4);
    v.seq = get32(in + 12);
    v.capture_ms = get32(in + 16);
    v.sample_age_ms = get16(in + 20);
    v.distance_mm = get16(in + 22);
    v.background_mm = get16(in + 24);
    v.noise_mm = get16(in + 26);
    v.learn_request = get32(in + 28);
    v.fault_bits = get32(in + 32);
    v.k3_seq = get32(in + 36);
    v.k3_result = in[40];
    if (!presence_structure(&v)) return false;
    *s = v;
    return true;
}

bool field_key_encode(const field_key_notice_t *s, uint8_t out[FIELD_KEY_BYTES]) {
    if (s == NULL || out == NULL || s->boot_id == 0 || s->seq == 0) return false;
    memset(out, 0, FIELD_KEY_BYTES);
    out[0] = FIELD_PROTO_VERSION;
    out[1] = 3;
    put64(out + 4, s->boot_id);
    put32(out + 12, s->seq);
    put32(out + 16, s->press_ms);
    return true;
}

bool field_key_decode(const uint8_t *in, size_t n, field_key_notice_t *s) {
    if (in == NULL || s == NULL || n != FIELD_KEY_BYTES || in[0] != FIELD_PROTO_VERSION ||
        in[1] != 3 || in[2] != 0 || in[3] != 0 || get64(in + 4) == 0 || get32(in + 12) == 0) return false;
    s->boot_id = get64(in + 4);
    s->seq = get32(in + 12);
    s->press_ms = get32(in + 16);
    return true;
}

void field_telemetry_encode(const field_telemetry_t *t, uint8_t out[FIELD_TELEMETRY_BYTES]) {
    out[0] = FIELD_PROTO_VERSION;
    out[1] = t->role;
    out[2] = t->chip;
    out[3] = t->flags;
    put32(out + 4, t->seq);
    put32(out + 8, t->uptime_s);
    put16(out + 12, t->boot_count);
    out[14] = t->reset_reason;
    out[15] = t->root_depth;
    out[16] = (uint8_t)t->parent_rssi_dbm;
    out[17] = 0; /* reserved */
    put16(out + 18, t->interval_s);
    put32(out + 20, t->tx_frames);
    put32(out + 24, t->rx_frames);
    put32(out + 28, t->rf_failures);
    put32(out + 32, t->local_busy);
    put32(out + 36, t->min_heap_bytes);
    put32(out + 40, t->display_seq);
}

bool field_telemetry_decode(const uint8_t *in, size_t n, field_telemetry_t *t) {
    if (in == NULL || n != FIELD_TELEMETRY_BYTES || in[0] != FIELD_PROTO_VERSION) {
        return false;
    }
    t->role = in[1];
    t->chip = in[2];
    t->flags = in[3];
    t->seq = get32(in + 4);
    t->uptime_s = get32(in + 8);
    t->boot_count = get16(in + 12);
    t->reset_reason = in[14];
    t->root_depth = in[15];
    t->parent_rssi_dbm = (int8_t)in[16];
    t->interval_s = get16(in + 18);
    t->tx_frames = get32(in + 20);
    t->rx_frames = get32(in + 24);
    t->rf_failures = get32(in + 28);
    t->local_busy = get32(in + 32);
    t->min_heap_bytes = get32(in + 36);
    t->display_seq = get32(in + 40);
    return true;
}

uint32_t field_counter32(uint64_t value, bool valid) { return valid ? (uint32_t)value : FIELD_UNKNOWN_U32; }

uint8_t field_reset_reason8(uint64_t value, bool valid) {
    return valid && value < FIELD_UNKNOWN_U8 ? (uint8_t)value : FIELD_UNKNOWN_U8;
}

int8_t field_rssi8(int16_t dbm, bool valid) {
    if (!valid) {
        return FIELD_RSSI_UNKNOWN;
    }
    return dbm < -127 ? -127 : dbm > 127 ? 127 : (int8_t)dbm;
}

uint8_t field_depth8(uint32_t depth, bool valid) { return valid && depth < FIELD_UNKNOWN_U8 ? (uint8_t)depth : FIELD_UNKNOWN_U8; }

bool field_ping_decode(const uint8_t *in, size_t n, uint32_t *round) {
    if (in == NULL || n != FIELD_PING_BYTES || in[0] != FIELD_PROTO_VERSION) {
        return false;
    }
    *round = get32(in + 1);
    return true;
}

bool field_display_decode(const uint8_t *in, size_t n, field_display_cmd_t *cmd) {
    if (in == NULL || n != FIELD_DISPLAY_CMD_BYTES || in[0] != FIELD_PROTO_VERSION ||
        (in[1] != FIELD_DISPLAY_USABLE && in[1] != FIELD_DISPLAY_FORBID)) {
        return false;
    }
    cmd->state = in[1];
    cmd->seq = get32(in + 2);
    return true;
}

field_action_t field_message_action(uint16_t app_port, const uint8_t *in, size_t n) {
    uint32_t round;
    switch (app_port) {
    case FIELD_PORT_PING:
        return field_ping_decode(in, n, &round) ? FIELD_ACT_PING_OK : FIELD_ACT_PING_UNKNOWN;
    case FIELD_PORT_DISPLAY:
        return FIELD_ACT_DISPLAY;
    default:
        return FIELD_ACT_IGNORE;
    }
}

uint32_t field_join_backoff_s(unsigned attempt) {
    static const uint8_t k_steps[] = {2, 4, 8, 15, 20};
    return attempt < sizeof k_steps ? k_steps[attempt] : 20u;
}

uint32_t field_telemetry_delay_ms(uint32_t random) {
    return FIELD_TELEMETRY_INTERVAL_S * 1000u + random % (FIELD_TELEMETRY_JITTER_MS + 1u);
}

/* ---- node event log ---- */

size_t field_put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
    return 4;
}

size_t field_put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
    return 2;
}

void field_log_init(field_log_t *log) {
    memset(log, 0, sizeof *log);
    log->next_seq = 1;
}

void field_log_add(field_log_t *log, uint8_t type, uint32_t t_ms, const uint8_t *payload, uint8_t len) {
    if (log->count == FIELD_LOG_RING) { /* full: the oldest goes, and is counted */
        log->head = (uint8_t)((log->head + 1u) % FIELD_LOG_RING);
        --log->count;
        if (log->dropped != 0xFFFFu) ++log->dropped;
    }
    field_log_rec_t *r = &log->rec[(log->head + log->count) % FIELD_LOG_RING];
    r->type = type;
    r->len = len > FIELD_LOG_PAYLOAD_MAX ? (uint8_t)FIELD_LOG_PAYLOAD_MAX : len;
    r->seq = log->next_seq;
    log->next_seq = (uint16_t)(log->next_seq == 0xFFFFu ? 1u : log->next_seq + 1u); /* 0 is the LOG_LOST record's */
    r->t_ms = t_ms;
    if (r->len != 0 && payload != NULL) memcpy(r->payload, payload, r->len);
    ++log->count;
}

static size_t put_record(uint8_t *p, uint8_t type, uint8_t len, uint16_t seq, uint32_t t_ms, const uint8_t *payload) {
    p[0] = type;
    p[1] = len;
    field_put16(p + 2, seq);
    field_put32(p + 4, t_ms);
    if (len != 0) memcpy(p + FIELD_LOG_RECORD_HEAD, payload, len);
    return FIELD_LOG_RECORD_HEAD + len;
}

size_t field_log_encode(const field_log_t *log, uint16_t boot_count, uint32_t now_ms, uint8_t *out, size_t cap,
                        unsigned *taken) {
    *taken = 0;
    if (cap > FIELD_LOG_MESSAGE_MAX) cap = FIELD_LOG_MESSAGE_MAX;
    if ((log->count == 0 && log->dropped == 0) || cap < FIELD_LOG_MESSAGE_HEAD + FIELD_LOG_RECORD_HEAD + 2) return 0;
    size_t n = FIELD_LOG_MESSAGE_HEAD;
    unsigned records = 0;
    if (log->dropped != 0) {
        uint8_t lost[2];
        field_put16(lost, log->dropped);
        n += put_record(out + n, FIELD_LOG_LOST, 2, 0, now_ms, lost);
        ++records;
    }
    while (*taken < log->count) {
        const field_log_rec_t *r = &log->rec[(log->head + *taken) % FIELD_LOG_RING];
        if (n + FIELD_LOG_RECORD_HEAD + r->len > cap) break;
        n += put_record(out + n, r->type, r->len, r->seq, r->t_ms, r->payload);
        ++*taken;
        ++records;
    }
    out[0] = FIELD_LOG_VERSION;
    out[1] = (uint8_t)records;
    field_put16(out + 2, boot_count);
    return n;
}

void field_log_consume(field_log_t *log, unsigned taken) {
    if (taken > log->count) taken = log->count;
    log->head = (uint8_t)((log->head + taken) % FIELD_LOG_RING);
    log->count = (uint8_t)(log->count - taken);
    log->dropped = 0;
}
