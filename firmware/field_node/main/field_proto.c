/* Field test kit wire formats and pure rules; see field_proto.h. */
#include "field_proto.h"

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

uint32_t field_join_backoff_s(unsigned attempt) {
    static const uint8_t k_steps[] = {5, 10, 20, 40, 60};
    return attempt < sizeof k_steps ? k_steps[attempt] : 60u;
}

uint32_t field_telemetry_delay_ms(uint32_t random) {
    return FIELD_TELEMETRY_INTERVAL_S * 1000u + random % (FIELD_TELEMETRY_JITTER_MS + 1u);
}
