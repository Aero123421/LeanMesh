#ifndef FIELD_PROTO_H
#define FIELD_PROTO_H
/* Field test kit: the wire formats and the pure rules of firmware/field_node (docs/field/protocol.md sections 2, 3).
   No ESP-IDF and no LeanMesh API in this file: it is built natively by tests/native/test_field.cpp. All integers
   are big-endian. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FIELD_PORT_TELEMETRY 210u
#define FIELD_PORT_PING 211u
#define FIELD_PORT_DISPLAY 212u
#define FIELD_PORT_LOG 213u
#define FIELD_PORT_PRESENCE 214u
#define FIELD_PORT_KEY 215u
#define FIELD_PORT_DEBUG 216u /* the SDK debug line as text (protocol 3.6) */
#define FIELD_DEBUG_MAX 480u
#define FIELD_DEBUG_INTERVAL_MS 300000u
#define FIELD_DEBUG_MIN_GAP_MS 60000u /* a path that comes back sooner after the last line sends no extra one */
#define FIELD_PRESENCE_BYTES 44u
#define FIELD_KEY_BYTES 20u

enum { FIELD_PRESENCE_DISABLED, FIELD_PRESENCE_UNKNOWN, FIELD_PRESENCE_VACANT, FIELD_PRESENCE_OCCUPIED };
enum { FIELD_LEARN_IDLE, FIELD_LEARN_RUNNING, FIELD_LEARN_DONE, FIELD_LEARN_FAILED, FIELD_LEARN_NO_SENSOR };
enum { FIELD_K3_IDLE, FIELD_K3_SENDING, FIELD_K3_CONFIRMED, FIELD_K3_NOT_SENT, FIELD_K3_UNCONFIRMED };
enum { FIELD_SENSOR_READY = 1, FIELD_BACKGROUND_VALID = 2, FIELD_KEYS_READY = 4 };
typedef struct {
    uint8_t presence, learning, flags;
    uint64_t boot_id;
    uint32_t seq, capture_ms;
    uint16_t sample_age_ms, distance_mm, background_mm, noise_mm;
    uint32_t learn_request, fault_bits, k3_seq;
    uint8_t k3_result;
} field_presence_snapshot_t;
typedef struct {
    uint64_t boot_id;
    uint32_t seq, press_ms;
} field_key_notice_t;
bool field_presence_encode(const field_presence_snapshot_t *s, uint8_t out[FIELD_PRESENCE_BYTES]);
bool field_presence_decode(const uint8_t *in, size_t n, field_presence_snapshot_t *s);
bool field_key_encode(const field_key_notice_t *s, uint8_t out[FIELD_KEY_BYTES]);
bool field_key_decode(const uint8_t *in, size_t n, field_key_notice_t *s);

#define FIELD_PROTO_VERSION 1u
#define FIELD_TELEMETRY_BYTES 44u
#define FIELD_TELEMETRY_INTERVAL_S 10u
#define FIELD_TELEMETRY_JITTER_MS 1000u /* the delay to the next telemetry is 10 s + 0..1000 ms */
#define FIELD_TELEMETRY_DEADLINE_MS 30000u
#define FIELD_PING_BYTES 5u
#define FIELD_DISPLAY_CMD_BYTES 6u

enum { FIELD_ROLE_LEAF = 1, FIELD_ROLE_RELAY = 2, FIELD_ROLE_DISPLAY = 3 };
enum { FIELD_CHIP_OTHER = 0, FIELD_CHIP_ESP32S3 = 1, FIELD_CHIP_ESP32C3 = 2, FIELD_CHIP_ESP32C6 = 3 };
enum {
    FIELD_FLAG_DISPLAY_VALID = 1u << 0, /* a display state is known (applied now or restored from NVS) */
    FIELD_FLAG_DISPLAY_FORBID = 1u << 1, /* that state is FORBID (else USABLE) */
    FIELD_FLAG_RENDER_FAULT = 1u << 2    /* the panel could not draw */
};
enum { FIELD_DISPLAY_USABLE = 0, FIELD_DISPLAY_FORBID = 1 };

/* lm_diagnostics_t.validity_bits that api/leanmesh.h does not name yet: the values of lm::diag::valid in
   src/core/diag/diag.hpp (tests/native/test_field.cpp asserts they are equal). */
#define FIELD_DIAG_VALID_RESET_REASON (UINT64_C(1) << 0)
#define FIELD_DIAG_VALID_HEAP (UINT64_C(1) << 1)
#define FIELD_DIAG_VALID_COUNTERS (UINT64_C(1) << 16) /* tx_frames, rx_frames, link_retries, rf_failures, local_busy */

#define FIELD_UNKNOWN_U8 0xFFu
#define FIELD_UNKNOWN_U32 0xFFFFFFFFu
#define FIELD_RSSI_UNKNOWN (-128)

typedef struct {
    uint8_t role, chip, flags;
    uint32_t seq, uptime_s;
    uint16_t boot_count;
    uint8_t reset_reason, root_depth;
    int8_t parent_rssi_dbm;
    uint16_t interval_s;
    uint32_t tx_frames, rx_frames, rf_failures, local_busy; /* low 32 bits; FIELD_UNKNOWN_U32 when invalid */
    uint32_t min_heap_bytes;
    uint32_t display_seq; /* the display command seq last applied (0 none) */
} field_telemetry_t;

/* Writes exactly FIELD_TELEMETRY_BYTES bytes. */
void field_telemetry_encode(const field_telemetry_t *t, uint8_t out[FIELD_TELEMETRY_BYTES]);
/* Reads one telemetry payload. False for a wrong length or version. */
bool field_telemetry_decode(const uint8_t *in, size_t n, field_telemetry_t *t);

/* Diagnostics value -> telemetry field. An invalid value is "unknown", never 0. */
uint32_t field_counter32(uint64_t value, bool valid);
uint8_t field_reset_reason8(uint64_t value, bool valid);
int8_t field_rssi8(int16_t dbm, bool valid); /* clamped to -127..127; -128 when invalid */
uint8_t field_depth8(uint32_t depth, bool valid);

/* Host -> node. Unknown version or a wrong length is false (the node reports REJECTED). */
bool field_ping_decode(const uint8_t *in, size_t n, uint32_t *round);
typedef struct {
    uint8_t state; /* FIELD_DISPLAY_USABLE / FIELD_DISPLAY_FORBID */
    uint32_t seq;
} field_display_cmd_t;
bool field_display_decode(const uint8_t *in, size_t n, field_display_cmd_t *cmd);

/* What the node application does with a received MESSAGE event of `app_port` (docs/field/protocol.md section 3). */
typedef enum {
    FIELD_ACT_IGNORE,      /* not a field message: nothing is reported, nothing counted */
    FIELD_ACT_PING_OK,     /* a version-1 ping: count it; no application result (the message is RECEIVED, the SDK's receipt answers) */
    FIELD_ACT_PING_UNKNOWN, /* a ping this node cannot read (unknown version or length): count it apart; still no result */
    FIELD_ACT_DISPLAY      /* a display command: decode it, draw it, report APPLIED / REJECTED */
} field_action_t;
field_action_t field_message_action(uint16_t app_port, const uint8_t *in, size_t n);

/* Seconds to wait after the `attempt`-th (0-based) join ended or was refused: 2, 4, 8, 15, 20, 20, ... (an ask that the
   root refused because the node is not expected yet should be repeated soon; HIL 2026-10-04 measured 50-70 s joins with
   the old 5..60 s steps). */
uint32_t field_join_backoff_s(unsigned attempt);
/* Milliseconds to the next telemetry: 10 s plus `random` modulo 1001 ms. */
uint32_t field_telemetry_delay_ms(uint32_t random);

/* ---- node event log (docs/field/protocol.md section 3.4) ---- */
enum {
    FIELD_LOG_BOOT = 1, FIELD_LOG_MEMBER = 2, FIELD_LOG_REACHABLE = 3, FIELD_LOG_UNREACHABLE = 4, FIELD_LOG_TIME_VALID = 5,
    FIELD_LOG_JOIN_END = 6, FIELD_LOG_RADIO = 7, FIELD_LOG_DEPTH = 8, FIELD_LOG_DISPLAY_FAULT = 9, FIELD_LOG_LOST = 10,
    FIELD_LOG_RADIO_FAULT = 11, FIELD_LOG_SDK_FAULT = 12, FIELD_LOG_TX_POWER = 13
};
#define FIELD_LOG_RING 32u
#define FIELD_LOG_PAYLOAD_MAX 12u
#define FIELD_LOG_MESSAGE_MAX 160u
#define FIELD_LOG_RECORD_HEAD 8u /* type, len, seq u16, t_ms u32 */
#define FIELD_LOG_VERSION 2u      /* version 2: the message names its boot */
#define FIELD_LOG_MESSAGE_HEAD 4u /* version, count, boot_count u16 */
#define FIELD_LOG_INTERVAL_MS 2000u

typedef struct {
    uint8_t type, len;
    uint16_t seq;
    uint32_t t_ms;
    uint8_t payload[FIELD_LOG_PAYLOAD_MAX];
} field_log_rec_t;

/* A fixed ring of records waiting to be sent. Full: the oldest record is dropped and counted (a LOG_LOST record tells
   the laptop in the next message). */
typedef struct {
    field_log_rec_t rec[FIELD_LOG_RING];
    uint8_t head, count; /* rec[head] is the oldest */
    uint16_t next_seq;   /* the seq of the next record (1.. per boot; 0 is the LOG_LOST record's) */
    uint16_t dropped;    /* records dropped since the last message that went out */
} field_log_t;

void field_log_init(field_log_t *log);
/* Adds a record; a payload longer than FIELD_LOG_PAYLOAD_MAX is cut. */
void field_log_add(field_log_t *log, uint8_t type, uint32_t t_ms, const uint8_t *payload, uint8_t len);
/* Builds one message from the oldest records (a LOG_LOST record first when records were dropped), at most
   FIELD_LOG_MESSAGE_MAX bytes. The ring is RAM, so every record is of this boot, `boot_count`, which the message names.
   Returns its length (0: nothing to send) and in *taken how many ring records it holds. */
size_t field_log_encode(const field_log_t *log, uint16_t boot_count, uint32_t now_ms, uint8_t *out, size_t cap,
                        unsigned *taken);
/* The message of field_log_encode went out (the SDK accepted it): its records and the drop count are done. */
void field_log_consume(field_log_t *log, unsigned taken);
/* Payload helpers (big-endian). */
size_t field_put32(uint8_t *p, uint32_t v);
size_t field_put16(uint8_t *p, uint16_t v);

#ifdef __cplusplus
}
#endif
#endif
