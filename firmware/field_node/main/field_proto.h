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

/* Seconds to wait after the `attempt`-th (0-based) join ended or was refused: 5, 10, 20, 40, 60, 60, ... */
uint32_t field_join_backoff_s(unsigned attempt);
/* Milliseconds to the next telemetry: 10 s plus `random` modulo 1001 ms. */
uint32_t field_telemetry_delay_ms(uint32_t random);

#ifdef __cplusplus
}
#endif
#endif
