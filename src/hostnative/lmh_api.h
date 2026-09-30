/* C API of libleanmesh_host: the Host's USB serial session (docs/IMPLEMENTATION.md S10). One handle
 * per serial port, used from ONE thread. Times are microseconds of a monotonic clock chosen by the
 * caller (Python: time.monotonic_ns() // 1000). Status values are LM_STATUS_* of api/leanmesh.h. */
#ifndef LMH_API_H
#define LMH_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LMH_ABI_VERSION 2u
#define LMH_EXPORT __attribute__((visibility("default")))

typedef struct lmh_usb lmh_usb_t;

enum { LMH_EVENT_SESSION_UP = 1, LMH_EVENT_SESSION_DOWN = 2, LMH_EVENT_RECORD = 3, LMH_EVENT_TX_READY = 4 };

typedef struct {
    uint32_t kind;        /* LMH_EVENT_* */
    uint32_t gen;         /* session generation */
    uint32_t aux;         /* SESSION_DOWN: reason code; RECORD: serial kind (3 request, 4 response, 5 event) */
    uint32_t lane;        /* RECORD: credit lane */
    uint32_t frame_bytes; /* RECORD: decoded frame size (credit accounting) */
    uint32_t payload_len; /* RECORD: bytes copied to the caller's buffer */
} lmh_event_t;

typedef struct { /* fixed order; new fields are appended and lmh_stats_count() grows */
    uint64_t v[24];
} lmh_stats_t;

LMH_EXPORT uint32_t lmh_abi_version(void);
/* kit: CBOR host kit (identity record, fleet trust record, expected domain). NULL on failure with
 * *status set (LM_STATUS_*). */
LMH_EXPORT lmh_usb_t *lmh_usb_create(const uint8_t *kit, size_t kit_len, uint64_t boot_id, int32_t *status);
LMH_EXPORT void lmh_usb_destroy(lmh_usb_t *h);
/* Own DeviceId (32 bytes). */
LMH_EXPORT int32_t lmh_usb_self(lmh_usb_t *h, uint8_t out[32]);

LMH_EXPORT int32_t lmh_usb_open(lmh_usb_t *h, uint64_t now_us);   /* port opened (or reopened) */
LMH_EXPORT void lmh_usb_close(lmh_usb_t *h);                       /* port lost: sessions dropped */
LMH_EXPORT int32_t lmh_usb_feed(lmh_usb_t *h, const uint8_t *data, size_t len, uint64_t now_us);
/* Encoded bytes for the port. peek copies without removing; consume removes exactly the `n` bytes the OS
 * accepted (a write may be partial: bytes are never dropped before that is known). */
LMH_EXPORT size_t lmh_usb_peek_tx(lmh_usb_t *h, uint8_t *out, size_t cap);
LMH_EXPORT int32_t lmh_usb_consume_tx(lmh_usb_t *h, size_t n);
LMH_EXPORT int32_t lmh_usb_tick(lmh_usb_t *h, uint64_t now_us);
/* Absolute time of the next required tick in the same clock, UINT64_MAX = none. */
LMH_EXPORT uint64_t lmh_usb_deadline_us(lmh_usb_t *h);
/* 1 = an event was returned (record payload copied, `*ev` filled), 0 = none, <0 = LM_STATUS_* error
 * (BUFFER_TOO_SMALL keeps the event queued and sets ev->payload_len to the needed size). */
LMH_EXPORT int32_t lmh_usb_poll_event(lmh_usb_t *h, lmh_event_t *ev, uint8_t *buf, size_t cap, uint64_t now_us);
/* kind: 3 REQUEST, 4 RESPONSE, 5 EVENT. BUSY = no credit or TX occupied (local flow control),
 * CONFLICT = that session generation ended. */
LMH_EXPORT int32_t lmh_usb_send(lmh_usb_t *h, uint32_t kind, uint32_t gen, const uint8_t *payload, size_t len,
                     uint64_t now_us);
LMH_EXPORT int32_t lmh_usb_active(lmh_usb_t *h, uint32_t *gen, uint32_t *session_id);
LMH_EXPORT size_t lmh_usb_stats_count(void);
LMH_EXPORT int32_t lmh_usb_stats(lmh_usb_t *h, lmh_stats_t *out);

#ifdef __cplusplus
}
#endif
#endif
