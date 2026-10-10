#ifndef FIELD_CONTROL_H
#define FIELD_CONTROL_H
#include "field_proto.h"
#include "field_render.h"
#ifdef __cplusplus
extern "C" {
#endif
/* Acquisition task owns debounce/queue; main removes events under the same short lock.
   Full: drop newest action, saturating dropped count; never overwrite an older press. */
#define FIELD_KEY_QUEUE_CAPACITY 8u
typedef struct { uint8_t button; uint32_t seq; uint64_t at_ms; } field_key_event_t;
typedef struct {
    bool initialized, armed, candidate, stable, candidate_valid;
    uint64_t since_ms;
} field_key_debounce_t;
typedef struct {
    field_key_debounce_t key[2];
    field_key_event_t events[FIELD_KEY_QUEUE_CAPACITY];
    uint8_t head, count;
    bool ready;
    uint32_t dropped, press_seq;
} field_keys_t;
void field_keys_read(field_keys_t *k, uint64_t now, bool ok, uint8_t input);
bool field_keys_pop(field_keys_t *k, field_key_event_t *out);
uint8_t field_keys_config(uint8_t old);
uint8_t field_keys_polarity(uint8_t old);

/* Main application owns one K3 operation. Admission is one attempt; the SDK
   owns retransmission. Expiry never asserts undelivered without evidence. */
typedef struct {
    uint32_t seq, busy;
    uint8_t result;
    bool pending, possibly_sent;
    uint64_t operation, press_ms, deadline_ms, feedback_until_ms, busy_until_ms;
} field_k3_t;
bool field_k3_press(field_k3_t *k, uint32_t seq, uint64_t press, uint64_t now);
void field_k3_accepted(field_k3_t *k, uint64_t op);
void field_k3_refused(field_k3_t *k, uint64_t now);
void field_k3_observe(field_k3_t *k, uint64_t op, bool final, bool sent, bool received, uint64_t now);
void field_k3_tick(field_k3_t *k, uint64_t now);
/* Sequence/result are a single association, never the raw physical press counter. */
void field_k3_snapshot(const field_k3_t *k, field_presence_snapshot_t *s);

/* One retained learning result. Acquisition offers it and blocks another learn;
   main starts its visible timer only after a successful matching DMA frame.
   The short acquisition/main lock protects this slot; no I/O under that lock. */
typedef struct {
    uint32_t token;
    uint8_t result;
    bool pending;
    uint64_t visible_until_ms;
} field_learning_feedback_t;
bool field_learning_feedback_offer(field_learning_feedback_t *f, uint8_t result);
void field_learning_feedback_shown(field_learning_feedback_t *f, uint32_t token, uint64_t now);
void field_learning_feedback_tick(field_learning_feedback_t *f, uint64_t now);
field_feedback_t field_feedback_select(const field_learning_feedback_t *f, const field_k3_t *k,
                                       uint8_t learning_state, uint64_t now);

typedef struct {
    field_presence_snapshot_t last;
    bool have_last;
    uint32_t seq;
    uint64_t operation, operation_until_ms, next_try_ms, refresh_ms;
} field_snapshot_send_t;
bool field_snapshot_due(const field_snapshot_send_t *t, const field_presence_snapshot_t *s, uint64_t now);
void field_snapshot_attempt(field_snapshot_send_t *t, const field_presence_snapshot_t *s, uint64_t now, uint64_t op);
#ifdef __cplusplus
}
#endif
#endif
