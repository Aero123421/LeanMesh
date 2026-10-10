#include "field_control.h"
#include <limits.h>

static void increment(uint32_t *n) { if (*n != UINT32_MAX) ++*n; }
uint8_t field_keys_config(uint8_t old) { return old | 6u; }
uint8_t field_keys_polarity(uint8_t old) { return old & (uint8_t)~6u; }

void field_keys_read(field_keys_t *k, uint64_t now, bool ok, uint8_t input) {
    k->ready = ok;
    for (unsigned i = 0; i < 2; ++i) {
        field_key_debounce_t *d = &k->key[i];
        if (!ok) {
            d->candidate_valid = false;
            continue;
        }
        const bool pressed = (input & (1u << (i + 1))) == 0;
        if (!d->initialized) {
            d->initialized = true;
            d->stable = pressed;
            d->armed = !pressed;
        }
        if (!d->candidate_valid || d->candidate != pressed) {
            d->candidate = pressed;
            d->candidate_valid = true;
            d->since_ms = now;
        }
        if (now - d->since_ms < 50) continue;
        if (!pressed) d->armed = true;
        if (d->stable == pressed) continue;
        d->stable = pressed;
        if (!pressed || !d->armed) continue;
        d->armed = false;
        const uint8_t button = i == 0 ? 1 : 3;
        if (button == 3 && k->press_seq == UINT32_MAX) {
            increment(&k->dropped);
            continue;
        }
        if (button == 3) ++k->press_seq;
        if (k->count == FIELD_KEY_QUEUE_CAPACITY) {
            increment(&k->dropped);
            continue;
        }
        k->events[(k->head + k->count) % FIELD_KEY_QUEUE_CAPACITY] =
            (field_key_event_t){button, button == 3 ? k->press_seq : 0, now};
        ++k->count;
    }
}

bool field_keys_pop(field_keys_t *k, field_key_event_t *out) {
    if (k->count == 0) return false;
    *out = k->events[k->head];
    k->head = (k->head + 1u) % FIELD_KEY_QUEUE_CAPACITY;
    --k->count;
    return true;
}

static void complete(field_k3_t *k, uint8_t result, uint64_t now) {
    k->result = result;
    k->pending = false;
    k->feedback_until_ms = now + 3000;
    k->busy_until_ms = now;
}

bool field_k3_press(field_k3_t *k, uint32_t seq, uint64_t press, uint64_t now) {
    if (k->pending || k->operation != 0 || (k->seq != 0 && press <= k->busy_until_ms)) {
        increment(&k->busy);
        return false;
    }
    if (seq == 0 || seq <= k->seq || now < press) return false;
    k->seq = seq;
    k->press_ms = press;
    k->deadline_ms = press + 30000;
    k->operation = 0;
    k->possibly_sent = false;
    k->pending = true;
    k->result = FIELD_K3_SENDING;
    k->feedback_until_ms = 0;
    field_k3_tick(k, now);
    return true;
}

void field_k3_accepted(field_k3_t *k, uint64_t op) { if (k->pending) k->operation = op; }
void field_k3_refused(field_k3_t *k, uint64_t now) { complete(k, FIELD_K3_NOT_SENT, now); }
void field_k3_observe(field_k3_t *k, uint64_t op, bool final, bool sent, bool received, uint64_t now) {
    if (op == 0 || op != k->operation) return;
    k->possibly_sent |= sent;
    if (received && k->result != FIELD_K3_CONFIRMED) complete(k, FIELD_K3_CONFIRMED, now);
    else if (final && k->pending) complete(k, FIELD_K3_UNCONFIRMED, now);
    if (final) {
        k->operation = 0;
        k->busy_until_ms = now;
    }
}
void field_k3_tick(field_k3_t *k, uint64_t now) {
    if (k->pending && now >= k->deadline_ms)
        complete(k, k->operation != 0 ? FIELD_K3_UNCONFIRMED : FIELD_K3_NOT_SENT, now);
}

void field_k3_snapshot(const field_k3_t *k, field_presence_snapshot_t *s) {
    s->k3_seq = k->seq;
    s->k3_result = k->result;
}

bool field_learning_feedback_offer(field_learning_feedback_t *f, uint8_t result) {
    if (f->pending || f->token == UINT32_MAX || result < FIELD_LEARN_DONE || result > FIELD_LEARN_NO_SENSOR) return false;
    ++f->token;
    f->result = result;
    f->pending = true;
    f->visible_until_ms = 0;
    return true;
}
void field_learning_feedback_shown(field_learning_feedback_t *f, uint32_t token, uint64_t now) {
    if (f->pending && token == f->token && f->visible_until_ms == 0) f->visible_until_ms = now + 3000;
}
void field_learning_feedback_tick(field_learning_feedback_t *f, uint64_t now) {
    if (f->pending && f->visible_until_ms != 0 && now >= f->visible_until_ms) {
        f->pending = false;
        f->result = FIELD_LEARN_IDLE;
        f->visible_until_ms = 0;
    }
}
field_feedback_t field_feedback_select(const field_learning_feedback_t *f, const field_k3_t *k,
                                       uint8_t learning_state, uint64_t now) {
    // Retained completion temporarily outranks K3, then its animation resumes.
    if (f->pending && (f->visible_until_ms == 0 || now < f->visible_until_ms)) {
        if (f->result == FIELD_LEARN_DONE) return FIELD_FEEDBACK_LEARN_DONE;
        if (f->result == FIELD_LEARN_FAILED) return FIELD_FEEDBACK_LEARN_FAILED;
        if (f->result == FIELD_LEARN_NO_SENSOR) return FIELD_FEEDBACK_NO_SENSOR;
    }
    if (k->pending) return FIELD_FEEDBACK_SENDING;
    if (now < k->feedback_until_ms) {
        if (k->result == FIELD_K3_CONFIRMED) return FIELD_FEEDBACK_CONFIRMED;
        if (k->result == FIELD_K3_NOT_SENT) return FIELD_FEEDBACK_NOT_SENT;
        if (k->result == FIELD_K3_UNCONFIRMED) return FIELD_FEEDBACK_UNCONFIRMED;
    }
    return learning_state == FIELD_LEARN_RUNNING ? FIELD_FEEDBACK_LEARNING : FIELD_FEEDBACK_NONE;
}

bool field_snapshot_due(const field_snapshot_send_t *t, const field_presence_snapshot_t *s, uint64_t now) {
    if (t->operation != 0 || t->seq == UINT32_MAX || now < t->next_try_ms) return false;
    const field_presence_snapshot_t *a = &t->last;
    const bool changed = !t->have_last || a->presence != s->presence || a->learning != s->learning ||
        a->flags != s->flags || a->fault_bits != s->fault_bits || a->learn_request != s->learn_request ||
        a->k3_seq != s->k3_seq || a->k3_result != s->k3_result;
    return changed || now >= t->refresh_ms;
}
void field_snapshot_attempt(field_snapshot_send_t *t, const field_presence_snapshot_t *s, uint64_t now, uint64_t op) {
    t->next_try_ms = now + 1000;
    if (op == 0) return;
    t->seq = s->seq;
    t->last = *s;
    t->have_last = true;
    t->operation = op;
    t->operation_until_ms = now + 30000;
    t->refresh_ms = now + 10000;
}
