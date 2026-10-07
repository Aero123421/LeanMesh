/* BENCH / HIL ONLY: see include/bench_line.h. */
#include "bench_line.h"

void bc_line_init(bc_line_t *l, char *buf, size_t cap) {
    l->buf = buf;
    l->cap = cap;
    l->len = 0;
    l->overflow = false;
}

bc_line_result_t bc_line_feed(bc_line_t *l, uint8_t c) {
    if (c == '\r' || c == '\n') {
        if (l->overflow) {
            l->overflow = false;
            l->len = 0;
            return BC_LINE_OVERFLOW;
        }
        if (l->len == 0) {
            return BC_LINE_PENDING; /* an empty line, or the second byte of CR LF */
        }
        l->buf[l->len] = '\0';
        l->len = 0;
        return BC_LINE_READY;
    }
    if (l->overflow) {
        return BC_LINE_PENDING;
    }
    if (l->len + 1 < l->cap) {
        l->buf[l->len++] = (char)c;
    } else {
        l->overflow = true; /* the whole line is dropped at its end */
        l->len = 0;
    }
    return BC_LINE_PENDING;
}
