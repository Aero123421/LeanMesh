#ifndef BENCH_LINE_H
#define BENCH_LINE_H
/* BENCH / HIL ONLY: the byte-to-line assembly of the bench console, without ESP-IDF (tests/native/test_field.cpp builds it
   natively). One line ends at CR or LF; empty lines are skipped. A line that does not fit is dropped as a whole and
   reported once, at its own CR/LF: its bytes are never cut and run as a shorter command. */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *buf;     /* caller's storage */
    size_t cap;    /* its size: a line is at most cap - 1 bytes */
    size_t len;    /* bytes kept of the line in progress */
    bool overflow; /* the line in progress is longer than cap - 1: the rest of it is discarded */
} bc_line_t;

typedef enum {
    BC_LINE_PENDING,  /* the byte was taken; no line ended */
    BC_LINE_READY,    /* buf holds one NUL-terminated line (not empty); the assembler starts a new line */
    BC_LINE_OVERFLOW  /* a line longer than cap - 1 ended here and was dropped; the assembler starts a new line */
} bc_line_result_t;

void bc_line_init(bc_line_t *l, char *buf, size_t cap);
bc_line_result_t bc_line_feed(bc_line_t *l, uint8_t c);

#ifdef __cplusplus
}
#endif
#endif
