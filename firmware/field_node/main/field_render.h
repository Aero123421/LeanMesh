#ifndef FIELD_RENDER_H
#define FIELD_RENDER_H
/* The 64 x 32 panel of the field test kit (docs/field/protocol.md section 4), drawn into an RGB565 frame. Pure code:
   no ESP-IDF, no panel driver; the HUB75 display copies the frame to the panel (tests/native/test_field.cpp checks it). */
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FIELD_PANEL_W 64
#define FIELD_PANEL_H 32

#define FIELD_RGB565_BLACK 0x0000u
#define FIELD_RGB565_WHITE 0xFFFFu
#define FIELD_RGB565_GREEN 0x07E0u
#define FIELD_RGB565_RED 0xF800u
#define FIELD_RGB565_BLUE 0x001Fu
#define FIELD_RGB565_YELLOW 0xFFE0u

typedef enum {
    FIELD_LINK_JOINING,   /* not an ACTIVE member yet (or asking again): "JOIN", yellow bar */
    FIELD_LINK_REACHABLE, /* a path to the root: "H<depth> <rssi>", green bar */
    FIELD_LINK_LOST,      /* a member without a path: "LOST", blue bar */
    FIELD_LINK_REVOKED,   /* revoked / quarantined: the node stops asking: "REVOKED", blue bar */
} field_link_t;

typedef struct {
    field_link_t link;
    uint8_t root_depth; /* 0xFF unknown */
    int8_t parent_rssi_dbm; /* -128 unknown */
    bool state_valid;   /* a display state is known; else the main area stays blank */
    bool forbid;        /* FORBID (red, 使用禁止) else USABLE (green, 使用可) */
} field_view_t;

/* The status line text (at most 11 characters plus NUL): "H2 -67", "H2 --", "JOIN", "LOST", "REVOKED". */
void field_status_text(const field_view_t *v, char out[12]);
/* Draws the whole panel: rows 0..7 status line (5x7 font, white), rows 8..23 the state in 16x16 glyphs centred
   (green / red), rows 30..31 the status bar. Everything else stays black. */
void field_render(const field_view_t *v, uint16_t frame[FIELD_PANEL_H][FIELD_PANEL_W]);

#ifdef __cplusplus
}
#endif
#endif
