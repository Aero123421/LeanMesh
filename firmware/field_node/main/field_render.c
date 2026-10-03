/* The 64 x 32 field panel as an RGB565 frame; see field_render.h. */
#include "field_render.h"

#include <stdio.h>
#include <string.h>

/* 16x16 glyphs of the five characters 使 用 可 禁 止, one uint16 per row, bit 15 = leftmost pixel.
   Source: the Shinonome 16 dot font (kanjic.bit) of the Electronic Font Open Laboratory (efont), public domain
   (their LICENSE: "all font data ... are provided as Public Domain"). The rows were taken unchanged from the generated
   Shinonome 16x16 pack of the owner's KGuard repository (firmware/pico-hub75/src/fonts_hybrid.hpp). */
typedef struct {
    uint16_t rows[16];
} glyph16_t;

static const glyph16_t k_shi = {{0x0420, 0x0420, 0x07FF, 0x0820, 0x0820, 0x13FE, 0x1222, 0x3222, 0x5222, 0x13FE, 0x10A0,
                                 0x1040, 0x1060, 0x1090, 0x130C, 0x1C03}}; /* U+4F7F 使 */
static const glyph16_t k_you = {{0x0000, 0x1FFC, 0x1084, 0x1084, 0x1084, 0x1FFC, 0x1084, 0x1084, 0x1084, 0x1FFC, 0x1084,
                                 0x1084, 0x1084, 0x2084, 0x2084, 0x408C}}; /* U+7528 用 */
static const glyph16_t k_ka = {{0x0000, 0x0000, 0x7FFF, 0x0008, 0x0008, 0x0FC8, 0x0848, 0x0848, 0x0848, 0x0848, 0x0FC8,
                                0x0008, 0x0008, 0x0008, 0x0008, 0x0018}}; /* U+53EF 可 */
static const glyph16_t k_kin = {{0x0410, 0x0410, 0x7FFF, 0x0C38, 0x0E34, 0x1554, 0x2492, 0x4411, 0x0FF8, 0x0000, 0x7FFF,
                                 0x0080, 0x04B0, 0x188C, 0x6082, 0x0180}}; /* U+7981 禁 */
static const glyph16_t k_shi2 = {{0x0080, 0x0080, 0x0080, 0x0080, 0x0880, 0x0880, 0x08FC, 0x0880, 0x0880, 0x0880, 0x0880,
                                  0x0880, 0x0880, 0x0880, 0x7FFF, 0x0000}}; /* U+6B62 止 */

/* 5x7 status font, written for this kit: five column bytes per character, bit 0 = top row. */
typedef struct {
    char c;
    uint8_t col[5];
} font5x7_t;

static const font5x7_t k_font[] = {
    {'0', {0x3E, 0x51, 0x49, 0x45, 0x3E}}, {'1', {0x00, 0x42, 0x7F, 0x40, 0x00}}, {'2', {0x42, 0x61, 0x51, 0x49, 0x46}},
    {'3', {0x21, 0x41, 0x45, 0x4B, 0x31}}, {'4', {0x18, 0x14, 0x12, 0x7F, 0x10}}, {'5', {0x27, 0x45, 0x45, 0x45, 0x39}},
    {'6', {0x3C, 0x4A, 0x49, 0x49, 0x30}}, {'7', {0x01, 0x71, 0x09, 0x05, 0x03}}, {'8', {0x36, 0x49, 0x49, 0x49, 0x36}},
    {'9', {0x06, 0x49, 0x49, 0x29, 0x1E}}, {'-', {0x08, 0x08, 0x08, 0x08, 0x08}}, {'?', {0x02, 0x01, 0x51, 0x09, 0x06}},
    {'A', {0x7E, 0x11, 0x11, 0x11, 0x7E}}, {'B', {0x7F, 0x49, 0x49, 0x49, 0x36}}, {'C', {0x3E, 0x41, 0x41, 0x41, 0x22}},
    {'D', {0x7F, 0x41, 0x41, 0x22, 0x1C}}, {'E', {0x7F, 0x49, 0x49, 0x49, 0x41}}, {'F', {0x7F, 0x09, 0x09, 0x09, 0x01}},
    {'G', {0x3E, 0x41, 0x41, 0x51, 0x32}}, {'H', {0x7F, 0x08, 0x08, 0x08, 0x7F}}, {'I', {0x00, 0x41, 0x7F, 0x41, 0x00}},
    {'J', {0x20, 0x40, 0x41, 0x3F, 0x01}}, {'K', {0x7F, 0x08, 0x14, 0x22, 0x41}}, {'L', {0x7F, 0x40, 0x40, 0x40, 0x40}},
    {'M', {0x7F, 0x02, 0x0C, 0x02, 0x7F}}, {'N', {0x7F, 0x04, 0x08, 0x10, 0x7F}}, {'O', {0x3E, 0x41, 0x41, 0x41, 0x3E}},
    {'P', {0x7F, 0x09, 0x09, 0x09, 0x06}}, {'Q', {0x3E, 0x41, 0x51, 0x21, 0x5E}}, {'R', {0x7F, 0x09, 0x19, 0x29, 0x46}},
    {'S', {0x46, 0x49, 0x49, 0x49, 0x31}}, {'T', {0x01, 0x01, 0x7F, 0x01, 0x01}}, {'U', {0x3F, 0x40, 0x40, 0x40, 0x3F}},
    {'V', {0x1F, 0x20, 0x40, 0x20, 0x1F}}, {'W', {0x3F, 0x40, 0x38, 0x40, 0x3F}}, {'X', {0x63, 0x14, 0x08, 0x14, 0x63}},
    {'Y', {0x03, 0x04, 0x78, 0x04, 0x03}}, {'Z', {0x61, 0x51, 0x49, 0x45, 0x43}},
};

#define FONT_ADVANCE 6 /* 5 columns and one blank */

static void put(uint16_t frame[FIELD_PANEL_H][FIELD_PANEL_W], int x, int y, uint16_t colour) {
    if (x >= 0 && x < FIELD_PANEL_W && y >= 0 && y < FIELD_PANEL_H) {
        frame[y][x] = colour;
    }
}

static void draw_char(uint16_t frame[FIELD_PANEL_H][FIELD_PANEL_W], int x, int y, char c, uint16_t colour) {
    for (size_t i = 0; i < sizeof k_font / sizeof k_font[0]; ++i) {
        if (k_font[i].c != c) {
            continue;
        }
        for (int col = 0; col < 5; ++col) {
            for (int row = 0; row < 7; ++row) {
                if ((k_font[i].col[col] >> row) & 1u) {
                    put(frame, x + col, y + row, colour);
                }
            }
        }
        return; /* a space or an unknown character stays blank */
    }
}

static void draw_glyph(uint16_t frame[FIELD_PANEL_H][FIELD_PANEL_W], int x, int y, const glyph16_t *g, uint16_t colour) {
    for (int row = 0; row < 16; ++row) {
        for (int col = 0; col < 16; ++col) {
            if ((g->rows[row] >> (15 - col)) & 1u) {
                put(frame, x + col, y + row, colour);
            }
        }
    }
}

void field_status_text(const field_view_t *v, char out[12]) {
    switch (v->link) {
    case FIELD_LINK_JOINING:
        snprintf(out, 12, "JOIN");
        break;
    case FIELD_LINK_LOST:
        snprintf(out, 12, "LOST");
        break;
    case FIELD_LINK_REVOKED:
        snprintf(out, 12, "REVOKED");
        break;
    default: {
        char depth[4] = "?";
        char rssi[6] = "--";
        if (v->root_depth != 0xFFu) {
            snprintf(depth, sizeof depth, "%u", (unsigned)v->root_depth);
        }
        if (v->parent_rssi_dbm != -128) {
            snprintf(rssi, sizeof rssi, "%d", (int)v->parent_rssi_dbm);
        }
        snprintf(out, 12, "H%s %s", depth, rssi);
        break;
    }
    }
}

void field_render(const field_view_t *v, uint16_t frame[FIELD_PANEL_H][FIELD_PANEL_W]) {
    memset(frame, 0, sizeof(uint16_t) * FIELD_PANEL_H * FIELD_PANEL_W);

    char text[12];
    field_status_text(v, text);
    const int chars = (int)strlen(text);
    const int x0 = (FIELD_PANEL_W - (chars * FONT_ADVANCE - 1)) / 2;
    for (int i = 0; i < chars; ++i) {
        draw_char(frame, x0 + i * FONT_ADVANCE, 0, text[i], FIELD_RGB565_WHITE); /* rows 0..6 of the 0..7 band */
    }

    if (v->state_valid) {
        static const glyph16_t *const k_usable[] = {&k_shi, &k_you, &k_ka};
        static const glyph16_t *const k_forbid[] = {&k_shi, &k_you, &k_kin, &k_shi2};
        const glyph16_t *const *g = v->forbid ? k_forbid : k_usable;
        const int n = v->forbid ? 4 : 3;
        const uint16_t colour = v->forbid ? FIELD_RGB565_RED : FIELD_RGB565_GREEN;
        const int gx = (FIELD_PANEL_W - 16 * n) / 2;
        for (int i = 0; i < n; ++i) {
            draw_glyph(frame, gx + 16 * i, 8, g[i], colour);
        }
    }

    const uint16_t bar = v->link == FIELD_LINK_REACHABLE ? FIELD_RGB565_GREEN
                         : v->link == FIELD_LINK_JOINING ? FIELD_RGB565_YELLOW
                                                         : FIELD_RGB565_BLUE;
    for (int y = 30; y < 32; ++y) {
        for (int x = 0; x < FIELD_PANEL_W; ++x) {
            frame[y][x] = bar;
        }
    }
}
