// Field test kit (firmware/field_node): the pure rules, built natively. Wire layouts against docs/field/protocol.md
// section 3, the join backoff, and the panel frame of section 4. The firmware around them (join, telemetry timing,
// panel driver) needs a board: nothing here measures a device.
#include <array>
#include <cstring>
#include <string>

#include "core/diag/diag.hpp"
#include "lmtest.hpp"

extern "C" {
#include "bench_line.h"
#include "field_proto.h"
#include "field_render.h"
}

namespace {

// The validity bits the firmware names locally must be the SDK's own (api/leanmesh.h does not name them).
static_assert(FIELD_DIAG_VALID_RESET_REASON == lm::diag::valid::reset_reason);
static_assert(FIELD_DIAG_VALID_HEAP == lm::diag::valid::heap);
static_assert(FIELD_DIAG_VALID_COUNTERS == lm::diag::valid::counters);

field_telemetry_t sample() {
    field_telemetry_t t{};
    t.role = FIELD_ROLE_DISPLAY;
    t.chip = FIELD_CHIP_ESP32S3;
    t.flags = FIELD_FLAG_DISPLAY_VALID | FIELD_FLAG_DISPLAY_FORBID;
    t.seq = 0x01020304;
    t.uptime_s = 0x05060708;
    t.boot_count = 0x090A;
    t.reset_reason = 0x0B;
    t.root_depth = 2;
    t.parent_rssi_dbm = -67;
    t.interval_s = 10;
    t.tx_frames = 0x11121314;
    t.rx_frames = 0x21222324;
    t.rf_failures = 0x31323334;
    t.local_busy = 0x41424344;
    t.min_heap_bytes = 0x51525354;
    t.display_seq = 0x61626364;
    return t;
}

using Frame = uint16_t[FIELD_PANEL_H][FIELD_PANEL_W];

field_view_t view(field_link_t link, bool valid = false, bool forbid = false) {
    field_view_t v{};
    v.link = link;
    v.root_depth = 2;
    v.parent_rssi_dbm = -67;
    v.state_valid = valid;
    v.forbid = forbid;
    return v;
}

int count_colour(const Frame &f, int y0, int y1, uint16_t colour) {
    int n = 0;
    for (int y = y0; y <= y1; ++y) {
        for (int x = 0; x < FIELD_PANEL_W; ++x) {
            n += f[y][x] == colour ? 1 : 0;
        }
    }
    return n;
}

int count_other(const Frame &f, int y0, int y1, uint16_t colour) {
    int n = 0;
    for (int y = y0; y <= y1; ++y) {
        for (int x = 0; x < FIELD_PANEL_W; ++x) {
            n += (f[y][x] != FIELD_RGB565_BLACK && f[y][x] != colour) ? 1 : 0;
        }
    }
    return n;
}

// One row of a 16x16 glyph area as text, to see what was drawn when a check fails.
std::string ascii(const Frame &f, int y0, int y1, int x0, int x1) {
    std::string s;
    for (int y = y0; y <= y1; ++y) {
        for (int x = x0; x <= x1; ++x) {
            s += f[y][x] != 0 ? '#' : '.';
        }
        s += '\n';
    }
    return s;
}

} // namespace

LM_TEST("FIELD telemetry encodes the 44 bytes of protocol 3.1 big-endian") {
    const field_telemetry_t t = sample();
    uint8_t w[FIELD_TELEMETRY_BYTES];
    std::memset(w, 0xEE, sizeof w);
    field_telemetry_encode(&t, w);
    const std::array<uint8_t, 44> want = {
        1,    // version
        3,    // role display
        1,    // chip esp32s3
        3,    // flags: display valid, FORBID
        0x01, 0x02, 0x03, 0x04,       // seq
        0x05, 0x06, 0x07, 0x08,       // uptime_s
        0x09, 0x0A,                   // boot_count
        0x0B,                         // reset reason
        2,                            // root_depth
        0xBD,                         // parent RSSI -67
        0,                            // reserved
        0, 10,                        // interval
        0x11, 0x12, 0x13, 0x14,       // tx
        0x21, 0x22, 0x23, 0x24,       // rx
        0x31, 0x32, 0x33, 0x34,       // rf failures
        0x41, 0x42, 0x43, 0x44,       // local busy
        0x51, 0x52, 0x53, 0x54,       // min heap
        0x61, 0x62, 0x63, 0x64};      // display seq
    LM_CHECK(std::memcmp(w, want.data(), want.size()) == 0);
    static_assert(FIELD_TELEMETRY_BYTES == 44);
}

LM_TEST("FIELD telemetry decode inverts encode and refuses another length or version") {
    const field_telemetry_t t = sample();
    uint8_t w[FIELD_TELEMETRY_BYTES];
    field_telemetry_encode(&t, w);
    field_telemetry_t back{};
    LM_CHECK(field_telemetry_decode(w, sizeof w, &back));
    LM_CHECK(std::memcmp(&back, &t, sizeof t) == 0);
    LM_CHECK(!field_telemetry_decode(w, sizeof w - 1, &back));
    w[0] = 2;
    LM_CHECK(!field_telemetry_decode(w, sizeof w, &back));
}

LM_TEST("FIELD an invalid diagnostics value is unknown, never zero") {
    LM_CHECK_EQ(field_counter32(0x1'0000'0007ull, true), 7u); // low 32 bits
    LM_CHECK_EQ(field_counter32(5, false), 0xFFFFFFFFu);
    LM_CHECK_EQ(field_rssi8(-67, true), -67);
    LM_CHECK_EQ(field_rssi8(-67, false), -128);
    LM_CHECK_EQ(field_rssi8(-300, true), -127);
    LM_CHECK_EQ(field_rssi8(300, true), 127);
    LM_CHECK_EQ(field_depth8(3, true), 3u);
    LM_CHECK_EQ(field_depth8(3, false), 0xFFu);
    LM_CHECK_EQ(field_reset_reason8(4, true), 4u);
    LM_CHECK_EQ(field_reset_reason8(4, false), 0xFFu);
    LM_CHECK_EQ(field_reset_reason8(0x1234, true), 0xFFu);
}

LM_TEST("FIELD ping payload: version 1 and a u32 round, nothing else") {
    uint32_t round = 0;
    const uint8_t ok[] = {1, 0x00, 0x00, 0x01, 0x02};
    LM_CHECK(field_ping_decode(ok, sizeof ok, &round));
    LM_CHECK_EQ(round, 0x102u);
    const uint8_t v2[] = {2, 0, 0, 0, 1};
    LM_CHECK(!field_ping_decode(v2, sizeof v2, &round));
    LM_CHECK(!field_ping_decode(ok, 4, &round));
    LM_CHECK(!field_ping_decode(ok, 6, &round));
    LM_CHECK(!field_ping_decode(nullptr, 0, &round));
}

LM_TEST("FIELD display payload: version 1, state 0/1, u32 command_seq") {
    field_display_cmd_t c{};
    const uint8_t forbid[] = {1, 1, 0xDE, 0xAD, 0xBE, 0xEF};
    LM_CHECK(field_display_decode(forbid, sizeof forbid, &c));
    LM_CHECK_EQ(c.state, static_cast<uint8_t>(FIELD_DISPLAY_FORBID));
    LM_CHECK_EQ(c.seq, 0xDEADBEEFu);
    const uint8_t usable[] = {1, 0, 0, 0, 0, 9};
    LM_CHECK(field_display_decode(usable, sizeof usable, &c));
    LM_CHECK_EQ(c.state, static_cast<uint8_t>(FIELD_DISPLAY_USABLE));
    LM_CHECK_EQ(c.seq, 9u);
    const uint8_t bad_state[] = {1, 2, 0, 0, 0, 1};
    LM_CHECK(!field_display_decode(bad_state, sizeof bad_state, &c));
    const uint8_t v9[] = {9, 0, 0, 0, 0, 1};
    LM_CHECK(!field_display_decode(v9, sizeof v9, &c));
    LM_CHECK(!field_display_decode(usable, 5, &c));
    LM_CHECK(!field_display_decode(usable, 7, &c));
}

LM_TEST("FIELD join backoff is 2, 4, 8, 15, 20, 20 ... seconds") {
    const unsigned want[] = {2, 4, 8, 15, 20, 20, 20};
    for (unsigned i = 0; i < sizeof want / sizeof want[0]; ++i) {
        LM_CHECK_EQ(field_join_backoff_s(i), want[i]);
    }
    LM_CHECK_EQ(field_join_backoff_s(1000), 20u);
}

LM_TEST("FIELD telemetry delay is 10 s plus 0..1000 ms") {
    LM_CHECK_EQ(field_telemetry_delay_ms(0), 10000u);
    LM_CHECK_EQ(field_telemetry_delay_ms(1000), 11000u);
    LM_CHECK_EQ(field_telemetry_delay_ms(1001), 10000u);
    for (uint32_t r = 0; r < 5000; r += 7) {
        const uint32_t d = field_telemetry_delay_ms(r);
        LM_CHECK(d >= 10000u && d <= 11000u);
    }
}

LM_TEST("FIELD status line text") {
    char s[12];
    field_view_t v = view(FIELD_LINK_REACHABLE);
    field_status_text(&v, s);
    LM_CHECK(std::string(s) == "H2 -67");
    v.parent_rssi_dbm = -128;
    field_status_text(&v, s);
    LM_CHECK(std::string(s) == "H2 --");
    v.root_depth = 0xFF;
    field_status_text(&v, s);
    LM_CHECK(std::string(s) == "H? --");
    v = view(FIELD_LINK_JOINING);
    field_status_text(&v, s);
    LM_CHECK(std::string(s) == "JOIN");
    v = view(FIELD_LINK_LOST);
    field_status_text(&v, s);
    LM_CHECK(std::string(s) == "LOST");
    v = view(FIELD_LINK_REVOKED);
    field_status_text(&v, s);
    LM_CHECK(std::string(s) == "REVOKED");
}

LM_TEST("FIELD panel: status bar colours per link state") {
    static Frame f;
    const struct {
        field_link_t link;
        uint16_t colour;
    } cases[] = {{FIELD_LINK_REACHABLE, FIELD_RGB565_GREEN},
                 {FIELD_LINK_JOINING, FIELD_RGB565_YELLOW},
                 {FIELD_LINK_LOST, FIELD_RGB565_BLUE},
                 {FIELD_LINK_REVOKED, FIELD_RGB565_BLUE}};
    for (const auto &c : cases) {
        const field_view_t v = view(c.link);
        field_render(&v, f);
        LM_CHECK_EQ(count_colour(f, 30, 31, c.colour), 2 * FIELD_PANEL_W);
        LM_CHECK_EQ(count_colour(f, 24, 29, FIELD_RGB565_BLACK), 6 * FIELD_PANEL_W); // the gap stays black
    }
}

LM_TEST("FIELD panel: no display state leaves rows 8..23 blank") {
    static Frame f;
    const field_view_t v = view(FIELD_LINK_REACHABLE, false);
    field_render(&v, f);
    LM_CHECK_EQ(count_colour(f, 8, 23, FIELD_RGB565_BLACK), 16 * FIELD_PANEL_W);
}

LM_TEST("FIELD panel: USABLE is green, FORBID is red, both inside rows 8..23") {
    static Frame usable, forbid;
    field_view_t v = view(FIELD_LINK_REACHABLE, true, false);
    field_render(&v, usable);
    v.forbid = true;
    field_render(&v, forbid);
    const int green = count_colour(usable, 8, 23, FIELD_RGB565_GREEN);
    const int red = count_colour(forbid, 8, 23, FIELD_RGB565_RED);
    LM_CHECK(green > 40);
    LM_CHECK(red > 60);
    LM_CHECK_EQ(count_other(usable, 8, 23, FIELD_RGB565_GREEN), 0);
    LM_CHECK_EQ(count_other(forbid, 8, 23, FIELD_RGB565_RED), 0);
    // USABLE is 3 glyphs = 48 px, centred: columns 0..7 and 56..63 are empty. FORBID is 4 glyphs = the whole width.
    int usable_edge = 0, forbid_edge = 0;
    for (int y = 8; y <= 23; ++y) {
        for (int x = 0; x < 8; ++x) {
            usable_edge += usable[y][x] != 0 || usable[y][63 - x] != 0 ? 1 : 0;
        }
        forbid_edge += forbid[y][0] != 0 || forbid[y][2] != 0 || forbid[y][63] != 0 ? 1 : 0;
    }
    LM_CHECK_EQ(usable_edge, 0);
    LM_CHECK(forbid_edge > 0);
    // The glyphs differ (使用可 vs 使用禁止): the third glyph of FORBID is not the third of USABLE.
    LM_CHECK(std::memcmp(usable[10] + 24, forbid[10] + 32, 16 * sizeof(uint16_t)) != 0);
}

LM_TEST("FIELD panel: the status line is white, in rows 0..7, and the glyph 使 is the Shinonome shape") {
    static Frame f;
    const field_view_t v = view(FIELD_LINK_REACHABLE, true, false);
    field_render(&v, f);
    LM_CHECK(count_colour(f, 0, 7, FIELD_RGB565_WHITE) > 20);
    LM_CHECK_EQ(count_other(f, 0, 7, FIELD_RGB565_WHITE), 0);
    LM_CHECK_EQ(count_colour(f, 7, 7, FIELD_RGB565_BLACK), FIELD_PANEL_W); // row 7 is the gap under a 7-row font
    // 使 starts at x = 8 (three glyphs centred), y = 8: its first row is 0x0420 = bits 10 and 5 -> columns 5 and 10.
    int first_row_pixels = 0;
    for (int x = 8; x < 24; ++x) {
        first_row_pixels += f[8][x] != 0 ? 1 : 0;
    }
    LM_CHECK_EQ(first_row_pixels, 2);
    LM_CHECK(f[8][8 + 5] != 0 && f[8][8 + 10] != 0);
    LM_CHECK(!ascii(f, 8, 23, 8, 23).empty());
}

LM_TEST("FIELD message action: pings are counted and never answered with an application result, display goes to the panel") {
    const uint8_t ping[5] = {1, 0, 0, 0, 7};
    const uint8_t v2[5] = {2, 0, 0, 0, 7};
    const uint8_t disp[6] = {1, 1, 0, 0, 0, 9};
    LM_CHECK_EQ(field_message_action(FIELD_PORT_PING, ping, sizeof ping), FIELD_ACT_PING_OK);
    LM_CHECK_EQ(field_message_action(FIELD_PORT_PING, v2, sizeof v2), FIELD_ACT_PING_UNKNOWN);   // counted apart, no result either
    LM_CHECK_EQ(field_message_action(FIELD_PORT_PING, ping, 4), FIELD_ACT_PING_UNKNOWN);
    LM_CHECK_EQ(field_message_action(FIELD_PORT_PING, nullptr, 0), FIELD_ACT_PING_UNKNOWN);
    LM_CHECK_EQ(field_message_action(FIELD_PORT_DISPLAY, disp, sizeof disp), FIELD_ACT_DISPLAY);
    LM_CHECK_EQ(field_message_action(FIELD_PORT_DISPLAY, ping, sizeof ping), FIELD_ACT_DISPLAY);  // the display path rejects what it cannot read
    LM_CHECK_EQ(field_message_action(FIELD_PORT_TELEMETRY, ping, sizeof ping), FIELD_ACT_IGNORE);
    LM_CHECK_EQ(field_message_action(0, ping, sizeof ping), FIELD_ACT_IGNORE);
}

// ---- bench console line assembly (firmware/common/bench_console/bench_line.c) ----

struct LineFeed {
    char buf[8];
    bc_line_t l;
    LineFeed() { bc_line_init(&l, buf, sizeof buf); }
    // Feeds the text; returns the results other than PENDING, in order, as 'R' (ready, with the line appended) / 'O' (overflow).
    std::string feed(const std::string &text) {
        std::string out;
        for (char c : text) {
            const bc_line_result_t r = bc_line_feed(&l, static_cast<uint8_t>(c));
            if (r == BC_LINE_READY) {
                out += std::string("R[") + buf + "]";
            } else if (r == BC_LINE_OVERFLOW) {
                out += "O";
            }
        }
        return out;
    }
};

LM_TEST("FIELD console line: CR, LF and CR LF end a line, empty lines are skipped") {
    LineFeed f;
    LM_CHECK(f.feed("info\n") == std::string("R[info]"));
    LM_CHECK(f.feed("a\r\nb\r") == std::string("R[a]R[b]"));
    LM_CHECK(f.feed("\n\r\n\n") == std::string(""));
}

LM_TEST("FIELD console line: a partial line is kept between calls (the bytes arrive over several reads)") {
    LineFeed f;
    LM_CHECK(f.feed("sta") == std::string(""));
    LM_CHECK(f.feed("tus") == std::string(""));
    LM_CHECK(f.feed("\n") == std::string("R[status]"));
}

LM_TEST("FIELD console line: a line that does not fit is dropped whole and answered once at its newline") {
    LineFeed f; // 8-byte buffer: a line holds at most 7 bytes
    LM_CHECK(f.feed("1234567\n") == std::string("R[1234567]"));   // exactly full is a line
    LM_CHECK(f.feed("12345678\n") == std::string("O"));            // one byte more: dropped, never run as "1234567"
    LM_CHECK(f.feed("info\n") == std::string("R[info]"));          // the next line is clean
    // Endless input without a newline keeps the buffer bounded and produces no line and no answer until the newline.
    std::string flood(100000, 'x');
    LM_CHECK(f.feed(flood) == std::string(""));
    LM_CHECK(f.l.len < sizeof f.buf);
    LM_CHECK(f.feed("\r\n") == std::string("O"));                  // CR LF answers once
    LM_CHECK(f.feed("ok\n") == std::string("R[ok]"));
}

LM_TEST("FIELD console line: the tail of a dropped line is not a command") {
    LineFeed f;
    LM_CHECK(f.feed("keygenXXXXXXXXXXXX\nkeygen\n") == std::string("OR[keygen]"));
}

LM_TEST_MAIN()


// ---- node event log (docs/field/protocol.md section 3.4) ----

LM_TEST("FIELD log: records encode as type, len, seq, t_ms, payload after version and count") {
    field_log_t log;
    field_log_init(&log);
    const uint8_t rch[2] = {2, static_cast<uint8_t>(-61)};
    field_log_add(&log, FIELD_LOG_MEMBER, 1234, nullptr, 0);
    field_log_add(&log, FIELD_LOG_REACHABLE, 0x01020304, rch, 2);
    uint8_t out[FIELD_LOG_MESSAGE_MAX];
    unsigned taken = 0;
    const size_t n = field_log_encode(&log, 5000, out, sizeof out, &taken);
    LM_CHECK_EQ(n, 2u + 8u + 10u);
    LM_CHECK_EQ(taken, 2u);
    const uint8_t want[] = {1, 2,                                          // version, count
                            FIELD_LOG_MEMBER, 0, 0, 1, 0, 0, 0x04, 0xD2,     // seq 1, t 1234
                            FIELD_LOG_REACHABLE, 2, 0, 2, 1, 2, 3, 4, 2, static_cast<uint8_t>(-61)};
    LM_CHECK(std::memcmp(out, want, sizeof want) == 0);
    field_log_consume(&log, taken);
    LM_CHECK_EQ(field_log_encode(&log, 5000, out, sizeof out, &taken), 0u); // nothing left
    field_log_add(&log, FIELD_LOG_TIME_VALID, 9, nullptr, 0);
    LM_CHECK_EQ(field_log_encode(&log, 5000, out, sizeof out, &taken), 10u);
    LM_CHECK_EQ(out[4], 0); // seq 3 continues after a consumed message
    LM_CHECK_EQ(out[5], 3);
}

LM_TEST("FIELD log: a full ring drops the oldest and the next message starts with LOG_LOST") {
    field_log_t log;
    field_log_init(&log);
    for (unsigned i = 0; i < FIELD_LOG_RING + 3; ++i) {
        field_log_add(&log, FIELD_LOG_DEPTH, i, nullptr, 0);
    }
    LM_CHECK_EQ(log.count, FIELD_LOG_RING);
    LM_CHECK_EQ(log.dropped, 3u);
    uint8_t out[FIELD_LOG_MESSAGE_MAX];
    unsigned taken = 0;
    const size_t n = field_log_encode(&log, 77, out, sizeof out, &taken);
    LM_CHECK(n <= FIELD_LOG_MESSAGE_MAX);
    LM_CHECK_EQ(out[2], FIELD_LOG_LOST);
    LM_CHECK_EQ(out[3], 2);           // len
    LM_CHECK_EQ(out[4] | out[5], 0);  // seq 0: not part of the record stream
    LM_CHECK_EQ(out[10], 0);          // records dropped, big-endian
    LM_CHECK_EQ(out[11], 3);
    LM_CHECK_EQ(out[12], FIELD_LOG_DEPTH);
    LM_CHECK_EQ(out[15], 4);          // the oldest kept record is seq 4
    LM_CHECK_EQ(out[1], taken + 1);   // count includes LOG_LOST
    const unsigned left = log.count - taken;
    field_log_consume(&log, taken);
    LM_CHECK_EQ(log.dropped, 0u);
    LM_CHECK_EQ(log.count, left);     // what did not fit stays for the next message
}

LM_TEST("FIELD log: a message never exceeds 160 bytes and keeps whole records") {
    field_log_t log;
    field_log_init(&log);
    uint8_t boot[12] = {};
    for (unsigned i = 0; i < 20; ++i) {
        field_log_add(&log, FIELD_LOG_BOOT, i, boot, sizeof boot);
    }
    uint8_t out[400];
    unsigned taken = 0;
    const size_t n = field_log_encode(&log, 0, out, sizeof out, &taken);
    LM_CHECK(n <= FIELD_LOG_MESSAGE_MAX);
    LM_CHECK_EQ(n, 2u + taken * 20u); // 8-byte head + 12-byte payload each
    LM_CHECK_EQ(out[1], taken);
}
