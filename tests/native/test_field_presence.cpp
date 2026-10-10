// Application behavior, not electrical/optical/RF or physical LED evidence.
#include "lmtest.hpp"
#include "field_presence.h"
#include "field_control.h"
#include "field_render.h"
#include <cstring>
#include <cstdio>
#include <kguard_field/presence_v2.hpp>

LM_TEST("FIELD presence wire fixed offsets and structural rejection") {
    field_presence_snapshot_t s{};
    s.presence = FIELD_PRESENCE_UNKNOWN;
    s.boot_id = UINT64_C(0x0102030405060708);
    s.seq = 9;
    s.capture_ms = 10;
    s.sample_age_ms = s.distance_mm = s.background_mm = UINT16_MAX;
    uint8_t w[44];
    LM_CHECK(field_presence_encode(&s, w));
    LM_CHECK(w[0] == 1 && w[1] == 1 && w[4] == 1 && w[11] == 8 && w[15] == 9);
    LM_CHECK(w[20] == 255 && w[21] == 255 && w[41] == 0 && w[43] == 0);
    field_presence_snapshot_t out{};
    LM_CHECK(field_presence_decode(w, sizeof w, &out));
    LM_CHECK(out.boot_id == s.boot_id && out.capture_ms == 10);
    w[41] = 1;
    LM_CHECK(!field_presence_decode(w, sizeof w, &out));
    w[41] = 0; w[3] = 8;
    LM_CHECK(!field_presence_decode(w, sizeof w, &out));
    s.seq = 0;
    LM_CHECK(!field_presence_encode(&s, w));
    s.seq = 1;
    s.distance_mm = 99;
    LM_CHECK(!field_presence_encode(&s, w));
    s.distance_mm = UINT16_MAX;
    s.noise_mm = 1;
    LM_CHECK(!field_presence_encode(&s, w));
    field_key_notice_t k{s.boot_id, 1, 1234};
    uint8_t n[20];
    LM_CHECK(field_key_encode(&k, n));
    LM_CHECK(n[1] == 3 && n[2] == 0 && n[19] == 0xd2);
    field_key_notice_t decoded{};
    LM_CHECK(field_key_decode(n, sizeof n, &decoded));
    LM_CHECK(decoded.press_ms == 1234);
    n[3] = 1;
    LM_CHECK(!field_key_decode(n, sizeof n, &decoded));
}

LM_TEST("FIELD keys debounce boot hold NACK release and bounded drop newest") {
    field_keys_t keys{};
    field_keys_read(&keys, 0, true, 0xf9); // boot-held both: not actions
    field_keys_read(&keys, 100, true, 0xf9);
    field_key_event_t event{};
    LM_CHECK(!field_keys_pop(&keys, &event));
    field_keys_read(&keys, 120, true, 0xff);
    field_keys_read(&keys, 180, true, 0xff);
    field_keys_read(&keys, 200, true, 0xfd);
    field_keys_read(&keys, 240, false, 0); // NACK must break the debounce evidence
    field_keys_read(&keys, 250, true, 0xfd);
    field_keys_read(&keys, 299, true, 0xfd);
    LM_CHECK(!field_keys_pop(&keys, &event));
    field_keys_read(&keys, 300, true, 0xfd);
    LM_CHECK(field_keys_pop(&keys, &event));
    LM_CHECK(event.button == 1 && event.at_ms == 300);
    field_keys_read(&keys, 1000, true, 0xfd);
    LM_CHECK(!field_keys_pop(&keys, &event));
    for (unsigned i = 0; i < FIELD_KEY_QUEUE_CAPACITY + 2; ++i) {
        const uint64_t t = 1100 + i * 200;
        field_keys_read(&keys, t, true, 0xff);
        field_keys_read(&keys, t + 50, true, 0xff);
        field_keys_read(&keys, t + 100, true, 0xfb);
        field_keys_read(&keys, t + 150, true, 0xfb);
    }
    LM_CHECK(keys.count == FIELD_KEY_QUEUE_CAPACITY && keys.dropped == 2);
    LM_CHECK(field_keys_config(0xa1) == 0xa7);
    LM_CHECK(field_keys_polarity(0xff) == 0xf9);
}

LM_TEST("FIELD K3 matching END_RECEIVED only finite original press budget") {
    field_k3_t k{};
    LM_CHECK(field_k3_press(&k, 1, 100, 100));
    field_k3_accepted(&k, 42);
    LM_CHECK(!field_k3_press(&k, 2, 200, 200) && k.busy == 1);
    field_k3_observe(&k, 41, true, true, true, 300);
    LM_CHECK(k.result == FIELD_K3_SENDING);
    field_k3_observe(&k, 42, false, true, false, 400); // SENT/accepted, not receipt
    LM_CHECK(k.result == FIELD_K3_SENDING);
    field_k3_observe(&k, 42, false, true, true, 500);
    LM_CHECK(k.result == FIELD_K3_CONFIRMED && k.feedback_until_ms == 3500);
    LM_CHECK(!field_k3_press(&k, 2, 550, 550));
    field_k3_observe(&k, 42, true, true, true, 550);
    LM_CHECK(k.feedback_until_ms == 3500); // repeated evidence doesn't extend animation
    LM_CHECK(!field_k3_press(&k, 2, 200, 580)); // queued while pending: still busy after settlement
    LM_CHECK(field_k3_press(&k, 2, 600, 600));
    field_k3_accepted(&k, 43);
    field_k3_tick(&k, 30600);
    LM_CHECK(k.result == FIELD_K3_UNCONFIRMED && !k.pending);
    LM_CHECK(!field_k3_press(&k, 3, 30650, 30650)); // one SDK op still outstanding
    field_k3_observe(&k, 43, true, false, false, 30700);
    k = {};
    LM_CHECK(field_k3_press(&k, 3, 1000, 31000)); // queue expiry is not extended
    LM_CHECK(k.result == FIELD_K3_NOT_SENT && !k.pending);
    k.seq = UINT32_MAX;
    LM_CHECK(!field_k3_press(&k, 0, 32000, 32000));
}

LM_TEST("FIELD snapshots coalesce sample-only updates rate-limit refusal and refuse sequence wrap") {
    field_snapshot_send_t t{};
    field_presence_snapshot_t s{};
    s.seq = 1;
    s.presence = FIELD_PRESENCE_UNKNOWN;
    LM_CHECK(field_snapshot_due(&t, &s, 0));
    field_snapshot_attempt(&t, &s, 0, 0);
    LM_CHECK(!field_snapshot_due(&t, &s, 999));
    LM_CHECK(field_snapshot_due(&t, &s, 1000));
    field_snapshot_attempt(&t, &s, 1000, 123);
    s.presence = FIELD_PRESENCE_VACANT;
    LM_CHECK(!field_snapshot_due(&t, &s, 10000)); // only one outstanding
    t.operation = 0;
    LM_CHECK(field_snapshot_due(&t, &s, 10000)); // latest meaningful change
    s.seq = 2;
    field_snapshot_attempt(&t, &s, 10000, 124);
    t.operation = 0;
    s.distance_mm = 2200;
    s.sample_age_ms = 40;
    LM_CHECK(!field_snapshot_due(&t, &s, 11000)); // no sample stream
    LM_CHECK(field_snapshot_due(&t, &s, 20000)); // 10 second refresh
    t.seq = UINT32_MAX;
    LM_CHECK(!field_snapshot_due(&t, &s, 30000));
}

LM_TEST("FIELD snapshot all big-endian fields golden and distance validation matches consumer") {
    field_presence_snapshot_t s{};
    s.presence = FIELD_PRESENCE_OCCUPIED;
    s.learning = FIELD_LEARN_DONE;
    s.flags = 7;
    s.boot_id = UINT64_C(0x0102030405060708);
    s.seq = 0x01020304;
    s.capture_ms = 0x05060708;
    s.sample_age_ms = 0x1234;
    s.distance_mm = 1000;
    s.background_mm = 2000;
    s.noise_mm = 13;
    s.learn_request = 0x11121314;
    s.fault_bits = 5;
    s.k3_seq = 0x21222324;
    s.k3_result = FIELD_K3_CONFIRMED;
    const uint8_t expected[] = {1,3,2,7, 1,2,3,4,5,6,7,8, 1,2,3,4, 5,6,7,8,
        0x12,0x34, 3,0xe8, 7,0xd0, 0,13, 0x11,0x12,0x13,0x14, 0,0,0,5,
        0x21,0x22,0x23,0x24, 2,0,0,0};
    uint8_t wire[44];
    LM_CHECK(field_presence_encode(&s, wire));
    LM_CHECK(std::memcmp(wire, expected, sizeof wire) == 0);
    field_presence_snapshot_t decoded{};
    LM_CHECK(field_presence_decode(wire, sizeof wire, &decoded));
    wire[22] = 0; wire[23] = 99;
    LM_CHECK(!field_presence_decode(wire, sizeof wire, &decoded));
    wire[22] = 3; wire[23] = 0xe8;
    wire[24] = 255; wire[25] = 255;
    LM_CHECK(!field_presence_decode(wire, sizeof wire, &decoded)); // unlearned with noise
}

LM_TEST("FIELD KG learning needs sample count validity and bounded spread in sliding window") {
    field_presence_snapshot_t s{};
    field_presence_begin(true, 0);
    field_presence_ready(true);
    LM_CHECK(field_presence_learn(1000));
    for (uint64_t t = 1000; t <= 4040; t += 200) field_presence_sample(t, 2000, 0);
    field_presence_capture(4040, &s);
    LM_CHECK(s.learning == FIELD_LEARN_RUNNING); // too few samples
    unsigned n = 0;
    for (uint64_t t = 4080; t <= 7280; t += 40, ++n)
        field_presence_sample(t, 2000, n % 5 == 0 ? 1 : 0); // 80%, cannot learn
    field_presence_capture(7280, &s);
    LM_CHECK(s.learning == FIELD_LEARN_RUNNING);
    for (uint64_t t = 7320; t <= 10520; t += 40, ++n)
        field_presence_sample(t, n % 2 ? 1700 : 2300, 0); // p10..p90 too wide
    field_presence_capture(10520, &s);
    LM_CHECK(s.learning == FIELD_LEARN_RUNNING);
    for (uint64_t t = 10560; t <= 13760; t += 40) field_presence_sample(t, 2000, 0);
    field_presence_capture(13760, &s);
    LM_CHECK(s.learning == FIELD_LEARN_DONE && s.background_mm == 2000);
    field_presence_ready(false);
    field_presence_capture(13800, &s);
    LM_CHECK(s.presence == FIELD_PRESENCE_UNKNOWN && s.background_mm == 2000);
    field_presence_ready(true); // reconnect never starts learning or discards calibration
    field_presence_capture(13800, &s);
    LM_CHECK(s.learn_request == 1 && s.background_mm == 2000);
    field_presence_begin(true, 0); // reboot: RAM only, no automatic learning
    field_presence_ready(true);
    field_presence_tick(9999);
    field_presence_capture(9999, &s);
    LM_CHECK(s.fault_bits == 0 && s.background_mm == UINT16_MAX);
    field_presence_tick(10000);
    field_presence_capture(10000, &s);
    LM_CHECK(s.fault_bits == 1 && s.sample_age_ms == UINT16_MAX);
    std::printf("[field host layout] detector=%zu keys(queue8)=%zu snapshot=%zu K3=%zu send-slot=%zu bytes; target RAM unmeasured\n",
        sizeof(kguard::field::presence_v2::Detector), sizeof(field_keys_t), sizeof(field_presence_snapshot_t),
        sizeof(field_k3_t), sizeof(field_snapshot_send_t));
}

LM_TEST("FIELD KG no boot learning explicit learning entry exit dropout and timeout") {
    field_presence_begin(true, 0);
    field_presence_ready(true);
    field_presence_snapshot_t s{};
    for (uint64_t t = 1000; t <= 5000; t += 40) field_presence_sample(t, 2000, 0);
    field_presence_capture(5000, &s);
    LM_CHECK(s.presence == FIELD_PRESENCE_UNKNOWN && s.background_mm == UINT16_MAX);
    LM_CHECK(field_presence_learn(5040));
    LM_CHECK(!field_presence_learn(5080)); // held/running request never restarts
    for (uint64_t t = 5040; t <= 8080; t += 40) field_presence_sample(t, 2000, 0);
    field_presence_capture(8080, &s);
    LM_CHECK(s.learning == FIELD_LEARN_DONE && s.presence == FIELD_PRESENCE_VACANT);
    LM_CHECK(s.background_mm == 2000 && s.learn_request == 1);
    for (uint64_t t = 8120; t <= 8400; t += 40) field_presence_sample(t, 1600, 0);
    field_presence_capture(8400, &s);
    LM_CHECK(s.presence == FIELD_PRESENCE_OCCUPIED);
    for (uint64_t t = 8440; t <= 8800; t += 40) field_presence_sample(t, 2000, 0);
    field_presence_capture(8800, &s);
    LM_CHECK(s.presence == FIELD_PRESENCE_VACANT);
    for (uint64_t t = 8840; t <= 10200; t += 40) field_presence_sample(t, 0, 1);
    field_presence_capture(10200, &s);
    LM_CHECK(s.presence == FIELD_PRESENCE_UNKNOWN && s.distance_mm == UINT16_MAX);
    LM_CHECK(field_presence_learn(10240));
    field_presence_tick(70240);
    field_presence_capture(70240, &s);
    LM_CHECK(s.learning == FIELD_LEARN_FAILED && s.background_mm == 2000);
    LM_CHECK((s.fault_bits & 5) == 5);
    LM_CHECK(s.sample_age_ms == 60040);
    field_presence_capture(1000000, &s);
    LM_CHECK(s.sample_age_ms == 65534);
    field_presence_begin(false, 0);
    field_presence_tick(100000);
    field_presence_capture(100000, &s);
    LM_CHECK(s.presence == FIELD_PRESENCE_DISABLED && s.fault_bits == 0);
    LM_CHECK(!field_presence_learn(100000));
    field_presence_capture(100000, &s);
    LM_CHECK(s.learning == FIELD_LEARN_NO_SENSOR);
}

LM_TEST("FIELD feedback animates preserves mesh bar and command bypass") {
    field_view_t v{};
    v.link = FIELD_LINK_REACHABLE;
    v.state_valid = true;
    uint16_t plain[32][64], overlay[32][64];
    field_render(&v, plain);
    v.feedback = FIELD_FEEDBACK_SENDING;
    v.animation = 0;
    field_render(&v, overlay);
    LM_CHECK(std::memcmp(plain[30], overlay[30], 2 * 64 * sizeof(uint16_t)) == 0);
    LM_CHECK(std::memcmp(plain, overlay, 30 * 64 * sizeof(uint16_t)) != 0);
    uint16_t second[32][64];
    v.animation = 1;
    field_render(&v, second);
    LM_CHECK(std::memcmp(second, overlay, 30 * 64 * sizeof(uint16_t)) != 0);
    v.feedback = FIELD_FEEDBACK_NONE; // received command must explicitly use this view
    field_render(&v, overlay);
    LM_CHECK(std::memcmp(plain, overlay, sizeof plain) == 0);
}

LM_TEST("FIELD failed relearn between samples never exposes old vacant before fresh reevaluation") {
    field_presence_begin(true, 0);
    field_presence_ready(true);
    LM_CHECK(field_presence_learn(1000));
    for (uint64_t t = 1000; t <= 4040; t += 40) field_presence_sample(t, 2000, 0);
    field_presence_snapshot_t s{};
    field_presence_capture(4040, &s);
    LM_CHECK(s.presence == FIELD_PRESENCE_VACANT && s.background_mm == 2000);
    LM_CHECK(field_presence_learn(4050));
    // All readings are valid but incompatible with the old background. Wide
    // alternating distances also prevent the relearn from completing.
    unsigned n = 0;
    for (uint64_t t = 4080; t < 64050; t += 40, ++n)
        field_presence_sample(t, n % 2 ? 2400 : 3000, 0);
    field_presence_tick(64050); // timeout falls between the 64040 and 64080 samples
    field_presence_capture(64050, &s);
    LM_CHECK(s.learning == FIELD_LEARN_FAILED && s.background_mm == 2000);
    LM_CHECK(s.presence == FIELD_PRESENCE_UNKNOWN);
    field_presence_capture(64060, &s);
    LM_CHECK(s.presence == FIELD_PRESENCE_UNKNOWN);
    field_presence_sample(64080, 2400, 0);
    field_presence_capture(64080, &s);
    LM_CHECK(s.presence == FIELD_PRESENCE_UNKNOWN && s.background_mm == 2000);
    for (uint64_t t = 64120; t <= 65320; t += 40) field_presence_sample(t, 2000, 0);
    field_presence_capture(65320, &s);
    LM_CHECK(s.presence == FIELD_PRESENCE_VACANT); // fresh compatible evidence can recover
}

LM_TEST("FIELD snapshot receipt remains associated with tracked press despite busy and dropped presses") {
    field_k3_t operation{};
    LM_CHECK(field_k3_press(&operation, 1, 100, 100));
    field_k3_accepted(&operation, 42);
    LM_CHECK(!field_k3_press(&operation, 2, 200, 200));
    field_presence_snapshot_t snapshot{};
    snapshot.boot_id = 99;
    snapshot.seq = 1;
    snapshot.distance_mm = snapshot.background_mm = UINT16_MAX;
    snapshot.k3_seq = 10; // newer physical presses, including a dropped action
    field_k3_observe(&operation, 42, true, true, true, 500);
    field_k3_snapshot(&operation, &snapshot); // same association function used by main
    uint8_t wire[FIELD_PRESENCE_BYTES];
    LM_CHECK(field_presence_encode(&snapshot, wire));
    field_presence_snapshot_t received{};
    LM_CHECK(field_presence_decode(wire, sizeof wire, &received));
    LM_CHECK(received.k3_seq == 1 && received.k3_result == FIELD_K3_CONFIRMED);
    LM_CHECK(field_k3_press(&operation, 11, 600, 600));
    field_k3_snapshot(&operation, &snapshot);
    LM_CHECK(snapshot.k3_seq == 11 && snapshot.k3_result == FIELD_K3_SENDING);
}

LM_TEST("FIELD main arbitration shows pending learning completion for visible three seconds then resumes K3") {
    field_learning_feedback_t learning{};
    field_k3_t k3{};
    LM_CHECK(field_k3_press(&k3, 1, 100, 100));
    field_k3_accepted(&k3, 42);
    LM_CHECK(field_learning_feedback_offer(&learning, FIELD_LEARN_DONE));
    const uint32_t token = learning.token;
    // Acquisition completion alone must not start a countdown. A slow or
    // unavailable panel can select this result much later without losing it.
    field_learning_feedback_tick(&learning, 9000);
    LM_CHECK(learning.pending && learning.visible_until_ms == 0);
    LM_CHECK(!field_learning_feedback_offer(&learning, FIELD_LEARN_FAILED));
    LM_CHECK(learning.result == FIELD_LEARN_DONE); // one retained result, no overwrite
    const field_feedback_t selected = field_feedback_select(&learning, &k3, FIELD_LEARN_DONE, 9000);
    LM_CHECK(selected == FIELD_FEEDBACK_LEARN_DONE); // outranks ongoing K3 sending
    field_view_t v{};
    v.link = FIELD_LINK_REACHABLE;
    v.feedback = selected;
    uint16_t frame[32][64];
    field_render(&v, frame); // host frame only, not DMA/LED evidence
    field_learning_feedback_shown(&learning, token + 1, 9000); // stale frame cannot consume this result
    LM_CHECK(learning.visible_until_ms == 0);
    field_learning_feedback_shown(&learning, token, 9300); // main's successful-DMA boundary
    field_learning_feedback_shown(&learning, token, 9600); // repeat draws cannot extend the time
    LM_CHECK(learning.visible_until_ms == 12300);
    LM_CHECK(field_feedback_select(&learning, &k3, FIELD_LEARN_DONE, 12299) == FIELD_FEEDBACK_LEARN_DONE);
    LM_CHECK(field_feedback_select(&learning, &k3, FIELD_LEARN_DONE, 12300) == FIELD_FEEDBACK_SENDING);
    field_learning_feedback_tick(&learning, 12300);
    LM_CHECK(!learning.pending);
    LM_CHECK(field_learning_feedback_offer(&learning, FIELD_LEARN_FAILED));
    LM_CHECK(field_feedback_select(&learning, &k3, FIELD_LEARN_FAILED, 12400) == FIELD_FEEDBACK_LEARN_FAILED);
    field_learning_feedback_shown(&learning, learning.token, 12400);
    field_learning_feedback_tick(&learning, 15400);
    LM_CHECK(field_learning_feedback_offer(&learning, FIELD_LEARN_NO_SENSOR));
    LM_CHECK(field_feedback_select(&learning, &k3, FIELD_LEARN_NO_SENSOR, 16000) == FIELD_FEEDBACK_NO_SENSOR);
    for (int x = 0; x < 64; ++x) LM_CHECK(frame[30][x] == FIELD_RGB565_GREEN && frame[31][x] == FIELD_RGB565_GREEN);
}

LM_TEST("FIELD Japanese learning labels use exact Shinonome 16-row glyphs and preserve animation bar command bypass") {
    // Golden rows from KG b80ce46d fonts_hybrid.hpp, not renderer internals.
    const uint16_t glyphs[7][16] = {
        {0x1108,0x0888,0x0890,0x7FFE,0x4002,0x4002,0x1FF0,0x0020,0x00C0,0x0100,0x7FFE,0x0100,0x0100,0x0100,0x0100,0x0300}, // 学
        {0x0000,0x7FFE,0x2142,0x1122,0x1326,0x051A,0x1962,0x6086,0x0100,0x0FF8,0x0808,0x0FF8,0x0808,0x0808,0x0FF8,0x0000}, // 習
        {0x0080,0x0080,0x0080,0x3FFE,0x2082,0x2082,0x2082,0x2082,0x2082,0x3FFE,0x0080,0x0080,0x0080,0x0080,0x0080,0x0080}, // 中
        {0x0100,0x0100,0x7FFE,0x4002,0x4002,0x1FF8,0x0000,0x0000,0x7FFE,0x0240,0x0240,0x0240,0x0442,0x0842,0x1022,0x601E}, // 完
        {0x0000,0x3FFC,0x0008,0x0010,0x0020,0x00C0,0x0080,0x0080,0x0080,0x0080,0x0080,0x0080,0x0080,0x0080,0x0080,0x0180}, // 了
        {0x0080,0x0880,0x0880,0x0880,0x0FFC,0x1080,0x1080,0x2080,0x7FFF,0x0080,0x0140,0x0140,0x0220,0x0410,0x180C,0x6003}, // 失
        {0x0040,0x3E40,0x2240,0x227F,0x3E44,0x2244,0x22C4,0x3EA4,0x2328,0x2228,0x2210,0x3E18,0x1428,0x1244,0x2282,0x4101}, // 敗
    };
    struct Label { field_feedback_t mode; int first, count; uint16_t colour; };
    const Label labels[] = {
        {FIELD_FEEDBACK_LEARNING, 0, 3, FIELD_RGB565_YELLOW},
        {FIELD_FEEDBACK_LEARN_DONE, 3, 2, FIELD_RGB565_GREEN},
        {FIELD_FEEDBACK_LEARN_FAILED, 5, 2, FIELD_RGB565_RED},
    };
    for (unsigned link = FIELD_LINK_JOINING; link <= FIELD_LINK_REVOKED; ++link) {
        field_view_t v{};
        v.link = static_cast<field_link_t>(link);
        v.state_valid = true;
        uint16_t commanded[32][64], frame[32][64];
        field_render(&v, commanded);
        for (const auto &label : labels) {
            v.feedback = label.mode;
            v.animation = 2;
            field_render(&v, frame);
            const int x0 = (64 - label.count * 16) / 2;
            bool exact = true;
            for (int row = 0; row < 16; ++row) {
                for (int x = 0; x < 64; ++x) {
                    const int offset = x - x0;
                    const bool on = offset >= 0 && offset < label.count * 16 &&
                        ((glyphs[label.first + offset / 16][row] >> (15 - offset % 16)) & 1u);
                    exact &= frame[8 + row][x] == (on ? label.colour : FIELD_RGB565_BLACK);
                }
            }
            LM_CHECK(exact); // full height includes rows 8 and 23, unlike the old ASCII rows 12..18
            LM_CHECK(std::memcmp(frame, commanded, 8 * 64 * sizeof(uint16_t)) == 0);
            LM_CHECK(std::memcmp(frame[30], commanded[30], 2 * 64 * sizeof(uint16_t)) == 0);
            for (int x = 0; x < 64; ++x) {
                const bool animated = label.mode == FIELD_FEEDBACK_LEARNING && x >= 20 && x < 25;
                LM_CHECK(frame[24][x] == (animated ? label.colour : FIELD_RGB565_BLACK));
            }
            if (label.mode == FIELD_FEEDBACK_LEARNING) {
                v.animation = 3;
                uint16_t next[32][64];
                field_render(&v, next);
                LM_CHECK(std::memcmp(frame[8], next[8], 16 * 64 * sizeof(uint16_t)) == 0);
                LM_CHECK(std::memcmp(frame[24], next[24], 64 * sizeof(uint16_t)) != 0);
            }
            v.feedback = FIELD_FEEDBACK_NONE;
            field_render(&v, frame);
            LM_CHECK(std::memcmp(frame, commanded, sizeof frame) == 0); // command bypass remains exact
        }
    }
}
