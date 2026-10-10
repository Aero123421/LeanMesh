#include "field_presence.h"
#include "lmtest.hpp"

LM_TEST("FIELD non-ToF build stays disabled even if caller requests a sensor and K1 reports no sensor") {
    field_presence_begin(true, 0); // compile-time exclusion overrides an erroneous runtime request
    field_presence_ready(true);
    field_presence_sample(1000, 2000, 0);
    field_presence_tick(100000);
    field_presence_snapshot_t s{};
    field_presence_capture(100000, &s);
    LM_CHECK(s.presence == FIELD_PRESENCE_DISABLED && s.flags == 0 && s.fault_bits == 0);
    LM_CHECK(s.distance_mm == UINT16_MAX && s.background_mm == UINT16_MAX && s.sample_age_ms == UINT16_MAX);
    LM_CHECK(!field_presence_learn(100000));
    field_presence_capture(100000, &s);
    LM_CHECK(s.learning == FIELD_LEARN_NO_SENSOR && s.learn_request == 0 && s.noise_mm == 0);
}
LM_TEST_MAIN()
