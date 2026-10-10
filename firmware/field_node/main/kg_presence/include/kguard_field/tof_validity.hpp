#pragma once

#include <cstdint>

// Product import of the PR94 sample-validity rule:
// experiments/tof-distance/esp-idf/main/validity.hpp at PR94 head
// 0bd0815f4232f073adf6bb46587c0efc3e31323d. Only fresh, acknowledged
// measurements become presence evidence; anything else contributes zero
// evidence but still advances wall-clock time via tick().

namespace kguard::field {

enum class TofModel : unsigned {
    Tof200c = 200,
    Tof400c = 400,
};

constexpr bool tof_sample_valid(
    TofModel model,
    unsigned range_status,
    uint16_t distance_mm,
    bool fresh_read,
    bool timeout) {
    if (!fresh_read || timeout || distance_mm == 0xffff) {
        return false;
    }
    switch (model) {
        case TofModel::Tof200c:
            return range_status == 11;
        case TofModel::Tof400c:
            return range_status == 0;
    }
    return false;
}

}  // namespace kguard::field
