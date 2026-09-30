// CRC-32 (IEEE, reflected, poly 0xEDB88320). Detects torn/partial writes only; it is not an
// integrity or authenticity proof against an adversary (docs/12 §2).
#pragma once

#include <cstdint>

#include "core/bytes.hpp"

namespace lm::store {

[[nodiscard]] inline uint32_t crc32_update(uint32_t crc, ByteView data) {
    crc = ~crc;
    for (uint8_t b : data) {
        crc ^= b;
        for (int i = 0; i < 8; ++i) {
            crc = (crc >> 1U) ^ (0xEDB88320U & (0U - (crc & 1U)));
        }
    }
    return ~crc;
}

[[nodiscard]] inline uint32_t crc32(ByteView data) { return crc32_update(0, data); }

} // namespace lm::store
