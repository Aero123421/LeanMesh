// ESP-IDF Clock port: esp_timer (microseconds since boot, monotonic, 64-bit).
#pragma once

#include "core/ports.hpp"

namespace lm::idf {

class IdfClock final : public port::Clock {
  public:
    [[nodiscard]] MonoTime now() const override;
};

} // namespace lm::idf
