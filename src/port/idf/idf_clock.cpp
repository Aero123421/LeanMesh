#include "port/idf/idf_clock.hpp"

#include "esp_timer.h"

namespace lm::idf {

MonoTime IdfClock::now() const { return MonoTime{static_cast<uint64_t>(esp_timer_get_time())}; }

} // namespace lm::idf
