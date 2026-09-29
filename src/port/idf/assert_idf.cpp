// ESP-IDF handler for internal invariant failures (LM_ASSERT): a controlled abort with the reason
// recorded by the panic handler. Never reached by external input.
#include "core/assert.hpp"
#include "esp_system.h"

namespace lm {

void assert_fail(const char *file, int line, const char *expr) {
    (void)file;
    (void)line;
    esp_system_abort(expr);
}

} // namespace lm
