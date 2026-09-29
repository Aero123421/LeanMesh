// Native/sim handler for internal invariant failures (LM_ASSERT). Never reached by external input.
#include <cstdio>
#include <cstdlib>

#include "core/assert.hpp"

namespace lm {

void assert_fail(const char *file, int line, const char *expr) {
    std::fprintf(stderr, "LM_ASSERT failed: %s (%s:%d)\n", expr, file, line);
    std::abort();
}

} // namespace lm
