// Internal invariant checks. NEVER use on external input (frames, serial, API arguments):
// those must return a Status (docs/15 §2 "外部入力にassertでabortしない").
#pragma once

namespace lm {
[[noreturn]] void assert_fail(const char *file, int line, const char *expr);
} // namespace lm

#define LM_ASSERT(cond)                                                                            \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            ::lm::assert_fail(__FILE__, __LINE__, #cond);                                          \
        }                                                                                          \
    } while (0)
