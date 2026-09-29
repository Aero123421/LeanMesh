// Minimal native test harness (no third-party framework). Each test binary is one CTest entry;
// every LM_TEST in it runs in registration order. A test that covers an acceptance scenario puts
// the scenario ID first in its name, e.g. LM_TEST("R10 late job completion is ignored"), so
// scripts can map tests to tests/scenarios.json. Usage: <binary> [substring-filter]
#pragma once

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace lmtest {

struct Case {
    const char *name;
    void (*fn)();
};

inline std::vector<Case> &registry() {
    static std::vector<Case> cases;
    return cases;
}

inline int &failures() {
    static int n = 0;
    return n;
}

struct Registrar {
    Registrar(const char *name, void (*fn)()) { registry().push_back(Case{name, fn}); }
};

inline void fail(const char *file, int line, const std::string &what) {
    std::fprintf(stderr, "  FAIL %s:%d: %s\n", file, line, what.c_str());
    ++failures();
}

inline std::vector<uint8_t> from_hex(const char *hex) {
    std::vector<uint8_t> out;
    const std::size_t n = std::strlen(hex);
    for (std::size_t i = 0; i + 1 < n; i += 2) {
        unsigned v = 0;
        std::sscanf(hex + i, "%2x", &v);
        out.push_back(static_cast<uint8_t>(v));
    }
    return out;
}

inline int run_all(int argc, char **argv) {
    const char *filter = argc > 1 ? argv[1] : nullptr;
    int ran = 0;
    int failed_cases = 0;
    for (const Case &c : registry()) {
        if (filter != nullptr && std::strstr(c.name, filter) == nullptr) {
            continue;
        }
        const int before = failures();
        std::printf("[ RUN  ] %s\n", c.name);
        c.fn();
        const bool ok = failures() == before;
        std::printf("[ %s ] %s\n", ok ? " OK " : "FAIL", c.name);
        ++ran;
        failed_cases += ok ? 0 : 1;
    }
    std::printf("%d test(s), %d failed\n", ran, failed_cases);
    if (ran == 0) {
        std::fprintf(stderr, "no test matched\n");
        return 2;
    }
    return failed_cases == 0 ? 0 : 1;
}

} // namespace lmtest

#define LMTEST_CAT2(a, b) a##b
#define LMTEST_CAT(a, b) LMTEST_CAT2(a, b)
#define LM_TEST(name)                                                                              \
    static void LMTEST_CAT(lmtest_fn_, __LINE__)();                                                \
    static const ::lmtest::Registrar LMTEST_CAT(lmtest_reg_, __LINE__)(                            \
        name, &LMTEST_CAT(lmtest_fn_, __LINE__));                                                  \
    static void LMTEST_CAT(lmtest_fn_, __LINE__)()

#define LM_CHECK(cond)                                                                             \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            ::lmtest::fail(__FILE__, __LINE__, #cond);                                             \
        }                                                                                          \
    } while (0)

// Operands must be printable as unsigned long long (integers, enums via static_cast).
#define LM_CHECK_EQ(a, b)                                                                          \
    do {                                                                                           \
        const auto lmtest_a_ = (a);                                                                \
        const auto lmtest_b_ = (b);                                                                \
        if (!(lmtest_a_ == lmtest_b_)) {                                                           \
            ::lmtest::fail(__FILE__, __LINE__,                                                     \
                           std::string(#a " == " #b " (") +                                        \
                               std::to_string(static_cast<unsigned long long>(lmtest_a_)) +        \
                               " vs " +                                                            \
                               std::to_string(static_cast<unsigned long long>(lmtest_b_)) + ")");  \
        }                                                                                          \
    } while (0)

#define LM_CHECK_OK(expr) LM_CHECK((expr) == ::lm::Status::Ok)

#define LM_TEST_MAIN()                                                                             \
    int main(int argc, char **argv) { return ::lmtest::run_all(argc, argv); }
