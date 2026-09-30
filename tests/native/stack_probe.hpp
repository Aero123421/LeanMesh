// Stack high-water probe for native tests: runs a callable on a thread whose stack we own and
// painted, then reports how deep it went. Under sanitizers the number is inflated (red zones);
// callers only assert when LM_STACK_PROBE_EXACT is set.
#pragma once

#include <pthread.h>
#include <sys/mman.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

#if defined(__SANITIZE_ADDRESS__)
#define LM_STACK_PROBE_EXACT 0
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define LM_STACK_PROBE_EXACT 0
#endif
#endif
#ifndef LM_STACK_PROBE_EXACT
#define LM_STACK_PROBE_EXACT 1
#endif

namespace lmtest {

template <class F> std::size_t peak_stack_of(F &&f) {
    constexpr std::size_t k_stack = 256 * 1024;
    struct Ctx {
        F *fn;
    } ctx{&f};
    // mmap, not malloc: keeps heap accounting of the callee clean.
    auto *stack = static_cast<uint8_t *>(
        mmap(nullptr, k_stack, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    std::memset(stack, 0xA5, k_stack);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstack(&attr, stack, k_stack);
    pthread_t t;
    pthread_create(
        &t, &attr,
        [](void *p) -> void * {
            (*static_cast<Ctx *>(p)->fn)();
            return nullptr;
        },
        &ctx);
    pthread_attr_destroy(&attr);
    pthread_join(t, nullptr);
    std::size_t untouched = 0;
    while (untouched < k_stack && stack[untouched] == 0xA5) {
        ++untouched;
    }
    munmap(stack, k_stack);
    return k_stack - untouched;
}

// glibc puts the thread descriptor and TLS on a caller-supplied stack and its start-up touches more
// below that, so the raw peak of even an EMPTY thread is ~6 KiB and small callees vanish in it. The
// depth of the callee's own frames is therefore measured against the entry depth of the thread,
// calibrated once per process with a callee that touches 16 KiB (frame overhead < 100 B).
inline std::size_t entry_depth() {
    static const std::size_t depth = [] {
        constexpr std::size_t k = 16384;
        return peak_stack_of([] {
                   volatile uint8_t a[k];
                   for (std::size_t i = 0; i < k; ++i) {
                       a[i] = 1;
                   }
                   asm volatile("" : : "r"(&a[0]) : "memory");
               }) -
               k;
    }();
    return depth;
}

// Stack depth used by `f` itself (above its own entry frame). Reliable above ~2 KiB.
template <class F> std::size_t depth_of(F &&f) {
    const std::size_t peak = peak_stack_of(static_cast<F &&>(f));
    return peak > entry_depth() ? peak - entry_depth() : 0;
}

} // namespace lmtest
