// Four time domains that never mix (docs/15 §2):
//   Duration   signed length of time (microseconds)
//   MonoTime   local monotonic clock since boot (microseconds); meaningless across reboots
//   RootTime   a point on the root's monotonic clock inside one root_term (milliseconds, as on
//   wire) UtcTime    wall clock supplied by a trusted host; only the Host uses it (never for
//   deadlines
//              on device, docs/08 §5)
#pragma once

#include <cstdint>
#include <limits>

#include "core/ids.hpp"

namespace lm {

struct Duration {
    int64_t us = 0;

    static constexpr Duration from_us(int64_t v) { return Duration{v}; }
    static constexpr Duration from_ms(int64_t v) { return Duration{v * 1000}; }
    static constexpr Duration from_s(int64_t v) { return Duration{v * 1000000}; }
    [[nodiscard]] constexpr int64_t to_ms() const { return us / 1000; }

    friend constexpr Duration operator+(Duration a, Duration b) { return Duration{a.us + b.us}; }
    friend constexpr Duration operator-(Duration a, Duration b) { return Duration{a.us - b.us}; }
    friend constexpr bool operator==(Duration a, Duration b) { return a.us == b.us; }
    friend constexpr bool operator!=(Duration a, Duration b) { return a.us != b.us; }
    friend constexpr bool operator<(Duration a, Duration b) { return a.us < b.us; }
    friend constexpr bool operator<=(Duration a, Duration b) { return a.us <= b.us; }
    friend constexpr bool operator>(Duration a, Duration b) { return a.us > b.us; }
    friend constexpr bool operator>=(Duration a, Duration b) { return a.us >= b.us; }
};

struct MonoTime {
    uint64_t us = 0;

    // "No deadline": the owner may sleep until an external event (docs/02 §5).
    static constexpr MonoTime never() { return MonoTime{std::numeric_limits<uint64_t>::max()}; }
    [[nodiscard]] constexpr bool is_never() const { return us == never().us; }
    [[nodiscard]] constexpr uint64_t to_ms() const { return us / 1000; }

    // Saturating: adding to never() stays never(); negative durations clamp at 0.
    friend constexpr MonoTime operator+(MonoTime t, Duration d) {
        if (t.is_never()) {
            return t;
        }
        if (d.us < 0) {
            const auto back = static_cast<uint64_t>(-d.us);
            return MonoTime{t.us > back ? t.us - back : 0};
        }
        const auto fwd = static_cast<uint64_t>(d.us);
        return MonoTime{fwd > never().us - t.us ? never().us : t.us + fwd};
    }
    friend constexpr Duration operator-(MonoTime a, MonoTime b) {
        return Duration{static_cast<int64_t>(a.us - b.us)};
    }
    friend constexpr bool operator==(MonoTime a, MonoTime b) { return a.us == b.us; }
    friend constexpr bool operator!=(MonoTime a, MonoTime b) { return a.us != b.us; }
    friend constexpr bool operator<(MonoTime a, MonoTime b) { return a.us < b.us; }
    friend constexpr bool operator<=(MonoTime a, MonoTime b) { return a.us <= b.us; }
    friend constexpr bool operator>(MonoTime a, MonoTime b) { return a.us > b.us; }
    friend constexpr bool operator>=(MonoTime a, MonoTime b) { return a.us >= b.us; }
};

[[nodiscard]] constexpr MonoTime earliest(MonoTime a, MonoTime b) { return a < b ? a : b; }

// A deadline or instant on the root clock. expires_root_ms == 0 means "no deadline" on the wire
// and is only legal for RECEIVED+DURABLE records (docs/08 §5); represent that as
// has_deadline=false.
struct RootTime {
    RootTerm term;
    uint64_t ms = 0;
};

// The local estimate of the current root time: an interval, never a point (docs/05 §5).
struct RootTimeBound {
    RootTerm term;
    uint64_t earliest_ms = 0;
    uint64_t latest_ms = 0;
    bool valid = false;
};

enum class DeadlineCheck : uint8_t {
    Before,    // provably before the deadline (latest estimate < deadline)
    After,     // provably at/after the deadline
    Uncertain, // bound invalid, term mismatch or interval straddles: TIME_UNCERTAIN
};

// A receiver may act only when it can prove the deadline has not passed (docs/08 §5).
[[nodiscard]] constexpr DeadlineCheck check_deadline(const RootTimeBound &now,
                                                     const RootTime &deadline) {
    if (!now.valid || now.term != deadline.term) {
        return DeadlineCheck::Uncertain;
    }
    if (now.latest_ms < deadline.ms) {
        return DeadlineCheck::Before;
    }
    if (now.earliest_ms >= deadline.ms) {
        return DeadlineCheck::After;
    }
    return DeadlineCheck::Uncertain;
}

struct UtcTime {
    int64_t ms = 0;
};

} // namespace lm
