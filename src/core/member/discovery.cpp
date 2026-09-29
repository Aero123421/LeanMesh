#include "core/member/discovery.hpp"

namespace lm::member {

void Discovery::begin(MonoTime now, uint16_t jitter_ms, bool listen_first, Duration budget, bool auto_resume) {
    const Duration jitter = Duration::from_ms(jitter_ms % 400);
    phase_ = listen_first ? Phase::Listen : Phase::Hello;
    // Listen ends after 800 ms; the first hello follows after the jitter (both are timers, not polls).
    hello_at_ = now + (listen_first ? k_listen : Duration{}) + jitter;
    budget_ = budget;
    budget_end_ = now + budget;
    handshakes_ = 0;
    auto_resume_ = auto_resume;
    resume_at_ = MonoTime::never();
}

void Discovery::wake(MonoTime now, uint16_t jitter_ms) {
    if (phase_ == Phase::Idle) {
        return;
    }
    backoff_ = k_backoff_min;
    begin(now, jitter_ms, false, budget_, auto_resume_);
}

Discovery::Act Discovery::poll(MonoTime now) {
    switch (phase_) {
    case Phase::Idle:
        return Act::None;
    case Phase::Listen:
    case Phase::Hello:
        if (now >= budget_end_) {
            phase_ = Phase::Backoff;
            resume_at_ = now + backoff_;
            backoff_ = backoff_ + backoff_ > k_backoff_max ? k_backoff_max : backoff_ + backoff_;
            return Act::Exhausted;
        }
        if (now >= hello_at_) {
            phase_ = Phase::Hello;
            if (suppressed(now)) {
                hello_at_ = earliest(suppress_until_, budget_end_); // asked to stay quiet: sleep until then
                return Act::None;
            }
            hello_at_ = now + k_hello_gap;
            return Act::Hello;
        }
        return Act::None;
    case Phase::Backoff:
        if (auto_resume_ && now >= resume_at_) {
            begin(now, 0, false, budget_, true);
            return Act::Resumed;
        }
        return Act::None;
    }
    return Act::None;
}

MonoTime Discovery::deadline() const {
    switch (phase_) {
    case Phase::Idle:
        return MonoTime::never();
    case Phase::Listen:
    case Phase::Hello:
        return earliest(hello_at_, budget_end_);
    case Phase::Backoff:
        return auto_resume_ ? resume_at_ : MonoTime::never();
    }
    return MonoTime::never();
}

} // namespace lm::member
