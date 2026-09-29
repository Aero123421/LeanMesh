#include "core/sched/sched.hpp"

namespace lm::sched {
namespace {

constexpr std::size_t idx(Class c) { return static_cast<std::size_t>(c); }
constexpr int64_t quantum(std::size_t c) {
    return static_cast<int64_t>(gen::defaults::scheduler::drr_weights[c]) * k_quantum_us;
}
// Airtime a class may go into debt: only URGENT and CONTROL borrow (repaid by the refill).
constexpr int64_t floor_of(Class c) { return (c == Class::Urgent || c == Class::Control) ? -k_urgent_debt_us : 0; }

} // namespace

void Scheduler::refill(MonoTime now) {
    if (now <= tokens_at_) {
        return;
    }
    const int64_t add = (now - tokens_at_).us * k_rate_ms_per_s / 1000;
    tokens_ = tokens_ + add > k_burst_us ? k_burst_us : tokens_ + add;
    tokens_at_ = now;
}

void Scheduler::roll_window(MonoTime now) {
    if (now >= win_start_ + Duration{k_window_us}) {
        win_start_ = now;
        win_ctrl_us_ = 0;
    }
}

bool Scheduler::allowed(Class c, int64_t cost) const { return tokens_ - cost >= floor_of(c); }

int64_t Scheduler::tokens_us(MonoTime now) {
    refill(now);
    return tokens_;
}

bool Scheduler::pick(const std::array<uint16_t, k_classes> &heads, MonoTime now, Class &out, MonoTime &wake) {
    refill(now);
    roll_window(now);
    wake = MonoTime::never();
    std::array<uint16_t, k_classes> head_bytes = heads;
    if (now < hold_until_) { // [S17] only CONTROL may go while the node is planned off its channel
        for (std::size_t c = 1; c < k_classes; ++c) {
            if (head_bytes[c] != 0) {
                wake = hold_until_;
                head_bytes[c] = 0;
            }
        }
    }
    bool any = false;
    for (std::size_t c = 0; c < k_classes; ++c) {
        if (head_bytes[c] == 0) {
            deficit_[c] = 0; // an idle class keeps no credit
        }
        any = any || head_bytes[c] != 0;
    }
    if (!any) {
        return false; // (wake is the end of a hold when data frames wait behind one)
    }
    drr_pending_ = false;
    // CONTROL reserve: inside its window entitlement a ready control frame goes first, even on empty tokens
    // (it is charged: the debt shows and the data classes pay it back). After two URGENT frames in a
    // row a ready control frame is served next if the tokens allow it.
    if (head_bytes[idx(Class::Control)] != 0) {
        const bool due = control_due();
        if (due || (urgent_run_ >= k_urgent_run && allowed(Class::Control, airtime_us(head_bytes[0])))) {
            ++(due ? stats_.reserve_picks : stats_.urgent_yields);
            out = Class::Control;
            return true;
        }
    }
    std::array<bool, k_classes> avail{};
    int64_t wait_us = INT64_MAX;
    for (std::size_t c = 0; c < k_classes; ++c) {
        if (head_bytes[c] == 0) {
            continue;
        }
        const int64_t cost = airtime_us(head_bytes[c]);
        avail[c] = allowed(static_cast<Class>(c), cost);
        if (!avail[c]) {
            const int64_t need = cost + floor_of(static_cast<Class>(c)) - tokens_; // tokens missing
            const int64_t us = (need * 1000 + k_rate_ms_per_s - 1) / k_rate_ms_per_s;
            wait_us = us < wait_us ? us : wait_us;
        }
    }
    bool have = false;
    for (bool a : avail) {
        have = have || a;
    }
    if (!have) {
        ++stats_.token_waits;
        wake = now + Duration{wait_us < 1000 ? 1000 : wait_us};
        return false;
    }
    // DRR over the classes that may send: visit rr_; serve while the deficit covers the head frame,
    // else add the quantum and move on (bounded: the largest frame needs a few quanta per class).
    for (unsigned i = 0; i < 64; ++i) {
        const std::size_t c = rr_;
        if (avail[c]) {
            if (deficit_[c] >= airtime_us(head_bytes[c])) {
                out = static_cast<Class>(c);
                last_ = out;
                drr_pending_ = true;
                return true;
            }
            deficit_[c] += static_cast<int32_t>(quantum(c));
        }
        rr_ = static_cast<uint8_t>((rr_ + 1) % k_classes);
    }
    // Unreachable with the constants above; serve the first available class rather than stall.
    for (std::size_t c = 0; c < k_classes; ++c) {
        if (avail[c]) {
            out = static_cast<Class>(c);
            return true;
        }
    }
    return false;
}

void Scheduler::charge(Class c, std::size_t bytes, MonoTime now, bool queued) {
    refill(now);
    roll_window(now);
    const int64_t cost = airtime_us(bytes);
    tokens_ = tokens_ - cost < -k_burst_us ? -k_burst_us : tokens_ - cost;
    ClassStats &s = stats_.cls[idx(c)];
    ++s.frames;
    s.airtime_us += static_cast<uint64_t>(cost);
    if (!queued) {
        stats_.ack_charged_us += static_cast<uint64_t>(cost);
        return;
    }
    if (c == Class::Control) {
        win_ctrl_us_ += static_cast<int32_t>(cost);
    }
    urgent_run_ = c == Class::Urgent ? static_cast<uint8_t>(urgent_run_ + 1) : 0;
    if (drr_pending_ && last_ == c) {
        deficit_[idx(c)] -= static_cast<int32_t>(cost);
        drr_pending_ = false;
    }
}

} // namespace lm::sched
