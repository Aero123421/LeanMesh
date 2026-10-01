#include "port/sim/sim_pm.hpp"

#include "port/sim/sim_node.hpp"
#include <cstring>

namespace lm::sim {

uint8_t SimPm::set_locks(uint8_t mask) {
    ++set_calls_;
    uint8_t held = mask_;
    for (unsigned b = 0; b < 4; ++b) {
        const bool was = (mask_ >> b) & 1U;
        const bool now = (mask >> b) & 1U;
        if (!was && now && ((take_fail >> b) & 1U) == 0) {
            ++acquired_[b];
            held = static_cast<uint8_t>(held | (1U << b));
        } else if (was && !now && ((drop_fail >> b) & 1U) == 0) {
            ++released_[b];
            held = static_cast<uint8_t>(held & ~(1U << b));
        }
    }
    mask_ = held;
    return held;
}

port::WakeInfo SimPm::boot_info() {
    port::WakeInfo w = boot_;
    boot_ = port::WakeInfo{}; // consumed: the next plain power cycle is a cold boot
    mask_ = 0;
    return w;
}

void SimPm::retain(ByteView state) {
    retained_len_ = static_cast<uint8_t>(state.size() < retained_.size() ? state.size() : retained_.size());
    std::memcpy(retained_.data(), state.data(), retained_len_);
}

port::SleepStart SimPm::sleep(uint8_t kind, uint8_t sources, uint64_t duration_ms, port::WakeInfo &woke) {
    if (!supported) {
        return port::SleepStart::Unsupported;
    }
    ++sleep_calls_;
    if (kind == LM_SLEEP_DEEP) {
        deep_ = true;
        deep_ms_ = duration_ms;
        deep_sources_ = sources;
        return port::SleepStart::Pending;
    }
    woke = port::WakeInfo{};
    woke.cause = port::ResetCause::LightWake;
    woke.ram_complete = ram_complete;
    woke.elapsed_known = elapsed_known;
    if (synchronous_wake_ms != 0) {
        node_.clock.advance(synchronous_wake_ms * 1000U);
        woke.source = synchronous_source;
        woke.elapsed_upper_ms = synchronous_wake_ms;
        return port::SleepStart::Woke;
    }
    return port::SleepStart::Pending; // the owner wakes itself at its deadline, or the bench calls power_wake()
}

void SimPm::prepare_deep_boot(uint8_t source, uint64_t elapsed_ms) {
    boot_ = port::WakeInfo{};
    boot_.cause = port::ResetCause::DeepWake;
    boot_.source = source;
    boot_.elapsed_known = elapsed_known;
    boot_.elapsed_upper_ms = elapsed_ms + 1U;
    boot_.retained_len = retained_len_;
    boot_.retained = retained_;
}

} // namespace lm::sim
