#include "port/sim/sim_pm.hpp"

#include <cstring>

namespace lm::sim {

void SimPm::set_locks(uint8_t mask) {
    ++set_calls_;
    for (unsigned b = 0; b < 4; ++b) {
        const bool was = (mask_ >> b) & 1U;
        const bool now = (mask >> b) & 1U;
        acquired_[b] += (!was && now) ? 1U : 0U;
        released_[b] += (was && !now) ? 1U : 0U;
    }
    mask_ = mask;
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
