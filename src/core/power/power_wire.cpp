#include "core/power/power_wire.hpp"

#include "core/codec.hpp"

namespace lm::power {
namespace {

// One field list per record (core/codec.hpp): it writes and reads the same layout.
template <class F> void io(F &f, Report &m) {
    f.is(k_op_report);
    f.is(uint8_t{1}); // version
    f.u8(m.mode);
    f.u8(m.quality);
    f.u8(m.kind);
    f.u32(m.policy_revision);
    f.u32(m.interval_ms);
    f.u32(m.earliest_ms);
    f.u32(m.latest_ms);
}
template <class F> void io(F &f, Policy &p) {
    f.is(uint8_t{1}); // version
    f.u64(p.revision);
    f.u8(p.mode);
    f.u8(p.pending);
    for (uint32_t *v : {&p.wake_interval_ms, &p.rx_window_ms, &p.max_rx_window_ms, &p.awake_budget_ms,
                        &p.shutdown_reserve_ms, &p.search_budget_ms, &p.guard_ms, &p.retry_min_ms,
                        &p.retry_max_ms, &p.offline_radio_ms_per_hour, &p.extra_wakes_per_day,
                        &p.extra_radio_ms_per_day, &p.shutdown_overrun_ms, &p.mailbox_child, &p.mailbox_total}) {
        f.u32(*v);
    }
}

} // namespace

Status encode(const Report &r, MutByteView out, std::size_t &len) {
    return put_record(r, out, len, [](auto &f, auto &m) { io(f, m); });
}

Status decode(ByteView body, Report &out) {
    Report m;
    if (get_record(body, m, [](auto &f, auto &x) { io(f, x); }) != Status::Ok || m.mode > k_report_only ||
        m.quality > k_quality_bounded || m.kind > LM_SLEEP_DEEP || m.earliest_ms > m.latest_ms ||
        m.interval_ms > 86400000U) {
        return Status::BadFrame;
    }
    out = m;
    return Status::Ok;
}

Status encode_policy(const Policy &p, MutByteView out, std::size_t &len) {
    return put_record(p, out, len, [](auto &f, auto &m) { io(f, m); });
}

Status decode_policy(ByteView in, Policy &out) {
    Policy p;
    if (get_record(in, p, [](auto &f, auto &m) { io(f, m); }) != Status::Ok) {
        return Status::RecoveryRequired; // a sealed record that does not parse: fail closed, never a default
    }
    out = p;
    return Status::Ok;
}

} // namespace lm::power
