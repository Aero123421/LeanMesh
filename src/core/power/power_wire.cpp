#include "core/power/power_wire.hpp"

#include "core/codec.hpp"

namespace lm::power {

Status encode(const Report &r, MutByteView out, std::size_t &len) {
    Writer w{out};
    w.u8(k_op_report);
    w.u8(1);
    w.u8(r.mode);
    w.u8(r.quality);
    w.u8(r.kind);
    w.u32be(r.policy_revision);
    w.u32be(r.interval_ms);
    w.u32be(r.earliest_ms);
    w.u32be(r.latest_ms);
    len = w.size();
    return w.finish();
}

Status decode(ByteView body, Report &out) {
    Reader r{body};
    Report m;
    const uint8_t op = r.u8();
    const uint8_t version = r.u8();
    m.mode = r.u8();
    m.quality = r.u8();
    m.kind = r.u8();
    m.policy_revision = r.u32be();
    m.interval_ms = r.u32be();
    m.earliest_ms = r.u32be();
    m.latest_ms = r.u32be();
    if (r.finish() != Status::Ok || op != k_op_report || version != 1 || m.mode > k_report_only ||
        m.quality > k_quality_bounded || m.kind > LM_SLEEP_DEEP || m.earliest_ms > m.latest_ms ||
        m.interval_ms > 86400000U) {
        return Status::BadFrame;
    }
    out = m;
    return Status::Ok;
}

Status encode_policy(const Policy &p, MutByteView out, std::size_t &len) {
    Writer w{out};
    w.u8(1);
    w.u64be(p.revision);
    w.u8(p.mode);
    w.u8(p.pending);
    for (uint32_t v : {p.wake_interval_ms, p.rx_window_ms, p.max_rx_window_ms, p.awake_budget_ms,
                       p.shutdown_reserve_ms, p.search_budget_ms, p.guard_ms, p.retry_min_ms, p.retry_max_ms,
                       p.offline_radio_ms_per_hour, p.extra_wakes_per_day, p.extra_radio_ms_per_day,
                       p.shutdown_overrun_ms, p.mailbox_child, p.mailbox_total}) {
        w.u32be(v);
    }
    len = w.size();
    return w.finish();
}

Status decode_policy(ByteView in, Policy &out) {
    Reader r{in};
    Policy p;
    const uint8_t version = r.u8();
    p.revision = r.u64be();
    p.mode = r.u8();
    p.pending = r.u8();
    for (uint32_t *v : {&p.wake_interval_ms, &p.rx_window_ms, &p.max_rx_window_ms, &p.awake_budget_ms,
                        &p.shutdown_reserve_ms, &p.search_budget_ms, &p.guard_ms, &p.retry_min_ms,
                        &p.retry_max_ms, &p.offline_radio_ms_per_hour, &p.extra_wakes_per_day,
                        &p.extra_radio_ms_per_day, &p.shutdown_overrun_ms, &p.mailbox_child, &p.mailbox_total}) {
        *v = r.u32be();
    }
    if (r.finish() != Status::Ok || version != 1) {
        return Status::RecoveryRequired; // a sealed record that does not parse: fail closed, never a default
    }
    out = p;
    return Status::Ok;
}

} // namespace lm::power
