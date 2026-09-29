// The root's view of the power state of its members (docs/20 §4, docs/22 §5). A report is a hint about
// availability: it never shortens a check and never grants authority. The only decisions taken from it are
//   - a route lease long enough for the member's own cycle (still granted per authenticated READY, capped),
//   - "the deadline lies before the member's earliest possible wake": DEADLINE_UNREACHABLE at submit time,
//   - what the Host is told about the node (GET /v1/nodes/{id}/power).
#include "core/delivery/types.hpp"
#include "core/engine.hpp"
#include "core/power/power.hpp"

namespace lm::power {
namespace {

constexpr uint32_t k_lease_base_ms = gen::defaults::routing::lease_ms;
constexpr uint32_t k_lease_cap_ms = 7200000;   // a sleepy member's route lease never exceeds 2 h
constexpr uint32_t k_lease_margin_ms = 60000;
constexpr uint32_t k_max_age_s = gen::defaults::power_limits::schedule_max_age_ms / 1000U;
constexpr uint64_t k_wake_settle_ms = 20000;
constexpr uint64_t k_wake_lead_ms = 3000; // a group target is sent this long before its earliest wake (the mailbox holds it)
constexpr uint64_t k_ppm = gen::defaults::channel::qualified_clock_drift_ppm; // drift of each clock
// A report crosses up to 40 hops before the root sees it: its "next wake in X" started that much earlier.
constexpr uint64_t k_transit_ms = 600 + 240 * static_cast<uint64_t>(gen::limits::path_hops);

MemberPower *slot(std::array<MemberPower, k_members> &t, ShortAddr a) {
    return a.value() >= 2 && a.value() - 2U < t.size() ? &t[a.value() - 2U] : nullptr;
}

} // namespace

void Power::on_report(const DeviceId &, ShortAddr addr, ByteView body, MonoTime now) {
    Report r;
    MemberPower *m = slot(members_, addr);
    if (m == nullptr || decode(body, r) != Status::Ok) {
        return;
    }
    ++stats_.reports_rx;
    const uint64_t t = now.to_ms();
    // The report crossed as many hops as the member is deep; the timer it names started that long ago.
    delivery::PathSpec ps;
    const uint64_t transit = engine_.routes().path_to_addr(addr, ps, now)
                                 ? static_cast<uint64_t>(delivery::round_timeout(ps.len).to_ms())
                                 : k_transit_ms;
    *m = MemberPower{};
    m->valid = true;
    m->mode = r.mode;
    m->quality = r.quality;
    m->kind = r.kind;
    m->policy_rev = r.policy_revision;
    m->interval_s = r.interval_ms / 1000U;
    m->reported_s = static_cast<uint32_t>(t / 1000U);
    if (r.quality != k_quality_unknown) { // rounded outwards: never a bound tighter than what was reported
        const uint64_t lo = t + r.earliest_ms > transit ? t + r.earliest_ms - transit : 0;
        m->earliest_s = static_cast<uint32_t>(lo / 1000U);
        m->latest_s = static_cast<uint32_t>((t + r.latest_ms + 999U) / 1000U);
    }
    engine_.routes().extend_lease(addr, lease_ms_for(addr, now), now);
    emit(kReportRx);
}

bool Power::member_power(ShortAddr addr, MemberPower &out) const {
    const MemberPower *m = slot(const_cast<std::array<MemberPower, k_members> &>(members_), addr);
    if (m == nullptr || !m->valid) {
        return false;
    }
    out = *m;
    return true;
}

uint32_t Power::lease_ms_for(ShortAddr addr, MonoTime now) const {
    MemberPower m;
    if (!member_power(addr, m) || m.mode == k_always_rx || now.to_ms() / 1000U > m.reported_s + uint64_t{k_max_age_s}) {
        return k_lease_base_ms;
    }
    const uint64_t want = 2ULL * m.interval_s * 1000U + k_lease_margin_ms;
    return static_cast<uint32_t>(std::min<uint64_t>(std::max<uint64_t>(want, k_lease_base_ms), k_lease_cap_ms));
}

// The member's next wake as an interval on the root clock. BOUNDED: one planned wake (REPORT_ONLY);
// ESTIMATED: the periodic windows of WINDOWED_RX extrapolated with the drift of both clocks. Anything else, or a
// report that is stale, is UNKNOWN: a target of unknown schedule waits, it is never called unreachable.
uint8_t Power::next_wake(ShortAddr addr, uint64_t now_ms, uint64_t &earliest_ms, uint64_t &latest_ms) const {
    MemberPower m;
    if (!member_power(addr, m) || m.quality == k_quality_unknown || m.mode == k_always_rx ||
        now_ms / 1000U > m.reported_s + uint64_t{k_max_age_s}) {
        return k_quality_unknown;
    }
    if (m.mode == k_windowed_rx) {
        const uint64_t period = uint64_t{m.interval_s} * 1000U;
        const uint64_t start = uint64_t{m.earliest_s} * 1000U; // report time less transit + first window phase
        if (period == 0 || now_ms < start) {
            return k_quality_unknown;
        }
        const uint64_t k = (now_ms - start) / period + 1U;
        const uint64_t g = required_guard_ms(k * period, k_ppm, k_ppm, k_transit_ms, policy_.guard_ms);
        earliest_ms = start + k * period > g ? start + k * period - g : 0;
        latest_ms = start + k * period + g;
        return k_quality_estimated;
    }
    earliest_ms = uint64_t{m.earliest_s} * 1000U;
    latest_ms = uint64_t{m.latest_s} * 1000U;
    return now_ms <= latest_ms ? k_quality_bounded : k_quality_unknown;
}

bool Power::sleepy_target(const DeviceId &dest, MonoTime now) const {
    if (members_.empty() || engine_.config().role != Role::Root) {
        return false;
    }
    const delivery::EndSession *s = engine_.delivery().sessions().find_peer(dest);
    MemberPower m;
    return s != nullptr && member_power(s->peer_addr, m) && m.mode != k_always_rx &&
           now.to_ms() / 1000U <= m.reported_s + uint64_t{k_max_age_s};
}

Duration Power::wait_for_wake(const DeviceId &dest, MonoTime now) const {
    if (members_.empty() || engine_.config().role != Role::Root) {
        return Duration{};
    }
    const delivery::EndSession *s = engine_.delivery().sessions().find_peer(dest);
    uint64_t lo = 0;
    uint64_t hi = 0;
    if (s == nullptr || next_wake(s->peer_addr, now.to_ms(), lo, hi) == k_quality_unknown || hi <= now.to_ms()) {
        return Duration{};
    }
    // The copy waits at the parent and reaches the target at its wake, so the receipt is normally back before
    // this runs out. Only then does the origin send it again (the parent may have lost the mailbox); the settle
    // time lets a target that had to re-attach after that finish doing so first.
    return Duration::from_ms(static_cast<int64_t>(hi - now.to_ms() + k_wake_settle_ms));
}

Power::WakeWait Power::target_wake(const DeviceId &dest, uint64_t expires_root_ms, MonoTime now, MonoTime &at) const {
    if (members_.empty() || engine_.config().role != Role::Root) {
        return WakeWait::None;
    }
    const delivery::EndSession *es = engine_.delivery().sessions().find_peer(dest); // the member reported through it
    uint64_t lo = 0;
    uint64_t hi = 0;
    if (es == nullptr || !es->rec.active() || next_wake(es->peer_addr, now.to_ms(), lo, hi) == k_quality_unknown) {
        return WakeWait::None; // unknown schedule: never waited for, never called unreachable
    }
    if (expires_root_ms != 0) {
        TargetFacts f;
        f.now_ms = now.to_ms();
        f.has_deadline = true;
        f.deadline_ms = expires_root_ms;
        f.wake_known = true;
        f.next_wake_earliest_ms = lo;
        if (target_wait(f) == Target::DeadlineUnreachable) {
            return WakeWait::Unreachable;
        }
    }
    if (lo <= now.to_ms() + k_wake_lead_ms) {
        return WakeWait::None;
    }
    at = now + Duration::from_ms(static_cast<int64_t>(lo - k_wake_lead_ms - now.to_ms()));
    return WakeWait::Wait;
}

// docs/22 §5 at submit time. Origin = the root; every other origin has no schedule and waits for the deadline.
Status Power::root_check_target(const DeviceId &dest, uint64_t expires_root_ms, MonoTime now) const {
    if (members_.empty() || engine_.config().role != Role::Root || expires_root_ms == 0) {
        return Status::Ok;
    }
    const delivery::EndSession *s = engine_.delivery().sessions().find_peer(dest);
    uint64_t lo = 0;
    uint64_t hi = 0;
    if (s == nullptr || next_wake(s->peer_addr, now.to_ms(), lo, hi) == k_quality_unknown) {
        return Status::Ok;
    }
    TargetFacts f;
    f.now_ms = now.to_ms();
    f.has_deadline = true;
    f.deadline_ms = expires_root_ms;
    f.wake_known = true;
    f.next_wake_earliest_ms = lo;
    return target_wait(f) == Target::DeadlineUnreachable ? Status::DeadlineUnreachable : Status::Ok;
}

// Device side: tell the root when we expect to be awake next (best effort; the ticket does not wait for the ACK).
void Power::send_report(MonoTime now) {
    delivery::PathSpec route;
    if (!engine_.identity().is_member() || engine_.config().role == Role::Root || !engine_.mesh().route_to_root(route, now)) {
        return;
    }
    Report r;
    r.mode = policy_.mode;
    r.kind = prep_req_.kind;
    r.policy_revision = static_cast<uint32_t>(policy_.revision);
    r.interval_ms = static_cast<uint32_t>(std::min<uint64_t>(prep_req_.sleep_ms, 86400000U));
    if ((prep_req_.sources & LM_WAKE_TIMER) != 0 && prep_req_.sleep_ms != 0) {
        const uint64_t g = required_guard_ms(prep_req_.sleep_ms, k_ppm, k_ppm, policy_.guard_ms, policy_.guard_ms);
        r.quality = k_quality_bounded;
        r.earliest_ms = static_cast<uint32_t>(prep_req_.sleep_ms > g ? prep_req_.sleep_ms - g : 0);
        r.latest_ms = static_cast<uint32_t>(std::min<uint64_t>(prep_req_.sleep_ms + g, 0xFFFFFFFFU));
    }
    std::array<uint8_t, 32> body{};
    std::size_t len = 0;
    if (encode(r, MutByteView{body}, len) != Status::Ok) {
        return;
    }
    if (engine_.delivery().send_control(engine_.identity().delegation().root, route, ByteView{body.data(), len}, now) ==
        Status::Ok) {
        ++stats_.reports_sent;
    }
}

} // namespace lm::power
