#include "core/diag/diag.hpp"

#include <cstring>

#include "core/engine.hpp"

namespace lm::diag {

void collect(Engine &e, MonoTime now, Snapshot &s) {
    s = Snapshot{};
    if (port::Health *h = e.health(); h != nullptr) {
        const port::HealthFacts f = h->read();
        if (f.reset_valid) {
            s.validity |= valid::reset_reason;
            s.reset_reason = static_cast<uint32_t>(f.reset);
        }
        if (f.heap_valid) {
            s.validity |= valid::heap;
            s.min_heap_bytes = f.min_heap_bytes;
        }
        if (f.stack_valid) {
            s.validity |= valid::stack;
            s.stack_free_bytes = f.stack_free_bytes;
        }
        if (f.cpu_valid) {
            s.validity |= valid::owner_cpu;
            s.owner_cpu_us = f.owner_cpu_us;
        }
        if (f.rx_ring_valid) {
            s.validity |= valid::rx_ring;
            s.rx_ring_depth = f.rx_ring_depth;
            s.rx_ring_dropped = f.rx_ring_dropped;
        }
        if (f.tx_power_valid) {
            s.validity |= valid::tx_power;
            s.tx_power_qdbm = f.tx_power_qdbm;
        }
        if (f.radio_recovery_valid) {
            s.validity |= valid::radio_recovery;
            s.radio_recovery_uptime_ms = f.radio_recovery_uptime_ms;
            s.radio_recovery_reason = f.radio_recovery_reason;
            s.radio_recovery_status = f.radio_recovery_status;
            s.radio_recovery_attempts = f.radio_recovery_attempts;
            s.radio_recovery_tx = f.radio_recovery_tx;
            s.radio_recovery_rx = f.radio_recovery_rx;
            s.radio_recovery_previous_boot = f.radio_recovery_previous_boot;
        }
    }

    // sdk: counters the owner keeps since the first lm_start (never reset, docs/16)
    const TxStats &tx = e.tx().stats();
    const delivery::HopStats &hop = e.delivery().hop_stats();
    s.validity |= valid::counters;
    s.tx_frames = tx.started;
    s.rx_frames = e.stats().rx_frames;
    s.link_retries = hop.retransmits + e.link().stats().hs_retransmits;
    s.rf_failures = tx.rf_failed;      // MacFailed only: the one RF-loss sample
    s.mac_unknown = tx.unknown;        // neither loss nor success
    s.unicast_acked = tx.unicast_acked;
    uint64_t refused = 0;              // admission refusals of the scheduler: our capacity, not RF
    for (const sched::ClassStats &c : e.sched().stats().cls) {
        refused += c.refused;
    }
    s.local_busy = tx.local_refused + tx.refused_isolated + refused + e.delivery().stats().rx_busy;
    s.validity |= valid::peers | valid::tx_depth;
    s.regular_peers = static_cast<uint32_t>(e.peers().regular_count());
    s.transient_peers = static_cast<uint32_t>(e.peers().transient_count());
    s.tx_depth = static_cast<uint32_t>(e.frames().in_use());
    s.radio_state = static_cast<uint32_t>(e.radio_state());
    if (!e.first_start().is_never()) {
        s.validity |= valid::interval;
        s.interval_us = static_cast<uint64_t>((now - e.first_start()).us);
    }
    if (e.identity().is_member()) {
        s.validity |= valid::root_term;
        s.root_term = static_cast<uint32_t>(e.identity().term().value());
    }
    int16_t rssi = 0;
    if (e.mesh().parent_rssi(rssi)) {
        s.validity |= valid::parent_rssi;
        s.parent_rssi_dbm = rssi;
    }
    const channel::Channel &ch = e.chan();
    if (ch.enabled()) {
        s.validity |= valid::channel;
        s.current_channel = e.channel();
        s.channel_epoch = static_cast<uint32_t>(ch.epoch().value());
        const bool planned = ch.mode() == channel::Mode::Prepared || ch.mode() == channel::Mode::Committed;
        s.pending_channel = planned && ch.plan().new_ch != e.channel() ? ch.plan().new_ch : 0;
    }

    // app
    s.validity |= valid::events | valid::operations;
    s.events_pending = static_cast<uint32_t>(e.events_pending());
    s.events_lost = e.events_lost();
    const delivery::Settle st = e.delivery().settle_state();
    s.ops_active = st.active;
    s.ops_uncommitted = st.uncommitted;
    s.ops_owed = st.owed;
}

void to_abi(const Snapshot &s, lm_diagnostics_t &o) {
    o = lm_diagnostics_t{};
    o.struct_size = sizeof(o);
    o.abi_version = LM_ABI_VERSION;
    o.validity_bits = s.validity & valid::abi_bits; // a bit only where the struct has the field
    const auto has = [&](uint64_t bit) { return (o.validity_bits & bit) != 0; };
    if (has(valid::root_term)) {
        o.root_term = s.root_term;
    }
    if (has(valid::channel)) {
        o.channel_epoch = s.channel_epoch;
        o.current_channel = s.current_channel;
        o.pending_channel = s.pending_channel;
    }
    if (has(valid::peers)) {
        o.regular_peers = s.regular_peers;
        o.transient_peers = s.transient_peers;
    }
    if (has(valid::tx_depth)) {
        o.tx_depth = s.tx_depth;
    }
    if (has(valid::rx_ring)) {
        o.rx_depth = s.rx_ring_depth;
    }
    if (has(valid::counters)) {
        o.tx_frames = s.tx_frames;
        o.rx_frames = s.rx_frames;
        o.link_retries = s.link_retries;
        o.rf_failures = s.rf_failures;
        o.local_busy = s.local_busy;
    }
    if (has(valid::owner_cpu)) {
        o.owner_cpu_us = s.owner_cpu_us;
    }
    if (has(valid::interval)) {
        o.interval_us = s.interval_us;
    }
    if (has(valid::parent_rssi)) {
        o.parent_rssi_dbm = s.parent_rssi_dbm;
    }
    if (has(valid::reset_reason)) {
        o.last_reset_reason = s.reset_reason;
    }
    if (has(valid::heap)) {
        o.min_heap_bytes = s.min_heap_bytes;
    }
    if (has(valid::stack)) {
        o.stack_free_bytes = s.stack_free_bytes;
    }
}

std::size_t features(const lm_capabilities_t &c, std::array<Feature, k_max_features> &out) {
    static constexpr struct {
        const char *name;
        uint64_t bit;
    } k_abi[] = {{"SMALL_MESSAGE", LM_FEATURE_SMALL_MESSAGE},
                 {"OBJECT_4K", LM_FEATURE_OBJECT_4K},
                 {"GROUP_FANOUT_V2", LM_FEATURE_GROUP_FANOUT_V2},
                 {"POWER_REPORT_ONLY", LM_FEATURE_POWER_REPORT_ONLY},
                 {"POWER_WINDOWED_RX", LM_FEATURE_POWER_WINDOWED_RX},
                 {"RAM_SESSION_RETAIN", LM_FEATURE_RAM_SESSION_RETAIN},
                 {"AUTO_CHANNEL", LM_FEATURE_AUTO_CHANNEL},
                 {"SIGNED_TRANSFER", LM_FEATURE_SIGNED_TRANSFER},
                 {"COMMISSIONING_WINDOW", LM_FEATURE_COMMISSIONING_WINDOW},
                 {"ROOT_HANDOVER", LM_FEATURE_ROOT_HANDOVER},
                 {"RTC_SECURE_RESUME_RESERVED", LM_FEATURE_RTC_SECURE_RESUME_RESERVED}};
    std::size_t n = 0;
    for (const auto &f : k_abi) {
        out[n++] = Feature{f.name, f.bit, (c.build_bits & f.bit) != 0, (c.implemented_bits & f.bit) != 0,
                           (c.enabled_bits & f.bit) != 0, (c.qualified_bits & f.bit) != 0, nullptr};
    }
    // OTA has no ABI bit (it is an independent release gate, docs/13 §6): the manifest check and the rollback
    // state exist when the option is compiled in; there is no image transfer, no writer, and nothing enables it.
#if defined(LM_OTA)
    constexpr bool ota_built = true;
#else
    constexpr bool ota_built = false;
#endif
    out[n++] = Feature{"OTA", 0, ota_built, false, false, false,
                       ota_built ? "manifest verification and rollback state only; no image transfer or flash writer"
                                 : "not built"};
    return n;
}

} // namespace lm::diag
