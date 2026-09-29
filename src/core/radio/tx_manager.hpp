// The single physical TX in flight (docs/03 §4). Owner only.
//
// Every transmission gets TxToken{driver_generation, sequence}. A completion is credited only to
// the in-flight record with an equal token: an old callback (older sequence, older driver
// generation, or one that arrives after the watchdog already declared the result unknown) is never
// attributed to a later frame. When no callback arrives within 1000 ms the result is UNKNOWN,
// further TX is refused (isolated) until the owner re-initialised the radio (new driver generation)
// and called reinitialised().
//
// Failure classes are kept apart: MacFailed is the only RF-loss sample. Busy / NoCapacity from the
// driver, a full previous TX, or isolation are local conditions: they create no outcome and are
// never counted as link failures.
#pragma once

#include <cstdint>

#include "core/ports.hpp"
#include "core/time.hpp"

namespace lm {

struct TxOutcome {
    uint32_t tag = 0; // the caller's frame identity (opaque to the manager)
    port::TxResult result = port::TxResult::Unknown;
    MonoTime at;
};

struct TxStats {
    uint64_t started = 0;
    uint64_t mac_acked = 0;
    uint64_t rf_failed = 0;           // MacFailed: the only RF-loss evidence
    uint64_t unknown = 0;             // watchdog: neither loss nor success
    uint64_t local_refused = 0;       // driver Busy/NoCapacity (BUSY/NO_MEM): never RF loss
    uint64_t refused_isolated = 0;    // refused while the result of an earlier TX is unknown
    uint64_t unmatched = 0;           // completion for no in-flight record (stale/early/foreign)
    uint64_t late_after_unknown = 0;  // completion of a frame already reported unknown
};

class TxManager {
  public:
    static constexpr Duration k_watchdog = Duration::from_ms(1000);

    // Status::Busy: a TX is already in flight (or the driver refused: local, not RF loss).
    // Status::DriverResultUnknown: isolated after a watchdog until reinitialised().
    [[nodiscard]] Status begin(port::Radio &radio, const MacAddr &dst, ByteView frame, uint32_t tag,
                               MonoTime now);
    // True and `out` filled when `done` belongs to the in-flight record.
    [[nodiscard]] bool on_tx_done(const port::RadioTxDone &done, TxOutcome &out);
    // True (once) when the deadline passed without completion: `out` is the UNKNOWN outcome.
    [[nodiscard]] bool check_watchdog(MonoTime now, TxOutcome &out);
    // Radio was stopped/started again: the old driver instance and its callbacks are gone.
    void reinitialised();

    [[nodiscard]] MonoTime deadline() const { return in_flight_ ? deadline_ : MonoTime::never(); }
    [[nodiscard]] bool in_flight() const { return in_flight_; }
    [[nodiscard]] bool isolated() const { return isolated_; }
    [[nodiscard]] const TxStats &stats() const { return stats_; }
    // The most recent outcome (diagnostics and tests; consumers act on it in on_tx_outcome).
    [[nodiscard]] const TxOutcome &last_outcome() const { return last_; }

  private:
    bool in_flight_ = false;
    bool isolated_ = false;
    port::TxToken token_;
    port::TxToken unknown_token_;
    uint32_t tag_ = 0;
    uint32_t sequence_ = 0;
    MonoTime deadline_;
    TxOutcome last_;
    TxStats stats_;
};

} // namespace lm
