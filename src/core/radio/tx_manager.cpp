#include "core/radio/tx_manager.hpp"

namespace lm {

Status TxManager::begin(port::Radio &radio, const MacAddr &dst, ByteView frame, uint32_t tag,
                        MonoTime now) {
    if (isolated_) {
        ++stats_.refused_isolated;
        return Status::DriverResultUnknown;
    }
    if (in_flight_) {
        ++stats_.local_refused;
        return Status::Busy;
    }
    ++sequence_;
    if (sequence_ == 0) {
        sequence_ = 1;
    }
    const port::TxToken token{radio.driver_generation(), sequence_};
    const Status s = radio.transmit(dst, frame, token);
    if (s != Status::Ok) {
        if (is_local_resource_error(s)) {
            ++stats_.local_refused;
        }
        return s; // no TX exists: no outcome, no RF sample
    }
    in_flight_ = true;
    token_ = token;
    tag_ = tag;
    deadline_ = now + k_watchdog;
    ++stats_.started;
    return Status::Ok;
}

bool TxManager::on_tx_done(const port::RadioTxDone &done, TxOutcome &out) {
    if (isolated_ && done.token == unknown_token_) {
        ++stats_.late_after_unknown; // the result was already reported unknown: never upgrade it
        return false;
    }
    if (!in_flight_ || !(done.token == token_)) {
        ++stats_.unmatched;
        return false;
    }
    in_flight_ = false;
    const Duration service = done.at - (deadline_ + Duration{-k_watchdog.us});
    if (done.result != port::TxResult::Unknown && service.us > service_bound_.us && service <= k_watchdog) {
        service_bound_ = service;
    }
    out = TxOutcome{tag_, done.result, done.at};
    last_ = out;
    if (done.result == port::TxResult::MacAcked) {
        ++stats_.mac_acked;
    } else if (done.result == port::TxResult::MacFailed) {
        ++stats_.rf_failed;
    } else {
        ++stats_.unknown;
    }
    return true;
}

bool TxManager::check_watchdog(MonoTime now, TxOutcome &out) {
    if (!in_flight_ || now < deadline_) {
        return false;
    }
    in_flight_ = false;
    isolated_ = true;
    unknown_token_ = token_;
    ++stats_.unknown;
    out = TxOutcome{tag_, port::TxResult::Unknown, now};
    last_ = out;
    return true;
}

void TxManager::reinitialised() {
    in_flight_ = false;
    isolated_ = false;
    unknown_token_ = port::TxToken{};
}

} // namespace lm
