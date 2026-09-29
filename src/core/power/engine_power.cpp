// Engine services for the power module (S16): the radio driver goes off and comes back with all RAM state kept.
#include "core/engine.hpp"

namespace lm {

// Sleep or a withheld radio: only the driver stops. Sessions, counters, routes and queued frames stay (docs/20 §7
// row 1); the peer table of the driver is rebuilt from the registry at wake. Never called with a frame on the air
// (the ticket requires quiescence).
Status Engine::radio_sleep() {
    if (radio_state_ == RadioState::Asleep) {
        return Status::Ok; // already confirmed off
    }
    if (radio_state_ != RadioState::Running) {
        return Status::Busy; // starting, recovering or failed: there is no driver state to put to sleep
    }
    if (const Status s = ports_.radio.stop(); s != Status::Ok) {
        enter_fault(); // a driver that cannot be stopped may still call back: like a failed lm_stop
        return s;
    }
    tx_.reinitialised();
    radio_state_ = RadioState::Asleep;
    return Status::Ok;
}

void Engine::radio_wake(MonoTime now) {
    if (radio_state_ != RadioState::Asleep) {
        return;
    }
    if (bring_up_radio() == Status::Ok) {
        radio_state_ = RadioState::Running;
        return;
    }
    radio_state_ = RadioState::Recovering; // the watchdog path retries three times, then FAULT
    recover_attempts_ = 0;
    recover_at_ = now;
}

} // namespace lm
