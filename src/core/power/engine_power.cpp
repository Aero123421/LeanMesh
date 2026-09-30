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
    // FIX13-D3: quiesce the RX producer, then take what the callback queued up to now through the ordinary receive path.
    // Anything there changes the node's state (a frame after the ticket was validated): the sleep is refused and the
    // radio goes on; the caller's ticket is spent (Power::enter/begin_sleep report SLEEP_TICKET_STALE).
    ports_.radio.hold_rx();
    port::RadioEvent late;
    if (ports_.radio.poll(late)) {
        on_radio_event(late, step_now_);
        (void)drain_radio(step_now_);
        ports_.radio.release_rx();
        return Status::SleepTicketStale;
    }
    if (const Status s = ports_.radio.stop(); s != Status::Ok) {
        ports_.radio.release_rx();
        enter_fault(); // a driver that cannot be stopped may still call back: like a failed lm_stop
        return s;
    }
    tx_.reinitialised();
    radio_state_ = RadioState::Asleep;
    return Status::Ok;
}

bool Engine::drain_radio(MonoTime now) {
    port::RadioEvent ev;
    int handled = 0;
    while (handled < k_max_radio_events_per_step && ports_.radio.poll(ev)) {
        on_radio_event(ev, now);
        ++handled;
    }
    return handled < k_max_radio_events_per_step;
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
