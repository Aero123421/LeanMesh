// The parts of Delivery that only power needs (S16): what a sleep would cut, the shortest session life, and the
// waiting timers that must not run into a sleep gap. Defined here to keep the power slice out of delivery*.cpp.
#include "core/delivery/delivery.hpp"

namespace lm::delivery {

// docs/20 §10. `active`: sends still in progress, `uncommitted`: a journal record not durable yet,
// `owed`: a received message whose event the application has not taken.
Settle Delivery::settle_state() const {
    Settle s;
    for (std::size_t i = 0; i < k_actives; ++i) {
        const Active *a = actives_.get(actives_.handle_at(i));
        if (a != nullptr) {
            ++s.active;
            s.uncommitted += (a->durable && a->persisted_version < a->version) ? 1U : 0U;
        }
    }
    for (const InLive &l : lives_) {
        if (l.used) {
            s.uncommitted += l.persisted_version < l.version ? 1U : 0U;
            s.owed += l.event_owed ? 1U : 0U;
        }
    }
    return s;
}

// The shortest remaining key life over the end sessions (link sessions are asked from the neighbour table).
Duration Delivery::min_key_life(MonoTime now) const {
    Duration d = Duration::from_s(1LL << 40);
    sessions_.for_each_active([&](const EndSession &s) {
        if (!s.valid_until.is_never() && s.valid_until - now < d) {
            d = s.valid_until - now;
        }
    });
    link_.neighbors().for_each([&](Handle, link::Neighbor &n) {
        if (n.cur.active && !n.join_only && !n.cur.valid_until.is_never() && n.cur.valid_until - now < d) {
            d = n.cur.valid_until - now;
        }
    });
    return d;
}

// Timers that measure waiting (retry, receipt rounds, route waits) do not count the time asleep: a receipt
// parked at the parent is not "late". Lifetimes (keys, leases, message deadlines) are not touched.
void Delivery::sleep_gap(Duration gap) {
    for (std::size_t i = 0; i < k_actives; ++i) {
        Active *a = actives_.get(actives_.handle_at(i));
        if (a != nullptr) {
            a->next_at = a->next_at + gap;
            a->round_at = a->round_at + gap;
        }
    }
    retry_kick_ = retry_kick_ + gap;
}

} // namespace lm::delivery
