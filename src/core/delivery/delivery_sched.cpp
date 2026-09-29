// Delivery <-> scheduler (S14): which sends may take an operation slot, and LATEST coalescing.
// Admission is by class so a BULK flood cannot keep URGENT and NORMAL sends out (the same headroom
// rule as the TX frame pool, radio/tx_pool.hpp); a refusal says why and when to look again.
#include "core/delivery/delivery.hpp"
#include "core/engine.hpp"

namespace lm::delivery {
namespace {

// Unmeasured default until the RF qualification measures the drain time of a full queue.
constexpr uint32_t k_admit_retry_ms = 500;
// BULK may hold at most half of the operation slots (at least one).
constexpr std::size_t k_bulk_share = k_actives / 2 > 0 ? k_actives / 2 : 1;

sched::Class class_of_priority(uint8_t p) { return sched::class_of(static_cast<wire::Priority>(p & 3U)); }

} // namespace

Reply Delivery::admit_send(const lm_send_request_t &rq, const DeviceId &dest, Handle &victim) {
    victim = Handle{};
    const bool latest = rq.queue_mode == LM_LATEST;
    if (rq.queue_mode > LM_LATEST || (!latest && rq.coalesce_key != 0)) {
        return Reply{Status::InvalidArgument, 0, 0};
    }
    // A latest value replaces only a record that was never handed to the radio, so it is only allowed
    // where losing the older record is harmless: best effort, volatile (docs/08 §1).
    if (latest && (rq.delivery != LM_BEST_EFFORT || rq.storage != LM_VOLATILE)) {
        return Reply{Status::InvalidArgument, 0, 0};
    }
    std::size_t bulk_live = 0;
    for (std::size_t i = 0; i < k_actives; ++i) {
        const Handle h = actives_.handle_at(i);
        const Active *a = actives_.get(h);
        if (a == nullptr) {
            continue;
        }
        const Op &op = ops_[a->op];
        if (latest && victim.is_none() && a->latest && a->key == rq.coalesce_key && op.dest == dest &&
            op.port == rq.app_port && !a->cancelled && !left_node(h, op)) {
            victim = h;
            continue; // it goes away before the new one is created: it does not count against the class
        }
        bulk_live += class_of_priority(op.priority) == sched::Class::Bulk ? 1U : 0U;
    }
    const sched::Class cls = class_of_priority(static_cast<uint8_t>(rq.priority));
    if (cls == sched::Class::Bulk && bulk_live >= k_bulk_share) {
        ++stats_.admit_refused;
        victim = Handle{}; // nothing changes when the request is refused
        Reply r{Status::NoCapacity, 0, 0};
        r.retry_after_ms = k_admit_retry_ms;
        r.queue_depth = static_cast<uint16_t>(bulk_live);
        return r;
    }
    return Reply{Status::Ok, 0, 0};
}

// Every refusal for lack of local capacity is counted under the class of the request and says how
// long to wait and how full the queue is (a local shortage, never RF loss).
Reply Delivery::send(const lm_send_request_t &rq, ByteView payload, MonoTime now) {
    Reply r = send_impl(rq, payload, now);
    if (r.status == Status::NoCapacity || r.status == Status::Busy) {
        engine_.sched().note_refused(class_of_priority(static_cast<uint8_t>(rq.priority)));
        if (r.retry_after_ms == 0) {
            r.retry_after_ms = k_admit_retry_ms;
            std::size_t live = 0;
            for (std::size_t i = 0; i < k_actives; ++i) {
                live += actives_.get(actives_.handle_at(i)) != nullptr ? 1U : 0U;
            }
            r.queue_depth = static_cast<uint16_t>(live);
        }
    }
    return r;
}

// The replaced send ends SUPERSEDED. Its operation event carries the new operation id (8 bytes, big
// endian) as its payload: that is the cause ("superseded_by") the application can look up.
void Delivery::supersede(Handle victim, uint64_t by_op, MonoTime now) {
    Active *a = actives_.get(victim);
    if (a == nullptr) {
        return;
    }
    Op &op = ops_[a->op];
    for (unsigned i = 0; i < 8; ++i) {
        op.result[i] = static_cast<uint8_t>(by_op >> (56U - 8U * i));
    }
    op.result_len = 8;
    ++stats_.superseded;
    finalize_active(victim, LM_OUTCOME_SUPERSEDED, static_cast<uint32_t>(Status::Ok), now);
}

} // namespace lm::delivery
