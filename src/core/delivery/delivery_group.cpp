// Delivery <-> group fan-out glue (S15): a group target is an ordinary send whose MessageId the group
// reserved, and whose lifecycle (events, generation check) the group owns.
#include "core/delivery/delivery.hpp"
#include "core/engine.hpp"

namespace lm::delivery {
namespace {
Reply reply(Status s, uint64_t op = 0) { return Reply{s, op, 0}; }
} // namespace

Reply Delivery::send_child(const lm_send_request_t &rq, ByteView payload, const std::array<uint8_t, 16> &mid,
                           MonoTime now) {
    child_mid_ = &mid; // consulted by send_impl() at exactly two places; never left set
    const Reply r = send(rq, payload, now);
    child_mid_ = nullptr;
    return r;
}

bool Delivery::probe(const DeviceId &dest, const std::array<uint8_t, 16> &mid, lm_operation_t &out) {
    const Op *op = find_op_by_message(dest, mid);
    if (op == nullptr) {
        return false;
    }
    fill_operation(*op, out);
    return true;
}

Reply Delivery::cancel_child(const DeviceId &dest, const std::array<uint8_t, 16> &mid, MonoTime now) {
    const Op *op = find_op_by_message(dest, mid);
    return op == nullptr ? reply(Status::NotFound) : cancel(op->id, now);
}

Status Delivery::deadline_status(uint64_t expires, uint32_t term) {
    refresh_bound(engine_.step_time());
    switch (own_deadline(expires, term)) {
    case DeadlineCheck::After:
        return Status::Expired;
    case DeadlineCheck::Uncertain:
        return Status::TimeUncertain;
    case DeadlineCheck::Before:
        break;
    }
    return Status::Ok;
}

Delivery::SeqBlock Delivery::reserve_sequences(uint32_t n) {
    const SeqBlock b{durable_.incarnation(), next_seq_};
    next_seq_ += n;
    return b;
}

} // namespace lm::delivery
