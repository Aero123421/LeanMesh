// Delivery's plug points for the mesh module (decision S11-D2): the node<->root control lane on the
// end session, unauthenticated routed carriers for the join tunnel, and session/route helpers. The
// mesh never touches end sessions or the TX pool itself.
#include "core/delivery/delivery.hpp"

#include <cstring>

#include "core/engine.hpp"
namespace lm::delivery {

bool Delivery::has_session(const DeviceId &peer, MonoTime now) {
    const EndSession *s = sessions_.find_peer(peer);
    return s != nullptr && !s->suspect && s->rec.active() && now < s->valid_until;
}

Status Delivery::start_session(const DeviceId &peer, const PathSpec &route, MonoTime now) {
    if (has_session(peer, now)) {
        return Status::Conflict;
    }
    if (link_.exchange().busy()) {
        return Status::Busy;
    }
    return link_.exchange().start_end(peer, route, now);
}

// The record is sealed into a pool frame borrowed for the call, right behind the room for the route header (P9);
// a control record has no MessageId meaning and no deadline.
Status Delivery::send_control(const DeviceId &peer, const PathSpec &route, ByteView body, MonoTime now, Handle owner) {
    EndSession *s = sessions_.find_peer(peer);
    if (s == nullptr || s->suspect || !s->rec.active() || !(now < s->valid_until)) {
        return Status::AuthPending;
    }
    if (route.len < 1 || body.empty() || body.size() > wire::data_capacity(route.len)) {
        return Status::PayloadTooLarge;
    }
    wire::EndHeader eh;
    eh.app_port = 0;
    eh.record_kind = wire::RecordKind::Control;
    eh.flags = wire::make_end_flags(wire::Delivery::BestEffort, wire::Priority::Control, false);
    Lease scratch{engine_.frames()};
    if (!scratch.ok()) {
        return Status::NoCapacity; // every pool frame is in use: a local shortage, the caller asks again
    }
    std::size_t rlen = 0;
    LM_TRY(seal_end_record(*s, s->tx_sid, route.term, eh, body, record_area(scratch, route.len), rlen));
    sessions_.touch(*s);
    Status why = Status::Ok;
    return build_and_send(route, scratch, rlen, OwnerKind::Mesh, owner, now, why) ? Status::Ok : why;
}

Status Delivery::send_routed(const PathSpec &route, ByteView record, OwnerKind kind, Handle owner, MonoTime now) {
    Status why = Status::Ok;
    return build_and_send(route, record, kind, owner, now, why) ? Status::Ok : why;
}

} // namespace lm::delivery
