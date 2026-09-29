// Delivery <-> Host bridge glue (S13, root only in practice): the Host's SEND with its own MessageId,
// its HOST_STORE_ACK, and the root clock estimate it derives deadlines from.
#include "core/delivery/delivery.hpp"
#include "core/engine.hpp"

namespace lm::delivery {

Reply Delivery::host_send(const HostSendRequest &rq, ByteView payload, MonoTime now) {
    host_tag_ = &rq; // consulted by send() at exactly three places; never left set
    const Reply r = send(rq.rq, payload, now);
    host_tag_ = nullptr;
    return r;
}

// The Host committed the message: only now does the origin hear END_RECEIVED (for a gated message) and
// the root release its copy (payload, journal record). Idempotent: an ACK repeated after a lost
// response finds the entry already taken. An unknown message is NOT_FOUND, never a fake success.
Status Delivery::host_store_ack(const HostStoreAckRequest &rq, MonoTime now) {
    for (std::size_t i = 0; i < k_in_entries; ++i) {
        const Handle h = in_.handle_at(i);
        InEntry *e = in_.get(h);
        if (e == nullptr || e->mid != rq.mid || e->origin != rq.origin) {
            continue;
        }
        if (e->hash != rq.hash) {
            return Status::Conflict;
        }
        if (e->st == InEntry::St::Committing) {
            return Status::Conflict; // the root itself has not stored it: nothing to acknowledge yet
        }
        if (e->gated) {
            e->gated = false;
            send_receipt(*e, ReceiptEv::EndReceived, 0, now);
        }
        if (e->st == InEntry::St::Held && !e->event_owed) {
            finish_take(h, *e, now); // the application (the bridge) took it earlier and kept it for the Host
        }
        return Status::Ok;
    }
    return Status::NotFound;
}

RootTimeBound Delivery::root_time(MonoTime now) {
    refresh_bound(now);
    return bound_;
}

} // namespace lm::delivery
