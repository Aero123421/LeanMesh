#include "core/link/link_layer.hpp"

#include "core/engine.hpp"

namespace lm::link {
namespace {

constexpr Duration k_rotation_retry = Duration::from_s(5);

bool is_session_kind(wire::FrameKind k) {
    return k == wire::FrameKind::Data || k == wire::FrameKind::HopAck ||
           k == wire::FrameKind::Route || k == wire::FrameKind::Control ||
           k == wire::FrameKind::Power;
}

} // namespace

bool LinkLayer::on_rx(const port::RadioRx &rx, MonoTime now) {
    ++stats_.rx_frames;
    const ByteView frame{rx.bytes.data(), rx.len};
    wire::LinkHeader h;
    ByteView payload;
    if (wire::decode_link_frame(frame, h, payload) != Status::Ok) {
        ++stats_.rx_malformed;
        return true;
    }
    if (h.kind == wire::FrameKind::Discovery || h.kind == wire::FrameKind::JoinProxy) {
        return false; // sessionless kinds belong to the join/mesh slices
    }
    if (!identity_.is_member()) {
        ++stats_.rx_no_identity;
        return true;
    }
    if (h.domain_hint != domain_hint_of(identity_.delegation().domain)) {
        ++stats_.rx_wrong_domain;
        return true;
    }
    if (h.kind == wire::FrameKind::Edhoc) {
        if (h.link_sid == 0) {
            exchange_.on_bootstrap(rx.src, payload, now);
        } else if (!exchange_.on_bind_frame(rx.src, h, frame, now)) {
            ++stats_.rx_unknown_sid;
        }
        return true;
    }
    SessionKeys *which = nullptr;
    Neighbor *n = neighbors_.by_rx_sid(rx.src, h.link_sid, which);
    if (n == nullptr) {
        ++stats_.rx_unknown_sid; // also every frame under an SID that died with a reboot
        return true;
    }
    if (!(now < which->valid_until)) {
        ++stats_.rx_expired;
        return true;
    }
    Opened op;
    switch (open_frame(*which, h, frame, op)) {
    case Status::Ok:
        which->rec.accept(h.link_counter); // only after the tag verified (docs/06 §6)
        ++stats_.rx_accepted;
        return deliver(*n, h, op, false);
    case Status::Replay:
        if (op.verdict == sec::ReplayVerdict::Duplicate) {
            ++stats_.rx_replay_dup;
            return deliver(*n, h, op, true);
        }
        ++stats_.rx_replay_old;
        return true;
    case Status::AuthRejected:
        ++stats_.rx_auth_fail;
        return true;
    case Status::SessionRefreshRequired:
        ++stats_.rx_expired;
        return true;
    default:
        ++stats_.rx_malformed;
        return true;
    }
}

bool LinkLayer::deliver(const Neighbor &n, const wire::LinkHeader &h, const Opened &op, bool duplicate) {
    if (sink_ == nullptr || !is_session_kind(h.kind)) {
        ++stats_.rx_no_consumer;
        return false;
    }
    RxInfo info;
    info.kind = h.kind;
    info.src = n.mac;
    info.peer = n.device;
    info.address = n.address;
    info.counter = h.link_counter;
    info.duplicate = duplicate;
    sink_(sink_ctx_, info, op.view());
    return true;
}

// Rotation time of one neighbour: age-based (the lower DeviceId first, the other only as a
// fallback so a silent peer cannot pin an old key) or immediately once the record threshold hit.
MonoTime LinkLayer::rotation_time(const Neighbor &n) const {
    if (!n.cur.active) {
        return MonoTime::never();
    }
    if (n.rotate_wanted) {
        return MonoTime{0};
    }
    const bool lower = identity_.self() < n.device;
    return n.cur.born + (lower ? policy_.rotate_lower_id : policy_.rotate_higher_id);
}

void LinkLayer::on_timer(MonoTime now) {
    PeerHandle released[k_max_neighbors];
    const std::size_t n = neighbors_.sweep(now, released, k_max_neighbors);
    for (std::size_t i = 0; i < n; ++i) {
        (void)shared_.engine.release_peer(released[i]);
        ++stats_.sessions_expired;
    }
    exchange_.on_timer(now);
    if (exchange_.busy() || !identity_.is_member() || now < rotation_retry_) {
        return;
    }
    Neighbor *due = nullptr;
    neighbors_.for_each([&](Handle, Neighbor &nb) {
        if (due == nullptr && now >= rotation_time(nb)) {
            due = &nb;
        }
    });
    if (due != nullptr) {
        ++stats_.rotations_started;
        if (exchange_.start_initiator(due->mac, now) != Status::Ok) {
            rotation_retry_ = now + k_rotation_retry; // gate/busy/capacity: try again later
        }
    }
}

MonoTime LinkLayer::deadline() const {
    MonoTime next = earliest(exchange_.deadline(), neighbors_.next_expiry());
    if (!exchange_.busy() && identity_.is_member()) {
        MonoTime rot = MonoTime::never();
        const_cast<Neighbors &>(neighbors_).for_each(
            [&](Handle, Neighbor &nb) { rot = earliest(rot, rotation_time(nb)); });
        if (!rot.is_never()) {
            next = earliest(next, rot < rotation_retry_ ? rotation_retry_ : rot);
        }
    }
    return next;
}

void LinkLayer::stop() {
    exchange_.stop();
    PeerHandle handles[k_max_neighbors];
    std::size_t n = 0;
    neighbors_.for_each([&](Handle, Neighbor &nb) {
        if (n < k_max_neighbors) {
            handles[n++] = nb.peer;
        }
    });
    for (std::size_t i = 0; i < n; ++i) {
        (void)shared_.engine.release_peer(handles[i]);
    }
    Neighbor *all[k_max_neighbors];
    std::size_t m = 0;
    neighbors_.for_each([&](Handle, Neighbor &nb) { all[m++] = &nb; });
    for (std::size_t i = 0; i < m; ++i) {
        neighbors_.remove(*all[i]);
    }
    rotation_retry_ = MonoTime{0};
}

Status LinkLayer::connect(const MacAddr &mac, MonoTime now, bool replace) {
    if (!replace) {
        const Neighbor *n = neighbors_.find_mac(mac);
        if (n != nullptr && n->cur.active) {
            return Status::Conflict;
        }
    }
    return exchange_.start_initiator(mac, now);
}

Status LinkLayer::seal(const DeviceId &peer, wire::FrameKind kind, ByteView plain, SealedFrame &out,
                       MonoTime now) {
    if (!is_session_kind(kind)) {
        return Status::InvalidArgument;
    }
    Neighbor *n = neighbors_.find_device(peer);
    if (n == nullptr || !n->cur.active) {
        ++stats_.tx_refused;
        return Status::AuthPending;
    }
    if (!(now < n->cur.valid_until)) {
        ++stats_.tx_refused;
        return Status::SessionRefreshRequired;
    }
    const Status st = seal_frame(n->cur, kind, domain_hint_of(identity_.delegation().domain),
                                 n->cur.tx_sid, plain, out);
    if (st != Status::Ok) {
        ++stats_.tx_refused;
        return st;
    }
    ++stats_.tx_sealed;
    if (n->cur.rec.tx_used() >= policy_.rotate_records) {
        n->rotate_wanted = true;
    }
    return Status::Ok;
}

Status LinkLayer::close(const DeviceId &peer) {
    Neighbor *n = neighbors_.find_device(peer);
    if (n == nullptr) {
        return Status::NotFound;
    }
    (void)shared_.engine.release_peer(n->peer);
    neighbors_.remove(*n);
    return Status::Ok;
}

} // namespace lm::link
