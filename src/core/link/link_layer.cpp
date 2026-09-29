#include "core/link/link_layer.hpp"

#include "core/engine.hpp"
#include "core/route/forward.hpp"

namespace lm::link {
namespace {

constexpr Duration k_rotation_retry = Duration::from_s(5);

bool is_session_kind(wire::FrameKind k) {
    return k == wire::FrameKind::Data || k == wire::FrameKind::HopAck ||
           k == wire::FrameKind::Route || k == wire::FrameKind::Control ||
           k == wire::FrameKind::Power;
}

// A routed DATA body whose end record belongs to an application (app_port 1..65534): data, receipts and fragments
// of messages. SDK control (port 0: handshake carriers, the join tunnel, mesh and time control) is not.
bool carries_app_data(ByteView plain) {
    wire::RouteHeader h;
    ByteView record;
    if (wire::decode_route(plain, h, record) != Status::Ok || record.size() < wire::k_end_header_bytes) {
        return false;
    }
    Reader r{record.subspan(28, 2)}; // end header: app_port at offset 28 (docs/09 §4)
    return r.u16be() != 0;
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
    if (proxy_sink_ != nullptr && proxy_sink_(proxy_ctx_, rx, now)) {
        return true; // [S11] carried for a joiner behind us
    }
    if (h.kind == wire::FrameKind::Discovery) {
        if (disc_sink_ == nullptr) {
            return false;
        }
        if (identity_.is_member() && h.domain_hint == domain_hint_of(identity_.delegation().domain)) {
            disc_sink_(disc_ctx_, rx.src, payload, now); // [S11] a hint of our own domain
        }
        return true;
    }
    if (h.kind == wire::FrameKind::JoinProxy) {
        // [S8] Unjoined device <-> root carrier. Discovery hints go to the join module, everything
        // else is an object of the (single) exchange in join mode; the exchange applies the policy.
        wire::BootstrapCarrier c;
        if (wire::decode_bootstrap(payload, c) != Status::Ok) {
            ++stats_.rx_malformed;
        } else if (c.object_kind >= member::k_obj_join_hello) {
            if (shared_.join.discovery != nullptr) {
                shared_.join.discovery(shared_.join.ctx, rx.src, c);
            }
        } else {
            exchange_.on_bootstrap(rx.src, payload, now, true);
        }
        return true;
    }
    // An unjoined device only takes the frames of its own JOIN_ONLY handshake and session (SESSION_BIND
    // and CONTROL under a SID it reserved); the SID/AEAD lookups below find nothing else for it.
    const bool member = identity_.is_member();
    const bool join_traffic = h.link_sid != 0 && (h.kind == wire::FrameKind::Edhoc ||
                                                  h.kind == wire::FrameKind::Control);
    if (!member && !join_traffic) {
        ++stats_.rx_no_identity;
        return true;
    }
    if (member && h.domain_hint != domain_hint_of(identity_.delegation().domain)) {
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
        if (!admissible(*n, h.kind, op.view())) {
            // Authentic but not for us / not parseable: the window stays where it is (SEC-D11). DATA still
            // goes to the delivery layer, which derives the same drop and answers REJECTED.
            ++stats_.rx_inadmissible;
            return h.kind == wire::FrameKind::Data ? deliver(*n, h, op, false) : true;
        }
        if (n->lease_uncertain && h.kind == wire::FrameKind::Data && carries_app_data(op.view())) {
            // SEC-D3: not accepted either: the same frame is judged again once the peer's lease is proven.
            ++stats_.rx_lease_restricted;
            return deliver(*n, h, op, false, true);
        }
        which->rec.accept(h.link_counter); // only after the tag and the minimum checks (docs/06 §6)
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

// The minimum checks of docs/06 §6 ("AEAD成功と宛先/長さ検査前にwindowを消費しない"), SEC-D11. The frame
// decoder already fixed the lengths of every kind. DATA must also be a routed body whose header names this
// node as the next hop of this very sender in the current term (the forwarding decision of docs/04 §4 the
// delivery layer takes again), with an end record a relay may carry or this node may open; a HOP_ACK must
// parse. The bodies of ROUTE / CONTROL / POWER are their consumers' formats and are not judged here.
bool LinkLayer::admissible(const Neighbor &n, wire::FrameKind kind, ByteView plain) const {
    if (kind == wire::FrameKind::HopAck) {
        wire::HopAck a;
        return wire::decode_hop_ack(plain, a) == Status::Ok;
    }
    if (kind != wire::FrameKind::Data) {
        return true;
    }
    if (n.join_only || !identity_.is_member()) {
        return false; // DATA never travels on a JOIN_ONLY session, nor to a device without membership
    }
    wire::RouteHeader h;
    ByteView record;
    if (wire::decode_route(plain, h, record) != Status::Ok) {
        return false;
    }
    const member::MemberCredential &self = identity_.member();
    const route::Decision d = route::decide_forward(h, self.address, n.address, self.root_term);
    if (d.action == route::Action::Drop) {
        return false;
    }
    wire::EndHeader eh;
    ByteView sealed;
    return d.action == route::Action::Forward ? record.size() >= wire::k_end_header_bytes
                                              : wire::decode_end_record(record, eh, sealed) == Status::Ok;
}

bool LinkLayer::deliver(const Neighbor &n, const wire::LinkHeader &h, const Opened &op, bool duplicate,
                        bool restricted) {
    if (n.join_only) {
        // JOIN_ONLY carries the join objects and nothing else (docs/06 §9): DATA/ROUTE never pass.
        if (h.kind != wire::FrameKind::Control || shared_.join.join_control == nullptr) {
            ++stats_.rx_no_consumer;
            return true;
        }
        RxInfo info;
        info.kind = h.kind;
        info.src = n.mac;
        info.peer = n.device;
        info.counter = h.link_counter;
        info.duplicate = duplicate;
        shared_.join.join_control(shared_.join.ctx, info, op.view());
        return true;
    }
    if (h.kind == wire::FrameKind::Control && shared_.join.link_control != nullptr) {
        RxInfo info;
        info.kind = h.kind;
        info.src = n.mac;
        info.peer = n.device;
        info.address = n.address;
        info.counter = h.link_counter;
        info.duplicate = duplicate;
        if (shared_.join.link_control(shared_.join.ctx, info, op.view())) {
            return true; // a leave notice: consumed by the membership module
        }
    }
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
    info.restricted = restricted;
    sink_(sink_ctx_, info, op.view());
    return true;
}

// Rotation time of one neighbour: age-based (the lower DeviceId first, the other only as a
// fallback so a silent peer cannot pin an old key) or immediately once the record threshold hit.
MonoTime LinkLayer::rotation_time(const Neighbor &n) const {
    if (!n.cur.active || n.join_only) { // a JOIN_ONLY session is never rotated: it ends with the join
        return MonoTime::never();
    }
    if (shared_.engine.power().child_asleep(n.mac, shared_.engine.step_time())) {
        return MonoTime::never(); // [S16] a sleeping child is not asked for a handshake; its next poll re-arms this
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
    if (n->lease_uncertain && kind == wire::FrameKind::Data && carries_app_data(plain)) {
        ++stats_.tx_lease_restricted; // SEC-D3: its authorisation cannot be proven yet
        return Status::TimeUncertain;
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

Status LinkLayer::seal_join(const DeviceId &peer, uint32_t domain_hint, ByteView plain, SealedFrame &out,
                            MonoTime now) {
    Neighbor *n = neighbors_.find_join(peer);
    if (n == nullptr || !n->cur.active) {
        return Status::AuthPending;
    }
    if (!(now < n->cur.valid_until)) {
        return Status::Expired;
    }
    const Status st = seal_frame(n->cur, wire::FrameKind::Control, domain_hint, n->cur.tx_sid, plain, out);
    if (st == Status::Ok) {
        ++stats_.tx_sealed;
    }
    return st;
}

Status LinkLayer::close_join(const DeviceId &peer) {
    Neighbor *n = neighbors_.find_join(peer);
    if (n == nullptr) {
        return Status::NotFound;
    }
    const PeerHandle h = n->peer;
    neighbors_.remove(*n);
    return shared_.engine.release_peer(h);
}

void LinkLayer::revalidate(const RootTimeBound &bound, MonoTime now) {
    DeviceId over[k_max_neighbors];
    std::size_t n = 0;
    neighbors_.for_each([&](Handle, Neighbor &nb) {
        if (nb.join_only || !nb.cur.active) {
            return; // a JOIN_ONLY session holds no member credential
        }
        switch (check_deadline(bound, nb.lease)) {
        case DeadlineCheck::After:
            if (n < k_max_neighbors) {
                over[n++] = nb.device;
            }
            break;
        case DeadlineCheck::Before:
            nb.lease_uncertain = false;
            nb.cur.valid_until = earliest(nb.cur.valid_until, member::lease_local_end(bound, nb.lease, now));
            break;
        case DeadlineCheck::Uncertain:
            nb.lease_uncertain = true;
            break;
        }
    });
    for (std::size_t i = 0; i < n; ++i) {
        if (close(over[i]) == Status::Ok) {
            ++stats_.sessions_lease_expired;
        }
    }
    exchange_.revalidate_end(bound, now);
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
