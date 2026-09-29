// End mode of the exchange (EDHOC purpose 2, docs/06 §4-§9) between two members that are not
// neighbours. Same state machine as a link exchange; what differs is here:
//   carrier   an end record with end_sid = k_handshake_sid, kind CONTROL, port 0, plaintext = one
//             in-order chunk (member::JoinChunk, tag = object kind), tag field zero (S9-D2). It is
//             only authenticated hop by hop; EDHOC and the credential chain authenticate the peers,
//             and nothing of it reaches the application. Fragments are sent one at a time, each
//             after the previous one was HOP_ACCEPTED (window 1, bounded TX pool use).
//   binding   SESSION_BIND/ACK is the record sealed under the new keys (header SID = the sender's
//             own reserved SID, S5-D3), carried as objects 7/8 so that it can be split.
//   peer      the requested DeviceId (initiator) and a route; the verified MemberCredential must
//             name the route's final address; the session goes to the delivery module's table.
#include <cstring>
#include <utility>

#include "core/engine.hpp"
#include "core/link/exchange.hpp"
#include "core/wire/cbor.hpp"

namespace lm::link {

Status Exchange::start_end(const DeviceId &peer, const delivery::PathSpec &route, MonoTime now) {
    if (!s_.identity.is_member()) {
        return Status::AuthPending;
    }
    if (end_.send == nullptr || end_.sessions == nullptr) {
        return Status::Unsupported;
    }
    LM_TRY(admission()); // SEC-D2
    if (busy()) {
        return Status::Busy;
    }
    if (phase_ == Phase::Linger) {
        finish_idle();
    }
    if (route.len == 0 || peer == s_.identity.self()) {
        return Status::InvalidArgument;
    }
    if (!end_gate_.allow(peer, now, s_.policy.handshake_gate)) {
        ++end_stats_.rate_limited;
        return Status::RateLimited;
    }
    begin_common(Mode::End, true, now);
    peer_id_ = peer;
    peer_known_ = true;
    route_ = route;
    end_gate_.touch(peer, now); // we chose to spend a full handshake on this peer
    s_.engine.random(MutByteView{xid_});
    phase_ = Phase::SendCred;
    expect_ = ObjKind::CredR;
    send_object(ObjKind::CredI, false);
    pump(now);
    return Status::Ok;
}

void Exchange::on_end_carrier(const delivery::PathSpec &reply, const wire::EndHeader &h,
                              ByteView plain, delivery::OpenedEnd &scratch, MonoTime now) {
    member::JoinChunk c;
    if (member::decode_chunk(plain, c) != Status::Ok || c.ack ||
        c.object_id > static_cast<uint8_t>(ObjKind::BindAck) ||
        c.total > wire::k_bootstrap_max_total || end_.send == nullptr) {
        return;
    }
    Frag f;
    f.xid = h.message_id;
    f.kind = static_cast<ObjKind>(c.object_id);
    f.total = c.total;
    f.offset = c.offset;
    f.body = c.bytes;
    Origin o;
    o.family = Family::End;
    o.reply = &reply;
    o.scratch = &scratch;
    on_fragment(f, o, now);
}

// The delivery module's estimate advanced to `now`; without it (a bench without delivery) the last anchor.
RootTimeBound Exchange::root_time(MonoTime now) const {
    return end_.root_time != nullptr ? end_.root_time(end_.ctx, now) : s_.root_time;
}

// One carrier record with the next fragment of `obj`, built in a pool frame borrowed for the call (no
// big locals on the owner stack). Busy: TX pool/radio shortage, the fragment is tried again.
Status Exchange::send_end_chunk(ByteView obj, MonoTime now) {
    Lease frame{s_.engine.frames()};
    if (!frame.ok()) {
        ++end_stats_.send_deferred; // every pool frame is in use: local, retried, never counted as loss
        return Status::Busy;
    }
    const MutByteView rec{frame.data(), Lease::size()};
    const std::size_t cap = wire::data_capacity(route_.len);
    if (cap <= k_end_obj_header ||
        rec.size() < wire::k_end_header_bytes + cap + wire::k_tag_bytes) {
        return Status::NoRoute;
    }
    const std::size_t chunk =
        std::min(std::min<std::size_t>(cap - k_end_obj_header, member::k_join_chunk_bytes),
                 obj.size() - tx_off_);
    const std::size_t plain_len = k_end_obj_header + chunk;
    wire::EndHeader h;
    h.end_sid = delivery::k_handshake_sid;
    h.end_counter = ++tx_seq_;
    h.message_id = xid_;
    h.app_port = 0;
    h.record_kind = wire::RecordKind::Control;
    h.flags = wire::make_end_flags(wire::Delivery::BestEffort, wire::Priority::Control, false);
    h.plaintext_length = static_cast<uint16_t>(plain_len);
    LM_TRY(wire::encode_end_header(h, rec.first(wire::k_end_header_bytes)));
    member::JoinChunk c;
    c.object_id = static_cast<uint8_t>(tx_kind_);
    c.total = static_cast<uint16_t>(obj.size());
    c.offset = static_cast<uint16_t>(tx_off_);
    c.bytes = obj.subspan(tx_off_, chunk);
    std::size_t clen = 0;
    LM_TRY(member::encode_chunk(c, rec.subspan(wire::k_end_header_bytes, plain_len), clen));
    // The tag field stays zero: the carrier is not end-authenticated.
    std::memset(rec.data() + wire::k_end_header_bytes + plain_len, 0, wire::k_tag_bytes);
    // Set before sending: the hop layer may report the frame's end from inside send().
    const std::size_t prev_off = tx_off_;
    tx_inflight_ = true;
    tx_off_ += chunk;
    const ByteView record{rec.data(), wire::k_end_header_bytes + plain_len + wire::k_tag_bytes};
    const Status st = end_.send(end_.ctx, route_, record, handle_, now);
    if (st == Status::Busy || st == Status::NoCapacity) {
        ++end_stats_.send_deferred; // TX pool/radio shortage: local, retried, never counted as loss
        tx_inflight_ = false;
        tx_off_ = prev_off;
        return Status::Busy;
    }
    if (st != Status::Ok) {
        tx_inflight_ = false;
        return st;
    }
    retry_at_ = MonoTime::never();
    return Status::Ok;
}

void Exchange::on_end_frame_done(Handle owner, bool accepted, MonoTime now) {
    if (!end_alive(owner) || !tx_inflight_) {
        return;
    }
    tx_inflight_ = false;
    if (!accepted) {
        // The object is broken; the initiator's next RTO repeats it as a whole, the responder waits
        // for the initiator's repeat.
        tx_active_ = false;
        if (initiator_) {
            rto_at_ = now + Duration::from_ms(100);
        }
        return;
    }
    if (tx_off_ >= tx_object().size()) {
        tx_active_ = false;
        arm_rto(now);
        return;
    }
    pump(now);
}

// SESSION_BIND / ACK = [1, ctx_hash, receiver_sid, nonce], sealed under the new keys with the
// sender's own reserved SID in the header (S5-D3). Staged for identical repeats.
Status Exchange::seal_end_bind(sec::RecordSession &rec, const Sha256Digest &ctx_hash,
                               uint32_t own_sid) {
    std::array<uint8_t, 64> plain{};
    wire::CborWriter w{MutByteView{plain}};
    w.array(4);
    w.uint(k_bind_version);
    w.bytes(ByteView{ctx_hash});
    w.uint(own_sid);
    w.bytes(ByteView{bind_nonce_});
    LM_TRY(w.finish());
    wire::EndHeader h;
    h.message_id = xid_;
    h.app_port = 0;
    h.record_kind = wire::RecordKind::Control;
    h.flags = wire::make_end_flags(wire::Delivery::BestEffort, wire::Priority::Control, false);
    std::size_t len = 0;
    FrameBuf *b = stage_buf();
    if (b == nullptr) {
        return Status::NoCapacity;
    }
    LM_TRY(delivery::seal_end_record(rec, ctx_hash, own_sid, route_.term, h, w.written(),
                                     MutByteView{b->bytes.data(), k_bind_record_max}, len));
    stage_len_ = len;
    staged_ = initiator_ ? ObjKind::Bind : ObjKind::BindAck;
    return Status::Ok;
}

// SESSION_BIND (initiator -> responder) or its ACK arrived as a whole carrier object.
void Exchange::on_end_bind(ByteView record, const Origin &o, MonoTime now) {
    if (o.family != Family::End) {
        return;
    }
    delivery::OpenedEnd &op = *o.scratch;
    if (phase_ == Phase::Linger) {
        // A bind repeat: the peer did not see our ACK. Answer with the same bytes.
        delivery::EndSession *s = end_.sessions->find_peer(peer_id_);
        wire::EndHeader h;
        ByteView sealed;
        if (s == nullptr || wire::decode_end_record(record, h, sealed) != Status::Ok ||
            h.end_sid != s->tx_sid) {
            return;
        }
        const Status st = delivery::open_end_record(*s, o.reply->term, record, op);
        if (st == Status::Replay && op.verdict == sec::ReplayVerdict::Duplicate) {
            send_object(ObjKind::BindAck, true);
            pump(now);
        }
        return;
    }
    if (phase_ != Phase::AwaitBind || !pend_.rec.active()) {
        return;
    }
    if (delivery::open_end_record(pend_.rec, pend_.ctx_hash, o.reply->term, record, op) !=
        Status::Ok) {
        return; // not authentic or a stale copy: no state change, the deadline still runs
    }
    uint32_t sid = 0;
    std::array<uint8_t, 16> nonce{};
    const bool ok = op.header.record_kind == wire::RecordKind::Control && op.header.app_port == 0 &&
                    check_bind_body(op.view(), op.header.end_sid, sid, nonce) &&
                    !delivery::is_reserved_sid(sid) && (!initiator_ || nonce == bind_nonce_);
    if (!ok) {
        count(Count::BindBad);
        return;
    }
    pend_.rec.accept(op.header.end_counter);
    pend_.tx_sid = sid;
    DeadlineCheck lease = DeadlineCheck::Uncertain;
    Status is = admit_peer(false, &lease); // the ledger, the floors or the time may have moved during the handshake
    if (is == Status::Ok) {
        is = install_end_session(now, lease);
    } else {
        count(Count::CredRejected);
    }
    if (is != Status::Ok) {
        abort(is);
        return;
    }
    count(Count::Completed);
    const DeviceId peer = peer_id_;
    if (initiator_) {
        finish_idle();
        if (end_.done != nullptr) {
            end_.done(end_.ctx, peer, Status::Ok, now);
        }
        return;
    }
    bind_nonce_ = nonce;
    delivery::EndSession *s = end_.sessions->find_peer(peer);
    is = s != nullptr ? seal_end_bind(s->rec, s->ctx_hash, s->rx_sid) : Status::RecoveryRequired;
    phase_ = Phase::Linger;
    deadline_ = now + s_.policy.end_linger;
    rto_at_ = MonoTime::never();
    if (is == Status::Ok) {
        send_object(ObjKind::BindAck, false);
        pump(now);
    }
    if (end_.done != nullptr) {
        end_.done(end_.ctx, peer, Status::Ok, now); // the session exists on our side
    }
}

// A fresh session replaces the old keys of the same peer; records sealed under the old keys are
// re-sealed (the epoch changes). It lives no longer than the peer's lease (SEC-D3).
Status Exchange::install_end_session(MonoTime now, DeadlineCheck lease) {
    delivery::EndSessions &ss = *end_.sessions;
    const DeviceId &peer = peer_state_.dc.device;
    // Review finding 20: the verified credential gives this address to `peer`. A session of another device at the
    // same address is of an owner the root replaced (it left, the ledger reused its slot): it and every route
    // learned before go.
    if (delivery::EndSession *old = ss.find_addr(peer_state_.mc.address); old != nullptr && old->peer != peer) {
        ss.remove(*old);
        s_.engine.delivery().invalidate_routes();
    }
    delivery::EndSession *slot = ss.find_peer(peer);
    if (slot == nullptr) {
        slot = &ss.acquire();
    } else {
        slot->wipe();
    }
    const member::MemberCredential &mc = peer_state_.mc;
    slot->used = true;
    slot->peer = peer;
    slot->peer_addr = mc.address;
    slot->peer_assignment = mc.assignment;
    slot->peer_membership = mc.membership;
    slot->rec = std::move(pend_.rec);
    slot->ctx_hash = pend_.ctx_hash;
    slot->rx_sid = pend_.rx_sid;
    slot->tx_sid = pend_.tx_sid;
    slot->valid_until = pend_.valid_until;
    slot->peer_lease = member::lease_of(mc);
    if (lease == DeadlineCheck::Before && !lease_exempt()) {
        slot->valid_until = earliest(slot->valid_until, member::lease_local_end(root_time(now), slot->peer_lease, now));
    }
    pend_.wipe();
    slot->epoch = ss.next_epoch();
    slot->suspect = false;
    ss.touch(*slot);
    return Status::Ok;
}

void Exchange::revalidate_end(const RootTimeBound &bound, MonoTime now) {
    if (end_.sessions == nullptr || lease_exempt()) {
        return; // [S18] the root's sessions follow its ledger, not the lease
    }
    end_.sessions->for_each_used([&](delivery::EndSession &s) {
        switch (check_deadline(bound, s.peer_lease)) {
        case DeadlineCheck::After:
            end_.sessions->remove(s); // no record under it any more; the peer needs a new credential
            ++end_stats_.lease_expired;
            break;
        case DeadlineCheck::Before:
            s.valid_until = earliest(s.valid_until, member::lease_local_end(bound, s.peer_lease, now));
            break;
        case DeadlineCheck::Uncertain:
            break; // application DATA is held back per link session (LinkLayer)
        }
    });
}

} // namespace lm::link
