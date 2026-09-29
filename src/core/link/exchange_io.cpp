// Carrier side of the exchange: fragments in (whatever carried them), in-order object assembly,
// the transmit pump for 1-hop frames, retransmission and phase timers. The end-record carrier
// (decode, send, hop completion) is in exchange_end.cpp.
#include <algorithm>
#include <cstring>

#include "core/engine.hpp"
#include "core/link/exchange.hpp"

namespace lm::link {
namespace {

constexpr Duration k_pump_retry =
    Duration::from_ms(20); // radio/TX pool busy: one fragment is waiting
// An unauthenticated CredI may hold the single slot only this long: the honest initiator sends
// message_1 right after CredR (its 3 x 1 s retransmissions of CredI fit).
constexpr Duration k_msg1_wait = Duration::from_s(4);

} // namespace

// ---- receive: 1-hop bootstrap carrier ----
void Exchange::on_bootstrap(const MacAddr &src, ByteView carrier, MonoTime now, bool via_join) {
    wire::BootstrapCarrier c;
    if (wire::decode_bootstrap(carrier, c) != Status::Ok || c.object_kind < 1 ||
        c.object_kind > static_cast<uint8_t>(ObjKind::Msg4)) {
        ++s_.stats.rx_malformed; // SESSION_BIND travels as a protected frame on a link, never here
        return;
    }
    Frag f;
    f.xid = c.exchange_id;
    f.kind = static_cast<ObjKind>(c.object_kind);
    f.total = c.total;
    f.offset = c.offset;
    f.body = c.body;
    Origin o;
    o.family = via_join ? Family::Join : Family::Link;
    o.mac = src;
    on_fragment(f, o, now);
}

// One fragment of a handshake object. Decides whether it belongs to the running exchange (same
// carrier family, same peer, same exchange id, expected phase), starts a responder, answers repeats
// from what was staged, and assembles objects in order.
void Exchange::on_fragment(const Frag &f, const Origin &o, MonoTime now) {
    const bool cred = f.kind == ObjKind::CredI || f.kind == ObjKind::CredR;
    if (lent_ || slot_lent_) {
        if (cred) {
            busy_drop(o.family); // the credential buffer / the slot is borrowed (join module, USB link)
        }
        return;
    }
    if (usb_reserved_ && cred && (phase_ == Phase::Idle || phase_ == Phase::Linger)) {
        busy_drop(o.family); // the USB link is next for the slot (S13-D10)
        return;
    }
    if (o.family != Family::End && !cred && !(f.offset == 0 && f.body.size() == f.total)) {
        return; // over one hop an EDHOC message is one fragment; rx_ keeps the peer's credentials
    }
    if (phase_ == Phase::Linger && cred &&
        !(o.family == family() && same_peer(o) && f.kind == ObjKind::CredI && f.xid == xid_)) {
        finish_idle(); // a new exchange takes the slot from a lingering responder
    }
    if (phase_ == Phase::Idle) {
        if (f.kind != ObjKind::CredI || f.offset != 0 || !start_responder(f, o, now)) {
            return;
        }
    } else {
        if (o.family != family() || !same_peer(o) || phase_ == Phase::Zombie) {
            busy_drop(o.family);
            return;
        }
        const bool same = f.xid == xid_;
        const bool normal =
            initiator_ && phase_ == Phase::SendCred && f.kind == ObjKind::CredR && same;
        const bool glare = mode_ != Mode::JoinInit && initiator_ && phase_ == Phase::SendCred &&
                           f.kind == ObjKind::CredI && !same;
        const bool expected = same && phase_ == Phase::AwaitMsg && f.kind == expect_; // incl. CredI
        const bool repeat_cred = !initiator_ && same && phase_ == Phase::AwaitMsg &&
                                 expect_ == ObjKind::Msg1 && f.kind == ObjKind::CredI;
        const bool repeat_msg =
            !initiator_ && same &&
            ((phase_ == Phase::AwaitMsg && expect_ == ObjKind::Msg3 && f.kind == ObjKind::Msg1) ||
             (phase_ == Phase::AwaitBind && f.kind == ObjKind::Msg3));
        const bool bind_in =
            mode_ == Mode::End && same &&
            ((!initiator_ && f.kind == ObjKind::Bind &&
              (phase_ == Phase::AwaitBind || phase_ == Phase::Linger)) ||
             (initiator_ && f.kind == ObjKind::BindAck && phase_ == Phase::AwaitBind));
        if (repeat_cred || repeat_msg) {
            if (f.offset == 0) { // the initiator did not see our answer: repeat it byte for byte
                if (o.family == Family::End) {
                    route_ = *o.reply;
                }
                send_object(repeat_cred ? ObjKind::CredR : staged_, true);
                pump(now);
            }
            return;
        }
        if (!normal && !glare && !expected && !bind_in) {
            busy_drop(o.family);
            return;
        }
        if (o.family == Family::End && !initiator_) {
            route_ = *o.reply; // the responder answers over the reverse of the latest route
        }
    }
    if (!cred && f.offset == 0 && f.body.size() == f.total) {
        obj_complete(f.kind, f.body, o, now); // a whole object in one fragment: no copy
        return;
    }
    if (f.offset == 0) {
        rx_xid_ = f.xid;
        rx_kind_ = f.kind;
        rx_total_ = f.total;
        rx_len_ = 0;
    }
    const std::size_t limit =
        cred ? rx_.size()
             : (f.kind == ObjKind::Bind || f.kind == ObjKind::BindAck ? k_bind_record_max
                                                                      : sec::k_edhoc_max_message);
    if (f.xid != rx_xid_ || f.kind != rx_kind_ || f.total != rx_total_ || f.offset != rx_len_ ||
        rx_len_ + f.body.size() > limit) {
        return; // out of order or foreign: the sender repeats the whole object
    }
    std::memcpy(rx_.data() + rx_len_, f.body.data(), f.body.size());
    rx_len_ += f.body.size();
    if (rx_len_ == rx_total_) {
        obj_complete(f.kind, ByteView{rx_.data(), rx_len_}, o, now);
    }
}

// An idle exchange becomes the responder of the CredI's sender, if this node may answer it.
bool Exchange::start_responder(const Frag &f, const Origin &o, MonoTime now) {
    switch (o.family) {
    case Family::Join:
        // [S8] Only the root answers, only while policy and a join slot allow it, and never for
        // a MAC that already is an ordinary neighbour (a live member does not need to join).
        if (s_.join.responder_open == nullptr || !s_.join.responder_open(s_.join.ctx) ||
            s_.neighbors.find_mac(o.mac) != nullptr || !s_.identity.is_member()) {
            busy_drop(o.family);
            return false;
        }
        [[fallthrough]];
    case Family::Link:
        if (acquire_link_peer(o.mac) != Status::Ok) {
            busy_drop(o.family); // no transient peer slot: a local shortage
            return false;
        }
        begin_common(o.family == Family::Join ? Mode::JoinResp : Mode::Link, false, now);
        break;
    case Family::End:
        if (!s_.identity.is_member() || end_.send == nullptr) {
            return false;
        }
        begin_common(Mode::End, false, now);
        route_ = *o.reply;
        break;
    }
    xid_ = f.xid;
    return true;
}

void Exchange::obj_complete(ObjKind kind, ByteView obj, const Origin &o, MonoTime now) {
    Status st = Status::Ok;
    switch (kind) {
    case ObjKind::CredI:
    case ObjKind::CredR:
        if (initiator_ && kind == ObjKind::CredI) {
            // Both sides started: the lower DeviceId keeps the initiator role (docs/06 §8, one
            // handshake per pair). The peek is structural only; the winner still verifies
            // everything.
            member::Bundle b;
            member::Envelope env;
            ByteView data;
            member::DeviceCredential dc;
            const bool ok = member::bundle_parse(obj, b) == Status::Ok &&
                            member::peek_signed(b.device_cose, member::k_type_device_credential,
                                                env, data) == Status::Ok &&
                            member::decode_device_credential(data, dc) == Status::Ok;
            if (!ok || !(dc.device < s_.identity.self())) {
                rx_len_ = rx_total_ =
                    0; // we keep initiating; the peer yields on seeing our credentials
                return;
            }
            switch_to_responder(o);
        } else if (initiator_) {
            rto_at_ = MonoTime::never();
        }
        phase_ = Phase::Verify;
        st = run_verify();
        break;
    case ObjKind::Msg2:
    case ObjKind::Msg4:
        rto_at_ = MonoTime::never();
        phase_ = Phase::Hs;
        st = run_hs(kind == ObjKind::Msg2 ? sec::HsStep::M2Process : sec::HsStep::M4Process, obj);
        break;
    case ObjKind::Msg1:
        resp_message_1(obj, now);
        return;
    case ObjKind::Msg3:
        phase_ = Phase::Hs;
        st = run_hs(sec::HsStep::M3Process, obj);
        break;
    case ObjKind::Bind:
    case ObjKind::BindAck:
        on_end_bind(obj, o, now);
        return;
    }
    if (st != Status::Ok) {
        abort(st);
    }
}

// From here the responder spends EDHOC work (ECDH, signature): one full handshake per peer per
// 30 s (docs/06 §8). Credential checks before this point are cheap and slot-bounded.
void Exchange::resp_message_1(ByteView msg1, MonoTime now) {
    const bool end = mode_ == Mode::End;
    const bool allowed = end ? end_gate_.allow(peer_id_, now, s_.policy.handshake_gate)
                             : s_.gate.allow(mac_, now, s_.policy.handshake_gate);
    if (!allowed) {
        count(Count::RateLimited);
        abort(Status::RateLimited);
        return;
    }
    if (end) {
        end_gate_.touch(peer_id_, now);
    } else {
        s_.gate.touch(mac_, now);
    }
    deadline_ = hard_deadline_;
    start_hs(sec::HsRole::Responder, msg1, now);
}

// rx_ already holds the winner's CredI. Our own attempt is abandoned, so it must not rate-limit
// the winner's message_1.
void Exchange::switch_to_responder(const Origin &o) {
    if (mode_ == Mode::End) {
        end_gate_.forget(peer_id_);
        route_ = *o.reply;
        peer_known_ = false; // the winner is verified like any responder's peer
    } else {
        s_.gate.forget(mac_);
    }
    initiator_ = false;
    xid_ = rx_xid_;
    tx_active_ = false;
    rto_at_ = MonoTime::never();
    attempts_ = 0;
    stage_len_ = 0;
    expect_ = ObjKind::CredI;
}

// ---- transmit ----
Status Exchange::build_plain(ObjKind kind, uint16_t total, uint16_t offset, ByteView body,
                             MutByteView out, std::size_t &len) const {
    std::array<uint8_t, wire::k_bootstrap_header_bytes + wire::k_bootstrap_max_body> carrier{};
    std::size_t clen = 0;
    wire::BootstrapCarrier c;
    c.exchange_id = xid_;
    c.object_kind = static_cast<uint8_t>(kind);
    c.total = total;
    c.offset = offset;
    c.body = body;
    LM_TRY(wire::encode_bootstrap(c, MutByteView{carrier}, clen));
    wire::LinkHeader h;
    h.kind = mode_ == Mode::Link ? wire::FrameKind::Edhoc : wire::FrameKind::JoinProxy;
    h.domain_hint = hint();
    h.body_length = static_cast<uint16_t>(clen);
    h.encrypted = false;
    if (out.size() < wire::k_link_header_bytes + clen) {
        return Status::NoCapacity;
    }
    LM_TRY(wire::encode_link_header(h, out.first(wire::k_link_header_bytes)));
    std::memcpy(out.data() + wire::k_link_header_bytes, carrier.data(), clen);
    len = wire::k_link_header_bytes + clen;
    return Status::Ok;
}

// Makes `kind` the current object; the pump sends it fragment by fragment.
void Exchange::send_object(ObjKind kind, bool retransmit) {
    tx_active_ = true;
    tx_kind_ = kind;
    tx_off_ = 0;
    rto_at_ = MonoTime::never();
    attempts_ = retransmit ? static_cast<uint8_t>(attempts_ + 1) : 1;
}

ByteView Exchange::tx_object() const {
    if (tx_kind_ == ObjKind::CredI || tx_kind_ == ObjKind::CredR) {
        return own_bundle();
    }
    const TxFrame *f = s_.engine.frames().get(stage_h_);
    return f != nullptr ? ByteView{f->frame.bytes.data(), stage_len_} : ByteView{};
}

void Exchange::arm_rto(MonoTime now) {
    if (!initiator_) {
        if (phase_ == Phase::SendCred) { // CredR is out: wait for message_1, but not for long
            phase_ = Phase::AwaitMsg;
            expect_ = ObjKind::Msg1;
            deadline_ = earliest(deadline_, now + k_msg1_wait);
        }
        return;
    }
    if (phase_ == Phase::SendCred || phase_ == Phase::AwaitMsg || phase_ == Phase::AwaitBind) {
        rto_at_ = now + (mode_ == Mode::End ? delivery::round_timeout(route_.len) : s_.policy.rto);
    }
}

void Exchange::pump(MonoTime now) {
    if (!tx_active_ || tx_inflight_ || phase_ == Phase::Idle || phase_ == Phase::Zombie) {
        return;
    }
    if (!retry_at_.is_never() && now < retry_at_) {
        return; // a busy radio or the inter-fragment gap of a proxied join: on_timer pumps again then
    }
    const ByteView obj = tx_object();
    if (obj.empty()) {
        abort(Status::RecoveryRequired);
        return;
    }
    const Status st = mode_ == Mode::End ? send_end_chunk(obj, now) : send_link_chunk(obj, now);
    if (st == Status::Busy) {
        retry_at_ = now + k_pump_retry; // the radio / TX pool is occupied: local, never an RF loss
    } else if (st != Status::Ok) {
        abort(st);
    }
}

// One 1-hop frame: a bootstrap carrier fragment, or (SESSION_BIND[_ACK]) the staged sealed frame.
Status Exchange::send_link_chunk(ByteView obj, MonoTime now) {
    std::array<uint8_t, wire::k_max_frame_bytes> buf{};
    ByteView frame = obj;
    std::size_t chunk = obj.size();
    if (tx_kind_ != ObjKind::Bind && tx_kind_ != ObjKind::BindAck) {
        const bool cred = tx_kind_ == ObjKind::CredI || tx_kind_ == ObjKind::CredR;
        if (!cred && obj.size() > wire::k_bootstrap_max_body) {
            return Status::RecoveryRequired; // an EDHOC message always fits one carrier here
        }
        chunk = std::min<std::size_t>(wire::k_bootstrap_max_body, obj.size() - tx_off_);
        std::size_t len = 0;
        LM_TRY(build_plain(tx_kind_, static_cast<uint16_t>(obj.size()),
                           static_cast<uint16_t>(tx_off_), obj.subspan(tx_off_, chunk),
                           MutByteView{buf}, len));
        frame = ByteView{buf.data(), len};
    }
    const Status st = s_.engine.transmit(mac_, frame, k_tag_base | (tx_seq_ & 0xFFFFU), now);
    if (st == Status::Busy || st == Status::DriverResultUnknown) {
        ++s_.stats.tx_local_busy; // the radio is occupied or isolated: not an RF loss
        return Status::Busy;
    }
    LM_TRY(st);
    ++tx_seq_;
    ++s_.stats.tx_frames_hs;
    tx_inflight_ = true;
    retry_at_ = MonoTime::never();
    tx_off_ += chunk;
    if (tx_off_ >= obj.size()) {
        tx_active_ = false; // the next fragment would follow the TX-done of this one
        arm_rto(now);
    }
    return Status::Ok;
}

void Exchange::on_tx_outcome(const TxOutcome &o, MonoTime now) {
    if (is_link_tag(o.tag) && mode_ != Mode::End) {
        tx_inflight_ = false;
        if (o.result == port::TxResult::MacFailed) {
            ++s_.stats.tx_rf_failed; // the only RF-loss sample; recovery is by RTO, not here
        }
        if (s_.policy.tx_gap.us > 0 && tx_active_) {
            retry_at_ = now + s_.policy.tx_gap; // [S11] a relay in the path needs a moment per frame
            return;
        }
    }
    pump(now);
}

void Exchange::on_timer(MonoTime now) {
    if (phase_ == Phase::Idle || phase_ == Phase::Zombie) {
        return;
    }
    if (now >= deadline_) {
        if (phase_ == Phase::Linger) {
            finish_idle();
        } else {
            abort(Status::Expired);
        }
        return;
    }
    if (now >= rto_at_ && initiator_) {
        if (attempts_ >= s_.policy.max_attempts) {
            abort(Status::Expired);
            return;
        }
        count(Count::Retransmit);
        send_object(phase_ == Phase::SendCred ? ObjKind::CredI : staged_, true);
    }
    if (now >= retry_at_) {
        retry_at_ = MonoTime::never();
    }
    pump(now);
}

} // namespace lm::link
