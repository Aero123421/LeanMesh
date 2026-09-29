// Wire side of the link exchange: bootstrap carrier reception (credential bundle reassembly, EDHOC
// messages), frame staging, transmission pump, retransmission timer. Split from exchange.cpp, which
// holds the state machine (jobs, owner-side steps, session install).
#include <algorithm>
#include <cstring>

#include "core/engine.hpp"
#include "core/link/exchange.hpp"

namespace lm::link {
namespace {

constexpr Duration k_pump_retry = Duration::from_ms(20); // radio busy: one frame is waiting
// An unauthenticated CredI may hold the single slot only this long: the honest initiator sends
// message_1 right after CredR (its 3 x 1 s retransmissions of CredI fit).
constexpr Duration k_msg1_wait = Duration::from_s(4);

bool same_id(const std::array<uint8_t, 16> &a, const std::array<uint8_t, 16> &b) { return a == b; }

} // namespace

// ---- receive: bootstrap carrier ----
void Exchange::on_bootstrap(const MacAddr &src, ByteView carrier, MonoTime now, bool via_join) {
    wire::BootstrapCarrier c;
    if (wire::decode_bootstrap(carrier, c) != Status::Ok) {
        ++s_.stats.rx_malformed;
        return;
    }
    switch (static_cast<ObjKind>(c.object_kind)) {
    case ObjKind::CredI:
        on_cred(src, c, ObjKind::CredI, now, via_join);
        break;
    case ObjKind::CredR:
        on_cred(src, c, ObjKind::CredR, now, via_join);
        break;
    case ObjKind::Msg1:
    case ObjKind::Msg2:
    case ObjKind::Msg3:
    case ObjKind::Msg4:
        if (phase_ != Phase::Idle && (mode_ != Mode::Link) != via_join) {
            ++s_.stats.hs_busy_drop; // a link carrier during a join exchange or the reverse
            break;
        }
        on_msg(src, c, static_cast<ObjKind>(c.object_kind), now);
        break;
    default:
        ++s_.stats.rx_malformed;
        break;
    }
}

void Exchange::on_cred(const MacAddr &src, const wire::BootstrapCarrier &c, ObjKind kind, MonoTime now,
                       bool via_join) {
    if (lent_) {
        ++s_.stats.hs_busy_drop; // the credential buffer is borrowed by a join module
        return;
    }
    if (phase_ == Phase::Linger && !(src == mac_ && kind == ObjKind::CredI && same_id(c.exchange_id, xid_))) {
        finish_idle(); // a new exchange takes the slot from a lingering responder
    }
    if (phase_ == Phase::Idle) {
        if (kind != ObjKind::CredI || c.offset != 0) {
            return;
        }
        if (via_join) {
            // [S8] Only the root answers, only while policy and a join slot allow it, and never for
            // a MAC that already is an ordinary neighbour (a live member does not need to join).
            if (s_.join.responder_open == nullptr || !s_.join.responder_open(s_.join.ctx) ||
                s_.neighbors.find_mac(src) != nullptr || !s_.identity.is_member()) {
                ++s_.stats.hs_busy_drop;
                return;
            }
        }
        if (begin_common(src, false, now) != Status::Ok) {
            ++s_.stats.hs_busy_drop; // no transient peer slot: a local shortage
            return;
        }
        mode_ = via_join ? Mode::JoinResp : Mode::Link;
        xid_ = c.exchange_id;
    } else {
        if (src != mac_ || phase_ == Phase::Zombie || (mode_ != Mode::Link) != via_join) {
            ++s_.stats.hs_busy_drop;
            return;
        }
        const bool normal = initiator_ && phase_ == Phase::SendCred && kind == ObjKind::CredR &&
                            same_id(c.exchange_id, xid_);
        const bool glare = mode_ == Mode::Link && initiator_ && phase_ == Phase::SendCred &&
                           kind == ObjKind::CredI && !same_id(c.exchange_id, xid_);
        const bool receiving = !initiator_ && phase_ == Phase::AwaitMsg &&
                               expect_ == ObjKind::CredI && kind == ObjKind::CredI &&
                               same_id(c.exchange_id, xid_);
        const bool repeat = !initiator_ && phase_ == Phase::AwaitMsg && expect_ == ObjKind::Msg1 &&
                            kind == ObjKind::CredI && same_id(c.exchange_id, xid_);
        if (repeat) {
            if (c.offset == 0) { // our CredR was lost: send it again
                send_object(Tx::Cred, ObjKind::CredR, true);
                pump(now);
            }
            return;
        }
        if (!normal && !glare && !receiving) {
            ++s_.stats.hs_busy_drop;
            return;
        }
    }
    if (c.offset == 0) {
        rx_xid_ = c.exchange_id;
        rx_kind_ = kind;
        rx_total_ = c.total;
        rx_len_ = 0;
    }
    if (!same_id(c.exchange_id, rx_xid_) || kind != rx_kind_ || c.total != rx_total_ ||
        c.offset != rx_len_ || rx_len_ + c.body.size() > rx_.size()) {
        return; // out of order or foreign: the sender repeats the whole object
    }
    std::memcpy(rx_.data() + rx_len_, c.body.data(), c.body.size());
    rx_len_ += c.body.size();
    if (rx_len_ == rx_total_) {
        cred_complete(kind, now);
    }
}

void Exchange::cred_complete(ObjKind kind, MonoTime /*now*/) {
    if (initiator_ && kind == ObjKind::CredI) {
        // Both sides started: the lower DeviceId keeps the initiator role (docs/06 §8, one
        // handshake per pair). The peek is structural only; the winner still verifies everything.
        member::Bundle b;
        member::Envelope env;
        ByteView data;
        member::DeviceCredential dc;
        const bool ok = member::bundle_parse(ByteView{rx_.data(), rx_len_}, b) == Status::Ok &&
                        member::peek_signed(b.device_cose, member::k_type_device_credential, env,
                                            data) == Status::Ok &&
                        member::decode_device_credential(data, dc) == Status::Ok;
        if (!ok || !(dc.device < s_.identity.self())) {
            rx_len_ = rx_total_ = 0; // we keep initiating; the peer yields on seeing our credentials
            return;
        }
        switch_to_responder();
    } else if (initiator_) {
        rto_at_ = MonoTime::never();
    }
    phase_ = Phase::Verify;
    const Status st = run_verify();
    if (st != Status::Ok) {
        abort(st);
    }
}

void Exchange::switch_to_responder() {
    // rx_ already holds the winner's CredI (reassembled by on_cred()). Our own attempt is
    // abandoned, so it must not rate-limit the winner's message_1.
    s_.gate.forget(mac_);
    initiator_ = false;
    xid_ = rx_xid_;
    tx_ = Tx::None;
    rto_at_ = MonoTime::never();
    attempts_ = 0;
    last_len_ = 0;
    expect_ = ObjKind::CredI;
}

void Exchange::on_msg(const MacAddr &src, const wire::BootstrapCarrier &c, ObjKind kind, MonoTime now) {
    if (phase_ == Phase::Idle || phase_ == Phase::Zombie || src != mac_ || !same_id(c.exchange_id, xid_) ||
        c.offset != 0 || c.total != c.body.size()) {
        return;
    }
    Status st = Status::Ok;
    if (initiator_ && phase_ == Phase::AwaitMsg && kind == expect_ &&
        (kind == ObjKind::Msg2 || kind == ObjKind::Msg4)) {
        rto_at_ = MonoTime::never();
        phase_ = Phase::Hs;
        st = run_hs(kind == ObjKind::Msg2 ? sec::HsStep::M2Process : sec::HsStep::M4Process, c.body);
    } else if (!initiator_ && phase_ == Phase::AwaitMsg && expect_ == ObjKind::Msg1 &&
               kind == ObjKind::Msg1) {
        // From here the responder spends EDHOC work (ECDH, signature): one full handshake per peer
        // per 30 s (docs/06 §8). Credential checks before this point are cheap and slot-bounded.
        if (!s_.gate.allow(src, now, s_.policy.handshake_gate)) {
            ++s_.stats.hs_rate_limited;
            abort(Status::RateLimited);
            return;
        }
        s_.gate.touch(src, now);
        deadline_ = hard_deadline_;
        const ByteView peers[1] = {ByteView{peer_state_.ccs.data(), peer_state_.ccs_len}};
        st = hs_.begin(sec::HsRole::Responder, s_.identity.key(), s_.identity.ccs(), peers, 1);
        if (st == Status::Ok) {
            phase_ = Phase::Hs;
            st = run_hs(sec::HsStep::M1Process, c.body);
        }
    } else if (!initiator_ && phase_ == Phase::AwaitMsg && expect_ == ObjKind::Msg3 &&
               kind == ObjKind::Msg3) {
        phase_ = Phase::Hs;
        st = run_hs(sec::HsStep::M3Process, c.body);
    } else if (!initiator_ && ((phase_ == Phase::AwaitMsg && expect_ == ObjKind::Msg3 &&
                                kind == ObjKind::Msg1) ||
                               (phase_ == Phase::AwaitBind && kind == ObjKind::Msg3))) {
        // The initiator did not see our answer: repeat it byte for byte.
        send_object(Tx::Frame, kind == ObjKind::Msg1 ? ObjKind::Msg2 : ObjKind::Msg4, true);
        pump(now);
        return;
    } else {
        return;
    }
    if (st != Status::Ok) {
        abort(st);
    }
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

void Exchange::stage_frame(ObjKind kind, ByteView body) {
    std::size_t len = 0;
    if (build_plain(kind, static_cast<uint16_t>(body.size()), 0, body, MutByteView{last_}, len) !=
        Status::Ok) {
        len = 0;
    }
    last_len_ = len;
}

void Exchange::send_object(Tx mode, ObjKind kind, bool retransmit) {
    tx_ = mode;
    tx_kind_ = kind;
    tx_off_ = 0;
    rto_at_ = MonoTime::never();
    attempts_ = retransmit ? static_cast<uint8_t>(attempts_ + 1) : 1;
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
        rto_at_ = now + s_.policy.rto;
    }
}

void Exchange::pump(MonoTime now) {
    if (tx_ == Tx::None || tx_inflight_ || phase_ == Phase::Idle || phase_ == Phase::Zombie) {
        return;
    }
    std::array<uint8_t, wire::k_max_frame_bytes> buf{};
    ByteView frame;
    std::size_t chunk = 0;
    if (tx_ == Tx::Cred) {
        const ByteView bundle = own_bundle();
        chunk = std::min<std::size_t>(wire::k_bootstrap_max_body, bundle.size() - tx_off_);
        std::size_t len = 0;
        const Status st = build_plain(tx_kind_, static_cast<uint16_t>(bundle.size()),
                                      static_cast<uint16_t>(tx_off_), bundle.subspan(tx_off_, chunk),
                                      MutByteView{buf}, len);
        if (st != Status::Ok) {
            abort(st);
            return;
        }
        frame = ByteView{buf.data(), len};
    } else {
        if (last_len_ == 0) {
            abort(Status::RecoveryRequired);
            return;
        }
        frame = ByteView{last_.data(), last_len_};
    }
    const Status st = s_.engine.transmit(mac_, frame, k_tag_base | tx_seq_, now);
    if (st == Status::Busy || st == Status::DriverResultUnknown) {
        ++s_.stats.tx_local_busy; // the radio is occupied or isolated: not an RF loss
        retry_at_ = now + k_pump_retry;
        return;
    }
    if (st != Status::Ok) {
        abort(st);
        return;
    }
    ++tx_seq_;
    ++s_.stats.tx_frames_hs;
    tx_inflight_ = true;
    retry_at_ = MonoTime::never();
    if (tx_ == Tx::Cred) {
        tx_off_ += chunk;
        if (tx_off_ < own_bundle().size()) {
            return; // the next fragment follows the TX-done of this one
        }
    }
    tx_ = Tx::None;
    arm_rto(now);
}

void Exchange::on_tx_outcome(const TxOutcome &o, MonoTime now) {
    if (is_link_tag(o.tag)) {
        tx_inflight_ = false;
        if (o.result == port::TxResult::MacFailed) {
            ++s_.stats.tx_rf_failed; // the only RF-loss sample; recovery is by RTO, not here
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
        ++s_.stats.hs_retransmits;
        const Tx mode = phase_ == Phase::SendCred ? Tx::Cred : Tx::Frame;
        send_object(mode, tx_kind_, true);
    }
    if (now >= retry_at_) {
        retry_at_ = MonoTime::never();
    }
    pump(now);
}

} // namespace lm::link
