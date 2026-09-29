// Join extension of the link exchange (docs/07 §4, decision S8-D1): the JOIN_ONLY handshake of an
// unjoined device with the root runs on the same single exchange slot and HandshakeSlot as a link
// exchange instead of a second engine. Differences from a link exchange:
//   - carriers travel in frames of kind JOIN_PROXY (SID 0); SESSION_BIND stays kind EDHOC;
//   - CredI is the joiner's DeviceCredential alone, CredR is [root DeviceCredential, RootDelegation];
//   - the session context has generation 0 on both sides and hashes the two DeviceCredentials, so
//     its keys can never open an ordinary link (docs/06 §4 "bootstrap join ... JOIN_ONLY");
//   - the finished session is not an ordinary neighbour: it is a `join_only` entry that carries the
//     join control objects only, and it is announced to the join module instead of the link layer.
#include <cstring>
#include <utility>

#include "core/engine.hpp"
#include "core/link/exchange.hpp"
#include "security/crypto.hpp"

namespace lm::link {

Status Exchange::start_join(const MacAddr &mac, JoinPeerOut *out, MonoTime now) {
    if (out == nullptr) {
        return Status::InvalidArgument;
    }
    if (s_.identity.state() != member::LocalIdentity::State::Ready || s_.identity.is_member()) {
        return Status::AuthPending;
    }
    if (busy()) {
        return Status::Busy;
    }
    if (phase_ == Phase::Linger) {
        finish_idle();
    }
    if (!s_.gate.allow(mac, now, s_.policy.handshake_gate)) {
        ++s_.stats.hs_rate_limited;
        return Status::RateLimited;
    }
    LM_TRY(begin_common(mac, true, now));
    mode_ = Mode::JoinInit;
    join_out_ = out;
    *out = JoinPeerOut{};
    s_.gate.touch(mac, now);
    s_.engine.random(MutByteView{xid_});
    phase_ = Phase::SendCred;
    expect_ = ObjKind::CredR;
    send_object(Tx::Cred, ObjKind::CredI, false);
    pump(now);
    return Status::Ok;
}

MutByteView Exchange::lend_scratch() {
    if (busy()) {
        return MutByteView{};
    }
    if (phase_ == Phase::Linger) {
        finish_idle(); // the peer already holds our ACK (it sent its first join object)
    }
    lent_ = true;
    return MutByteView{rx_.data(), rx_.size()};
}

uint32_t Exchange::hint() const {
    if (mode_ == Mode::JoinInit) {
        return join_out_ != nullptr && join_out_->known ? domain_hint_of(join_out_->delegation.domain) : 0;
    }
    return domain_hint_of(s_.identity.delegation().domain);
}

Neighbor *Exchange::installed() {
    return mode_ == Mode::Link ? s_.neighbors.find_device(peer_state_.dc.device)
                               : s_.neighbors.find_join(peer_state_.dc.device);
}

// Worker. JoinResp: the joiner's DeviceCredential (fleet signature, generation floor, key == id).
// JoinInit: the root's DeviceCredential plus its RootDelegation, which must name that very device
// and allow approvals. The delegation is what makes the peer "the root of this domain".
Status Exchange::verify_join_body(Exchange &x) {
    PeerState &p = x.peer_state_;
    if (x.mode_ == Mode::JoinResp) {
        const ByteView dc{x.rx_.data(), x.rx_len_};
        LM_TRY(member::check_device_credential(x.vin_.trust, dc, p.dc));
        LM_TRY(sec::ccs_encode(ByteView{p.dc.serial.data(), p.dc.serial_len}, p.dc.key,
                               MutByteView{p.ccs}, p.ccs_len));
        return sec::sha256(dc, p.mc_hash);
    }
    member::JoinBundle b;
    LM_TRY(member::join_bundle_parse(ByteView{x.rx_.data(), x.rx_len_}, b));
    LM_TRY(member::check_device_credential(x.vin_.trust, b.device_cose, p.dc));
    member::RootDelegation d;
    LM_TRY(member::check_root_delegation(x.vin_.trust, b.delegation_cose, d));
    if (d.root != p.dc.device || (d.permissions & member::k_perm_approve) == 0) {
        return Status::AuthRejected;
    }
    LM_TRY(sec::ccs_encode(ByteView{p.dc.serial.data(), p.dc.serial_len}, p.dc.key, MutByteView{p.ccs},
                           p.ccs_len));
    LM_TRY(sec::sha256(b.device_cose, p.mc_hash));
    LM_TRY(sec::sha256(b.delegation_cose, x.join_out_->delegation_hash));
    x.join_out_->delegation = d;
    return Status::Ok;
}

// Owner. The verify job is done and rx_ no longer holds anything we need: stage CredR there.
Status Exchange::build_join_response() {
    return member::join_bundle_encode(s_.identity.device_cose(), s_.identity.delegation_cose(),
                                      MutByteView{rx_}, own_len_);
}

Status Exchange::make_join_context(sec::SessionContext &ctx) const {
    const member::LocalIdentity &id = s_.identity;
    Sha256Digest self_hash{};
    LM_TRY(sec::sha256(id.device_cose(), self_hash));
    ctx = sec::SessionContext{}; // the caller's struct is reused: generations must be 0, not left over
    ctx.purpose = sec::Purpose::Link;
    ctx.fleet = id.trust().fleet;
    if (initiator_) {
        ctx.domain = join_out_->delegation.domain;
        ctx.initiator = id.self();
        ctx.responder = peer_state_.dc.device;
        ctx.credential_hash_i = self_hash;
        ctx.credential_hash_r = peer_state_.mc_hash;
    } else {
        ctx.domain = id.delegation().domain;
        ctx.initiator = peer_state_.dc.device;
        ctx.responder = id.self();
        ctx.credential_hash_i = peer_state_.mc_hash;
        ctx.credential_hash_r = self_hash;
    }
    // Both sides are unassigned for this session: generations stay 0.
    return Status::Ok;
}

Status Exchange::install_join_session(MonoTime now) {
    if (!peer_transient_) {
        return Status::RecoveryRequired; // join peers are always transient registrations
    }
    Neighbor *n = s_.neighbors.acquire();
    if (n == nullptr) {
        return Status::NoCapacity;
    }
    n->peer = peer_;
    n->mac = mac_;
    n->device = peer_state_.dc.device;
    n->join_only = true;
    n->cur = std::move(pend_);
    pend_.wipe();
    n->cur.valid_until = now + s_.policy.join_session_life;
    peer_transient_ = false; // the neighbour entry owns the registration now
    peer_ = PeerHandle{};
    if (s_.join.session_up != nullptr) {
        const ByteView bundle = initiator_ ? ByteView{rx_.data(), rx_len_} : ByteView{};
        s_.join.session_up(s_.join.ctx, initiator_, mac_, n->device, bundle, peer_state_.mc_hash);
    }
    return Status::Ok;
}

} // namespace lm::link
