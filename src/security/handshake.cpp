#include "security/handshake.hpp"

#include <cstring>
#include <utility>

#include "core/codec.hpp"
#include "security/crypto.hpp"

namespace lm::sec {

namespace {

bool is_process(HsStep s) {
    return s == HsStep::M1Process || s == HsStep::M2Process || s == HsStep::M3Process ||
           s == HsStep::M4Process;
}

bool is_compose(HsStep s) {
    return s == HsStep::M1Compose || s == HsStep::M2Compose || s == HsStep::M3Compose ||
           s == HsStep::M4Compose;
}

lm_edhoc_step to_c(HsStep s) {
    switch (s) {
    case HsStep::M1Compose: return LM_EDHOC_M1_COMPOSE;
    case HsStep::M1Process: return LM_EDHOC_M1_PROCESS;
    case HsStep::M2Compose: return LM_EDHOC_M2_COMPOSE;
    case HsStep::M2Process: return LM_EDHOC_M2_PROCESS;
    case HsStep::M3Compose: return LM_EDHOC_M3_COMPOSE;
    case HsStep::M3Process: return LM_EDHOC_M3_PROCESS;
    case HsStep::M4Compose: return LM_EDHOC_M4_COMPOSE;
    default: return LM_EDHOC_M4_PROCESS;
    }
}

// libedhoc codes -> Status. Malformed input and failed authentication are the peer's fault
// (BadFrame / AuthRejected); backend trouble fails closed (RecoveryRequired, docs D7).
Status map_rc(int rc, int32_t fault) {
    if (rc == 0) {
        return Status::Ok;
    }
    if (fault != 0) { // a local failure (memory, backend): never blamed on the peer
        return from_psa(fault) == Status::NoCapacity ? Status::NoCapacity : Status::RecoveryRequired;
    }
    switch (rc) {
    case -110: // EDHOC_ERROR_CBOR_FAILURE
        return Status::BadFrame;
    case -103: // BUFFER_TOO_SMALL
        return Status::BufferTooSmall;
    case -106: // NOT_ENOUGH_MEMORY
        return Status::NoCapacity;
    case -105: // INVALID_ARGUMENT
    case LM_EDHOC_ERR_ARG:
        return Status::InvalidArgument;
    case -104: // BAD_STATE
        return Status::Conflict;
    case -111: // CRYPTO_FAILURE without a local fault: bad AEAD tag, bad signature, invalid point
    case -134: // ephemeral key exchange (peer's G_X/G_Y not a curve point)
    case -112: // CREDENTIALS_FAILURE (unknown kid, kid/key mismatch)
    case -130: case -131: case -132: case -133: // MSG_x_PROCESS_FAILURE
    case -138: case -140:                       // signature invalid
    case -121:                                  // unknown critical EAD
        return Status::AuthRejected;
    default:
        return Status::RecoveryRequired;
    }
}

} // namespace

Status HandshakeSlot::begin(HsRole role, KeyHandle local_key, ByteView local_ccs,
                            const ByteView *peer_ccs, std::size_t peer_count) {
    if (state_ == State::Failed && !in_flight_) {
        LM_TRY(wipe()); // retry the teardown that failed before; never build on leaked handles
    }
    if (state_ != State::Idle || in_flight_) {
        return Status::Busy;
    }
    if (local_key.id == 0 || local_ccs.empty() || local_ccs.size() > sizeof session_.local_ccs ||
        peer_count == 0 || peer_count > k_edhoc_max_peers || peer_ccs == nullptr) {
        return Status::InvalidArgument;
    }
    for (std::size_t i = 0; i < peer_count; ++i) {
        if (peer_ccs[i].empty() || peer_ccs[i].size() > sizeof session_.peers[i].ccs) {
            return Status::InvalidArgument;
        }
    }
    role_ = role;
    local_key_ = local_key;
    // The inputs go straight into the idle EDHOC session, their only copy; the first job parses and
    // validates them there (the owner never touches the session while a job may run).
    std::memcpy(session_.local_ccs, local_ccs.data(), local_ccs.size());
    session_.local_ccs_len = local_ccs.size();
    for (std::size_t i = 0; i < peer_count; ++i) {
        std::memcpy(session_.peers[i].ccs, peer_ccs[i].data(), peer_ccs[i].size());
        session_.peers[i].ccs_len = peer_ccs[i].size();
    }
    session_.peer_count = peer_count;
    state_ = State::Running;
    expected_ = role == HsRole::Initiator ? HsStep::M1Compose : HsStep::M1Process;
    return Status::Ok;
}

Status HandshakeSlot::prepare(HsStep step, ByteView input) {
    if (state_ != State::Running && !(state_ == State::Established && step == HsStep::Export)) {
        return Status::Conflict;
    }
    if (in_flight_ || cancelled_) {
        return Status::Busy;
    }
    if (step != expected_ || step == HsStep::None) {
        return Status::Conflict;
    }
    if (is_process(step)) {
        if (input.empty()) {
            return Status::InvalidArgument;
        }
        if (input.size() > in_.size()) {
            return Status::PayloadTooLarge;
        }
        LM_TRY(copy_bytes(MutByteView{in_.data(), in_.size()}, input));
        in_len_ = input.size();
    } else if (!input.empty()) {
        return Status::InvalidArgument;
    }
    if (step == HsStep::Export && !ctx_set_) {
        return Status::Conflict;
    }
    armed_ = step;
    in_flight_ = true;
    return Status::Ok;
}

void HandshakeSlot::unprepare() {
    if (in_flight_) {
        in_flight_ = false;
        armed_ = HsStep::None;
    }
}

Status HandshakeSlot::init_session() {
    PublicKey local_pub;
    const ByteView local_ccs{session_.local_ccs, session_.local_ccs_len};
    LM_TRY(ccs_parse(local_ccs, local_pub, local_device_));
    PublicKey actual;
    LM_TRY(public_key_of(local_key_, actual));
    if (actual.x != local_pub.x || actual.y != local_pub.y) {
        return Status::InvalidArgument; // the CCS we would present is not the key we sign with
    }
    session_.local_key = local_key_.id;
    std::memcpy(session_.local_kid, local_device_.bytes.data(), 32);
    for (std::size_t i = 0; i < session_.peer_count; ++i) {
        lm_edhoc_peer &p = session_.peers[i];
        PublicKey pub;
        DeviceId id;
        LM_TRY(ccs_parse(ByteView{p.ccs, p.ccs_len}, pub, id));
        if (id == local_device_) {
            return Status::InvalidArgument; // no handshake with ourselves
        }
        std::memcpy(p.kid, id.bytes.data(), 32);
        p.pub[0] = 0x04;
        std::memcpy(p.pub + 1, pub.x.data(), 32);
        std::memcpy(p.pub + 33, pub.y.data(), 32);
    }
    const int rc = lm_edhoc_session_init(&session_, role_ == HsRole::Initiator ? 1 : 0);
    last_rc_ = rc;
    if (rc != 0) {
        return Status::RecoveryRequired;
    }
    session_ready_ = true;
    return Status::Ok;
}

Status HandshakeSlot::run_job(port::JobEnv &, void *arg) {
    return static_cast<HandshakeSlot *>(arg)->run();
}

Status HandshakeSlot::run() {
    if (!session_ready_) {
        LM_TRY(init_session());
    }
    if (is_compose(armed_) || is_process(armed_)) {
        std::size_t len = 0;
        const int rc = lm_edhoc_session_step(&session_, to_c(armed_), in_.data(), in_len_,
                                             out_.data(), out_.size(), &len);
        last_rc_ = rc;
        out_len_ = is_compose(armed_) && rc == 0 ? len : 0;
        return map_rc(rc, session_.crypto.fault);
    }
    if (armed_ == HsStep::Export) {
        std::array<uint8_t, 32> seed{};
        int rc = lm_edhoc_session_export(&session_, ctx_hash_.data(), ctx_hash_.size(), seed.data(),
                                         seed.size());
        last_rc_ = rc;
        Status st = map_rc(rc, session_.crypto.fault);
        if (st == Status::Ok) {
            st = derive_record_keys(ByteView{seed.data(), seed.size()}, ctx_hash_, purpose_,
                                    role_ == HsRole::Initiator, keys_);
        }
        secure_zero(MutByteView{seed.data(), seed.size()});
        // The EDHOC state (PRKs, ephemeral keys) is not needed any more: destroy it here, on the
        // worker, before the owner ever sees the result. A handle that cannot be destroyed fails
        // the export (keys are dropped in complete()) and complete() retries the teardown.
        if (lm_edhoc_session_destroy(&session_) != 0) {
            return Status::RecoveryRequired;
        }
        session_ready_ = false;
        return st;
    }
    return Status::Conflict;
}

Status HandshakeSlot::complete(Status job_status) {
    const HsStep done = armed_;
    in_flight_ = false;
    armed_ = HsStep::None;
    if (cancelled_) {
        return wipe() == Status::Ok ? Status::Conflict : Status::RecoveryRequired;
    }
    if (job_status != Status::Ok) {
        const Status w = wipe();
        return w == Status::Ok ? job_status : w;
    }
    const bool init = role_ == HsRole::Initiator;
    switch (done) {
    case HsStep::M1Compose: expected_ = HsStep::M2Process; break;
    case HsStep::M1Process: expected_ = HsStep::M2Compose; break;
    case HsStep::M2Compose: expected_ = HsStep::M3Process; break;
    case HsStep::M3Compose: expected_ = HsStep::M4Process; break;
    case HsStep::M2Process:
    case HsStep::M3Process: {
        const int idx = session_.matched_peer;
        if (idx < 0 || static_cast<std::size_t>(idx) >= session_.peer_count) {
            const Status w = wipe();
            return w == Status::Ok ? Status::AuthRejected : w; // authenticated nobody
        }
        peer_index_ = static_cast<std::size_t>(idx);
        std::memcpy(peer_device_.bytes.data(), session_.peers[peer_index_].kid, 32);
        peer_known_ = true;
        expected_ = init ? HsStep::M3Compose : HsStep::M4Compose;
        break;
    }
    case HsStep::M4Process:
    case HsStep::M4Compose:
        state_ = State::Established;
        expected_ = HsStep::Export;
        break;
    case HsStep::Export:
        keys_ready_ = true;
        expected_ = HsStep::None;
        break;
    default: {
        const Status w = wipe();
        return w == Status::Ok ? Status::Conflict : w;
    }
    }
    return Status::Ok;
}

Status HandshakeSlot::cancel() {
    if (in_flight_) {
        cancelled_ = true;
        return Status::Busy;
    }
    return wipe();
}

Status HandshakeSlot::set_context(const SessionContext &ctx) {
    if (!peer_known_ || in_flight_ || cancelled_ || keys_ready_) {
        return Status::Conflict;
    }
    const bool init = role_ == HsRole::Initiator;
    if (ctx.initiator != (init ? local_device_ : peer_device_) ||
        ctx.responder != (init ? peer_device_ : local_device_)) {
        return Status::AuthRejected;
    }
    Sha256Digest h{};
    LM_TRY(sec::context_hash(ctx, h));
    ctx_hash_ = h;
    purpose_ = ctx.purpose;
    ctx_set_ = true;
    return Status::Ok;
}

Status HandshakeSlot::take_keys(RecordKeys &out) {
    if (!keys_ready_ || in_flight_) {
        return Status::Conflict;
    }
    out = std::move(keys_); // the slot's copy is zeroed by the move
    // The keys are ours now. A teardown failure stays visible through teardown_failed() and blocks
    // the next begin() until the handles were destroyed.
    (void)wipe();
    return Status::Ok;
}

Status HandshakeSlot::wipe() {
    // Also wipes when init never ran. On failure the session (and its handles) stays for a retry.
    const bool destroyed = lm_edhoc_session_destroy(&session_) == 0;
    keys_.wipe();
    secure_zero(MutByteView{in_.data(), in_.size()});
    secure_zero(MutByteView{out_.data(), out_.size()});
    local_key_ = KeyHandle{};
    in_len_ = out_len_ = 0;
    ctx_hash_.fill(0);
    state_ = State::Idle;
    expected_ = HsStep::None;
    armed_ = HsStep::None;
    in_flight_ = false;
    cancelled_ = false;
    session_ready_ = false;
    peer_known_ = false;
    ctx_set_ = false;
    keys_ready_ = false;
    peer_index_ = 0;
    if (!destroyed) {
        state_ = State::Failed;
        session_ready_ = true;
        return Status::RecoveryRequired;
    }
    return Status::Ok;
}

} // namespace lm::sec
