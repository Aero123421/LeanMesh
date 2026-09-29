// Handshake half of UsbLink: credential exchange (CredI/CredR), EDHOC steps as slow jobs, session
// context and key installation. See usb_link.hpp for the protocol.
#include <algorithm>
#include <cstring>
#include <utility>

#include "core/wire/cbor.hpp"
#include "core/wire/cbor_reader.hpp"
#include "security/crypto.hpp"
#include "serial/usb_link.hpp"

namespace lm::serial {
namespace {

constexpr uint8_t k_obj_max = 6;

// [device] (Host) or [device, delegation] (root): what CredI / CredR carry.
Status parse_creds(ByteView in, bool with_delegation, ByteView &device, ByteView &delegation) {
    LM_TRY(wire::cbor_validate(in));
    wire::CborReader r{in};
    (void)r.array(with_delegation ? 2 : 1, with_delegation ? 2 : 1);
    device = r.bstr(1, member::k_max_device_cose);
    delegation = with_delegation ? r.bstr(1, member::k_max_delegation_cose) : ByteView{};
    return r.finish();
}

} // namespace

// ---- job plumbing ----
Status UsbLink::job_entry(port::JobEnv &env, void *arg) {
    auto *l = static_cast<UsbLink *>(arg);
    return l->job_ == Job::Verify ? l->verify_body() : sec::HandshakeSlot::run_job(env, &l->hs_);
}

// Worker: checks the peer's credential chain. Root: the Host's DeviceCredential must be fleet-signed
// and be exactly the paired Host. Host: the root's DeviceCredential and RootDelegation must both be
// fleet-signed, the delegation must name that root and (if configured) the expected domain.
Status UsbLink::verify_body() {
    const bool host = role_ == UsbRole::Host;
    ByteView dcose;
    ByteView dele;
    LM_TRY(parse_creds(ByteView{cred_rx_.data(), cred_rx_len_}, host, dcose, dele));
    member::DeviceCredential dc;
    LM_TRY(member::check_device_credential(trust_, dcose, dc));
    Peer p;
    if (host) {
        member::RootDelegation d;
        LM_TRY(member::check_root_delegation(trust_, dele, d));
        if (d.root != dc.device) {
            return Status::AuthRejected;
        }
        if (!domain_.is_zero() && d.domain != domain_) {
            return Status::NetworkMismatch;
        }
        p.domain = d.domain;
    } else {
        if (dc.device != paired_) {
            return Status::AuthRejected; // a valid fleet device, but not the one paired here (D6)
        }
        p.domain = domain_;
    }
    p.device = dc.device;
    LM_TRY(sec::ccs_encode(ByteView{dc.serial.data(), dc.serial_len}, dc.key, MutByteView{p.ccs}, p.ccs_len));
    LM_TRY(sec::sha256(dcose, p.cred_hash));
    peer_ = p;
    return Status::Ok;
}

Status UsbLink::start_job(Job job, sec::HsStep step, ByteView input, MonoTime now) {
    if (job == Job::Hs) {
        LM_TRY(hs_.prepare(step, input));
        hs_step_ = step;
    }
    job_ = job;
    job_deferred_ = false;
    const Status st = env_.submit(handle_, JobClass::PublicKey, &job_entry, this);
    if (st == Status::Busy) {
        // The single public-key slot is taken (a link exchange is running). The job stays armed and
        // is submitted again shortly; the handshake deadline bounds the wait.
        job_deferred_ = true;
        job_retry_at_ = now + timing_.job_retry;
        return Status::Ok;
    }
    if (st != Status::Ok) {
        job_ = Job::None;
        if (job == Job::Hs) {
            hs_.unprepare();
        }
    }
    return st;
}

void UsbLink::retry_job(MonoTime now) {
    job_retry_at_ = MonoTime::never();
    const Status st = env_.submit(handle_, JobClass::PublicKey, &job_entry, this);
    if (st == Status::Busy) {
        job_retry_at_ = now + timing_.job_retry;
    } else if (st == Status::Ok) {
        job_deferred_ = false;
    } else {
        abort_attempt(st, now);
    }
}

// ---- attempt lifecycle ----
void UsbLink::begin_attempt(uint32_t sid, MonoTime now) {
    handle_ = Handle{0, ++handle_gen_ == 0 ? ++handle_gen_ : handle_gen_};
    cand_sid_ = sid;
    cand_ = -1;
    stage_len_ = 0;
    stage_hold_ = false;
    bind_ping_due_ = false;
    cred_rx_len_ = 0;
    peer_ = Peer{};
    attempt_deadline_ = now + timing_.attempt;
    last_attempt_ = now;
    attempt_seen_ = true;
    ++stats_.hs_started;
}

void UsbLink::abort_attempt(Status why, MonoTime now) {
    if (phase_ == Phase::Idle || phase_ == Phase::Zombie) {
        return;
    }
    if (why != Status::Ok) {
        ++stats_.hs_failed;
        last_failure_ = why;
        // Host retries with backoff; the root only rate-limits accepted attempts.
        const uint32_t shift = std::min<uint32_t>(fail_streak_++, 5);
        next_attempt_at_ = now + Duration{std::min(timing_.hello_max.us, timing_.attempt_gate.us << shift)};
    }
    if (cand_ >= 0) {
        keys_[cand_].wipe();
        cand_ = -1;
    }
    stage_len_ = 0;
    stage_hold_ = false;
    bind_ping_due_ = false;
    attempt_deadline_ = MonoTime::never();
    if (job_deferred_) {
        hs_.unprepare(); // armed but never submitted: nothing will complete
        job_ = Job::None;
        job_deferred_ = false;
        job_retry_at_ = MonoTime::never();
    }
    (void)hs_.cancel(); // Busy while a job is in flight: wiped by its completion (zombie rule)
    phase_ = job_ != Job::None ? Phase::Zombie : Phase::Idle;
}

void UsbLink::on_job_done(Handle slot, Status job_status, MonoTime now) {
    if (phase_ == Phase::Zombie) {
        if (job_ == Job::Hs) {
            (void)hs_.complete(job_status); // wipes the cancelled slot
        }
        job_ = Job::None;
        phase_ = Phase::Idle;
        pump(now);
        return;
    }
    if (slot != handle_ || job_ == Job::None) {
        return; // completion of an earlier attempt
    }
    const Job j = job_;
    job_ = Job::None;
    if (job_status != Status::Ok) {
        if (j == Job::Hs) {
            (void)hs_.complete(job_status); // aborts the handshake and wipes the secrets
        } else {
            ++stats_.hs_rejected;
        }
        abort_attempt(job_status, now);
    } else if (j == Job::Verify) {
        after_verify(now);
    } else {
        after_hs(now);
    }
    pump(now);
}

void UsbLink::stage(Obj kind, ByteView body, bool hold) {
    wire::CborWriter w{MutByteView{stage_}};
    w.array(2);
    w.uint(static_cast<uint8_t>(kind));
    w.bytes(body);
    stage_len_ = w.finish() == Status::Ok ? w.size() : 0;
    stage_hold_ = hold;
}

// Host: a root HELLO asked for a handshake and the gate/backoff allows it.
void UsbLink::maybe_start_attempt(MonoTime now) {
    if (role_ != UsbRole::Host || !attempt_wanted_ || phase_ != Phase::Idle || !open_ ||
        !configured_ || now < next_attempt_at_) {
        return;
    }
    attempt_wanted_ = false;
    std::array<uint8_t, 4> b{};
    uint32_t sid = 0;
    for (int i = 0; i < 8 && sid == 0; ++i) {
        env_.random(MutByteView{b});
        const uint32_t v = (uint32_t{b[0]} << 24U) | (uint32_t{b[1]} << 16U) | (uint32_t{b[2]} << 8U) | b[3];
        sid = (v != 0 && (act_ < 0 || v != keys_[act_].sid)) ? v : 0;
    }
    if (sid == 0) {
        return;
    }
    begin_attempt(sid, now);
    stage(Obj::CredI, ByteView{own_cred_.data(), own_cred_len_}, false);
    phase_ = Phase::AwaitCred;
    expect_ = Obj::CredR;
}

void UsbLink::handle_edhoc(uint32_t sid, ByteView payload, MonoTime now) {
    if (!configured_ || wire::cbor_validate(payload) != Status::Ok) {
        ++stats_.rx_edhoc_dropped;
        return;
    }
    wire::CborReader r{payload};
    (void)r.array(2, 2);
    const uint64_t kind = r.uint_in(1, k_obj_max);
    const ByteView body = r.bstr(1, 1000);
    if (r.finish() != Status::Ok) {
        ++stats_.rx_edhoc_dropped;
        return;
    }
    const bool root = role_ == UsbRole::Root;
    if (root && kind == static_cast<uint64_t>(Obj::CredI)) {
        // A new attempt: one at a time, rate-limited (each costs public-key work), never on the
        // session id of the ACTIVE session.
        const bool gated = attempt_seen_ && now - last_attempt_ < timing_.attempt_gate;
        if (phase_ != Phase::Idle || gated || sid == 0 || (act_ >= 0 && sid == keys_[act_].sid) ||
            body.size() > cred_rx_.size()) {
            ++stats_.rx_edhoc_dropped;
            return;
        }
        begin_attempt(sid, now);
        std::memcpy(cred_rx_.data(), body.data(), body.size());
        cred_rx_len_ = body.size();
        phase_ = Phase::Verify;
        const Status st = start_job(Job::Verify, sec::HsStep::None, ByteView{}, now);
        if (st != Status::Ok) {
            abort_attempt(st, now);
        }
        return;
    }
    if ((phase_ != Phase::AwaitCred && phase_ != Phase::AwaitMsg) || sid != cand_sid_ ||
        kind != static_cast<uint64_t>(expect_)) {
        ++stats_.rx_edhoc_dropped; // unexpected, duplicate, stale or from another attempt
        return;
    }
    Status st = Status::Ok;
    switch (expect_) {
    case Obj::CredR:
        if (body.size() > cred_rx_.size()) {
            st = Status::PayloadTooLarge;
            break;
        }
        std::memcpy(cred_rx_.data(), body.data(), body.size());
        cred_rx_len_ = body.size();
        phase_ = Phase::Verify;
        st = start_job(Job::Verify, sec::HsStep::None, ByteView{}, now);
        break;
    case Obj::Msg1:
        phase_ = Phase::Hs;
        st = start_job(Job::Hs, sec::HsStep::M1Process, body, now);
        break;
    case Obj::Msg2:
        phase_ = Phase::Hs;
        st = start_job(Job::Hs, sec::HsStep::M2Process, body, now);
        break;
    case Obj::Msg3:
        phase_ = Phase::Hs;
        st = start_job(Job::Hs, sec::HsStep::M3Process, body, now);
        break;
    case Obj::Msg4:
        phase_ = Phase::Hs;
        st = start_job(Job::Hs, sec::HsStep::M4Process, body, now);
        break;
    case Obj::CredI:
        st = Status::Conflict;
        break;
    }
    if (st != Status::Ok) {
        abort_attempt(st, now);
    }
}

void UsbLink::after_verify(MonoTime now) {
    const sec::HsRole hr = role_ == UsbRole::Root ? sec::HsRole::Responder : sec::HsRole::Initiator;
    const ByteView peers[1] = {ByteView{peer_.ccs.data(), peer_.ccs_len}};
    Status st = hs_.begin(hr, key_, ByteView{ccs_.data(), ccs_len_}, peers, 1);
    if (st == Status::Ok) {
        if (role_ == UsbRole::Root) {
            stage(Obj::CredR, ByteView{own_cred_.data(), own_cred_len_}, false);
            phase_ = Phase::AwaitMsg;
            expect_ = Obj::Msg1;
        } else {
            phase_ = Phase::Hs;
            st = start_job(Job::Hs, sec::HsStep::M1Compose, ByteView{}, now);
        }
    }
    if (st != Status::Ok) {
        abort_attempt(st, now);
    }
}

// Both sides derive the same context from what they verified: purpose 3, the domain of the root's
// delegation, the two DeviceIds, no mesh generations (a USB pairing is not a membership), and the
// hashes of the two DeviceCredentials (decision S10-D1).
Status UsbLink::make_context() {
    const bool root = role_ == UsbRole::Root;
    ctx_ = sec::SessionContext{};
    ctx_.purpose = sec::Purpose::Usb;
    ctx_.fleet = trust_.fleet;
    ctx_.domain = peer_.domain;
    ctx_.initiator = root ? peer_.device : self_;
    ctx_.responder = root ? self_ : peer_.device;
    ctx_.credential_hash_i = root ? peer_.cred_hash : own_hash_;
    ctx_.credential_hash_r = root ? own_hash_ : peer_.cred_hash;
    return Status::Ok;
}

void UsbLink::after_hs(MonoTime now) {
    const sec::HsStep step = hs_step_;
    Status st = hs_.complete(Status::Ok);
    if (st != Status::Ok) {
        abort_attempt(st, now);
        return;
    }
    using S = sec::HsStep;
    const bool root = role_ == UsbRole::Root;
    switch (step) {
    case S::M1Compose: // Host
        stage(Obj::Msg1, hs_.output(), false);
        phase_ = Phase::AwaitMsg;
        expect_ = Obj::Msg2;
        break;
    case S::M2Process: // Host
        phase_ = Phase::Hs;
        st = start_job(Job::Hs, S::M3Compose, ByteView{}, now);
        break;
    case S::M3Compose: // Host
        stage(Obj::Msg3, hs_.output(), false);
        phase_ = Phase::AwaitMsg;
        expect_ = Obj::Msg4;
        break;
    case S::M1Process: // root
        phase_ = Phase::Hs;
        st = start_job(Job::Hs, S::M2Compose, ByteView{}, now);
        break;
    case S::M2Compose: // root
        stage(Obj::Msg2, hs_.output(), false);
        phase_ = Phase::AwaitMsg;
        expect_ = Obj::Msg3;
        break;
    case S::M3Process: // root
    case S::M4Process: // Host
        st = make_context();
        if (st == Status::Ok) {
            st = hs_.set_context(ctx_);
        }
        if (st == Status::Ok) {
            ctx_hash_ = hs_.context_hash();
            phase_ = Phase::Hs;
            st = start_job(Job::Hs, root ? S::M4Compose : S::Export, ByteView{}, now);
        }
        break;
    case S::M4Compose: // root: held back until the keys exist, so the Host's first PING finds them
        stage(Obj::Msg4, hs_.output(), true);
        phase_ = Phase::Hs;
        st = start_job(Job::Hs, S::Export, ByteView{}, now);
        break;
    case S::Export:
        finish_keys(now);
        return;
    case S::None:
        st = Status::RecoveryRequired;
        break;
    }
    if (st != Status::Ok) {
        abort_attempt(st, now);
    }
}

void UsbLink::finish_keys(MonoTime now) {
    sec::RecordKeys keys; // move-only, wipes itself
    Status st = hs_.take_keys(keys);
    if (st == Status::Ok) {
        const int slot = act_ == 0 ? 1 : 0;
        keys_[slot].wipe();
        st = keys_[slot].rec.install(std::move(keys));
        if (st == Status::Ok) {
            keys_[slot].ctx_hash = ctx_hash_;
            keys_[slot].sid = cand_sid_;
            keys_[slot].valid = true;
            cand_ = slot;
        }
    }
    if (st != Status::Ok) {
        abort_attempt(st, now);
        return;
    }
    phase_ = Phase::AwaitBind;
    if (role_ == UsbRole::Host) {
        bind_ping_due_ = true;
    } else {
        stage_hold_ = false; // message_4 goes out now that the keys can open the Host's first record
    }
}

} // namespace lm::serial
