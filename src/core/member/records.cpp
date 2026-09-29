#include "core/member/records.hpp"

#include <algorithm>
#include <cstring>

#include "core/codec.hpp"
#include "core/engine.hpp"
#include "security/crypto.hpp"

namespace lm::member {
namespace {

constexpr std::size_t head_size(std::size_t n) { return n < 24 ? 1 : (n < 256 ? 2 : 3); }

} // namespace

Status encode_identity(ByteView scalar32, ByteView device_cose, MutByteView out, std::size_t &len) {
    if (scalar32.size() != 32 || device_cose.empty() || device_cose.size() > k_max_device_cose) {
        return Status::InvalidArgument;
    }
    Writer w{out};
    w.bytes(scalar32);
    w.bytes(device_cose);
    len = w.size();
    return w.finish();
}

Status decode_identity(ByteView payload, ByteView &scalar32, ByteView &device_cose) {
    if (payload.size() <= 32 || payload.size() > 32 + k_max_device_cose) {
        return Status::BadFrame;
    }
    scalar32 = payload.first(32);
    device_cose = payload.from(32);
    return Status::Ok;
}

Status encode_trust(const TrustAnchor &t, MutByteView out, std::size_t &len) {
    Writer w{out};
    w.bytes(t.fleet.view());
    w.bytes(ByteView{t.key.x});
    w.bytes(ByteView{t.key.y});
    w.u64be(t.min_credential_generation);
    len = w.size();
    return w.finish();
}

Status decode_trust(ByteView payload, TrustAnchor &out) {
    Reader r{payload};
    FleetId fleet;
    sec::PublicKey key;
    r.copy_to(fleet.bytes);
    r.copy_to(key.x);
    r.copy_to(key.y);
    const uint64_t min_gen = r.u64be();
    LM_TRY(r.finish());
    return make_trust_anchor(fleet, key, min_gen, out);
}

Status encode_floors(const Floors &f, MutByteView out, std::size_t &len) {
    Writer w{out};
    w.u8(static_cast<uint8_t>(f.count()));
    for (std::size_t i = 0; i < f.count(); ++i) {
        w.bytes(f.at(i).device.view());
        w.u64be(f.at(i).assignment);
        w.u64be(f.at(i).membership);
    }
    len = w.size();
    return w.finish();
}

Status decode_floors(ByteView payload, Floors &out) {
    Reader r{payload};
    const uint8_t n = r.u8();
    if (!r.ok() || n > k_max_floors) {
        return Status::BadFrame;
    }
    Floors f;
    for (uint8_t i = 0; i < n; ++i) {
        DeviceId d;
        r.copy_to(d.bytes);
        const uint64_t a = r.u64be();
        const uint64_t m = r.u64be();
        if (!r.ok()) {
            break;
        }
        LM_TRY(f.raise(d, a, m));
    }
    LM_TRY(r.finish());
    out = f;
    return Status::Ok;
}

// ---- LocalIdentity ----
Status LocalIdentity::begin_load(Engine &engine) {
    if (job_in_flight_) {
        return Status::Busy; // a cancelled load still owns this memory
    }
    if (state_ == State::Loading) {
        return Status::Conflict;
    }
    clear();
    state_ = State::Loading;
    slot_ = Handle{0, slot_.generation + 1};
    const Status s = engine.submit_job(JobOwner::Identity, slot_, JobClass::PublicKey, &load_job, this);
    if (s != Status::Ok) {
        state_ = State::Unloaded;
        return s;
    }
    job_in_flight_ = true;
    return Status::Ok;
}

void LocalIdentity::on_job_done(Status job_status, Handle slot) {
    job_in_flight_ = false;
    if (cancelled_) {
        cancelled_ = false;
        clear();
        return;
    }
    if (slot != slot_ || state_ != State::Loading) {
        return; // stale
    }
    if (job_status == Status::Ok) {
        state_ = unprovisioned_ ? State::Unprovisioned : State::Ready;
        load_status_ = Status::Ok;
        return;
    }
    clear();
    state_ = State::Failed;
    load_status_ = job_status;
}

void LocalIdentity::release() {
    if (job_in_flight_) {
        cancelled_ = true; // memory stays reserved until the completion is polled
        state_ = State::Unloaded;
        return;
    }
    clear();
}

void LocalIdentity::clear() {
    sec::destroy_key(key_);
    sec::secure_zero(MutByteView{rec_.payload});
    sec::secure_zero(MutByteView{rec_.scratch});
    state_ = State::Unloaded;
    unprovisioned_ = false;
    has_delegation_ = false;
    has_member_ = false;
    load_status_ = Status::Ok;
    member_status_ = Status::NotFound;
    trust_ = TrustAnchor{};
    dc_ = DeviceCredential{};
    delegation_ = RootDelegation{};
    mc_ = MemberCredential{};
    floors_.clear();
    ccs_len_ = 0;
    bundle_len_ = 0;
    dc_off_ = dc_len_ = mc_off_ = mc_len_ = 0;
}

Status LocalIdentity::load_job(port::JobEnv &env, void *arg) {
    return static_cast<LocalIdentity *>(arg)->run_load(env);
}

Status LocalIdentity::load_record(port::JobEnv &env, uint16_t id) {
    rec_.op = store::RecordJob::Op::Load;
    rec_.id = id;
    rec_.state = 0;
    rec_.payload_len = 0;
    return store::record_load(env.store, rec_);
}

Status LocalIdentity::run_load(port::JobEnv &env) {
    LM_TRY(sec::crypto_init());
    Status st = load_record(env, store::rec::identity);
    if (st == Status::NotFound) {
        unprovisioned_ = true; // never provisioned; every other failure stays a failure
        return Status::Ok;
    }
    LM_TRY(st);
    ByteView scalar;
    ByteView dc_cose;
    st = decode_identity(ByteView{rec_.payload.data(), rec_.payload_len}, scalar, dc_cose);
    if (st == Status::Ok) {
        dc_len_ = dc_cose.size();
        // The DeviceCredential waits at the tail of the bundle buffer until the bundle is built.
        dc_off_ = k_max_bundle - dc_len_;
        std::memcpy(bundle_.data() + dc_off_, dc_cose.data(), dc_len_);
        st = sec::import_signing_key(scalar, key_);
    }
    sec::secure_zero(MutByteView{rec_.payload}); // the scalar was in these buffers
    sec::secure_zero(MutByteView{rec_.scratch});
    LM_TRY(st);
    const ByteView dc{bundle_.data() + k_max_bundle - dc_len_, dc_len_};

    st = load_record(env, store::rec::fleet_trust);
    if (st == Status::NotFound) {
        return Status::RecoveryRequired; // an identity without its trust anchor is half-provisioned
    }
    LM_TRY(st);
    LM_TRY(decode_trust(ByteView{rec_.payload.data(), rec_.payload_len}, trust_));
    LM_TRY(check_device_credential(trust_, dc, dc_));
    sec::PublicKey pub;
    LM_TRY(sec::public_key_of(key_, pub));
    if (pub.x != dc_.key.x || pub.y != dc_.key.y) {
        return Status::AuthRejected; // the credential names a different key than the one stored
    }
    LM_TRY(sec::ccs_encode(ByteView{dc_.serial.data(), dc_.serial_len}, dc_.key, MutByteView{ccs_},
                           ccs_len_));

    st = load_record(env, store::rec::revocation_floors);
    if (st == Status::Ok) {
        LM_TRY(decode_floors(ByteView{rec_.payload.data(), rec_.payload_len}, floors_));
    } else if (st != Status::NotFound) {
        return st;
    }
    st = load_record(env, store::rec::root_delegation);
    if (st == Status::NotFound) {
        return Status::Ok; // identity only: not (yet) part of a domain
    }
    LM_TRY(st);
    LM_TRY(check_root_delegation(trust_, ByteView{rec_.payload.data(), rec_.payload_len}, delegation_));
    has_delegation_ = true;
    return load_membership(env);
}

Status LocalIdentity::load_membership(port::JobEnv &env) {
    const ByteView dc{bundle_.data() + k_max_bundle - dc_len_, dc_len_};
    const Status st = load_record(env, store::rec::membership);
    if (st == Status::NotFound) {
        return Status::Ok;
    }
    LM_TRY(st);
    if (rec_.state != k_membership_active) {
        return Status::Ok; // PREPARED or LEAVING records are the join slice's business
    }
    const ByteView mc{rec_.payload.data(), rec_.payload_len};
    LM_TRY(check_member_credential(delegation_, mc, mc_));
    LM_TRY(check_binding(dc_, dc, mc_));
    if (floors_.check(dc_.device, mc_.assignment, mc_.membership) != Status::Ok) {
        member_status_ = Status::Revoked; // valid identity, credential below the revocation floor
        return Status::Ok;
    }
    LM_TRY(bundle_encode(dc, mc, MutByteView{bundle_}, bundle_len_));
    dc_len_ = dc.size();
    mc_len_ = mc.size();
    dc_off_ = 1 + head_size(dc_len_);
    mc_off_ = dc_off_ + dc_len_ + head_size(mc_len_);
    has_member_ = true;
    member_status_ = Status::Ok;
    return Status::Ok;
}

} // namespace lm::member
