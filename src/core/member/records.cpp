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
    own_floor_ = Floors::Entry{};
    ccs_len_ = 0;
    bundle_len_ = 0;
    dc_off_ = dc_len_ = mc_off_ = mc_len_ = 0;
    sec::secure_zero(MutByteView{deleg_cose_});
    deleg_cose_len_ = 0;
    paired_host_.fill(0);
    paired_status_ = Status::NotFound;
    sec::secure_zero(MutByteView{scope_});
    has_scope_ = false;
    rec_lent_ = false;
    delegation_behind_ = false;
}

Status LocalIdentity::adopt_member(const RootDelegation &delegation, const MemberCredential &mc,
                                   ByteView mc_cose) {
    if (state_ != State::Ready) {
        return Status::Conflict;
    }
    const std::size_t dc_len = dc_len_;
    LM_TRY(check_binding(dc_, device_cose(), mc));
    if (mc_cose.empty() || mc_cose.size() > k_max_member_cose) {
        return Status::InvalidArgument; // checked before the bundle is touched: a refusal keeps the live one
    }
    // [S18] A member adopting a renewed credential has its DeviceCredential at the front of the bundle: it moves to
    // the tail first, so the new bundle is never built from bytes it overwrites.
    uint8_t *tail = bundle_.data() + k_max_bundle - dc_len;
    std::memmove(tail, bundle_.data() + dc_off_, dc_len);
    dc_off_ = k_max_bundle - dc_len;
    LM_TRY(bundle_encode(ByteView{tail, dc_len}, mc_cose, MutByteView{bundle_}, bundle_len_));
    dc_len_ = dc_len;
    mc_len_ = mc_cose.size();
    dc_off_ = 1 + head_size(dc_len_);
    mc_off_ = dc_off_ + dc_len_ + head_size(mc_len_);
    delegation_ = delegation;
    has_delegation_ = true;
    mc_ = mc;
    has_member_ = true;
    member_status_ = Status::Ok;
    return Status::Ok;
}

void LocalIdentity::drop_member(const Floors::Entry &floor, bool revoked) {
    own_floor_.device = dc_.device;
    own_floor_.assignment = std::max(own_floor_.assignment, floor.assignment);
    own_floor_.membership = std::max(own_floor_.membership, floor.membership);
    has_member_ = false;
    has_delegation_ = false;
    member_status_ = revoked ? Status::Revoked : Status::NotFound; // [S18] lm_membership_get: MEMBER_REVOKED
    mc_ = MemberCredential{};
    delegation_ = RootDelegation{};
    bundle_len_ = 0; // the DeviceCredential stays where device_cose() finds it
    mc_len_ = 0;
    sec::secure_zero(MutByteView{deleg_cose_});
    deleg_cose_len_ = 0;
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
    if constexpr (k_root_capable) {
        load_paired_host(env); // its own status: a pairing problem never fails the identity
    }
    load_scope(env);
    load_power(env);

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
    if constexpr (k_root_capable) {
        std::memcpy(deleg_cose_.data(), rec_.payload.data(), rec_.payload_len); // <= k_max_delegation_cose
        deleg_cose_len_ = rec_.payload_len;
    }
    return load_membership(env);
}

void LocalIdentity::load_paired_host(port::JobEnv &env) {
    paired_status_ = load_record(env, store::rec::paired_host);
    if (paired_status_ == Status::Ok && (rec_.payload_len != paired_host_.size() ||
                                         rec_.state != store::k_paired_host_active)) {
        paired_status_ = Status::NotFound; // no installed pairing: unpaired, every Host is refused
    }
    if (paired_status_ == Status::Ok) {
        std::copy_n(rec_.payload.begin(), paired_host_.size(), paired_host_.begin());
    }
}

void LocalIdentity::load_power(port::JobEnv &env) {
    power_status_ = load_record(env, store::rec::power_policy);
    power_len_ = 0;
    if (power_status_ == Status::Ok && rec_.payload_len > power_policy_.size()) {
        power_status_ = Status::RecoveryRequired;
    }
    if (power_status_ == Status::Ok) {
        power_len_ = static_cast<uint8_t>(rec_.payload_len);
        std::copy_n(rec_.payload.begin(), power_len_, power_policy_.begin());
    }
    sec::secure_zero(MutByteView{rec_.payload});
}

void LocalIdentity::load_scope(port::JobEnv &env) {
    has_scope_ = load_record(env, store::rec::discovery_scope) == Status::Ok && rec_.payload_len == scope_.size();
    if (has_scope_) {
        std::copy_n(rec_.payload.begin(), scope_.size(), scope_.begin());
    }
    sec::secure_zero(MutByteView{rec_.payload});
}

// [S18] The membership record names another root than root_delegation: a transfer or handover committed its
// credential and was cut before it rewrote root_delegation. The pending delegation of that switch must be fleet-signed
// and verify the credential; anything else stays a failure (never a guess).
Status LocalIdentity::load_pending_delegation(port::JobEnv &env, ByteView mc) {
    std::array<uint8_t, k_max_member_cose> keep{};
    if (mc.size() > keep.size()) {
        return Status::RecoveryRequired;
    }
    std::copy(mc.begin(), mc.end(), keep.begin());
    LM_TRY(load_record(env, store::rec::pending_delegation));
    RootDelegation d;
    LM_TRY(check_root_delegation(trust_, ByteView{rec_.payload.data(), rec_.payload_len}, d));
    if constexpr (k_root_capable) {
        std::memcpy(deleg_cose_.data(), rec_.payload.data(), rec_.payload_len);
        deleg_cose_len_ = rec_.payload_len;
    }
    std::copy(keep.begin(), keep.begin() + mc.size(), rec_.payload.begin());
    rec_.payload_len = static_cast<uint32_t>(mc.size());
    LM_TRY(check_member_credential(d, ByteView{rec_.payload.data(), mc.size()}, mc_));
    delegation_ = d;
    delegation_behind_ = true;
    return Status::Ok;
}

Status LocalIdentity::load_membership(port::JobEnv &env) {
    const ByteView dc{bundle_.data() + k_max_bundle - dc_len_, dc_len_};
    const Status st = load_record(env, store::rec::membership);
    if (st == Status::NotFound) {
        return Status::Ok;
    }
    LM_TRY(st);
    if ((rec_.state == k_membership_left || rec_.state == k_membership_revoked) &&
        rec_.payload_len == k_left_bytes) { // SEC-D8: what the device consumed
        Reader r{ByteView{rec_.payload.data(), rec_.payload_len}};
        own_floor_.device = dc_.device;
        own_floor_.assignment = r.u64be();
        own_floor_.membership = r.u64be();
        member_status_ = rec_.state == k_membership_revoked ? Status::Revoked : Status::NotFound;
        return r.finish();
    }
    if (rec_.state != k_membership_active) {
        return Status::Ok; // PREPARED or LEAVING records are the join slice's business
    }
    const ByteView mc{rec_.payload.data(), rec_.payload_len};
    Status ck = check_member_credential(delegation_, mc, mc_);
    if (ck == Status::AuthRejected || ck == Status::NetworkMismatch) {
        LM_TRY(load_pending_delegation(env, mc)); // [S18] the cut between a transfer's two commits
    } else {
        LM_TRY(ck);
    }
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
