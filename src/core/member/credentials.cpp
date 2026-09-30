#include "core/member/credentials.hpp"

#include <algorithm>

#include "core/wire/cbor.hpp"
#include "core/wire/cbor_reader.hpp"
#include "core/wire/control.hpp"
#include "security/cose_sign1.hpp"
#include "security/crypto.hpp"

namespace lm::member {
namespace {

using wire::CborReader;
using wire::CborWriter;

constexpr uint64_t k_u32_max = 0xFFFFFFFFULL;

template <std::size_t N, class Tag> void rd_id(CborReader &r, FixedId<N, Tag> &id) {
    const ByteView v = r.bstr(N, N);
    if (r.ok()) {
        std::copy(v.begin(), v.end(), id.bytes.begin());
    }
}

void rd_hash(CborReader &r, Sha256Digest &h) {
    const ByteView v = r.bstr(32, 32);
    if (r.ok()) {
        std::copy(v.begin(), v.end(), h.begin());
    }
}

void rd_nonce(CborReader &r, std::array<uint8_t, 16> &n) {
    const ByteView v = r.bstr(16, 16);
    if (r.ok()) {
        std::copy(v.begin(), v.end(), n.begin());
    }
}

// {1: 2, -1: 1, -2: x32, -3: y32}
void rd_key(CborReader &r, sec::PublicKey &k) {
    r.map_exact(4);
    (void)r.uint_in(1, 1);
    (void)r.uint_in(2, 2);
    (void)r.int_in(-1, -1);
    (void)r.uint_in(1, 1);
    (void)r.int_in(-2, -2);
    const ByteView x = r.bstr(32, 32);
    (void)r.int_in(-3, -3);
    const ByteView y = r.bstr(32, 32);
    if (r.ok()) {
        std::copy(x.begin(), x.end(), k.x.begin());
        std::copy(y.begin(), y.end(), k.y.begin());
    }
}

bool printable(ByteView s) {
    return std::all_of(s.begin(), s.end(), [](uint8_t c) { return c >= 0x20 && c <= 0x7E; });
}

} // namespace

Status make_trust_anchor(const FleetId &fleet, const sec::PublicKey &key, uint64_t min_generation,
                         TrustAnchor &out) {
    LM_TRY(sec::validate_public_key(key));
    TrustAnchor t;
    t.fleet = fleet;
    t.key = key;
    t.min_credential_generation = min_generation;
    LM_TRY(sec::device_id_of(key, t.key_id));
    out = t;
    return Status::Ok;
}

// ---- decoders ----
Status decode_device_credential(ByteView data, DeviceCredential &out) {
    CborReader r{data};
    DeviceCredential c;
    (void)r.array(6, 6);
    rd_id(r, c.device);
    rd_key(r, c.key);
    rd_id(r, c.fleet);
    const ByteView serial = r.tstr(1, k_serial_max);
    c.generation = r.uint_in(0, k_u63_max);
    rd_hash(r, c.ccs_hash);
    LM_TRY(r.finish());
    std::copy(serial.begin(), serial.end(), c.serial.begin());
    c.serial_len = static_cast<uint8_t>(serial.size());
    out = c;
    return Status::Ok;
}

Status decode_root_delegation(ByteView data, RootDelegation &out) {
    CborReader r{data};
    RootDelegation d;
    (void)r.array(6, 6);
    rd_id(r, d.fleet);
    rd_id(r, d.root);
    rd_key(r, d.key);
    rd_id(r, d.domain);
    d.generation = r.uint_in(0, k_u63_max);
    d.permissions = static_cast<uint8_t>(r.uint_in(0, 63));
    LM_TRY(r.finish());
    out = d;
    return Status::Ok;
}

Status decode_assignment_ticket(ByteView data, AssignmentTicket &out) {
    CborReader r{data};
    AssignmentTicket t;
    (void)r.array(11, 11);
    rd_id(r, t.device);
    rd_id(r, t.fleet);
    rd_id(r, t.source);
    rd_id(r, t.target);
    rd_hash(r, t.root_delegation_hash);
    t.expected_old = r.uint_in(0, k_u63_max);
    t.new_generation = r.uint_in(0, k_u63_max);
    rd_id(r, t.grant);
    t.mode = static_cast<uint8_t>(r.uint_in(0, 1));
    rd_nonce(r, t.nonce);
    rd_hash(r, t.device_credential_hash);
    LM_TRY(r.finish());
    out = t;
    return Status::Ok;
}

Status decode_member_credential(ByteView data, MemberCredential &out) {
    CborReader r{data};
    MemberCredential m;
    (void)r.array(10, 10);
    rd_id(r, m.device);
    m.address = ShortAddr{static_cast<uint16_t>(r.uint_in(1, 65534))};
    m.assignment = AssignmentGen{r.uint_in(0, k_u63_max)};
    m.membership = MembershipGen{r.uint_in(0, k_u63_max)};
    m.role = static_cast<uint8_t>(r.uint_in(0, 2));
    m.relay_allowed = r.boolean();
    m.root_term = RootTerm{static_cast<uint32_t>(r.uint_in(0, k_u32_max))};
    m.lease_expires_root_ms = r.uint_in(0, UINT64_MAX);
    rd_hash(r, m.policy_hash);
    rd_hash(r, m.credential_hash);
    LM_TRY(r.finish());
    out = m;
    return Status::Ok;
}

Status decode_expected_set(ByteView data, ExpectedSet &out) {
    CborReader r{data};
    ExpectedSet s;
    (void)r.array(4, 4);
    s.page = static_cast<uint8_t>(r.uint_in(0, 15));
    s.pages = static_cast<uint8_t>(r.uint_in(1, 16));
    rd_hash(r, s.set_hash);
    const std::size_t n = r.array(0, k_expected_page_entries);
    for (std::size_t i = 0; i < n && r.ok(); ++i) {
        ExpectedEntry &e = s.entries[i];
        (void)r.array(4, 4);
        rd_id(r, e.device);
        e.assignment = r.uint_in(0, k_u63_max);
        rd_hash(r, e.grant_hash);
        e.allowed = r.boolean();
    }
    LM_TRY(r.finish());
    s.count = static_cast<uint8_t>(n);
    out = s;
    return Status::Ok;
}

Status decode_revoke(ByteView data, RevokeObject &out) {
    CborReader r{data};
    RevokeObject v;
    (void)r.array(5, 5);
    rd_id(r, v.device);
    v.assignment_floor = r.uint_in(0, k_u63_max);
    v.membership_floor = r.uint_in(0, k_u63_max);
    v.reason = static_cast<uint32_t>(r.uint_in(0, k_u32_max));
    v.revision = r.uint_in(0, k_u63_max);
    LM_TRY(r.finish());
    out = v;
    return Status::Ok;
}

Status decode_window(ByteView data, CommissioningWindow &out) {
    CborReader r{data};
    CommissioningWindow w;
    (void)r.array(8, 8);
    rd_nonce(r, w.id);
    w.term = RootTerm{static_cast<uint32_t>(r.uint_in(0, k_u32_max))};
    w.expected_revision = r.uint_in(0, k_u63_max);
    w.not_before_ms = r.uint_in(0, UINT64_MAX);
    w.expires_ms = r.uint_in(0, UINT64_MAX);
    w.max_new_members = static_cast<uint8_t>(r.uint_in(1, 64));
    w.allowed_roles = static_cast<uint8_t>(r.uint_in(1, 3));
    w.policy_revision = r.uint_in(0, k_u63_max);
    LM_TRY(r.finish());
    out = w;
    return Status::Ok;
}

Status decode_handover(ByteView data, RootHandover &out) {
    CborReader r{data};
    RootHandover h;
    (void)r.array(8, 8);
    rd_nonce(r, h.id);
    rd_id(r, h.old_root);
    rd_id(r, h.new_root);
    h.old_generation = r.uint_in(0, k_u63_max);
    h.new_generation = r.uint_in(0, k_u63_max);
    rd_hash(r, h.new_delegation_hash);
    h.new_term = RootTerm{static_cast<uint32_t>(r.uint_in(0, k_u32_max))};
    h.recovery_mode = static_cast<uint8_t>(r.uint_in(0, 1));
    LM_TRY(r.finish());
    out = h;
    return Status::Ok;
}

// ---- [FIX5-D4] RootHandover semantics ----
Status check_handover(const RootHandover &h) {
    return h.old_root != h.new_root && h.old_generation < h.new_generation ? Status::Ok : Status::InvalidArgument;
}

Status handover_from(const RootHandover &h, const DeviceId &root, uint64_t generation, RootTerm term) {
    LM_TRY(check_handover(h));
    if (h.old_root != root || h.old_generation != generation) {
        return Status::NetworkMismatch;
    }
    return term < h.new_term ? Status::Ok : Status::Conflict;
}

Status handover_to(const RootHandover &h, const DeviceId &root, uint64_t generation,
                   const Sha256Digest &delegation_hash) {
    LM_TRY(check_handover(h));
    return h.new_root == root && h.new_generation == generation && h.new_delegation_hash == delegation_hash
               ? Status::Ok
               : Status::NetworkMismatch;
}

// ---- encoders ----
Status encode_member_credential(const MemberCredential &m, MutByteView out, std::size_t &len) {
    if (!is_valid_short_addr(m.address) || m.role > 2 || m.assignment.value() > k_u63_max ||
        m.membership.value() > k_u63_max) {
        return Status::InvalidArgument;
    }
    CborWriter w{out};
    w.array(10);
    w.bytes(m.device.view());
    w.uint(m.address.value());
    w.uint(m.assignment.value());
    w.uint(m.membership.value());
    w.uint(m.role);
    w.boolean(m.relay_allowed);
    w.uint(m.root_term.value());
    w.uint(m.lease_expires_root_ms);
    w.bytes(ByteView{m.policy_hash});
    w.bytes(ByteView{m.credential_hash});
    len = w.size();
    return w.finish();
}

Status encode_revoke(const RevokeObject &r, MutByteView out, std::size_t &len) {
    if (r.assignment_floor > k_u63_max || r.membership_floor > k_u63_max || r.revision > k_u63_max) {
        return Status::InvalidArgument;
    }
    CborWriter w{out};
    w.array(5);
    w.bytes(r.device.view());
    w.uint(r.assignment_floor);
    w.uint(r.membership_floor);
    w.uint(r.reason);
    w.uint(r.revision);
    len = w.size();
    return w.finish();
}

// ---- signed objects ----
Status issue_signed(sec::KeyHandle key, const Envelope &env, ByteView data, MutByteView out,
                    std::size_t &len) {
    if (env.revision > k_u63_max) {
        return Status::InvalidArgument;
    }
    wire::ControlBody b;
    b.type = env.type;
    b.request_id = env.request.bytes;
    b.domain = env.domain.bytes;
    b.revision = env.revision;
    b.issuer = env.issuer.bytes;
    b.data = data;
    std::array<uint8_t, k_max_bundle> body{}; // credential-class objects only (<= 1024 B)
    std::size_t body_len = 0;
    LM_TRY(wire::encode_control_body(b, MutByteView{body}, body_len));
    return sec::sign1_create(key, env.issuer, ByteView{body.data(), body_len}, out, len);
}

namespace {

Status read_body(ByteView payload, uint8_t expect_type, Envelope &env, ByteView &data) {
    wire::ControlBody b;
    LM_TRY(wire::decode_control_body(payload, wire::ControlCarrier::Signed, b));
    if (b.type != expect_type) {
        return Status::AuthRejected;
    }
    env.type = b.type;
    env.request.bytes = b.request_id;
    env.domain.bytes = b.domain;
    env.revision = b.revision;
    env.issuer.bytes = b.issuer;
    data = b.data;
    return Status::Ok;
}

} // namespace

Status peek_signed(ByteView cose, uint8_t expect_type, Envelope &env, ByteView &data) {
    sec::Sign1View v;
    LM_TRY(sec::sign1_parse(cose, v));
    LM_TRY(read_body(v.payload, expect_type, env, data));
    return env.issuer == v.kid ? Status::Ok : Status::AuthRejected;
}

Status open_signed(ByteView cose, const sec::PublicKey &signer, uint8_t expect_type, Envelope &env,
                   ByteView &data) {
    sec::Sign1View v;
    LM_TRY(sec::sign1_verify(signer, cose, v));
    LM_TRY(read_body(v.payload, expect_type, env, data));
    return env.issuer == v.kid ? Status::Ok : Status::AuthRejected;
}

// ---- chain checks ----
Status check_device_credential(const TrustAnchor &trust, ByteView cose, DeviceCredential &out) {
    Envelope env;
    ByteView data;
    LM_TRY(open_signed(cose, trust.key, k_type_device_credential, env, data));
    DeviceCredential dc;
    LM_TRY(decode_device_credential(data, dc));
    if (dc.fleet != trust.fleet) {
        return Status::NetworkMismatch;
    }
    if (dc.generation < trust.min_credential_generation) {
        return Status::Revoked;
    }
    // The key must be a real curve point and hash to the DeviceId; the CCS EDHOC will use is
    // derived here, so no other encoding of the key can be presented later.
    LM_TRY(sec::validate_public_key(dc.key));
    DeviceId id;
    LM_TRY(sec::device_id_of(dc.key, id));
    if (id != dc.device) {
        return Status::AuthRejected;
    }
    const ByteView serial{dc.serial.data(), dc.serial_len};
    if (!printable(serial)) {
        return Status::BadFrame;
    }
    std::array<uint8_t, sec::k_ccs_max_bytes> ccs{};
    std::size_t ccs_len = 0;
    LM_TRY(sec::ccs_encode(serial, dc.key, MutByteView{ccs}, ccs_len));
    Sha256Digest h{};
    LM_TRY(sec::sha256(ByteView{ccs.data(), ccs_len}, h));
    if (h != dc.ccs_hash) {
        return Status::AuthRejected;
    }
    out = dc;
    return Status::Ok;
}

Status check_root_delegation(const TrustAnchor &trust, ByteView cose, RootDelegation &out) {
    Envelope env;
    ByteView data;
    LM_TRY(open_signed(cose, trust.key, k_type_root_delegation, env, data));
    RootDelegation d;
    LM_TRY(decode_root_delegation(data, d));
    if (d.fleet != trust.fleet || env.domain != d.domain) {
        return Status::NetworkMismatch;
    }
    LM_TRY(sec::validate_public_key(d.key));
    DeviceId id;
    LM_TRY(sec::device_id_of(d.key, id));
    if (id != d.root) {
        return Status::AuthRejected;
    }
    out = d;
    return Status::Ok;
}

Status check_member_credential(const RootDelegation &delegation, ByteView cose,
                               MemberCredential &out) {
    if ((delegation.permissions & k_perm_approve) == 0) {
        return Status::AuthRejected; // the delegation does not allow issuing memberships
    }
    Envelope env;
    ByteView data;
    LM_TRY(open_signed(cose, delegation.key, k_type_member_credential, env, data));
    if (env.domain != delegation.domain) {
        return Status::NetworkMismatch;
    }
    return decode_member_credential(data, out);
}

Status check_assignment_ticket(const TrustAnchor &trust, ByteView cose, const DeviceCredential &dc,
                               ByteView dc_cose, ByteView target_delegation_cose,
                               AssignmentTicket &out) {
    Envelope env;
    ByteView data;
    LM_TRY(open_signed(cose, trust.key, k_type_assignment_ticket, env, data));
    AssignmentTicket t;
    LM_TRY(decode_assignment_ticket(data, t));
    if (t.fleet != trust.fleet || env.domain != t.target) {
        return Status::NetworkMismatch;
    }
    Sha256Digest dc_hash{};
    Sha256Digest delegation_hash{};
    LM_TRY(sec::sha256(dc_cose, dc_hash));
    LM_TRY(sec::sha256(target_delegation_cose, delegation_hash));
    if (t.device != dc.device || t.device_credential_hash != dc_hash ||
        t.root_delegation_hash != delegation_hash || t.new_generation <= t.expected_old) {
        return Status::AuthRejected; // wrong device, stale credential/root, or no generation gain
    }
    out = t;
    return Status::Ok;
}

Status open_authority(const TrustAnchor &trust, const RootDelegation *delegation, uint8_t permission, ByteView cose,
                      uint8_t type, Envelope &env, ByteView &data) {
    sec::Sign1View v;
    LM_TRY(sec::sign1_parse(cose, v));
    const sec::PublicKey *signer = nullptr;
    if (v.kid == trust.key_id) {
        signer = &trust.key;
    } else if (delegation != nullptr && v.kid == delegation->root && (delegation->permissions & permission) != 0) {
        signer = &delegation->key;
    } else {
        return Status::AuthRejected;
    }
    LM_TRY(open_signed(cose, *signer, type, env, data));
    if (signer != &trust.key && env.domain != delegation->domain) {
        return Status::NetworkMismatch;
    }
    return Status::Ok;
}

Status check_expected_set(const TrustAnchor &trust, const RootDelegation *delegation, ByteView cose,
                          ExpectedSet &out) {
    Envelope env;
    ByteView data;
    LM_TRY(open_authority(trust, delegation, k_perm_approve, cose, k_type_expected_set, env, data));
    return decode_expected_set(data, out);
}

Status check_binding(const DeviceCredential &dc, ByteView dc_cose, const MemberCredential &mc) {
    if (mc.device != dc.device) {
        return Status::AuthRejected;
    }
    Sha256Digest h{};
    LM_TRY(sec::sha256(dc_cose, h));
    return h == mc.credential_hash ? Status::Ok : Status::AuthRejected;
}

// ---- withheld signature (SEC-D1) ----
Status withheld_hash(ByteView cose, Sha256Digest &out) {
    sec::Sign1View v;
    LM_TRY(sec::sign1_parse(cose, v));
    static constexpr std::array<uint8_t, k_signature_bytes> k_zero{};
    return sec::sha256_parts(cose.first(cose.size() - k_signature_bytes), ByteView{k_zero}, out);
}

bool signature_withheld(ByteView cose) {
    sec::Sign1View v;
    return sec::sign1_parse(cose, v) == Status::Ok &&
           std::all_of(v.signature.begin(), v.signature.end(), [](uint8_t b) { return b == 0; });
}

// ---- floors ----
Status Floors::raise(const DeviceId &device, uint64_t assignment, uint64_t membership) {
    for (std::size_t i = 0; i < count_; ++i) {
        if (entries_[i].device == device) {
            entries_[i].assignment = std::max(entries_[i].assignment, assignment);
            entries_[i].membership = std::max(entries_[i].membership, membership);
            return Status::Ok;
        }
    }
    if (count_ == k_max_floors) {
        return Status::NoCapacity;
    }
    entries_[count_++] = Entry{device, assignment, membership};
    return Status::Ok;
}

Status Floors::check(const DeviceId &device, AssignmentGen a, MembershipGen m) const {
    for (std::size_t i = 0; i < count_; ++i) {
        if (entries_[i].device == device) {
            const bool low = a.value() < entries_[i].assignment || m.value() < entries_[i].membership;
            return low ? Status::Revoked : Status::Ok;
        }
    }
    return Status::Ok;
}

Status verify_revoke(const TrustAnchor &trust, const RootDelegation *delegation, ByteView cose, RevokeObject &out) {
    Envelope env;
    ByteView data;
    LM_TRY(open_authority(trust, delegation, k_perm_revoke, cose, k_type_revoke, env, data));
    return decode_revoke(data, out);
}

Status apply_revoke(const TrustAnchor &trust, const RootDelegation *delegation, ByteView cose,
                    Floors &floors, RevokeObject &out) {
    RevokeObject rv;
    LM_TRY(verify_revoke(trust, delegation, cose, rv));
    LM_TRY(floors.raise(rv.device, rv.assignment_floor, rv.membership_floor));
    out = rv;
    return Status::Ok;
}

DeadlineCheck check_lease(const MemberCredential &mc, const RootTimeBound &now) {
    return check_deadline(now, lease_of(mc));
}

MonoTime lease_local_end(const RootTimeBound &bound, const RootTime &lease, MonoTime now) {
    if (lease.ms <= bound.latest_ms) {
        return now; // not provably before: no time left
    }
    const uint64_t left_ms = lease.ms - bound.latest_ms;
    const uint64_t cap_ms = static_cast<uint64_t>(INT64_MAX / 1000 / 2);
    const uint64_t ms = left_ms < cap_ms ? left_ms : cap_ms;
    const uint64_t margin_ms = ms / 1000 + 1; // 1000 ppm + 1 ms
    return ms > margin_ms ? now + Duration::from_ms(static_cast<int64_t>(ms - margin_ms)) : now;
}

// ---- credential pair ----
Status cred_pair_encode(ByteView device_cose, ByteView x, std::size_t x_max, MutByteView out, std::size_t &len) {
    if (device_cose.empty() || device_cose.size() > k_max_device_cose || x.empty() || x.size() > x_max) {
        return Status::InvalidArgument;
    }
    CborWriter w{out};
    w.array(2);
    w.bytes(device_cose);
    w.bytes(x);
    len = w.size();
    return w.finish();
}

Status cred_pair_parse(ByteView in, std::size_t x_max, ByteView &device_cose, ByteView &x) {
    LM_TRY(wire::cbor_validate(in));
    CborReader r{in};
    (void)r.array(2, 2);
    const ByteView dc = r.bstr(1, k_max_device_cose);
    const ByteView second = r.bstr(1, x_max);
    LM_TRY(r.finish());
    device_cose = dc;
    x = second;
    return Status::Ok;
}

} // namespace lm::member
