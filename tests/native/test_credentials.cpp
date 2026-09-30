// Credential objects (DeviceCredential, RootDelegation, AssignmentTicket, MemberCredential,
// ExpectedSet, RevokeObject): codec vectors, signature chain, and the negative cases of S07
// (invalid curve point, hash/ID/key mismatches, wrong signer/type/domain, low generation).
// Objects come from the TEST-ONLY fleet issuer.
#include <cstring>

#include "core/member/credentials.hpp"
#include "core/member/records.hpp"
#include "core/wire/cbor.hpp"
#include "fleet.hpp"
#include "lmtest.hpp"
#include "stack_probe.hpp"
#include "security/cose_sign1.hpp"
#include "security/crypto.hpp"

using namespace lm;
using namespace lm::member;
using fleet::Bytes;

namespace {

ByteView view(const Bytes &b) { return ByteView{b.data(), b.size()}; }

struct Env {
    Env() : net(21), node(net.make_node(1, 2)), root_node(net.make_root()) { LM_CHECK_OK(sec::crypto_init()); }
    fleet::Network net;
    fleet::NodeKit node;
    fleet::NodeKit root_node;
    const TrustAnchor &trust() const { return net.fleet.trust(); }
    RootDelegation delegation() const {
        RootDelegation d;
        LM_CHECK_OK(check_root_delegation(trust(), view(net.delegation_cose), d));
        return d;
    }
};

Bytes flip_last(Bytes b) {
    b.back() ^= 0x01;
    return b;
}

Bytes encode_dc_data(const DeviceCredential &dc) {
    Bytes buf(320);
    wire::CborWriter w{MutByteView{buf.data(), buf.size()}};
    std::array<uint8_t, sec::k_cose_key_bytes> ck{};
    LM_CHECK_OK(sec::cose_key_encode(dc.key, MutByteView{ck}));
    w.array(6);
    w.bytes(dc.device.view());
    w.raw(ByteView{ck});
    w.bytes(dc.fleet.view());
    w.text(ByteView{dc.serial.data(), dc.serial_len});
    w.uint(dc.generation);
    w.bytes(ByteView{dc.ccs_hash});
    buf.resize(w.size());
    return buf;
}

Envelope env_of(const Env &e, uint8_t type, const DomainId &domain, uint64_t rev = 1) {
    Envelope env;
    env.type = type;
    env.domain = domain;
    env.issuer = e.trust().key_id;
    env.revision = rev;
    env.request.bytes.fill(0x44);
    return env;
}

} // namespace

LM_TEST("S07 vectors: MemberCredential and RevokeObject control-data are the CDDL bytes") {
    MemberCredential m;
    m.device.bytes.fill(0x11);
    m.address = ShortAddr{2};
    m.assignment = AssignmentGen{1};
    m.membership = MembershipGen{1};
    m.role = 1;
    m.relay_allowed = true;
    m.root_term = RootTerm{1};
    m.lease_expires_root_ms = 1000;
    m.policy_hash.fill(0x22);
    m.credential_hash.fill(0x33);
    std::array<uint8_t, 200> out{};
    std::size_t len = 0;
    LM_CHECK_OK(encode_member_credential(m, MutByteView{out}, len));
    // 8A | bstr32 | 02 | 01 | 01 | 01 | F5 | 01 | 19 03E8 | bstr32 | bstr32
    Bytes expect = {0x8A, 0x58, 0x20};
    expect.insert(expect.end(), 32, 0x11);
    for (uint8_t b : {0x02, 0x01, 0x01, 0x01, 0xF5, 0x01, 0x19, 0x03, 0xE8, 0x58, 0x20}) {
        expect.push_back(b);
    }
    expect.insert(expect.end(), 32, 0x22);
    expect.push_back(0x58);
    expect.push_back(0x20);
    expect.insert(expect.end(), 32, 0x33);
    LM_CHECK(Bytes(out.begin(), out.begin() + len) == expect);
    MemberCredential back;
    LM_CHECK_OK(decode_member_credential(ByteView{out.data(), len}, back));
    LM_CHECK(back.device == m.device && back.address == m.address && back.role == 1 &&
             back.relay_allowed && back.lease_expires_root_ms == 1000 &&
             back.credential_hash == m.credential_hash);
    // trailing byte, truncation and out-of-range fields are refused by the strict decoder
    Bytes extra = expect;
    extra.push_back(0);
    LM_CHECK(decode_member_credential(view(extra), back) == Status::BadFrame);
    Bytes cut(expect.begin(), expect.end() - 1);
    LM_CHECK(decode_member_credential(view(cut), back) == Status::BadFrame);
    Bytes bad_role = expect;
    bad_role[3 + 32 + 4] = 0x03; // role 3
    LM_CHECK(decode_member_credential(view(bad_role), back) == Status::BadFrame);
    m.address = ShortAddr{0};
    LM_CHECK(encode_member_credential(m, MutByteView{out}, len) == Status::InvalidArgument);

    RevokeObject r;
    r.device.bytes.fill(0x11);
    r.assignment_floor = 5;
    r.membership_floor = 7;
    r.reason = 2;
    r.revision = 9;
    LM_CHECK_OK(encode_revoke(r, MutByteView{out}, len));
    Bytes rexp = {0x85, 0x58, 0x20};
    rexp.insert(rexp.end(), 32, 0x11);
    for (uint8_t b : {0x05, 0x07, 0x02, 0x09}) {
        rexp.push_back(b);
    }
    LM_CHECK(Bytes(out.begin(), out.begin() + len) == rexp);
    RevokeObject rb;
    LM_CHECK_OK(decode_revoke(ByteView{out.data(), len}, rb));
    LM_CHECK(rb.assignment_floor == 5 && rb.membership_floor == 7 && rb.reason == 2 && rb.revision == 9);
}

LM_TEST("S07 chain: DeviceCredential, RootDelegation and MemberCredential verify and bind") {
    Env e;
    DeviceCredential dc;
    LM_CHECK_OK(check_device_credential(e.trust(), view(e.node.kit.device_cose), dc));
    LM_CHECK(dc.device == e.node.kit.id && dc.fleet == e.trust().fleet && dc.generation == 1);
    LM_CHECK_EQ(dc.serial_len, e.node.kit.serial.size());
    const RootDelegation d = e.delegation();
    LM_CHECK(d.root == e.net.root.id && d.domain == e.net.domain && d.permissions == 3);
    MemberCredential mc;
    LM_CHECK_OK(check_member_credential(d, view(e.node.member_cose), mc));
    LM_CHECK_OK(check_binding(dc, view(e.node.kit.device_cose), mc));
    LM_CHECK(mc.address == ShortAddr{2} && mc.assignment == AssignmentGen{1});
    // The CCS the handshake will use is derived from the verified key only.
    std::array<uint8_t, sec::k_ccs_max_bytes> ccs{};
    std::size_t len = 0;
    LM_CHECK_OK(sec::ccs_encode(ByteView{dc.serial.data(), dc.serial_len}, dc.key, MutByteView{ccs}, len));
    Sha256Digest h{};
    LM_CHECK_OK(sec::sha256(ByteView{ccs.data(), len}, h));
    LM_CHECK(h == dc.ccs_hash);
    // AssignmentTicket and ExpectedSet decode from the same envelope machinery.
    DomainId zero;
    const Bytes ticket = e.net.fleet.ticket(e.node.kit, zero, e.net.domain, e.net.delegation_cose, 0, 1);
    Envelope env;
    ByteView data;
    LM_CHECK_OK(open_signed(view(ticket), e.trust().key, k_type_assignment_ticket, env, data));
    AssignmentTicket t;
    LM_CHECK_OK(decode_assignment_ticket(data, t));
    LM_CHECK(t.device == e.node.kit.id && t.target == e.net.domain && t.source == zero &&
             t.new_generation == 1 && t.expected_old == 0 && t.mode == 1);
    Sha256Digest dh{};
    LM_CHECK_OK(sec::sha256(view(e.node.kit.device_cose), dh));
    LM_CHECK(t.device_credential_hash == dh);

    Bytes eb(300);
    wire::CborWriter w{MutByteView{eb.data(), eb.size()}};
    w.array(4);
    w.uint(0);
    w.uint(1);
    w.bytes(ByteView{h});
    w.array(2);
    for (int i = 0; i < 2; ++i) {
        w.array(4);
        w.bytes(e.node.kit.id.view());
        w.uint(1);
        w.bytes(ByteView{h});
        w.boolean(i == 0);
    }
    Envelope eenv = env_of(e, k_type_expected_set, e.net.domain);
    const Bytes es = e.net.fleet.sign(eenv, w.written());
    LM_CHECK_OK(open_signed(view(es), e.trust().key, k_type_expected_set, env, data));
    ExpectedSet set;
    LM_CHECK_OK(decode_expected_set(data, set));
    LM_CHECK(set.count == 2 && set.entries[0].allowed && !set.entries[1].allowed && set.pages == 1);
}

LM_TEST("S07 ticket and expected set: signer, bindings and generation gain are checked") {
    Env e;
    DeviceCredential dc;
    LM_CHECK_OK(check_device_credential(e.trust(), view(e.node.kit.device_cose), dc));
    const RootDelegation d = e.delegation();
    DomainId none;
    AssignmentTicket t;
    const Bytes good = e.net.fleet.ticket(e.node.kit, none, e.net.domain, e.net.delegation_cose, 0, 1);
    LM_CHECK_OK(check_assignment_ticket(e.trust(), view(good), dc, view(e.node.kit.device_cose),
                                        view(e.net.delegation_cose), t));
    LM_CHECK(t.new_generation == 1 && t.target == e.net.domain);
    // signature, other device, stale device credential, other target root, no generation gain
    LM_CHECK(check_assignment_ticket(e.trust(), view(flip_last(good)), dc, view(e.node.kit.device_cose),
                                     view(e.net.delegation_cose), t) == Status::AuthRejected);
    const fleet::NodeKit other = e.net.make_node(2, 3);
    DeviceCredential dc2;
    LM_CHECK_OK(check_device_credential(e.trust(), view(other.kit.device_cose), dc2));
    LM_CHECK(check_assignment_ticket(e.trust(), view(good), dc2, view(other.kit.device_cose),
                                     view(e.net.delegation_cose), t) == Status::AuthRejected);
    const fleet::Kit gen2 = e.net.fleet.device(1, e.node.kit.serial, 2);
    LM_CHECK(check_assignment_ticket(e.trust(), view(good), dc, view(gen2.device_cose),
                                     view(e.net.delegation_cose), t) == Status::AuthRejected);
    LM_CHECK(check_assignment_ticket(e.trust(), view(good), dc, view(e.node.kit.device_cose),
                                     view(e.node.member_cose), t) == Status::AuthRejected);
    const Bytes no_gain = e.net.fleet.ticket(e.node.kit, none, e.net.domain, e.net.delegation_cose, 3, 3);
    LM_CHECK(check_assignment_ticket(e.trust(), view(no_gain), dc, view(e.node.kit.device_cose),
                                     view(e.net.delegation_cose), t) == Status::AuthRejected);
    fleet::Network rogue(77, "rogue");
    const Bytes forged = rogue.fleet.ticket(e.node.kit, none, e.net.domain, e.net.delegation_cose, 0, 1);
    LM_CHECK(check_assignment_ticket(e.trust(), view(forged), dc, view(e.node.kit.device_cose),
                                     view(e.net.delegation_cose), t) == Status::AuthRejected);

    // Expected set: fleet-signed or root-signed (approve, own domain); nothing else.
    Bytes body(200);
    wire::CborWriter w{MutByteView{body.data(), body.size()}};
    w.array(4);
    w.uint(0);
    w.uint(1);
    w.bytes(ByteView{dc.ccs_hash});
    w.array(0);
    body.resize(w.size());
    ExpectedSet es;
    const Bytes by_fleet = e.net.fleet.sign(env_of(e, k_type_expected_set, e.net.domain), view(body));
    LM_CHECK_OK(check_expected_set(e.trust(), &d, view(by_fleet), es));
    LM_CHECK_EQ(es.count, 0u);
    // signed by the root key: its DeviceId is the kid, which the fleet key does not have
    Envelope root_env = env_of(e, k_type_expected_set, e.net.domain);
    root_env.issuer = e.net.root.id;
    sec::KeyHandle rk;
    LM_CHECK_OK(sec::import_signing_key(ByteView{e.net.root.scalar}, rk));
    Bytes by_root(1024);
    std::size_t len = 0;
    LM_CHECK_OK(issue_signed(rk, root_env, view(body), MutByteView{by_root.data(), by_root.size()}, len));
    sec::destroy_key(rk);
    by_root.resize(len);
    LM_CHECK_OK(check_expected_set(e.trust(), &d, view(by_root), es));
    RootDelegation weak = d;
    weak.permissions = k_perm_revoke;
    LM_CHECK(check_expected_set(e.trust(), &weak, view(by_root), es) == Status::AuthRejected);
    LM_CHECK(check_expected_set(e.trust(), nullptr, view(by_root), es) == Status::AuthRejected);
    LM_CHECK(check_expected_set(e.trust(), &d, view(flip_last(by_root)), es) == Status::AuthRejected);
}

LM_TEST("S07 DeviceCredential negatives: signature, signer, key point, ids, hashes, generation, shape") {
    Env e;
    DeviceCredential dc;
    // signature and payload bit flips
    LM_CHECK(check_device_credential(e.trust(), view(flip_last(e.node.kit.device_cose)), dc) == Status::AuthRejected);
    Bytes payload_flip = e.node.kit.device_cose;
    payload_flip[payload_flip.size() / 2] ^= 0x08;
    LM_CHECK(check_device_credential(e.trust(), view(payload_flip), dc) != Status::Ok);
    // wrong issuer (another fleet), and the same fleet under a wrong anchor generation floor
    fleet::Network rogue(77, "rogue");
    const fleet::NodeKit fake = rogue.make_node(1, 2);
    LM_CHECK(check_device_credential(e.trust(), view(fake.kit.device_cose), dc) == Status::AuthRejected);
    TrustAnchor high = e.trust();
    high.min_credential_generation = 2;
    LM_CHECK(check_device_credential(high, view(e.node.kit.device_cose), dc) == Status::Revoked);
    // truncation and trailing bytes
    Bytes cut(e.node.kit.device_cose.begin(), e.node.kit.device_cose.end() - 1);
    LM_CHECK(check_device_credential(e.trust(), view(cut), dc) == Status::BadFrame);
    Bytes extra = e.node.kit.device_cose;
    extra.push_back(0);
    LM_CHECK(check_device_credential(e.trust(), view(extra), dc) == Status::BadFrame);

    // Properly signed by the fleet but semantically broken: each must still be refused.
    const DeviceCredential good = e.node.kit.dc;
    const Envelope env = env_of(e, k_type_device_credential, DomainId{});
    auto signed_dc = [&](const DeviceCredential &x) { return e.net.fleet.sign(env, view(encode_dc_data(x))); };
    DeviceCredential bad = good;
    bad.key.y[0] ^= 0x01; // not on the curve (PSA refuses the point)
    LM_CHECK(check_device_credential(e.trust(), view(signed_dc(bad)), dc) == Status::InvalidArgument);
    bad = good;
    bad.device.bytes[0] ^= 1; // DeviceId is not SHA-256(COSE_Key)
    LM_CHECK(check_device_credential(e.trust(), view(signed_dc(bad)), dc) == Status::AuthRejected);
    bad = good;
    bad.ccs_hash[5] ^= 1;
    LM_CHECK(check_device_credential(e.trust(), view(signed_dc(bad)), dc) == Status::AuthRejected);
    bad = good;
    bad.fleet.bytes[0] ^= 1;
    LM_CHECK(check_device_credential(e.trust(), view(signed_dc(bad)), dc) == Status::NetworkMismatch);
    bad = good;
    bad.serial[0] = 0x01; // control character: the CCS subject must be printable
    LM_CHECK(check_device_credential(e.trust(), view(signed_dc(bad)), dc) == Status::BadFrame);
    bad = good;
    bad.serial_len = 49; // over the 48-byte bound of control.cddl
    LM_CHECK(check_device_credential(e.trust(), view(signed_dc(bad)), dc) == Status::BadFrame);
    // A different object type under the same signature is not a DeviceCredential.
    LM_CHECK(check_device_credential(e.trust(), view(e.net.delegation_cose), dc) == Status::AuthRejected);
    // Envelope issuer that differs from the COSE kid.
    Envelope liar = env;
    liar.issuer.bytes[0] ^= 1;
    LM_CHECK(check_device_credential(e.trust(), view(e.net.fleet.sign_body_issuer_mismatch(liar, view(encode_dc_data(good)))), dc) ==
             Status::AuthRejected);
}

LM_TEST("S07 delegation and member negatives: signer, permission, domain, binding") {
    Env e;
    RootDelegation d;
    LM_CHECK(check_root_delegation(e.trust(), view(flip_last(e.net.delegation_cose)), d) == Status::AuthRejected);
    fleet::Network rogue(77, "rogue");
    LM_CHECK(check_root_delegation(e.trust(), view(rogue.delegation_cose), d) == Status::AuthRejected);
    LM_CHECK(check_root_delegation(e.trust(), view(e.node.kit.device_cose), d) == Status::AuthRejected);
    d = e.delegation();

    MemberCredential mc;
    LM_CHECK(check_member_credential(d, view(flip_last(e.node.member_cose)), mc) == Status::AuthRejected);
    // signed by the device itself instead of the delegated root
    const Bytes self_signed = fleet::issue_member(e.node.kit, e.net.domain, e.node.kit, fleet::MemberSpec{});
    LM_CHECK(check_member_credential(d, view(self_signed), mc) == Status::AuthRejected);
    // right root, other domain
    DomainId other = e.net.domain;
    other.bytes[15] ^= 1;
    const Bytes wrong_domain = fleet::issue_member(e.net.root, other, e.node.kit, fleet::MemberSpec{});
    LM_CHECK(check_member_credential(d, view(wrong_domain), mc) == Status::NetworkMismatch);
    // delegation without the approve permission cannot vouch for members
    RootDelegation no_approve = d;
    no_approve.permissions = k_perm_revoke;
    LM_CHECK(check_member_credential(no_approve, view(e.node.member_cose), mc) == Status::AuthRejected);
    // binding: another device's credential, and a credential hash of a different DeviceCredential
    DeviceCredential dc;
    LM_CHECK_OK(check_device_credential(e.trust(), view(e.node.kit.device_cose), dc));
    LM_CHECK_OK(check_member_credential(d, view(e.node.member_cose), mc));
    const fleet::NodeKit other_node = e.net.make_node(2, 3);
    DeviceCredential dc2;
    LM_CHECK_OK(check_device_credential(e.trust(), view(other_node.kit.device_cose), dc2));
    LM_CHECK(check_binding(dc2, view(other_node.kit.device_cose), mc) == Status::AuthRejected); // device differs
    LM_CHECK(check_binding(dc, view(other_node.kit.device_cose), mc) == Status::AuthRejected);  // hash differs
    // A newer DeviceCredential (generation 2, same key) does not match a member credential of gen 1.
    const fleet::Kit reissued = e.net.fleet.device(1, e.node.kit.serial, 2);
    LM_CHECK(reissued.id == e.node.kit.id);
    LM_CHECK(check_binding(dc, view(reissued.device_cose), mc) == Status::AuthRejected);
}

LM_TEST("S07 revocation: fleet or delegated root raise floors, never lower them, table is bounded") {
    Env e;
    const RootDelegation d = e.delegation();
    Floors floors;
    RevokeObject rv;
    LM_CHECK_OK(floors.check(e.node.kit.id, AssignmentGen{1}, MembershipGen{1}));
    const Bytes by_fleet = e.net.fleet.revoke(e.node.kit.id, 1, 2, 5);
    LM_CHECK_OK(apply_revoke(e.trust(), &d, view(by_fleet), floors, rv));
    LM_CHECK(rv.membership_floor == 2 && rv.revision == 5);
    LM_CHECK(floors.check(e.node.kit.id, AssignmentGen{1}, MembershipGen{1}) == Status::Revoked);
    LM_CHECK_OK(floors.check(e.node.kit.id, AssignmentGen{1}, MembershipGen{2}));
    LM_CHECK(floors.check(e.node.kit.id, AssignmentGen{0}, MembershipGen{9}) == Status::Revoked);
    // a lower floor later never lowers the stored one
    LM_CHECK_OK(apply_revoke(e.trust(), &d, view(e.net.fleet.revoke(e.node.kit.id, 0, 1, 6)), floors, rv));
    LM_CHECK(floors.check(e.node.kit.id, AssignmentGen{1}, MembershipGen{1}) == Status::Revoked);
    // delegated root: allowed for its domain with the revoke permission
    const fleet::NodeKit victim = e.net.make_node(3, 4);
    const Bytes by_root = fleet::issue_root_revoke(e.net.root, e.net.domain, victim.kit.id, 1, 2);
    LM_CHECK_OK(apply_revoke(e.trust(), &d, view(by_root), floors, rv));
    LM_CHECK(floors.check(victim.kit.id, AssignmentGen{1}, MembershipGen{1}) == Status::Revoked);
    RootDelegation weak = d;
    weak.permissions = k_perm_approve;
    Floors f2;
    LM_CHECK(apply_revoke(e.trust(), &weak, view(by_root), f2, rv) == Status::AuthRejected);
    LM_CHECK(apply_revoke(e.trust(), nullptr, view(by_root), f2, rv) == Status::AuthRejected);
    DomainId other = e.net.domain;
    other.bytes[0] ^= 1;
    const Bytes wrong = fleet::issue_root_revoke(e.net.root, other, victim.kit.id, 1, 2);
    LM_CHECK(apply_revoke(e.trust(), &d, view(wrong), f2, rv) == Status::NetworkMismatch);
    LM_CHECK(apply_revoke(e.trust(), &d, view(flip_last(by_fleet)), f2, rv) == Status::AuthRejected);
    LM_CHECK_EQ(f2.count(), 0u);
    // bounded table: the 11th device is refused, nothing is forgotten
    Floors full;
    for (uint32_t i = 0; i < k_max_floors; ++i) {
        DeviceId id;
        id.bytes[0] = static_cast<uint8_t>(i + 1);
        LM_CHECK_OK(full.raise(id, 1, 1));
    }
    DeviceId extra;
    extra.bytes[0] = 0xEE;
    LM_CHECK(full.raise(extra, 1, 1) == Status::NoCapacity);
    LM_CHECK_EQ(full.count(), k_max_floors);
}

LM_TEST("S5 lease: provably valid, provably expired, or uncertain (term mismatch, no bound)") {
    MemberCredential mc;
    mc.root_term = RootTerm{3};
    mc.lease_expires_root_ms = 1000;
    RootTimeBound b;
    LM_CHECK(check_lease(mc, b) == DeadlineCheck::Uncertain); // invalid bound
    b.valid = true;
    b.term = RootTerm{3};
    b.earliest_ms = 100;
    b.latest_ms = 200;
    LM_CHECK(check_lease(mc, b) == DeadlineCheck::Before);
    b.earliest_ms = 1500;
    b.latest_ms = 1600;
    LM_CHECK(check_lease(mc, b) == DeadlineCheck::After);
    b.earliest_ms = 900;
    b.latest_ms = 1100;
    LM_CHECK(check_lease(mc, b) == DeadlineCheck::Uncertain); // interval straddles
    b.term = RootTerm{4};
    b.earliest_ms = b.latest_ms = 100;
    LM_CHECK(check_lease(mc, b) == DeadlineCheck::Uncertain); // another root term: never assumed
}

LM_TEST("S5 bundle and record payload codecs are strict") {
    Env e;
    Bytes out(member::k_max_bundle);
    std::size_t len = 0;
    LM_CHECK_OK(cred_pair_encode(view(e.node.kit.device_cose), view(e.node.member_cose), k_max_member_cose,
                                 MutByteView{out.data(), out.size()}, len));
    // ARCH2-P2B: one codec for the link bundle and the join CredR; the bytes are those of CBOR [bstr, bstr].
    Bytes manual(member::k_max_bundle);
    wire::CborWriter mw{MutByteView{manual.data(), manual.size()}};
    mw.array(2);
    mw.bytes(view(e.node.kit.device_cose));
    mw.bytes(view(e.node.member_cose));
    LM_CHECK_OK(mw.finish());
    LM_CHECK(bytes_equal(ByteView{out.data(), len}, mw.written()));
    ByteView pdc;
    ByteView pmc;
    LM_CHECK_OK(cred_pair_parse(ByteView{out.data(), len}, k_max_member_cose, pdc, pmc));
    LM_CHECK(bytes_equal(pdc, view(e.node.kit.device_cose)));
    LM_CHECK(bytes_equal(pmc, view(e.node.member_cose)));
    Bytes extra(out.begin(), out.begin() + len);
    extra.push_back(0);
    LM_CHECK(cred_pair_parse(view(extra), k_max_member_cose, pdc, pmc) == Status::BadFrame);
    LM_CHECK(cred_pair_parse(ByteView{out.data(), len - 1}, k_max_member_cose, pdc, pmc) == Status::BadFrame);
    LM_CHECK(cred_pair_encode(ByteView{}, view(e.node.member_cose), k_max_member_cose,
                              MutByteView{out.data(), out.size()}, len) == Status::InvalidArgument);
    // The second element is bounded by its kind: 400 B is a RootDelegation's room, not a MemberCredential's.
    const Bytes big(400, 0x5A);
    LM_CHECK(cred_pair_encode(view(e.node.kit.device_cose), view(big), k_max_member_cose,
                              MutByteView{out.data(), out.size()}, len) == Status::InvalidArgument);
    LM_CHECK_OK(cred_pair_encode(view(e.node.kit.device_cose), view(big), k_max_delegation_cose,
                                 MutByteView{out.data(), out.size()}, len));
    LM_CHECK(cred_pair_parse(ByteView{out.data(), len}, k_max_member_cose, pdc, pmc) == Status::BadFrame);
    LM_CHECK_OK(cred_pair_parse(ByteView{out.data(), len}, k_max_delegation_cose, pdc, pmc));
    LM_CHECK(bytes_equal(pmc, view(big)));

    // sealed record payloads
    std::array<uint8_t, 600> buf{};
    TrustAnchor t;
    LM_CHECK_OK(encode_trust(e.trust(), MutByteView{buf}, len));
    LM_CHECK_EQ(len, k_trust_bytes);
    LM_CHECK_OK(decode_trust(ByteView{buf.data(), len}, t));
    LM_CHECK(t.fleet == e.trust().fleet && t.key_id == e.trust().key_id);
    LM_CHECK(decode_trust(ByteView{buf.data(), len - 1}, t) == Status::BadFrame);
    buf[20] ^= 1; // the stored fleet key is no longer a curve point
    LM_CHECK(decode_trust(ByteView{buf.data(), k_trust_bytes}, t) == Status::InvalidArgument);

    Floors f;
    LM_CHECK_OK(f.raise(e.node.kit.id, 3, 4));
    LM_CHECK_OK(encode_floors(f, MutByteView{buf}, len));
    Floors g;
    LM_CHECK_OK(decode_floors(ByteView{buf.data(), len}, g));
    LM_CHECK(g.check(e.node.kit.id, AssignmentGen{3}, MembershipGen{3}) == Status::Revoked);
    LM_CHECK(decode_floors(ByteView{buf.data(), len + 1}, g) == Status::BadFrame);
    buf[0] = 11; // more entries than the table holds
    LM_CHECK(decode_floors(ByteView{buf.data(), len}, g) == Status::BadFrame);

    LM_CHECK_OK(encode_identity(ByteView{e.node.kit.scalar}, view(e.node.kit.device_cose), MutByteView{buf}, len));
    ByteView sc, dc;
    LM_CHECK_OK(decode_identity(ByteView{buf.data(), len}, sc, dc));
    LM_CHECK(bytes_equal(dc, view(e.node.kit.device_cose)));
    LM_CHECK(decode_identity(ByteView{buf.data(), 32}, sc, dc) == Status::BadFrame);
}

LM_TEST("measure: worker stack peak of the credential-chain job (2 ECDSA verifies + hashing)") {
    Env e;
    Status result = Status::RecoveryRequired;
    // The same calls as link::Exchange::verify_body, on a painted stack: PSA ECDSA verify dominates.
    const RootDelegation d = e.delegation();
    const std::size_t depth = lmtest::depth_of([&] {
        DeviceCredential dc;
        MemberCredential mc;
        result = check_device_credential(e.trust(), view(e.node.kit.device_cose), dc);
        if (result == Status::Ok) {
            result = check_member_credential(d, view(e.node.member_cose), mc);
        }
        if (result == Status::Ok) {
            result = check_binding(dc, view(e.node.kit.device_cose), mc);
        }
    });
    LM_CHECK(result == Status::Ok);
    std::printf("  [measure] credential-chain job stack depth: %zu B (thread entry depth %zu B)\n", depth,
                lmtest::entry_depth());
#if LM_STACK_PROBE_EXACT
    LM_CHECK(depth < 5500); // same class as one EDHOC step: the worker stack need does not grow
#endif
}

LM_TEST_MAIN()
