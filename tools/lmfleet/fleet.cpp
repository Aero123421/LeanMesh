#include "fleet.hpp"

#include <algorithm>

#include "core/wire/cbor.hpp"
#include "port/sim/sim_provision.hpp"
#include "security/crypto.hpp"

namespace lm::fleet {
namespace {

using wire::CborWriter;


Sha256Digest hash_of(ByteView v) {
    Sha256Digest d{};
    (void)sec::sha256(v, d);
    return d;
}

void put_key(CborWriter &w, const sec::PublicKey &k) {
    std::array<uint8_t, sec::k_cose_key_bytes> raw{};
    (void)sec::cose_key_encode(k, MutByteView{raw});
    w.raw(ByteView{raw});
}

Sha256Digest seeded(const std::string &label, uint64_t seed, uint32_t index, uint8_t ctr) {
    Bytes in(label.begin(), label.end());
    for (int i = 7; i >= 0; --i) {
        in.push_back(static_cast<uint8_t>(seed >> (8 * i)));
    }
    for (int i = 3; i >= 0; --i) {
        in.push_back(static_cast<uint8_t>(index >> (8 * i)));
    }
    in.push_back(ctr);
    return hash_of(ByteView{in.data(), in.size()});
}

} // namespace

void Fleet::derive_key(uint64_t seed, const std::string &label, uint32_t index,
                       std::array<uint8_t, 32> &scalar, sec::PublicKey &pub) {
    (void)sec::crypto_init();
    for (uint8_t ctr = 0; ctr < 255; ++ctr) {
        scalar = seeded("lmfleet-key/" + label, seed, index, ctr);
        sec::KeyHandle h;
        if (sec::import_signing_key(ByteView{scalar}, h) == Status::Ok) {
            (void)sec::public_key_of(h, pub);
            sec::destroy_key(h);
            return;
        }
    }
}

Fleet::Fleet(uint64_t seed, const std::string &label) : seed_(seed), label_(label) {
    sec::PublicKey pub;
    derive_key(seed, label, 0xFFFFFFFFU, scalar_, pub);
    FleetId id;
    const Sha256Digest d = seeded("lmfleet-id/" + label, seed, 0, 0);
    std::copy(d.begin(), d.begin() + 16, id.bytes.begin());
    (void)member::make_trust_anchor(id, pub, 0, trust_);
}

Fleet::~Fleet() { sec::secure_zero(MutByteView{scalar_}); }

member::Envelope Fleet::envelope(uint8_t type, const DomainId &domain, const DeviceId &issuer,
                                 uint64_t revision) {
    member::Envelope e;
    e.type = type;
    e.domain = domain;
    e.issuer = issuer;
    e.revision = revision;
    const Sha256Digest d = seeded("lmfleet-req/" + label_, seed_, request_counter_++, 0);
    std::copy(d.begin(), d.begin() + 16, e.request.bytes.begin());
    return e;
}

Bytes Fleet::sign_with(const std::array<uint8_t, 32> &scalar, const DeviceId &kid,
                       const member::Envelope &env, ByteView data) {
    (void)kid;
    sec::KeyHandle h;
    if (sec::import_signing_key(ByteView{scalar}, h) != Status::Ok) {
        return {};
    }
    Bytes out(member::k_max_bundle);
    std::size_t len = 0;
    const Status st = member::issue_signed(h, env, data, MutByteView{out.data(), out.size()}, len);
    sec::destroy_key(h);
    out.resize(st == Status::Ok ? len : 0);
    return out;
}

Bytes Fleet::sign(const member::Envelope &env, ByteView data) {
    return sign_with(scalar_, trust_.key_id, env, data);
}

Kit Fleet::device(uint32_t index, const std::string &serial, uint64_t generation) {
    Kit k;
    derive_key(seed_, label_ + "/dev", index, k.scalar, k.pub);
    (void)sec::device_id_of(k.pub, k.id);
    k.serial = serial;
    k.dc.device = k.id;
    k.dc.key = k.pub;
    k.dc.fleet = trust_.fleet;
    std::copy(serial.begin(), serial.end(), k.dc.serial.begin());
    k.dc.serial_len = static_cast<uint8_t>(serial.size());
    k.dc.generation = generation;
    std::array<uint8_t, sec::k_ccs_max_bytes> ccs{};
    std::size_t ccs_len = 0;
    (void)sec::ccs_encode(ByteView{k.dc.serial.data(), k.dc.serial_len}, k.pub, MutByteView{ccs}, ccs_len);
    k.dc.ccs_hash = hash_of(ByteView{ccs.data(), ccs_len});

    std::array<uint8_t, 320> buf{};
    CborWriter w{MutByteView{buf}};
    w.array(6);
    w.bytes(k.id.view());
    put_key(w, k.pub);
    w.bytes(trust_.fleet.view());
    w.text(ByteView{k.dc.serial.data(), k.dc.serial_len});
    w.uint(generation);
    w.bytes(ByteView{k.dc.ccs_hash});
    k.device_cose = sign(envelope(member::k_type_device_credential, DomainId{}, trust_.key_id, generation),
                         w.written());
    return k;
}

Bytes Fleet::delegation(const Kit &root, const DomainId &domain, uint64_t generation, uint8_t perms) {
    std::array<uint8_t, 256> buf{};
    CborWriter w{MutByteView{buf}};
    w.array(6);
    w.bytes(trust_.fleet.view());
    w.bytes(root.id.view());
    put_key(w, root.pub);
    w.bytes(domain.view());
    w.uint(generation);
    w.uint(perms);
    return sign(envelope(member::k_type_root_delegation, domain, trust_.key_id, generation), w.written());
}

Bytes Fleet::revoke(const DeviceId &device, uint64_t af, uint64_t mf, uint64_t revision) {
    std::array<uint8_t, 96> buf{};
    member::RevokeObject r;
    r.device = device;
    r.assignment_floor = af;
    r.membership_floor = mf;
    r.revision = revision;
    std::size_t len = 0;
    (void)member::encode_revoke(r, MutByteView{buf}, len);
    return sign(envelope(member::k_type_revoke, DomainId{}, trust_.key_id, revision),
                ByteView{buf.data(), len});
}

Bytes Fleet::ticket(const Kit &dev, const DomainId &source, const DomainId &target,
                    const Bytes &delegation_cose, uint64_t expected_old, uint64_t new_generation) {
    std::array<uint8_t, 320> buf{};
    CborWriter w{MutByteView{buf}};
    w.array(11);
    w.bytes(dev.id.view());
    w.bytes(trust_.fleet.view());
    w.bytes(source.view());
    w.bytes(target.view());
    w.bytes(ByteView{hash_of(ByteView{delegation_cose.data(), delegation_cose.size()})});
    w.uint(expected_old);
    w.uint(new_generation);
    const Sha256Digest g = seeded("lmfleet-grant/" + label_, seed_, request_counter_, 0);
    w.bytes(ByteView{g.data(), 16});
    w.uint(1); // mode 1: one-time grant registered at the device
    w.bytes(ByteView{g.data() + 16, 16});
    w.bytes(ByteView{hash_of(ByteView{dev.device_cose.data(), dev.device_cose.size()})});
    return sign(envelope(member::k_type_assignment_ticket, target, trust_.key_id, new_generation),
                w.written());
}

Bytes issue_member(const Kit &root, const DomainId &domain, const Kit &dev, const MemberSpec &spec) {
    member::MemberCredential mc;
    mc.device = dev.id;
    mc.address = ShortAddr{spec.address};
    mc.assignment = AssignmentGen{spec.assignment};
    mc.membership = MembershipGen{spec.membership};
    mc.role = spec.role;
    mc.relay_allowed = spec.relay_allowed;
    mc.root_term = RootTerm{spec.root_term};
    mc.lease_expires_root_ms = spec.lease_expires_root_ms;
    mc.credential_hash = hash_of(ByteView{dev.device_cose.data(), dev.device_cose.size()});
    std::array<uint8_t, 256> buf{};
    std::size_t len = 0;
    if (member::encode_member_credential(mc, MutByteView{buf}, len) != Status::Ok) {
        return {};
    }
    member::Envelope env;
    env.type = member::k_type_member_credential;
    env.domain = domain;
    env.issuer = root.id;
    env.revision = spec.membership;
    const Sha256Digest d = seeded("lmfleet-mreq", spec.assignment + spec.membership, spec.address, 0);
    std::copy(d.begin(), d.begin() + 16, env.request.bytes.begin());
    sec::KeyHandle h;
    if (sec::import_signing_key(ByteView{root.scalar}, h) != Status::Ok) {
        return {};
    }
    Bytes out(member::k_max_bundle);
    std::size_t olen = 0;
    const Status st = member::issue_signed(h, env, ByteView{buf.data(), len},
                                           MutByteView{out.data(), out.size()}, olen);
    sec::destroy_key(h);
    out.resize(st == Status::Ok ? olen : 0);
    return out;
}

Bytes issue_root_revoke(const Kit &root, const DomainId &domain, const DeviceId &device,
                        uint64_t af, uint64_t mf) {
    member::RevokeObject r;
    r.device = device;
    r.assignment_floor = af;
    r.membership_floor = mf;
    r.revision = 1;
    std::array<uint8_t, 96> buf{};
    std::size_t len = 0;
    (void)member::encode_revoke(r, MutByteView{buf}, len);
    member::Envelope env;
    env.type = member::k_type_revoke;
    env.domain = domain;
    env.issuer = root.id;
    env.revision = 1;
    sec::KeyHandle h;
    if (sec::import_signing_key(ByteView{root.scalar}, h) != Status::Ok) {
        return {};
    }
    Bytes out(member::k_max_bundle);
    std::size_t olen = 0;
    const Status st = member::issue_signed(h, env, ByteView{buf.data(), len},
                                           MutByteView{out.data(), out.size()}, olen);
    sec::destroy_key(h);
    out.resize(st == Status::Ok ? olen : 0);
    return out;
}

Network::Network(uint64_t seed, const std::string &label)
    : fleet(seed, label), root(fleet.device(1000, "root-0")) {
    const Sha256Digest d = seeded("lmfleet-domain/" + label, seed, 0, 0);
    std::copy(d.begin(), d.begin() + 16, domain.bytes.begin());
    delegation_cose = fleet.delegation(root, domain);
}

NodeKit Network::make_root() {
    MemberSpec s;
    s.address = 1;
    s.role = 2;
    return NodeKit{root, issue_member(root, domain, root, s)};
}

NodeKit Network::make_node(uint32_t index, uint16_t address, uint8_t role, const MemberSpec *override_spec) {
    NodeKit n;
    n.kit = fleet.device(index, "node-" + std::to_string(index));
    MemberSpec s = override_spec != nullptr ? *override_spec : MemberSpec{};
    if (override_spec == nullptr) {
        s.address = address;
        s.role = role;
    }
    n.member_cose = issue_member(root, domain, n.kit, s);
    return n;
}

NodeKit Network::make_unjoined(uint32_t index) {
    NodeKit n;
    n.kit = fleet.device(index, "node-" + std::to_string(index));
    return n;
}

Status provision(sim::SimStore &store, const Network &net, const NodeKit &node, bool with_membership,
                 const member::Floors *floors) {
    sim::ProvisionInput in;
    in.scalar32 = ByteView{node.kit.scalar};
    in.device_cose = ByteView{node.kit.device_cose.data(), node.kit.device_cose.size()};
    in.trust = net.fleet.trust();
    in.delegation_cose = ByteView{net.delegation_cose.data(), net.delegation_cose.size()};
    if (with_membership) {
        in.member_cose = ByteView{node.member_cose.data(), node.member_cose.size()};
    }
    in.floors = floors;
    return sim::provision_store(store, in);
}

} // namespace lm::fleet
