#include "fleet.hpp"

#include <algorithm>

#include <memory>

#include "core/wire/cbor.hpp"
#include "core/wire/control.hpp"
#include "port/sim/sim_provision.hpp"
#include "root/ledger.hpp"
#include "security/cose_sign1.hpp"
#include "security/crypto.hpp"
#include "store/record.hpp"

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

Bytes Fleet::sign_body_issuer_mismatch(const member::Envelope &env, ByteView data) {
    wire::ControlBody b;
    b.type = env.type;
    b.request_id = env.request.bytes;
    b.domain = env.domain.bytes;
    b.revision = env.revision;
    b.issuer = env.issuer.bytes;
    b.data = data;
    std::array<uint8_t, member::k_max_bundle> body{};
    std::size_t body_len = 0;
    sec::KeyHandle h;
    if (wire::encode_control_body(b, MutByteView{body}, body_len) != Status::Ok ||
        sec::import_signing_key(ByteView{scalar_}, h) != Status::Ok) {
        return {};
    }
    Bytes out(member::k_max_bundle);
    std::size_t len = 0;
    const Status st = sec::sign1_create(h, trust_.key_id, ByteView{body.data(), body_len},
                                        MutByteView{out.data(), out.size()}, len);
    sec::destroy_key(h);
    out.resize(st == Status::Ok ? len : 0);
    return out;
}

Bytes Fleet::window(const DomainId &domain, const member::CommissioningWindow &win) {
    std::array<uint8_t, 128> buf{};
    CborWriter w{MutByteView{buf}};
    w.array(8);
    w.bytes(ByteView{win.id});
    w.uint(win.term.value());
    w.uint(win.expected_revision);
    w.uint(win.not_before_ms);
    w.uint(win.expires_ms);
    w.uint(win.max_new_members);
    w.uint(win.allowed_roles);
    w.uint(win.policy_revision);
    return sign(envelope(member::k_type_commissioning_window, domain, trust_.key_id, win.policy_revision), w.written());
}

Bytes Fleet::handover(const DomainId &domain, const member::RootHandover &h) {
    std::array<uint8_t, 192> buf{};
    CborWriter w{MutByteView{buf}};
    w.array(8);
    w.bytes(ByteView{h.id});
    w.bytes(h.old_root.view());
    w.bytes(h.new_root.view());
    w.uint(h.old_generation);
    w.uint(h.new_generation);
    w.bytes(ByteView{h.new_delegation_hash});
    w.uint(h.new_term.value());
    w.uint(h.recovery_mode);
    return sign(envelope(member::k_type_root_handover, domain, trust_.key_id, h.new_generation), w.written());
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
                    const Bytes &delegation_cose, uint64_t expected_old, uint64_t new_generation, uint8_t mode,
                    const std::array<uint8_t, 16> *nonce) {
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
    w.uint(mode); // 1: one-time grant registered at the device; 0: bound to the device's fresh nonce
    w.bytes(nonce != nullptr ? ByteView{*nonce} : ByteView{g.data() + 16, 16});
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

Network::Network(uint64_t seed, const std::string &label, const std::string &domain_label, uint32_t root_index)
    : fleet(seed, label), root(fleet.device(root_index, "root-" + std::to_string(root_index - 1000))) {
    const Sha256Digest d = seeded("lmfleet-domain/" + label + domain_label, seed, 0, 0);
    std::copy(d.begin(), d.begin() + 16, domain.bytes.begin());
    delegation_cose = fleet.delegation(root, domain);
}

// The root's stored credential names the last term it published (ARCH2-D1): 0 for a new network, so its first boot
// publishes term 1, the term of the members issued here.
NodeKit Network::make_root() {
    MemberSpec s;
    s.address = 1;
    s.role = 2;
    s.root_term = 0;
    return NodeKit{root, issue_member(root, domain, root, s)};
}

NodeKit Network::make_new_root(uint32_t index, uint64_t generation, uint32_t term, Bytes &delegation_out) {
    NodeKit n;
    n.kit = fleet.device(index, "root-" + std::to_string(index));
    delegation_out = fleet.delegation(n.kit, domain, generation);
    MemberSpec s;
    s.address = 1;
    s.role = 2;
    s.root_term = term - 1; // its first boot publishes `term`, the one the handover names
    n.member_cose = issue_member(n.kit, domain, n.kit, s);
    return n;
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
    members.push_back(n);
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
    const bool root = with_membership && node.kit.id == net.root.id;
    if (root) {
        in.new_ledger_domain = &net.domain;
    }
    LM_TRY(sim::provision_store(store, in));
    uint64_t used = 0;
    for (std::size_t i = 0; root && i < net.members.size(); ++i) {
        uint16_t slot = 0;
        const Status st = register_member(store, net.members[i], &slot);
        if (st != Status::Ok && st != Status::InvalidArgument) {
            return st; // InvalidArgument: an address outside the ledger's slots is never listed
        }
        used |= st == Status::Ok ? uint64_t{1} << slot : 0;
    }
    if (used == 0) {
        return Status::Ok;
    }
    // Entries first, then the manifest naming their slots (the ledger's own order of a first use, SEC-D5), so
    // the root loads a consistent ledger and has nothing to repair at boot.
    root::Manifest m;
    m.domain = net.domain;
    m.used = used;
    auto job = std::make_unique<store::RecordJob>();
    std::size_t len = 0;
    LM_TRY(root::encode_manifest(m, MutByteView{job->payload}, len));
    job->op = store::RecordJob::Op::Commit;
    job->id = store::rec::root_ledger;
    job->state = 0;
    job->payload_len = static_cast<uint32_t>(len);
    return store::record_commit(store, *job);
}

Status provision_replacement_root(sim::SimStore &store, const Network &net, const NodeKit &node,
                                  const Bytes &delegation_cose) {
    sim::ProvisionInput in;
    in.scalar32 = ByteView{node.kit.scalar};
    in.device_cose = ByteView{node.kit.device_cose.data(), node.kit.device_cose.size()};
    in.trust = net.fleet.trust();
    in.delegation_cose = ByteView{delegation_cose.data(), delegation_cose.size()};
    in.member_cose = ByteView{node.member_cose.data(), node.member_cose.size()};
    return sim::provision_store(store, in);
}

Status copy_ledger(sim::SimStore &from, sim::SimStore &to) {
    auto job = std::make_unique<store::RecordJob>();
    for (uint32_t id = store::rec::root_ledger; id < root::k_rec_ledger_base + root::k_ledger_slots;
         id = id == store::rec::root_ledger ? root::k_rec_ledger_base : id + 1) {
        job->op = store::RecordJob::Op::Load;
        job->id = static_cast<uint16_t>(id);
        const Status st = store::record_load(from, *job);
        if (st == Status::NotFound) {
            continue;
        }
        LM_TRY(st);
        job->op = store::RecordJob::Op::Commit;
        LM_TRY(store::record_commit(to, *job));
    }
    return Status::Ok;
}

Status register_member(sim::SimStore &root_store, const NodeKit &node, uint16_t *slot) {
    member::Envelope env;
    ByteView data;
    member::MemberCredential mc;
    const ByteView cose{node.member_cose.data(), node.member_cose.size()};
    LM_TRY(member::peek_signed(cose, member::k_type_member_credential, env, data));
    LM_TRY(member::decode_member_credential(data, mc));
    auto job = std::make_unique<store::RecordJob>();
    std::size_t len = 0;
    uint16_t id = 0;
    LM_TRY(root::encode_provisioned_member(mc, cose, id, MutByteView{job->payload}, len));
    if (slot != nullptr) {
        *slot = static_cast<uint16_t>(id - root::k_rec_ledger_base);
    }
    job->op = store::RecordJob::Op::Commit;
    job->id = id;
    job->state = static_cast<uint8_t>(root::EntryState::Active);
    job->payload_len = static_cast<uint32_t>(len);
    return store::record_commit(root_store, *job);
}

} // namespace lm::fleet
