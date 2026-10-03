// TEST-ONLY fleet issuer (docs/21, docs/IMPLEMENTATION.md §1). It stands in for the fleet's
// offline signing service and the root's approval path so meshsim and native tests can provision
// sim nodes. Keys are derived from a seed, are public knowledge and exist only in tools/ and
// tests/: this library is never linked into firmware (AGENTS.md "テスト鍵の製品への残存は禁止").
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "core/member/credentials.hpp"
#include "port/sim/sim_store.hpp"

namespace lm::fleet {

using Bytes = std::vector<uint8_t>;

// One device as the fleet ships it: key pair and fleet-signed DeviceCredential.
struct Kit {
    std::array<uint8_t, 32> scalar{};
    sec::PublicKey pub;
    DeviceId id;
    std::string serial;
    member::DeviceCredential dc;
    Bytes device_cose;
};

struct MemberSpec {
    uint16_t address = 2;
    uint64_t assignment = 1;
    uint64_t membership = 1;
    uint8_t role = 1;
    bool relay_allowed = true;
    uint32_t root_term = 1;
    uint64_t lease_expires_root_ms = 0xFFFFFFFFFFULL; // far in the future on the root clock
};

// The fleet signer: trust anchor + signing of fleet-level objects.
class Fleet {
  public:
    // `label` separates independent fleets built from the same seed (rogue-issuer tests).
    Fleet(uint64_t seed, const std::string &label);
    ~Fleet();
    Fleet(const Fleet &) = delete;
    Fleet &operator=(const Fleet &) = delete;

    [[nodiscard]] const member::TrustAnchor &trust() const { return trust_; }
    [[nodiscard]] uint64_t seed() const { return seed_; }

    Kit device(uint32_t index, const std::string &serial, uint64_t generation = 1);
    Bytes delegation(const Kit &root, const DomainId &domain, uint64_t generation = 1,
                     uint8_t permissions = 15); // approve | revoke | channel | groups (FIX12-D2)
    Bytes revoke(const DeviceId &device, uint64_t assignment_floor, uint64_t membership_floor,
                 uint64_t revision = 1);
    // mode 1: a preissued one-time grant (the nonce field is filler); mode 0: bound to the device's fresh nonce.
    Bytes ticket(const Kit &dev, const DomainId &source, const DomainId &target,
                 const Bytes &delegation_cose, uint64_t expected_old, uint64_t new_generation, uint8_t mode = 1,
                 const std::array<uint8_t, 16> *nonce = nullptr);
    // Generic signed object (negative tests build malformed ones with it).
    Bytes sign(const member::Envelope &env, ByteView data);
    // [S18] Fleet-signed lifecycle objects of `domain`: an admission window (control 30) and a root handover (31).
    Bytes window(const DomainId &domain, const member::CommissioningWindow &w);
    Bytes handover(const DomainId &domain, const member::RootHandover &h);
    // Negative tests: body says `env.issuer`, the COSE kid is the fleet's real key id (sign1_create
    // itself refuses a kid that is not the signer's, so this is the only way to build the lie).
    Bytes sign_body_issuer_mismatch(const member::Envelope &env, ByteView data);

    // Deterministic key pair for (seed, label, index); retries until the scalar is valid.
    static void derive_key(uint64_t seed, const std::string &label, uint32_t index,
                           std::array<uint8_t, 32> &scalar, sec::PublicKey &pub);

  private:
    Bytes sign_with(const std::array<uint8_t, 32> &scalar, const DeviceId &kid,
                    const member::Envelope &env, ByteView data);
    member::Envelope envelope(uint8_t type, const DomainId &domain, const DeviceId &issuer,
                              uint64_t revision);

    uint64_t seed_;
    std::string label_;
    std::array<uint8_t, 32> scalar_{};
    member::TrustAnchor trust_;
    uint32_t request_counter_ = 0;
    friend class Network;
};

// The root signs the objects of its domain (MemberCredential, root-issued RevokeObject).
Bytes issue_member(const Kit &root, const DomainId &domain, const Kit &dev, const MemberSpec &spec);
Bytes issue_root_revoke(const Kit &root, const DomainId &domain, const DeviceId &device,
                        uint64_t assignment_floor, uint64_t membership_floor);

struct NodeKit {
    Kit kit;
    Bytes member_cose;
};

// One fleet, one domain, one root: the common test topology.
class Network {
  public:
    // [S18] `domain_label` / `root_index`: another domain (and root) of the same fleet (same seed and label: the same
    // fleet key and the same device identities, e.g. for a transfer between two domains).
    explicit Network(uint64_t seed, const std::string &label = "fleet", const std::string &domain_label = "",
                     uint32_t root_index = 1000);

    Fleet fleet;
    DomainId domain;
    Kit root;
    Bytes delegation_cose;

    // Root node (address 1) or an ordinary member; device index is unique per node.
    NodeKit make_root();
    // [S18] A new root device for this domain (a handover): delegation of `generation`; its first boot publishes `term`.
    NodeKit make_new_root(uint32_t index, uint64_t generation, uint32_t term, Bytes &delegation_out);
    // A member issued outside a join. It is also remembered as one the root's ledger lists (SEC-D2: the root
    // admits nobody else): provisioning the root writes all members made so far, register_member() a later one.
    NodeKit make_node(uint32_t index, uint16_t address, uint8_t role = 1,
                      const MemberSpec *override_spec = nullptr);
    // Identity + delegation only: a provisioned device that has not joined yet.
    NodeKit make_unjoined(uint32_t index);

    std::vector<NodeKit> members; // every make_node() so far, in order
};

// Writes the sealed records of `node` into `store` (sim_provision underneath). For the root (with its
// membership) this is the provisioning of a new network: an empty ledger bound to the domain (SEC-D5), then
// every member of `net.members` listed ACTIVE as if the root had admitted it.
[[nodiscard]] Status provision(sim::SimStore &store, const Network &net, const NodeKit &node,
                               bool with_membership = true, const member::Floors *floors = nullptr);
// Bench only: lists `node` ACTIVE in the ledger held by `root_store` (address 2..65 is its slot, out: `slot`).
// Alone (a member made after the root's provisioning) its manifest bit is repaired when the root loads.
[[nodiscard]] Status register_member(sim::SimStore &root_store, const NodeKit &node, uint16_t *slot = nullptr);
// [S18] A replacement root (a handover): its own delegation and credential; no ledger of its own - it gets the old
// root's from its signed backup, restored through the root's own verified path (issue #5), or it is RECOVERY_REQUIRED
// (docs/12 §5, docs/21 §8). (The sim-only copy of the old root's store that stood here as "the backup" is gone.)
[[nodiscard]] Status provision_replacement_root(sim::SimStore &store, const Network &net, const NodeKit &node,
                                                const Bytes &delegation_cose);

} // namespace lm::fleet
