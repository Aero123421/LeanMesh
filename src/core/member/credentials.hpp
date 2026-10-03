// Credential objects and their checks (docs/06 §3, docs/07 §2, docs/21, protocol/control.cddl).
// Every persistent authorisation object is a COSE_Sign1 over a control-body (types 1..5 and 11).
// Chain of trust: fleet -> DeviceCredential | RootDelegation, root (per delegation) ->
// MemberCredential | RevokeObject. A check verifies the signature with the issuer key it derives
// itself (never a key the object names), then the semantic bindings. The signature checks are
// public-key work: call them from a worker job, not from the mesh owner.
//
// Decision S5-D2: MemberCredential.credential_hash is the SHA-256 of
// the DeviceCredential COSE object it was issued against; the session context's credential hash is
// the SHA-256 of the MemberCredential COSE object.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/ids.hpp"
#include "core/status.hpp"
#include "core/time.hpp"
#include "security/identity.hpp"

namespace lm::member {

// control-body `type` numbers of the signed objects (registry control_types).
inline constexpr uint8_t k_type_device_credential = 1;
inline constexpr uint8_t k_type_root_delegation = 2;
inline constexpr uint8_t k_type_assignment_ticket = 3;
inline constexpr uint8_t k_type_member_credential = 4;
inline constexpr uint8_t k_type_expected_set = 5;
inline constexpr uint8_t k_type_revoke = 11;
inline constexpr uint8_t k_type_commissioning_window = 30; // [S18]
inline constexpr uint8_t k_type_root_handover = 31;        // [S18]
inline constexpr uint8_t k_type_ledger_backup = 34;        // [ISSUE5] the root-signed header of a ledger backup

// RootDelegation permission bits (control.cddl note 2).
inline constexpr uint8_t k_perm_approve = 1;
inline constexpr uint8_t k_perm_revoke = 2;
inline constexpr uint8_t k_perm_channel = 4; // FIX12-D2: channel plans (originated by the root, accepted by members)
inline constexpr uint8_t k_perm_groups = 8;  // FIX12-D2: group definitions and their signed snapshots

inline constexpr std::size_t k_max_device_cose = 448;
inline constexpr std::size_t k_max_member_cose = 384;
inline constexpr std::size_t k_max_delegation_cose = 448;
inline constexpr std::size_t k_max_bundle = 1024; // docs/06 §9: one credential exchange <= 1024 B
inline constexpr std::size_t k_serial_max = 48;

struct Envelope {
    uint8_t type = 0;
    RequestId request;
    DomainId domain; // all-zero for fleet-level objects
    uint64_t revision = 0;
    DeviceId issuer; // must equal the COSE kid
};

struct DeviceCredential {
    DeviceId device;
    sec::PublicKey key;
    FleetId fleet;
    std::array<uint8_t, k_serial_max> serial{};
    uint8_t serial_len = 0;
    uint64_t generation = 0;
    Sha256Digest ccs_hash{};
};

struct RootDelegation {
    FleetId fleet;
    DeviceId root;
    sec::PublicKey key;
    DomainId domain;
    uint64_t generation = 0;
    uint8_t permissions = 0;
};

struct AssignmentTicket {
    DeviceId device;
    FleetId fleet;
    DomainId source;
    DomainId target;
    Sha256Digest root_delegation_hash{};
    uint64_t expected_old = 0;
    uint64_t new_generation = 0;
    GrantId grant;
    uint8_t mode = 0;
    std::array<uint8_t, 16> nonce{};
    Sha256Digest device_credential_hash{};
};

struct MemberCredential {
    DeviceId device;
    ShortAddr address;
    AssignmentGen assignment;
    MembershipGen membership;
    uint8_t role = 0; // 0 leaf, 1 relay, 2 root
    bool relay_allowed = false;
    RootTerm root_term;
    uint64_t lease_expires_root_ms = 0;
    Sha256Digest policy_hash{};
    Sha256Digest credential_hash{}; // SHA-256 of the DeviceCredential COSE object
};

struct ExpectedEntry {
    DeviceId device;
    uint64_t assignment = 0;
    Sha256Digest grant_hash{};
    bool allowed = false;
};

inline constexpr std::size_t k_expected_page_entries = 8;
struct ExpectedSet {
    uint8_t page = 0;
    uint8_t pages = 1;
    Sha256Digest set_hash{};
    std::array<ExpectedEntry, k_expected_page_entries> entries{};
    uint8_t count = 0;
};

struct RevokeObject {
    DeviceId device;
    uint64_t assignment_floor = 0;
    uint64_t membership_floor = 0;
    uint32_t reason = 0;
    uint64_t revision = 0;
};

// [S18] control.cddl 30: an admission window of one root term (docs/21 §2).
struct CommissioningWindow {
    std::array<uint8_t, 16> id{};
    RootTerm term;
    uint64_t expected_revision = 0;
    uint64_t not_before_ms = 0; // root clock of `term`
    uint64_t expires_ms = 0;
    uint8_t max_new_members = 1; // 1..64
    uint8_t allowed_roles = 1;   // bit 0 leaf, bit 1 relay
    uint64_t policy_revision = 0;
};

// [S18] control.cddl 31: the fleet moves a domain's root authority to another device (docs/21 §8).
struct RootHandover {
    std::array<uint8_t, 16> id{};
    DeviceId old_root;
    DeviceId new_root;
    uint64_t old_generation = 0;
    uint64_t new_generation = 0;
    Sha256Digest new_delegation_hash{};
    RootTerm new_term;
    uint8_t recovery_mode = 0;
};

// The fleet trust anchor a node holds (docs/07 §2 "Fleet trust anchor").
struct TrustAnchor {
    FleetId fleet;
    sec::PublicKey key;
    DeviceId key_id;                       // SHA-256(COSE_Key(key)): the kid of fleet signatures
    uint64_t min_credential_generation = 0; // DeviceCredentials below this are refused
};

[[nodiscard]] Status make_trust_anchor(const FleetId &fleet, const sec::PublicKey &key,
                                       uint64_t min_generation, TrustAnchor &out);

// ---- control-data codecs (the encoded item inside the control-body) ----
// Decoders validate the item strictly (shape already fixed by wire::decode_control_body) and
// return BadFrame for any deviation, trailing bytes included.
[[nodiscard]] Status decode_device_credential(ByteView data, DeviceCredential &out);
[[nodiscard]] Status decode_root_delegation(ByteView data, RootDelegation &out);
[[nodiscard]] Status decode_assignment_ticket(ByteView data, AssignmentTicket &out);
[[nodiscard]] Status decode_member_credential(ByteView data, MemberCredential &out);
[[nodiscard]] Status decode_expected_set(ByteView data, ExpectedSet &out);
[[nodiscard]] Status decode_revoke(ByteView data, RevokeObject &out);
[[nodiscard]] Status decode_window(ByteView data, CommissioningWindow &out);
[[nodiscard]] Status decode_handover(ByteView data, RootHandover &out);

// ---- [FIX5-D4] the semantic rules of a RootHandover (docs/21 §8), one place for every party ----
// The old root, the device and the new root each apply these; a handover that breaks them would retire a root that no
// member can follow (the domain strands). Intrinsic: the authority moves to ANOTHER device under a HIGHER delegation
// generation. InvalidArgument otherwise.
[[nodiscard]] Status check_handover(const RootHandover &h);
// The old side: `h` hands over the authority of `root` at delegation `generation`, and its new term is above `term`, the
// term that root's members live in (the old root's own term bounds them): a member refuses a new term that is not above
// its own. NetworkMismatch: not that root; Conflict: the new term is not above `term`.
[[nodiscard]] Status handover_from(const RootHandover &h, const DeviceId &root, uint64_t generation, RootTerm term);
// The new side: `h` names `root` with this delegation (generation, hash) as the domain's new root. NetworkMismatch
// otherwise. (Only the new root itself knows which term it has reached; it checks that on its own.)
[[nodiscard]] Status handover_to(const RootHandover &h, const DeviceId &root, uint64_t generation,
                                 const Sha256Digest &delegation_hash);
// The root issues member credentials and revocations, so these encoders are production code.
[[nodiscard]] Status encode_member_credential(const MemberCredential &m, MutByteView out,
                                              std::size_t &len);
[[nodiscard]] Status encode_revoke(const RevokeObject &r, MutByteView out, std::size_t &len);

// ---- signed objects ----
// Builds control-body(envelope, data) and signs it: COSE_Sign1, kid = env.issuer. Credential-class
// objects only: the control-body must fit 1024 B (NoCapacity otherwise).
[[nodiscard]] Status issue_signed(sec::KeyHandle key, const Envelope &env, ByteView data,
                                  MutByteView out, std::size_t &len);
// Structure only (no signature check): envelope + aliased control-data. For lookups that must
// happen before the issuer key is known. Never authorises anything.
[[nodiscard]] Status peek_signed(ByteView cose, uint8_t expect_type, Envelope &env, ByteView &data);
// Verifies against `signer` (kid must be DeviceId(signer), envelope issuer == kid) and requires
// `expect_type`. AuthRejected for any mismatch.
[[nodiscard]] Status open_signed(ByteView cose, const sec::PublicKey &signer, uint8_t expect_type,
                                 Envelope &env, ByteView &data);

// ---- chain checks (public-key work) ----
[[nodiscard]] Status check_device_credential(const TrustAnchor &trust, ByteView cose,
                                             DeviceCredential &out);
[[nodiscard]] Status check_root_delegation(const TrustAnchor &trust, ByteView cose,
                                           RootDelegation &out);
[[nodiscard]] Status check_member_credential(const RootDelegation &delegation, ByteView cose,
                                             MemberCredential &out);
// Fleet-signed ticket for `dc` (docs/07 §8): fleet/device/credential hash, the target delegation it
// names, the envelope domain == target, and new_generation > expected_old. Consuming the grant
// (one-time ledger, floors, mode 0 nonce) belongs to the join/transfer slices.
[[nodiscard]] Status check_assignment_ticket(const TrustAnchor &trust, ByteView cose,
                                             const DeviceCredential &dc, ByteView dc_cose,
                                             ByteView target_delegation_cose, AssignmentTicket &out);
// A signed object of `type` from the fleet, or from the delegated root when its delegation holds `permission` (then
// for its own domain only). AuthRejected for any other signer. Public-key work.
[[nodiscard]] Status open_authority(const TrustAnchor &trust, const RootDelegation *delegation, uint8_t permission,
                                    ByteView cose, uint8_t type, Envelope &env, ByteView &data);
// Signed by the fleet or by the delegated root with the approve permission (its domain only).
[[nodiscard]] Status check_expected_set(const TrustAnchor &trust, const RootDelegation *delegation,
                                        ByteView cose, ExpectedSet &out);
// MemberCredential belongs to this DeviceCredential (device id and credential_hash).
[[nodiscard]] Status check_binding(const DeviceCredential &dc, ByteView dc_cose,
                                   const MemberCredential &mc);

// ---- SEC-D1: a MemberCredential whose signature is withheld until the root's ACTIVE commit ----
// JoinPrepare carries the COSE_Sign1 with its 64 signature bytes zeroed: every field is final, but no verifier
// accepts it, so a joiner that stops at PREPARE holds no credential. JoinCommit brings the 64 bytes once the
// root's ACTIVE entry is durable. The signature of a well-formed COSE_Sign1 is its last 64 bytes.
inline constexpr std::size_t k_signature_bytes = 64;
// SHA-256 of `cose` with its signature zeroed (the join's prepare-hash). BadFrame: not a COSE_Sign1.
[[nodiscard]] Status withheld_hash(ByteView cose, Sha256Digest &out);
// `cose` is a well-formed COSE_Sign1 whose signature bytes are all zero.
[[nodiscard]] bool signature_withheld(ByteView cose);

// ---- revocation floors (docs/06 §7) ----
// Minimum acceptable generations per device, raised only. Bounded: a full table refuses new
// devices (NoCapacity) instead of forgetting one. On a root it holds the floors of devices its ledger does not list
// (and copies that let a departed device's slot be reused); a listed device's floor is its ledger entry (FIX8-D1).
inline constexpr std::size_t k_max_floors = 10;
class Floors {
  public:
    struct Entry {
        DeviceId device;
        uint64_t assignment = 0;
        uint64_t membership = 0;
    };
    [[nodiscard]] Status raise(const DeviceId &device, uint64_t assignment, uint64_t membership);
    // Revoked when either generation is below its floor.
    [[nodiscard]] Status check(const DeviceId &device, AssignmentGen a, MembershipGen m) const;
    // The floor of `device` (all zero: none).
    [[nodiscard]] Entry floor_of(const DeviceId &device) const;
    // FIX8-D1: drops entry i. Only for a copy that another durable record holds at least as high (a root's ledger
    // entry): the device's effective floor never goes down.
    void remove(std::size_t i);
    [[nodiscard]] std::size_t count() const { return count_; }
    [[nodiscard]] const Entry &at(std::size_t i) const { return entries_[i]; }
    void clear() { *this = Floors{}; }

  private:
    std::array<Entry, k_max_floors> entries_{};
    std::size_t count_ = 0;
};

// Verifies a RevokeObject signed by the fleet, or by the delegated root with the revoke
// permission for its domain, and raises the floors. AuthRejected when neither holds.
[[nodiscard]] Status apply_revoke(const TrustAnchor &trust, const RootDelegation *delegation,
                                  ByteView cose, Floors &floors, RevokeObject &out);
// [S18] The verification alone (a worker job; the owner raises the floors).
[[nodiscard]] Status verify_revoke(const TrustAnchor &trust, const RootDelegation *delegation, ByteView cose,
                                   RevokeObject &out);

// Lease of a member credential on the root clock. Before: provably valid; After: expired;
// Uncertain: no proof either way (the caller decides, see the link layer).
[[nodiscard]] DeadlineCheck check_lease(const MemberCredential &mc, const RootTimeBound &now);
[[nodiscard]] inline RootTime lease_of(const MemberCredential &mc) {
    return RootTime{mc.root_term, mc.lease_expires_root_ms};
}
// SEC-D3: the local time until which `lease` provably holds, given `bound` (for which it is Before) at `now`: its
// remaining root time from the latest estimate, shortened by 1000 ppm of local clock drift (twice the qualified
// 500 ppm) and 1 ms. A session authorised by that lease ends then at the latest.
[[nodiscard]] MonoTime lease_local_end(const RootTimeBound &bound, const RootTime &lease, MonoTime now);

// The credential pair every exchange sends first, CBOR [DeviceCredential COSE, x]: x is the MemberCredential COSE
// (a link or end exchange; x_max = k_max_member_cose) or the RootDelegation COSE (the root's CredR of a join;
// k_max_delegation_cose). One codec for both.
[[nodiscard]] Status cred_pair_encode(ByteView device_cose, ByteView x, std::size_t x_max, MutByteView out,
                                      std::size_t &len);
[[nodiscard]] Status cred_pair_parse(ByteView in, std::size_t x_max, ByteView &device_cose, ByteView &x);

} // namespace lm::member
