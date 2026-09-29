// What a device persists about who it is and whom it trusts (docs/12 §1, §2) and the boot loader
// that turns those sealed records into RAM state. Payload layouts (big endian):
//   identity          scalar32 || DeviceCredential COSE_Sign1           (secret: NVS encryption)
//   fleet_trust       fleet_id16 || x32 || y32 || min_credential_generation u64
//   root_delegation   RootDelegation COSE_Sign1 (verbatim)
//   membership        MemberCredential COSE_Sign1 (verbatim), record state 1 = ACTIVE
//   revocation_floors count u8 || count * (device32 || assignment u64 || membership u64)
// The loader runs as one worker job: it reads the records, verifies every signature, imports the
// private key into PSA and builds the credential bundle. A record that cannot be read or verified
// fails the load closed (Failed), never "unprovisioned"; only a missing identity record means that.
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/member/credentials.hpp"
#include "core/pool.hpp"
#include "core/ports.hpp"
#include "core/profile.hpp"
#include "security/crypto.hpp"
#include "store/record.hpp"

namespace lm {
class Engine;
}

namespace lm::member {

inline constexpr uint8_t k_membership_active = 1;
inline constexpr std::size_t k_trust_bytes = 16 + 64 + 8;
inline constexpr std::size_t k_floor_entry_bytes = 32 + 8 + 8;

[[nodiscard]] Status encode_identity(ByteView scalar32, ByteView device_cose, MutByteView out,
                                     std::size_t &len);
[[nodiscard]] Status decode_identity(ByteView payload, ByteView &scalar32, ByteView &device_cose);
[[nodiscard]] Status encode_trust(const TrustAnchor &t, MutByteView out, std::size_t &len);
[[nodiscard]] Status decode_trust(ByteView payload, TrustAnchor &out);
[[nodiscard]] Status encode_floors(const Floors &f, MutByteView out, std::size_t &len);
[[nodiscard]] Status decode_floors(ByteView payload, Floors &out);

class LocalIdentity {
  public:
    enum class State : uint8_t { Unloaded, Loading, Unprovisioned, Ready, Failed };

    LocalIdentity() = default;
    LocalIdentity(const LocalIdentity &) = delete;
    LocalIdentity &operator=(const LocalIdentity &) = delete;
    ~LocalIdentity() { clear(); }

    // Owner. Submits the load job (Busy while a cancelled job still owns the memory).
    [[nodiscard]] Status begin_load(Engine &engine);
    // Owner, for the completion of the load job (slot checked by the caller's Handle).
    void on_job_done(Status job_status, Handle slot);
    // Owner. Forgets everything, destroys the PSA key. With a job in flight the memory stays
    // reserved until its completion (zombie rule) and the result is discarded.
    void release();

    [[nodiscard]] State state() const { return state_; }
    [[nodiscard]] bool busy() const { return job_in_flight_; }
    [[nodiscard]] Status load_status() const { return load_status_; }
    // Ready with an ACTIVE MemberCredential: the device may open link sessions.
    [[nodiscard]] bool is_member() const { return state_ == State::Ready && has_member_; }
    [[nodiscard]] Status member_status() const { return member_status_; }

    [[nodiscard]] sec::KeyHandle key() const { return key_; }
    [[nodiscard]] const DeviceId &self() const { return dc_.device; }
    [[nodiscard]] const TrustAnchor &trust() const { return trust_; }
    [[nodiscard]] const DeviceCredential &device_credential() const { return dc_; }
    [[nodiscard]] const RootDelegation &delegation() const { return delegation_; }
    [[nodiscard]] const MemberCredential &member() const { return mc_; }
    [[nodiscard]] Floors &floors() { return floors_; }
    [[nodiscard]] const Floors &floors() const { return floors_; }
    [[nodiscard]] ByteView ccs() const { return ByteView{ccs_.data(), ccs_len_}; }
    [[nodiscard]] ByteView device_cose() const { return ByteView{bundle_.data() + dc_off_, dc_len_}; }
    [[nodiscard]] ByteView member_cose() const { return ByteView{bundle_.data() + mc_off_, mc_len_}; }
    // CBOR [DeviceCredential COSE, MemberCredential COSE], what a link exchange sends.
    [[nodiscard]] ByteView bundle() const { return ByteView{bundle_.data(), bundle_len_}; }

    // ---- [S8] membership changes at runtime (join commit, leave) ----
    // The verbatim RootDelegation COSE a root hands to joiners. Root-capable builds only; empty
    // elsewhere (a relay forwards join traffic without ever answering a handshake).
    [[nodiscard]] ByteView delegation_cose() const { return ByteView{deleg_cose_.data(), deleg_cose_len_}; }
    // [S10] Root-capable builds: the one Host paired for USB (decision D6), read with the identity.
    // NotFound = unpaired (every Host is refused); another error = unreadable (the USB link stays
    // down, the mesh does not). Only the root's serial adapter uses it.
    [[nodiscard]] Status paired_host_status() const { return paired_status_; }
    [[nodiscard]] DeviceId paired_host() const {
        DeviceId d;
        std::copy(paired_host_.begin(), paired_host_.end(), d.bytes.begin());
        return d;
    }
    // A committed ACTIVE MemberCredential becomes the live one (the caller verified the chain and
    // persisted it). Conflict unless the identity is Ready.
    [[nodiscard]] Status adopt_member(const RootDelegation &delegation, const MemberCredential &mc,
                                      ByteView mc_cose);
    // Logical erase of the domain membership (leave): identity, trust and floors stay.
    void drop_member();
    // Borrow of the record I/O memory (docs/IMPLEMENTATION.md §13: no per-feature buffers). Null while
    // the boot load owns it or another module holds it. The lender returns it after the job's
    // completion was polled.
    [[nodiscard]] store::RecordJob *lend_record() {
        if (job_in_flight_ || rec_lent_) {
            return nullptr;
        }
        rec_lent_ = true;
        return &rec_;
    }
    void return_record() {
        sec::secure_zero(MutByteView{rec_.payload});
        rec_lent_ = false;
    }

  private:
    static Status load_job(port::JobEnv &env, void *arg);
    [[nodiscard]] Status run_load(port::JobEnv &env);
    [[nodiscard]] Status load_record(port::JobEnv &env, uint16_t id);
    [[nodiscard]] Status load_membership(port::JobEnv &env);
    void load_paired_host(port::JobEnv &env);
    void clear();

    State state_ = State::Unloaded;
    bool job_in_flight_ = false;
    bool cancelled_ = false;
    bool unprovisioned_ = false;
    bool has_delegation_ = false;
    bool has_member_ = false;
    bool rec_lent_ = false;
    Status load_status_ = Status::Ok;
    Status member_status_ = Status::NotFound;
    Handle slot_;

    sec::KeyHandle key_;
    TrustAnchor trust_;
    DeviceCredential dc_;
    RootDelegation delegation_;
    MemberCredential mc_;
    Floors floors_;
    std::array<uint8_t, sec::k_ccs_max_bytes> ccs_{};
    std::size_t ccs_len_ = 0;
    std::array<uint8_t, k_max_bundle> bundle_{};
    std::size_t bundle_len_ = 0;
    std::size_t dc_off_ = 0, dc_len_ = 0, mc_off_ = 0, mc_len_ = 0;
    std::array<uint8_t, k_root_capable ? k_max_delegation_cose : 1> deleg_cose_{};
    std::size_t deleg_cose_len_ = 0;
    std::array<uint8_t, k_root_capable ? sizeof(DeviceId) : 0> paired_host_{};
    Status paired_status_ = Status::NotFound;
    store::RecordJob rec_;                            // the job's I/O memory
};

} // namespace lm::member
