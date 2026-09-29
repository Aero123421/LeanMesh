#include "port/sim/sim_provision.hpp"

#include <memory>

#include "core/member/records.hpp"
#include "store/record.hpp"

namespace lm::sim {
namespace {

Status commit(port::Store &store, store::RecordJob &job, uint16_t id, uint8_t state, ByteView payload) {
    if (payload.size() > store::k_max_payload) {
        return Status::NoCapacity;
    }
    job.op = store::RecordJob::Op::Commit;
    job.id = id;
    job.state = state;
    job.payload_len = static_cast<uint32_t>(payload.size());
    std::copy(payload.begin(), payload.end(), job.payload.begin());
    return store::record_commit(store, job);
}

} // namespace

Status provision_store(port::Store &store, const ProvisionInput &in) {
    auto job = std::make_unique<store::RecordJob>(); // ~1 KiB: heap is fine on the bench
    std::array<uint8_t, store::k_max_payload> buf{};
    std::size_t len = 0;
    // Counter floor first: a provisioned device must never look virgin to boot_incarnation_advance.
    std::array<uint8_t, 8> zero{};
    LM_TRY(commit(store, *job, store::rec::boot_incarnation, 0, ByteView{zero.data(), zero.size()}));
    LM_TRY(member::encode_identity(in.scalar32, in.device_cose, MutByteView{buf}, len));
    LM_TRY(commit(store, *job, store::rec::identity, 0, ByteView{buf.data(), len}));
    LM_TRY(member::encode_trust(in.trust, MutByteView{buf}, len));
    LM_TRY(commit(store, *job, store::rec::fleet_trust, 0, ByteView{buf.data(), len}));
    if (in.floors != nullptr) {
        LM_TRY(member::encode_floors(*in.floors, MutByteView{buf}, len));
        LM_TRY(commit(store, *job, store::rec::revocation_floors, 0, ByteView{buf.data(), len}));
    }
    if (!in.delegation_cose.empty()) {
        LM_TRY(commit(store, *job, store::rec::root_delegation, 0, in.delegation_cose));
    }
    if (!in.member_cose.empty()) {
        LM_TRY(commit(store, *job, store::rec::membership, member::k_membership_active, in.member_cose));
    }
    return Status::Ok;
}

} // namespace lm::sim
