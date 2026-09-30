#include "serial/pairing.hpp"

#include <memory>

#include "store/record.hpp"

namespace lm::serial {

Status write_paired_host(port::Store &store, const DeviceId &host) {
    if (host.is_zero()) {
        return Status::InvalidArgument;
    }
    auto job = std::make_unique<store::RecordJob>(); // ~1 KiB: provisioning context, heap is fine
    job->arm(store::RecordJob::Op::Commit, k_rec_paired_host, k_paired_state_active, host.bytes.size());
    std::copy(host.bytes.begin(), host.bytes.end(), job->payload.begin());
    return store::record_commit(store, *job);
}

} // namespace lm::serial
