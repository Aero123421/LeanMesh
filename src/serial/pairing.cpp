#include "serial/pairing.hpp"

#include <memory>

#include "store/record.hpp"

namespace lm::serial {

Status write_paired_host(port::Store &store, const DeviceId &host) {
    if (host.is_zero()) {
        return Status::InvalidArgument;
    }
    auto job = std::make_unique<store::RecordJob>(); // ~1 KiB: provisioning context, heap is fine
    job->op = store::RecordJob::Op::Commit;
    job->id = k_rec_paired_host;
    job->state = k_paired_state_active;
    job->payload_len = static_cast<uint32_t>(host.bytes.size());
    std::copy(host.bytes.begin(), host.bytes.end(), job->payload.begin());
    return store::record_commit(store, *job);
}

} // namespace lm::serial
