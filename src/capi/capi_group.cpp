// C ABI of groups (api/leanmesh.h, docs/10 §group): lm_group_set (root), lm_group_progress and
// lm_group_targets. A send to a group is lm_send with LM_DEST_GROUP (capi_send.cpp). Each call validates
// its arguments, then runs on the mesh owner through OwnerCall.
#include <cstring>

#include "capi/context.hpp"
#include "core/group/group.hpp"

using lm::Status;
using lm::to_abi;

namespace {

bool valid_ctx(const lm_context_t *ctx) { return ctx != nullptr && ctx->magic == lm_context::k_magic; }

lm::Reply call(lm_context_t *ctx, lm::CommandKind kind, const void *req, std::size_t req_size, void *resp,
               std::size_t resp_size) {
    lm::Command cmd;
    cmd.kind = kind;
    cmd.request = req;
    cmd.request_size = req_size;
    cmd.response = resp;
    cmd.response_size = resp_size;
    return ctx->owner.call(cmd);
}

} // namespace

extern "C" {

lm_status_t lm_group_set(lm_context_t *ctx, uint32_t group_id, uint64_t expected_revision,
                         const lm_device_id_t *members, size_t count, lm_operation_id_t *operation) {
    if (!valid_ctx(ctx) || operation == nullptr || (members == nullptr && count != 0)) {
        return to_abi(Status::InvalidArgument);
    }
    lm::group::SetRequest rq;
    rq.group_id = group_id;
    rq.expected_revision = expected_revision;
    rq.members = members != nullptr ? members->bytes : nullptr;
    rq.count = count;
    const lm::Reply r = call(ctx, lm::CommandKind::GroupSet, &rq, sizeof(rq), nullptr, 0);
    if (r.status == Status::Ok) {
        *operation = r.operation_id;
    }
    return to_abi(r.status);
}

lm_status_t lm_group_progress(lm_context_t *ctx, lm_operation_id_t operation, lm_group_progress_t *out) {
    if (!valid_ctx(ctx) || out == nullptr) {
        return to_abi(Status::InvalidArgument);
    }
    const Status a = lm::capi::check_abi(out->struct_size, out->abi_version, sizeof(*out));
    if (a != Status::Ok) {
        return to_abi(a);
    }
    lm_group_progress_t p{};
    const lm::Reply r = call(ctx, lm::CommandKind::GroupProgress, &operation, sizeof(operation), &p, sizeof(p));
    if (r.status == Status::Ok) {
        *out = p;
    }
    return to_abi(r.status);
}

lm_status_t lm_group_targets(lm_context_t *ctx, lm_operation_id_t operation, const uint8_t snapshot_token[16],
                             uint32_t offset, lm_group_target_t *out, size_t capacity, size_t *written,
                             uint32_t *total) {
    if (!valid_ctx(ctx) || snapshot_token == nullptr || (out == nullptr && capacity != 0) || written == nullptr ||
        total == nullptr) {
        return to_abi(Status::InvalidArgument);
    }
    lm::group::TargetsRequest rq;
    rq.operation = operation;
    std::memcpy(rq.token.data(), snapshot_token, 16);
    rq.offset = offset;
    rq.out = out; // the caller is blocked: the owner writes the page straight into its array
    rq.capacity = capacity;
    const lm::Reply r = call(ctx, lm::CommandKind::GroupTargets, &rq, sizeof(rq), nullptr, 0);
    *written = rq.written;
    *total = rq.total;
    return to_abi(r.status);
}

} // extern "C"
