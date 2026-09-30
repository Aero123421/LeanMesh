// C ABI entry points of membership (api/leanmesh.h): lm_membership_get, lm_join, lm_leave,
// lm_install_control (AssignmentTicket / ExpectedSet), lm_get_request. Each validates its arguments,
// then runs on the mesh owner through OwnerCall.
#include "capi/context.hpp"
#include "core/member/membership.hpp"

using lm::Status;
using lm::to_abi;
using lm::capi::call;
using lm::capi::valid_ctx;

extern "C" {

lm_status_t lm_membership_get(lm_context_t *ctx, lm_membership_t *out) {
    if (!valid_ctx(ctx) || out == nullptr) {
        return to_abi(Status::InvalidArgument);
    }
    const Status a = lm::capi::check_abi(out->struct_size, out->abi_version, sizeof(*out));
    if (a != Status::Ok) {
        return to_abi(a);
    }
    lm_membership_t m{};
    const lm::Reply r = call(ctx, lm::CommandKind::MembershipGet, nullptr, 0, &m, sizeof(m));
    if (r.status == Status::Ok) {
        *out = m;
    }
    return to_abi(r.status);
}

lm_status_t lm_join(lm_context_t *ctx, const lm_join_request_t *req, lm_operation_id_t *operation) {
    if (!valid_ctx(ctx) || req == nullptr || operation == nullptr) {
        return to_abi(Status::InvalidArgument);
    }
    const Status a = lm::capi::check_abi(req->struct_size, req->abi_version, sizeof(*req));
    if (a != Status::Ok) {
        return to_abi(a);
    }
    if (req->reserved != 0 || req->constrain_target > 1 || req->mode > LM_JOIN_TRANSFER_CANDIDATE) {
        return to_abi(Status::InvalidArgument);
    }
    const lm::Reply r = call(ctx, lm::CommandKind::Join, req, sizeof(*req), nullptr, 0);
    if (r.status == Status::Ok) {
        *operation = r.operation_id;
    }
    return to_abi(r.status);
}

lm_status_t lm_leave(lm_context_t *ctx, uint32_t mode, uint32_t deadline_ms, lm_operation_id_t *operation) {
    if (!valid_ctx(ctx) || operation == nullptr || mode > LM_LEAVE_IMMEDIATE || deadline_ms > 30000) {
        return to_abi(Status::InvalidArgument);
    }
    const lm::member::LeaveArgs args{mode, deadline_ms};
    const lm::Reply r = call(ctx, lm::CommandKind::Leave, &args, sizeof(args), nullptr, 0);
    if (r.status == Status::Ok) {
        *operation = r.operation_id;
    }
    return to_abi(r.status);
}

lm_status_t lm_install_control(lm_context_t *ctx, uint32_t control_type, const uint8_t *signed_cbor, size_t len,
                               lm_operation_id_t *operation) {
    if (!valid_ctx(ctx) || signed_cbor == nullptr || len == 0 || operation == nullptr) {
        return to_abi(Status::InvalidArgument);
    }
    const lm::Reply r = call(ctx, lm::CommandKind::InstallControl, &control_type, sizeof(control_type), nullptr, 0,
                             lm::ByteView{signed_cbor, len});
    if (r.status == Status::Ok) {
        *operation = r.operation_id;
    }
    return to_abi(r.status);
}

lm_status_t lm_transfer_nonce_get(lm_context_t *ctx, uint8_t nonce[16]) {
    if (!valid_ctx(ctx) || nonce == nullptr) {
        return to_abi(Status::InvalidArgument);
    }
    return to_abi(call(ctx, lm::CommandKind::TransferNonce, nullptr, 0, nonce, 16).status);
}

lm_status_t lm_get_request(lm_context_t *ctx, const lm_request_id_t *id, lm_operation_t *out) {
    if (!valid_ctx(ctx) || id == nullptr || out == nullptr) {
        return to_abi(Status::InvalidArgument);
    }
    const Status a = lm::capi::check_abi(out->struct_size, out->abi_version, sizeof(*out));
    if (a != Status::Ok) {
        return to_abi(a);
    }
    lm_operation_t op{};
    const lm::Reply r = call(ctx, lm::CommandKind::GetRequest, id, sizeof(*id), &op, sizeof(op));
    if (r.status == Status::Ok) {
        *out = op;
    }
    return to_abi(r.status);
}

} // extern "C"
