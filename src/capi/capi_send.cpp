// C ABI of delivery (api/leanmesh.h, docs/10 §3-§4): send, operation queries, cancel, the
// application's result report and the payload capacity. Each call validates its arguments, then
// runs on the mesh owner; nothing here touches core state.
#include <cstring>

#include "capi/context.hpp"
#include "core/delivery/delivery.hpp"

namespace {

using lm::Status;
using lm::to_abi;

bool valid_ctx(const lm_context_t *ctx) { return ctx != nullptr && ctx->magic == lm_context::k_magic; }

lm::Reply call(lm_context_t *ctx, lm::CommandKind kind, const void *request, std::size_t request_size,
               lm::ByteView payload = lm::ByteView{}, void *response = nullptr, std::size_t response_size = 0) {
    lm::Command cmd;
    cmd.kind = kind;
    cmd.request = request;
    cmd.request_size = request_size;
    cmd.payload = payload;
    cmd.response = response;
    cmd.response_size = response_size;
    return ctx->owner.call(cmd);
}

lm_status_t send_common(lm_context_t *ctx, const lm_send_request_t *rq, const uint8_t *payload, size_t len,
                        lm_operation_id_t *op) {
    if (!valid_ctx(ctx) || rq == nullptr || op == nullptr || (payload == nullptr && len != 0)) {
        return to_abi(Status::InvalidArgument);
    }
    const Status a = lm::capi::check_abi(rq->struct_size, rq->abi_version, sizeof(*rq));
    if (a != Status::Ok) {
        return to_abi(a);
    }
    const lm::Reply r = call(ctx, lm::CommandKind::Send, rq, sizeof(*rq), lm::ByteView{payload, len});
    if (r.status == Status::Ok) {
        *op = r.operation_id;
    }
    return to_abi(r.status);
}

} // namespace

extern "C" {

lm_status_t lm_send(lm_context_t *ctx, const lm_send_request_t *rq, const uint8_t *payload, size_t len,
                    lm_operation_id_t *op) {
    return send_common(ctx, rq, payload, len, op);
}

// Objects (4096 B) need the fragment engine of the transfer slice: the operation does not exist yet.
lm_status_t lm_send_object(lm_context_t *ctx, const lm_send_request_t *, const uint8_t *, size_t,
                           lm_operation_id_t *) {
    return to_abi(valid_ctx(ctx) ? Status::Unsupported : Status::InvalidArgument);
}

lm_status_t lm_get_operation(lm_context_t *ctx, lm_operation_id_t id, lm_operation_t *out) {
    if (!valid_ctx(ctx) || out == nullptr) {
        return to_abi(Status::InvalidArgument);
    }
    const Status a = lm::capi::check_abi(out->struct_size, out->abi_version, sizeof(*out));
    if (a != Status::Ok) {
        return to_abi(a);
    }
    lm_operation_t tmp{};
    const lm::Reply r = call(ctx, lm::CommandKind::GetOperation, &id, sizeof(id), lm::ByteView{}, &tmp, sizeof(tmp));
    if (r.status == Status::Ok) {
        *out = tmp;
    }
    return to_abi(r.status);
}

lm_status_t lm_get_message(lm_context_t *ctx, const lm_message_ref_t *ref, lm_operation_t *out) {
    if (!valid_ctx(ctx) || ref == nullptr || out == nullptr) {
        return to_abi(Status::InvalidArgument);
    }
    const Status a = lm::capi::check_abi(out->struct_size, out->abi_version, sizeof(*out));
    if (a != Status::Ok) {
        return to_abi(a);
    }
    lm_operation_t tmp{};
    const lm::Reply r =
        call(ctx, lm::CommandKind::GetMessage, ref, sizeof(*ref), lm::ByteView{}, &tmp, sizeof(tmp));
    if (r.status == Status::Ok) {
        *out = tmp;
    }
    return to_abi(r.status);
}

lm_status_t lm_cancel(lm_context_t *ctx, lm_operation_id_t id) {
    if (!valid_ctx(ctx)) {
        return to_abi(Status::InvalidArgument);
    }
    return to_abi(call(ctx, lm::CommandKind::Cancel, &id, sizeof(id)).status);
}

lm_status_t lm_report_application_result(lm_context_t *ctx, const lm_message_ref_t *ref, uint32_t outcome,
                                         const uint8_t *result, size_t len, lm_operation_id_t *op) {
    if (!valid_ctx(ctx) || ref == nullptr || (result == nullptr && len != 0) || len > LM_MAX_APP_RESULT_BYTES) {
        return to_abi(Status::InvalidArgument);
    }
    lm::delivery::ReportRequest rq;
    rq.ref = *ref;
    rq.outcome = outcome;
    const lm::Reply r = call(ctx, lm::CommandKind::ReportApplicationResult, &rq, sizeof(rq),
                             lm::ByteView{result, len});
    if (r.status == Status::Ok && op != nullptr) {
        *op = r.operation_id;
    }
    return to_abi(r.status);
}

lm_status_t lm_payload_capacity(lm_context_t *ctx, const lm_destination_t *dest, uint32_t *single_frame_bytes,
                                uint32_t *path_hops) {
    if (!valid_ctx(ctx) || dest == nullptr || single_frame_bytes == nullptr || path_hops == nullptr) {
        return to_abi(Status::InvalidArgument);
    }
    lm::delivery::CapacityRequest rq;
    rq.dest = *dest;
    const lm::Reply r = call(ctx, lm::CommandKind::PayloadCapacity, &rq, sizeof(rq));
    if (r.status == Status::Ok) {
        *single_frame_bytes = rq.single_frame_bytes;
        *path_hops = rq.path_hops;
    }
    return to_abi(r.status);
}

} // extern "C"
