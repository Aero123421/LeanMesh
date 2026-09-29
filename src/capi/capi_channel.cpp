// C ABI entry point of the channel slice (api/leanmesh.h): lm_channel_request. The application never touches the
// radio; auto/freeze/recalculate are requests to the root's coordinator (docs/10 §5). Non-root builds answer
// UNSUPPORTED: the operation does not exist there, it is never faked.
#include <array>

#include "capi/context.hpp"

extern "C" lm_status_t lm_channel_request(lm_context_t *ctx, uint32_t action, uint64_t expected_revision,
                                          lm_operation_id_t *operation) {
    if (ctx == nullptr || ctx->magic != lm_context::k_magic || operation == nullptr || action > LM_CHANNEL_RECALCULATE ||
        expected_revision > lm::k_u63_max) {
        return lm::to_abi(lm::Status::InvalidArgument);
    }
    const std::array<uint64_t, 2> rq{action, expected_revision};
    lm::Command cmd;
    cmd.kind = lm::CommandKind::ChannelRequest;
    cmd.request = &rq;
    cmd.request_size = sizeof(rq);
    const lm::Reply r = ctx->owner.call(cmd);
    if (r.status == lm::Status::Ok) {
        *operation = r.operation_id; // 0: applied on acceptance (no asynchronous operation follows)
    }
    return lm::to_abi(r.status);
}
