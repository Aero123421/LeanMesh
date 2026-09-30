// C ABI entry points lm_connectivity_get, lm_policy_get and lm_policy_set (api/leanmesh.h). All three run on the
// owner (Engine::execute); the argument checks that do not need engine state happen here.
#include "capi/context.hpp"

using lm::Status;
using lm::to_abi;

extern "C" {

lm_status_t lm_connectivity_get(lm_context_t *ctx, lm_connectivity_t *out) {
    if (!lm::capi::valid_ctx(ctx) || out == nullptr) {
        return to_abi(Status::InvalidArgument);
    }
    const Status s = lm::capi::check_abi(out->struct_size, out->abi_version, sizeof(*out));
    if (s != Status::Ok) {
        return to_abi(s);
    }
    return to_abi(lm::capi::call(ctx, lm::CommandKind::ConnectivityGet, nullptr, 0, out, sizeof(*out)).status);
}

lm_status_t lm_policy_get(lm_context_t *ctx, lm_policy_t *out) {
    if (!lm::capi::valid_ctx(ctx) || out == nullptr) {
        return to_abi(Status::InvalidArgument);
    }
    const Status s = lm::capi::check_abi(out->struct_size, out->abi_version, sizeof(*out));
    if (s != Status::Ok) {
        return to_abi(s);
    }
    return to_abi(lm::capi::call(ctx, lm::CommandKind::PolicyGet, nullptr, 0, out, sizeof(*out)).status);
}

lm_status_t lm_policy_set(lm_context_t *ctx, const lm_policy_t *policy, uint64_t expected_revision,
                          lm_operation_id_t *operation) {
    if (!lm::capi::valid_ctx(ctx) || policy == nullptr || operation == nullptr || expected_revision > lm::k_u63_max) {
        return to_abi(Status::InvalidArgument);
    }
    const Status s = lm::capi::check_abi(policy->struct_size, policy->abi_version, sizeof(*policy));
    if (s != Status::Ok) {
        return to_abi(s);
    }
    if (policy->join_mode > 2 || policy->channel_automatic > 1 || policy->channel_freeze > 1 || policy->relay_allowed > 1 ||
        policy->channel_automatic == policy->channel_freeze || policy->reserved[0] != 0 || policy->reserved[1] != 0) {
        return to_abi(Status::InvalidArgument);
    }
    const lm::PolicySetRequest rq{*policy, expected_revision};
    const lm::Reply r = lm::capi::call(ctx, lm::CommandKind::PolicySet, &rq, sizeof(rq));
    if (r.status == Status::Ok) {
        *operation = r.operation_id; // 0: applied on acceptance
    }
    return to_abi(r.status);
}

} // extern "C"
