// C ABI entry points of the power API (api/leanmesh.h): lm_power_policy_get/set, lm_power_get,
// lm_sleep_prepare[_ex], lm_sleep_ticket_get, lm_sleep_enter, lm_sleep_abort. Each validates its arguments and
// runs on the mesh owner. lm_sleep_prepare is the thin entry over lm_sleep_prepare_ex (docs/20 §10): one
// implementation behind both.
#include "capi/context.hpp"
#include "core/power/power.hpp"

using lm::Status;
using lm::to_abi;
using lm::capi::call;
using lm::capi::valid_ctx;

namespace {

lm::power::Policy to_policy(const lm_power_policy_t &p) {
    lm::power::Policy o;
    o.revision = p.revision;
    o.mode = static_cast<uint8_t>(p.mode);
    o.pending = static_cast<uint8_t>(p.pending_policy);
    o.wake_interval_ms = p.wake_interval_ms;
    o.rx_window_ms = p.rx_window_ms;
    o.max_rx_window_ms = p.max_rx_window_ms;
    o.awake_budget_ms = p.awake_budget_ms;
    o.shutdown_reserve_ms = p.shutdown_reserve_ms;
    o.search_budget_ms = p.search_budget_ms;
    o.guard_ms = p.guard_ms;
    o.retry_min_ms = p.retry_min_ms;
    o.retry_max_ms = p.retry_max_ms;
    o.offline_radio_ms_per_hour = p.offline_radio_ms_per_hour;
    o.extra_wakes_per_day = p.extra_event_wakes_per_day;
    o.extra_radio_ms_per_day = p.extra_event_radio_ms_per_day;
    o.shutdown_overrun_ms = p.shutdown_overrun_limit_ms;
    o.mailbox_child = p.mailbox_frames_per_child;
    o.mailbox_total = p.mailbox_frames_total;
    return o;
}

void from_policy(const lm::power::Policy &o, lm_power_policy_t &p) {
    p = lm_power_policy_t{};
    p.struct_size = sizeof(p);
    p.abi_version = LM_ABI_VERSION;
    p.revision = o.revision;
    p.mode = o.mode;
    p.pending_policy = o.pending;
    p.wake_interval_ms = o.wake_interval_ms;
    p.rx_window_ms = o.rx_window_ms;
    p.max_rx_window_ms = o.max_rx_window_ms;
    p.awake_budget_ms = o.awake_budget_ms;
    p.shutdown_reserve_ms = o.shutdown_reserve_ms;
    p.search_budget_ms = o.search_budget_ms;
    p.guard_ms = o.guard_ms;
    p.retry_min_ms = o.retry_min_ms;
    p.retry_max_ms = o.retry_max_ms;
    p.offline_radio_ms_per_hour = o.offline_radio_ms_per_hour;
    p.extra_event_wakes_per_day = o.extra_wakes_per_day;
    p.extra_event_radio_ms_per_day = o.extra_radio_ms_per_day;
    p.shutdown_overrun_limit_ms = o.shutdown_overrun_ms;
    p.mailbox_frames_per_child = o.mailbox_child;
    p.mailbox_frames_total = o.mailbox_total;
}

lm_status_t prepare(lm_context_t *ctx, lm::CommandKind kind, const void *req, std::size_t size,
                    lm_operation_id_t *operation) {
    const lm::Reply r = call(ctx, kind, req, size, nullptr, 0);
    if (r.status == Status::Ok) {
        *operation = r.operation_id;
    }
    return to_abi(r.status);
}

} // namespace

extern "C" {

lm_status_t lm_power_policy_get(lm_context_t *ctx, lm_power_policy_t *out) {
    if (!valid_ctx(ctx) || out == nullptr) {
        return to_abi(Status::InvalidArgument);
    }
    const Status a = lm::capi::check_abi(out->struct_size, out->abi_version, sizeof(*out));
    if (a != Status::Ok) {
        return to_abi(a);
    }
    lm::power::Policy p;
    const lm::Reply r = call(ctx, lm::CommandKind::PowerPolicyGet, nullptr, 0, &p, sizeof(p));
    if (r.status == Status::Ok) {
        from_policy(p, *out);
    }
    return to_abi(r.status);
}

lm_status_t lm_power_policy_set(lm_context_t *ctx, const lm_power_policy_t *policy, uint64_t expected_revision,
                                lm_operation_id_t *operation) {
    if (!valid_ctx(ctx) || policy == nullptr || operation == nullptr) {
        return to_abi(Status::InvalidArgument);
    }
    const Status a = lm::capi::check_abi(policy->struct_size, policy->abi_version, sizeof(*policy));
    if (a != Status::Ok) {
        return to_abi(a);
    }
    if (policy->reserved[0] != 0 || policy->reserved[1] != 0 || policy->mode > LM_POWER_REPORT_ONLY ||
        policy->pending_policy > LM_PENDING_SAVE_AND_SLEEP) {
        return to_abi(Status::InvalidArgument);
    }
    const lm::power::PolicySetRequest rq{to_policy(*policy), expected_revision};
    return prepare(ctx, lm::CommandKind::PowerPolicySet, &rq, sizeof(rq), operation);
}

lm_status_t lm_power_get(lm_context_t *ctx, lm_power_snapshot_t *out) {
    if (!valid_ctx(ctx) || out == nullptr) {
        return to_abi(Status::InvalidArgument);
    }
    const Status a = lm::capi::check_abi(out->struct_size, out->abi_version, sizeof(*out));
    if (a != Status::Ok) {
        return to_abi(a);
    }
    lm_power_snapshot_t s{};
    const lm::Reply r = call(ctx, lm::CommandKind::PowerGet, nullptr, 0, &s, sizeof(s));
    if (r.status == Status::Ok) {
        *out = s;
    }
    return to_abi(r.status);
}

lm_status_t lm_sleep_prepare(lm_context_t *ctx, uint32_t awake_budget_ms, lm_operation_id_t *operation) {
    if (!valid_ctx(ctx) || operation == nullptr) {
        return to_abi(Status::InvalidArgument);
    }
    return prepare(ctx, lm::CommandKind::SleepPrepare, &awake_budget_ms, sizeof(awake_budget_ms), operation);
}

lm_status_t lm_sleep_prepare_ex(lm_context_t *ctx, const lm_sleep_request_t *req, lm_operation_id_t *operation) {
    if (!valid_ctx(ctx) || req == nullptr || operation == nullptr) {
        return to_abi(Status::InvalidArgument);
    }
    const Status a = lm::capi::check_abi(req->struct_size, req->abi_version, sizeof(*req));
    if (a != Status::Ok) {
        return to_abi(a);
    }
    if (req->reserved[0] != 0 || req->reserved[1] != 0) {
        return to_abi(Status::InvalidArgument);
    }
    if (req->wake_source_mask > 0xFFU || req->sleep_kind > 0xFFU || req->pending_policy > 0xFFU) {
        return to_abi(Status::InvalidArgument);
    }
    lm::power::SleepRequest r;
    r.kind = static_cast<uint8_t>(req->sleep_kind);
    r.sources = static_cast<uint8_t>(req->wake_source_mask);
    r.pending = static_cast<uint8_t>(req->pending_policy);
    r.budget_ms = req->awake_budget_ms;
    r.sleep_ms = req->requested_sleep_ms;
    return prepare(ctx, lm::CommandKind::SleepPrepareEx, &r, sizeof(r), operation);
}

lm_status_t lm_sleep_ticket_get(lm_context_t *ctx, lm_operation_id_t operation, lm_sleep_ticket_t *out) {
    if (!valid_ctx(ctx) || out == nullptr) {
        return to_abi(Status::InvalidArgument);
    }
    lm_sleep_ticket_t t{};
    const lm::Reply r = call(ctx, lm::CommandKind::SleepTicketGet, &operation, sizeof(operation), &t, sizeof(t));
    if (r.status == Status::Ok) {
        *out = t;
    }
    return to_abi(r.status);
}

lm_status_t lm_sleep_enter(lm_context_t *ctx, const lm_sleep_ticket_t *ticket) {
    if (!valid_ctx(ctx) || ticket == nullptr) {
        return to_abi(Status::InvalidArgument);
    }
    return to_abi(call(ctx, lm::CommandKind::SleepEnter, ticket, sizeof(*ticket), nullptr, 0).status);
}

lm_status_t lm_sleep_abort(lm_context_t *ctx, lm_operation_id_t operation) {
    if (!valid_ctx(ctx)) {
        return to_abi(Status::InvalidArgument);
    }
    return to_abi(call(ctx, lm::CommandKind::SleepAbort, &operation, sizeof(operation), nullptr, 0).status);
}

} // extern "C"
