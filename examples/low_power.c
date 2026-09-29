/* Compile-only integration example. No hardware code, secret, or success stub. */
#include "leanmesh.h"
#include <string.h>
lm_status_t enable_periodic_reporting(lm_context_t *ctx, lm_operation_id_t *op) {
    lm_power_policy_t p;
    memset(&p, 0, sizeof p);
    p.struct_size = sizeof p;
    p.abi_version = LM_ABI_VERSION;
    lm_status_t status = lm_power_policy_get(ctx, &p);
    if (status != LM_STATUS_OK) return status;
    uint64_t expected_revision = p.revision;
    if (expected_revision >= UINT64_C(9223372036854775807))
        return LM_STATUS_CONFLICT;
    p.revision = expected_revision + 1u;
    p.mode = LM_POWER_REPORT_ONLY;
    p.wake_interval_ms = 60000;
    p.rx_window_ms = 250;
    p.max_rx_window_ms = 1500;
    p.pending_policy = LM_PENDING_SAVE_AND_SLEEP;
    return lm_power_policy_set(ctx, &p, expected_revision, op);
}
lm_status_t prepare_report_sleep(lm_context_t *ctx, lm_operation_id_t *op) {
    lm_sleep_request_t request;
    memset(&request, 0, sizeof request);
    request.struct_size = sizeof request;
    request.abi_version = LM_ABI_VERSION;
    request.sleep_kind = LM_SLEEP_DEEP;
    request.wake_source_mask = LM_WAKE_TIMER;
    request.requested_sleep_ms = 60000;
    request.awake_budget_ms = 15000;
    request.pending_policy = LM_PENDING_SAVE_AND_SLEEP;
    return lm_sleep_prepare_ex(ctx, &request, op);
}
/* Application waits for the operation, checks sensors, retrieves the one-use
   sleep ticket and calls lm_sleep_enter. New RX may invalidate the ticket. */
