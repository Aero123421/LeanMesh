#ifndef LEANMESH_H
#define LEANMESH_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* SPEC CONTRACT ONLY: these declarations do not implement a Mesh SDK. */
#define LM_ABI_VERSION 2u
#define LM_MAX_ROOT_DEPTH 20u
#define LM_MAX_PATH_HOPS 40u
#define LM_MAX_RF_BYTES 250u
#define LM_MAX_MESSAGE_BYTES 512u
#define LM_MAX_OBJECT_BYTES 4096u
#define LM_MAX_APP_RESULT_BYTES 32u

typedef struct lm_context lm_context_t;
typedef struct { uint8_t bytes[32]; } lm_device_id_t;
typedef struct { uint8_t bytes[16]; } lm_domain_id_t;
typedef struct { uint8_t bytes[16]; } lm_message_id_t;
typedef struct { uint8_t bytes[16]; } lm_request_id_t;
typedef struct {
 lm_device_id_t origin;
 uint64_t assignment_generation;
 lm_message_id_t id;
 uint8_t intent_hash[32];
} lm_message_ref_t;
typedef uint64_t lm_operation_id_t;
typedef uint32_t lm_status_t;
enum {
 LM_STATUS_OK=0,
 LM_STATUS_INVALID_ARGUMENT=1,
 LM_STATUS_UNSUPPORTED=2,
 LM_STATUS_BUSY=3,
 LM_STATUS_NO_CAPACITY=4,
 LM_STATUS_NO_ROUTE=5,
 LM_STATUS_AUTH_PENDING=6,
 LM_STATUS_AUTH_REJECTED=7,
 LM_STATUS_REVOKED=8,
 LM_STATUS_CONFLICT=9,
 LM_STATUS_EXPIRED=10,
 LM_STATUS_TIME_UNCERTAIN=11,
 LM_STATUS_RX_WINDOW_CLOSED=12,
 LM_STATUS_RF_PROFILE_UNAPPROVED=13,
 LM_STATUS_STORAGE_FAILURE=14,
 LM_STATUS_RECOVERY_REQUIRED=15,
 LM_STATUS_DRIVER_RESULT_UNKNOWN=16,
 LM_STATUS_BUFFER_TOO_SMALL=17,
 LM_STATUS_CANCEL_TOO_LATE=18,
 LM_STATUS_CURSOR_GAP=19,
 LM_STATUS_EPOCH_CLOSED=20,
 LM_STATUS_PAYLOAD_TOO_LARGE=21,
 LM_STATUS_NETWORK_MISMATCH=22,
 LM_STATUS_ROLE_NOT_ALLOWED=23,
 LM_STATUS_NOT_FOUND=24,
 LM_STATUS_BAD_FRAME=25,
 LM_STATUS_REPLAY=26,
 LM_STATUS_RATE_LIMITED=27,
 LM_STATUS_ROOT_UNAVAILABLE=28,
 LM_STATUS_DEADLINE_UNREACHABLE=29,
 LM_STATUS_POWER_BUDGET_EXHAUSTED=30,
 LM_STATUS_SLEEP_TICKET_STALE=31,
 LM_STATUS_SESSION_REFRESH_REQUIRED=32,
 LM_STATUS_PEER_ASLEEP=33,
 LM_STATUS_TARGET_GENERATION_CHANGED=34
};
enum { LM_ROLE_LEAF=0, LM_ROLE_RELAY=1, LM_ROLE_ROOT=2 };
enum { LM_DEST_NODE=0, LM_DEST_GROUP=1, LM_DEST_ROOT_APP=2 };
enum { LM_BEST_EFFORT=0, LM_RECEIVED=1, LM_APPLIED=2 };
enum { LM_VOLATILE=0, LM_DURABLE=1 };
enum { LM_FIFO=0, LM_LATEST=1 };
enum { LM_PRIORITY_BULK=0, LM_PRIORITY_NORMAL=1,
       LM_PRIORITY_URGENT=2, LM_PRIORITY_CONTROL=3 };
enum { LM_UNASSIGNED=0, LM_DISCOVERING=1, LM_AUTHENTICATING=2,
       LM_APPROVAL_PENDING=3, LM_PREPARED=4, LM_ACTIVE=5,
       LM_LEAVING=6, LM_MEMBER_REVOKED=7, LM_QUARANTINED=8 };
enum { LM_CONNECTIVITY_UNKNOWN=0, LM_REACHABLE=1, LM_DEGRADED=2,
       LM_ISOLATED=3, LM_SLEEPING=4 };
enum { LM_OUTCOME_PENDING=0, LM_OUTCOME_RECEIVED=1, LM_OUTCOME_APPLIED=2,
       LM_OUTCOME_REJECTED=3, LM_OUTCOME_EXPIRED=4,
       LM_OUTCOME_CANCELLED_NOT_SENT=5, LM_OUTCOME_INDETERMINATE=6,
       LM_OUTCOME_SUPERSEDED=7, LM_OUTCOME_PARTIAL=8, LM_OUTCOME_SUBMITTED=9 };
enum { LM_JOIN_NEW=0, LM_JOIN_RESUME=1, LM_JOIN_TRANSFER_CANDIDATE=2 };
enum { LM_LEAVE_DRAIN=0, LM_LEAVE_IMMEDIATE=1 };
enum { LM_CHANNEL_AUTO=0, LM_CHANNEL_FREEZE=1, LM_CHANNEL_RECALCULATE=2 };
enum { LM_EVENT_STARTED=1, LM_EVENT_MESSAGE=2, LM_EVENT_OPERATION=3,
       LM_EVENT_MEMBERSHIP=4, LM_EVENT_CONNECTIVITY=5,
       LM_EVENT_CHANNEL=6, LM_EVENT_GAP=7, LM_EVENT_FAULT=8,
       LM_EVENT_POWER=9, LM_EVENT_GROUP_PROGRESS=10 };

typedef struct {
 uint32_t struct_size, abi_version;
 uint32_t role, object_transfer_enabled;
 uint32_t application_event_slots, reserved;
} lm_config_t;
typedef struct { size_t bytes, alignment; } lm_workspace_size_t;
typedef struct {
 uint32_t kind, group_id;
 lm_device_id_t node;
 uint64_t group_revision;
} lm_destination_t;
typedef struct {
 uint32_t struct_size, abi_version;
 lm_destination_t destination;
 uint16_t app_port;
 uint8_t delivery, storage, priority, queue_mode, strict_single_frame, reserved;
 uint64_t coalesce_key;
 uint32_t root_term, reserved2;
 uint64_t expires_root_ms; /* zero only for allowed non-command records */
} lm_send_request_t;
typedef struct {
 uint32_t struct_size, abi_version;
 lm_operation_id_t operation_id;
 lm_message_id_t message_id;
 uint32_t phase, outcome, reason, evidence_bits;
 uint8_t intent_hash[32];
 uint64_t accepted_mono_ms, last_evidence_mono_ms;
} lm_operation_t;
typedef struct {
 uint32_t struct_size, abi_version;
 uint32_t kind, reason;
 uint64_t event_sequence, observed_mono_ms;
 lm_operation_id_t operation_id;
 lm_device_id_t peer;
 lm_message_id_t message_id;
 uint64_t origin_assignment_generation;
 uint8_t intent_hash[32];
 uint16_t app_port, reserved;
 uint32_t payload_bytes;
} lm_event_t;
typedef struct {
 uint32_t struct_size, abi_version;
 lm_device_id_t device;
 lm_domain_id_t domain;
 uint64_t assignment_generation, membership_generation;
 uint32_t state, reason;
 uint64_t state_since_mono_ms;
} lm_membership_t;
typedef struct {
 uint32_t struct_size, abi_version;
 uint32_t state, reason;
 uint64_t state_since_mono_ms, last_authenticated_rx_mono_ms;
 uint64_t last_root_roundtrip_mono_ms;
 uint32_t validity_bits, root_depth;
} lm_connectivity_t;
typedef struct {
 uint32_t struct_size, abi_version;
 lm_request_id_t request_id;
 lm_domain_id_t target_domain;
 uint32_t mode, search_budget_ms, constrain_target, reserved;
} lm_join_request_t;
typedef struct {
 uint32_t struct_size, abi_version;
 uint64_t revision;
 uint32_t join_mode; /* 0 closed, 1 external, 2 preapproved */
 uint32_t auto_transfer_on_isolation, isolation_before_transfer_ms;
 uint32_t relay_allowed, channel_automatic, channel_freeze;
 uint32_t reserved[2];
} lm_policy_t;
typedef struct {
 uint32_t struct_size, abi_version;
 uint64_t build_bits, implemented_bits, qualified_bits, enabled_bits;
 uint32_t max_root_depth, max_path_hops, max_message_bytes, max_object_bytes;
 uint32_t max_members, max_regular_peers, available_single_frame_bytes, reserved;
} lm_capabilities_t;
typedef struct {
 uint32_t struct_size, abi_version;
 uint64_t validity_bits;
 uint32_t root_term, channel_epoch, current_channel, pending_channel;
 uint32_t regular_peers, transient_peers, tx_depth, rx_depth;
 uint64_t tx_frames, rx_frames, link_retries, rf_failures, local_busy;
 uint64_t owner_cpu_us, interval_us, last_reset_reason;
 uint32_t min_heap_bytes, stack_free_bytes;
 int16_t parent_rssi_dbm;
 uint16_t reserved;
} lm_diagnostics_t;
typedef struct {
 uint64_t id, state_generation, expires_mono_ms;
} lm_sleep_ticket_t;

lm_status_t lm_config_init(lm_config_t *out, size_t out_size);
lm_status_t lm_workspace_required(const lm_config_t*, lm_workspace_size_t*);
lm_status_t lm_init(void *workspace, size_t bytes, const lm_config_t*, lm_context_t**);
lm_status_t lm_start(lm_context_t*);
lm_status_t lm_stop(lm_context_t*, uint32_t drain_ms, lm_operation_id_t*);
lm_status_t lm_destroy(lm_context_t*); /* requires stopped and no borrowed state */
lm_status_t lm_send(lm_context_t*, const lm_send_request_t*, const uint8_t*, size_t,
                    lm_operation_id_t*);
lm_status_t lm_send_object(lm_context_t*, const lm_send_request_t*, const uint8_t*,
                           size_t, lm_operation_id_t*);
lm_status_t lm_get_operation(lm_context_t*, lm_operation_id_t, lm_operation_t*);
lm_status_t lm_get_message(lm_context_t*, const lm_message_ref_t*, lm_operation_t*);
lm_status_t lm_get_request(lm_context_t*, const lm_request_id_t*, lm_operation_t*);
lm_status_t lm_payload_capacity(lm_context_t*, const lm_destination_t*,
 uint32_t *single_frame_bytes, uint32_t *path_hops);
lm_status_t lm_cancel(lm_context_t*, lm_operation_id_t);
lm_status_t lm_next_event(lm_context_t*, lm_event_t*, uint8_t*, size_t, size_t*);
lm_status_t lm_report_application_result(lm_context_t*, const lm_message_ref_t*,
 uint32_t outcome, const uint8_t*, size_t,
 lm_operation_id_t*);
lm_status_t lm_membership_get(lm_context_t*, lm_membership_t*);
lm_status_t lm_connectivity_get(lm_context_t*, lm_connectivity_t*);
lm_status_t lm_join(lm_context_t*, const lm_join_request_t*, lm_operation_id_t*);
lm_status_t lm_leave(lm_context_t*, uint32_t mode, uint32_t deadline_ms,
                     lm_operation_id_t*);
lm_status_t lm_install_control(lm_context_t*, uint32_t control_type,
 const uint8_t *signed_cbor, size_t, lm_operation_id_t*);
/* The device's outstanding transfer_nonce16 (docs/07 §8): a mode-0 AssignmentTicket must name it. Made on the first
   call and kept (RAM only) until a join made ACTIVE with it; a restart voids it (a ticket for it is refused). */
lm_status_t lm_transfer_nonce_get(lm_context_t*, uint8_t nonce[16]);
lm_status_t lm_group_set(lm_context_t*, uint32_t group_id, uint64_t expected_revision,
 const lm_device_id_t *members, size_t count, lm_operation_id_t*);
lm_status_t lm_policy_get(lm_context_t*, lm_policy_t*);
lm_status_t lm_policy_set(lm_context_t*, const lm_policy_t*, uint64_t expected_revision,
                          lm_operation_id_t*);
lm_status_t lm_channel_request(lm_context_t*, uint32_t action,
                               uint64_t expected_revision, lm_operation_id_t*);
lm_status_t lm_get_capabilities(lm_context_t*, lm_capabilities_t*);
lm_status_t lm_diagnostics_get(lm_context_t*, lm_diagnostics_t*);
lm_status_t lm_sleep_prepare(lm_context_t*, uint32_t awake_budget_ms,
                             lm_operation_id_t*);
lm_status_t lm_sleep_ticket_get(lm_context_t*, lm_operation_id_t, lm_sleep_ticket_t*);
lm_status_t lm_sleep_enter(lm_context_t*, const lm_sleep_ticket_t*);

/* Spec0.2 additions. No alternate security suite or routing algorithm. */
enum { LM_POWER_ALWAYS_RX=0, LM_POWER_WINDOWED_RX=1, LM_POWER_REPORT_ONLY=2 };
enum { LM_SLEEP_LIGHT=0, LM_SLEEP_DEEP=1 };
enum { LM_WAKE_TIMER=1u, LM_WAKE_EXTERNAL=2u };
enum { LM_PENDING_REQUIRE_SETTLED=0, LM_PENDING_SAVE_AND_SLEEP=1 };
enum { LM_POWER_RUNNING=0, LM_POWER_QUIESCING=1, LM_POWER_SLEEP_READY=2,
       LM_POWER_SLEEPING=3, LM_POWER_WAKING=4, LM_POWER_BUDGET_BLOCKED=5,
       LM_POWER_FAULT=6 };
enum { LM_TARGET_WAIT_ROUTE=0, LM_TARGET_WAIT_AUTH=1, LM_TARGET_WAIT_WAKE=2,
       LM_TARGET_READY=3, LM_TARGET_SENDING=4, LM_TARGET_WAIT_RECEIPT=5,
       LM_TARGET_FINAL=6 };
#define LM_FEATURE_SMALL_MESSAGE (UINT64_C(1) << 0u)
#define LM_FEATURE_OBJECT_4K (UINT64_C(1) << 1u)
#define LM_FEATURE_GROUP_FANOUT_V2 (UINT64_C(1) << 2u)
#define LM_FEATURE_POWER_REPORT_ONLY (UINT64_C(1) << 3u)
#define LM_FEATURE_POWER_WINDOWED_RX (UINT64_C(1) << 4u)
#define LM_FEATURE_RAM_SESSION_RETAIN (UINT64_C(1) << 5u)
#define LM_FEATURE_AUTO_CHANNEL (UINT64_C(1) << 6u)
#define LM_FEATURE_SIGNED_TRANSFER (UINT64_C(1) << 7u)
#define LM_FEATURE_COMMISSIONING_WINDOW (UINT64_C(1) << 8u)
#define LM_FEATURE_ROOT_HANDOVER (UINT64_C(1) << 9u)
#define LM_FEATURE_RTC_SECURE_RESUME_RESERVED (UINT64_C(1) << 10u)

typedef struct {
 uint32_t struct_size, abi_version;
 uint64_t revision;
 uint32_t mode, wake_interval_ms, rx_window_ms, max_rx_window_ms;
 uint32_t awake_budget_ms, shutdown_reserve_ms, search_budget_ms, guard_ms;
 uint32_t retry_min_ms, retry_max_ms, offline_radio_ms_per_hour;
 uint32_t extra_event_wakes_per_day, extra_event_radio_ms_per_day;
 uint32_t shutdown_overrun_limit_ms, pending_policy;
 uint32_t mailbox_frames_per_child, mailbox_frames_total, reserved[2];
} lm_power_policy_t;
typedef struct {
 uint32_t struct_size, abi_version;
 uint32_t sleep_kind, wake_source_mask, awake_budget_ms, pending_policy;
 uint64_t requested_sleep_ms;
 uint32_t reserved[2];
} lm_sleep_request_t;
typedef struct {
 uint32_t struct_size, abi_version;
 uint64_t validity_bits, policy_revision;
 uint32_t mode, state, wake_reason, last_reason;
 uint64_t radio_on_us, cpu_active_us, episode_count, handshake_count;
 uint64_t flash_commits, polls, missed_windows, overruns;
 uint32_t remaining_awake_ms, offline_budget_remaining_ms;
 uint32_t next_wake_quality, reserved;
 uint64_t next_wake_earliest_root_ms, next_wake_latest_root_ms;
} lm_power_snapshot_t;
typedef struct {
 uint32_t struct_size, abi_version;
 uint8_t snapshot_token[16], snapshot_hash[32];
 uint32_t total, pending, submitted, received, applied, rejected;
 uint32_t expired, cancelled, indeterminate, superseded;
 uint64_t progress_revision;
} lm_group_progress_t;
typedef struct {
 lm_device_id_t device;
 uint64_t assignment_generation, membership_generation;
 lm_message_id_t message_id;
 uint32_t phase, outcome, reason, evidence_bits;
} lm_group_target_t;

lm_status_t lm_power_policy_get(lm_context_t*, lm_power_policy_t*);
lm_status_t lm_power_policy_set(lm_context_t*, const lm_power_policy_t*,
 uint64_t expected_revision, lm_operation_id_t*);
lm_status_t lm_power_get(lm_context_t*, lm_power_snapshot_t*);
lm_status_t lm_sleep_prepare_ex(lm_context_t*, const lm_sleep_request_t*,
 lm_operation_id_t*);
lm_status_t lm_sleep_abort(lm_context_t*, lm_operation_id_t);
lm_status_t lm_group_progress(lm_context_t*, lm_operation_id_t, lm_group_progress_t*);
lm_status_t lm_group_targets(lm_context_t*, lm_operation_id_t,
 const uint8_t snapshot_token[16], uint32_t offset, lm_group_target_t *out,
 size_t capacity, size_t *written, uint32_t *total);

#ifdef __cplusplus
}
#endif
#endif
