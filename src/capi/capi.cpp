// C ABI entry points (api/leanmesh.h). Each public call validates its arguments, then runs on the
// mesh owner through OwnerCall. Entry points not defined here are not implemented in this build
// (they fail to link rather than returning fake success); slices add them as they land.
#include <new>

#include "capi/context.hpp"
#include "core/profile.hpp"

namespace lm::capi {

namespace {

bool valid_ctx(const lm_context_t *ctx) {
    return ctx != nullptr && ctx->magic == lm_context::k_magic;
}

Status run(lm_context_t *ctx, CommandKind kind, void *response, std::size_t response_size) {
    Command cmd;
    cmd.kind = kind;
    cmd.response = response;
    cmd.response_size = response_size;
    return ctx->owner.call(cmd).status;
}

} // namespace

Status check_abi(uint32_t struct_size, uint32_t abi_version, std::size_t expected) {
    if (abi_version != LM_ABI_VERSION) {
        return Status::Unsupported;
    }
    return struct_size == expected ? Status::Ok : Status::InvalidArgument;
}

Status validate_config(const lm_config_t *config) {
    if (config == nullptr) {
        return Status::InvalidArgument;
    }
    LM_TRY(check_abi(config->struct_size, config->abi_version, sizeof(lm_config_t)));
    if (config->reserved != 0 || config->object_transfer_enabled > 1 ||
        config->application_event_slots == 0 ||
        config->application_event_slots > k_max_app_events) {
        return Status::InvalidArgument;
    }
    if (config->role > LM_ROLE_ROOT) {
        return Status::InvalidArgument;
    }
    if (config->object_transfer_enabled != 0 && !delivery::k_object_capable) {
        return Status::Unsupported; // the 4 KiB object lane is not part of this build (LM_OBJECT_TRANSFER)
    }
    if (!build_supports(static_cast<Role>(config->role))) {
        return Status::RoleNotAllowed;
    }
    return Status::Ok;
}

Status init_context(void *workspace, std::size_t bytes, const lm_config_t *config, Ports ports,
                    OwnerCall &owner_call, const port::RfProfile &rf, lm_context_t **out) {
    if (workspace == nullptr || out == nullptr) {
        return Status::InvalidArgument;
    }
    LM_TRY(validate_config(config));
    if (bytes < sizeof(lm_context) ||
        reinterpret_cast<std::uintptr_t>(workspace) % alignof(lm_context) != 0) {
        return Status::BufferTooSmall;
    }
    EngineConfig cfg;
    cfg.role = static_cast<Role>(config->role);
    cfg.object_transfer_enabled = config->object_transfer_enabled != 0;
    cfg.application_event_slots = config->application_event_slots;
    cfg.rf = rf;
    *out = new (workspace) lm_context(cfg, ports, owner_call);
    return Status::Ok;
}

} // namespace lm::capi

using lm::Status;
using lm::to_abi;

extern "C" {

lm_status_t lm_config_init(lm_config_t *out, size_t out_size) {
    if (out == nullptr || out_size != sizeof(lm_config_t)) {
        return to_abi(Status::InvalidArgument);
    }
    lm_config_t c{};
    c.struct_size = sizeof(lm_config_t);
    c.abi_version = LM_ABI_VERSION;
    c.role = static_cast<uint32_t>(lm::k_build_max_role);
    c.object_transfer_enabled = 0;
    c.application_event_slots = static_cast<uint32_t>(lm::k_max_app_events);
    c.reserved = 0;
    *out = c;
    return to_abi(Status::Ok);
}

lm_status_t lm_workspace_required(const lm_config_t *config, lm_workspace_size_t *out) {
    if (out == nullptr) {
        return to_abi(Status::InvalidArgument);
    }
    const Status s = lm::capi::validate_config(config);
    if (s != Status::Ok) {
        return to_abi(s);
    }
    out->bytes = sizeof(lm_context);
    out->alignment = alignof(lm_context);
    return to_abi(Status::Ok);
}

// lm_init lives in the platform port (src/port/idf): it owns the tasks the context runs on.

lm_status_t lm_start(lm_context_t *ctx) {
    if (!lm::capi::valid_ctx(ctx)) {
        return to_abi(Status::InvalidArgument);
    }
    return to_abi(lm::capi::run(ctx, lm::CommandKind::Start, nullptr, 0));
}

// Decision: without pending operations stop completes inside the call; *operation is then 0,
// which is not a valid operation id (delivery slices return a real drain operation).
lm_status_t lm_stop(lm_context_t *ctx, uint32_t /*drain_ms*/, lm_operation_id_t *operation) {
    if (!lm::capi::valid_ctx(ctx)) {
        return to_abi(Status::InvalidArgument);
    }
    const Status s = lm::capi::run(ctx, lm::CommandKind::Stop, nullptr, 0);
    if (s == Status::Ok && operation != nullptr) {
        *operation = 0;
    }
    return to_abi(s);
}

// MESSAGE events carry their payload; an OPERATION event carries the application result (<= 32 B).
// BUFFER_TOO_SMALL leaves the event queued and reports the required size (docs/10 §2).
lm_status_t lm_next_event(lm_context_t *ctx, lm_event_t *out, uint8_t *payload, size_t capacity,
                          size_t *required) {
    if (!lm::capi::valid_ctx(ctx) || out == nullptr || (payload == nullptr && capacity != 0)) {
        return to_abi(Status::InvalidArgument);
    }
    const Status a = lm::capi::check_abi(out->struct_size, out->abi_version, sizeof(*out));
    if (a != Status::Ok) {
        return to_abi(a);
    }
    lm_event_t ev{};
    lm::Command cmd;
    cmd.kind = lm::CommandKind::NextEvent;
    cmd.response = &ev;
    cmd.response_size = sizeof(ev);
    cmd.response_payload = lm::MutByteView{payload, capacity};
    const lm::Reply r = ctx->owner.call(cmd);
    if (r.status == Status::Ok) {
        *out = ev;
    }
    if ((r.status == Status::Ok || r.status == Status::BufferTooSmall) && required != nullptr) {
        *required = r.required_bytes;
    }
    return to_abi(r.status);
}

lm_status_t lm_get_capabilities(lm_context_t *ctx, lm_capabilities_t *out) {
    if (!lm::capi::valid_ctx(ctx) || out == nullptr) {
        return to_abi(Status::InvalidArgument);
    }
    const Status s = lm::capi::check_abi(out->struct_size, out->abi_version, sizeof(*out));
    if (s != Status::Ok) {
        return to_abi(s);
    }
    return to_abi(lm::capi::run(ctx, lm::CommandKind::GetCapabilities, out, sizeof(*out)));
}

} // extern "C"
