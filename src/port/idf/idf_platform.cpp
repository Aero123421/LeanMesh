// lm_init / lm_destroy for ESP-IDF: builds the context in the caller's workspace and starts the
// owner and worker tasks. One context per device: the radio driver, the Wi-Fi stack and the flash
// partitions are singletons. Everything the tasks need is static (no heap use by the port after
// this point; task stacks and queues are static objects).
#include <new>

#include "capi/context.hpp"
#include "port/idf/idf_clock.hpp"
#include "port/idf/idf_health.hpp"
#include "port/idf/idf_jobs.hpp"
#include "port/idf/idf_owner.hpp"
#include "port/idf/idf_pm.hpp"
#include "port/idf/idf_radio.hpp"
#include "port/idf/idf_store.hpp"
#include "sdkconfig.h"
#ifdef LM_BUILD_PROFILE_ROOT
#include "serial/idf_serial.hpp"
#endif

namespace lm::idf {

namespace {

struct Platform {
    IdfClock clock;
    IdfOwner owner;
    IdfStore store;
    IdfRadio radio{owner};
    IdfJobs jobs{store, owner};
    IdfPm pm; // [S16]
    IdfHealth health{owner, jobs, radio}; // [S19]
};

Platform g_platform;
lm_context_t *g_ctx = nullptr;

// The deployment's RF profile comes from Kconfig; it is unapproved unless the product build says
// otherwise, and then lm_start returns RF_PROFILE_UNAPPROVED (docs/03 §3).
port::RfProfile rf_profile_from_config() {
    port::RfProfile p;
#ifdef CONFIG_LEANMESH_RF_DEPLOYMENT_APPROVED
    p.deployment_approved = true;
#endif
    p.channel = CONFIG_LEANMESH_RF_CHANNEL;
    p.allowed_channels_mask = CONFIG_LEANMESH_RF_ALLOWED_CHANNELS_MASK;
    p.tx_power_qdbm = CONFIG_LEANMESH_RF_TX_POWER_QDBM;
    p.country[0] = CONFIG_LEANMESH_RF_COUNTRY[0];
    p.country[1] = CONFIG_LEANMESH_RF_COUNTRY[1];
    return p;
}

} // namespace

} // namespace lm::idf

extern "C" {

lm_status_t lm_init(void *workspace, size_t bytes, const lm_config_t *config,
                    lm_context_t **out) {
    using namespace lm;
    using namespace lm::idf;
    if (out == nullptr) {
        return to_abi(Status::InvalidArgument);
    }
    if (g_ctx != nullptr) {
        return to_abi(Status::Busy); // one context per device
    }
    Status s = g_platform.store.init();
    if (s != Status::Ok) {
        return to_abi(s); // fail closed: read errors are never "unprovisioned"
    }
    s = capi::init_context(workspace, bytes, config,
                           Ports{g_platform.clock, g_platform.radio, g_platform.jobs, &g_platform.pm, &g_platform.health},
                           g_platform.owner, rf_profile_from_config(), &g_ctx);
    if (s != Status::Ok) {
        g_ctx = nullptr;
        return to_abi(s);
    }
#ifdef LM_BUILD_PROFILE_ROOT
    if (config->role == static_cast<uint32_t>(Role::Root)) {
        // [SLICE:S10] The root's USB serial port. Attached before the owner task exists (the engine
        // hook is not synchronised). Failure leaves the mesh running with the USB link down, which
        // the Host sees as root_connected=false; it is not turned into success anywhere.
        (void)serial::idf_root_serial_start(g_ctx->engine, g_platform.owner);
    }
#endif
    s = g_platform.jobs.start();
    if (s == Status::Ok) {
        s = g_platform.owner.start(g_ctx, g_platform.clock);
        if (s != Status::Ok) {
            g_platform.jobs.stop();
        }
    }
    if (s != Status::Ok) {
#ifdef LM_BUILD_PROFILE_ROOT
        serial::idf_root_serial_stop(); // [SLICE:S10]
#endif
        g_ctx->~lm_context();
        g_ctx = nullptr;
        return to_abi(s);
    }
    *out = g_ctx;
    return to_abi(Status::Ok);
}

lm_status_t lm_destroy(lm_context_t *ctx) {
    using namespace lm;
    using namespace lm::idf;
    if (ctx == nullptr || ctx != g_ctx || ctx->magic != lm_context::k_magic) {
        return to_abi(Status::InvalidArgument);
    }
    Command cmd;
    cmd.kind = CommandKind::Destroy;
    const Status s = g_platform.owner.call(cmd).status;
    if (s != Status::Ok) {
        return to_abi(s); // still running: stop first
    }
    g_platform.owner.stop();
    g_platform.jobs.stop();
#ifdef LM_BUILD_PROFILE_ROOT
    serial::idf_root_serial_stop(); // [SLICE:S10] before the engine it is attached to goes away
#endif
    g_ctx->~lm_context();
    g_ctx = nullptr;
    return to_abi(Status::Ok);
}

} // extern "C"
