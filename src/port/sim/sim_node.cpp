#include "port/sim/sim_node.hpp"

#include <new>

#include "port/sim/sim_world.hpp"

namespace lm::sim {

SimNode::SimNode(World &world, uint16_t index, const MacAddr &mac, const NodeOptions &opts)
    : clock(world, opts.clock_drift_ppm), radio(world, index, mac),
      jobs(world, index, world.options().seed * 0x9E3779B97F4A7C15ULL + index), store(opts.store),
      owner_call(*this), world_(world), index_(index), opts_(opts) {}

SimNode::~SimNode() { power_cut(); }

Status SimNode::boot() {
    if (ctx_ != nullptr) {
        return Status::Ok;
    }
    lm_config_t cfg;
    LM_TRY(static_cast<Status>(lm_config_init(&cfg, sizeof(cfg))));
    cfg.role = static_cast<uint32_t>(opts_.role);
    cfg.object_transfer_enabled = opts_.object_transfer_enabled ? 1 : 0;
    lm_workspace_size_t ws{};
    LM_TRY(static_cast<Status>(lm_workspace_required(&cfg, &ws)));
    if (workspace_ == nullptr) {
        workspace_bytes_ = ws.bytes + ws.alignment;
        workspace_ = std::make_unique<uint8_t[]>(workspace_bytes_);
    }
    // Align inside the buffer (operator new[] only guarantees the default new alignment).
    auto base = reinterpret_cast<std::uintptr_t>(workspace_.get());
    const std::uintptr_t aligned = (base + ws.alignment - 1) / ws.alignment * ws.alignment;
    void *at = workspace_.get() + (aligned - base);
    clock.on_boot(world_.now_us());
    jobs.set_epoch(epoch_);
    LM_TRY(capi::init_context(at, ws.bytes, &cfg, Ports{clock, radio, jobs, opts_.power_port ? &pm : nullptr}, owner_call, opts_.rf, &ctx_));
    ctx_->engine.mesh().set_enabled(opts_.mesh);
    ctx_->engine.chan().set_enabled(opts_.channel);
    notify();
    return Status::Ok;
}

void SimNode::power_cut() {
    if (ctx_ == nullptr) {
        return;
    }
    ctx_->~lm_context(); // RAM is gone; nothing is persisted on the way down
    ctx_ = nullptr;
    radio.power_cut();
    jobs.power_cut();
    scheduled_wake_us_ = UINT64_MAX;
    ++epoch_; // pending TX-done and job events of the old epoch are discarded
}

void SimNode::on_wake_event(uint64_t at_us) {
    if (at_us != scheduled_wake_us_ || ctx_ == nullptr) {
        return; // superseded by an earlier wake, or powered off
    }
    scheduled_wake_us_ = UINT64_MAX;
    if (pm.deep_requested()) {
        go_deep(); // the sleep call returned Pending: now the RAM goes
        return;
    }
    const MonoTime local_now = clock.now();
    const MonoTime next = ctx_->engine.step(local_now);
    if (!next.is_never()) {
        const int64_t delta = (next - local_now).us;
        request_wake(world_.now_us() + static_cast<uint64_t>(delta > 0 ? delta : 0));
    }
}

// A deep sleep: the node loses its RAM and the radio, keeps its Store and the RTC memory of the Pm, and starts again
// at the wake time (or never, for an external-only wake) as a firmware reset would.
void SimNode::go_deep() {
    deep_slept_at_us_ = world_.now_us();
    deep_sources_ = pm.deep_sources();
    const uint64_t ms = pm.deep_wake_after_ms();
    pm.deep_taken();
    power_cut();
    store.power_restore();
    deep_boot_at_us_ = ms != 0 ? deep_slept_at_us_ + ms * 1000U : UINT64_MAX - 1U;
    if (ms != 0) {
        world_.schedule_boot(index_, deep_boot_at_us_);
    }
}

void SimNode::on_boot_event(uint64_t at_us) {
    if (at_us != deep_boot_at_us_ || ctx_ != nullptr) {
        return; // superseded (an external wake got there first) or already running
    }
    const uint8_t source = (deep_sources_ & LM_WAKE_TIMER) != 0 && at_us != UINT64_MAX - 1U ? LM_WAKE_TIMER : LM_WAKE_EXTERNAL;
    pm.prepare_deep_boot(source, (world_.now_us() - deep_slept_at_us_) / 1000U);
    deep_boot_at_us_ = UINT64_MAX;
    if (boot() == Status::Ok) {
        (void)lm_start(ctx_); // app main after a reset
    }
}

void SimNode::wake_external() {
    if (deep_sleeping()) {
        deep_boot_at_us_ = world_.now_us();
        deep_sources_ = LM_WAKE_EXTERNAL;
        on_boot_event(deep_boot_at_us_);
        return;
    }
    if (ctx_ != nullptr) {
        port::WakeInfo w;
        w.cause = port::ResetCause::LightWake;
        w.source = LM_WAKE_EXTERNAL;
        w.ram_complete = pm.ram_complete;
        w.elapsed_known = pm.elapsed_known;
        w.elapsed_upper_ms = ctx_->engine.power().slept_ms(clock.now()) + 1U;
        ctx_->engine.power_wake(w, clock.now());
        notify();
    }
}

void SimNode::notify() { request_wake(world_.now_us()); }

void SimNode::request_wake(uint64_t world_at_us) {
    if (ctx_ == nullptr || world_at_us >= scheduled_wake_us_) {
        return;
    }
    scheduled_wake_us_ = world_at_us;
    world_.schedule_wake(index_, world_at_us);
}

} // namespace lm::sim
