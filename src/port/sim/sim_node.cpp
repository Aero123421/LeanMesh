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
    LM_TRY(capi::init_context(at, ws.bytes, &cfg, Ports{clock, radio, jobs}, owner_call, opts_.rf, &ctx_));
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
    const MonoTime local_now = clock.now();
    const MonoTime next = ctx_->engine.step(local_now);
    if (!next.is_never()) {
        const int64_t delta = (next - local_now).us;
        request_wake(world_.now_us() + static_cast<uint64_t>(delta > 0 ? delta : 0));
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
