// The only thing the mesh owner knows about the root's USB serial adapter (src/serial, decision D5):
// it forwards job completions, the engine start/stop and identity-load events, and asks for the
// adapter's next deadline. The adapter itself is a root-only object owned by the platform layer and
// attached with Engine::attach_serial(); leaf/relay builds never create one.
#pragma once

#include "core/pool.hpp"
#include "core/status.hpp"
#include "core/time.hpp"

namespace lm {

class SerialHook {
  public:
    // Engine::start succeeded / Engine stops (secrets must be wiped, jobs cancelled).
    virtual void on_started(MonoTime now) = 0;
    virtual void on_stop() = 0;
    // The identity load job finished (state Ready, Unprovisioned or Failed).
    virtual void on_identity(MonoTime now) = 0;
    // Completion of a job submitted with JobOwner::Serial; `slot` is the handle passed at submit.
    virtual void on_job_done(Handle slot, Status job_status, MonoTime now) = 0;
    // Every Engine::step(): drain port input, run due timers. Must be cheap when idle.
    virtual void on_step(MonoTime now) = 0;
    [[nodiscard]] virtual MonoTime deadline() const = 0;

  protected:
    ~SerialHook() = default;
};

} // namespace lm
