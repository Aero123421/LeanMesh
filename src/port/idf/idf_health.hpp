// ESP-IDF Health port (S19): what the platform knows and the SDK cannot - reset cause, the SoC's minimum free
// heap since boot, the least free stack of the SDK's own tasks, the time the owner spent working and the depth
// of the RX callback ring. Read only when the application asks for diagnostics.
//
// Not verified on hardware: values are IDF calls, not a result. `owner_cpu_us` is wall time inside the owner's
// pass and includes preemption by higher-priority tasks (the Wi-Fi task), so it bounds the CPU time from above.
#pragma once

#include "core/diag/health.hpp"
#include "port/idf/idf_jobs.hpp"
#include "port/idf/idf_owner.hpp"
#include "port/idf/idf_radio.hpp"

namespace lm::idf {

class IdfHealth final : public port::Health {
  public:
    IdfHealth(const IdfOwner &owner, const IdfJobs &jobs, const IdfRadio &radio)
        : owner_(owner), jobs_(jobs), radio_(radio) {}
    port::HealthFacts read() override;

  private:
    const IdfOwner &owner_;
    const IdfJobs &jobs_;
    const IdfRadio &radio_;
};

} // namespace lm::idf
