// ESP-IDF slow-job worker (docs/02 §2): one task, one bounded job queue, one bounded completion
// ring. Job bodies (P-256, sign/verify, Store I/O) run here and never on the owner. The owner
// polls completions; the worker wakes it with a notification.
#pragma once

#include <atomic>

#include "core/engine.hpp"
#include "core/ports.hpp"
#include "core/ring.hpp"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "port/idf/idf_owner.hpp"

namespace lm::idf {

class IdfJobs final : public port::Jobs {
  public:
    static constexpr std::size_t k_queue = k_job_table_entries; // == owner job table size
    // Worker stack = measured depth of the deepest job body x 2 (port::k_worker_stack_bytes, sized per
    // optimisation level). Natively (x86-64, painted stack, thread-entry depth calibrated away,
    // tests/native/stack_probe.hpp): one EDHOC step 4344 B at -O2 / 5600 B at -O0 (test_link "EDHOC
    // worker stack", after SEC-D15 moved the ECDH output into the handshake slot and signs/verifies a
    // precomputed digest), the credential-chain job 3992 B (test_credentials). NOT yet measured on a target: read
    // uxTaskGetStackHighWaterMark on hardware before lowering it.
#if defined(__OPTIMIZE__)
    static constexpr std::size_t k_stack_bytes = 10240;
    static constexpr std::size_t k_measured_job_depth_bytes = 4488; // -Og, the deepest optimised level
#else
    static constexpr std::size_t k_stack_bytes = 12288;
    static constexpr std::size_t k_measured_job_depth_bytes = 5600;
#endif
    static_assert(k_stack_bytes == port::k_worker_stack_bytes, "one worker stack size per optimisation level");
    static_assert(k_stack_bytes >= 2 * k_measured_job_depth_bytes,
                  "worker stack: at least twice the measured deepest job body");
    static constexpr UBaseType_t k_priority = 3;

    IdfJobs(port::Store &store, IdfOwner &owner) : store_(store), owner_(owner) {}

    [[nodiscard]] Status start();
    void stop(); // lm_destroy: finishes the running job, then ends the task

    [[nodiscard]] Status submit(uint16_t table_index, uint32_t job_id, port::JobFn fn,
                                void *arg) override;
    [[nodiscard]] bool poll(port::JobCompletion &out) override;
    void random(MutByteView out) override; // hardware RNG; no seeding path exists
    [[nodiscard]] TaskHandle_t task() const { return task_; } // [S19] stack high-water mark

  private:
    struct Job {
        uint16_t table_index;
        uint32_t job_id;
        port::JobFn fn;
        void *arg;
    };
    static void task_entry(void *self);
    void run();

    port::Store &store_;
    IdfOwner &owner_;
    TaskHandle_t task_ = nullptr;
    QueueHandle_t queue_ = nullptr;
    // Jobs submitted and not yet polled. Capped at k_queue, which also guarantees room in done_.
    std::atomic<uint32_t> outstanding_{0};
    volatile bool exited_ = false;
    SpscRing<port::JobCompletion, 4> done_;
    StaticTask_t tcb_{};
    StackType_t stack_[k_stack_bytes / sizeof(StackType_t)]{};
    StaticQueue_t queue_storage_{};
    uint8_t queue_items_[k_queue * sizeof(Job)]{};
};

} // namespace lm::idf
