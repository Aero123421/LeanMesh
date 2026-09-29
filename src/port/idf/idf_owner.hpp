// ESP-IDF mesh owner task and the OwnerCall queue (docs/02 §2, §5).
//
// One task runs Engine::step() and every command. It sleeps until the earliest deadline the engine
// reports, or until a notification (radio callback, job completion, command). There is no fixed
// tick: an idle owner is blocked indefinitely. Application tasks reach the owner through a bounded
// queue of stack-resident call records (Busy when full). Each call waits on its own stack-resident
// binary semaphore, so no FreeRTOS notification index is consumed (the notification array size is
// a build option) and a stray application notification cannot end the wait while the owner still
// holds a pointer to the caller's stack (FIX1-D3).
#pragma once

#include "capi/context.hpp"
#include "core/command.hpp"
#include "core/ports.hpp"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

namespace lm::idf {

class IdfOwner final : public OwnerCall {
  public:
    static constexpr std::size_t k_stack_bytes = 4096; // AES-GCM per frame runs here (S2 measures)
    static constexpr UBaseType_t k_priority = 5;       // below the Wi-Fi task, above the app
    static constexpr std::size_t k_call_queue = 4;

    // Creates the queue and the task; `ctx` must stay valid until stop().
    [[nodiscard]] Status start(lm_context_t *ctx, const port::Clock &clock);
    // Ends the task (lm_destroy). Precondition: the engine is stopped.
    void stop();
    [[nodiscard]] Reply call(const Command &cmd) override;
    // Any task or driver callback (task context, not ISR): wake the owner.
    void notify();

  private:
    struct Call {
        const Command *cmd;
        Reply reply;
        SemaphoreHandle_t done;
    };
    static void task_entry(void *self);
    void run();

    lm_context_t *ctx_ = nullptr;
    const port::Clock *clock_ = nullptr;
    TaskHandle_t task_ = nullptr;
    QueueHandle_t queue_ = nullptr;
    volatile bool quit_ = false;
    volatile bool exited_ = false;
    StaticTask_t tcb_{};
    StackType_t stack_[k_stack_bytes / sizeof(StackType_t)]{};
    StaticQueue_t queue_storage_{};
    uint8_t queue_items_[k_call_queue * sizeof(Call *)]{};
};

} // namespace lm::idf
