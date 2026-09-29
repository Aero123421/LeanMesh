#include "port/idf/idf_owner.hpp"

namespace lm::idf {

Status IdfOwner::start(lm_context_t *ctx, const port::Clock &clock) {
    if (task_ != nullptr) {
        return Status::Busy;
    }
    ctx_ = ctx;
    clock_ = &clock;
    quit_ = false;
    exited_ = false;
    queue_ = xQueueCreateStatic(k_call_queue, sizeof(Call *), queue_items_, &queue_storage_);
    task_ = xTaskCreateStatic(task_entry, "lm_owner", sizeof(stack_) / sizeof(StackType_t), this,
                              k_priority, stack_, &tcb_);
    return task_ != nullptr ? Status::Ok : Status::NoCapacity;
}

void IdfOwner::stop() {
    if (task_ == nullptr) {
        return;
    }
    quit_ = true;
    notify();
    while (!exited_) {
        vTaskDelay(1); // lm_destroy is a blocking app call; the owner exits within one pass
    }
    // Calls queued after the owner's last pass would leave their callers blocked forever.
    Call *late = nullptr;
    while (xQueueReceive(queue_, &late, 0) == pdTRUE) {
        late->reply = Reply{Status::InvalidArgument, 0, 0};
        xSemaphoreGive(late->done);
    }
    vQueueDelete(queue_);
    queue_ = nullptr;
    task_ = nullptr;
}

void IdfOwner::notify() {
    if (task_ != nullptr) {
        xTaskNotifyGive(task_);
    }
}

Reply IdfOwner::call(const Command &cmd) {
    if (task_ == nullptr || quit_) {
        return Reply{Status::InvalidArgument, 0, 0};
    }
    if (xTaskGetCurrentTaskHandle() == task_) {
        return ctx_->engine.execute(cmd, clock_->now()); // no self-deadlock from owner context
    }
    StaticSemaphore_t sem_storage;
    Call c{&cmd, Reply{}, xSemaphoreCreateBinaryStatic(&sem_storage)};
    if (c.done == nullptr) {
        return Reply{Status::NoCapacity, 0, 0};
    }
    Call *p = &c;
    if (xQueueSend(queue_, &p, 0) != pdTRUE) {
        vSemaphoreDelete(c.done);
        return Reply{Status::Busy, 0, 0}; // bounded intake: the command does not exist
    }
    notify();
    // The owner never blocks (docs/02 §2), so the reply always comes. `c` lives on this stack and
    // only this semaphore, given exactly once per call, releases it.
    while (xSemaphoreTake(c.done, portMAX_DELAY) != pdTRUE) {
    }
    vSemaphoreDelete(c.done);
    return c.reply;
}

void IdfOwner::task_entry(void *self) {
    static_cast<IdfOwner *>(self)->run();
    vTaskDelete(nullptr);
}

void IdfOwner::run() {
    Engine &engine = ctx_->engine;
    while (!quit_) {
        Call *c = nullptr;
        while (xQueueReceive(queue_, &c, 0) == pdTRUE) {
            c->reply = engine.execute(*c->cmd, clock_->now());
            xSemaphoreGive(c->done);
        }
        const MonoTime now = clock_->now();
        const MonoTime next = engine.step(now);
        if (quit_) {
            break;
        }
        TickType_t wait = portMAX_DELAY; // idle: sleep until an external event
        if (!next.is_never()) {
            const int64_t us = (next - now).us;
            const uint32_t ms = us <= 0 ? 0 : static_cast<uint32_t>((us + 999) / 1000);
            wait = ms == 0 ? 0 : (ms + portTICK_PERIOD_MS - 1) / portTICK_PERIOD_MS;
        }
        (void)ulTaskNotifyTake(pdTRUE, wait);
    }
    exited_ = true;
}

} // namespace lm::idf
