#include "port/idf/idf_jobs.hpp"

#include "esp_random.h"

namespace lm::idf {

static_assert(IdfJobs::k_queue <= 4, "completion ring capacity");

Status IdfJobs::start() {
    if (task_ != nullptr) {
        return Status::Busy;
    }
    exited_ = false;
    queue_ = xQueueCreateStatic(k_queue, sizeof(Job), queue_items_, &queue_storage_);
    task_ = xTaskCreateStatic(task_entry, "lm_worker", sizeof(stack_) / sizeof(StackType_t), this,
                              k_priority, stack_, &tcb_);
    return task_ != nullptr ? Status::Ok : Status::NoCapacity;
}

void IdfJobs::stop() {
    if (task_ == nullptr) {
        return;
    }
    const Job quit{0, 0, nullptr, nullptr};
    while (xQueueSend(queue_, &quit, pdMS_TO_TICKS(10)) != pdTRUE) {
    }
    while (!exited_) {
        vTaskDelay(1);
    }
    vQueueDelete(queue_);
    queue_ = nullptr;
    task_ = nullptr;
}

Status IdfJobs::submit(uint16_t table_index, uint32_t job_id, port::JobFn fn, void *arg) {
    if (fn == nullptr) {
        return Status::InvalidArgument;
    }
    if (outstanding_.load() >= k_queue) {
        return Status::Busy;
    }
    const Job j{table_index, job_id, fn, arg};
    if (xQueueSend(queue_, &j, 0) != pdTRUE) {
        return Status::Busy;
    }
    outstanding_.fetch_add(1);
    return Status::Ok;
}

bool IdfJobs::poll(port::JobCompletion &out) {
    if (!done_.pop(out)) {
        return false;
    }
    outstanding_.fetch_sub(1);
    return true;
}

void IdfJobs::random(MutByteView out) { esp_fill_random(out.data(), out.size()); }

void IdfJobs::task_entry(void *self) {
    static_cast<IdfJobs *>(self)->run();
    vTaskDelete(nullptr);
}

void IdfJobs::run() {
    for (;;) {
        Job j{};
        if (xQueueReceive(queue_, &j, portMAX_DELAY) != pdTRUE) {
            continue;
        }
        if (j.fn == nullptr) {
            break;
        }
        port::JobEnv env{store_};
        const Status st = j.fn(env, j.arg);
        (void)done_.push(port::JobCompletion{j.table_index, j.job_id, st}); // room reserved
        owner_.notify();
    }
    exited_ = true;
}

} // namespace lm::idf
