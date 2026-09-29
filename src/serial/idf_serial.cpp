#include "serial/idf_serial.hpp"

#include <array>
#include <atomic>
#include <new>

#include "driver/usb_serial_jtag.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "port/idf/idf_owner.hpp"
#include "serial/bridge.hpp"
#include "serial/root_usb.hpp"

namespace lm::serial {
namespace {

constexpr std::size_t k_rx_ring_bytes = 2048;   // power of two
constexpr std::size_t k_write_chunk = 64;       // the driver's ring takes whole chunks or nothing
constexpr uint32_t k_driver_tx_bytes = 1024;
constexpr uint32_t k_driver_rx_bytes = 512;
constexpr std::size_t k_task_stack_bytes = 2560;
constexpr UBaseType_t k_task_priority = 4; // below the owner (5)

class IdfStream final : public ByteStream {
  public:
    explicit IdfStream(idf::IdfOwner &owner) : owner_(owner) {}

    Status start() {
        usb_serial_jtag_driver_config_t cfg = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
        cfg.tx_buffer_size = k_driver_tx_bytes;
        cfg.rx_buffer_size = k_driver_rx_bytes;
        if (!installed_ && usb_serial_jtag_driver_install(&cfg) != ESP_OK) {
            return Status::RecoveryRequired;
        }
        installed_ = true;
        quit_ = false;
        task_ = xTaskCreateStatic(&IdfStream::task_entry, "lm_usb", k_task_stack_bytes / sizeof(StackType_t),
                                  this, k_task_priority, stack_, &tcb_);
        return task_ != nullptr ? Status::Ok : Status::NoCapacity;
    }
    void stop() {
        quit_ = true; // the task leaves within one read timeout
        while (!exited_ && task_ != nullptr) {
            vTaskDelay(1);
        }
        task_ = nullptr;
    }

    // Owner side.
    std::size_t write(ByteView out) override {
        std::size_t done = 0;
        while (done < out.size()) {
            const std::size_t n = out.size() - done < k_write_chunk ? out.size() - done : k_write_chunk;
            const int w = usb_serial_jtag_write_bytes(out.data() + done, n, 0); // never blocks the owner
            if (w <= 0) {
                break; // ring full: the link retries shortly (a slow reader, not a loss)
            }
            done += static_cast<std::size_t>(w);
        }
        return done;
    }
    std::size_t read(MutByteView out) override { // owner: consumer of the ring
        const uint32_t head = head_.load(std::memory_order_acquire);
        uint32_t tail = tail_.load(std::memory_order_relaxed);
        std::size_t n = 0;
        while (tail != head && n < out.size()) {
            out[n++] = ring_[tail++ & (k_rx_ring_bytes - 1)];
        }
        tail_.store(tail, std::memory_order_release);
        return n;
    }
    bool input_pending() const override {
        return head_.load(std::memory_order_acquire) != tail_.load(std::memory_order_relaxed);
    }

  private:
    static void task_entry(void *self) {
        static_cast<IdfStream *>(self)->run();
        static_cast<IdfStream *>(self)->exited_ = true;
        vTaskDelete(nullptr);
    }
    void run() {
        exited_ = false;
        uint8_t buf[64];
        while (!quit_) {
            // A blocking wait in the driver (100 ms so stop() is honoured), not a poll.
            const int n = usb_serial_jtag_read_bytes(buf, sizeof buf, pdMS_TO_TICKS(100));
            for (int i = 0; i < n; ++i) {
                push_byte(buf[i]);
            }
            if (n > 0) {
                owner_.notify();
            }
        }
    }

    // Producer: the port task. A full ring makes it wait for the owner (the driver buffers meanwhile).
    void push_byte(uint8_t b) {
        for (;;) {
            const uint32_t head = head_.load(std::memory_order_relaxed);
            if (head - tail_.load(std::memory_order_acquire) < k_rx_ring_bytes) {
                ring_[head & (k_rx_ring_bytes - 1)] = b;
                head_.store(head + 1, std::memory_order_release);
                return;
            }
            owner_.notify();
            vTaskDelay(1);
            if (quit_) {
                return;
            }
        }
    }

    idf::IdfOwner &owner_;
    std::array<uint8_t, k_rx_ring_bytes> ring_{};
    std::atomic<uint32_t> head_{0};
    std::atomic<uint32_t> tail_{0};
    TaskHandle_t task_ = nullptr;
    volatile bool quit_ = false;
    volatile bool exited_ = true;
    bool installed_ = false;
    StaticTask_t tcb_{};
    StackType_t stack_[k_task_stack_bytes / sizeof(StackType_t)]{};
};

// One root, one port: static storage, no heap.
struct RootSerial {
    explicit RootSerial(idf::IdfOwner &owner) : stream(owner) {}
    IdfStream stream;
    alignas(RootUsb) uint8_t usb_storage[sizeof(RootUsb)];
    RootUsb *usb = nullptr;
    alignas(Bridge) uint8_t bridge_storage[sizeof(Bridge)]; // S13: the Host bridge on the same owner
    Bridge *bridge = nullptr;
};
alignas(RootSerial) uint8_t g_storage[sizeof(RootSerial)];
RootSerial *g_root = nullptr;

} // namespace

Status idf_root_serial_start(Engine &engine, idf::IdfOwner &owner) {
    if (g_root != nullptr) {
        return Status::Busy;
    }
    auto *r = new (g_storage) RootSerial(owner);
    Status st = r->stream.start();
    if (st != Status::Ok) {
        r->~RootSerial();
        return st;
    }
    const uint64_t boot = (uint64_t{esp_random()} << 32U) | esp_random(); // HELLO boot id, informative only
    r->usb = new (r->usb_storage) RootUsb(engine, r->stream, boot);
    engine.attach_serial(r->usb);
    r->bridge = new (r->bridge_storage) Bridge(engine, *r->usb, boot);
    g_root = r;
    return Status::Ok;
}

void idf_root_serial_stop() {
    if (g_root == nullptr) {
        return;
    }
    g_root->stream.stop();
    g_root->bridge->~Bridge(); // detaches from the adapter first
    g_root->usb->~RootUsb();
    g_root->~RootSerial();
    g_root = nullptr;
}

} // namespace lm::serial
