// Bounded FIFOs. Every queue has a fixed capacity, an owner and an explicit full behaviour
// (AGENTS.md): push() returns false when full and the caller decides (reject with BUSY/NO_CAPACITY,
// count a gap, or use a reserved slot). Nothing grows.
#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <utility>

namespace lm {

// Single-thread FIFO (owner-internal queues).
template <class T, std::size_t N> class BoundedQueue {
    static_assert(N > 0, "capacity");

  public:
    [[nodiscard]] bool push(const T &v) {
        if (count_ == N) {
            return false;
        }
        items_[(head_ + count_) % N] = v;
        ++count_;
        return true;
    }
    [[nodiscard]] bool pop(T &out) {
        if (count_ == 0) {
            return false;
        }
        out = std::move(items_[head_]);
        head_ = (head_ + 1) % N;
        --count_;
        return true;
    }
    [[nodiscard]] const T *front() const { return count_ == 0 ? nullptr : &items_[head_]; }
    [[nodiscard]] std::size_t size() const { return count_; }
    [[nodiscard]] bool empty() const { return count_ == 0; }
    [[nodiscard]] bool full() const { return count_ == N; }
    static constexpr std::size_t capacity() { return N; }
    void clear() {
        head_ = 0;
        count_ = 0;
    }

  private:
    std::array<T, N> items_{};
    std::size_t head_ = 0;
    std::size_t count_ = 0;
};

// Lock-free single-producer/single-consumer ring for driver callback -> owner hand-off.
// The producer side is safe to call from a driver callback: fixed-size copy, no allocation, no
// logging, no crypto (docs/15 §2). N must be a power of two.
template <class T, std::size_t N> class SpscRing {
    static_assert(N >= 2 && (N & (N - 1)) == 0, "capacity must be a power of two");

  public:
    // Producer only.
    [[nodiscard]] bool push(const T &v) {
        const uint32_t head = head_.load(std::memory_order_relaxed);
        const uint32_t tail = tail_.load(std::memory_order_acquire);
        if (head - tail == N) {
            dropped_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        items_[head & (N - 1)] = v;
        head_.store(head + 1, std::memory_order_release);
        return true;
    }
    // Consumer only.
    [[nodiscard]] bool pop(T &out) {
        const uint32_t tail = tail_.load(std::memory_order_relaxed);
        const uint32_t head = head_.load(std::memory_order_acquire);
        if (head == tail) {
            return false;
        }
        out = items_[tail & (N - 1)];
        tail_.store(tail + 1, std::memory_order_release);
        return true;
    }
    // Items the producer could not enqueue (reported in diagnostics, never silently lost).
    [[nodiscard]] uint32_t dropped() const { return dropped_.load(std::memory_order_relaxed); }
    static constexpr std::size_t capacity() { return N; }

  private:
    std::array<T, N> items_{};
    std::atomic<uint32_t> head_{0};
    std::atomic<uint32_t> tail_{0};
    std::atomic<uint32_t> dropped_{0};
};

} // namespace lm
