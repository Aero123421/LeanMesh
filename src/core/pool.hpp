// Fixed pools addressed by slot+generation handles (docs/15 §2 "各slotにgeneration").
// Releasing a slot bumps its generation, so a late job completion, receipt or timer that still
// carries the old handle resolves to nullptr and cannot act on the slot's next occupant (R10).
// A slot whose generation counter is exhausted (UINT32_MAX released) is retired for good instead of
// wrapping, so an ancient handle can never revalidate; capacity shrinks by one slot (FIX1-D25).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace lm {

struct Handle {
    uint16_t index = 0;
    uint32_t generation = 0; // 0 = none; live generations start at 1 and never wrap

    [[nodiscard]] constexpr bool is_none() const { return generation == 0; }
    static constexpr Handle none() { return Handle{}; }
    friend constexpr bool operator==(Handle a, Handle b) {
        return a.index == b.index && a.generation == b.generation;
    }
    friend constexpr bool operator!=(Handle a, Handle b) { return !(a == b); }
};

template <class T, std::size_t N> class Pool {
    static_assert(N > 0 && N < 0xFFFF, "capacity");

  public:
    Pool() {
        for (auto &g : generation_) {
            g = 1;
        }
    }

    // Handle::none() when the pool is full; the caller reports NO_CAPACITY/BUSY.
    [[nodiscard]] Handle acquire() {
        for (std::size_t i = 0; i < N; ++i) {
            if (!used_[i] && !retired_[i]) {
                used_[i] = true;
                items_[i] = T{};
                ++in_use_;
                return Handle{static_cast<uint16_t>(i), generation_[i]};
            }
        }
        return Handle::none();
    }

    // nullptr for stale or foreign handles.
    [[nodiscard]] T *get(Handle h) { return valid(h) ? &items_[h.index] : nullptr; }
    [[nodiscard]] const T *get(Handle h) const { return valid(h) ? &items_[h.index] : nullptr; }

    // Returns false for stale handles (double release is detected, never applied twice).
    bool release(Handle h) {
        if (!valid(h)) {
            return false;
        }
        used_[h.index] = false;
        items_[h.index] = T{};
        if (generation_[h.index] == UINT32_MAX) {
            retired_[h.index] = true; // never handed out again: its generation cannot advance
        } else {
            ++generation_[h.index];
        }
        --in_use_;
        return true;
    }

    [[nodiscard]] bool valid(Handle h) const {
        return h.index < N && used_[h.index] && generation_[h.index] == h.generation;
    }
    // Handle that would address slot i right now; get() of it is nullptr while the slot is free.
    [[nodiscard]] Handle handle_at(std::size_t i) const {
        return Handle{static_cast<uint16_t>(i), generation_[i]};
    }
    [[nodiscard]] std::size_t in_use() const { return in_use_; }
    [[nodiscard]] bool retired(std::size_t i) const { return retired_[i]; }
    // Test bench only: starts slot i at generation `g` (reaching UINT32_MAX takes 4e9 releases).
    void seed_generation_for_test(std::size_t i, uint32_t g) { generation_[i] = g; }
    static constexpr std::size_t capacity() { return N; }

    // Visits live slots in index order (deterministic).
    template <class F> void for_each(F &&f) {
        for (std::size_t i = 0; i < N; ++i) {
            if (used_[i]) {
                f(Handle{static_cast<uint16_t>(i), generation_[i]}, items_[i]);
            }
        }
    }

  private:
    std::array<T, N> items_{};
    std::array<uint32_t, N> generation_{};
    std::array<bool, N> used_{};
    std::array<bool, N> retired_{};
    std::size_t in_use_ = 0;
};

} // namespace lm
