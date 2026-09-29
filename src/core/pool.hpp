// Fixed pools addressed by slot+generation handles (docs/15 §2 "各slotにgeneration").
// Releasing a slot bumps its generation, so a late job completion, receipt or timer that still
// carries the old handle resolves to nullptr and cannot act on the slot's next occupant (R10).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace lm {

struct Handle {
    uint16_t index = 0;
    uint32_t generation = 0; // 0 = none; live generations start at 1 and skip 0 on wrap

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
            if (!used_[i]) {
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
        uint32_t g = generation_[h.index] + 1;
        generation_[h.index] = g == 0 ? 1 : g;
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
    std::size_t in_use_ = 0;
};

} // namespace lm
