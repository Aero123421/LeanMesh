// Length-carrying views (C++17 has no std::span). All copies go through checked helpers
// (docs/15 §2 "memcpyは検査済みbounds内のみ").
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>

#include "core/status.hpp"

namespace lm {

template <class T> class Span {
  public:
    constexpr Span() = default;
    constexpr Span(T *data, std::size_t size) : data_(data), size_(size) {}
    template <std::size_t N>
    // NOLINTNEXTLINE(google-explicit-constructor): arrays convert like std::span.
    constexpr Span(std::array<std::remove_const_t<T>, N> &a) : data_(a.data()), size_(N) {}
    template <std::size_t N>
    // NOLINTNEXTLINE(google-explicit-constructor)
    constexpr Span(const std::array<std::remove_const_t<T>, N> &a) : data_(a.data()), size_(N) {}
    template <class U, class = std::enable_if_t<std::is_same_v<const U, T>>>
    // NOLINTNEXTLINE(google-explicit-constructor): Span<U> -> Span<const U>.
    constexpr Span(Span<U> other) : data_(other.data()), size_(other.size()) {}

    [[nodiscard]] constexpr T *data() const { return data_; }
    [[nodiscard]] constexpr std::size_t size() const { return size_; }
    [[nodiscard]] constexpr bool empty() const { return size_ == 0; }
    [[nodiscard]] constexpr T *begin() const { return data_; }
    [[nodiscard]] constexpr T *end() const { return data_ + size_; }
    // Unchecked element access: callers index within size() (internal invariant).
    constexpr T &operator[](std::size_t i) const { return data_[i]; }

    // Returns an empty span when [offset, offset+count) is out of bounds; check size().
    [[nodiscard]] constexpr Span subspan(std::size_t offset, std::size_t count) const {
        if (offset > size_ || count > size_ - offset) {
            return Span{};
        }
        return Span{data_ + offset, count};
    }
    [[nodiscard]] constexpr Span first(std::size_t count) const { return subspan(0, count); }
    [[nodiscard]] constexpr Span from(std::size_t offset) const {
        return offset > size_ ? Span{} : Span{data_ + offset, size_ - offset};
    }

  private:
    T *data_ = nullptr;
    std::size_t size_ = 0;
};

using ByteView = Span<const uint8_t>;
using MutByteView = Span<uint8_t>;

// Not constant-time. Secrets and MACs are compared with lm::sec::ct_equal.
[[nodiscard]] inline bool bytes_equal(ByteView a, ByteView b) {
    return a.size() == b.size() && (a.empty() || std::memcmp(a.data(), b.data(), a.size()) == 0);
}

// Copies src into the start of dst. NoCapacity when dst is too small; dst is untouched then.
[[nodiscard]] inline Status copy_bytes(MutByteView dst, ByteView src) {
    if (src.size() > dst.size()) {
        return Status::NoCapacity;
    }
    if (!src.empty()) {
        std::memcpy(dst.data(), src.data(), src.size());
    }
    return Status::Ok;
}

} // namespace lm
