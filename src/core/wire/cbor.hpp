// Deterministic CBOR encoder (RFC 8949 §4.2.1 core deterministic encoding): shortest heads,
// definite lengths only, no floats. Maps must be written with keys already in bytewise
// lexicographic order of their encodings; the writer does not reorder. Errors are sticky
// (NoCapacity on overflow). The strict decoder (duplicate keys, ordering, trailing bytes, UTF-8,
// depth) is in cbor_reader.hpp.
#pragma once

#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/codec.hpp"
#include "core/status.hpp"

namespace lm::wire {

class CborWriter {
  public:
    explicit CborWriter(MutByteView out) : w_(out) {}

    void uint(uint64_t v) { head(0, v); }
    // Negative integer n (< 0) encoded as major type 1 with argument -1-n.
    void nint(int64_t n) { head(1, static_cast<uint64_t>(-1 - n)); }
    void integer(int64_t v) {
        if (v >= 0) {
            uint(static_cast<uint64_t>(v));
        } else {
            nint(v);
        }
    }
    void bytes(ByteView b) {
        head(2, b.size());
        w_.bytes(b);
    }
    // Caller guarantees valid UTF-8 (SDK text is ASCII constants).
    void text(ByteView utf8) {
        head(3, utf8.size());
        w_.bytes(utf8);
    }
    // Head of a byte string of length n; the n content bytes follow via raw() or the caller.
    void bytes_head(std::size_t n) { head(2, n); }
    void array(std::size_t n) { head(4, n); }
    void map(std::size_t n) { head(5, n); }
    void tag(uint64_t t) { head(6, t); }
    void boolean(bool v) { w_.u8(v ? 0xF5 : 0xF4); }
    void null() { w_.u8(0xF6); }
    // Appends an already-encoded deterministic item (caller-validated).
    void raw(ByteView encoded) { w_.bytes(encoded); }

    [[nodiscard]] Status finish() const { return w_.finish(); }
    [[nodiscard]] ByteView written() const { return w_.written(); }
    [[nodiscard]] std::size_t size() const { return w_.size(); }

  private:
    void head(uint8_t major, uint64_t arg) {
        const auto m = static_cast<uint8_t>(major << 5U);
        if (arg < 24) {
            w_.u8(static_cast<uint8_t>(m | arg));
        } else if (arg <= 0xFF) {
            w_.u8(static_cast<uint8_t>(m | 24U));
            w_.u8(static_cast<uint8_t>(arg));
        } else if (arg <= 0xFFFF) {
            w_.u8(static_cast<uint8_t>(m | 25U));
            w_.u16be(static_cast<uint16_t>(arg));
        } else if (arg <= 0xFFFFFFFFULL) {
            w_.u8(static_cast<uint8_t>(m | 26U));
            w_.u32be(static_cast<uint32_t>(arg));
        } else {
            w_.u8(static_cast<uint8_t>(m | 27U));
            w_.u64be(arg);
        }
    }

    Writer w_;
};

// ASCII string literal as a text-string view.
template <std::size_t N> [[nodiscard]] inline ByteView ascii(const char (&s)[N]) {
    return ByteView{reinterpret_cast<const uint8_t *>(s), N - 1};
}

} // namespace lm::wire
