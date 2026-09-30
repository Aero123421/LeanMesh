// Strict CBOR decoding for LM1 control objects (docs/09 §1). Only the deterministic subset of
// RFC 8949 §4.2.1 that control.cddl needs is accepted: definite lengths, shortest heads,
// uint/nint/bstr/tstr/array/map/false/true/null. Rejected: indefinite lengths, non-minimal
// heads, floats, undefined, other simple values, tags (COSE's tag 18 is stripped by the COSE
// parser), map keys that are not uint/nint/bstr/tstr, duplicate or unsorted keys (bytewise
// order of the encoded keys), invalid UTF-8, trailing bytes, nesting deeper than k_cbor_max_depth
// and container sizes above k_cbor_max_array / k_cbor_max_map. Every failure is BadFrame.
#pragma once

#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/status.hpp"

namespace lm::wire {

inline constexpr unsigned k_cbor_max_depth = 16; // item nesting levels 0..16
inline constexpr uint64_t k_cbor_max_array = 4096;
inline constexpr uint64_t k_cbor_max_map = 128;

enum class CborType : uint8_t { Uint, Nint, Bytes, Text, Array, Map, Bool, Null };

// Whole input is exactly one well-formed deterministic item.
[[nodiscard]] Status cbor_validate(ByteView in);

// Pull parser over one buffer. Sticky error like lm::Reader: after the first failure every call
// returns zero/empty and status() is BadFrame. It bounds-checks and enforces minimal heads and
// UTF-8 by itself; map ordering and depth are enforced by cbor_validate (typed decoders call it
// on the whole buffer first).
class CborReader {
  public:
    explicit CborReader(ByteView in) : in_(in) {}

    [[nodiscard]] uint64_t uint_in(uint64_t lo, uint64_t hi);
    [[nodiscard]] int64_t int_in(int64_t lo, int64_t hi);
    [[nodiscard]] ByteView bstr(std::size_t lo, std::size_t hi);
    [[nodiscard]] ByteView tstr(std::size_t lo, std::size_t hi);
    [[nodiscard]] std::size_t array(std::size_t lo, std::size_t hi);
    void map_exact(std::size_t n);
    [[nodiscard]] bool boolean();
    // Consumes a null if it is next.
    [[nodiscard]] bool try_null();
    // Returns the encoding of the next complete item and skips it.
    [[nodiscard]] ByteView skip_item();
    // Generic pull for tools: arg = uint value, nint magnitude (value is -1-arg), bool 0/1,
    // element/pair count for Array/Map, length for Bytes/Text (then `data` holds the content).
    struct Item {
        CborType type = CborType::Null;
        uint64_t arg = 0;
        ByteView data;
    };
    [[nodiscard]] bool next(Item &item);

    void fail() { ok_ = false; }
    [[nodiscard]] bool ok() const { return ok_; }
    [[nodiscard]] std::size_t position() const { return pos_; }
    [[nodiscard]] Status finish() const {
        return (ok_ && pos_ == in_.size()) ? Status::Ok : Status::BadFrame;
    }

  private:
    struct Head {
        uint8_t major = 0;
        uint64_t arg = 0;
    };
    bool head(Head &h);
    ByteView string(uint8_t major, std::size_t lo, std::size_t hi);

    ByteView in_;
    std::size_t pos_ = 0;
    bool ok_ = true;
};

// Strict UTF-8 (no overlongs, no surrogates, <= U+10FFFF).
[[nodiscard]] bool utf8_valid(ByteView s);

} // namespace lm::wire
