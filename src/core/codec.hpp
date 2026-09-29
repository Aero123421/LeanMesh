// Explicit big-endian codec helpers (docs/09 §1: network byte order, no struct memcpy/casts).
// Errors are sticky: after the first overrun every read returns 0 and ok() stays false, so a
// decoder can read all fields and check once. Decoders must still validate every field value.
#pragma once

#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/status.hpp"

namespace lm {

class Reader {
  public:
    explicit Reader(ByteView in) : in_(in) {}

    [[nodiscard]] uint8_t u8() { return static_cast<uint8_t>(take(1)); }
    [[nodiscard]] uint16_t u16be() { return static_cast<uint16_t>(take(2)); }
    [[nodiscard]] uint32_t u32be() { return static_cast<uint32_t>(take(4)); }
    [[nodiscard]] uint64_t u64be() { return take(8); }

    // Returns a view of the next n bytes (empty and error on overrun). The view aliases the input.
    [[nodiscard]] ByteView bytes(std::size_t n) {
        if (!ok_ || n > in_.size() - pos_) {
            ok_ = false;
            return ByteView{};
        }
        ByteView v = in_.subspan(pos_, n);
        pos_ += n;
        return v;
    }
    // Copies the next N bytes into a fixed array (zero-filled on error).
    template <std::size_t N> void copy_to(std::array<uint8_t, N> &out) {
        ByteView v = bytes(N);
        if (ok_) {
            for (std::size_t i = 0; i < N; ++i) {
                out[i] = v[i];
            }
        } else {
            out.fill(0);
        }
    }

    [[nodiscard]] bool ok() const { return ok_; }
    [[nodiscard]] std::size_t position() const { return pos_; }
    [[nodiscard]] std::size_t remaining() const { return ok_ ? in_.size() - pos_ : 0; }
    // BadFrame on overrun or trailing bytes (docs/09 §1 "末尾余剰...を拒否").
    [[nodiscard]] Status finish() const {
        return (ok_ && pos_ == in_.size()) ? Status::Ok : Status::BadFrame;
    }

  private:
    uint64_t take(std::size_t n) {
        if (!ok_ || n > in_.size() - pos_) {
            ok_ = false;
            return 0;
        }
        uint64_t v = 0;
        for (std::size_t i = 0; i < n; ++i) {
            v = (v << 8U) | in_[pos_ + i];
        }
        pos_ += n;
        return v;
    }

    ByteView in_;
    std::size_t pos_ = 0;
    bool ok_ = true;
};

class Writer {
  public:
    explicit Writer(MutByteView out) : out_(out) {}

    void u8(uint8_t v) { put(v, 1); }
    void u16be(uint16_t v) { put(v, 2); }
    void u32be(uint32_t v) { put(v, 4); }
    void u64be(uint64_t v) { put(v, 8); }
    void bytes(ByteView v) {
        if (!ok_ || v.size() > out_.size() - pos_) {
            ok_ = false;
            return;
        }
        for (std::size_t i = 0; i < v.size(); ++i) {
            out_[pos_ + i] = v[i];
        }
        pos_ += v.size();
    }
    void zeros(std::size_t n) {
        if (!ok_ || n > out_.size() - pos_) {
            ok_ = false;
            return;
        }
        for (std::size_t i = 0; i < n; ++i) {
            out_[pos_ + i] = 0;
        }
        pos_ += n;
    }

    [[nodiscard]] bool ok() const { return ok_; }
    [[nodiscard]] std::size_t size() const { return pos_; }
    [[nodiscard]] ByteView written() const { return ByteView{out_.data(), pos_}; }
    // NoCapacity when any write overflowed the output buffer.
    [[nodiscard]] Status finish() const { return ok_ ? Status::Ok : Status::NoCapacity; }

  private:
    void put(uint64_t v, std::size_t n) {
        if (!ok_ || n > out_.size() - pos_) {
            ok_ = false;
            return;
        }
        for (std::size_t i = 0; i < n; ++i) {
            out_[pos_ + i] = static_cast<uint8_t>(v >> (8U * (n - 1 - i)));
        }
        pos_ += n;
    }

    MutByteView out_;
    std::size_t pos_ = 0;
    bool ok_ = true;
};

} // namespace lm
