// Explicit big-endian codec helpers (docs/09 §1: network byte order, no struct memcpy/casts).
// Errors are sticky: after the first overrun every read returns 0 and ok() stays false, so a
// decoder can read all fields and check once. Decoders must still validate every field value.
#pragma once

#include <array>
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

    // A layout rule the byte reader cannot see was broken (a count above its bound): the read has failed.
    void fail() { ok_ = false; }
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

    void fail() { ok_ = false; } // a value the layout cannot carry (a count above its bound)
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

// ---- one layout, two directions ----
// The compact fixed-layout records (mesh, channel, power, ledger, trust) list their fields once, in a function
// `io(f, record)` that FieldPut runs to write and FieldGet runs to read, so the two directions cannot drift apart.
// Integers are big endian; `is(c)` is a one-byte constant (opcode, version) that FieldGet requires; `list` is a count
// byte followed by at most N 16-bit entries; `flag_en` is a high flag bit over a 7-bit enum. Range checks of what was
// read stay with each record. FieldPut only reads the record (every parameter is const): a field list never writes
// in that direction, so an encoder may run it on the caller's record (put_fields below) instead of on a copy.
struct FieldPut {
    Writer w;
    void u8(const uint8_t &v) { w.u8(v); }
    void u16(const uint16_t &v) { w.u16be(v); }
    void u32(const uint32_t &v) { w.u32be(v); }
    void u64(const uint64_t &v) { w.u64be(v); }
    void flag(const bool &v) { w.u8(v ? 1 : 0); }
    template <std::size_t N> void raw(const std::array<uint8_t, N> &v) { w.bytes(ByteView{v}); }
    template <class T> void tag(const T &t) { w.u32be(t.value()); } // RootTerm, ChannelEpoch
    template <class E> void en(const E &e) { w.u8(static_cast<uint8_t>(e)); }
    template <class E> void flag_en(const bool &flag, const E &e) {
        w.u8(static_cast<uint8_t>((flag ? 0x80U : 0U) | static_cast<uint8_t>(e)));
    }
    template <class C> void is(C c) {
        static_assert(sizeof(C) == 1, "one-byte constants only");
        w.u8(static_cast<uint8_t>(c));
    }
    template <std::size_t N> void list(const uint8_t &n, const std::array<uint16_t, N> &v) {
        if (n > N) {
            w.fail();
            return;
        }
        w.u8(n);
        for (std::size_t i = 0; i < n; ++i) {
            w.u16be(v[i]);
        }
    }
};

struct FieldGet {
    Reader r;
    bool match = true; // every is() constant was there
    void u8(uint8_t &v) { v = r.u8(); }
    void u16(uint16_t &v) { v = r.u16be(); }
    void u32(uint32_t &v) { v = r.u32be(); }
    void u64(uint64_t &v) { v = r.u64be(); }
    void flag(bool &v) { v = r.u8() != 0; }
    template <std::size_t N> void raw(std::array<uint8_t, N> &v) { r.copy_to(v); }
    template <class T> void tag(T &t) { t = T{r.u32be()}; }
    template <class E> void en(E &e) { e = static_cast<E>(r.u8()); }
    template <class E> void flag_en(bool &flag, E &e) {
        const uint8_t b = r.u8();
        flag = (b & 0x80U) != 0;
        e = static_cast<E>(b & 0x7FU);
    }
    template <class C> void is(C c) {
        static_assert(sizeof(C) == 1, "one-byte constants only");
        match = r.u8() == static_cast<uint8_t>(c) && match;
    }
    template <std::size_t N> void list(uint8_t &n, std::array<uint16_t, N> &v) {
        n = r.u8();
        if (n > N) {
            r.fail();
            n = 0;
            return;
        }
        for (std::size_t i = 0; i < n; ++i) {
            v[i] = r.u16be();
        }
    }
    // BadFrame on overrun, trailing bytes or a missing constant.
    [[nodiscard]] Status finish() const { return r.finish() == Status::Ok && match ? Status::Ok : Status::BadFrame; }
};

// `io(f, record)` runs the record's field list (a generic lambda around it). The lists take the record by non-const
// reference for FieldGet's sake; FieldPut's parameters are const, so put_record() lends the caller's record without a
// copy.
template <class M, class IO> [[nodiscard]] Status put_record(const M &record, MutByteView out, std::size_t &len, IO &&io) {
    FieldPut f{Writer{out}};
    io(f, const_cast<M &>(record)); // read only: every FieldPut parameter is const
    len = f.w.size();
    return f.w.finish();
}
template <class M, class IO> [[nodiscard]] Status get_record(ByteView in, M &record, IO &&io) {
    FieldGet f{Reader{in}};
    io(f, record);
    return f.finish();
}

} // namespace lm
