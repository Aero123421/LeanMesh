#include "core/wire/cbor_reader.hpp"

#include <cstring>

namespace lm::wire {
namespace {

// One head: shortest form only. Major 6 (tags), indefinite lengths, reserved additional info
// and every major-7 value except false/true/null (no floats, no undefined, no simple values)
// are refused.
bool parse_head(ByteView in, std::size_t &pos, uint8_t &major, uint64_t &arg) {
    if (pos >= in.size()) {
        return false;
    }
    const uint8_t first = in[pos++];
    major = first >> 5U;
    const uint8_t ai = first & 31U;
    if (major == 6) {
        return false;
    }
    if (major == 7) {
        arg = ai;
        return ai >= 20 && ai <= 22;
    }
    if (ai < 24) {
        arg = ai;
        return true;
    }
    if (ai > 27) {
        return false;
    }
    const std::size_t width = std::size_t{1} << (ai - 24U);
    if (width > in.size() - pos) {
        return false;
    }
    uint64_t v = 0;
    for (std::size_t i = 0; i < width; ++i) {
        v = (v << 8U) | in[pos + i];
    }
    pos += width;
    constexpr uint64_t min_for_width[4] = {24, 256, 65536, 0x100000000ULL};
    if (v < min_for_width[ai - 24U]) {
        return false;
    }
    arg = v;
    return true;
}

bool key_less(ByteView a, ByteView b) {
    const std::size_t n = a.size() < b.size() ? a.size() : b.size();
    const int c = n == 0 ? 0 : std::memcmp(a.data(), b.data(), n);
    return c < 0 || (c == 0 && a.size() < b.size());
}

// Walks one complete item; pos advances past it.
bool walk(ByteView in, std::size_t &pos, unsigned depth) {
    if (depth > k_cbor_max_depth) {
        return false;
    }
    uint8_t major = 0;
    uint64_t arg = 0;
    if (!parse_head(in, pos, major, arg)) {
        return false;
    }
    switch (major) {
    case 0:
    case 1:
    case 7:
        return true;
    case 2:
    case 3: {
        if (arg > in.size() - pos) {
            return false;
        }
        const ByteView s = in.subspan(pos, static_cast<std::size_t>(arg));
        pos += s.size();
        return major == 2 || utf8_valid(s);
    }
    case 4:
        if (arg > k_cbor_max_array || arg > in.size() - pos) {
            return false;
        }
        for (uint64_t i = 0; i < arg; ++i) {
            if (!walk(in, pos, depth + 1)) {
                return false;
            }
        }
        return true;
    default: { // 5: map
        if (arg > k_cbor_max_map || arg * 2 > in.size() - pos) {
            return false;
        }
        ByteView prev;
        for (uint64_t i = 0; i < arg; ++i) {
            const std::size_t start = pos;
            if (pos >= in.size() || (in[pos] >> 5U) > 3U || !walk(in, pos, depth + 1)) {
                return false;
            }
            const ByteView key = in.subspan(start, pos - start);
            if (i > 0 && !key_less(prev, key)) {
                return false;
            }
            prev = key;
            if (!walk(in, pos, depth + 1)) {
                return false;
            }
        }
        return true;
    }
    }
}

} // namespace

bool utf8_valid(ByteView s) {
    std::size_t i = 0;
    while (i < s.size()) {
        const uint8_t b = s[i];
        std::size_t extra = 0;
        uint32_t cp = 0;
        uint32_t min_cp = 0;
        if (b < 0x80) {
            ++i;
            continue;
        }
        if (b >= 0xC2 && b <= 0xDF) {
            extra = 1;
            cp = b & 0x1FU;
            min_cp = 0x80;
        } else if (b >= 0xE0 && b <= 0xEF) {
            extra = 2;
            cp = b & 0x0FU;
            min_cp = 0x800;
        } else if (b >= 0xF0 && b <= 0xF4) {
            extra = 3;
            cp = b & 0x07U;
            min_cp = 0x10000;
        } else {
            return false;
        }
        if (extra > s.size() - i - 1) {
            return false;
        }
        for (std::size_t k = 1; k <= extra; ++k) {
            if ((s[i + k] & 0xC0U) != 0x80U) {
                return false;
            }
            cp = (cp << 6U) | (s[i + k] & 0x3FU);
        }
        if (cp < min_cp || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
            return false;
        }
        i += extra + 1;
    }
    return true;
}

Status cbor_validate(ByteView in) {
    std::size_t pos = 0;
    return (walk(in, pos, 0) && pos == in.size()) ? Status::Ok : Status::BadFrame;
}

bool CborReader::head(Head &h) {
    if (ok_ && !parse_head(in_, pos_, h.major, h.arg)) {
        ok_ = false;
    }
    return ok_;
}

uint64_t CborReader::uint_in(uint64_t lo, uint64_t hi) {
    Head h;
    if (!head(h)) {
        return 0;
    }
    if (h.major != 0 || h.arg < lo || h.arg > hi) {
        ok_ = false;
        return 0;
    }
    return h.arg;
}

int64_t CborReader::int_in(int64_t lo, int64_t hi) {
    Head h;
    if (!head(h)) {
        return 0;
    }
    int64_t v = 0;
    if (h.major == 0 && h.arg <= static_cast<uint64_t>(INT64_MAX)) {
        v = static_cast<int64_t>(h.arg);
    } else if (h.major == 1 && h.arg <= static_cast<uint64_t>(INT64_MAX)) {
        v = -1 - static_cast<int64_t>(h.arg);
    } else {
        ok_ = false;
        return 0;
    }
    if (v < lo || v > hi) {
        ok_ = false;
        return 0;
    }
    return v;
}

ByteView CborReader::string(uint8_t major, std::size_t lo, std::size_t hi) {
    Head h;
    if (!head(h)) {
        return ByteView{};
    }
    if (h.major != major || h.arg < lo || h.arg > hi || h.arg > in_.size() - pos_) {
        ok_ = false;
        return ByteView{};
    }
    const ByteView v = in_.subspan(pos_, static_cast<std::size_t>(h.arg));
    pos_ += v.size();
    if (major == 3 && !utf8_valid(v)) {
        ok_ = false;
        return ByteView{};
    }
    return v;
}

ByteView CborReader::bstr(std::size_t lo, std::size_t hi) { return string(2, lo, hi); }
ByteView CborReader::tstr(std::size_t lo, std::size_t hi) { return string(3, lo, hi); }

std::size_t CborReader::array(std::size_t lo, std::size_t hi) {
    Head h;
    if (!head(h)) {
        return 0;
    }
    if (h.major != 4 || h.arg < lo || h.arg > hi || h.arg > k_cbor_max_array ||
        h.arg > in_.size() - pos_) {
        ok_ = false;
        return 0;
    }
    return static_cast<std::size_t>(h.arg);
}

void CborReader::map_exact(std::size_t n) {
    Head h;
    if (head(h) && (h.major != 5 || h.arg != n)) {
        ok_ = false;
    }
}

bool CborReader::boolean() {
    Head h;
    if (!head(h)) {
        return false;
    }
    if (h.major != 7 || h.arg == 22) {
        ok_ = false;
        return false;
    }
    return h.arg == 21;
}

bool CborReader::try_null() {
    if (!ok_ || pos_ >= in_.size() || in_[pos_] != 0xF6) {
        return false;
    }
    ++pos_;
    return true;
}

ByteView CborReader::skip_item() {
    if (!ok_) {
        return ByteView{};
    }
    const std::size_t start = pos_;
    if (!walk(in_, pos_, 0)) {
        ok_ = false;
        return ByteView{};
    }
    return in_.subspan(start, pos_ - start);
}

bool CborReader::next(Item &item) {
    Head h;
    if (!head(h)) {
        return false;
    }
    switch (h.major) {
    case 0:
        item = {CborType::Uint, h.arg, ByteView{}};
        return true;
    case 1:
        item = {CborType::Nint, h.arg, ByteView{}};
        return true;
    case 2:
    case 3: {
        if (h.arg > in_.size() - pos_) {
            ok_ = false;
            return false;
        }
        const ByteView v = in_.subspan(pos_, static_cast<std::size_t>(h.arg));
        pos_ += v.size();
        if (h.major == 3 && !utf8_valid(v)) {
            ok_ = false;
            return false;
        }
        item = {h.major == 2 ? CborType::Bytes : CborType::Text, h.arg, v};
        return true;
    }
    case 4:
        item = {CborType::Array, h.arg, ByteView{}};
        return true;
    case 5:
        item = {CborType::Map, h.arg, ByteView{}};
        return true;
    default:
        item = {h.arg == 22 ? CborType::Null : CborType::Bool, h.arg == 21 ? 1U : 0U, ByteView{}};
        return true;
    }
}

} // namespace lm::wire
