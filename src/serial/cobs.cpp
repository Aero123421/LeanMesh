#include "serial/cobs.hpp"

namespace lm::serial {

std::size_t cobs_encode_in_place(MutByteView buf, std::size_t data_off, std::size_t n) {
    if (data_off > buf.size() || n > buf.size() - data_off || data_off < 1 + n / 254 + 1) {
        return 0;
    }
    uint8_t *b = buf.data();
    std::size_t w = 1;
    std::size_t code_at = 0;
    for (std::size_t r = data_off; r < data_off + n; ++r) {
        const uint8_t v = b[r];
        if (v == 0) {
            b[code_at] = static_cast<uint8_t>(w - code_at);
            code_at = w++;
        } else {
            b[w++] = v;
            if (w - code_at == 255) {
                b[code_at] = 255;
                code_at = w++;
            }
        }
    }
    b[code_at] = static_cast<uint8_t>(w - code_at);
    if (w >= buf.size()) {
        return 0;
    }
    b[w++] = 0; // delimiter
    return w;
}

void CobsDecoder::reset() {
    len_ = 0;
    code_ = 0;
    remaining_ = 0;
    started_ = false;
    discarding_ = false;
}

void CobsDecoder::append(uint8_t b) {
    if (discarding_) {
        return;
    }
    if (len_ >= buf_.size()) {
        discarding_ = true;
        ++overflows_;
        return;
    }
    buf_[len_++] = b;
}

CobsDecoder::Result CobsDecoder::push(uint8_t b) {
    if (pending_reset_) {
        pending_reset_ = false;
        len_ = 0;
    }
    if (b == 0) {
        Result r = Result::None;
        if (discarding_) {
            r = Result::Bad; // overflow: counted when it happened
        } else if (started_ && remaining_ != 0) {
            ++bad_;
            r = Result::Bad;
        } else if (len_ > 0) {
            r = Result::Frame;
        }
        code_ = 0;
        remaining_ = 0;
        started_ = false;
        discarding_ = false;
        if (r == Result::Frame) {
            pending_reset_ = true; // frame() stays readable until the next byte
        } else {
            len_ = 0;
        }
        return r;
    }
    if (remaining_ == 0) {
        if (started_ && code_ != 0xFF) {
            append(0);
        }
        code_ = b;
        remaining_ = static_cast<uint8_t>(b - 1);
        started_ = true;
    } else {
        append(b);
        --remaining_;
    }
    return Result::None;
}

} // namespace lm::serial
