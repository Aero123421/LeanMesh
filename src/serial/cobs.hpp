// COBS framing of the USB serial stream (docs/09 §9): every decoded frame is followed by one 0x00
// delimiter, and 0x00 never appears inside an encoded frame, so a receiver that lost sync (noise,
// half a record, a reset peer) resumes at the next delimiter. Both sides use these two pieces.
#pragma once

#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"

namespace lm::serial {

// Frame data starts at buf[data_off]; the encoding is written from buf[0] forward, so it never
// overtakes the data it has not read yet as long as the headroom covers the code bytes
// (1 + n/254). Returns the encoded length including the trailing delimiter, or 0 when it does
// not fit (nothing usable in buf then).
inline constexpr std::size_t k_cobs_headroom = 40; // enough for the 8230 B maximum frame

[[nodiscard]] std::size_t cobs_encode_in_place(MutByteView buf, std::size_t data_off, std::size_t n);

// Streaming decoder with a fixed output buffer. A frame that does not fit is discarded up to the
// next delimiter (overflow counted); a structurally broken frame (truncated block) is discarded
// and counted. Empty frames (idle delimiters) are ignored without a count.
class CobsDecoder {
  public:
    enum class Result : uint8_t { None, Frame, Bad };

    explicit CobsDecoder(MutByteView buf) : buf_(buf) {}

    // Frame: frame() is valid until the next push().
    [[nodiscard]] Result push(uint8_t b);
    [[nodiscard]] ByteView frame() const { return ByteView{buf_.data(), len_}; }
    void reset();

    [[nodiscard]] uint64_t overflows() const { return overflows_; }
    [[nodiscard]] uint64_t bad_frames() const { return bad_; }

  private:
    void append(uint8_t b);

    MutByteView buf_;
    std::size_t len_ = 0;
    uint8_t code_ = 0;
    uint8_t remaining_ = 0; // data bytes still to come in the current block
    bool started_ = false;
    bool discarding_ = false;
    bool pending_reset_ = false; // a Frame was delivered: clear len_ on the next byte
    uint64_t overflows_ = 0;
    uint64_t bad_ = 0;
};

} // namespace lm::serial
