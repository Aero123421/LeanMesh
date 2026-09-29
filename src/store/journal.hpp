// Append-only journal for durable pending/result entries (docs/12 §3). Worker-only: every method
// does Flash I/O through the Store port and runs inside a job body; the object is owned by the
// worker side (its module hands it to jobs through the job `arg`; the owner never reads it while a
// job is in flight).
//
// Entry (big endian, 4-byte aligned, each entry is self-validating):
//   magic2 0xA55A | kind1 (1 Put, 2 Retire) | reserved1 | len2 | reserved2 | seq4 | id4 | crc4
//   | payload[len] | pad to 4        CRC32 covers kind..id and the payload. Header 20 B.
// `id` is chosen by the owner module; a Put with a live id replaces it; Retire removes it.
// Live set = latest Put per id without a later Retire (rebuilt by open() from Flash, in seq order).
//
// Space: entries are appended to the head segment; the next segment is erased (after its live
// entries were copied forward with new seq numbers) only when the head is full. If the live data
// cannot make room the append fails with NoCapacity and nothing is dropped: an ACKed (durable Ok)
// entry disappears only through an explicit Retire. Ok is returned after the Flash write of the
// whole batch completed (docs/12 §3 "ACKは当該commit以後"). Batching = one write for several ops
// (the owner collects them for at most k_commit_batch_window_us before submitting one job);
// each entry is individually atomic (CRC), the batch as a whole is not.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/ports.hpp"

namespace lm::store {

// 145 B fixed fields of a received durable record + 512 B small message (delivery_durable.cpp), 4-aligned.
inline constexpr std::size_t k_journal_max_payload = 672;
inline constexpr std::size_t k_journal_header = 20;
inline constexpr std::size_t k_journal_max_segments = 32; // 128 KiB / 4 KiB
// Staging memory the owner lends (see Journal): at least one entry of the largest payload; a larger
// scratch (e.g. k_journal_batch_bytes) lets apply() take batches of several entries.
inline constexpr std::size_t k_journal_min_scratch = k_journal_header + k_journal_max_payload;
inline constexpr std::size_t k_journal_batch_bytes = 1100;
inline constexpr uint32_t k_commit_batch_window_us = 20'000;

struct JournalOp {
    enum class Kind : uint8_t { Put = 1, Retire = 2 };
    Kind kind = Kind::Put;
    uint32_t id = 0;
    ByteView data; // Put only, <= k_journal_max_payload
};

struct JournalLive {
    uint32_t id = 0;
    uint32_t seq = 0;
    uint32_t offset = 0; // absolute journal offset of the entry header
    uint16_t len = 0;
    uint16_t segment = 0;
};

class Journal {
  public:
    // `index` holds the live entries: its size is the durable-entry capacity of this role
    // (profile durable_pending + results). open() fails closed if Flash holds more live entries.
    // `scratch` (>= k_journal_min_scratch) is where every operation stages entries; it belongs to
    // the owner's job memory (the journal is only used inside jobs) and its size bounds a batch.
    Journal(JournalLive *index, std::size_t capacity, MutByteView scratch)
        : index_(index), capacity_(capacity), buf_(scratch) {}

    // Scans all segments (two passes), rebuilds the live set, and finishes an interrupted
    // reclaim. Safe to call again after any failed operation.
    [[nodiscard]] Status open(port::Store &store);
    // Ok = durable. NoCapacity: no room (live entries never dropped) or live table full.
    // NotFound: Retire of an id that is not live (checked before anything is written).
    [[nodiscard]] Status apply(port::Store &store, const JournalOp *ops, std::size_t count);
    [[nodiscard]] Status read(port::Store &store, uint32_t id, MutByteView out, std::size_t &len);

    [[nodiscard]] std::size_t live_count() const { return live_; }
    [[nodiscard]] const JournalLive &live_at(std::size_t i) const { return index_[i]; }
    [[nodiscard]] uint32_t next_seq() const { return next_seq_; }
    [[nodiscard]] uint32_t free_bytes_in_head() const;

  private:
    struct Segment {
        uint32_t tail = 0;     // next write offset; == segment size when full or torn
        uint32_t last_seq = 0; // highest valid seq (0 = none)
        bool used = false;     // any non-erased byte
    };

    Status scan_segment(port::Store &store, uint32_t seg, bool apply_entries);
    void apply_entry(uint8_t kind, uint32_t id, uint32_t seq, uint32_t offset, uint16_t len,
                     uint32_t seg);
    Status rest_erased(port::Store &store, uint32_t offset, uint32_t bytes, bool &clean);
    Status make_room(port::Store &store, uint32_t need);
    Status reclaim(port::Store &store, uint32_t seg);
    Status write_at_head(port::Store &store, ByteView buf);
    JournalLive *find(uint32_t id);
    [[nodiscard]] uint32_t live_bytes_in(uint32_t seg) const;

    JournalLive *index_;
    std::size_t capacity_;
    std::size_t live_ = 0;
    uint32_t next_seq_ = 1;
    uint32_t seg_bytes_ = 0;
    uint32_t nseg_ = 0;
    uint32_t head_ = 0;
    bool open_ = false;
    bool overflow_ = false;
    std::array<Segment, k_journal_max_segments> seg_{};
    MutByteView buf_; // lent staging memory (see the constructor)
};

// Entry size on Flash for a payload of `len` bytes.
[[nodiscard]] constexpr uint32_t journal_entry_bytes(std::size_t len) {
    return static_cast<uint32_t>(k_journal_header + ((len + 3U) & ~3U));
}

} // namespace lm::store
