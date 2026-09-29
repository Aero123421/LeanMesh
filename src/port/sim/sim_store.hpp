// In-memory Store port for simulation. Contents survive SimNode::power_cut() (it models Flash);
// RAM state does not. The store slice adds power-cut injection at each durable boundary
// (docs/12 §4, POWER-* scenarios) on top of this: e.g. a write that is torn or lost when the cut
// is armed for that boundary. Sim evidence is never hardware power-cut evidence.
#pragma once

#include <cstdint>
#include <map>
#include <utility>
#include <vector>

#include "core/ports.hpp"

namespace lm::sim {

// Power-cut injection (docs/12 §4, POWER-*): every mutating call (slot_write, slot_erase,
// journal_write, journal_erase) has an index; a cut armed for index k fires when call k begins.
//   Before: the call has no effect.   Torn: it is applied partially (half of the bytes / half of
//   the segment erased).   After: it is fully applied.
// After the cut the "device is off": every call returns StorageFailure until power_restore().
enum class CutMode : uint8_t { Before, Torn, After };

struct StoreGeometry {
    uint32_t journal_segment_bytes = 4096;
    uint32_t journal_segments = 8;
};

class SimStore final : public port::Store {
  public:
    explicit SimStore(const StoreGeometry &g);

    [[nodiscard]] Status slot_read(uint16_t record, uint8_t slot, MutByteView out,
                                   std::size_t &len) override;
    [[nodiscard]] Status slot_write(uint16_t record, uint8_t slot, ByteView data) override;
    [[nodiscard]] Status slot_erase(uint16_t record, uint8_t slot) override;

    [[nodiscard]] uint32_t journal_segment_bytes() const override {
        return geometry_.journal_segment_bytes;
    }
    [[nodiscard]] uint32_t journal_segments() const override { return geometry_.journal_segments; }
    [[nodiscard]] Status journal_read(uint32_t offset, MutByteView out) override;
    [[nodiscard]] Status journal_write(uint32_t offset, ByteView data) override;
    [[nodiscard]] Status journal_erase(uint32_t segment) override;

    void arm_cut(uint64_t mutating_op_index, CutMode mode) {
        cut_armed_ = true;
        cut_index_ = mutating_op_index;
        cut_mode_ = mode;
    }
    void disarm_cut() { cut_armed_ = false; }
    [[nodiscard]] bool cut_fired() const { return dead_; }
    void power_restore() { dead_ = false; cut_armed_ = false; }
    [[nodiscard]] uint64_t mutating_ops() const { return op_count_; }

    // Counters for tests/diagnostics (Flash commits per hour etc., docs/16 §5).
    [[nodiscard]] uint64_t slot_writes() const { return slot_writes_; }
    [[nodiscard]] uint64_t journal_erases() const { return journal_erases_; }

  private:
    // Counts a mutating call; returns true when the armed cut fires on it (then `mode` is set).
    [[nodiscard]] bool begin_mutation(CutMode &mode);

    StoreGeometry geometry_;
    uint64_t op_count_ = 0;
    bool cut_armed_ = false;
    bool dead_ = false;
    uint64_t cut_index_ = 0;
    CutMode cut_mode_ = CutMode::Before;
    std::map<std::pair<uint16_t, uint8_t>, std::vector<uint8_t>> slots_;
    std::vector<uint8_t> journal_; // erased bytes are 0xFF, like NOR Flash
    uint64_t slot_writes_ = 0;
    uint64_t journal_erases_ = 0;
};

} // namespace lm::sim
