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

    // Counters for tests/diagnostics (Flash commits per hour etc., docs/16 §5).
    [[nodiscard]] uint64_t slot_writes() const { return slot_writes_; }
    [[nodiscard]] uint64_t journal_erases() const { return journal_erases_; }

  private:
    StoreGeometry geometry_;
    std::map<std::pair<uint16_t, uint8_t>, std::vector<uint8_t>> slots_;
    std::vector<uint8_t> journal_; // erased bytes are 0xFF, like NOR Flash
    uint64_t slot_writes_ = 0;
    uint64_t journal_erases_ = 0;
};

} // namespace lm::sim
