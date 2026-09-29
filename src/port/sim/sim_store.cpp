#include "port/sim/sim_store.hpp"

#include <algorithm>

namespace lm::sim {

SimStore::SimStore(const StoreGeometry &g)
    : geometry_(g),
      journal_(static_cast<std::size_t>(g.journal_segment_bytes) * g.journal_segments, 0xFF) {}

Status SimStore::slot_read(uint16_t record, uint8_t slot, MutByteView out, std::size_t &len) {
    len = 0;
    auto it = slots_.find({record, slot});
    if (it == slots_.end()) {
        return Status::NotFound;
    }
    if (it->second.size() > out.size()) {
        return Status::BufferTooSmall;
    }
    std::copy(it->second.begin(), it->second.end(), out.begin());
    len = it->second.size();
    return Status::Ok;
}

Status SimStore::slot_write(uint16_t record, uint8_t slot, ByteView data) {
    if (slot > 1) {
        return Status::InvalidArgument;
    }
    slots_[{record, slot}] = std::vector<uint8_t>(data.begin(), data.end());
    ++slot_writes_;
    return Status::Ok;
}

Status SimStore::slot_erase(uint16_t record, uint8_t slot) {
    slots_.erase({record, slot});
    return Status::Ok;
}

Status SimStore::journal_read(uint32_t offset, MutByteView out) {
    if (offset > journal_.size() || out.size() > journal_.size() - offset) {
        return Status::InvalidArgument;
    }
    std::copy_n(journal_.begin() + offset, out.size(), out.begin());
    return Status::Ok;
}

Status SimStore::journal_write(uint32_t offset, ByteView data) {
    if (offset > journal_.size() || data.size() > journal_.size() - offset) {
        return Status::InvalidArgument;
    }
    // NOR semantics: only erased bytes may be programmed.
    for (std::size_t i = 0; i < data.size(); ++i) {
        if (journal_[offset + i] != 0xFF) {
            return Status::StorageFailure;
        }
    }
    std::copy(data.begin(), data.end(), journal_.begin() + offset);
    return Status::Ok;
}

Status SimStore::journal_erase(uint32_t segment) {
    if (segment >= geometry_.journal_segments) {
        return Status::InvalidArgument;
    }
    const auto begin = static_cast<std::size_t>(segment) * geometry_.journal_segment_bytes;
    std::fill_n(journal_.begin() + static_cast<std::ptrdiff_t>(begin),
                geometry_.journal_segment_bytes, 0xFF);
    ++journal_erases_;
    return Status::Ok;
}

} // namespace lm::sim
