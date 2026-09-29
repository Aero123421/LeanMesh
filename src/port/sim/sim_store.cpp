#include "port/sim/sim_store.hpp"

#include <algorithm>

namespace lm::sim {

SimStore::SimStore(const StoreGeometry &g)
    : geometry_(g),
      journal_(static_cast<std::size_t>(g.journal_segment_bytes) * g.journal_segments, 0xFF) {}

bool SimStore::begin_mutation(CutMode &mode) {
    const bool fire = cut_armed_ && op_count_ == cut_index_;
    ++op_count_;
    if (fire) {
        mode = cut_mode_;
        cut_armed_ = false;
        dead_ = true;
    }
    return fire;
}

Status SimStore::slot_read(uint16_t record, uint8_t slot, MutByteView out, std::size_t &len) {
    len = 0;
    if (dead_) {
        return Status::StorageFailure;
    }
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
    if (dead_) {
        return Status::StorageFailure;
    }
    CutMode mode = CutMode::Before;
    if (begin_mutation(mode)) {
        if (mode == CutMode::Torn) {
            slots_[{record, slot}] = std::vector<uint8_t>(data.begin(), data.begin() + data.size() / 2);
        } else if (mode == CutMode::After) {
            slots_[{record, slot}] = std::vector<uint8_t>(data.begin(), data.end());
        }
        return Status::StorageFailure;
    }
    slots_[{record, slot}] = std::vector<uint8_t>(data.begin(), data.end());
    ++slot_writes_;
    return Status::Ok;
}

Status SimStore::slot_erase(uint16_t record, uint8_t slot) {
    if (dead_) {
        return Status::StorageFailure;
    }
    CutMode mode = CutMode::Before;
    if (begin_mutation(mode)) {
        if (mode == CutMode::After) {
            slots_.erase({record, slot});
        }
        return Status::StorageFailure; // NVS key erase is atomic: Torn == Before
    }
    slots_.erase({record, slot});
    return Status::Ok;
}

Status SimStore::journal_read(uint32_t offset, MutByteView out) {
    if (dead_) {
        return Status::StorageFailure;
    }
    if (offset > journal_.size() || out.size() > journal_.size() - offset) {
        return Status::InvalidArgument;
    }
    std::copy_n(journal_.begin() + offset, out.size(), out.begin());
    return Status::Ok;
}

Status SimStore::journal_write(uint32_t offset, ByteView data) {
    if (dead_) {
        return Status::StorageFailure;
    }
    if (offset > journal_.size() || data.size() > journal_.size() - offset) {
        return Status::InvalidArgument;
    }
    // NOR semantics: only erased bytes may be programmed.
    for (std::size_t i = 0; i < data.size(); ++i) {
        if (journal_[offset + i] != 0xFF) {
            return Status::StorageFailure;
        }
    }
    CutMode mode = CutMode::Before;
    const bool cut = begin_mutation(mode);
    std::size_t n = data.size();
    if (cut) {
        n = mode == CutMode::Torn ? n / 2 : (mode == CutMode::After ? n : 0);
    }
    std::copy_n(data.begin(), n, journal_.begin() + offset);
    return cut ? Status::StorageFailure : Status::Ok;
}

Status SimStore::journal_erase(uint32_t segment) {
    if (segment >= geometry_.journal_segments) {
        return Status::InvalidArgument;
    }
    if (dead_) {
        return Status::StorageFailure;
    }
    CutMode mode = CutMode::Before;
    const bool cut = begin_mutation(mode);
    const auto begin = static_cast<std::size_t>(segment) * geometry_.journal_segment_bytes;
    std::size_t n = geometry_.journal_segment_bytes;
    if (cut) {
        n = mode == CutMode::Torn ? n / 2 : (mode == CutMode::After ? n : 0);
    }
    std::fill_n(journal_.begin() + static_cast<std::ptrdiff_t>(begin), n, 0xFF);
    ++journal_erases_;
    return cut ? Status::StorageFailure : Status::Ok;
}

} // namespace lm::sim
