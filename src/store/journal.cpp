#include "store/journal.hpp"

#include <cstring>

#include "core/codec.hpp"
#include "store/crc32.hpp"

namespace lm::store {
namespace {

constexpr uint16_t k_magic = 0xA55A;

struct Header {
    uint8_t kind = 0;
    uint16_t len = 0;
    uint32_t seq = 0;
    uint32_t id = 0;
    uint32_t crc = 0;
    bool blank = false; // all bytes erased
    bool valid = false; // structurally plausible (CRC checked after the payload is read)
};

Header parse_header(ByteView h, uint32_t room) {
    Header out;
    out.blank = true;
    for (uint8_t b : h) {
        out.blank = out.blank && b == 0xFF;
    }
    Reader r(h);
    const uint16_t magic = r.u16be();
    out.kind = r.u8();
    const uint8_t rsv1 = r.u8();
    out.len = r.u16be();
    const uint16_t rsv2 = r.u16be();
    out.seq = r.u32be();
    out.id = r.u32be();
    out.crc = r.u32be();
    out.valid = r.ok() && magic == k_magic && (out.kind == 1 || out.kind == 2) && rsv1 == 0 &&
                rsv2 == 0 && out.len <= k_journal_max_payload && out.seq != 0 &&
                (out.kind == 1 || out.len == 0) && journal_entry_bytes(out.len) <= room;
    return out;
}

// CRC over kind..id (header bytes 2..15) and the payload.
uint32_t entry_crc(ByteView header16, ByteView payload) {
    return crc32_update(crc32(header16.from(2)), payload);
}

} // namespace

JournalLive *Journal::find(uint32_t id) {
    for (std::size_t i = 0; i < live_; ++i) {
        if (index_[i].id == id) {
            return &index_[i];
        }
    }
    return nullptr;
}

uint32_t Journal::live_bytes_in(uint32_t seg) const {
    uint32_t total = 0;
    for (std::size_t i = 0; i < live_; ++i) {
        if (index_[i].segment == seg) {
            total += journal_entry_bytes(index_[i].len);
        }
    }
    return total;
}

uint32_t Journal::free_bytes_in_head() const { return seg_bytes_ - seg_[head_].tail; }

void Journal::apply_entry(uint8_t kind, uint32_t id, uint32_t seq, uint32_t offset, uint16_t len,
                          uint32_t seg) {
    JournalLive *e = find(id);
    if (kind == 2) {
        if (e != nullptr) {
            *e = index_[--live_];
        }
        return;
    }
    if (e == nullptr) {
        if (live_ >= capacity_) {
            overflow_ = true; // open() fails closed; apply() checks capacity beforehand
            return;
        }
        e = &index_[live_++];
    }
    *e = JournalLive{id, seq, offset, len, static_cast<uint16_t>(seg)};
}

// Programming over non-erased bytes fails, so a blank header must be followed by erased bytes.
Status Journal::rest_erased(port::Store &store, uint32_t offset, uint32_t bytes, bool &clean) {
    for (uint32_t done = 0; done < bytes && clean; done += static_cast<uint32_t>(buf_.size())) {
        const uint32_t n = bytes - done < buf_.size() ? bytes - done
                                                       : static_cast<uint32_t>(buf_.size());
        LM_TRY(store.journal_read(offset + done, MutByteView{buf_.data(), n}));
        for (uint32_t i = 0; i < n; ++i) {
            clean = clean && buf_[i] == 0xFF;
        }
    }
    return Status::Ok;
}

// Reads a segment entry by entry. Stops at the first erased header (tail) or at the first
// invalid/torn entry (the rest of that segment is unusable: tail = full).
Status Journal::scan_segment(port::Store &store, uint32_t seg, bool apply_entries) {
    Segment s;
    uint32_t off = 0;
    const uint32_t base = seg * seg_bytes_;
    while (true) {
        if (seg_bytes_ - off < k_journal_header) {
            s.tail = seg_bytes_;
            break;
        }
        std::array<uint8_t, k_journal_header> hb{};
        LM_TRY(store.journal_read(base + off, hb));
        const Header h = parse_header(hb, seg_bytes_ - off);
        if (h.blank) {
            s.tail = off;
            if (!apply_entries) {
                bool clean = true;
                LM_TRY(rest_erased(store, base + off, seg_bytes_ - off, clean));
                if (!clean) { // interrupted erase or foreign bytes: unusable until erased again
                    s.tail = seg_bytes_;
                    s.used = true;
                }
            }
            break;
        }
        s.used = true;
        bool ok = h.valid && h.seq > s.last_seq;
        if (ok) {
            LM_TRY(store.journal_read(base + off + k_journal_header,
                                      MutByteView{buf_.data(), h.len}));
            ok = h.crc == entry_crc(ByteView{hb.data(), 16}, ByteView{buf_.data(), h.len});
        }
        if (!ok) {
            s.tail = seg_bytes_;
            break;
        }
        s.last_seq = h.seq;
        if (apply_entries) {
            apply_entry(h.kind, h.id, h.seq, base + off, h.len, seg);
        }
        off += journal_entry_bytes(h.len);
    }
    seg_[seg] = s;
    return Status::Ok;
}

Status Journal::open(port::Store &store) {
    open_ = false;
    seg_bytes_ = store.journal_segment_bytes();
    nseg_ = store.journal_segments();
    if (nseg_ < 3 || nseg_ > k_journal_max_segments || seg_bytes_ % 4 != 0 ||
        seg_bytes_ < journal_entry_bytes(k_journal_max_payload)) {
        return Status::InvalidArgument;
    }
    live_ = 0;
    overflow_ = false;
    uint32_t max_seq = 0;
    head_ = 0;
    for (uint32_t i = 0; i < nseg_; ++i) { // pass 1: validity, tails, newest segment
        LM_TRY(scan_segment(store, i, false));
        if (seg_[i].last_seq > max_seq) {
            max_seq = seg_[i].last_seq;
            head_ = i;
        }
    }
    if (max_seq == UINT32_MAX) {
        return Status::NoCapacity; // sequence numbers never wrap
    }
    next_seq_ = max_seq + 1;
    for (uint32_t i = 1; i <= nseg_; ++i) { // pass 2: apply oldest to newest
        LM_TRY(scan_segment(store, (head_ + i) % nseg_, true));
    }
    if (overflow_) {
        live_ = 0;
        return Status::StorageFailure; // more live entries than this role can hold: fail closed
    }
    open_ = true;
    return reclaim(store, (head_ + 1) % nseg_); // finish an interrupted rotation
}

Status Journal::write_at_head(port::Store &store, ByteView buf) {
    Segment &h = seg_[head_];
    const Status st = store.journal_write(head_ * seg_bytes_ + h.tail, buf);
    if (st != Status::Ok) {
        h.tail = seg_bytes_; // unknown bytes may be programmed: never append behind them
        return st == Status::InvalidArgument ? st : Status::StorageFailure;
    }
    h.tail += static_cast<uint32_t>(buf.size());
    h.used = true;
    return Status::Ok;
}

// Copies the live entries of `seg` to the head (new seq) and erases it, if they fit. Index
// entries move only after their copy is durable, so a cut at any point leaves the originals valid.
Status Journal::reclaim(port::Store &store, uint32_t seg) {
    if (!seg_[seg].used || seg == head_) {
        return Status::Ok;
    }
    if (live_bytes_in(seg) > free_bytes_in_head()) {
        return Status::Ok; // cannot make progress now; nothing dropped
    }
    for (std::size_t i = 0; i < live_; ++i) {
        JournalLive &e = index_[i];
        if (e.segment != seg) {
            continue;
        }
        if (next_seq_ == UINT32_MAX) {
            return Status::NoCapacity;
        }
        LM_TRY(store.journal_read(e.offset, MutByteView{buf_.data(), journal_entry_bytes(e.len)}));
        // The source is trusted only after it matches the live index and its CRC: flash that rotted
        // after open() must not be re-sealed as valid. Fail with the source segment untouched.
        const Header src = parse_header(ByteView{buf_.data(), k_journal_header}, seg_bytes_);
        if (!src.valid || src.kind != 1 || src.id != e.id || src.seq != e.seq || src.len != e.len ||
            src.crc != entry_crc(ByteView{buf_.data(), 16},
                                 ByteView{buf_.data() + k_journal_header, e.len})) {
            return Status::StorageFailure;
        }
        Writer w(MutByteView{buf_.data(), k_journal_header});
        w.u16be(k_magic);
        w.u8(1);
        w.u8(0);
        w.u16be(e.len);
        w.u16be(0);
        w.u32be(next_seq_);
        w.u32be(e.id);
        w.u32be(entry_crc(ByteView{buf_.data(), 16}, ByteView{buf_.data() + k_journal_header, e.len}));
        const uint32_t at = head_ * seg_bytes_ + seg_[head_].tail;
        LM_TRY(write_at_head(store, ByteView{buf_.data(), journal_entry_bytes(e.len)}));
        e.segment = static_cast<uint16_t>(head_);
        e.offset = at;
        e.seq = next_seq_;
        seg_[head_].last_seq = next_seq_++;
    }
    LM_TRY(store.journal_erase(seg));
    seg_[seg] = Segment{};
    return Status::Ok;
}

Status Journal::make_room(port::Store &store, uint32_t need) {
    if (seg_[head_].tail + need <= seg_bytes_) {
        return Status::Ok;
    }
    const uint32_t next = (head_ + 1) % nseg_;
    if (seg_[next].used) {
        if (live_bytes_in(next) != 0) {
            return Status::NoCapacity; // oldest segment still holds ACKed entries: keep them
        }
        LM_TRY(store.journal_erase(next));
        seg_[next] = Segment{};
    }
    head_ = next;
    const uint32_t after = (next + 1) % nseg_;
    if (live_bytes_in(after) + need <= seg_bytes_) { // only reclaim when it leaves room to write
        LM_TRY(reclaim(store, after));
    }
    return seg_[head_].tail + need <= seg_bytes_ ? Status::Ok : Status::NoCapacity;
}

Status Journal::apply(port::Store &store, const JournalOp *ops, std::size_t count) {
    if (!open_ || count == 0) {
        return Status::InvalidArgument;
    }
    uint32_t total = 0;
    std::size_t added = 0;
    for (std::size_t i = 0; i < count; ++i) {
        if (ops[i].kind == JournalOp::Kind::Retire) {
            if (find(ops[i].id) == nullptr) {
                return Status::NotFound;
            }
        } else {
            if (ops[i].data.size() > k_journal_max_payload) {
                return Status::PayloadTooLarge;
            }
            bool fresh = find(ops[i].id) == nullptr;
            for (std::size_t j = 0; j < i; ++j) {
                fresh = fresh && !(ops[j].kind == JournalOp::Kind::Put && ops[j].id == ops[i].id);
            }
            added += fresh ? 1 : 0;
        }
        total += journal_entry_bytes(ops[i].kind == JournalOp::Kind::Put ? ops[i].data.size() : 0);
    }
    if (total > buf_.size()) {
        return Status::PayloadTooLarge;
    }
    if (live_ + added > capacity_ || next_seq_ > UINT32_MAX - count) {
        return Status::NoCapacity;
    }
    LM_TRY(make_room(store, total));

    Writer w(buf_);
    const uint32_t base = head_ * seg_bytes_ + seg_[head_].tail;
    for (std::size_t i = 0; i < count; ++i) {
        const std::size_t start = w.size();
        const std::size_t len = ops[i].kind == JournalOp::Kind::Put ? ops[i].data.size() : 0;
        w.u16be(k_magic);
        w.u8(static_cast<uint8_t>(ops[i].kind));
        w.u8(0);
        w.u16be(static_cast<uint16_t>(len));
        w.u16be(0);
        w.u32be(next_seq_ + static_cast<uint32_t>(i));
        w.u32be(ops[i].id);
        w.u32be(entry_crc(ByteView{buf_.data() + start, 16}, ops[i].data.first(len)));
        w.bytes(ops[i].data.first(len));
        w.zeros(journal_entry_bytes(len) - k_journal_header - len);
    }
    LM_TRY(w.finish());
    LM_TRY(write_at_head(store, w.written()));

    uint32_t off = base;
    for (std::size_t i = 0; i < count; ++i) {
        const std::size_t len = ops[i].kind == JournalOp::Kind::Put ? ops[i].data.size() : 0;
        apply_entry(static_cast<uint8_t>(ops[i].kind), ops[i].id,
                    next_seq_ + static_cast<uint32_t>(i), off, static_cast<uint16_t>(len), head_);
        off += journal_entry_bytes(len);
    }
    seg_[head_].last_seq = next_seq_ + static_cast<uint32_t>(count) - 1;
    next_seq_ += static_cast<uint32_t>(count);
    return Status::Ok;
}

Status Journal::read(port::Store &store, uint32_t id, MutByteView out, std::size_t &len) {
    len = 0;
    const JournalLive *e = find(id);
    if (!open_ || e == nullptr) {
        return Status::NotFound;
    }
    if (out.size() < e->len) {
        return Status::BufferTooSmall;
    }
    LM_TRY(store.journal_read(e->offset, MutByteView{buf_.data(), journal_entry_bytes(e->len)}));
    const Header h = parse_header(ByteView{buf_.data(), k_journal_header}, seg_bytes_);
    const ByteView payload{buf_.data() + k_journal_header, e->len};
    if (!h.valid || h.id != id || h.seq != e->seq || h.crc != entry_crc(ByteView{buf_.data(), 16}, payload)) {
        return Status::StorageFailure;
    }
    std::memcpy(out.data(), payload.data(), e->len);
    len = e->len;
    return Status::Ok;
}

} // namespace lm::store
