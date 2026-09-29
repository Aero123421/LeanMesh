#include "store/record.hpp"

#include <cstring>

#include "core/codec.hpp"
#include "core/ids.hpp"
#include "security/crypto.hpp"
#include "store/crc32.hpp"

namespace lm::store {
namespace {

constexpr uint8_t k_record_magic[4] = {'L', 'M', 'R', '1'};
constexpr uint8_t k_marker_magic[4] = {'L', 'M', 'K', '1'};

struct SlotInfo {
    bool valid = false; // record parses (magic, schema, length, CRC, SHA-256)
    uint8_t state = 0;
    uint32_t len = 0;
    uint64_t gen = 0;
    Sha256Digest hash{};
};

struct MarkerInfo {
    bool valid = false;
    uint8_t state = 0;
    uint64_t gen = 0;
    Sha256Digest hash{};
};

struct View {
    bool have = false; // a committed record exists
    uint8_t slot = 0;
    SlotInfo info;
    bool quarantined = false;
    uint64_t evidence = 0;
};

bool magic_is(Reader &r, const uint8_t (&m)[4]) {
    const ByteView v = r.bytes(4);
    return r.ok() && std::memcmp(v.data(), m, 4) == 0;
}

SlotInfo parse_record(ByteView blob) {
    SlotInfo s;
    if (blob.size() < k_header_bytes + k_crc_bytes) {
        return s;
    }
    Reader r(blob);
    if (!magic_is(r, k_record_magic) || r.u16be() != k_schema) {
        return s;
    }
    s.state = r.u8();
    if (r.u8() != 0) {
        return s;
    }
    s.gen = r.u64be();
    s.len = r.u32be();
    r.copy_to(s.hash);
    if (!r.ok() || s.gen == 0 || s.len > k_max_payload ||
        blob.size() != k_header_bytes + s.len + k_crc_bytes) {
        return SlotInfo{};
    }
    const ByteView payload = r.bytes(s.len);
    const uint32_t stored_crc = r.u32be();
    Sha256Digest actual{};
    if (!r.ok() || stored_crc != crc32(blob.first(blob.size() - k_crc_bytes)) ||
        sec::sha256(payload, actual) != Status::Ok || actual != s.hash) {
        return SlotInfo{};
    }
    s.valid = true;
    return s;
}

std::array<uint8_t, k_marker_bytes> build_marker(uint16_t id, uint8_t slot, const SlotInfo &s) {
    std::array<uint8_t, k_marker_bytes> out{};
    Writer w(out);
    w.bytes(ByteView{k_marker_magic, 4});
    w.u16be(id);
    w.u8(slot);
    w.u8(s.state);
    w.u64be(s.gen);
    w.bytes(ByteView{s.hash});
    w.u32be(crc32(w.written()));
    return out;
}

MarkerInfo parse_marker(ByteView blob, uint16_t id, uint8_t slot) {
    MarkerInfo m;
    if (blob.size() != k_marker_bytes) {
        return m;
    }
    Reader r(blob);
    if (!magic_is(r, k_marker_magic) || r.u16be() != id || r.u8() != slot) {
        return m;
    }
    m.state = r.u8();
    m.gen = r.u64be();
    r.copy_to(m.hash);
    const uint32_t stored_crc = r.u32be();
    m.valid = r.ok() && m.gen != 0 && stored_crc == crc32(blob.first(k_marker_bytes - k_crc_bytes));
    return m;
}

// Only NotFound is "empty". Garbage that fits is "no valid marker"; data that does not even fit
// the buffer is present-but-corrupt (`oversize`) and quarantines the record (FIX1-D10). A real
// read error is reported as StorageFailure (fail closed).
Status read_marker(port::Store &store, uint16_t id, uint8_t slot, MarkerInfo &out, bool &oversize) {
    std::array<uint8_t, k_marker_bytes> buf{};
    std::size_t len = 0;
    const Status st = store.slot_read(id | k_marker_flag, slot, buf, len);
    if (st == Status::NotFound || st == Status::BufferTooSmall) {
        out = MarkerInfo{};
        oversize = oversize || st == Status::BufferTooSmall;
        return Status::Ok;
    }
    if (st != Status::Ok) {
        return Status::StorageFailure;
    }
    out = parse_marker(ByteView{buf.data(), len}, id, slot);
    return Status::Ok;
}

// Reads one slot into job.scratch. `io_error` is set for a real read error, `oversize` for data
// larger than any valid blob (present but corrupt); an empty or garbage slot sets neither.
SlotInfo read_slot(port::Store &store, uint16_t id, uint8_t slot, RecordJob &job, bool &io_error,
                   bool &oversize) {
    std::size_t len = 0;
    const Status st = store.slot_read(id, slot, job.scratch, len);
    if (st == Status::Ok) {
        return parse_record(ByteView{job.scratch.data(), len});
    }
    if (st == Status::BufferTooSmall) {
        oversize = true;
    } else if (st != Status::NotFound) {
        io_error = true;
    }
    return SlotInfo{};
}

bool marker_matches(const SlotInfo &s, const MarkerInfo &m) {
    return s.valid && m.valid && s.gen == m.gen && s.state == m.state && s.hash == m.hash;
}

// Decides the committed state of a record id. Leaves the last slot read in job.scratch.
Status inspect(port::Store &store, uint16_t id, RecordJob &job, View &view) {
    view = View{};
    bool io_error = false;
    bool oversize = false;
    bool committed[2] = {false, false};
    SlotInfo slots[2];
    MarkerInfo markers[2];
    for (uint8_t s = 0; s < 2; ++s) {
        slots[s] = read_slot(store, id, s, job, io_error, oversize);
        LM_TRY(read_marker(store, id, s, markers[s], oversize));
        committed[s] = marker_matches(slots[s], markers[s]);
        if (committed[s] && (!view.have || slots[s].gen > view.info.gen)) {
            view.have = true;
            view.slot = s;
            view.info = slots[s];
        }
    }
    // A marker proves a commit finished. If its record is gone or damaged and its generation is
    // above every valid one, a higher generation existed: never fall back to the older slot.
    for (uint8_t s = 0; s < 2; ++s) {
        if (markers[s].valid && !committed[s] &&
            (!view.have || markers[s].gen > view.info.gen)) {
            view.quarantined = true;
            view.evidence = markers[s].gen > view.evidence ? markers[s].gen : view.evidence;
        }
    }
    // An oversized slot or marker may have been a newer generation: an older committed record must
    // not silently win, and "never committed" would be a lie.
    view.quarantined = view.quarantined || oversize;
    if (view.quarantined) {
        return Status::RecoveryRequired;
    }
    if (!view.have) {
        return io_error ? Status::StorageFailure : Status::NotFound;
    }
    return Status::Ok;
}

// Re-targets a job without building a second ~1 KiB RecordJob on the worker stack.
void reset_job(RecordJob &j, uint16_t id) {
    j.op = RecordJob::Op::Load;
    j.id = id;
    j.state = 0;
    j.payload_len = 0;
    j.generation = 0;
    j.evidence = 0;
}

bool id_ok(uint16_t id) { return id != 0 && id < k_marker_flag; }

Status commit_impl(port::Store &store, RecordJob &job, bool recover) {
    if (!id_ok(job.id) || job.payload_len > k_max_payload) {
        return Status::InvalidArgument;
    }
    View v;
    const Status cur = inspect(store, job.id, job, v);
    uint64_t base = 0;
    uint8_t target = 0;
    if (cur == Status::Ok) {
        base = v.info.gen;
        target = static_cast<uint8_t>(1 - v.slot);
    } else if (cur == Status::RecoveryRequired && recover) {
        base = v.evidence > v.info.gen || !v.have ? v.evidence : v.info.gen;
        target = v.have ? static_cast<uint8_t>(1 - v.slot) : 0;
    } else if (cur != Status::NotFound) {
        return cur;
    }
    if (base == UINT64_MAX) {
        return Status::RecoveryRequired; // generations never wrap
    }

    const ByteView payload{job.payload.data(), job.payload_len};
    SlotInfo want;
    want.valid = true;
    want.state = job.state;
    want.len = job.payload_len;
    want.gen = base + 1;
    LM_TRY(sec::sha256(payload, want.hash));

    Writer w(job.scratch);
    w.bytes(ByteView{k_record_magic, 4});
    w.u16be(k_schema);
    w.u8(want.state);
    w.u8(0);
    w.u64be(want.gen);
    w.u32be(want.len);
    w.bytes(ByteView{want.hash});
    w.bytes(payload);
    w.u32be(crc32(w.written()));
    LM_TRY(w.finish());
    const std::size_t blob_len = w.size();
    const auto marker = build_marker(job.id, target, want);

    LM_TRY(store.slot_write(job.id, target, ByteView{job.scratch.data(), blob_len}));
    std::size_t len = 0;
    LM_TRY(store.slot_read(job.id, target, job.scratch, len));
    const SlotInfo back = parse_record(ByteView{job.scratch.data(), len});
    if (!back.valid || back.gen != want.gen || back.hash != want.hash) {
        return Status::StorageFailure;
    }
    LM_TRY(store.slot_write(job.id | k_marker_flag, target, ByteView{marker}));
    std::array<uint8_t, k_marker_bytes> mback{};
    LM_TRY(store.slot_read(job.id | k_marker_flag, target, mback, len));
    if (!bytes_equal(ByteView{mback.data(), len}, ByteView{marker})) {
        return Status::StorageFailure;
    }
    job.generation = want.gen;
    return Status::Ok;
}

} // namespace

Status record_load(port::Store &store, RecordJob &job) {
    if (!id_ok(job.id)) {
        return Status::InvalidArgument;
    }
    View v;
    const Status st = inspect(store, job.id, job, v);
    job.evidence = v.evidence;
    if (st != Status::Ok) {
        return st;
    }
    // The last slot read may be the other one; read the winner again into the scratch.
    bool io_error = false;
    bool oversize = false;
    const SlotInfo again = read_slot(store, job.id, v.slot, job, io_error, oversize);
    if (!again.valid || again.gen != v.info.gen || again.hash != v.info.hash) {
        return Status::StorageFailure;
    }
    std::memcpy(job.payload.data(), job.scratch.data() + k_header_bytes, again.len);
    job.payload_len = again.len;
    job.state = again.state;
    job.generation = again.gen;
    return Status::Ok;
}

Status record_commit(port::Store &store, RecordJob &job) { return commit_impl(store, job, false); }
Status record_recover(port::Store &store, RecordJob &job) { return commit_impl(store, job, true); }

Status record_job(port::JobEnv &env, void *arg) {
    auto &job = *static_cast<RecordJob *>(arg);
    switch (job.op) {
    case RecordJob::Op::Load:
        return record_load(env.store, job);
    case RecordJob::Op::Commit:
        return record_commit(env.store, job);
    case RecordJob::Op::Recover:
        return record_recover(env.store, job);
    }
    return Status::InvalidArgument;
}

Status boot_incarnation_advance(port::Store &store, BootJob &job) {
    job.incarnation = 0;
    job.rec.id = rec::boot_incarnation;
    uint64_t current = 0;
    const Status st = record_load(store, job.rec);
    if (st == Status::Ok) {
        Reader r(ByteView{job.rec.payload.data(), job.rec.payload_len});
        current = r.u64be();
        if (r.finish() != Status::Ok) {
            return Status::RecoveryRequired; // committed but malformed: do not guess
        }
    } else if (st == Status::NotFound) {
        // Virgin only if the device was never provisioned. Provisioning commits this record (value
        // 0) before the identity; an identity without a counter means the counter was lost, and
        // starting again at 1 would reuse MessageId space (FIX1-D9).
        reset_job(job.rec, rec::identity);
        const Status idst = record_load(store, job.rec);
        reset_job(job.rec, rec::boot_incarnation);
        if (idst != Status::NotFound) {
            return idst == Status::StorageFailure ? idst : Status::RecoveryRequired;
        }
    } else {
        return st;
    }
    if (current == UINT64_MAX) {
        return Status::RecoveryRequired;
    }
    Writer w(job.rec.payload);
    w.u64be(current + 1);
    job.rec.payload_len = static_cast<uint32_t>(w.size());
    job.rec.state = 0;
    LM_TRY(record_commit(store, job.rec));
    job.incarnation = current + 1; // durable: only now may the caller use it
    return Status::Ok;
}

Status boot_job(port::JobEnv &env, void *arg) {
    return boot_incarnation_advance(env.store, *static_cast<BootJob *>(arg));
}

} // namespace lm::store
