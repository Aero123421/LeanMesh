// STORE slice: sealed 2-slot records, boot incarnation and journal on the sim Store, with power-cut
// injection at every mutating Flash call (docs/12 §4). Sim evidence only: it is not a hardware
// power-cut or Flash-endurance result (docs/IMPLEMENTATION.md §9).
#include <cstdio>
#include <iterator>
#include <cstring>
#include <map>
#include <vector>

#include "lmtest.hpp"
#include "port/sim/sim_store.hpp"
#include "security/crypto.hpp"
#include "store/journal.hpp"
#include "store/record.hpp"

using namespace lm;
using namespace lm::sim;
using namespace lm::store;

namespace {

// Staging memory of the journals under test: batch-sized, so every batch the scripts build fits.
MutByteView journal_scratch() {
    static std::array<uint8_t, k_journal_batch_bytes> b{};
    return MutByteView{b.data(), b.size()};
}

constexpr CutMode k_modes[3] = {CutMode::Before, CutMode::Torn, CutMode::After};

const char *mode_name(CutMode m) {
    return m == CutMode::Before ? "before" : (m == CutMode::Torn ? "torn" : "after");
}

// The job memory is ~1.1 KiB: keep it off the test stack.
RecordJob &job() {
    static RecordJob j;
    return j;
}

void set_payload(uint8_t fill, uint32_t len, uint8_t state = 1) {
    RecordJob &j = job();
    j = RecordJob{};
    j.id = rec::membership;
    j.state = state;
    j.payload_len = len;
    std::memset(j.payload.data(), fill, len);
}

Status commit_fill(SimStore &s, uint8_t fill, uint32_t len = 40) {
    set_payload(fill, len);
    return record_commit(s, job());
}

struct Loaded {
    Status st;
    uint64_t gen;
    uint8_t fill;
    uint32_t len;
};

Loaded load(SimStore &s) {
    RecordJob &j = job();
    j = RecordJob{};
    j.id = rec::membership;
    Loaded l{record_load(s, j), j.generation, 0, j.payload_len};
    l.fill = l.st == Status::Ok && l.len > 0 ? j.payload[0] : 0;
    return l;
}

StoreGeometry small_geometry() {
    StoreGeometry g;
    g.journal_segment_bytes = 1024;
    g.journal_segments = 6;
    return g;
}

} // namespace

LM_TEST("setup crypto backend") { LM_CHECK_OK(sec::crypto_init()); }

// ---- sealed record: every cut point of a commit ------------------------------------------------

// Boundaries (docs/12 §2, in port-call order): write slot | write marker.
//   POWER-before-slot-write   = Before on the slot write     POWER-during-slot-write = Torn on it
//   POWER-after-slot-commit   = After on the slot write      POWER-before-marker     = Before on
//   the marker write          POWER-after-marker = After on the marker write (the only NEW state)
//   POWER-before-ack / -after-ack = the commit returned Ok (durable) and the cut follows.
LM_TEST("POWER-* record commit: one cut per boundary leaves exactly old or new") {
    for (int prior = 0; prior <= 3; ++prior) { // 0 = first ever commit; parities of the target slot
        SimStore base(small_geometry());
        for (int i = 1; i <= prior; ++i) {
            LM_CHECK_OK(commit_fill(base, static_cast<uint8_t>(i)));
        }
        SimStore probe = base;
        const uint64_t before = probe.mutating_ops();
        LM_CHECK_OK(commit_fill(probe, 0xC0));
        const uint64_t n_ops = probe.mutating_ops() - before;
        LM_CHECK_EQ(n_ops, 2); // slot write, marker write
        // before-ack / after-ack: durable on Ok, so the new record is what a reboot sees.
        const Loaded acked = load(probe);
        LM_CHECK(acked.st == Status::Ok && acked.gen == static_cast<uint64_t>(prior) + 1 &&
                 acked.fill == 0xC0);

        for (uint64_t k = 0; k < n_ops; ++k) {
            for (CutMode m : k_modes) {
                SimStore s = base;
                s.arm_cut(s.mutating_ops() + k, m);
                LM_CHECK(commit_fill(s, 0xC0) == Status::StorageFailure);
                LM_CHECK(s.cut_fired());
                LM_CHECK(load(s).st == Status::StorageFailure); // device is off: read error, not empty
                s.power_restore();
                const Loaded l = load(s);
                const bool is_new = k == 1 && m == CutMode::After;
                if (is_new) {
                    LM_CHECK(l.st == Status::Ok && l.gen == static_cast<uint64_t>(prior) + 1 &&
                             l.fill == 0xC0);
                } else if (prior == 0) {
                    LM_CHECK(l.st == Status::NotFound); // first commit never acknowledged
                } else {
                    LM_CHECK(l.st == Status::Ok && l.gen == static_cast<uint64_t>(prior) &&
                             l.fill == static_cast<uint8_t>(prior));
                }
                if (l.st != Status::NotFound) { // never quarantined by a torn commit
                    LM_CHECK(l.st == Status::Ok);
                }
                // The recovered store still commits, and never reuses the un-acked generation
                // for different content than what a later reader sees.
                LM_CHECK_OK(commit_fill(s, 0xD0));
                const Loaded next = load(s);
                LM_CHECK(next.st == Status::Ok && next.fill == 0xD0 &&
                         next.gen == (l.st == Status::Ok ? l.gen : 0) + 1);
            }
        }
    }
}

LM_TEST("POWER-* record commit: two consecutive cuts (fault during recovery commit)") {
    SimStore base(small_geometry());
    LM_CHECK_OK(commit_fill(base, 1));
    LM_CHECK_OK(commit_fill(base, 2));
    int cases = 0;
    for (uint64_t k1 = 0; k1 < 2; ++k1) {
        for (CutMode m1 : k_modes) {
            for (uint64_t k2 = 0; k2 < 2; ++k2) {
                for (CutMode m2 : k_modes) {
                    SimStore s = base;
                    s.arm_cut(s.mutating_ops() + k1, m1);
                    LM_CHECK(commit_fill(s, 3) == Status::StorageFailure);
                    s.power_restore();
                    s.arm_cut(s.mutating_ops() + k2, m2);
                    LM_CHECK(commit_fill(s, 4) == Status::StorageFailure);
                    s.power_restore();
                    const Loaded l = load(s);
                    LM_CHECK_OK(l.st);
                    // Only committed payloads can appear, never below the last acknowledged (2).
                    LM_CHECK(l.gen >= 2 && (l.fill == 2 || l.fill == 3 || l.fill == 4));
                    LM_CHECK(l.gen == 2 ? l.fill == 2 : true);
                    ++cases;
                }
            }
        }
    }
    LM_CHECK_EQ(cases, 36);
}

// ---- quarantine, read errors, generations ------------------------------------------------------

LM_TEST("S05 higher-generation evidence with a damaged record quarantines, never rolls back") {
    SimStore s(small_geometry());
    LM_CHECK_OK(commit_fill(s, 1)); // gen 1 -> slot 0
    LM_CHECK_OK(commit_fill(s, 2)); // gen 2 -> slot 1
    SimStore lost = s;
    SimStore torn = s;

    // Record of the newest slot damaged (one flipped byte): marker still proves generation 2.
    std::vector<uint8_t> blob(k_max_blob);
    std::size_t len = 0;
    LM_CHECK_OK(torn.slot_read(rec::membership, 1, MutByteView{blob.data(), blob.size()}, len));
    blob[k_header_bytes + 3] ^= 0x01;
    LM_CHECK_OK(torn.slot_write(rec::membership, 1, ByteView{blob.data(), len}));
    // Record of the newest slot missing entirely.
    LM_CHECK_OK(lost.slot_erase(rec::membership, 1));

    for (SimStore *x : {&torn, &lost}) {
        const Loaded l = load(*x);
        LM_CHECK(l.st == Status::RecoveryRequired);
        LM_CHECK_EQ(job().evidence, 2);
        LM_CHECK(commit_fill(*x, 9) == Status::RecoveryRequired); // no silent overwrite
        set_payload(7, 10);
        LM_CHECK_OK(record_recover(*x, job())); // after a verified recovery object (caller's job)
        LM_CHECK_EQ(job().generation, 3);
        const Loaded r = load(*x);
        LM_CHECK(r.st == Status::Ok && r.gen == 3 && r.fill == 7);
    }
}

LM_TEST("read error is not unprovisioned; empty store is NotFound") {
    SimStore s(small_geometry());
    LM_CHECK(load(s).st == Status::NotFound);
    LM_CHECK_OK(commit_fill(s, 1));
    s.arm_cut(s.mutating_ops(), CutMode::Before);
    LM_CHECK(commit_fill(s, 2) == Status::StorageFailure); // device off: every read fails
    LM_CHECK(load(s).st == Status::StorageFailure);
    s.power_restore();
    LM_CHECK(load(s).st == Status::Ok);
}

LM_TEST("FIX1-10 an oversized slot or marker is corruption, never 'absent' or 'unprovisioned'") {
    const std::vector<uint8_t> huge(k_max_blob + 1, 0x5A);
    // Empty store + an oversized slot: not NotFound (which would let a device look virgin).
    {
        SimStore s(small_geometry());
        LM_CHECK_OK(s.slot_write(rec::membership, 0, ByteView{huge.data(), huge.size()}));
        LM_CHECK(load(s).st == Status::RecoveryRequired);
    }
    // A committed older record must not win over an oversized (possibly newer) slot.
    for (const uint16_t id_flag : {uint16_t{0}, k_marker_flag}) {
        SimStore s(small_geometry());
        LM_CHECK_OK(commit_fill(s, 1));
        LM_CHECK_OK(commit_fill(s, 2)); // generation 2 lives in slot 1
        LM_CHECK_OK(s.slot_erase(rec::membership | id_flag, 1));
        LM_CHECK_OK(s.slot_write(rec::membership | id_flag, 1, ByteView{huge.data(), huge.size()}));
        const Loaded l = load(s);
        LM_CHECK(l.st == Status::RecoveryRequired); // not Ok(gen 1) and not NotFound
        // A fleet-verified recovery may then move forward, above the surviving generation.
        set_payload(9, 8);
        job().op = RecordJob::Op::Recover;
        LM_CHECK_OK(record_recover(s, job()));
        LM_CHECK(job().generation > 1);
        LM_CHECK_EQ(load(s).fill, 9);
    }
}

LM_TEST("FIX1-9 a provisioned device that lost its boot counter is RecoveryRequired, not incarnation 1") {
    static BootJob b;
    SimStore s(small_geometry());
    // Virgin store: no identity, no counter -> the first incarnation is 1.
    b = BootJob{};
    LM_CHECK_OK(boot_incarnation_advance(s, b));
    LM_CHECK_EQ(b.incarnation, 1);
    // Provisioned (counter floor, then identity) and running: counter 2, 3.
    SimStore p(small_geometry());
    RecordJob &j = job();
    j = RecordJob{};
    j.id = rec::boot_incarnation;
    j.payload_len = 8; // u64be(0), the provisioning floor
    LM_CHECK_OK(record_commit(p, j));
    j = RecordJob{};
    j.id = rec::identity;
    j.payload_len = 4;
    LM_CHECK_OK(record_commit(p, j));
    b = BootJob{};
    LM_CHECK_OK(boot_incarnation_advance(p, b));
    LM_CHECK_EQ(b.incarnation, 1);
    b = BootJob{};
    LM_CHECK_OK(boot_incarnation_advance(p, b));
    LM_CHECK_EQ(b.incarnation, 2);
    // Partial store loss: both counter slots and markers vanish, the identity stays.
    for (uint8_t slot = 0; slot < 2; ++slot) {
        LM_CHECK_OK(p.slot_erase(rec::boot_incarnation, slot));
        LM_CHECK_OK(p.slot_erase(rec::boot_incarnation | k_marker_flag, slot));
    }
    b = BootJob{};
    LM_CHECK(boot_incarnation_advance(p, b) == Status::RecoveryRequired);
    LM_CHECK_EQ(b.incarnation, 0); // nothing was handed out
}

LM_TEST("record argument limits") {
    SimStore s(small_geometry());
    set_payload(1, k_max_payload);
    LM_CHECK_OK(record_commit(s, job()));
    set_payload(1, 0);
    LM_CHECK_OK(record_commit(s, job())); // empty payload is a valid record
    job().payload_len = static_cast<uint32_t>(k_max_payload + 1);
    LM_CHECK(record_commit(s, job()) == Status::InvalidArgument);
    job().payload_len = 1;
    job().id = 0;
    LM_CHECK(record_commit(s, job()) == Status::InvalidArgument);
    job().id = k_marker_flag;
    LM_CHECK(record_commit(s, job()) == Status::InvalidArgument);
}

// ---- boot incarnation --------------------------------------------------------------------------

LM_TEST("POWER-* boot incarnation is durable before use and strictly increasing across cuts") {
    static BootJob b;
    for (uint64_t k = 0; k < 2; ++k) {
        for (CutMode m : k_modes) {
            SimStore s(small_geometry());
            uint64_t highest_used = 0;
            for (int boot = 0; boot < 4; ++boot) {
                b = BootJob{};
                port::JobEnv env{s};
                LM_CHECK_OK(boot_job(env, &b)); // JobFn path
                LM_CHECK(b.incarnation > highest_used);
                highest_used = b.incarnation;
            }
            LM_CHECK_EQ(highest_used, 4);
            s.arm_cut(s.mutating_ops() + k, m);
            b = BootJob{};
            LM_CHECK(boot_incarnation_advance(s, b) == Status::StorageFailure);
            LM_CHECK_EQ(b.incarnation, 0); // never handed out
            s.power_restore();
            b = BootJob{};
            LM_CHECK_OK(boot_incarnation_advance(s, b));
            // 5 was possibly persisted (after-marker) but never used: skipping it is fine.
            LM_CHECK(b.incarnation == 5 || b.incarnation == 6);
            LM_CHECK(b.incarnation == (k == 1 && m == CutMode::After ? 6 : 5));
        }
    }
}

// ---- journal -----------------------------------------------------------------------------------

namespace {

using Model = std::map<uint32_t, std::vector<uint8_t>>;

struct Op {
    JournalOp::Kind kind;
    uint32_t id;
    std::vector<uint8_t> data;
};

constexpr std::size_t k_cap = 6;

struct Rng {
    uint64_t s = 0x1234567;
    uint32_t next() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        return static_cast<uint32_t>(s >> 11);
    }
};

void apply_model(Model &m, const Op &op) {
    if (op.kind == JournalOp::Kind::Put) {
        m[op.id] = op.data;
    } else {
        m.erase(op.id);
    }
}

Status run_batch(SimStore &s, Journal &j, const std::vector<Op> &ops) {
    std::vector<JournalOp> v;
    for (const Op &o : ops) {
        v.push_back(JournalOp{o.kind, o.id, ByteView{o.data.data(), o.data.size()}});
    }
    return j.apply(s, v.data(), v.size());
}

Model recover_model(SimStore &s, Journal &j) {
    Model m;
    LM_CHECK_OK(j.open(s));
    for (std::size_t i = 0; i < j.live_count(); ++i) {
        std::vector<uint8_t> buf(k_journal_max_payload);
        std::size_t len = 0;
        LM_CHECK_OK(j.read(s, j.live_at(i).id, MutByteView{buf.data(), buf.size()}, len));
        buf.resize(len);
        m[j.live_at(i).id] = buf;
    }
    return m;
}

struct Run {
    Model acked;
    std::vector<Op> inflight;
    int nocap = 0;
    int notfound = 0;
    int batches = 0;
};

// Deterministic workload: id 100 lives forever (forces compaction), others churn with 40..500 B
// payloads so segments rotate many times. Stops at the first StorageFailure (a cut).
Run run_script(SimStore &s, Journal &j) {
    Run r;
    Rng rng;
    for (int i = 0; i < 80; ++i) {
        std::vector<Op> ops;
        const int count = 1 + static_cast<int>(rng.next() % 2);
        Model pre = r.acked;
        for (int c = 0; c < count; ++c) {
            const uint32_t roll = rng.next();
            Op op{JournalOp::Kind::Put, 0, {}};
            const bool retire = !pre.empty() && (roll % 3 == 0 || pre.size() >= k_cap);
            if (retire) {
                // first churn id at or after a random position (id 100 is never retired)
                auto it = pre.lower_bound(roll % 8);
                if (it == pre.end() || it->first == 100) {
                    it = pre.begin()->first == 100 ? std::next(pre.begin()) : pre.begin();
                }
                if (it != pre.end()) {
                    op.kind = JournalOp::Kind::Retire;
                    op.id = it->first;
                    pre.erase(it);
                    ops.push_back(op);
                    continue;
                }
            }
            op.id = i == 0 && c == 0 ? 100 : 1 + roll % 8;
            op.data.assign(40 + rng.next() % 260, static_cast<uint8_t>(i + 1));
            pre[op.id] = op.data;
            ops.push_back(op);
        }
        // A batch may hold a Retire of an id Put in the same batch: not allowed by the API, so
        // the model only retires ids live before the batch (pre is updated in step, so filter).
        const Status st = run_batch(s, j, ops);
        if (st == Status::Ok) {
            for (const Op &o : ops) {
                apply_model(r.acked, o);
            }
        } else if (st == Status::NoCapacity) {
            ++r.nocap;
        } else if (st == Status::NotFound) { // Retire of an id Put in the same batch: rejected
            ++r.notfound;
        } else {
            r.inflight = ops;
            return r;
        }
        ++r.batches;
    }
    return r;
}

} // namespace

LM_TEST("POWER-* journal: cut at every mutating call keeps ACKed entries, never a partial one") {
    static std::array<JournalLive, k_cap> idx;
    Journal ref(idx.data(), idx.size(), journal_scratch());
    SimStore refstore(small_geometry());
    LM_CHECK_OK(ref.open(refstore));
    const Run full = run_script(refstore, ref);
    const uint64_t total_ops = refstore.mutating_ops();
    std::printf("  journal script: %d batches, %d NoCapacity, %d NotFound, %llu mutating calls, "
                "%llu segment erases\n",
                full.batches, full.nocap, full.notfound, static_cast<unsigned long long>(total_ops),
                static_cast<unsigned long long>(refstore.journal_erases()));
    LM_CHECK(refstore.journal_erases() >= 8); // several full rotations happened
    LM_CHECK(full.acked.count(100) == 1);     // the long-lived entry survived every compaction
    {
        std::array<JournalLive, k_cap> idx2;
        Journal again(idx2.data(), idx2.size(), journal_scratch());
        LM_CHECK(recover_model(refstore, again) == full.acked); // clean reopen == acked state
    }

    int cases = 0;
    for (uint64_t k = 0; k < total_ops; ++k) {
        for (CutMode m : k_modes) {
            SimStore s(small_geometry());
            std::array<JournalLive, k_cap> a;
            Journal j(a.data(), a.size(), journal_scratch());
            LM_CHECK_OK(j.open(s));
            s.arm_cut(k, m);
            const Run r = run_script(s, j);
            if (!s.cut_fired()) {
                // reclaim ran inside open() of an earlier cut is impossible here: script must fire
                LM_CHECK(false);
                continue;
            }
            s.power_restore();
            std::array<JournalLive, k_cap> b;
            Journal j2(b.data(), b.size(), journal_scratch());
            const Model got = recover_model(s, j2);
            // Recovered == acked + some prefix of the in-flight batch (entries are atomic, the
            // batch is one write that may tear between entries).
            bool ok = false;
            Model cand = r.acked;
            for (std::size_t p = 0; p <= r.inflight.size() && !ok; ++p) {
                ok = cand == got;
                if (p < r.inflight.size()) {
                    apply_model(cand, r.inflight[p]);
                }
            }
            if (!ok) {
                std::fprintf(stderr, "  counterexample: cut op %llu mode %s\n",
                             static_cast<unsigned long long>(k), mode_name(m));
            }
            LM_CHECK(ok);
            // The recovered journal accepts new work (or reports NoCapacity), never corrupts.
            const std::vector<uint8_t> tail(64, 0xEE);
            const Op after{JournalOp::Kind::Put, 7, tail};
            const Status st = run_batch(s, j2, {after});
            LM_CHECK(st == Status::Ok || st == Status::NoCapacity);
            if (st == Status::Ok) {
                Model want = got;
                apply_model(want, after);
                std::array<JournalLive, k_cap> c;
                Journal j3(c.data(), c.size(), journal_scratch());
                LM_CHECK(recover_model(s, j3) == want);
            }
            ++cases;
        }
    }
    LM_CHECK_EQ(cases, static_cast<int>(total_ops) * 3);
    std::printf("  journal cut cases: %d\n", cases);
}

LM_TEST("journal full returns NO_CAPACITY and never drops an ACKed entry") {
    SimStore s(small_geometry()); // 6 x 1 KiB
    static std::array<JournalLive, 64> idx;
    Journal j(idx.data(), idx.size(), journal_scratch());
    LM_CHECK_OK(j.open(s));
    Model acked;
    uint32_t id = 1;
    Status st = Status::Ok;
    while (true) {
        const Op op{JournalOp::Kind::Put, id, std::vector<uint8_t>(500, static_cast<uint8_t>(id))};
        st = run_batch(s, j, {op});
        if (st != Status::Ok) {
            break;
        }
        apply_model(acked, op);
        ++id;
        LM_CHECK(id < 100); // must fill up
    }
    LM_CHECK(st == Status::NoCapacity);
    LM_CHECK(acked.size() >= 3);
    std::array<JournalLive, 64> idx2;
    Journal j2(idx2.data(), idx2.size(), journal_scratch());
    LM_CHECK(recover_model(s, j2) == acked);
    // Retiring frees space for new durable entries.
    const Op gone{JournalOp::Kind::Retire, 1, {}};
    LM_CHECK_OK(run_batch(s, j2, {gone}));
    apply_model(acked, gone);
    const Op fresh{JournalOp::Kind::Put, 500, std::vector<uint8_t>(500, 0x55)};
    LM_CHECK_OK(run_batch(s, j2, {fresh}));
    apply_model(acked, fresh);
    std::array<JournalLive, 64> idx3;
    Journal j3(idx3.data(), idx3.size(), journal_scratch());
    LM_CHECK(recover_model(s, j3) == acked);
    // Unknown retire and oversized payload are rejected before anything is written.
    const uint64_t ops = s.mutating_ops();
    LM_CHECK(run_batch(s, j3, {Op{JournalOp::Kind::Retire, 9999, {}}}) == Status::NotFound);
    LM_CHECK(run_batch(s, j3, {Op{JournalOp::Kind::Put, 5, std::vector<uint8_t>(513, 1)}}) ==
             Status::PayloadTooLarge);
    LM_CHECK_EQ(s.mutating_ops(), ops);
}

LM_TEST("FIX1-11 reclaim refuses to re-seal a live entry that decayed after open(); source is kept") {
    SimStore s(small_geometry()); // 6 x 1 KiB segments
    static std::array<JournalLive, 8> idx;
    Journal j(idx.data(), idx.size(), journal_scratch());
    LM_CHECK_OK(j.open(s));
    const std::vector<uint8_t> victim(100, 0x11);
    LM_CHECK_OK(run_batch(s, j, {Op{JournalOp::Kind::Put, 1, victim}}));
    // Flash decay of the live entry's payload after open(): the CRC no longer matches.
    uint32_t victim_at = 0;
    for (std::size_t i = 0; i < j.live_count(); ++i) {
        if (j.live_at(i).id == 1) {
            victim_at = j.live_at(i).offset;
        }
    }
    s.corrupt_journal_byte(victim_at + k_journal_header + 7, 0x01);
    // Keep writing other data until the head wraps around to reclaim the victim's segment.
    Status st = Status::Ok;
    for (int n = 0; n < 40 && st == Status::Ok; ++n) {
        st = run_batch(s, j, {Op{JournalOp::Kind::Put, 2, std::vector<uint8_t>(500, static_cast<uint8_t>(n))}});
    }
    LM_CHECK(st == Status::StorageFailure); // reclaim noticed; it did not "launder" the entry
    // The corrupt source segment was not erased, and the decay is still visible, never valid data.
    std::vector<uint8_t> out(600);
    std::size_t len = 0;
    LM_CHECK(j.read(s, 1, MutByteView{out.data(), out.size()}, len) == Status::StorageFailure);
    LM_CHECK(s.journal_erases() < 6); // the victim's segment survives for repair/inspection
}

LM_TEST("journal live table limit is NO_CAPACITY (durable pending bound)") {
    SimStore s(StoreGeometry{});
    std::array<JournalLive, 3> idx;
    Journal j(idx.data(), idx.size(), journal_scratch());
    LM_CHECK_OK(j.open(s));
    for (uint32_t id = 1; id <= 3; ++id) {
        LM_CHECK_OK(run_batch(s, j, {Op{JournalOp::Kind::Put, id, {1, 2, 3}}}));
    }
    LM_CHECK(run_batch(s, j, {Op{JournalOp::Kind::Put, 4, {4}}}) == Status::NoCapacity);
    LM_CHECK_OK(run_batch(s, j, {Op{JournalOp::Kind::Put, 2, {9, 9}}})); // replace is fine
    // The table bound is checked before writing (a Retire in the same batch does not count).
    LM_CHECK(run_batch(s, j, {Op{JournalOp::Kind::Retire, 3, {}}, Op{JournalOp::Kind::Put, 4, {4}}}) ==
             Status::NoCapacity);
    LM_CHECK_OK(run_batch(s, j, {Op{JournalOp::Kind::Retire, 3, {}}}));
    LM_CHECK_OK(run_batch(s, j, {Op{JournalOp::Kind::Put, 4, {4}}}));
    LM_CHECK_EQ(j.live_count(), 3);
    // One write for a whole batch (20 ms window is the owner's collection time).
    const uint64_t ops = s.mutating_ops();
    LM_CHECK_OK(run_batch(s, j, {Op{JournalOp::Kind::Put, 1, {7}}, Op{JournalOp::Kind::Retire, 2, {}}}));
    LM_CHECK_EQ(s.mutating_ops() - ops, 1);
}

LM_TEST("journal staging memory: one largest entry is the minimum, a batch never exceeds the lent scratch") {
    SimStore s(StoreGeometry{});
    std::array<JournalLive, 4> idx;
    std::array<uint8_t, k_journal_min_scratch> scratch{};
    Journal small(idx.data(), idx.size(), MutByteView{scratch.data(), scratch.size() - 1});
    LM_CHECK(small.open(s) == Status::InvalidArgument); // cannot hold one entry: refused, not truncated
    Journal j(idx.data(), idx.size(), MutByteView{scratch.data(), scratch.size()});
    LM_CHECK_OK(j.open(s));
    LM_CHECK_OK(run_batch(s, j, {Op{JournalOp::Kind::Put, 1, std::vector<uint8_t>(k_journal_max_payload, 5)}}));
    LM_CHECK(run_batch(s, j, {Op{JournalOp::Kind::Put, 2, std::vector<uint8_t>(300, 6)},
                              Op{JournalOp::Kind::Put, 3, std::vector<uint8_t>(300, 7)}}) == Status::PayloadTooLarge);
    std::vector<uint8_t> out(k_journal_max_payload);
    std::size_t len = 0;
    LM_CHECK_OK(j.read(s, 1, MutByteView{out.data(), out.size()}, len));
    LM_CHECK(len == k_journal_max_payload && out == std::vector<uint8_t>(k_journal_max_payload, 5));
}

LM_TEST("sizeof store structures (informational)") {
    std::printf("  RecordJob=%zu BootJob=%zu Journal=%zu JournalLive=%zu (x capacity)\n",
                sizeof(RecordJob), sizeof(BootJob), sizeof(Journal), sizeof(JournalLive));
}

LM_TEST_MAIN()
