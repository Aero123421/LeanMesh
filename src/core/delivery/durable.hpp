// The durable side of delivery (docs/12 §3): boot incarnation, journal open and every journal
// Put/Retire/Read as slow jobs on the worker. The owner never touches the journal or the job
// memory while a job is in flight (zombie rule, docs/IMPLEMENTATION.md §3). One job at a time; the
// other writers wait in a bounded queue and their record is built when their turn comes, so the
// journal always gets the newest state of a slot. Ok from a job means durable (docs/12 §2).
//
// Record ids are per slot (S9-D6): out = 0x01000000 | slot, in = 0x02000000 | slot. A slot has at
// most one live record, so the journal's live table can never exceed the slot counts.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/jobs.hpp"
#include "core/pool.hpp"
#include "core/profile.hpp"
#include "core/ring.hpp"
#include "store/journal.hpp"
#include "store/record.hpp"

namespace lm {
class Engine;
}

namespace lm::delivery {

inline constexpr uint32_t k_id_out = 0x01000000U;
inline constexpr uint32_t k_id_in = 0x02000000U;
inline constexpr std::size_t k_journal_entries = k_build_limits.app_messages + k_build_limits.receipts;

struct DurableReq {
    enum class Op : uint8_t { Put, Retire };
    Op op = Op::Put;
    uint32_t id = 0;
    uint32_t gen = 0;     // generation of the owner slot (a reused slot must not inherit the result)
    uint32_t version = 0; // owner's record version this write is meant to make durable
};

class Durable {
  public:
    struct Hooks {
        void *ctx = nullptr;
        // Builds the record of `req` (Put). A non-Ok status cancels the write (reported to done()).
        Status (*fill)(void *ctx, const DurableReq &req, MutByteView out, std::size_t &len) = nullptr;
        // Completion of a Put/Retire (Ok = durable) and of Read (record in read_data()).
        void (*done)(void *ctx, const DurableReq &req, Status st, MonoTime now) = nullptr;
        void (*boot_done)(void *ctx, Status st, MonoTime now) = nullptr;
        void (*read_done)(void *ctx, uint32_t id, Status st, ByteView record, MonoTime now) = nullptr;
    };

    // The journal stages its entries in the boot job's record scratch (one job at a time uses it).
    explicit Durable(Engine &engine)
        : engine_(engine), journal_(index_.data(), index_.size(), MutByteView{boot_.rec.scratch}) {}
    void set_hooks(const Hooks &h) { hooks_ = h; }

    // Advances the boot incarnation and opens the journal (one job). Busy while an older job of a
    // stopped engine still owns the memory.
    [[nodiscard]] Status begin_boot();
    [[nodiscard]] bool ready() const { return state_ == State::Ready; }
    [[nodiscard]] bool failed() const { return state_ == State::Failed; }
    [[nodiscard]] uint64_t incarnation() const { return incarnation_; }
    [[nodiscard]] std::size_t live_count() const { return journal_.live_count(); }
    [[nodiscard]] uint32_t live_id(std::size_t i) const { return journal_.live_at(i).id; }

    // Queues a write. False: queue full (the caller keeps its "wanted" flag and asks again).
    [[nodiscard]] bool enqueue(const DurableReq &req, MonoTime now);
    // Reads one live record (recovery). Busy while a job runs.
    [[nodiscard]] Status read(uint32_t id);

    void on_job_done(Handle slot, Status s, MonoTime now);
    // Runs the next queued write when idle.
    void pump(MonoTime now);
    // Engine stop: forget queued writes; a job in flight keeps the memory reserved.
    void stop();
    [[nodiscard]] bool job_pending() const { return job_ != Job::None; }
    [[nodiscard]] std::size_t queued() const { return queue_.size(); }

  private:
    enum class State : uint8_t { Off, Booting, Ready, Failed };
    enum class Job : uint8_t { None, Boot, Put, Retire, Read };

    static Status job_entry(port::JobEnv &env, void *arg);
    Status submit(Job j);

    Engine &engine_;
    Hooks hooks_;
    State state_ = State::Off;
    Job job_ = Job::None;
    bool cancelled_ = false;
    Handle handle_;
    uint32_t handle_gen_ = 0;
    uint64_t incarnation_ = 0;

    std::array<store::JournalLive, k_journal_entries> index_{};
    // Job memory: BootJob is the largest scratch (RecordJob payload + read/verify buffer). The
    // journal jobs borrow it instead of adding their own: the record is built in its payload and
    // staged by the journal in its scratch (declared before journal_, which holds a view of it).
    store::BootJob boot_;
    store::Journal journal_;
    store::JournalOp op_;
    DurableReq req_;
    std::size_t rec_len_ = 0;
    BoundedQueue<DurableReq, 8> queue_;
};

} // namespace lm::delivery
