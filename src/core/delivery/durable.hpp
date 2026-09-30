// The durable side of delivery (docs/12 §3): boot incarnation, journal open and every journal
// Put/Retire/Read as slow jobs on the worker. The owner never touches the journal or the job
// memory while a job is in flight (zombie rule, docs/IMPLEMENTATION.md §3). One job at a time; the
// other writers wait in a bounded queue and their record is built when their turn comes, so the
// journal always gets the newest state of a slot. Ok from a job means durable (docs/12 §2).
//
// Job memory (ADR-002 P4): the node's one RecordJob, borrowed from the identity for each job and given
// back when its completion is polled: the record is built in its payload and the journal stages entries
// in its scratch for that job only. Work that finds the memory lent to another module (a channel, power,
// membership or ledger record job; the identity's own boot load) waits and runs as soon as it is back:
// deadline() is "now" then, never a poll.
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
        // Completion of a Put/Retire (Ok = durable) and of Read (the record, valid during the call).
        void (*done)(void *ctx, const DurableReq &req, Status st, MonoTime now) = nullptr;
        void (*boot_done)(void *ctx, Status st, MonoTime now) = nullptr;
        void (*read_done)(void *ctx, uint32_t id, Status st, ByteView record, MonoTime now) = nullptr;
    };

    explicit Durable(Engine &engine) : engine_(engine), journal_(index_.data(), index_.size()) {}
    void set_hooks(const Hooks &h) { hooks_ = h; }

    // Advances the boot incarnation and opens the journal (one job, run once the record memory is free).
    // Busy while an older job of a stopped engine still owns the memory.
    [[nodiscard]] Status begin_boot(MonoTime now);
    [[nodiscard]] bool ready() const { return state_ == State::Ready; }
    [[nodiscard]] bool failed() const { return state_ == State::Failed; }
    [[nodiscard]] uint64_t incarnation() const { return incarnation_; }
    [[nodiscard]] std::size_t live_count() const { return journal_.live_count(); }
    [[nodiscard]] uint32_t live_id(std::size_t i) const { return journal_.live_at(i).id; }

    // Queues a write. False: queue full (the caller keeps its "wanted" flag and asks again).
    [[nodiscard]] bool enqueue(const DurableReq &req, MonoTime now);
    // Reads one live record (recovery); the result comes through read_done. Busy while a read waits.
    [[nodiscard]] Status read(uint32_t id, MonoTime now);

    void on_job_done(Handle slot, Status s, MonoTime now);
    // Starts the next job (boot, read, queued write) when idle and the record memory is free.
    void pump(MonoTime now);
    [[nodiscard]] MonoTime deadline() const;
    // Engine stop: forget queued work; a job in flight keeps the borrowed memory until it is polled.
    void stop();
    [[nodiscard]] bool job_pending() const { return job_ != Job::None; }
    [[nodiscard]] std::size_t queued() const { return queue_.size(); }

  private:
    enum class State : uint8_t { Off, Booting, Ready, Failed };
    enum class Job : uint8_t { None, Boot, Put, Retire, Read };

    static Status job_entry(port::JobEnv &env, void *arg);
    [[nodiscard]] bool wants_job() const;
    [[nodiscard]] Status submit(Job j);
    void give_back();

    Engine &engine_;
    Hooks hooks_;
    State state_ = State::Off;
    Job job_ = Job::None;
    bool cancelled_ = false;
    bool boot_wanted_ = false;
    bool read_wanted_ = false;
    uint32_t read_id_ = 0; // the record a waiting read wants (req_ belongs to the job in flight)
    Handle handle_;
    uint32_t handle_gen_ = 0;
    uint64_t incarnation_ = 0;
    uint64_t boot_out_ = 0; // written by the boot job; taken by the owner only from a completed, live job
    MonoTime retry_at_ = MonoTime::never(); // a boot/read the worker queue refused: tried again then

    std::array<store::JournalLive, k_journal_entries> index_{};
    static_assert(store::k_journal_min_scratch <= store::k_max_blob && store::k_journal_max_payload <= store::k_max_payload);
    store::Journal journal_;
    store::RecordJob *rec_ = nullptr; // the identity's record memory while a job (or its completion) runs
    store::JournalOp op_;
    DurableReq req_;
    std::size_t rec_len_ = 0;
    BoundedQueue<DurableReq, 8> queue_;
};

} // namespace lm::delivery
