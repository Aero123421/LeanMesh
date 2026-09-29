// Owner-side table of slow jobs in flight (docs/02 §2, AGENTS.md "完了はslot_generation + job_idで
// 照合"). Each entry remembers which module slot (owner + handle) asked for the job. A completion
// is accepted only if its (table_index, job_id) matches a running entry; the owning module must
// then also check that its slot handle is still live. Stale completions are counted and dropped.
//
// Memory rule: a job's `arg` points into the requesting module's slot. That memory must not be
// reused until the completion has been polled, even if the slot was logically cancelled (its
// generation bumped). Modules keep such slots in a "job pending" state until then.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/pool.hpp"
#include "core/ports.hpp"
#include "core/status.hpp"

namespace lm {

// Which module receives a completion. Each slice adds its owner here (additive edit only).
enum class JobOwner : uint8_t {
    None = 0,
    Test = 1, // native tests only
    Identity = 2, // S5: boot load of identity/trust/membership records
    Link = 3,     // S5: link exchange (credential verify, EDHOC steps)
};

// Public-key jobs share one global slot (docs/06 §8 "同時P-256 jobs1"); Flash jobs are separate.
enum class JobClass : uint8_t { PublicKey, Flash };

struct JobTicket {
    uint16_t table_index = 0;
    uint32_t job_id = 0;
};

struct JobOrigin {
    JobOwner owner = JobOwner::None;
    Handle slot;
};

template <std::size_t N> class JobTable {
    static_assert(N > 0 && N < 0xFFFF, "capacity");

  public:
    // Reserves an entry. Busy when the table is full or a public-key job is already running.
    [[nodiscard]] Status reserve(JobOwner owner, Handle slot, JobClass cls, JobTicket &out) {
        if (cls == JobClass::PublicKey && public_key_running_) {
            return Status::Busy;
        }
        for (std::size_t i = 0; i < N; ++i) {
            if (!entries_[i].running) {
                ++next_job_id_;
                if (next_job_id_ == 0) {
                    next_job_id_ = 1;
                }
                entries_[i] = Entry{true, cls, next_job_id_, JobOrigin{owner, slot}};
                if (cls == JobClass::PublicKey) {
                    public_key_running_ = true;
                }
                out = JobTicket{static_cast<uint16_t>(i), next_job_id_};
                return Status::Ok;
            }
        }
        return Status::Busy;
    }

    // Undo a reservation whose submit() failed (the job never existed).
    void cancel_unsubmitted(JobTicket t) { (void)finish(t.table_index, t.job_id); }

    // Resolves a completion. Returns false (and counts it) for unknown/stale completions.
    [[nodiscard]] bool complete(const port::JobCompletion &c, JobOrigin &origin) {
        if (!finish(c.table_index, c.job_id, &origin)) {
            ++stale_completions_;
            return false;
        }
        return true;
    }

    [[nodiscard]] uint32_t stale_completions() const { return stale_completions_; }
    [[nodiscard]] bool public_key_busy() const { return public_key_running_; }

  private:
    struct Entry {
        bool running = false;
        JobClass cls = JobClass::Flash;
        uint32_t job_id = 0;
        JobOrigin origin;
    };

    bool finish(uint16_t index, uint32_t job_id, JobOrigin *origin = nullptr) {
        if (index >= N || !entries_[index].running || entries_[index].job_id != job_id) {
            return false;
        }
        if (origin != nullptr) {
            *origin = entries_[index].origin;
        }
        if (entries_[index].cls == JobClass::PublicKey) {
            public_key_running_ = false;
        }
        entries_[index] = Entry{};
        return true;
    }

    std::array<Entry, N> entries_{};
    uint32_t next_job_id_ = 0;
    uint32_t stale_completions_ = 0;
    bool public_key_running_ = false;
};

} // namespace lm
