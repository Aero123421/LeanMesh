// Owner -> application event queue (docs/10 §2). Bounded; when the application is slow the owner
// never blocks: it counts the overflow and, once space is available again, emits one
// LM_EVENT_GAP event first. The application resynchronises through get_operation/snapshots.
// Both ends run on the mesh owner: lm_next_event reaches pop() through the owner call, so no lock
// is needed. Payload delivery (message bodies) is added by the delivery slice; see
// docs/IMPLEMENTATION.md.
#pragma once

#include <cstdint>

#include "core/ring.hpp"
#include "leanmesh.h"

namespace lm {

template <std::size_t N> class AppEventQueue {
  public:
    // Owner side. Returns false when the event was not queued (a GAP will be reported).
    // After a loss, the GAP marker is queued together with the next event that fits with it, so
    // the application sees GAP exactly where events went missing.
    bool push(lm_event_t ev) {
        if (lost_ > 0) {
            if (ring_.size() + 2 > N) {
                ++lost_;
                return false;
            }
            push_gap();
        }
        ev.event_sequence = sequence_ + 1;
        if (!ring_.push(ev)) {
            ++lost_;
            return false;
        }
        ++sequence_;
        return true;
    }

    // Called on the owner on behalf of lm_next_event.
    [[nodiscard]] bool pop(lm_event_t &out) {
        if (ring_.empty() && lost_ > 0) {
            push_gap();
        }
        return ring_.pop(out);
    }

    // The event pop() would return next, without consuming it ([SLICE:S9]: the caller checks the
    // payload capacity first, BufferTooSmall must not consume the event). Like pop(), it reports
    // a pending GAP once the queue is empty.
    [[nodiscard]] const lm_event_t *peek() {
        if (ring_.empty() && lost_ > 0) {
            push_gap();
        }
        return ring_.front();
    }

    // Withdraws the queued events for which `gone(ev)` holds (their backing state no longer exists: a payload that
    // was dropped by a stop). The order of the others is kept; the application sees one GAP where they were.
    template <class Pred> void withdraw(Pred gone) {
        for (std::size_t n = ring_.size(); n > 0; --n) {
            lm_event_t ev{};
            if (!ring_.pop(ev)) {
                return;
            }
            if (gone(ev)) {
                ++lost_;
            } else {
                (void)ring_.push(ev);
            }
        }
    }

    [[nodiscard]] uint64_t lost() const { return lost_; }
    // [S19] Diagnostics: events waiting for the application, and every event ever lost (lost_ restarts at each GAP).
    [[nodiscard]] std::size_t depth() const { return ring_.size(); }
    [[nodiscard]] uint64_t lost_total() const { return lost_total_ + lost_; }

  private:
    // Precondition: the ring has a free slot.
    void push_gap() {
        lm_event_t gap{};
        gap.struct_size = sizeof(lm_event_t);
        gap.abi_version = LM_ABI_VERSION;
        gap.kind = LM_EVENT_GAP;
        gap.event_sequence = ++sequence_;
        gap.payload_bytes = 0;
        (void)ring_.push(gap);
        lost_total_ += lost_;
        lost_ = 0;
    }

    BoundedQueue<lm_event_t, N> ring_;
    uint64_t sequence_ = 0;
    uint64_t lost_ = 0;
    uint64_t lost_total_ = 0;
};

} // namespace lm
