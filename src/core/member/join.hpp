// JoinPipe: delivery of one control object at a time over a JOIN_ONLY session (docs/07 §4).
// The join objects (join_wire.hpp) can exceed one frame (JoinRequest ~0.9 KiB, JoinPrepare ~0.5 KiB)
// and control fragmentation (S12) does not exist yet, so a small chunker lives here (decision S8-D4):
//   - every chunk is one CONTROL frame sealed under the JOIN_ONLY session with a *fresh* counter;
//     a retransmission re-seals the same plaintext (never re-encrypts under an old nonce);
//   - a receiver acknowledges a completed object with one tiny ack chunk (also for a repeat of an
//     object it already delivered); the peer's next protocol message acknowledges it as well. The
//     RTO re-sends the whole object, at most `max_attempts` times, until either arrives;
//   - the receiver assembles into a buffer the caller lends (the exchange's credential buffer, not a
//     new one, docs/IMPLEMENTATION.md §13); single-chunk objects need no buffer at all;
//   - object ids are per direction and per session; the same id again after completion is reported
//     as Duplicate so the state machine can repeat its last reply (idempotent, hash-invariant).
// Radio Busy/isolated is a local condition retried shortly; only the RTO counts attempts.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/ids.hpp"
#include "core/member/join_wire.hpp"
#include "core/pool.hpp"
#include "core/radio/tx_manager.hpp"
#include "core/time.hpp"

namespace lm {
class Engine;
}

namespace lm::member {

class JoinPipe {
  public:
    enum class Feed : uint8_t { Ignored, NeedBuffer, Partial, Object, Duplicate, Acked };

    // `tag_base` marks this pipe's TX completions (upper 16 bits; the low 16 are a sequence).
    JoinPipe() = default;
    JoinPipe(Engine &engine, uint32_t tag_base) : engine_(&engine), tag_base_(tag_base) {}
    void attach(Engine &engine, uint32_t tag_base) {
        engine_ = &engine;
        tag_base_ = tag_base;
    }

    // Session bound: the peer's identity and MAC and the domain hint every frame carries.
    void bind(const MacAddr &mac, const DeviceId &peer, uint32_t domain_hint);
    void set_hint(uint32_t domain_hint) { hint_ = domain_hint; }
    // Forgets the session and any object in flight in either direction.
    void reset();
    [[nodiscard]] bool bound() const { return bound_; }
    [[nodiscard]] const DeviceId &peer() const { return peer_; }
    [[nodiscard]] const MacAddr &mac() const { return mac_; }

    // ---- TX ----
    // Staging area for small objects (<= one pool frame); send_staged() makes it the current object.
    // It is a frame borrowed from the node's pool (P9) from the first stage() until reset(); empty
    // when the pool has no room (a local shortage the caller treats as a failed attempt).
    [[nodiscard]] MutByteView stage();
    void send_staged(std::size_t len, MonoTime now);
    // `object` must stay valid until acked() or reset(). Replaces an object still in flight.
    void send(ByteView object, MonoTime now);
    // The peer answered: stop retransmitting.
    void acked() {
        tx_active_ = false;
        rto_at_ = MonoTime::never();
        retry_at_ = MonoTime::never();
    }
    [[nodiscard]] bool sending() const { return tx_active_; }
    [[nodiscard]] bool owns_tag(uint32_t tag) const { return (tag & 0xFFFF0000U) == tag_base_; }
    void on_tx_outcome(const TxOutcome &o, MonoTime now);
    // Expired when the object was sent `max_attempts` times without an answer (the owner decides
    // what that means); Ok otherwise. Stops the object on Expired.
    [[nodiscard]] Status on_timer(MonoTime now);
    [[nodiscard]] MonoTime deadline() const { return earliest(rto_at_, retry_at_); }
    [[nodiscard]] uint64_t frames_sent() const { return frames_sent_; }

    // ---- RX ----
    // `chunk_plain` is the authenticated CONTROL plaintext. `buf` (may be empty) is the assembly
    // buffer for multi-chunk objects. Object: `object` is complete and valid until the buffer is
    // reused (single-chunk objects alias `chunk_plain`).
    [[nodiscard]] Feed feed(ByteView chunk_plain, MutByteView buf, ByteView &object, MonoTime now);
    // The id of the object being assembled / last completed (0 = none yet).
    [[nodiscard]] uint8_t rx_id() const { return rx_id_; }
    void rx_forget() { rx_len_ = rx_total_ = 0; }

  private:
    void pump(MonoTime now);

    Engine *engine_ = nullptr;
    uint32_t tag_base_ = 0;
    bool bound_ = false;
    DeviceId peer_;
    MacAddr mac_;
    uint32_t hint_ = 0;

    ByteView tx_obj_;
    std::size_t tx_off_ = 0;
    uint8_t tx_id_ = 0;
    uint8_t attempts_ = 0;
    bool tx_active_ = false;
    bool tx_inflight_ = false;
    uint16_t tx_seq_ = 0;
    MonoTime rto_at_ = MonoTime::never();
    MonoTime retry_at_ = MonoTime::never();
    uint64_t frames_sent_ = 0;
    Handle stage_h_; // the borrowed staging frame

    uint8_t rx_id_ = 0;    // id of the object being assembled or last completed
    bool rx_done_ = false; // rx_id_ completed
    uint16_t rx_total_ = 0;
    uint16_t rx_len_ = 0;
    uint8_t ack_id_ = 0;   // an ack chunk for this received object id waits for the TX slot
    Status error_ = Status::Ok; // set by pump(), returned once by on_timer()
};

} // namespace lm::member
