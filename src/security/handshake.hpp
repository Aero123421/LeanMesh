// EDHOC (RFC 9528, method 0, suite 3) handshake slot driven as slow-job bodies (docs/06 §2, §4, §9).
//
// Owner side (cheap, no public-key work): begin(), prepare(), complete(), set_context(),
// take_keys(). Worker side: run_job(), which executes exactly the step prepare() armed and touches
// nothing but this slot. The owner keeps the slot's memory untouched and un-reused until the
// completion has been polled, also after cancel() (zombie rule, docs/IMPLEMENTATION.md §3); match a
// completion by (table_index, job_id) and then by the slot handle generation before calling
// complete().
//
// Message flow (message_4 is mandatory; a session exists only after it):
//   initiator: M1Compose  M2Process  M3Compose  M4Process  Export
//   responder: M1Process  M2Compose  M3Process  M4Compose  Export
// Which peer key is acceptable is decided before the handshake: begin() takes the candidate CCSs
// the owner already validated (fleet signature, revocation, generations). A received kid outside
// that set aborts the handshake; a self-declared key is never trusted (docs/06 §4).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/ids.hpp"
#include "core/ports.hpp"
#include "core/status.hpp"
#include "security/identity.hpp"
#include "security/record.hpp"

extern "C" {
#include "security/edhoc/lm_edhoc.h"
}

namespace lm::sec {

inline constexpr std::size_t k_edhoc_max_message = LM_EDHOC_MAX_MSG;
inline constexpr std::size_t k_edhoc_max_peers = LM_EDHOC_MAX_PEERS;

enum class HsRole : uint8_t { Initiator, Responder };

enum class HsStep : uint8_t {
    None,
    M1Compose,
    M1Process,
    M2Compose,
    M2Process,
    M3Compose,
    M3Process,
    M4Compose,
    M4Process,
    Export,
};

class HandshakeSlot {
  public:
    HandshakeSlot() = default;
    HandshakeSlot(const HandshakeSlot &) = delete;
    HandshakeSlot &operator=(const HandshakeSlot &) = delete;
    ~HandshakeSlot() { wipe(); }

    // Owner. Copies the inputs; parsing and validation run in the first job. `local_key` is a PSA
    // handle the caller created (import_signing_key) and keeps owning; it must outlive the
    // handshake. local_ccs must encode the public key of local_key. Busy when the slot is in use.
    [[nodiscard]] Status begin(HsRole role, KeyHandle local_key, ByteView local_ccs,
                               const ByteView *peer_ccs, std::size_t peer_count);

    // Owner. Arms `step` for the next run_job(); `input` is the received message for the *Process
    // steps (copied). InvalidArgument/Conflict for a step out of order, Busy while a job is in
    // flight, PayloadTooLarge for an oversize message.
    [[nodiscard]] Status prepare(HsStep step, ByteView input = ByteView{});

    // Worker. JobFn-compatible; `arg` is the slot. The returned Status is the step result; the raw
    // libedhoc code is kept in last_rc() for diagnostics (never logged).
    static Status run_job(port::JobEnv &env, void *arg);

    // Owner, after the matching completion was accepted. Advances the state on Ok, otherwise
    // aborts the handshake (all secrets wiped, slot back to idle). Returns `job_status`, or
    // Conflict when cancel() was requested meanwhile (the result is discarded).
    [[nodiscard]] Status complete(Status job_status);

    // Owner. Undoes prepare() when the job could not be submitted (queue full): the job never ran.
    void unprepare();

    // Owner. Idle slots are wiped now. With a job in flight the slot is only marked; it is wiped in
    // complete(). Returns Busy in that case so the caller keeps the memory reserved.
    [[nodiscard]] Status cancel();

    // Message composed by the last successful *Compose step.
    [[nodiscard]] ByteView output() const { return ByteView{out_.data(), out_len_}; }

    // Valid once the peer authenticated (initiator: after M2Process, responder: after M3Process).
    [[nodiscard]] bool peer_known() const { return peer_known_; }
    [[nodiscard]] const DeviceId &peer_device() const { return peer_device_; }
    [[nodiscard]] const DeviceId &local_device() const { return local_device_; }
    [[nodiscard]] std::size_t peer_index() const { return peer_index_; }

    // Owner, after the peer is known and before Export: fixes the LM session context. Its
    // initiator/responder DeviceIds must be exactly this slot's local and peer devices for the
    // slot's role (AuthRejected otherwise), so the keys cannot be bound to other identities.
    [[nodiscard]] Status set_context(const SessionContext &ctx);
    [[nodiscard]] const Sha256Digest &context_hash() const { return ctx_hash_; }

    // Owner, after Export completed: moves the derived keys out and wipes the slot.
    [[nodiscard]] Status take_keys(RecordKeys &out);

    [[nodiscard]] bool idle() const { return state_ == State::Idle; }
    [[nodiscard]] bool in_flight() const { return in_flight_; }
    [[nodiscard]] HsStep expected_step() const { return expected_; }
    [[nodiscard]] int last_rc() const { return last_rc_; }
    // EDHOC objects live here: roughly sizeof(*this) is the per-handshake RAM (docs/16 budget).

  private:
    enum class State : uint8_t { Idle, Running, Established, Failed };

    Status run();
    Status init_session();
    void wipe();

    State state_ = State::Idle;
    HsRole role_ = HsRole::Initiator;
    HsStep expected_ = HsStep::None; // next step prepare() accepts
    HsStep armed_ = HsStep::None;    // step run_job() executes
    bool in_flight_ = false;
    bool cancelled_ = false;
    bool session_ready_ = false;     // lm_edhoc_session_init done
    bool peer_known_ = false;
    bool ctx_set_ = false;
    bool keys_ready_ = false;
    int last_rc_ = 0;
    std::size_t peer_index_ = 0;
    DeviceId local_device_;
    DeviceId peer_device_;
    Sha256Digest ctx_hash_{};
    Purpose purpose_ = Purpose::Link;

    KeyHandle local_key_;
    std::array<uint8_t, k_ccs_max_bytes> local_ccs_{};
    std::size_t local_ccs_len_ = 0;
    std::array<std::array<uint8_t, k_ccs_max_bytes>, k_edhoc_max_peers> peer_ccs_{};
    std::array<std::size_t, k_edhoc_max_peers> peer_ccs_len_{};
    std::size_t peer_count_ = 0;
    std::array<DeviceId, k_edhoc_max_peers> peer_ids_{};

    std::array<uint8_t, k_edhoc_max_message> in_{};
    std::size_t in_len_ = 0;
    std::array<uint8_t, k_edhoc_max_message> out_{};
    std::size_t out_len_ = 0;
    RecordKeys keys_{};
    lm_edhoc_session session_{};
};

} // namespace lm::sec
