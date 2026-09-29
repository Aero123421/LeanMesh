// The four fixed port contracts (docs/02 §4): Clock, Radio, Store, Jobs ("CryptoJobs").
// Implementations: src/port/idf (ESP-IDF) and src/port/sim (meshsim / native tests). They are
// selected by linking; there is no plugin registry. Rules for every implementation:
//  - Never block the mesh owner: Radio::transmit, Jobs::submit and poll() return immediately.
//  - Driver callbacks only copy into a fixed ring and notify the owner (docs/15 §2).
//  - Local resource failures (BUSY/NO_MEM/peer table full) are reported as Status::Busy /
//    Status::NoCapacity and are never counted as RF loss (docs/03 §4).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/ids.hpp"
#include "core/status.hpp"
#include "core/time.hpp"
#include "gen/registry.hpp"

namespace lm::port {

// ---- Clock -------------------------------------------------------------------------------------
class Clock {
  public:
    [[nodiscard]] virtual MonoTime now() const = 0;

  protected:
    ~Clock() = default;
};

// ---- Radio -------------------------------------------------------------------------------------
inline constexpr std::size_t k_max_frame_bytes = gen::limits::rf_body_bytes; // 250, self-limited

// RF profile (docs/03 §3): RF start is refused unless deployment_approved.
struct RfProfile {
    bool deployment_approved = false;
    uint8_t channel = 0;                // 1..13, must be in allowed_channels_mask
    uint16_t allowed_channels_mask = 0; // bit c set = channel c allowed
    int16_t tx_power_qdbm = 0;          // quarter-dBm upper bound
    std::array<char, 3> country{};      // e.g. "JP" (not a legal-compliance proof)
};

// Owner-side identity of a physical transmission. The driver generation changes on every radio
// re-initialisation so a late callback from an older driver instance is never matched (docs/03 §4).
struct TxToken {
    uint32_t driver_generation = 0;
    uint32_t sequence = 0;
    friend bool operator==(TxToken a, TxToken b) {
        return a.driver_generation == b.driver_generation && a.sequence == b.sequence;
    }
};

enum class TxResult : uint8_t {
    MacAcked,  // driver reported MAC-level success (not a LeanMesh HOP_ACK)
    MacFailed, // RF failure sample
    Unknown,   // watchdog/driver reset: result unknown (DRIVER_RESULT_UNKNOWN)
};

struct RadioRx {
    MacAddr src;
    bool broadcast = false;  // received on the broadcast address
    bool rssi_valid = false; // RSSI unknown is not 0 dBm (docs/03 §4)
    int16_t rssi_dbm = 0;
    MonoTime at;
    uint8_t len = 0;
    std::array<uint8_t, k_max_frame_bytes> bytes{};
};

struct RadioTxDone {
    TxToken token;
    TxResult result = TxResult::Unknown;
    MonoTime at;
};

struct RadioEvent {
    enum class Kind : uint8_t { Rx, TxDone };
    Kind kind = Kind::Rx;
    RadioRx rx;       // valid when kind == Rx
    RadioTxDone done; // valid when kind == TxDone
};

class Radio {
  public:
    // Brings the radio up in the order of docs/03 §3. RfProfileUnapproved when not approved.
    [[nodiscard]] virtual Status start(const RfProfile &profile) = 0;
    [[nodiscard]] virtual Status stop() = 0;
    // Includes readback of the channel actually applied.
    [[nodiscard]] virtual Status set_channel(uint8_t channel) = 0;
    // NoCapacity when the driver peer table is full (20 = 16 regular + 3 transient + 1 broadcast).
    [[nodiscard]] virtual Status add_peer(const MacAddr &mac) = 0;
    [[nodiscard]] virtual Status remove_peer(const MacAddr &mac) = 0;
    // Queues one frame (<= 250 B). At most one physical TX is in flight: Busy otherwise.
    [[nodiscard]] virtual Status transmit(const MacAddr &dst, ByteView frame, TxToken token) = 0;
    // Owner only: next RX / TX-completion event, false when none.
    [[nodiscard]] virtual bool poll(RadioEvent &out) = 0;
    [[nodiscard]] virtual uint32_t driver_generation() const = 0;

  protected:
    ~Radio() = default;
};

// ---- Store -------------------------------------------------------------------------------------
// Durable storage, used ONLY from the slow-job worker (docs/02 §2). Record identifiers and the
// sealed 2-slot record format are defined in src/store; this port is raw keyed slots plus an
// append-only journal region. Read errors are StorageFailure, never "empty" (docs/12 §2).
class Store {
  public:
    // NotFound when the slot is empty; StorageFailure on I/O or integrity error.
    [[nodiscard]] virtual Status slot_read(uint16_t record, uint8_t slot, MutByteView out,
                                           std::size_t &len) = 0;
    // Durable (committed and read back) when Ok is returned.
    [[nodiscard]] virtual Status slot_write(uint16_t record, uint8_t slot, ByteView data) = 0;
    [[nodiscard]] virtual Status slot_erase(uint16_t record, uint8_t slot) = 0;

    [[nodiscard]] virtual uint32_t journal_segment_bytes() const = 0;
    [[nodiscard]] virtual uint32_t journal_segments() const = 0;
    [[nodiscard]] virtual Status journal_read(uint32_t offset, MutByteView out) = 0;
    // Writes into previously erased bytes only; durable when Ok is returned.
    [[nodiscard]] virtual Status journal_write(uint32_t offset, ByteView data) = 0;
    [[nodiscard]] virtual Status journal_erase(uint32_t segment) = 0;

  protected:
    ~Store() = default;
};

// ---- Jobs ("CryptoJobs") ----------------------------------------------------------------------
// The bounded slow-job worker: public-key operations and Flash I/O run here, never on the owner.
// Job bodies are common code (src/security, src/store); the port only queues and runs them.
struct JobEnv {
    Store &store;
};

// A job body. Runs on the worker; must not touch mesh-owner state except through `arg`, whose
// memory the owner keeps untouched (and unreused) until the completion has been polled.
using JobFn = Status (*)(JobEnv &env, void *arg);

struct JobCompletion {
    uint16_t table_index = 0;
    uint32_t job_id = 0;
    Status status = Status::Ok;
};

class Jobs {
  public:
    // Busy when the worker queue is full; the job then does not exist.
    [[nodiscard]] virtual Status submit(uint16_t table_index, uint32_t job_id, JobFn fn,
                                        void *arg) = 0;
    // Owner only.
    [[nodiscard]] virtual bool poll(JobCompletion &out) = 0;
    // CSPRNG bytes for SDK-level nonces and jitter. Keys are generated inside PSA, not here.
    // Sim builds may be seeded deterministically; production builds refuse test seeds (docs/06 §8).
    virtual void random(MutByteView out) = 0;

  protected:
    ~Jobs() = default;
};

} // namespace lm::port
