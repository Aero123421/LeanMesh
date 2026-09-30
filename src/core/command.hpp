// Commands from application tasks to the mesh owner (docs/02 §5 MPSC command queue).
// A command points at caller-owned request/response memory; the caller is blocked in the owner
// call until the reply is written, so the owner may read the request and copy the payload into
// its fixed pools during execute(). Acceptance is bounded: a full queue yields Busy immediately.
#pragma once

#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/status.hpp"

namespace lm {

// One kind per public C API entry (api/leanmesh.h) plus root-local bridge commands. Values are
// internal (not ABI) and may be reordered.
enum class CommandKind : uint8_t {
    Start,
    Stop,
    Destroy, // lm_destroy precondition: Ok only when stopped
    Send,
    SendObject,
    GetOperation,
    GetMessage,
    GetRequest,
    PayloadCapacity,
    Cancel,
    NextEvent,
    ReportApplicationResult,
    MembershipGet,
    ConnectivityGet,
    Join,
    Leave,
    InstallControl,
    GroupSet,
    PolicyGet,
    PolicySet,
    ChannelRequest,
    GetCapabilities,
    DiagnosticsGet,
    SleepPrepare,
    SleepTicketGet,
    SleepEnter,
    PowerPolicyGet,
    PowerPolicySet,
    PowerGet,
    SleepPrepareEx,
    SleepAbort,
    GroupProgress,
    GroupTargets,
    // Root-local commands used by the serial bridge (root builds only). They have no public C ABI
    // in api/leanmesh.h v0.2 (see docs/IMPLEMENTATION.md, spec decisions).
    RootJoinDecide,
    RootNodeQuery,
    RootHostStoreAck,
    RootGroupSnapshot,
    RootSleepWindow,
    SendControl,  // [S12] internal: a control object to a device (delivery::ControlSendRequest)
    RootHostSend, // [S13] lm_send with the Host's MessageId and intent_hash (see delivery::HostSendRequest)
    TransferNonce, // [S18] lm_transfer_nonce_get: the device's outstanding mode-0 ticket nonce (16 B response)
    RootTimeGet,   // [ARCH2] lm_root_time_get: the node's root clock estimate (lm_root_time_t response)
};

struct Command {
    CommandKind kind = CommandKind::GetCapabilities;
    const void *request = nullptr; // kind-specific request struct (caller memory)
    std::size_t request_size = 0;
    ByteView payload;         // caller memory, copied by the owner if accepted
    void *response = nullptr; // kind-specific output struct (caller memory)
    std::size_t response_size = 0;
    MutByteView response_payload; // optional output buffer (e.g. event payload)
};

struct Reply {
    Status status = Status::Unsupported;
    uint64_t operation_id = 0;      // for accepted asynchronous operations
    std::size_t required_bytes = 0; // for BufferTooSmall
    // [S14] Admission refusals (NoCapacity/Busy from the scheduler) say why and when to try again:
    // the diagnostics and the Host's 429/503 use them. 0 = not stated.
    uint32_t retry_after_ms = 0;
    uint16_t queue_depth = 0; // live operations in the class or pool that refused
};

// Platform glue that runs a command on the owner thread and waits for the reply. IDF: bounded
// queue + task notification (Busy when the queue is full). Sim/native: direct call on the single
// simulation thread. Not one of the four ports: it is the owner-task mechanism itself.
class OwnerCall {
  public:
    [[nodiscard]] virtual Reply call(const Command &cmd) = 0;

  protected:
    ~OwnerCall() = default;
};

} // namespace lm
