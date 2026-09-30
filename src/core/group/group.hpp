// Group fan-out (docs/08 §7, docs/22, S15). One logical operation = a snapshot fixed at the start
// (GroupSnapshotV2: token, hash, sorted targets with their generations) and one ordinary unicast per
// target through Delivery, at most four in flight, round-robin. The origin does the fan-out: the root
// for the Host (and for its own application), any other member for itself; the root only serves
// signed snapshot pages and never sees a body it is not the origin of.
//
// Ownership: `Fanout` owns the operations (`Op`: header + 64 compact `Target`s + their DeviceIds, at most `k_ops`), the
// payload (one message-pool buffer, never a copy per target) and the snapshots the root serves to other
// origins (`Kind::Served`, same pool, <= 120 s). A target is a Delivery send whose MessageId is
// (incarnation, base + attempt * total + index): the block is reserved when the operation begins, so
// the id of a target is arithmetic, not state. Delivery reports a child's final outcome (and late
// upgrades) through GroupHooks; nothing in the hooks calls back into Delivery.
//
// Current outcomes only: every target holds exactly one outcome, the counts sum to `total` (GS10);
// history stays in the evidence bits.
#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/command.hpp"
#include "core/delivery/delivery.hpp"
#include "core/ids.hpp"
#include "core/profile.hpp"
#include "core/time.hpp"
#include "leanmesh.h"
#include "security/identity.hpp"

namespace lm {
class Engine;
namespace wire {
struct ControlBody;
}
} // namespace lm

namespace lm::group {

inline constexpr std::size_t k_max_targets = 64; // registry limits.members, docs/22 §1
inline constexpr std::size_t k_page = 16;        // targets per page of the API (lm_group_targets, the bridge)
// A signed snapshot page holds at most k_page rows and at most k_row_bytes of encoded rows (FIX3-D10). A row is
// [DeviceId, assignment, membership]: 37 B with small generations (16 rows, 4 pages for 64 targets) and up to 53 B
// with generations near 2^63 (13 rows, 5 pages), so a page and its COSE envelope (185 B) stay inside the exchange's
// 1 KiB scratch for every legal value. The rows of page p are derived from the snapshot alone (`page_span`).
inline constexpr std::size_t k_row_bytes = 700;
inline constexpr std::size_t k_snap_pages = 5;
inline constexpr std::size_t k_ops = k_build_limits.group_operations; // leaf 1, relay 1, root 4 (profiles.json)
inline constexpr std::size_t k_inflight = 4;     // docs/22 §4; also bounded by half of the message slots
inline constexpr uint8_t k_attempts = 4;         // dispatches per target (a parked target is dispatched again)
inline constexpr uint64_t k_id_tag = 1ULL << 61; // operation ids (member ops use bit 62, deliveries neither)
inline constexpr uint8_t k_type_snapshot = 32;
inline constexpr uint8_t k_type_request = 33;
inline constexpr Duration k_snapshot_life = Duration::from_s(120);
inline constexpr Duration k_fetch_rto = Duration::from_s(3);
inline constexpr Duration k_park_after = Duration::from_s(5);
inline constexpr Duration k_progress_gap = Duration::from_ms(500);
inline constexpr uint8_t k_fetch_tries = 3;
// Every operation keeps the full DeviceIds of its snapshot (FIX3-D10): a target is a device and two 64 bit
// generations, never a ledger slot plus a prefix that another device could share.
inline constexpr std::size_t k_id_slots = k_ops * k_max_targets;
inline constexpr std::size_t k_serve_rows = k_root_capable ? k_page : 0; // the root's sign job encodes one page

// protocol/serial.cddl has only a DeviceId as the destination of SEND. A group is written as the
// 32 byte value 12 x 0 | group_id (u32 BE) | revision (u64 BE) | 8 x 0, which no DeviceId (a SHA-256)
// can take in practice (S15 decision; the Host encodes it, the root decodes it, both refuse anything else).
[[nodiscard]] inline DeviceId group_dest(uint32_t group_id, uint64_t revision) {
    DeviceId d;
    for (unsigned i = 0; i < 4; ++i) {
        d.bytes[12 + i] = static_cast<uint8_t>(group_id >> (24U - 8U * i));
    }
    for (unsigned i = 0; i < 8; ++i) {
        d.bytes[16 + i] = static_cast<uint8_t>(revision >> (56U - 8U * i));
    }
    return d;
}
[[nodiscard]] inline bool is_group_dest(ByteView v, uint32_t &group_id, uint64_t &revision) {
    if (v.size() != 32) {
        return false;
    }
    DeviceId d;
    std::copy(v.begin(), v.end(), d.bytes.begin());
    group_id = 0;
    revision = 0;
    for (unsigned i = 0; i < 4; ++i) {
        group_id = group_id << 8U | d.bytes[12 + i];
    }
    for (unsigned i = 0; i < 8; ++i) {
        revision = revision << 8U | d.bytes[16 + i];
    }
    return group_id != 0 && d == group_dest(group_id, revision);
}

// One target, 24 B (its DeviceId is in Fanout::ids_). Generations are the full u63 values of the snapshot.
struct Target {
    uint64_t assignment = 0;
    uint64_t membership = 0;
    uint16_t evidence = 0;      // Delivery ev:: bits of the final outcome
    uint8_t phase : 3;          // stored phase (Ready / WaitRoute / Final); live phases come from the child
    uint8_t attempt : 2;
    uint8_t live : 1;           // a Delivery child exists and is not final
    uint8_t outcome = LM_OUTCOME_PENDING;
    uint8_t reason = 0;         // Status
    Target() : phase(LM_TARGET_READY), attempt(0), live(0) {}
};
static_assert(sizeof(Target) == 24, "Target is the unit of the group RAM budget");

struct Op {
    enum class Kind : uint8_t { Free, Own, Served };
    enum class St : uint8_t { Fetching, Running, Final };
    Kind kind = Kind::Free;
    St st = St::Final;
    bool cancelled = false;
    bool host = false;         // sent by the Host: host_mid / host_hash make a repeat idempotent
    bool released = false;     // payload buffer given back
    bool progress_due = false;
    uint8_t total = 0;
    uint8_t got = 0;           // Fetching: targets received
    uint8_t pages = 0;         // Fetching: signed pages accepted
    uint8_t live = 0;          // children in flight
    uint8_t cursor = 0;
    uint8_t tries = 0;         // Fetching: requests sent for the current page
    uint8_t delivery = 0;
    uint8_t priority = 0;
    uint8_t outcome = LM_OUTCOME_PENDING;
    uint16_t port = 0;
    uint16_t len = 0;
    uint32_t seq = 0;          // eviction order
    uint32_t generation = 0;   // reuse counter: a job completion must match it
    uint32_t group_id = 0;
    uint32_t reason = 0;
    uint32_t term = 0;
    uint64_t id = 0;
    uint64_t revision = 0;
    uint64_t expires = 0;
    uint64_t progress = 0;     // progress_revision
    uint64_t incarnation = 0;
    uint64_t base = 0;
    uint64_t accepted_ms = 0;
    MonoTime at = MonoTime::never();       // Fetching: request RTO; Running: next look; Served: expiry
    MonoTime progress_at = MonoTime::never();
    Handle msg;
    DeviceId origin;           // Served: the member that may fetch it
    std::array<uint8_t, 16> token{};
    std::array<uint8_t, 16> req{};         // request id of the outstanding page request (Served: of page 0)
    std::array<uint8_t, 16> host_mid{};
    Sha256Digest hash{};
    Sha256Digest host_hash{};
    std::array<Target, k_max_targets> t{};
};

// Commands of the C API and the bridge (request structs; the caller is blocked while they run).
struct SetRequest {
    uint32_t group_id = 0;
    uint64_t expected_revision = 0;
    const uint8_t *members = nullptr; // count DeviceIds of 32 bytes, `stride` bytes apart (the bridge points into CBOR)
    std::size_t stride = 32;
    std::size_t count = 0;
};
struct TargetsRequest {
    uint64_t operation = 0;
    std::array<uint8_t, 16> token{};
    uint32_t offset = 0;
    std::size_t limit = k_page; // at most this many (the bridge walks a page one target at a time)
    lm_group_target_t *out = nullptr;
    std::size_t capacity = 0;
    std::size_t written = 0; // out
    uint32_t total = 0;      // out
};

class Fanout {
  public:
    explicit Fanout(Engine &engine);
    Fanout(const Fanout &) = delete;
    Fanout &operator=(const Fanout &) = delete;

    void install();  // hooks into Delivery (once, from the Engine constructor)
    void stop();     // payload buffers and the snapshots served; finished operations stay queryable
    void end_for_stop(MonoTime now);                // lm_stop: every open operation ends with per-target outcomes
    [[nodiscard]] bool has_open() const;            // an operation that is not final (lm_stop's drain waits for it)
    void on_timer(MonoTime now);
    [[nodiscard]] MonoTime deadline() const;
    void on_job_done(Handle slot, Status s, MonoTime now);
    [[nodiscard]] bool job_pending() const { return job_ != Job::None; }
    // True for the commands this module answers (a send to a group, an operation id it issued, group API).
    [[nodiscard]] static bool wants(const Command &cmd);
    [[nodiscard]] Reply execute(const Command &cmd, MonoTime now);
    // A control object of another node completed here (Delivery's control sink): types 32 and 33.
    void on_control(const DeviceId &origin, ByteView payload, MonoTime now);
    // Looks up a Host message (GET_MESSAGE) among the group operations.
    [[nodiscard]] Reply get_message(const lm_message_ref_t &ref, lm_operation_t &out);
    [[nodiscard]] const Op *op_at(std::size_t i) const { return &ops_[i]; }

  private:
    enum class Job : uint8_t { None, Sign, Verify };
    // -- group.cpp: operations --
    [[nodiscard]] Reply send(const lm_send_request_t &rq, ByteView payload, const delivery::HostSendRequest *host,
                             MonoTime now);
    [[nodiscard]] Op *alloc(Op::Kind kind);
    [[nodiscard]] Op *find(uint64_t id);
    void begin(Op &g, MonoTime now);
    void pump(Op &g, MonoTime now);
    [[nodiscard]] bool dispatch(Op &g, std::size_t i, MonoTime now);
    void park(Op &g, std::size_t i, MonoTime now);
    void settle(Op &g, std::size_t i, uint8_t outcome, uint32_t reason);
    void end(Op &g);
    void aggregate(Op &g);
    void free_payload(Op &g);
    static void reset_op(Op &g);
    [[nodiscard]] Reply cancel(uint64_t id, MonoTime now);
    void get_operation(const Op &g, lm_operation_t &out) const;
    [[nodiscard]] Reply progress(const Op &g, lm_group_progress_t &out) const;
    [[nodiscard]] Reply targets(Op &g, TargetsRequest &rq);
    [[nodiscard]] std::array<uint8_t, 16> mid_of(const Op &g, std::size_t i, unsigned attempt) const;
    [[nodiscard]] bool locate(const MessageId &m, Op *&g, std::size_t &i, unsigned &attempt);
    [[nodiscard]] bool device_at(const Op &g, std::size_t i, DeviceId &out) const;
    [[nodiscard]] Status snapshot_hash(const Op &g, Sha256Digest &out) const;
    void child(const delivery::Op &c, MonoTime now);
    [[nodiscard]] bool gate(const delivery::Op &c, uint64_t assignment, uint64_t membership);
    static void child_hook(void *ctx, const delivery::Op &c, MonoTime now);
    static bool gate_hook(void *ctx, const delivery::Op &c, uint64_t a, uint64_t m);
    // -- snapshot.cpp: pages, fetch (origin) and serve (root) --
    // Rows [first, first + n) of signed page `page` of the snapshot in g (n = 0: no such page).
    static void page_span(const Op &g, unsigned page, std::size_t &first, std::size_t &n);
    void request_page(Op &g, MonoTime now);
    void fetch_failed(Op &g, uint32_t reason);
    void on_page(ByteView cose, MonoTime now);
    void accept_page(Op &g, ByteView cose, MonoTime now);
    void serve(const DeviceId &origin, const wire::ControlBody &b, MonoTime now);
    void sign_page(Op &s, unsigned page, const std::array<uint8_t, 16> &req, MonoTime now);
    void send_page(Op &s, MonoTime now);
    [[nodiscard]] Status submit(Job kind, const Op &g, MonoTime now);
    static Status job_body(port::JobEnv &env, void *arg);
    void release_scratch();
    [[nodiscard]] uint64_t next_id() { return k_id_tag | ++counter_; }

    Engine &engine_;
    std::array<Op, k_ops> ops_{};
    std::array<DeviceId, k_id_slots> ids_{}; // k_max_targets per operation, sorted: the DeviceIds behind Op::t
    [[nodiscard]] DeviceId *ids_of(const Op &g) { return &ids_[static_cast<std::size_t>(&g - ops_.data()) * k_max_targets]; }
    [[nodiscard]] const DeviceId *ids_of(const Op &g) const {
        return &ids_[static_cast<std::size_t>(&g - ops_.data()) * k_max_targets];
    }
    [[nodiscard]] bool root_origin() const;
    // One sign/verify job at a time; its memory stays reserved until the completion is polled.
    Job job_ = Job::None;
    uint32_t job_op_ = 0;      // index of the operation the job serves
    MutByteView scratch_;      // the exchange's lent 1 KiB: the COSE page in / out
    std::size_t cose_len_ = 0;
    struct Page { // what the sign job encodes: copied on the owner, read by the worker
        std::array<DeviceId, k_serve_rows> dev{};
        std::array<uint64_t, k_serve_rows> a{};
        std::array<uint64_t, k_serve_rows> m{};
        std::array<uint8_t, 16> req{};
        std::array<uint8_t, 16> token{};
        Sha256Digest hash{};
        DomainId domain;
        DeviceId issuer;
        DeviceId origin;
        sec::KeyHandle key{};
        sec::PublicKey root_key{};
        uint64_t revision = 0;
        uint32_t group_id = 0;
        uint8_t total = 0;
        uint8_t page = 0;
        uint8_t n = 0;
    };
    Page page_;
    uint64_t counter_ = 0;
    uint32_t tick_ = 0;
    uint32_t gen_ = 0;
    struct Stats {
        uint64_t started = 0, pages_served = 0, pages_fetched = 0, parked = 0, late = 0;
    };
    Stats stats_;
    std::size_t parking_ = ~std::size_t{0}; // target being parked (its cancel is not its outcome)
    Op *parking_op_ = nullptr;

  public:
    [[nodiscard]] const Stats &stats() const { return stats_; }
};

} // namespace lm::group
