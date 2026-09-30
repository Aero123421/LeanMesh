// Records of the channel slice (docs/05, S17). Like the mesh records (S11-D1) they are compact binary
// CONTROL end records of the node<->root end session: a signed CBOR ChannelPlan would be 300+ B and could
// not cross a hop (S17-D1). The end session already authenticates the root; nothing here is a hint.
// First byte 0xE6..0xED (a CBOR control-body starts with 0x87, a mesh record with 0xE1..0xE5).
// The plan hash is the one of docs/19 §1 (deterministic CBOR over the plan body, phase excluded).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/codec.hpp"
#include "core/ids.hpp"
#include "core/status.hpp"

namespace lm::channel {

enum class Op : uint8_t { Plan = 0xE6, Receipt, TimeReq, TimeResp, State, Survey, SurveyResult, Degraded };
enum class Phase : uint8_t { Prepare = 0, Commit = 1, Abort = 2 }; // control.cddl channel-plan phase
// control.cddl channel-receipt evidence. Stored and Applied are separate facts (docs/05 §8).
enum class Evidence : uint8_t { Refused = 0, Prepared = 1, Stored = 2, Applied = 3 };

struct Plan { // the immutable body; PREPARE, COMMIT and ABORT carry the same one
    PlanId id;
    RootTerm term;
    ChannelEpoch epoch;
    uint8_t old_ch = 0;
    uint8_t new_ch = 0;
    uint64_t switch_root_ms = 0;
    uint32_t max_err_ms = 0;
    uint32_t settle_ms = 0;
    uint64_t policy_rev = 0;
    Sha256Digest participants{};
};
struct PlanRec {
    static constexpr Op op = Op::Plan;
    Phase phase = Phase::Prepare;
    Plan plan;
};
struct Receipt {
    static constexpr Op op = Op::Receipt;
    PlanId id;
    Sha256Digest hash{};
    Evidence evidence = Evidence::Refused;
    uint32_t reason = 0; // Status of a refusal
    uint32_t clock_err_ms = 0;
};
struct TimeReq {
    static constexpr Op op = Op::TimeReq;
    std::array<uint8_t, 8> nonce{};
    RootTerm term;
    uint64_t t1_us = 0;
};
struct TimeResp {
    static constexpr Op op = Op::TimeResp;
    std::array<uint8_t, 8> nonce{};
    RootTerm term;
    uint64_t t1_us = 0, t2_us = 0, t3_us = 0;
};
struct State { // node -> root after every (re)attach: where am I
    static constexpr Op op = Op::State;
    ChannelEpoch epoch;
    uint8_t channel = 0;
};
enum class Side : uint8_t { Listen = 0, Probe = 1 };
struct Survey { // root -> node: one side of a paired visit (docs/05 §4)
    static constexpr Op op = Op::Survey;
    uint16_t sid = 0;
    Side role = Side::Listen;
    uint8_t channel = 0;
    uint16_t peer = 0; // the address of the other side (the visitor's parent)
    uint64_t start_root_ms = 0;
    uint16_t visit_ms = 0;
    uint16_t tol_ms = 0;
    uint8_t probes = 0;
};
struct SurveyResult {
    static constexpr Op op = Op::SurveyResult;
    uint16_t sid = 0;
    Side role = Side::Listen;
    uint8_t status = 0; // Status (low byte); Ok = the side was there
    uint8_t ok = 0, fail = 0;
    uint16_t service_ms = 0; // median TX-done latency of the probes, milliseconds
};
struct Degraded { // node -> root: my parent link lost > 10 % of >= 32 RF attempts in the window
    static constexpr Op op = Op::Degraded;
    uint32_t loss_q16 = 0;
    uint16_t attempts = 0;
};

inline constexpr std::size_t k_max_record = 96;

[[nodiscard]] bool is_record(ByteView body);
[[nodiscard]] Op op_of(ByteView body);

[[nodiscard]] Status plan_hash(const Plan &p, Sha256Digest &out);
// One layout per record (wire.cpp), used both ways. decode() rejects trailing bytes and out-of-range fields.
template <class M> [[nodiscard]] Status encode(const M &m, MutByteView out, std::size_t &len);
template <class M> [[nodiscard]] Status decode(ByteView body, M &out);

// Plan body as stored in the channel record and on the wire (no phase byte).
void put_plan(Writer &w, const Plan &p);
[[nodiscard]] Plan get_plan(Reader &r);
[[nodiscard]] bool valid_plan(const Plan &p);

} // namespace lm::channel
