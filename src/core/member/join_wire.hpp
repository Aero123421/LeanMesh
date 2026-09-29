// Wire objects of the Join protocol (docs/07 §4, protocol/control.cddl types 6..10 and 27).
// Pure codecs: no state, no crypto, no I/O. The join objects are AEAD-only control bodies that
// travel inside a JOIN_ONLY session (frame kind CONTROL), never signed objects. What a joiner and
// the root exchange:
//   JoinRequest  device -> root   [device-credential, ticket, nonce, capabilities]
//   JoinPrepare  root -> device   [member-credential, prepare-hash, address, membership, term, ms]
//   JoinStored   device -> root   [prepare-hash, record-generation]   device stored + read back
//   JoinCommit   root -> device   [prepare-hash, membership, member-signature]  root ACTIVE ledger committed
//   JoinActive   device -> root   [prepare-hash, record-generation]   device ACTIVE committed
//   JoinActive   root -> device   same bytes                          root recorded it (final ack)
//   JoinCommit   root -> device   prepare-hash all zero, membership = Status code (>0), no signature: refusal
// (decisions S8-D2/D3: control.cddl has no refusal or final-ack type and types may not be added.)
// SEC-D1: the member-credential of JoinPrepare has its signature withheld (64 zero bytes; prepare-hash is the
// SHA-256 of exactly that form) and JoinCommit carries the 64 bytes, sent only after the ACTIVE entry is durable.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/ids.hpp"
#include "core/status.hpp"
#include "core/wire/control.hpp"
#include "core/wire/transfer.hpp"

namespace lm::member {

inline constexpr uint8_t k_type_join_request = 6;
inline constexpr uint8_t k_type_join_prepare = 7;
inline constexpr uint8_t k_type_join_stored = 8;
inline constexpr uint8_t k_type_join_commit = 9;
inline constexpr uint8_t k_type_join_active = 10;
inline constexpr uint8_t k_type_leave_request = 27;

inline constexpr std::size_t k_max_delegation_bundle = 1024;
// Join objects are chunked into CONTROL frames of this many bytes (frame 250 - link 24 - tag 16 -
// chunk header 5 = 205; kept round and below every retransmission concern).
inline constexpr std::size_t k_join_chunk_bytes = 160;
inline constexpr std::size_t k_join_chunk_header = 5;
inline constexpr std::size_t k_join_max_object = 1100;

// ---- credential swap ----
// CredR of a JOIN handshake: CBOR [DeviceCredential COSE, RootDelegation COSE]. (CredI is the raw
// DeviceCredential COSE alone.)
struct JoinBundle {
    ByteView device_cose;
    ByteView delegation_cose;
};
[[nodiscard]] Status join_bundle_encode(ByteView device_cose, ByteView delegation_cose, MutByteView out,
                                        std::size_t &len);
[[nodiscard]] Status join_bundle_parse(ByteView in, JoinBundle &out);

// ---- discovery hints (JOIN_PROXY carrier object kinds outside the exchange's 1..6) ----
inline constexpr uint8_t k_obj_join_hello = 0x10; // broadcast by an unjoined device; exchange_id = nonce
inline constexpr uint8_t k_obj_join_offer = 0x11; // unicast reply of an open root/proxy; echoes the nonce
// Hints only: neither is an authorisation (docs/07 §3). The body is one version byte.
// [S11] What an offer tells besides "I exist": how deep in the tree the offerer sits (0 = the root itself;
// a joiner behind a relay paces and waits accordingly) and the low 32 bits of the root's expected-list
// revision (a higher one than the joiner was refused at ends its NOT_EXPECTED wait, docs/07 §3). Hints only.
// SEC-Da: a node holding a DiscoveryScopeKey adds its scope tag (member::scope_tag). Bodies:
//   hello [1] | [3, tag8]      offer [1] (S8) | [2, depth, revision u32] | [4, depth, revision u32, tag8]
struct OfferHint {
    uint8_t depth = 0;
    uint32_t expected_revision = 0;
    bool scoped = false;
    std::array<uint8_t, 8> tag{};
};
[[nodiscard]] Status encode_discovery(bool offer, const std::array<uint8_t, 16> &nonce, uint32_t domain_hint,
                                      MutByteView out, std::size_t &len,
                                      const OfferHint *hint = nullptr); // whole link frame
// An offer body; a one-byte body (an offer of S8) reads as depth 0, revision 0.
[[nodiscard]] Status decode_offer_hint(ByteView body, OfferHint &out);
// A hello body ([1] or, scoped, [3, tag8]).
[[nodiscard]] Status decode_hello(ByteView body, OfferHint &out);

// ---- object envelope ----
struct JoinObjectHeader {
    uint8_t type = 0;
    RequestId request;
    DomainId domain;
    uint64_t revision = 0;
    DeviceId issuer;
};
// Builds control-body(type, ...) around an already encoded data item.
[[nodiscard]] Status join_object_build(const JoinObjectHeader &h, ByteView data, MutByteView out,
                                       std::size_t &len);
// The envelope alone (array(7) head, type, version, ids, revision, issuer): the caller appends the
// encoded data item straight after it, so a large object is built once, in place.
[[nodiscard]] Status join_object_begin(const JoinObjectHeader &h, MutByteView out, std::size_t &len);
// Strict decode of a session control body of type 6..10 / 27; `data` aliases `plain`.
[[nodiscard]] Status join_object_parse(ByteView plain, JoinObjectHeader &h, ByteView &data);

// ---- data items ----
struct JoinRequestData {
    ByteView device_credential;
    ByteView ticket;
    std::array<uint8_t, 16> nonce{};
    uint64_t capabilities = 0;
};
[[nodiscard]] Status encode_join_request(const JoinRequestData &d, MutByteView out, std::size_t &len);
[[nodiscard]] Status decode_join_request(ByteView data, JoinRequestData &out);

struct JoinPrepareData {
    ByteView member; // COSE_Sign1; the encoder writes its last 64 bytes (the signature) as zero (SEC-D1)
    Sha256Digest prepare_hash{};
    ShortAddr address;
    uint64_t membership = 0;
    uint32_t root_term = 0;
    uint32_t reservation_ms = 0;
};
[[nodiscard]] Status encode_join_prepare(const JoinPrepareData &d, MutByteView out, std::size_t &len);
[[nodiscard]] Status decode_join_prepare(ByteView data, JoinPrepareData &out);

// [prepare-hash, u63]: STORED/ACTIVE carry the record generation.
struct JoinAckData {
    Sha256Digest prepare_hash{};
    uint64_t value = 0;
};
[[nodiscard]] Status encode_join_ack(const JoinAckData &d, MutByteView out, std::size_t &len);
[[nodiscard]] Status decode_join_ack(ByteView data, JoinAckData &out);

// [prepare-hash, membership, member-signature (64 B; empty in a refusal)] (SEC-D1). A refusal has an all-zero
// prepare-hash and the reason in `membership` (S8-D3).
struct JoinCommitData {
    Sha256Digest prepare_hash{};
    uint64_t membership = 0;
    std::array<uint8_t, 64> signature{};
    bool refusal = false;
};
[[nodiscard]] Status encode_join_commit(const JoinCommitData &d, MutByteView out, std::size_t &len);
[[nodiscard]] Status decode_join_commit(ByteView data, JoinCommitData &out);

struct LeaveData {
    DeviceId device;
    uint8_t mode = 0; // LM_LEAVE_DRAIN / LM_LEAVE_IMMEDIATE
    uint32_t deadline_ms = 0;
};
[[nodiscard]] Status encode_leave(const LeaveData &d, MutByteView out, std::size_t &len);
[[nodiscard]] Status decode_leave(ByteView data, LeaveData &out);

// ---- the in-order chunk (decision ARCH-D3: the one format for objects sent in order) ----
// chunk = tag u8 (never 0) | total u16 | offset u16 | bytes; offsets are contiguous from 0. Used
// for the JOIN_ONLY control objects over CONTROL frames (tag = object id, S8-D4) and for the
// handshake objects the exchange carries over a route (tag = object kind, S9-D2). An ack chunk
// (JOIN_ONLY only) has total 0 and no bytes and tells the sender its object arrived (a pending
// approval may take minutes, so waiting for the next protocol message alone would exhaust the
// retransmissions).
struct JoinChunk {
    uint8_t object_id = 0;
    uint16_t total = 0;
    uint16_t offset = 0;
    ByteView bytes;
    bool ack = false; // total 0, no bytes: "object object_id arrived completely" (transport ack)
};
[[nodiscard]] Status encode_chunk(const JoinChunk &c, MutByteView out, std::size_t &len);
[[nodiscard]] Status decode_chunk(ByteView in, JoinChunk &out);

} // namespace lm::member
