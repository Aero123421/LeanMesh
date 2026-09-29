// ControlObject envelope and COSE_Sign1 (docs/09 §8, docs/19 §1, protocol/control.cddl).
// Decoding validates the whole object, including the mandatory type -> data shape table.
// It never verifies signatures or authority: that is the security/identity layer's job.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/status.hpp"

namespace lm::wire {

inline constexpr uint8_t k_control_version = 1;
inline constexpr std::size_t k_cose_max_bytes = 4096;

// Where a control-body travels. Persistent authorization objects (registry signed types) exist
// only inside COSE_Sign1; every other type exists only inside a session AEAD. Mixing them up is
// AuthRejected (docs/19 §1: an unsigned control may not stand in for a signed one).
enum class ControlCarrier : uint8_t { Signed, Session };

[[nodiscard]] bool is_signed_control_type(uint8_t type);
// 1..21 and 25..33. 22..24 are reserved and rejected.
[[nodiscard]] bool is_control_type_defined(uint8_t type);

struct ControlBody {
    uint8_t type = 0;
    uint8_t version = k_control_version;
    std::array<uint8_t, 16> request_id{};
    std::array<uint8_t, 16> domain{};
    uint64_t revision = 0; // u63
    std::array<uint8_t, 32> issuer{};
    ByteView data; // encoded `control-data` item; aliases the input (decode) or the caller (encode)
};

// Unsupported: version != 1 or undefined/reserved type. BadFrame: any other malformation
// (including data that does not match its type's shape). AuthRejected: wrong carrier.
[[nodiscard]] Status decode_control_body(ByteView in, ControlCarrier carrier, ControlBody &out);
// `data` must already be the deterministic encoding of the type's data item.
[[nodiscard]] Status encode_control_body(const ControlBody &body, MutByteView out, std::size_t &len);

struct CoseSign1 {
    ByteView protected_bytes; // bstr content: {1: -7, 4: kid}
    std::array<uint8_t, 32> kid{};
    ByteView payload;   // deterministic control-body
    ByteView signature; // 64 bytes, raw r||s
};

// Tag 18, [protected, {}, payload, signature]. Total size <= 4096 (docs/09 §6 object limit).
[[nodiscard]] Status decode_cose_sign1(ByteView in, CoseSign1 &out);
[[nodiscard]] Status encode_cose_sign1(const std::array<uint8_t, 32> &kid, ByteView payload,
                                       ByteView signature64, MutByteView out, std::size_t &len);
// Sig_structure = ["Signature1", protected, h'LM1-CONTROL', payload] is emitted as
// prefix || payload so a signer/verifier can hash it without a 4 KiB copy. Writes the prefix
// (everything up to and including the payload bstr head); at most k_sig_prefix_max bytes.
inline constexpr std::size_t k_sig_prefix_max = 80; // 64 fixed bytes + payload bstr head (<= 5)
[[nodiscard]] Status sig_structure_prefix(ByteView protected_bytes, std::size_t payload_len,
                                          MutByteView out, std::size_t &len);

} // namespace lm::wire
