// COSE_Sign1 for LM1 control objects (docs/09 §8, protocol/control.cddl):
//   #6.18([ h'{1:-7, 4:kid32}', {}, payload, sig64 ])  with external_aad = "LM1-CONTROL".
// kid is the signer's DeviceId and must equal SHA-256(COSE_Key of the verifying key), so a kid can
// never be paired with a different key. The whole object, payload included, is at most 4096 bytes
// (docs/09 §6). The Sig_structure is hashed in pieces; nothing large is buffered on the stack.
// The general-purpose wire codec (S1) parses the same shape for routing; this file is the signing
// side and the strict verifier.
#pragma once

#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/ids.hpp"
#include "core/status.hpp"
#include "security/identity.hpp"

namespace lm::sec {

inline constexpr std::size_t k_cose_sign1_max_bytes = 4096;

struct Sign1View {
    DeviceId kid;
    ByteView payload; // aliases the input
    ByteView signature;
};

// Signs `payload` with `key`. `kid` must equal the DeviceId of that key (InvalidArgument otherwise).
// out receives the tagged object.
[[nodiscard]] Status sign1_create(KeyHandle key, const DeviceId &kid, ByteView payload,
                                  MutByteView out, std::size_t &len);
// Strict structural parse, no signature check: lets the caller look up the issuer for `kid` first.
// BadFrame for any deviation (extra bytes, other header params, non-shortest lengths, wrong sizes).
[[nodiscard]] Status sign1_parse(ByteView cose, Sign1View &out);
// Parse + kid == DeviceId(signer) + ES256 verification. AuthRejected on any mismatch.
[[nodiscard]] Status sign1_verify(const PublicKey &signer, ByteView cose, Sign1View &out);

} // namespace lm::sec
