// Device keys, DeviceId, the deterministic COSE_Key/CCS encodings and ES256 over PSA (docs/06 §3-4).
// The COSE_Key has exactly one encoding, so one public key has exactly one DeviceId. Public-key
// operations here (sign, verify, import validation) belong on the slow-job worker, not the owner.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/ids.hpp"
#include "core/status.hpp"

namespace lm::sec {

// PSA key handle of a volatile private key. id 0 = none. The key material never leaves PSA except
// through generate_signing_key() (provisioning) and is destroyed with destroy_key().
struct KeyHandle {
    uint32_t id = 0;
};

struct PublicKey {
    std::array<uint8_t, 32> x{};
    std::array<uint8_t, 32> y{};
};

using Signature = std::array<uint8_t, 64>; // raw r || s (COSE ES256)

inline constexpr std::size_t k_cose_key_bytes = 75;
inline constexpr std::size_t k_ccs_subject_max = 64;
inline constexpr std::size_t k_ccs_max_bytes = 160; // {2: tstr<=64, 8: {1: COSE_Key}}

// True when (x, y) is a valid P-256 point (on the curve, canonical coordinates). PSA performs the
// check while importing; InvalidArgument otherwise.
[[nodiscard]] Status validate_public_key(const PublicKey &key);

// Imports a raw 32-byte scalar as a volatile ES256 signing key (rejects 0 and values >= n).
[[nodiscard]] Status import_signing_key(ByteView scalar32, KeyHandle &out);
// Provisioning/test only: generates a key inside PSA and exports scalar + public key. The transient
// PSA handle is destroyed before returning; the caller owns the secret bytes and must wipe them.
[[nodiscard]] Status generate_signing_key(std::array<uint8_t, 32> &scalar, PublicKey &pub);
[[nodiscard]] Status public_key_of(KeyHandle key, PublicKey &out);
void destroy_key(KeyHandle &key);

// ES256 over `message` (SHA-256 first, then ECDSA P-256 with PSA's randomised nonce).
[[nodiscard]] Status sign_es256(KeyHandle key, ByteView message, Signature &out);
// Ok, or AuthRejected for a wrong signature, InvalidArgument for an invalid public key.
[[nodiscard]] Status verify_es256(const PublicKey &key, ByteView message, ByteView signature);
// Same over an already computed SHA-256 digest (COSE objects are hashed in pieces, not buffered).
[[nodiscard]] Status sign_es256_digest(KeyHandle key, const Sha256Digest &digest, Signature &out);
[[nodiscard]] Status verify_es256_digest(const PublicKey &key, const Sha256Digest &digest,
                                         ByteView signature);

// COSE_Key {1:2, -1:1, -2:x, -3:y} (docs/06 §3). Writes exactly k_cose_key_bytes.
[[nodiscard]] Status cose_key_encode(const PublicKey &key, MutByteView out);
// DeviceId = SHA-256(deterministic COSE_Key).
[[nodiscard]] Status device_id_of(const PublicKey &key, DeviceId &out);

// CCS = {2: subject, 8: {1: COSE_Key}} (protocol/control.cddl). `subject` is printable ASCII, at
// most k_ccs_subject_max bytes. `len` receives the encoded size.
[[nodiscard]] Status ccs_encode(ByteView subject, const PublicKey &key, MutByteView out,
                                std::size_t &len);
// Strict parse: accepts only the byte-exact deterministic form ccs_encode() produces (no other
// keys, no trailing bytes, shortest heads), and a valid curve point. BadFrame / InvalidArgument.
[[nodiscard]] Status ccs_parse(ByteView ccs, PublicKey &key, DeviceId &device);

} // namespace lm::sec
