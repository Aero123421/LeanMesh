// Thin wrappers over the single crypto backend: PSA Crypto (TF-PSA-Crypto from the pinned ESP-IDF
// tree, docs/06 §2). No second crypto implementation, no test shortcuts. Heavy public-key work runs
// only in job bodies on the slow worker; short symmetric operations (SHA-256, AES-GCM per frame)
// may run on the owner.
#pragma once

#include <cstddef>
#include <cstdint>

#include "core/bytes.hpp"
#include "core/ids.hpp"
#include "core/status.hpp"

namespace lm::sec {

// Maps a psa_status_t (int32_t) to Status, failing closed. The registry has no generic
// "internal error" code, so unexpected backend failures map to RecoveryRequired
// (docs/IMPLEMENTATION.md §10).
[[nodiscard]] Status from_psa(int32_t psa_status);

// Idempotent psa_crypto_init().
[[nodiscard]] Status crypto_init();

[[nodiscard]] Status sha256(ByteView data, Sha256Digest &out);

// Zeroisation that the optimiser cannot remove (mbedtls_platform_zeroize).
void secure_zero(MutByteView buf);

// Constant-time equality for MACs/tags/secrets. False when lengths differ.
[[nodiscard]] bool ct_equal(ByteView a, ByteView b);

} // namespace lm::sec
