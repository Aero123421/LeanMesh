#include "security/crypto.hpp"

#include <psa/crypto.h>

#include "mbedtls/platform_util.h"

namespace lm::sec {

Status from_psa(int32_t psa_status) {
    switch (psa_status) {
    case PSA_SUCCESS:
        return Status::Ok;
    case PSA_ERROR_NOT_SUPPORTED:
        return Status::Unsupported;
    case PSA_ERROR_INSUFFICIENT_MEMORY:
    case PSA_ERROR_INSUFFICIENT_STORAGE:
        return Status::NoCapacity;
    case PSA_ERROR_BUFFER_TOO_SMALL:
        return Status::BufferTooSmall;
    case PSA_ERROR_INVALID_ARGUMENT:
        return Status::InvalidArgument;
    case PSA_ERROR_INVALID_SIGNATURE:
        return Status::AuthRejected;
    default:
        return Status::RecoveryRequired;
    }
}

Status crypto_init() {
    // psa_crypto_init() is documented as idempotent.
    return from_psa(psa_crypto_init());
}

Status sha256(ByteView data, Sha256Digest &out) {
    std::size_t len = 0;
    const psa_status_t st =
        psa_hash_compute(PSA_ALG_SHA_256, data.data(), data.size(), out.data(), out.size(), &len);
    LM_TRY(from_psa(st));
    return len == out.size() ? Status::Ok : Status::RecoveryRequired;
}

Status sha256_parts(ByteView a, ByteView b, Sha256Digest &out) {
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    psa_status_t st = psa_hash_setup(&op, PSA_ALG_SHA_256);
    if (st == PSA_SUCCESS) {
        st = psa_hash_update(&op, a.data(), a.size());
    }
    if (st == PSA_SUCCESS) {
        st = psa_hash_update(&op, b.data(), b.size());
    }
    std::size_t len = 0;
    if (st == PSA_SUCCESS) {
        st = psa_hash_finish(&op, out.data(), out.size(), &len);
    }
    if (st != PSA_SUCCESS) {
        (void)psa_hash_abort(&op);
        return from_psa(st);
    }
    return len == out.size() ? Status::Ok : Status::RecoveryRequired;
}

void secure_zero(MutByteView buf) {
    if (!buf.empty()) {
        mbedtls_platform_zeroize(buf.data(), buf.size());
    }
}

bool ct_equal(ByteView a, ByteView b) {
    if (a.size() != b.size()) {
        return false;
    }
    uint8_t diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        diff = static_cast<uint8_t>(diff | (a[i] ^ b[i]));
    }
    return diff == 0;
}

} // namespace lm::sec
