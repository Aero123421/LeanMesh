#include "security/identity.hpp"

#include <psa/crypto.h>

#include "core/codec.hpp"
#include "core/wire/cbor.hpp"
#include "security/crypto.hpp"

namespace lm::sec {

namespace {

constexpr psa_algorithm_t k_es256 = PSA_ALG_ECDSA(PSA_ALG_SHA_256);

// 0x04 || x || y, the only public-key form PSA imports.
std::array<uint8_t, 65> uncompressed(const PublicKey &k) {
    std::array<uint8_t, 65> p{};
    p[0] = 0x04;
    for (std::size_t i = 0; i < 32; ++i) {
        p[1 + i] = k.x[i];
        p[33 + i] = k.y[i];
    }
    return p;
}

psa_key_attributes_t public_attrs() {
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_lifetime(&a, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_type(&a, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&a, k_es256);
    return a;
}

psa_key_attributes_t signing_attrs(psa_key_usage_t extra) {
    psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_lifetime(&a, PSA_KEY_LIFETIME_VOLATILE);
    psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&a, 256);
    psa_set_key_usage_flags(&a, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_SIGN_HASH | extra);
    psa_set_key_algorithm(&a, k_es256);
    return a;
}

Status export_public(psa_key_id_t id, PublicKey &out) {
    std::array<uint8_t, 65> p{};
    std::size_t len = 0;
    LM_TRY(from_psa(psa_export_public_key(id, p.data(), p.size(), &len)));
    if (len != p.size() || p[0] != 0x04) {
        return Status::RecoveryRequired;
    }
    for (std::size_t i = 0; i < 32; ++i) {
        out.x[i] = p[1 + i];
        out.y[i] = p[33 + i];
    }
    return Status::Ok;
}

void write_cose_key(wire::CborWriter &w, const PublicKey &k) {
    w.map(4);
    w.uint(1);
    w.uint(2);
    w.nint(-1);
    w.uint(1);
    w.nint(-2);
    w.bytes(ByteView{k.x.data(), k.x.size()});
    w.nint(-3);
    w.bytes(ByteView{k.y.data(), k.y.size()});
}

bool printable_ascii(ByteView s) {
    for (uint8_t c : s) {
        if (c < 0x20 || c > 0x7E) {
            return false;
        }
    }
    return true;
}

} // namespace

Status validate_public_key(const PublicKey &key) {
    const auto p = uncompressed(key);
    psa_key_attributes_t a = public_attrs();
    psa_key_id_t id = PSA_KEY_ID_NULL;
    const psa_status_t st = psa_import_key(&a, p.data(), p.size(), &id);
    psa_reset_key_attributes(&a);
    if (st == PSA_SUCCESS) {
        (void)psa_destroy_key(id);
    }
    return from_psa(st);
}

Status import_signing_key(ByteView scalar32, KeyHandle &out) {
    if (scalar32.size() != 32) {
        return Status::InvalidArgument;
    }
    psa_key_attributes_t a = signing_attrs(0);
    psa_key_id_t id = PSA_KEY_ID_NULL;
    const psa_status_t st = psa_import_key(&a, scalar32.data(), scalar32.size(), &id);
    psa_reset_key_attributes(&a);
    LM_TRY(from_psa(st));
    out.id = id;
    return Status::Ok;
}

Status generate_signing_key(std::array<uint8_t, 32> &scalar, PublicKey &pub) {
    psa_key_attributes_t a = signing_attrs(PSA_KEY_USAGE_EXPORT);
    psa_key_id_t id = PSA_KEY_ID_NULL;
    Status rc = from_psa(psa_generate_key(&a, &id));
    psa_reset_key_attributes(&a);
    LM_TRY(rc);
    std::size_t len = 0;
    rc = from_psa(psa_export_key(id, scalar.data(), scalar.size(), &len));
    if (rc == Status::Ok && len != scalar.size()) {
        rc = Status::RecoveryRequired;
    }
    if (rc == Status::Ok) {
        rc = export_public(id, pub);
    }
    (void)psa_destroy_key(id);
    if (rc != Status::Ok) {
        secure_zero(MutByteView{scalar.data(), scalar.size()});
    }
    return rc;
}

Status public_key_of(KeyHandle key, PublicKey &out) {
    return key.id == 0 ? Status::InvalidArgument : export_public(key.id, out);
}

void destroy_key(KeyHandle &key) {
    if (key.id != 0) {
        (void)psa_destroy_key(key.id);
        key.id = 0;
    }
}

Status sign_es256_digest(KeyHandle key, const Sha256Digest &digest, Signature &out) {
    if (key.id == 0) {
        return Status::InvalidArgument;
    }
    std::size_t len = 0;
    LM_TRY(from_psa(psa_sign_hash(key.id, k_es256, digest.data(), digest.size(), out.data(),
                                  out.size(), &len)));
    return len == out.size() ? Status::Ok : Status::RecoveryRequired;
}

Status sign_es256(KeyHandle key, ByteView message, Signature &out) {
    Sha256Digest digest{};
    LM_TRY(sha256(message, digest));
    return sign_es256_digest(key, digest, out);
}

Status verify_es256_digest(const PublicKey &key, const Sha256Digest &digest, ByteView signature) {
    if (signature.size() != 64) {
        return Status::AuthRejected;
    }
    const auto p = uncompressed(key);
    psa_key_attributes_t a = public_attrs();
    psa_key_id_t id = PSA_KEY_ID_NULL;
    const psa_status_t imp = psa_import_key(&a, p.data(), p.size(), &id);
    psa_reset_key_attributes(&a);
    LM_TRY(from_psa(imp)); // invalid point: the key is rejected, never used
    const psa_status_t st = psa_verify_hash(id, k_es256, digest.data(), digest.size(),
                                            signature.data(), signature.size());
    (void)psa_destroy_key(id);
    return from_psa(st); // INVALID_SIGNATURE -> AuthRejected
}

Status verify_es256(const PublicKey &key, ByteView message, ByteView signature) {
    Sha256Digest digest{};
    LM_TRY(sha256(message, digest));
    return verify_es256_digest(key, digest, signature);
}

Status cose_key_encode(const PublicKey &key, MutByteView out) {
    if (out.size() < k_cose_key_bytes) {
        return Status::BufferTooSmall;
    }
    wire::CborWriter w{MutByteView{out.data(), k_cose_key_bytes}};
    write_cose_key(w, key);
    LM_TRY(w.finish());
    return w.size() == k_cose_key_bytes ? Status::Ok : Status::RecoveryRequired;
}

Status device_id_of(const PublicKey &key, DeviceId &out) {
    std::array<uint8_t, k_cose_key_bytes> enc{};
    LM_TRY(cose_key_encode(key, MutByteView{enc.data(), enc.size()}));
    return sha256(ByteView{enc.data(), enc.size()}, out.bytes);
}

Status ccs_encode(ByteView subject, const PublicKey &key, MutByteView out, std::size_t &len) {
    if (subject.size() > k_ccs_subject_max || !printable_ascii(subject)) {
        return Status::InvalidArgument;
    }
    wire::CborWriter w{out};
    w.map(2);
    w.uint(2);
    w.text(subject);
    w.uint(8);
    w.map(1);
    w.uint(1);
    write_cose_key(w, key);
    LM_TRY(w.finish() == Status::Ok ? Status::Ok : Status::BufferTooSmall);
    len = w.size();
    return Status::Ok;
}

Status ccs_parse(ByteView ccs, PublicKey &key, DeviceId &device) {
    // Locate the fields with fixed-position reads, then require that re-encoding them reproduces the
    // input byte for byte. That single comparison enforces canonical heads, key order and no extras.
    Reader r{ccs};
    if (r.u8() != 0xA2 || r.u8() != 0x02) {
        return Status::BadFrame;
    }
    const uint8_t head = r.u8();
    std::size_t n = 0;
    if (head >= 0x60 && head <= 0x77) {
        n = head - 0x60U;
    } else if (head == 0x78) {
        n = r.u8();
    } else {
        return Status::BadFrame;
    }
    const ByteView subject = r.bytes(n);
    const ByteView tail = r.bytes(r.remaining());
    // tail = 08 a1 01 <COSE_Key>: x at offset 3 + 8, y at 3 + 43.
    if (!r.ok() || tail.size() != 3 + k_cose_key_bytes) {
        return Status::BadFrame;
    }
    PublicKey k;
    for (std::size_t i = 0; i < 32; ++i) {
        k.x[i] = tail[3 + 8 + i];
        k.y[i] = tail[3 + 43 + i];
    }
    std::array<uint8_t, k_ccs_max_bytes> again{};
    std::size_t again_len = 0;
    if (ccs_encode(subject, k, MutByteView{again.data(), again.size()}, again_len) != Status::Ok ||
        !bytes_equal(ByteView{again.data(), again_len}, ccs)) {
        return Status::BadFrame;
    }
    LM_TRY(validate_public_key(k));
    LM_TRY(device_id_of(k, device));
    key = k;
    return Status::Ok;
}

} // namespace lm::sec
