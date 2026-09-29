#include "security/cose_sign1.hpp"

#include <array>

#include <psa/crypto.h>

#include "core/codec.hpp"
#include "core/wire/cbor.hpp"
#include "security/crypto.hpp"

namespace lm::sec {

namespace {

constexpr std::size_t k_protected_bytes = 38; // a2 01 26 04 58 20 kid32

Status protected_header(const DeviceId &kid, std::array<uint8_t, k_protected_bytes> &out) {
    wire::CborWriter w{MutByteView{out.data(), out.size()}};
    w.map(2);
    w.uint(1);
    w.nint(-7); // alg ES256
    w.uint(4);
    w.bytes(kid.view()); // kid = DeviceId
    LM_TRY(w.finish());
    return w.size() == out.size() ? Status::Ok : Status::RecoveryRequired;
}

// Head of a byte string of `n` bytes in shortest form (n <= 65535). Returns the head length.
std::size_t bstr_head(std::size_t n, std::array<uint8_t, 3> &h) {
    if (n < 24) {
        h[0] = static_cast<uint8_t>(0x40U | n);
        return 1;
    }
    if (n < 256) {
        h[0] = 0x58;
        h[1] = static_cast<uint8_t>(n);
        return 2;
    }
    h[0] = 0x59;
    h[1] = static_cast<uint8_t>(n >> 8);
    h[2] = static_cast<uint8_t>(n);
    return 3;
}

// SHA-256(Sig_structure) with Sig_structure = ["Signature1", protected, "LM1-CONTROL", payload].
Status sig_structure_digest(const std::array<uint8_t, k_protected_bytes> &prot, ByteView payload,
                            Sha256Digest &digest) {
    std::array<uint8_t, 1 + 11 + 2 + k_protected_bytes + 1 + 11 + 3> head{};
    wire::CborWriter w{MutByteView{head.data(), head.size()}};
    w.array(4);
    w.text(wire::ascii("Signature1"));
    w.bytes(ByteView{prot.data(), prot.size()});
    w.bytes(wire::ascii("LM1-CONTROL"));
    LM_TRY(w.finish());
    std::size_t n = w.size();
    std::array<uint8_t, 3> ph{};
    const std::size_t phl = bstr_head(payload.size(), ph);
    for (std::size_t i = 0; i < phl; ++i) {
        head[n++] = ph[i];
    }
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    psa_status_t st = psa_hash_setup(&op, PSA_ALG_SHA_256);
    if (st == PSA_SUCCESS) {
        st = psa_hash_update(&op, head.data(), n);
    }
    if (st == PSA_SUCCESS && !payload.empty()) {
        st = psa_hash_update(&op, payload.data(), payload.size());
    }
    std::size_t len = 0;
    if (st == PSA_SUCCESS) {
        st = psa_hash_finish(&op, digest.data(), digest.size(), &len);
    }
    if (st != PSA_SUCCESS) {
        psa_hash_abort(&op);
        return from_psa(st);
    }
    return len == digest.size() ? Status::Ok : Status::RecoveryRequired;
}

} // namespace

Status sign1_create(KeyHandle key, const DeviceId &kid, ByteView payload, MutByteView out,
                    std::size_t &len) {
    // 2 (tag+array) + 2+38 (protected) + 1 (unprotected) + <=3 (payload head) + payload + 2+64.
    if (payload.size() + 112 > k_cose_sign1_max_bytes) {
        return Status::PayloadTooLarge;
    }
    std::array<uint8_t, k_protected_bytes> prot{};
    LM_TRY(protected_header(kid, prot));
    Sha256Digest digest{};
    LM_TRY(sig_structure_digest(prot, payload, digest));
    Signature sig{};
    LM_TRY(sign_es256_digest(key, digest, sig));
    wire::CborWriter w{out};
    w.tag(18);
    w.array(4);
    w.bytes(ByteView{prot.data(), prot.size()});
    w.map(0);
    w.bytes(payload);
    w.bytes(ByteView{sig.data(), sig.size()});
    LM_TRY(w.finish() == Status::Ok ? Status::Ok : Status::BufferTooSmall);
    len = w.size();
    return Status::Ok;
}

Status sign1_parse(ByteView cose, Sign1View &out) {
    if (cose.size() > k_cose_sign1_max_bytes) {
        return Status::BadFrame;
    }
    Reader r{cose};
    // d2 84 | 58 26 | protected(38) | a0 | payload bstr | 58 40 | sig(64)
    if (r.u8() != 0xD2 || r.u8() != 0x84 || r.u8() != 0x58 || r.u8() != k_protected_bytes) {
        return Status::BadFrame;
    }
    const ByteView prot = r.bytes(k_protected_bytes);
    if (!r.ok() || prot[0] != 0xA2 || prot[1] != 0x01 || prot[2] != 0x26 || prot[3] != 0x04 ||
        prot[4] != 0x58 || prot[5] != 0x20 || r.u8() != 0xA0) {
        return Status::BadFrame;
    }
    const uint8_t head = r.u8();
    std::size_t n = 0;
    if (head >= 0x40 && head <= 0x57) {
        n = head - 0x40U;
    } else if (head == 0x58) {
        n = r.u8();
        if (n < 24) {
            return Status::BadFrame; // not shortest form
        }
    } else if (head == 0x59) {
        n = r.u16be();
        if (n < 256) {
            return Status::BadFrame;
        }
    } else {
        return Status::BadFrame;
    }
    const ByteView payload = r.bytes(n);
    if (r.u8() != 0x58 || r.u8() != 0x40) {
        return Status::BadFrame;
    }
    const ByteView sig = r.bytes(64);
    LM_TRY(r.finish());
    for (std::size_t i = 0; i < 32; ++i) {
        out.kid.bytes[i] = prot[6 + i];
    }
    out.payload = payload;
    out.signature = sig;
    return Status::Ok;
}

Status sign1_verify(const PublicKey &signer, ByteView cose, Sign1View &out) {
    Sign1View v;
    LM_TRY(sign1_parse(cose, v));
    DeviceId expected;
    LM_TRY(device_id_of(signer, expected));
    if (expected != v.kid) {
        return Status::AuthRejected;
    }
    std::array<uint8_t, k_protected_bytes> prot{};
    LM_TRY(protected_header(v.kid, prot));
    Sha256Digest digest{};
    LM_TRY(sig_structure_digest(prot, v.payload, digest));
    LM_TRY(verify_es256_digest(signer, digest, v.signature));
    out = v;
    return Status::Ok;
}

} // namespace lm::sec
