// Proves the single crypto backend path natively: PSA (TF-PSA-Crypto from the pinned IDF tree)
// reproduces the tests/golden.json AES-GCM frames and COSE_Sign1 signature produced by the Python
// fixture generator, and libedhoc (pinned + patched) links against it. This test drives PSA
// directly; the product record layer (src/security) is the CRYPTO slice and must pass the same
// vectors through its own API.
#include <psa/crypto.h>

#include <cstring>
#include <vector>

#include "core/codec.hpp"
#include "gen/golden.hpp"
#include "lmtest.hpp"
#include "security/crypto.hpp"

// libedhoc's headers are C11 (_Static_assert); the link check lives in a C translation unit.
extern "C" int lm_test_edhoc_link_check(void);

using namespace lm;
using Bytes = std::vector<uint8_t>;

namespace {

Bytes sha(const Bytes &in) {
    Sha256Digest d{};
    LM_CHECK_OK(sec::sha256(ByteView{in.data(), in.size()}, d));
    return Bytes(d.begin(), d.end());
}

Bytes cat(std::initializer_list<Bytes> parts) {
    Bytes out;
    for (const Bytes &p : parts) {
        out.insert(out.end(), p.begin(), p.end());
    }
    return out;
}

// docs/06 §5: PRK = HKDF-Extract(ctx_hash, seed); OKM = HKDF-Expand(PRK, info, 20).
void record_key(const Bytes &seed, const Bytes &ctx, uint8_t purpose, uint8_t direction, Bytes &key,
                Bytes &prefix) {
    const Bytes ctx_hash = sha(ctx);
    Bytes info = {'L', 'M', '1', '-', 'R', 'E', 'C', 'O', 'R', 'D', purpose, direction};
    info.insert(info.end(), ctx_hash.begin(), ctx_hash.end());
    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    uint8_t okm[20];
    LM_CHECK(psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256)) == PSA_SUCCESS);
    LM_CHECK(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, ctx_hash.data(),
                                            ctx_hash.size()) == PSA_SUCCESS);
    LM_CHECK(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SECRET, seed.data(),
                                            seed.size()) == PSA_SUCCESS);
    LM_CHECK(psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO, info.data(),
                                            info.size()) == PSA_SUCCESS);
    LM_CHECK(psa_key_derivation_output_bytes(&op, okm, sizeof okm) == PSA_SUCCESS);
    psa_key_derivation_abort(&op);
    key.assign(okm, okm + 16);
    prefix.assign(okm + 16, okm + 20);
    sec::secure_zero(MutByteView{okm, sizeof okm});
}

// AES-128-GCM open; returns false on authentication failure.
bool gcm_open(const Bytes &key, const Bytes &nonce, const Bytes &aad, const Bytes &ct, Bytes &pt) {
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);
    psa_key_id_t id = PSA_KEY_ID_NULL;
    LM_CHECK(psa_import_key(&attr, key.data(), key.size(), &id) == PSA_SUCCESS);
    pt.assign(ct.size(), 0);
    size_t len = 0;
    const psa_status_t st =
        psa_aead_decrypt(id, PSA_ALG_GCM, nonce.data(), nonce.size(), aad.data(), aad.size(),
                         ct.data(), ct.size(), pt.data(), pt.size(), &len);
    (void)psa_destroy_key(id);
    pt.resize(st == PSA_SUCCESS ? len : 0);
    return st == PSA_SUCCESS;
}

Bytes nonce(const Bytes &prefix, uint64_t counter) {
    Bytes n = prefix;
    for (int i = 7; i >= 0; --i) {
        n.push_back(static_cast<uint8_t>(counter >> (8 * i)));
    }
    return n;
}

// Opens both AEAD layers of a golden frame with the docs/09 layouts. Returns the E2E payload.
bool open_frame(const gen::golden::Frame &f, const Bytes &packet, Bytes &payload) {
    const Bytes link_ctx = lmtest::from_hex(f.link_context_hex);
    const Bytes end_ctx = lmtest::from_hex(f.end_context_hex);
    Bytes lk, lp, ek, ep;
    record_key(lmtest::from_hex(f.link_exporter_test_seed_hex), link_ctx, 1, 0, lk, lp);
    record_key(lmtest::from_hex(f.end_exporter_test_seed_hex), end_ctx, 2, 0, ek, ep);

    const Bytes header(packet.begin(), packet.begin() + 24);
    Reader h{ByteView{header.data(), header.size()}};
    (void)h.bytes(12);
    const uint64_t link_counter = h.u64be();
    Bytes plain;
    if (!gcm_open(lk, nonce(lp, link_counter), cat({header, sha(link_ctx)}),
                  Bytes(packet.begin() + 24, packet.end()), plain)) {
        return false;
    }
    Reader route{ByteView{plain.data(), plain.size()}};
    (void)route.bytes(4);
    const uint8_t path_len = route.u8();
    (void)route.bytes(3);
    const uint32_t root_term = route.u32be();
    const std::size_t off = 16 + 2U * path_len;
    const Bytes end_header(plain.begin() + static_cast<long>(off),
                           plain.begin() + static_cast<long>(off) + 42);
    Reader e{ByteView{end_header.data(), end_header.size()}};
    (void)e.u32be();
    const uint64_t end_counter = e.u64be();
    const Bytes term = {static_cast<uint8_t>(root_term >> 24),
                        static_cast<uint8_t>(root_term >> 16), static_cast<uint8_t>(root_term >> 8),
                        static_cast<uint8_t>(root_term)};
    const Bytes aad =
        cat({Bytes{'L', 'M', '1', '-', 'E', 'N', 'D'}, sha(end_ctx), term, end_header});
    return gcm_open(ek, nonce(ep, end_counter), aad,
                    Bytes(plain.begin() + static_cast<long>(off) + 42, plain.end()), payload);
}

} // namespace

LM_TEST("PSA init and SHA-256 known answer") {
    LM_CHECK_OK(sec::crypto_init());
    const Bytes abc = {'a', 'b', 'c'};
    LM_CHECK(sha(abc) ==
             lmtest::from_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

LM_TEST("S04 golden AES-GCM frames open with PSA; tampering is rejected") {
    LM_CHECK_OK(sec::crypto_init());
    for (const auto &f : gen::golden::k_frames) {
        const Bytes packet = lmtest::from_hex(f.packet_hex);
        LM_CHECK_EQ(packet.size(), 250u);
        LM_CHECK(sha(packet) == lmtest::from_hex(f.packet_sha256));
        Bytes payload;
        LM_CHECK(open_frame(f, packet, payload));
        LM_CHECK(payload == lmtest::from_hex(f.payload_hex));
        LM_CHECK_EQ(payload.size(), 136u - 2u * f.hops); // docs/09 §5 capacity

        Bytes tag_flip = packet;
        tag_flip.back() ^= 1U;
        LM_CHECK(!open_frame(f, tag_flip, payload));
        Bytes header_flip = packet;
        header_flip[4] ^= 1U; // domain_hint is authenticated
        LM_CHECK(!open_frame(f, header_flip, payload));
    }
}

LM_TEST("golden COSE_Sign1 (ES256, raw r||s) verifies with PSA; DeviceId = SHA-256(COSE_Key)") {
    LM_CHECK_OK(sec::crypto_init());
    namespace c = gen::golden::cose;
    const Bytes key = lmtest::from_hex(c::cose_key_hex);
    LM_CHECK(sha(key) == lmtest::from_hex(c::device_id_hex));
    // COSE_Key {1:2, -1:1, -2:x, -3:y}: x at offset 8, y at offset 43.
    Bytes point = {0x04};
    point.insert(point.end(), key.begin() + 8, key.begin() + 40);
    point.insert(point.end(), key.begin() + 43, key.begin() + 75);
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_MESSAGE);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_key_id_t id = PSA_KEY_ID_NULL;
    LM_CHECK(psa_import_key(&attr, point.data(), point.size(), &id) == PSA_SUCCESS);
    const Bytes tbs = lmtest::from_hex(c::sig_structure_hex);
    Bytes sig = lmtest::from_hex(c::signature_raw_hex);
    LM_CHECK(psa_verify_message(id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), tbs.data(), tbs.size(),
                                sig.data(), sig.size()) == PSA_SUCCESS);
    sig[10] ^= 1U;
    LM_CHECK(psa_verify_message(id, PSA_ALG_ECDSA(PSA_ALG_SHA_256), tbs.data(), tbs.size(),
                                sig.data(), sig.size()) == PSA_ERROR_INVALID_SIGNATURE);
    (void)psa_destroy_key(id);
}

LM_TEST("libedhoc (pinned, exact-input patch) links and initialises a method-0 context") {
    LM_CHECK_EQ(lm_test_edhoc_link_check(), 0);
}

LM_TEST_MAIN()
