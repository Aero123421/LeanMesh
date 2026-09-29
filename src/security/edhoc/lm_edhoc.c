/* EDHOC suite-3 glue over PSA + session driver. See lm_edhoc.h. Runs on the slow-job worker only.
 *
 * Secrets live in PSA key slots (handles, never bytes) and in the session; every exit path either
 * hands a handle to libedhoc (which destroys it in edhoc_context_deinit) or destroys it here.
 * Nothing in this file logs. */
#include "security/edhoc/lm_edhoc.h"

#include <string.h>

#include <edhoc/edhoc.h>

#define MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS
#include <psa/crypto.h>

#include <mbedtls/private/bignum.h>
#include <mbedtls/private/ecp.h>
#include "mbedtls/platform_util.h"

/* PSA is used from the mesh owner (AES-GCM per frame) and from this worker at the same time. The
 * IDF build must therefore have PSA thread safety on (docs/IMPLEMENTATION.md D16). */
#if defined(ESP_PLATFORM) && !defined(CONFIG_MBEDTLS_THREADING_C)
#error "LeanMesh needs CONFIG_MBEDTLS_THREADING_C: owner and slow-job worker share PSA"
#endif

#define P256_X_LEN 32
#define P256_POINT_LEN 65
#define SIG_LEN 64
#define HASH_LEN 32
#define AEAD_KEY_LEN 16

_Static_assert(sizeof(psa_hash_operation_t) <= sizeof(((struct lm_edhoc_crypto_ctx *)0)->hash_ops[0]),
	       "hash operation storage too small");
_Static_assert(sizeof(psa_key_id_t) == CONFIG_LIBEDHOC_KEY_ID_LEN, "key handle size");

static void wipe(void *p, size_t n) { mbedtls_platform_zeroize(p, n); }

static psa_key_id_t key_load(const void *slot) {
	psa_key_id_t k = PSA_KEY_ID_NULL;
	memcpy(&k, slot, sizeof k);
	return k;
}

static void key_store(void *slot, psa_key_id_t k) { memcpy(slot, &k, sizeof k); }

static uint8_t tag_len(void *uc) {
	return ((const struct lm_edhoc_crypto_ctx *)uc)->aead_tag_len;
}

/* A PSA failure caused by the peer's input (bad tag, bad signature, invalid point) is an ordinary
 * rejection. Anything else (out of memory, storage, hardware) is a local fault and is remembered in
 * the crypto context so the caller can report it as such instead of blaming the peer. */
static void note(void *uc, psa_status_t st) {
	switch (st) {
	case PSA_SUCCESS:
	case PSA_ERROR_INVALID_SIGNATURE:
	case PSA_ERROR_INVALID_ARGUMENT:
	case PSA_ERROR_INVALID_PADDING:
		return;
	default:
		((struct lm_edhoc_crypto_ctx *)uc)->fault = (int32_t)st;
	}
}

/* ---- P-256 x-only decompression -------------------------------------------------------------
 * G_X / G_Y / static keys arrive as x only. The point is rebuilt with y even (the shared secret
 * uses x only, so the sign of y is irrelevant) and rejected unless x < p and x^3+ax+b is a square:
 * an off-curve or non-canonical value never reaches the ECDH operation. */
static int decompress(void *uc, const uint8_t *x, size_t x_len, uint8_t out[P256_POINT_LEN]) {
	if (x == NULL || x_len != P256_X_LEN) {
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}
	int rc = EDHOC_ERROR_CRYPTO_FAILURE;
	int ret;
	mbedtls_ecp_group grp;
	mbedtls_mpi mx, rhs, y, chk, e;
	mbedtls_ecp_group_init(&grp);
	mbedtls_mpi_init(&mx);
	mbedtls_mpi_init(&rhs);
	mbedtls_mpi_init(&y);
	mbedtls_mpi_init(&chk);
	mbedtls_mpi_init(&e);
	/* An mpi error (allocation...) is a local fault; a failed comparison is an invalid point. */
#define MPI(expr)                                                                                  \
	do {                                                                                       \
		ret = (expr);                                                                      \
		if (ret != 0) {                                                                    \
			((struct lm_edhoc_crypto_ctx *)uc)->fault =                                \
				ret == MBEDTLS_ERR_MPI_ALLOC_FAILED ? PSA_ERROR_INSUFFICIENT_MEMORY        \
							      : PSA_ERROR_GENERIC_ERROR;           \
			goto done;                                                                 \
		}                                                                                  \
	} while (0)
	MPI(mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1));
	MPI(mbedtls_mpi_read_binary(&mx, x, x_len));
	if (mbedtls_mpi_cmp_mpi(&mx, &grp.P) >= 0) {
		goto done; /* non-canonical coordinate */
	}
	MPI(mbedtls_mpi_mul_mpi(&rhs, &mx, &mx));
	MPI(mbedtls_mpi_sub_int(&rhs, &rhs, 3));
	MPI(mbedtls_mpi_mul_mpi(&rhs, &rhs, &mx));
	MPI(mbedtls_mpi_add_mpi(&rhs, &rhs, &grp.B));
	MPI(mbedtls_mpi_mod_mpi(&rhs, &rhs, &grp.P)); /* rhs = x^3 - 3x + b mod p */
	MPI(mbedtls_mpi_add_int(&e, &grp.P, 1));
	MPI(mbedtls_mpi_shift_r(&e, 2));
	MPI(mbedtls_mpi_exp_mod(&y, &rhs, &e, &grp.P, NULL)); /* p = 3 mod 4: y = rhs^((p+1)/4) */
	MPI(mbedtls_mpi_mul_mpi(&chk, &y, &y));
	MPI(mbedtls_mpi_mod_mpi(&chk, &chk, &grp.P));
	if (mbedtls_mpi_cmp_mpi(&chk, &rhs) != 0) {
		goto done; /* x^3 - 3x + b is not a square: no such point */
	}
	if (mbedtls_mpi_get_bit(&y, 0) != 0) {
		MPI(mbedtls_mpi_sub_mpi(&y, &grp.P, &y));
	}
	out[0] = 0x04;
	memcpy(out + 1, x, P256_X_LEN);
	MPI(mbedtls_mpi_write_binary(&y, out + 1 + P256_X_LEN, P256_X_LEN));
	rc = EDHOC_SUCCESS;
#undef MPI
done:
	mbedtls_mpi_free(&mx);
	mbedtls_mpi_free(&rhs);
	mbedtls_mpi_free(&y);
	mbedtls_mpi_free(&chk);
	mbedtls_mpi_free(&e);
	mbedtls_ecp_group_free(&grp);
	return rc;
}

/* ---- key attribute helpers ------------------------------------------------------------------ */
static void derive_attrs(psa_key_attributes_t *a, size_t bytes) {
	psa_set_key_lifetime(a, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(a, PSA_KEY_TYPE_DERIVE);
	psa_set_key_usage_flags(a, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(a, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));
	psa_set_key_enrollment_algorithm(a, PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256));
	psa_set_key_bits(a, PSA_BYTES_TO_BITS(bytes));
}

static int ecdh_pair(void *uc, psa_key_id_t *out, uint8_t x_out[P256_X_LEN]) {
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&a, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_bits(&a, 256);
	psa_set_key_usage_flags(&a, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&a, PSA_ALG_ECDH);
	psa_key_id_t k = PSA_KEY_ID_NULL;
	psa_status_t st = psa_generate_key(&a, &k);
	if (st != PSA_SUCCESS) {
		note(uc, st);
		return EDHOC_ERROR_EPHEMERAL_KEY_EXCHANGE_FAILURE;
	}
	uint8_t pt[P256_POINT_LEN];
	size_t len = 0;
	st = psa_export_public_key(k, pt, sizeof pt, &len);
	if (st != PSA_SUCCESS || len != sizeof pt) {
		note(uc, st);
		(void)psa_destroy_key(k);
		return EDHOC_ERROR_EPHEMERAL_KEY_EXCHANGE_FAILURE;
	}
	memcpy(x_out, pt + 1, P256_X_LEN); /* EDHOC carries x only */
	*out = k;
	return EDHOC_SUCCESS;
}

static int ecdh(void *uc, psa_key_id_t priv, const uint8_t *peer_x, size_t peer_len,
		void *secret_slot) {
	uint8_t pt[P256_POINT_LEN];
	if (priv == PSA_KEY_ID_NULL || decompress(uc, peer_x, peer_len, pt) != EDHOC_SUCCESS) {
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	derive_attrs(&a, HASH_LEN);
	psa_key_id_t out = PSA_KEY_ID_NULL;
	const psa_status_t st = psa_key_agreement(priv, pt, sizeof pt, PSA_ALG_ECDH, &a, &out);
	psa_reset_key_attributes(&a);
	if (st != PSA_SUCCESS) {
		note(uc, st);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}
	key_store(secret_slot, out);
	return EDHOC_SUCCESS;
}

/* ---- struct edhoc_crypto ---------------------------------------------------------------------- */
static int c_destroy_key(void *uc, void *key_id) {
	(void)uc;
	const psa_key_id_t k = key_load(key_id);
	if (k == PSA_KEY_ID_NULL) {
		return EDHOC_SUCCESS;
	}
	return psa_destroy_key(k) == PSA_SUCCESS ? EDHOC_SUCCESS : EDHOC_ERROR_CRYPTO_FAILURE;
}

static int c_generate_key_pair(void *uc, void *decaps, uint8_t *encaps, size_t cap, size_t *len) {
	psa_key_id_t k;
	if (cap < P256_X_LEN) {
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}
	const int rc = ecdh_pair(uc, &k, encaps);
	if (rc != EDHOC_SUCCESS) {
		return rc;
	}
	key_store(decaps, k);
	*len = P256_X_LEN;
	return EDHOC_SUCCESS;
}

/* NIKE-as-KEM: the responder's fresh ephemeral public key is the "ciphertext" G_Y. */
static int c_encapsulate(void *uc, const uint8_t *encaps, size_t encaps_len, void *decaps,
			 void *secret, uint8_t *ct, size_t ct_cap, size_t *ct_len) {
	psa_key_id_t k;
	if (ct_cap < P256_X_LEN) {
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}
	int rc = ecdh_pair(uc, &k, ct);
	if (rc != EDHOC_SUCCESS) {
		return rc;
	}
	rc = ecdh(uc, k, encaps, encaps_len, secret);
	if (rc != EDHOC_SUCCESS) {
		(void)psa_destroy_key(k);
		return EDHOC_ERROR_EPHEMERAL_KEY_EXCHANGE_FAILURE;
	}
	key_store(decaps, k);
	*ct_len = P256_X_LEN;
	return EDHOC_SUCCESS;
}

static int c_decapsulate(void *uc, const void *decaps, const uint8_t *ct, size_t ct_len,
			 void *secret) {
	return ecdh(uc, key_load(decaps), ct, ct_len, secret) == EDHOC_SUCCESS
		       ? EDHOC_SUCCESS
		       : EDHOC_ERROR_EPHEMERAL_KEY_EXCHANGE_FAILURE;
}

static int c_key_agreement(void *uc, const void *priv, const uint8_t *peer, size_t peer_len,
			   void *secret) {
	return ecdh(uc, key_load(priv), peer, peer_len, secret);
}

static int c_sign(void *uc, const void *priv, const uint8_t *in, size_t in_len, uint8_t *sig,
		  size_t sig_cap, size_t *sig_len) {
	if (sig_cap < SIG_LEN) {
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}
	const psa_status_t st = psa_sign_message(key_load(priv), PSA_ALG_ECDSA(PSA_ALG_SHA_256), in,
						 in_len, sig, sig_cap, sig_len);
	note(uc, st);
	return (st == PSA_SUCCESS && *sig_len == SIG_LEN) ? EDHOC_SUCCESS : EDHOC_ERROR_CRYPTO_FAILURE;
}

static int c_verify(void *uc, const uint8_t *pub, size_t pub_len, const uint8_t *in, size_t in_len,
		    const uint8_t *sig, size_t sig_len) {
	/* Uncompressed point only: PSA import rejects points that are not on the curve. */
	if (pub == NULL || pub_len != P256_POINT_LEN || pub[0] != 0x04 || sig_len != SIG_LEN) {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&a, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_type(&a, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
	psa_set_key_usage_flags(&a, PSA_KEY_USAGE_VERIFY_MESSAGE);
	psa_set_key_algorithm(&a, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
	psa_key_id_t k = PSA_KEY_ID_NULL;
	const psa_status_t imp = psa_import_key(&a, pub, pub_len, &k);
	psa_reset_key_attributes(&a);
	if (imp != PSA_SUCCESS) {
		note(uc, imp);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}
	const psa_status_t st =
		psa_verify_message(k, PSA_ALG_ECDSA(PSA_ALG_SHA_256), in, in_len, sig, sig_len);
	(void)psa_destroy_key(k);
	note(uc, st);
	return st == PSA_SUCCESS ? EDHOC_SUCCESS : EDHOC_ERROR_CRYPTO_FAILURE;
}

static int c_extract(void *uc, const void *ikm, const uint8_t *salt, size_t salt_len, void *prk) {
	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	psa_key_id_t out = PSA_KEY_ID_NULL;
	derive_attrs(&a, HASH_LEN);
	psa_status_t st = psa_key_derivation_setup(&op, PSA_ALG_HKDF_EXTRACT(PSA_ALG_SHA_256));
	if (st == PSA_SUCCESS) {
		st = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_SALT, salt, salt_len);
	}
	if (st == PSA_SUCCESS) {
		st = psa_key_derivation_input_key(&op, PSA_KEY_DERIVATION_INPUT_SECRET, key_load(ikm));
	}
	if (st == PSA_SUCCESS) {
		st = psa_key_derivation_output_key(&a, &op, &out);
	}
	psa_key_derivation_abort(&op);
	psa_reset_key_attributes(&a);
	if (st != PSA_SUCCESS) {
		note(uc, st);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}
	key_store(prk, out);
	return EDHOC_SUCCESS;
}

static psa_status_t expand_setup(psa_key_derivation_operation_t *op, const void *prk,
				 const uint8_t *info, size_t info_len, size_t out_len) {
	psa_status_t st = psa_key_derivation_setup(op, PSA_ALG_HKDF_EXPAND(PSA_ALG_SHA_256));
	if (st == PSA_SUCCESS) {
		st = psa_key_derivation_input_key(op, PSA_KEY_DERIVATION_INPUT_SECRET, key_load(prk));
	}
	if (st == PSA_SUCCESS) {
		st = psa_key_derivation_input_bytes(op, PSA_KEY_DERIVATION_INPUT_INFO, info, info_len);
	}
	if (st == PSA_SUCCESS) {
		st = psa_key_derivation_set_capacity(op, out_len);
	}
	return st;
}

static int c_expand(void *uc, const void *prk, const uint8_t *info, size_t info_len,
		    enum edhoc_key_usage usage, void *out_slot) {
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	size_t out_len;
	if (usage == EDHOC_KEY_USAGE_KDF) {
		derive_attrs(&a, HASH_LEN);
		out_len = HASH_LEN;
	} else if (usage == EDHOC_KEY_USAGE_AEAD) {
		psa_set_key_lifetime(&a, PSA_KEY_LIFETIME_VOLATILE);
		psa_set_key_type(&a, PSA_KEY_TYPE_AES);
		psa_set_key_bits(&a, PSA_BYTES_TO_BITS(AEAD_KEY_LEN));
		psa_set_key_usage_flags(&a, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
		psa_set_key_algorithm(&a, PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, tag_len(uc)));
		out_len = AEAD_KEY_LEN;
	} else {
		return EDHOC_ERROR_INVALID_ARGUMENT;
	}
	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
	psa_key_id_t out = PSA_KEY_ID_NULL;
	psa_status_t st = expand_setup(&op, prk, info, info_len, out_len);
	if (st == PSA_SUCCESS) {
		st = psa_key_derivation_output_key(&a, &op, &out);
	}
	psa_key_derivation_abort(&op);
	psa_reset_key_attributes(&a);
	if (st != PSA_SUCCESS) {
		note(uc, st);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}
	key_store(out_slot, out);
	return EDHOC_SUCCESS;
}

static int c_expand_raw(void *uc, const void *prk, const uint8_t *info, size_t info_len,
			uint8_t *out, size_t out_len) {
	psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
	psa_status_t st = expand_setup(&op, prk, info, info_len, out_len);
	if (st == PSA_SUCCESS) {
		st = psa_key_derivation_output_bytes(&op, out, out_len);
	}
	psa_key_derivation_abort(&op);
	note(uc, st);
	return st == PSA_SUCCESS ? EDHOC_SUCCESS : EDHOC_ERROR_CRYPTO_FAILURE;
}

static int c_aead(void *uc, int encrypt, const void *key, const uint8_t *nonce, size_t nonce_len,
		  const uint8_t *ad, size_t ad_len, const uint8_t *in, size_t in_len, uint8_t *out,
		  size_t out_cap, size_t *out_len) {
	const psa_key_id_t k = key_load(key);
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	psa_status_t st = psa_get_key_attributes(k, &a);
	if (st != PSA_SUCCESS) {
		note(uc, st);
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}
	const psa_algorithm_t alg = psa_get_key_algorithm(&a);
	psa_reset_key_attributes(&a);
	st = encrypt ? psa_aead_encrypt(k, alg, nonce, nonce_len, ad, ad_len, in,
							   in_len, out, out_cap, out_len)
					: psa_aead_decrypt(k, alg, nonce, nonce_len, ad, ad_len, in,
							   in_len, out, out_cap, out_len);
	note(uc, st);
	return st == PSA_SUCCESS ? EDHOC_SUCCESS : EDHOC_ERROR_CRYPTO_FAILURE;
}

static int c_aead_encrypt(void *uc, const void *key, const uint8_t *nonce, size_t nonce_len,
			  const uint8_t *ad, size_t ad_len, const uint8_t *pt, size_t pt_len,
			  uint8_t *ct, size_t ct_cap, size_t *ct_len) {
	return c_aead(uc, 1, key, nonce, nonce_len, ad, ad_len, pt, pt_len, ct, ct_cap, ct_len);
}

static int c_aead_decrypt(void *uc, const void *key, const uint8_t *nonce, size_t nonce_len,
			  const uint8_t *ad, size_t ad_len, const uint8_t *ct, size_t ct_len,
			  uint8_t *pt, size_t pt_cap, size_t *pt_len) {
	return c_aead(uc, 0, key, nonce, nonce_len, ad, ad_len, ct, ct_len, pt, pt_cap, pt_len);
}

/* Multipart hash operations live in the crypto context (no global pool). */
static psa_hash_operation_t *hash_slot(struct lm_edhoc_crypto_ctx *c, const void *op, unsigned *idx) {
	for (unsigned i = 0; i < LM_EDHOC_HASH_OPS; ++i) {
		if ((void *)c->hash_ops[i] == op && (c->hash_ops_busy & (1U << i)) != 0) {
			*idx = i;
			return (psa_hash_operation_t *)c->hash_ops[i];
		}
	}
	return NULL;
}

static int c_hash_init(void *uc, void **op) {
	struct lm_edhoc_crypto_ctx *c = uc;
	for (unsigned i = 0; i < LM_EDHOC_HASH_OPS; ++i) {
		if ((c->hash_ops_busy & (1U << i)) == 0) {
			psa_hash_operation_t *h = (psa_hash_operation_t *)c->hash_ops[i];
			*h = (psa_hash_operation_t)PSA_HASH_OPERATION_INIT;
			const psa_status_t st = psa_hash_setup(h, PSA_ALG_SHA_256);
			if (st != PSA_SUCCESS) {
				note(uc, st);
				return EDHOC_ERROR_CRYPTO_FAILURE;
			}
			c->hash_ops_busy |= 1U << i;
			*op = h;
			return EDHOC_SUCCESS;
		}
	}
	return EDHOC_ERROR_NOT_ENOUGH_MEMORY;
}

static int c_hash_update(void *uc, void *op, const uint8_t *in, size_t len) {
	unsigned i;
	psa_hash_operation_t *h = hash_slot(uc, op, &i);
	return (h != NULL && psa_hash_update(h, in, len) == PSA_SUCCESS) ? EDHOC_SUCCESS
									  : EDHOC_ERROR_CRYPTO_FAILURE;
}

static int c_hash_finish(void *uc, void *op, uint8_t *hash, size_t cap, size_t *len) {
	unsigned i;
	psa_hash_operation_t *h = hash_slot(uc, op, &i);
	if (h == NULL) {
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}
	const psa_status_t st = psa_hash_finish(h, hash, cap, len);
	psa_hash_abort(h);
	((struct lm_edhoc_crypto_ctx *)uc)->hash_ops_busy &= ~(1U << i);
	return st == PSA_SUCCESS ? EDHOC_SUCCESS : EDHOC_ERROR_CRYPTO_FAILURE;
}

static int c_hash_abort(void *uc, void *op) {
	unsigned i;
	psa_hash_operation_t *h = hash_slot(uc, op, &i);
	if (h == NULL) {
		return EDHOC_ERROR_CRYPTO_FAILURE;
	}
	psa_hash_abort(h);
	((struct lm_edhoc_crypto_ctx *)uc)->hash_ops_busy &= ~(1U << i);
	return EDHOC_SUCCESS;
}

static const struct edhoc_crypto k_crypto = {
	.destroy_key = c_destroy_key,
	.generate_key_pair = c_generate_key_pair,
	.encapsulate = c_encapsulate,
	.decapsulate = c_decapsulate,
	.key_agreement = c_key_agreement,
	.sign = c_sign,
	.verify = c_verify,
	.extract = c_extract,
	.expand = c_expand,
	.expand_raw = c_expand_raw,
	.aead_encrypt = c_aead_encrypt,
	.aead_decrypt = c_aead_decrypt,
	.hash_init = c_hash_init,
	.hash_update = c_hash_update,
	.hash_finish = c_hash_finish,
	.hash_abort = c_hash_abort,
};

static const struct edhoc_cipher_suite k_suite3 = {
	.value = 3,
	.supports_dh_nike = true,
	.kem_encapsulation_key_length = P256_X_LEN,
	.kem_ciphertext_length = P256_X_LEN,
	.nike_key_length = P256_X_LEN,
	.sign_length = SIG_LEN,
	.aead_key_length = AEAD_KEY_LEN,
	.aead_tag_length = 16,
	.aead_iv_length = 13,
	.hash_length = HASH_LEN,
	.mac_length = 16,
};

const struct edhoc_crypto *lm_edhoc_crypto(void) { return &k_crypto; }
const struct edhoc_cipher_suite *lm_edhoc_suite3(void) { return &k_suite3; }

void lm_edhoc_crypto_ctx_init(struct lm_edhoc_crypto_ctx *c, uint8_t aead_tag_len) {
	memset(c, 0, sizeof *c);
	c->aead_tag_len = aead_tag_len;
}

/* ---- credentials, EAD, platform ------------------------------------------------------------ */
static int cred_select_local(void *uc, const struct edhoc_call_context *cc,
			     struct edhoc_credential_selected *sel) {
	const struct lm_edhoc_session *s = uc;
	if (s == NULL || cc->method != EDHOC_METHOD_0 || s->local_ccs_len == 0) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}
	struct edhoc_credential_selected_asymmetric *a = &sel->asymmetric;
	a->label = EDHOC_COSE_HEADER_KID;
	a->kid.identifier.value = s->local_kid;
	a->kid.identifier.length = sizeof s->local_kid;
	a->kid.credential.value = s->local_ccs;
	a->kid.credential.length = s->local_ccs_len;
	a->kid.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED;
	key_store(a->private_key_id, (psa_key_id_t)s->local_key);
	return EDHOC_SUCCESS;
}

/* Only a credential the owner already validated (fleet signature, revocation, generation) and
 * handed over as a candidate is accepted; a self-declared key is never trusted (docs/06 §4). */
static int cred_authenticate_peer(void *uc, const struct edhoc_call_context *cc,
				  const struct edhoc_credential_received *rx,
				  struct edhoc_credential_trusted *trusted) {
	struct lm_edhoc_session *s = uc;
	if (s == NULL || cc->method != EDHOC_METHOD_0 || rx->label != EDHOC_COSE_HEADER_KID ||
	    rx->kid.identifier.length != sizeof s->peers[0].kid) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}
	for (size_t i = 0; i < s->peer_count; ++i) {
		if (memcmp(s->peers[i].kid, rx->kid.identifier.value, sizeof s->peers[i].kid) == 0) {
			s->matched_peer = (int)i;
			trusted->asymmetric.credential.value = s->peers[i].ccs;
			trusted->asymmetric.credential.length = s->peers[i].ccs_len;
			trusted->asymmetric.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED;
			trusted->asymmetric.public_key.value = s->peers[i].pub;
			trusted->asymmetric.public_key.length = sizeof s->peers[i].pub;
			return EDHOC_SUCCESS;
		}
	}
	return EDHOC_ERROR_CREDENTIALS_FAILURE;
}

static const struct edhoc_credentials k_creds = {
	.select_local = cred_select_local,
	.authenticate_peer = cred_authenticate_peer,
};

/* docs/06 §9: the only EAD sent is nothing (padding label 0 may be received). An unknown critical
 * item (negative label) aborts the handshake; libedhoc itself would ignore it without this hook. */
static int ead_compose(void *uc, const struct edhoc_call_context *cc, struct edhoc_ead_token *t,
		       size_t cap, size_t *count) {
	(void)uc;
	(void)cc;
	(void)t;
	(void)cap;
	*count = 0;
	return EDHOC_SUCCESS;
}

static int ead_process(void *uc, const struct edhoc_call_context *cc,
		       const struct edhoc_ead_token *t, size_t n) {
	(void)uc;
	(void)cc;
	for (size_t i = 0; i < n; ++i) {
		if (t[i].label < 0) {
			return EDHOC_ERROR_EAD_PROCESS_FAILURE;
		}
	}
	return EDHOC_SUCCESS;
}

static const struct edhoc_ead k_ead = {.compose = ead_compose, .process = ead_process};

static void platform_zeroize(void *p, size_t n) { wipe(p, n); }
static const struct edhoc_platform k_platform = {.zeroize = platform_zeroize};

/* ---- session ----------------------------------------------------------------------------------- */
static struct edhoc_context *ectx(struct lm_edhoc_session *s) {
	return (struct edhoc_context *)s->ctx_storage;
}

int lm_edhoc_session_init(struct lm_edhoc_session *s, int initiator) {
	if (s == NULL || s->initialised || s->peer_count > LM_EDHOC_MAX_PEERS ||
	    s->local_ccs_len == 0 || s->local_ccs_len > sizeof s->local_ccs) {
		return LM_EDHOC_ERR_ARG;
	}
	if (edhoc_context_size() > sizeof s->ctx_storage) {
		return LM_EDHOC_ERR_SIZE;
	}
	lm_edhoc_crypto_ctx_init(&s->crypto, k_suite3.aead_tag_length);
	s->initiator = initiator != 0;
	s->matched_peer = -1;
	/* C_I / C_R carry no meaning here (no OSCORE, exchanges are told apart by the carrier). */
	const uint8_t cid = initiator ? 0x00 : 0x01;
	const struct edhoc_buffer conn_id = {&cid, 1};
	const enum edhoc_method method = EDHOC_METHOD_0;
	struct edhoc_context *c = ectx(s);
	int rc = edhoc_context_init(c);
	if (rc != EDHOC_SUCCESS) {
		return rc;
	}
	s->initialised = 1;
	if ((rc = edhoc_set_methods(c, &method, 1)) == EDHOC_SUCCESS &&
	    (rc = edhoc_set_cipher_suites(c, &k_suite3, 1)) == EDHOC_SUCCESS &&
	    (rc = edhoc_set_connection_id(c, &conn_id)) == EDHOC_SUCCESS &&
	    (rc = edhoc_set_user_context(c, s)) == EDHOC_SUCCESS &&
	    (rc = edhoc_bind_crypto(c, &k_crypto)) == EDHOC_SUCCESS &&
	    (rc = edhoc_bind_credentials(c, &k_creds)) == EDHOC_SUCCESS &&
	    (rc = edhoc_bind_platform(c, &k_platform)) == EDHOC_SUCCESS &&
	    (rc = edhoc_bind_ead(c, &k_ead)) == EDHOC_SUCCESS) {
		return EDHOC_SUCCESS;
	}
	lm_edhoc_session_destroy(s);
	return rc;
}

int lm_edhoc_session_step(struct lm_edhoc_session *s, enum lm_edhoc_step step, const uint8_t *in,
			  size_t in_len, uint8_t *out, size_t out_cap, size_t *out_len) {
	if (s == NULL || !s->initialised) {
		return LM_EDHOC_ERR_ARG;
	}
	struct edhoc_context *c = ectx(s);
	const int is_process = step == LM_EDHOC_M1_PROCESS || step == LM_EDHOC_M2_PROCESS ||
			       step == LM_EDHOC_M3_PROCESS || step == LM_EDHOC_M4_PROCESS;
	if ((is_process && (in == NULL || in_len == 0 || in_len > LM_EDHOC_MAX_MSG)) ||
	    (!is_process && (out == NULL || out_len == NULL))) {
		return LM_EDHOC_ERR_ARG;
	}
	switch (step) {
	case LM_EDHOC_M1_COMPOSE: return edhoc_message_1_compose(c, out, out_cap, out_len);
	case LM_EDHOC_M1_PROCESS: return edhoc_message_1_process(c, in, in_len);
	case LM_EDHOC_M2_COMPOSE: return edhoc_message_2_compose(c, out, out_cap, out_len);
	case LM_EDHOC_M2_PROCESS: return edhoc_message_2_process(c, in, in_len);
	case LM_EDHOC_M3_COMPOSE: return edhoc_message_3_compose(c, out, out_cap, out_len);
	case LM_EDHOC_M3_PROCESS: return edhoc_message_3_process(c, in, in_len);
	case LM_EDHOC_M4_COMPOSE: return edhoc_message_4_compose(c, out, out_cap, out_len);
	case LM_EDHOC_M4_PROCESS: return edhoc_message_4_process(c, in, in_len);
	}
	return LM_EDHOC_ERR_ARG;
}

int lm_edhoc_session_export(struct lm_edhoc_session *s, const uint8_t *ctx_hash, size_t ctx_hash_len,
			    uint8_t *seed, size_t seed_len) {
	if (s == NULL || !s->initialised || ctx_hash == NULL || ctx_hash_len != HASH_LEN ||
	    seed == NULL || seed_len != HASH_LEN) {
		return LM_EDHOC_ERR_ARG;
	}
	return edhoc_export_raw(ectx(s), LM_EDHOC_EXPORTER_LABEL, ctx_hash, ctx_hash_len, seed, seed_len);
}

size_t lm_edhoc_context_size(void) { return edhoc_context_size(); }

void lm_edhoc_session_destroy(struct lm_edhoc_session *s) {
	if (s == NULL) {
		return;
	}
	if (s->initialised) {
		(void)edhoc_context_deinit(ectx(s)); /* destroys every slot handle libedhoc still holds */
	}
	for (unsigned i = 0; i < LM_EDHOC_HASH_OPS; ++i) {
		if ((s->crypto.hash_ops_busy & (1U << i)) != 0) {
			psa_hash_abort((psa_hash_operation_t *)s->crypto.hash_ops[i]);
		}
	}
	wipe(s, sizeof *s);
}
