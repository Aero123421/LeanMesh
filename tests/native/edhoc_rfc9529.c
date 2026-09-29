/* S01 (docs/IMPLEMENTATION.md D1a): RFC 9529 chapter 3 trace (method 3, suite 2, kid + CCS) replayed
 * through the LeanMesh crypto glue (src/security/edhoc/lm_edhoc.c) and the pinned, patched libedhoc.
 *
 * Only the two ephemeral-key operations are replaced (the RFC fixes X and Y); the glue supplies
 * everything else: static-DH key agreement, HKDF, hash, AES-CCM. The glue is parameterised to
 * suite 2 (AEAD tag 8) through its crypto context; product code always runs suite 3.
 * The vectors come straight from libedhoc's test support header (RFC 9529 data, pinned submodule).
 * C because libedhoc's headers are C11-only. Test only: it holds the RFC's public test private keys. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <edhoc/edhoc.h>
#include <psa/crypto.h>

#include "security/edhoc/lm_edhoc.h"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-const-variable"
#include "test_vector_rfc9529_chapter_3.h"
#pragma GCC diagnostic pop

int lm_test_rfc9529_chapter3(char *why, size_t why_cap);

#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define REQUIRE(cond)                                                                              \
	do {                                                                                       \
		if (!(cond)) {                                                                     \
			(void)snprintf(why, why_cap, "%s:%d: %s", __FILE__, __LINE__, #cond);      \
			return -1;                                                                 \
		}                                                                                  \
	} while (0)
#define REQUIRE_OK(expr)                                                                           \
	do {                                                                                       \
		const int rc_ = (expr);                                                            \
		if (rc_ != EDHOC_SUCCESS) {                                                        \
			(void)snprintf(why, why_cap, "%s:%d: %s -> %d", __FILE__, __LINE__, #expr,  \
				       rc_);                                                       \
			return -1;                                                                 \
		}                                                                                  \
	} while (0)

static struct lm_edhoc_crypto_ctx crypto_i;
static struct lm_edhoc_crypto_ctx crypto_r;
static struct edhoc_crypto vt_i;
static struct edhoc_crypto vt_r;
static psa_key_id_t static_key_i, static_key_r; /* the RFC's static keys, destroyed at the end */

static psa_key_id_t import_scalar(const uint8_t *s, size_t n) {
	psa_key_attributes_t a = PSA_KEY_ATTRIBUTES_INIT;
	psa_set_key_lifetime(&a, PSA_KEY_LIFETIME_VOLATILE);
	psa_set_key_usage_flags(&a, PSA_KEY_USAGE_DERIVE);
	psa_set_key_algorithm(&a, PSA_ALG_ECDH);
	psa_set_key_type(&a, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
	psa_key_id_t k = PSA_KEY_ID_NULL;
	(void)psa_import_key(&a, s, n, &k);
	return k;
}

/* The RFC's X / G_X. */
static int gen_i(void *uc, void *decaps, uint8_t *encaps, size_t cap, size_t *len) {
	(void)uc;
	if (cap < sizeof G_X) {
		return EDHOC_ERROR_BUFFER_TOO_SMALL;
	}
	const psa_key_id_t k = import_scalar(X, sizeof X);
	memcpy(decaps, &k, sizeof k);
	memcpy(encaps, G_X, sizeof G_X);
	*len = sizeof G_X;
	return k == PSA_KEY_ID_NULL ? EDHOC_ERROR_CRYPTO_FAILURE : EDHOC_SUCCESS;
}

/* The RFC's Y / G_Y as the "ciphertext"; G_XY comes from the glue's real ECDH(Y, G_X). */
static int encaps_r(void *uc, const uint8_t *encaps, size_t encaps_len, void *decaps, void *secret,
		    uint8_t *ct, size_t ct_cap, size_t *ct_len) {
	(void)uc;
	(void)ct_cap;
	const psa_key_id_t y = import_scalar(Y, sizeof Y);
	int rc = lm_edhoc_crypto()->key_agreement(uc, &y, encaps, encaps_len, secret);
	if (rc != EDHOC_SUCCESS) {
		return rc;
	}
	memcpy(ct, G_Y, sizeof G_Y);
	*ct_len = sizeof G_Y;
	memcpy(decaps, &y, sizeof y);
	return EDHOC_SUCCESS;
}

static int sel_i(void *uc, const struct edhoc_call_context *cc, struct edhoc_credential_selected *s) {
	(void)uc;
	(void)cc;
	const psa_key_id_t k = static_key_i = import_scalar(SK_I, sizeof SK_I);
	memcpy(s->asymmetric.private_key_id, &k, sizeof k);
	s->asymmetric.label = EDHOC_COSE_HEADER_KID;
	s->asymmetric.kid.identifier = (struct edhoc_buffer){ID_CRED_I_raw_cborised, sizeof ID_CRED_I_raw_cborised};
	s->asymmetric.kid.credential = (struct edhoc_buffer){CRED_I_cborised, sizeof CRED_I_cborised};
	s->asymmetric.kid.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED;
	return EDHOC_SUCCESS;
}

static int sel_r(void *uc, const struct edhoc_call_context *cc, struct edhoc_credential_selected *s) {
	(void)uc;
	(void)cc;
	const psa_key_id_t k = static_key_r = import_scalar(SK_R, sizeof SK_R);
	memcpy(s->asymmetric.private_key_id, &k, sizeof k);
	s->asymmetric.label = EDHOC_COSE_HEADER_KID;
	s->asymmetric.kid.identifier = (struct edhoc_buffer){ID_CRED_R_raw_cborised, sizeof ID_CRED_R_raw_cborised};
	s->asymmetric.kid.credential = (struct edhoc_buffer){CRED_R_cborised, sizeof CRED_R_cborised};
	s->asymmetric.kid.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED;
	return EDHOC_SUCCESS;
}

static int peer_common(const struct edhoc_credential_received *rx, const uint8_t *kid, size_t kid_len,
		       const uint8_t *cred, size_t cred_len, const uint8_t *pk, size_t pk_len,
		       struct edhoc_credential_trusted *t) {
	if (rx->label != EDHOC_COSE_HEADER_KID || rx->kid.identifier.length != kid_len ||
	    memcmp(rx->kid.identifier.value, kid, kid_len) != 0) {
		return EDHOC_ERROR_CREDENTIALS_FAILURE;
	}
	t->asymmetric.credential = (struct edhoc_buffer){cred, cred_len};
	t->asymmetric.format = EDHOC_CREDENTIAL_FORMAT_CBOR_ENCODED;
	t->asymmetric.public_key = (struct edhoc_buffer){pk, pk_len};
	return EDHOC_SUCCESS;
}

static int auth_i(void *uc, const struct edhoc_call_context *cc,
		  const struct edhoc_credential_received *rx, struct edhoc_credential_trusted *t) {
	(void)uc;
	(void)cc;
	return peer_common(rx, ID_CRED_R_raw_cborised, sizeof ID_CRED_R_raw_cborised, CRED_R_cborised,
			   sizeof CRED_R_cborised, PK_R, sizeof PK_R, t);
}

static int auth_r(void *uc, const struct edhoc_call_context *cc,
		  const struct edhoc_credential_received *rx, struct edhoc_credential_trusted *t) {
	(void)uc;
	(void)cc;
	return peer_common(rx, ID_CRED_I_raw_cborised, sizeof ID_CRED_I_raw_cborised, CRED_I_cborised,
			   sizeof CRED_I_cborised, PK_I, sizeof PK_I, t);
}

static const struct edhoc_credentials creds_i = {sel_i, auth_i};
static const struct edhoc_credentials creds_r = {sel_r, auth_r};

static void zeroize(void *p, size_t n) { memset(p, 0, n); }
static const struct edhoc_platform platform = {zeroize};

static struct edhoc_cipher_suite suite2(int32_t value) {
	struct edhoc_cipher_suite s = *lm_edhoc_suite3();
	s.value = value;
	s.aead_tag_length = 8;
	s.mac_length = 8;
	return s;
}

static int setup(struct edhoc_context *c, const struct edhoc_crypto *vt, void *uc,
		 const struct edhoc_credentials *cr, const struct edhoc_cipher_suite *suites, size_t ns,
		 const uint8_t *cid, char *why, size_t why_cap) {
	const enum edhoc_method m = (enum edhoc_method)METHOD;
	const struct edhoc_buffer conn = {cid, 1};
	REQUIRE_OK(edhoc_context_init(c));
	REQUIRE_OK(edhoc_set_methods(c, &m, 1));
	REQUIRE_OK(edhoc_set_cipher_suites(c, suites, ns));
	REQUIRE_OK(edhoc_set_connection_id(c, &conn));
	REQUIRE_OK(edhoc_set_user_context(c, uc));
	REQUIRE_OK(edhoc_bind_crypto(c, vt));
	REQUIRE_OK(edhoc_bind_credentials(c, cr));
	REQUIRE_OK(edhoc_bind_platform(c, &platform));
	return 0;
}

int lm_test_rfc9529_chapter3(char *why, size_t why_cap) {
	REQUIRE(psa_crypto_init() == PSA_SUCCESS);
	lm_edhoc_crypto_ctx_init(&crypto_i, 8);
	lm_edhoc_crypto_ctx_init(&crypto_r, 8);
	vt_i = *lm_edhoc_crypto();
	vt_i.generate_key_pair = gen_i;
	vt_r = *lm_edhoc_crypto();
	vt_r.encapsulate = encaps_r;

	/* The initiator offers suites [6, 2], the responder supports [2] (RFC 9529 §3.3). */
	const struct edhoc_cipher_suite offered[2] = {suite2(6), suite2(2)};
	const struct edhoc_cipher_suite supported[1] = {suite2(2)};

	uint64_t *store_i = calloc(1, edhoc_context_size() + 8);
	uint64_t *store_r = calloc(1, edhoc_context_size() + 8);
	REQUIRE(store_i != NULL && store_r != NULL);
	struct edhoc_context *ci = (struct edhoc_context *)store_i;
	struct edhoc_context *cr = (struct edhoc_context *)store_r;
	if (setup(ci, &vt_i, &crypto_i, &creds_i, offered, 2, C_I, why, why_cap) != 0 ||
	    setup(cr, &vt_r, &crypto_r, &creds_r, supported, 1, C_R, why, why_cap) != 0) {
		return -1;
	}

	uint8_t m1[64], m2[160], m3[160], m4[64];
	size_t l1 = 0, l2 = 0, l3 = 0, l4 = 0;
	REQUIRE_OK(edhoc_message_1_compose(ci, m1, sizeof m1, &l1));
	REQUIRE(l1 == sizeof message_1 && memcmp(m1, message_1, l1) == 0);
	REQUIRE_OK(edhoc_message_1_process(cr, m1, l1));
	REQUIRE_OK(edhoc_message_2_compose(cr, m2, sizeof m2, &l2));
	REQUIRE(l2 == sizeof message_2 && memcmp(m2, message_2, l2) == 0);
	REQUIRE_OK(edhoc_message_2_process(ci, m2, l2));
	REQUIRE_OK(edhoc_message_3_compose(ci, m3, sizeof m3, &l3));
	REQUIRE(l3 == sizeof message_3 && memcmp(m3, message_3, l3) == 0);
	REQUIRE_OK(edhoc_message_3_process(cr, m3, l3));
	REQUIRE_OK(edhoc_message_4_compose(cr, m4, sizeof m4, &l4));
	REQUIRE(l4 == sizeof message_4 && memcmp(m4, message_4, l4) == 0);
	REQUIRE_OK(edhoc_message_4_process(ci, m4, l4));

	/* Exporter: OSCORE Master Secret / Salt match the RFC on both sides. */
	uint8_t sec_i[16], sec_r[16], salt_i[8], salt_r[8];
	REQUIRE_OK(edhoc_export_raw(ci, EDHOC_EXPORTER_LABEL_OSCORE_MASTER_SECRET, NULL, 0, sec_i, sizeof sec_i));
	REQUIRE_OK(edhoc_export_raw(cr, EDHOC_EXPORTER_LABEL_OSCORE_MASTER_SECRET, NULL, 0, sec_r, sizeof sec_r));
	REQUIRE_OK(edhoc_export_raw(ci, EDHOC_EXPORTER_LABEL_OSCORE_MASTER_SALT, NULL, 0, salt_i, sizeof salt_i));
	REQUIRE_OK(edhoc_export_raw(cr, EDHOC_EXPORTER_LABEL_OSCORE_MASTER_SALT, NULL, 0, salt_r, sizeof salt_r));
	REQUIRE(sizeof OSCORE_Master_Secret == sizeof sec_i && sizeof OSCORE_Master_Salt == sizeof salt_i);
	REQUIRE(memcmp(sec_i, OSCORE_Master_Secret, sizeof sec_i) == 0);
	REQUIRE(memcmp(sec_r, OSCORE_Master_Secret, sizeof sec_r) == 0);
	REQUIRE(memcmp(salt_i, OSCORE_Master_Salt, sizeof salt_i) == 0);
	REQUIRE(memcmp(salt_r, OSCORE_Master_Salt, sizeof salt_r) == 0);

	REQUIRE_OK(edhoc_context_deinit(ci));
	REQUIRE_OK(edhoc_context_deinit(cr));
	(void)psa_destroy_key(static_key_i);
	(void)psa_destroy_key(static_key_r);
	free(store_i);
	free(store_r);
	return 0;
}
