/* EDHOC suite-3 crypto glue over PSA and the handshake session driver (docs/06 §2, §4).
 *
 * C, not C++: libedhoc's public headers are C11-only (docs/IMPLEMENTATION.md D2). C++ code sees this
 * header only; it exposes no libedhoc type. Everything here runs on the slow-job worker.
 *
 * Suite 3 = P-256 key exchange (x-only G_X/G_Y), ES256 signatures, AES-CCM-16-128-128, SHA-256.
 * Only the AEAD tag length is a parameter (`struct lm_edhoc_crypto_ctx`, first member of the user
 * context): RFC 9529 chapter 3 is a suite-2 trace (tag 8) and is replayed through the very same
 * glue in tests. The context also owns the multipart-hash operation pool, so there is no global
 * state and no lock: one context = one handshake = one worker thread.
 */
#ifndef LM_EDHOC_H
#define LM_EDHOC_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LM_EDHOC_MAX_MSG 256   /* every EDHOC message of this profile is < 160 B */
#define LM_EDHOC_CCS_MAX 160   /* {2: tstr<=64, 8: {1: COSE_Key}} */
#define LM_EDHOC_MAX_PEERS 2   /* docs/06 §9: at most two candidate credentials at once */
#define LM_EDHOC_SESSION_CTX_BYTES 1024 /* >= edhoc_context_size(); checked at init */
#define LM_EDHOC_EXPORTER_LABEL 40000

/* Return codes: 0 ok, negative libedhoc codes, or the values below. */
#define LM_EDHOC_ERR_ARG (-1000)
#define LM_EDHOC_ERR_SIZE (-1001)  /* context storage too small for this libedhoc build */
#define LM_EDHOC_ERR_PEER (-1002)  /* received kid is not one of the candidate credentials */

#define LM_EDHOC_ERR_STUCK (-1003) /* a PSA key slot could not be destroyed yet: retry the destroy */

#define LM_EDHOC_HASH_OPS 4
#define LM_EDHOC_STUCK_KEYS 8 /* >= the number of key slots libedhoc holds at once */
/* First member of every user context passed to the crypto vtable (never NULL). */
struct lm_edhoc_crypto_ctx {
	uint8_t aead_tag_len;          /* 16 for suite 3 */
	int32_t fault;                 /* first non-peer PSA/mpi failure (out of memory, ...), 0 = none */
	uint32_t hash_ops_busy;        /* bit i: hash_ops[i] is live */
	uint32_t stuck_keys[LM_EDHOC_STUCK_KEYS]; /* handles psa_destroy_key refused (libedhoc forgets
						   * a handle whose destroy failed; we keep it here) */
	uint8_t stuck_count;
	uint64_t hash_ops[LM_EDHOC_HASH_OPS][32]; /* psa_hash_operation_t storage */
	/* ECDH output between the raw agreement and its import as a derivation key (wiped at once).
	 * Kept here and not on the worker stack: psa_key_agreement() holds a ~1 KiB output buffer in its
	 * own frame (SEC-D15: the worker stack keeps 2x margin over the deepest job). */
	uint8_t secret[32];
};
void lm_edhoc_crypto_ctx_init(struct lm_edhoc_crypto_ctx *c, uint8_t aead_tag_len);

struct edhoc_crypto;
struct edhoc_cipher_suite;
const struct edhoc_crypto *lm_edhoc_crypto(void);
const struct edhoc_cipher_suite *lm_edhoc_suite3(void);

struct lm_edhoc_peer {
	uint8_t kid[32];                /* DeviceId, checked against the received ID_CRED */
	uint8_t pub[65];                /* 0x04 || x || y, already validated by the caller */
	uint8_t ccs[LM_EDHOC_CCS_MAX];  /* CRED, byte-exact as the peer signs it */
	size_t ccs_len;
};

enum lm_edhoc_step {
	LM_EDHOC_M1_COMPOSE = 1,
	LM_EDHOC_M1_PROCESS,
	LM_EDHOC_M2_COMPOSE,
	LM_EDHOC_M2_PROCESS,
	LM_EDHOC_M3_COMPOSE,
	LM_EDHOC_M3_PROCESS,
	LM_EDHOC_M4_COMPOSE,
	LM_EDHOC_M4_PROCESS,
};

struct lm_edhoc_session {
	struct lm_edhoc_crypto_ctx crypto; /* must stay first */
	uint8_t initiator;
	uint8_t initialised;
	int matched_peer;              /* index of the authenticated candidate, -1 before m2/m3 */
	uint32_t local_key;            /* PSA key id of the ES256 signing key (owned by the caller) */
	uint8_t local_kid[32];
	uint8_t local_ccs[LM_EDHOC_CCS_MAX];
	size_t local_ccs_len;
	struct lm_edhoc_peer peers[LM_EDHOC_MAX_PEERS];
	size_t peer_count;
	uint64_t ctx_storage[LM_EDHOC_SESSION_CTX_BYTES / 8]; /* struct edhoc_context */
};

/* Configures the context: method 0, suite 3, kid credentials, EAD filter, platform zeroize.
 * The session's peers/local fields must be filled before the call. */
int lm_edhoc_session_init(struct lm_edhoc_session *s, int initiator);
/* One handshake step. `in` for *_PROCESS, `out` for *_COMPOSE (out_len set). */
int lm_edhoc_session_step(struct lm_edhoc_session *s, enum lm_edhoc_step step, const uint8_t *in,
			  size_t in_len, uint8_t *out, size_t out_cap, size_t *out_len);
/* EDHOC_Exporter(label 40000, ctx_hash, 32) after message_4 on both sides. */
int lm_edhoc_session_export(struct lm_edhoc_session *s, const uint8_t *ctx_hash, size_t ctx_hash_len,
			    uint8_t *seed, size_t seed_len);
/* sizeof(struct edhoc_context) of this libedhoc build (for RAM reports). */
size_t lm_edhoc_context_size(void);
/* Destroys every PSA handle held by libedhoc and wipes the whole session (secrets included).
 * Returns 0, or the libedhoc code when a handle could not be destroyed: the session is then left
 * intact (handles kept) and the call may be repeated. */
int lm_edhoc_session_destroy(struct lm_edhoc_session *s);

#ifdef __cplusplus
}
#endif
#endif
