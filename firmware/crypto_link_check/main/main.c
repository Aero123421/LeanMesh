/*
 * Link/known-answer check of the LeanMesh crypto backend path on ESP-IDF: PSA SHA-256 and the
 * pinned libedhoc (context init, method 0) linked from the leanmesh component. BUILD GATE ONLY.
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <edhoc/edhoc.h>
#include <psa/crypto.h>

#include "esp_log.h"

static const char *TAG = "lm_crypto_check";

static int sha256_abc(void) {
    static const uint8_t expect[32] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                                       0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                                       0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                                       0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
    uint8_t out[32];
    size_t len = 0;
    if (psa_hash_compute(PSA_ALG_SHA_256, (const uint8_t *)"abc", 3, out, sizeof out, &len) !=
        PSA_SUCCESS) {
        return -1;
    }
    return (len == sizeof out && memcmp(out, expect, sizeof out) == 0) ? 0 : -2;
}

static int edhoc_init_deinit(void) {
    const size_t size = edhoc_context_size();
    uint64_t *storage = calloc((size + 7) / 8, sizeof(uint64_t));
    if (storage == NULL) {
        return -1;
    }
    struct edhoc_context *ctx = (struct edhoc_context *)storage;
    int rc = edhoc_context_init(ctx);
    const enum edhoc_method methods[] = {EDHOC_METHOD_0};
    if (rc == EDHOC_SUCCESS) {
        rc = edhoc_set_methods(ctx, methods, 1);
    }
    const int deinit = edhoc_context_deinit(ctx);
    free(storage);
    return rc != EDHOC_SUCCESS ? rc : deinit;
}

void app_main(void) {
    const int init = psa_crypto_init() == PSA_SUCCESS ? 0 : -1;
    const int sha = init == 0 ? sha256_abc() : -1;
    const int edhoc = edhoc_init_deinit();
    ESP_LOGI(TAG, "psa_init=%d sha256_kat=%d edhoc_ctx=%d (context %u bytes)", init, sha, edhoc,
             (unsigned)edhoc_context_size());
}
