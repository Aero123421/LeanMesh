/* Link check for the pinned libedhoc build: context init, method-0 selection, deinit.
 * C because libedhoc's public headers are C11-only (_Static_assert). */
#include <stdint.h>
#include <stdlib.h>

#include <edhoc/edhoc.h>

int lm_test_edhoc_link_check(void);

int lm_test_edhoc_link_check(void) {
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
