#ifndef LEANMESH_BENCH_H
#define LEANMESH_BENCH_H
/* BENCH / HIL ONLY (CONFIG_LEANMESH_BENCH_PROVISIONING, default n): provisioning of a test board's sealed records
   before lm_init. Not part of the C ABI of api/leanmesh.h and never in a product image.

   The device key is generated on the device (PSA, with the RF-independent entropy source enabled for the call) and
   only its public key leaves the board. It waits as a pending key in the `identity` partition until the fleet-signed
   DeviceCredential for exactly that key comes back; then the SDK's own record layer writes the records a device of
   the role needs (docs/12 "provisioningが書くrecord"):
     leaf: boot_incarnation(0), identity, fleet_trust, assignment_ticket
     root: boot_incarnation(0), identity, fleet_trust, root_delegation, its own ACTIVE MemberCredential (address 1,
           term 0, signed on the board with the device key), the empty ledger manifest of the domain, paired_host
   Call these before lm_init (they mount the SDK partitions themselves) and restart the board after a provisioning. */
#include <stddef.h>
#include <stdint.h>

#include "leanmesh.h"

#ifdef __cplusplus
extern "C" {
#endif

enum { LMB_UNPROVISIONED = 0, LMB_KEY_PENDING = 1, LMB_PROVISIONED = 2 };

typedef struct {
  uint8_t public_key[65]; /* SEC1 uncompressed: 0x04 || x || y */
  uint8_t device_id[32];  /* SHA-256 of the deterministic COSE_Key */
} lmb_key_t;

/* LMB_* state of this board. A read error is STORAGE_FAILURE, never "unprovisioned". */
lm_status_t lmb_state(uint32_t *state);
/* The pending key (generated once; a second call returns the same key). CONFLICT when already provisioned. */
lm_status_t lmb_keygen(lmb_key_t *out);
/* trust88: fleet_id16 || x32 || y32 || min_credential_generation u64be (the fleet_trust record).
   device_cose: the fleet's DeviceCredential of the pending key; ticket_cose: the initial AssignmentTicket. */
lm_status_t lmb_provision_leaf(const uint8_t trust88[88], const uint8_t *device_cose, size_t device_len,
                               const uint8_t *ticket_cose, size_t ticket_len);
/* delegation_cose: the RootDelegation naming this board; host_id: the DeviceId of the one Host paired for USB.
   UNSUPPORTED in a non-ROOT build. */
lm_status_t lmb_provision_root(const uint8_t trust88[88], const uint8_t *device_cose, size_t device_len,
                               const uint8_t *delegation_cose, size_t delegation_len, const uint8_t host_id[32]);

/* Bench debugging: one text line of SDK internals (mesh attach state, candidates, link handshake and RX counters,
   end-session counters, neighbours). Reads owner state without the owner (racy counters, bench use only). */
lm_status_t lmb_debug(lm_context_t *ctx, char *out, size_t cap);

#ifdef __cplusplus
}
#endif
#endif
