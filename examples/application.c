/* Compile-only API example. Not a firmware, radio implementation or success stub. */
#include "leanmesh.h"
#include <string.h>
lm_status_t send_measurement(lm_context_t *ctx, const lm_device_id_t *target,
                            uint32_t root_term, uint64_t expires_root_ms,
                            const uint8_t *bytes, size_t len,
                            lm_operation_id_t *operation) {
 lm_send_request_t r;
 memset(&r,0,sizeof r);
 r.struct_size=sizeof r; r.abi_version=LM_ABI_VERSION;
 r.destination.kind=LM_DEST_NODE; r.destination.node=*target;
 r.app_port=100; r.delivery=LM_RECEIVED; r.storage=LM_DURABLE;
 r.priority=LM_PRIORITY_NORMAL; r.queue_mode=LM_FIFO;
 r.root_term=root_term; r.expires_root_ms=expires_root_ms;
 return lm_send(ctx,&r,bytes,len,operation);
}
/* On receive: persist/verify application revision and perform actual I/O first.
   Only after confirmed application success call lm_report_application_result(). */
