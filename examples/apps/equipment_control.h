/* Example application 1 (docs/17 G6): equipment state control. Uses only api/leanmesh.h and libc; nothing here is
   specific to any product, Cloud or vocabulary of another system. Not a firmware and not a radio implementation.

   Wire format of the application on port EQUIPMENT_PORT (application-owned, opaque to the SDK):
     command  = version(1) | 'S' | revision u32 BE | desired u8 (0 off, 1 on)
     result   = revision u32 BE | state u8
   The Host (or any other node) sends the command with delivery APPLIED and a finite deadline; the application performs
   the physical change FIRST and reports APPLIED only after the driver confirmed it. */
#ifndef EQUIPMENT_CONTROL_H
#define EQUIPMENT_CONTROL_H
#include "leanmesh.h"
#ifdef __cplusplus
extern "C" {
#endif

#define EQUIPMENT_PORT 100u
#define EQUIPMENT_COMMAND_BYTES 7u

typedef struct {
 /* The platform's output driver. Returns 0 only when the change is confirmed. */
 int (*drive)(void *user, uint8_t on);
 void *user;
 uint32_t revision; /* highest command revision applied so far (kept by the application, never by the SDK) */
 uint8_t on;
 uint32_t applied, rejected;
} equipment_t;

void equipment_init(equipment_t *eq, int (*drive)(void *, uint8_t), void *user);
/* Builds a command; returns its length (EQUIPMENT_COMMAND_BYTES). */
size_t equipment_encode(uint8_t out[EQUIPMENT_COMMAND_BYTES], uint32_t revision, uint8_t on);
/* Takes every pending event of the context; answers each MESSAGE of EQUIPMENT_PORT. Returns the number answered. */
unsigned equipment_poll(lm_context_t *ctx, equipment_t *eq);
#ifdef __cplusplus
}
#endif
#endif
