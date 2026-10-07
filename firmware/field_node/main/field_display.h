#ifndef FIELD_DISPLAY_H
#define FIELD_DISPLAY_H
/* The panel of the display build, behind three calls. field_display_hub75.cpp drives the 64x32 HUB75 panel;
   field_display_none.c (every other build) has no panel: present() is false and nothing can be drawn. */
#include <stdbool.h>

#include "field_render.h"

#ifdef __cplusplus
extern "C" {
#endif

/* True in the display build. */
bool field_display_present(void);
/* Brings the panel up (blank). False when it cannot (no memory, GDMA/driver error, the DMA runs no frames): everything it
   set up is released again, the node reports a render fault, and the call may be made again later. True once it is up
   (a second call then does nothing). */
bool field_display_init(void);
/* Draws the view into the panel's back buffer and shows it. True only when the display driver has evidence that the new
   frame went out (hub75: a whole DMA pass of the flipped buffer, see field_display_hub75.cpp); false when the panel is
   not up or that evidence does not come within a bounded wait (a few hundred ms at most). */
bool field_display_show(const field_view_t *view);

#ifdef __cplusplus
}
#endif
#endif
