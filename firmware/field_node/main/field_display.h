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
/* Brings the panel up (blank). False when it cannot (no memory, driver error): the node then reports a render fault. */
bool field_display_init(void);
/* Draws the view into the panel's back buffer and shows it. True when the frame is on the panel. */
bool field_display_show(const field_view_t *view);

#ifdef __cplusplus
}
#endif
#endif
