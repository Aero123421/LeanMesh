/* A build without a panel (relay / leaf): nothing can be drawn. See field_display.h. */
#include "field_display.h"

bool field_display_present(void) { return false; }
bool field_display_init(void) { return false; }
bool field_display_show(const field_view_t *view) {
    (void)view;
    return false;
}
