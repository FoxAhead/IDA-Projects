//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
//лл                                                                        лл
//лл  MOUSE.H: C type definitions & mouse API prototypes                    лл
//лл                                                                        лл
//лл  Source compatible with 32-bit 80386 C/C++                             лл
//лл                                                                        лл
//лл  V1.00 of  9-Jul-93: Initial release                                   лл
//лл   1.10 of 24-Jan-94: Added MOUSE_pane_refresh()                        лл
//лл   1.11 of 15-Feb-94: Upper-case MOUSE_ function names                  лл
//лл                                                                        лл
//лл  Project: 386FX Sound & Light(TM)                                      лл
//лл   Author: John Miles                                                   лл
//лл                                                                        лл
//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
//лл                                                                        лл
//лл  Copyright (C) 1992-1994 Non-Linear Arts, Inc.                         лл
//лл                                                                        лл
//лл  Non-Linear Arts, Inc.                                                 лл
//лл  3415 Greystone #200                                                   лл
//лл  Austin, TX 78731                                                      лл
//лл                                                                        лл
//лл  (512) 346-9595 / FAX (512) 346-9596 / BBS (512) 454-9990              лл
//лл                                                                        лл
//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

#ifndef MOUSE_H
#define MOUSE_H

#ifndef VFX_H
#include "vfx.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

//
// MAX_MOUSE_BUFFER_SIZE should be set to the size of the visible area
// in bytes of the largest mouse cursor to be used
//

#define MAX_MOUSE_BUFFER_SIZE 16384

extern LONG MOUSE_init(LONG xsize, LONG ysize, LONG background);
extern void MOUSE_shutdown(void);

extern void MOUSE_show(void);
extern void MOUSE_hide(void);
extern void MOUSE_set_pointer(void *table, LONG shape);
extern void MOUSE_status(LONG *mx, LONG *my, LONG *ml, LONG *mr, LONG *mc);
extern void MOUSE_force_move(LONG new_x, LONG new_y);

extern void MOUSE_register_mouse_event_callback(void cdecl (*fn)
   (LONG x, LONG y));
extern void MOUSE_register_button_event_callback(void cdecl (*fn)
   (LONG left, LONG right, LONG center));
extern void MOUSE_register_watchdog_callback(LONG cdecl (*fn)
   (RECT *area));

extern void MOUSE_lock(void);
extern void MOUSE_unlock(void);
extern void MOUSE_hold(void);
extern void MOUSE_release(void);

extern LONG MOUSE_visible_area(RECT *area);
extern LONG MOUSE_shape_in_area(RECT *area);

extern void __cdecl MOUSE_serve(void);

extern void MOUSE_window_refresh(WINDOW *target, LONG x0, LONG y0, 
   LONG x1, LONG y1);
extern void MOUSE_pane_refresh(PANE *target, LONG x0, LONG y0, 
   LONG x1, LONG y1);

extern void MOUSE_pane_list_refresh(PANE_LIST *list);

#ifdef __cplusplus
}
#endif

#endif
