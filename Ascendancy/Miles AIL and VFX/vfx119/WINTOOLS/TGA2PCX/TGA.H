#include "winvfx.h"

extern "C"
{
   extern VFX_RGB * __cdecl TGA_parse        (void *TGA_image, S32 *x_res, S32 *y_res);
   extern S32       __cdecl TGA_write_16bpp  (PANE *src, C8 *filename);
}
