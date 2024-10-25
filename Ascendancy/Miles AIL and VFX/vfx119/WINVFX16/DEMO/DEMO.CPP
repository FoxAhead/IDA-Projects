//
// VFX demo program
//

#define USE_PANE_LIST 0   // Use fast pane list refresh, not slower
                          // full-screen diagnostic refresh

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <windowsx.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <io.h>
#include <fcntl.h>

#include "sal.h"
#include "winvfx.h"

char szAppName[] = "WinVFX Test Bed";

//
// Window handle created by SAL
//

HWND hWnd;

//
// Demo resolution
//

#define RES_X   640
#define RES_Y   480
#define RES_BPP 16

//
// Windows/panes used by demo
//
// Screen window and pane are needed only to test clipped primitives --
// otherwise, use pane list for fast refresh performance
//

VFX_WINDOW *stage;
PANE       *stage_pane;

#if USE_PANE_LIST
  PANE_LIST  *pane_list;
#else
  VFX_WINDOW *screen;
  PANE       *screen_pane;
#endif

PANE       *pane1,*pane2,*pane3;

S32         background_invalid;

S32         state;

//****************************************************************************
//*                                                                          *
//*  Refresh screen                                                          *
//*                                                                          *
//****************************************************************************

void SCREEN_refresh(void)
{
#if USE_PANE_LIST

   //
   // Copy background to all video pages if/when necessary
   //

   if (background_invalid)
      {
      --background_invalid;

      PANE_LIST *stage_list = VFX_pane_list_construct(1);

      VFX_pane_list_add(stage_list, stage_pane);

      VFX_pane_list_refresh(stage_list);

      VFX_pane_list_destroy(stage_list);
      }

   //
   // We are not debugging a clipped primitive, so refresh only the
   // regions of the screen that have changed (3 panes)
   //

   VFX_pane_list_refresh(pane_list);

#else

   //
   // Lock the buffer and validate the VFX_WINDOW
   //

   VFX_lock_window_surface(screen,VFX_BACK_SURFACE);

   //
   // Copy entire staging pane to screen
   // 

   VFX_pane_copy(stage_pane,0,0,screen_pane,0,0,NO_COLOR);

   //
   // Release surface and perform page flip
   //

   VFX_unlock_window_surface(screen, TRUE);

#endif
}

//****************************************************************************
//*                                                                          *
//*  Read all or part of a file into memory, returning memory location       *
//*  or NULL on error                                                        *
//*                                                                          *
//*  Memory will be allocated if dest==NULL                                  *
//*                                                                          *
//****************************************************************************

void * FILE_read (C8     *filename, //)     
                  void   *dest         = NULL,
                  S32     len          = -1,
                  S32     start_offset = 0)

{
   HANDLE handle;
   U32    n_bytes;
   U32    nbytes_read;
   S32    result;
   void  *buf;

   //
   // Open file
   //

   handle = CreateFile(filename,
                       GENERIC_READ,
                       FILE_SHARE_READ,
                       NULL,
                       OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                       NULL);

   if (handle == INVALID_HANDLE_VALUE)
      {
      return NULL;
      }

   //
   // Set pointer to beginning of range
   //

   if (SetFilePointer(handle,
                      start_offset,
                      NULL,
                      FILE_BEGIN) == 0xffffffff)
      {
      CloseHandle(handle);
      return NULL;
      }

   //
   // Allocate memory for file range
   //

   n_bytes = len;

   if (n_bytes == 0xffffffff)
      {
      n_bytes = GetFileSize(handle, NULL) - start_offset;
      }

   buf = (dest == NULL) ? malloc(n_bytes) : dest;

   if (buf == NULL)
      {
      CloseHandle(handle);
      return NULL;
      }

   //
   // Read range
   //

   result = ReadFile(handle,
                     buf,
                     n_bytes,
                    &nbytes_read,
                     NULL);

   CloseHandle(handle);

   if ((!result) || (nbytes_read != n_bytes))
      {
      if (dest != buf)
         {
         free(buf);
         }

      return NULL;
      }   

   return buf;
}

//****************************************************************************
//
// Exit handlers must be present in every SAL application
//
// These routines handle exits under different conditions (exit() call, 
// user request via GUI, etc.)
//
//****************************************************************************

static int exit_handler_active = 0;

void WINAPI WinClean(void)
{
   if (exit_handler_active)
      {
      return;
      }

   exit_handler_active = 1;

   SAL_shutdown();

   OutputDebugString("Final exit OK\n");
}

void WINAPI WinExit(void)
{
   OutputDebugString("WinExit called\n");

   if (!exit_handler_active)
      {
      WinClean();
      }

   exit(0);
}

void AppExit(void)
{
   OutputDebugString("AppExit() called via atexit()\n");

   if (!exit_handler_active)
      {
      WinClean();
      }

   return;
}

//****************************************************************************
//
// Window message receiver procedure for application
//
//****************************************************************************

long FAR PASCAL WindowProc(HWND   hWnd,   UINT   message,   //)
                           WPARAM wParam, LPARAM lParam)
{
   switch (message)
      {
      case WM_CHAR:

         switch (wParam)
            {
            //
            // ESC terminates test
            // 

            case VK_ESCAPE:
               exit(0);

            //
            // Any other key advances demo state
            //

            default:
               ++state;
               break;
            }
         break;

      case WM_SYSKEYUP:

         if (wParam == VK_RETURN)
            {
            //
            // User has toggled fullscreen mode, clearing video memory...
            //

            background_invalid = SAL_get_preference(SAL_MAX_VIDEO_PAGES);
            }
         break;

      case WM_KILLFOCUS:
         
         //
         // Video memory has been lost; set up to reload background image
         // when control returned
         //

         background_invalid = SAL_get_preference(SAL_MAX_VIDEO_PAGES);
         break;
      }

    return DefWindowProc(hWnd, message, wParam, lParam);
}

//****************************************************************************
//
// Main app function
//
//****************************************************************************

void AppMain(LPSTR lpCmdLine)
{
   S32 i;

   //
   // Set RES_X * RES_Y mode at desired pixel depth
   //

   if (!VFX_set_display_mode(RES_X,
                             RES_Y,
                             RES_BPP,
                             SAL_WINDOW,
                             TRUE))
      {
      exit(1);
      }

   //
   // Don't allow user to resize window
   //

   SAL_set_preference(SAL_ALLOW_WINDOW_RESIZE, NO);

   //
   // Set global palette
   //

   for (i=0; i < 256; i++)
      {
      VFX_RGB entry;

      entry.r = rand() & 0xff;
      entry.g = rand() & 0xff;
      entry.b = rand() & 0xff;

      VFX_set_palette_entry(i, &entry, FALSE);
      }

   //
   // Load shape table
   //

   VFX_SHAPETABLE *shape_buffer = (VFX_SHAPETABLE *) FILE_read("demo.shp");

   //
   // Configure window and clipping regions
   //

   stage       = VFX_window_construct(RES_X, RES_Y);
   stage_pane  = VFX_pane_construct(stage,0,0,RES_X-1,RES_Y-1);

   VFX_assign_window_buffer(stage,NULL,-1);

   pane1 = VFX_pane_construct(stage, 0,   0,   (RES_X/4)-1, (RES_Y/3)-1);
   pane2 = VFX_pane_construct(stage, RES_X/4, RES_Y/3, ((RES_X/4)*3)-1, ((RES_Y/3)*2)-1);
   pane3 = VFX_pane_construct(stage, (RES_X/4)*3, (RES_Y/3)*2, RES_X-1, RES_Y-1);

   VFX_pane_wipe(stage_pane,RGB_TRIPLET(32,64,128));

   VFX_pane_wipe(pane1,RGB_TRIPLET(255,255,255));
   VFX_pane_wipe(pane2,RGB_TRIPLET(255,255,255));
   VFX_pane_wipe(pane3,RGB_TRIPLET(255,255,255));

#if USE_PANE_LIST

   pane_list   = VFX_pane_list_construct(16);

   VFX_pane_list_add(pane_list, pane1);
   VFX_pane_list_add(pane_list, pane2);
   VFX_pane_list_add(pane_list, pane3);

   background_invalid = SAL_get_preference(SAL_MAX_VIDEO_PAGES);

#else

   screen      = VFX_window_construct(RES_X,RES_Y);
   screen_pane = VFX_pane_construct(screen,0,0,RES_X-1,RES_Y-1);

#endif

   //
   // Pixels
   //

   state = 0;

   while (!state)
      {
      //
      // Check Windows message queue
      //

      SAL_serve_message_queue();

      //
      // Render scene (500 random dots) for this frame
      //

      for (S32 i=0; i < 500; i++)
         {
         S32 x = rand() % 400;
         S32 y = rand() % 300;

         VFX_pixel_write(pane1,x,y,RGB_TRIPLET(rand() & 0xff,0,0));
         VFX_pixel_write(pane2,x,y,RGB_TRIPLET(0,rand() & 0xff,0));
         VFX_pixel_write(pane3,x,y,RGB_TRIPLET(0,0,rand() & 0xff));
         }

      //
      // Refresh the screen
      //

      SCREEN_refresh();
      }

   //
   // Pane scroll
   //

   S32 scrollbufsize  = VFX_pane_scroll(pane2, 8, 8, PS_WRAP, NULL);
   void *scrollbuffer = malloc(scrollbufsize);

   S32 time  = 0;

   state = 0;

   while (!state)
      {
      //
      // Check Windows message queue
      //

      SAL_serve_message_queue();

      //
      // Scroll center pane by random amount in random direction
      //

      S32 x,y;

      if (!(time--))
         {
         time = 10;

         x = (rand()%17)-8;
         y = (rand()%17)-8;
         }

      VFX_pane_scroll(pane2, x,y, PS_WRAP, (LONG) scrollbuffer);

      //
      // Refresh the screen
      //

      SCREEN_refresh();
      }

   //
   // Lines
   //

   VFX_pane_wipe(pane1, RGB_TRIPLET(255,0,255));
   VFX_pane_wipe(pane2, RGB_TRIPLET(255,0,255));
   VFX_pane_wipe(pane3, RGB_TRIPLET(255,0,255));

   state = 0;

   while (!state)
      {
      //
      // Check Windows message queue
      //

      SAL_serve_message_queue();

      for (S32 i=0; i < 10; i++)
         {
         S32 x  = rand()%400 - 40;
         S32 x1 = rand()%400 - 40;
         S32 y  = rand()%350 - 25;
         S32 y1 = rand()%350 - 25;

         VFX_line_draw(pane1, x, y, x1, y1, LD_DRAW, rand () & 255);
         VFX_line_draw(pane2, x, y, x1, y1, LD_DRAW, rand () & 255);
         VFX_line_draw(pane3, x, y, x1, y1, LD_DRAW, rand () & 255);
         }

      //
      // Refresh the screen
      //

      SCREEN_refresh();
      }

   //
   // Build tables for translation tests (shades of primary colors)
   //

   U16 R_xlat[65536];
   U16 G_xlat[65536];
   U16 B_xlat[65536];

   for (i=0; i < 65536; i++)
      {
      VFX_RGB RGB;

      RGB.r = rand() & 0xff;
      RGB.g = 0;
      RGB.b = 0;

      R_xlat[i] = (U16) VFX_pixel_value(&RGB);

      RGB.r = 0;
      RGB.g = rand() & 0xff;
      RGB.b = 0;

      G_xlat[i] = (U16) VFX_pixel_value(&RGB);

      RGB.r = 0;
      RGB.g = 0;
      RGB.b = rand() & 0xff;

      B_xlat[i] = (U16) VFX_pixel_value(&RGB);
      }

   U8 byte_LUT[256];

   for (i=0; i < 256; i++)
      {
      byte_LUT[i] = (U8) i;
      }

   VFX_shape_lookaside(byte_LUT);

   //
   // Translated lines
   //

   state = 0;

   while (!state)
      {
      //
      // Check Windows message queue
      //

      SAL_serve_message_queue();

      for (S32 i=0; i < 10; i++)
         {
         S32 x  = rand()%400 - 40;
         S32 x1 = rand()%400 - 40;
         S32 y  = rand()%350 - 25;
         S32 y1 = rand()%350 - 25;

         VFX_line_draw(pane1, x, y, x1, y1, LD_TRANSLATE, (U32) R_xlat);
         VFX_line_draw(pane2, x, y, x1, y1, LD_TRANSLATE, (U32) G_xlat);
         VFX_line_draw(pane3, x, y, x1, y1, LD_TRANSLATE, (U32) B_xlat);
         }

      //
      // Refresh the screen
      //

      SCREEN_refresh();
      }

   //
   // Shape draw
   //

   S32 base = 0;

   state = 0;

   while (!state)
      {
      //
      // Check Windows message queue
      //

      SAL_serve_message_queue();

	   VFX_pane_wipe(pane1, RGB_TRIPLET(0,0,128));
	   VFX_pane_wipe(pane2, RGB_TRIPLET(0,0,128));
	   VFX_pane_wipe(pane3, RGB_TRIPLET(0,0,128));

      for (S32 y = -35; y < 228; y += 36)
         {
         for (S32 x = -40; x < 320; x += 50)
            {
            VFX_shape_draw(pane1, shape_buffer, 0, x+base, y+base);
            VFX_shape_draw(pane2, shape_buffer, 0, x+base, y+base);
            VFX_shape_draw(pane3, shape_buffer, 0, x+base, y+base);
            }
         }

      base = (base+3+(rand()%3))%40;

      //
      // Refresh the screen
      //

      SCREEN_refresh();
      }

   //
   // Rectangle hash
   //

   state = 0;
   i     = 0;

   while (!state)
      {
      //
      // Check Windows message queue
      //

      SAL_serve_message_queue();

      VFX_rectangle_hash(pane1, -999, -999, 999, 999, RGB_TRIPLET(i,0,0));
      VFX_rectangle_hash(pane2, -999, -999, 999, 999, RGB_TRIPLET(0,i,0));
      VFX_rectangle_hash(pane3, -999, -999, 999, 999, RGB_TRIPLET(0,0,i));

      i = (i + 4) & 0xff;

      //
      // Refresh the screen
      //

      SCREEN_refresh();
      }

   //
   // Shape translate/draw
   //

   base = 0;

   state = 0;

   while (!state)
      {
      //
      // Check Windows message queue
      //

      SAL_serve_message_queue();

	   VFX_pane_wipe(pane1, RGB_TRIPLET(0,0,128));
	   VFX_pane_wipe(pane2, RGB_TRIPLET(0,0,128));
	   VFX_pane_wipe(pane3, RGB_TRIPLET(0,0,128));

      for (S32 y = -35; y < 228; y += 36)
         {
         for (S32 x = -40; x < 320; x += 50)
            {
            VFX_shape_translate_draw(pane1, shape_buffer, 0, x+base, y+base);
            VFX_shape_translate_draw(pane2, shape_buffer, 0, x+base, y+base);
            VFX_shape_translate_draw(pane3, shape_buffer, 0, x+base, y+base);
            }
         }

      base = (base+3+(rand()%3))%40;

      //
      // Refresh the screen
      //

      SCREEN_refresh();
      }

   //
   // Shape transform
   //

   U8 *transform_buffer = (U8 *) calloc(320 * 200, 2);

   S32 z=0;
   S32 sx=0x10000;
   S32 sy=0x10000;
   S32 sdx = 0x1000;
   S32 sdy = 0x1000;

   base = 0;

   state = 0;

   while (!state)
      {
      //
      // Check Windows message queue
      //

      SAL_serve_message_queue();

      z += 100;

      z = z > 3599 ? 0 : z;
   
      if (sx > 0x20000)
         {
         sdx = -0x1000;
         }

      if (sx < 0x02000)
         {
         sdx = 0x1000;
         }

      sx += sdx;

      if (sy > 0x20000)
         {
         sdy = -0x1000;
         }

      if (sy < 0x02000)
         {
         sdy = 0x1000;
         }

      sy += sdy;

	   VFX_pane_wipe(pane1, RGB_TRIPLET(0,0,128));
	   VFX_pane_wipe(pane2, RGB_TRIPLET(0,0,128));
	   VFX_pane_wipe(pane3, RGB_TRIPLET(0,0,128));

      S32 flags = 0;

      for (S32 y = -35; y < 228; y +=36)
         {
         for (S32 x = -40; x < 320; x += 50)
            {
            VFX_shape_transform(pane1, shape_buffer, 0, x+base, y+base, 
                                transform_buffer, z, sx, sy, flags);

            flags = ST_REUSE;

            VFX_shape_transform(pane2, shape_buffer, 0, x+base, y+base, 
                                transform_buffer, z, sx, sy, flags);

            VFX_shape_transform(pane3, shape_buffer, 0, x+base, y+base, 
                                transform_buffer, z, sx, sy, flags);
            }
         }

      base = (base+3+(rand()%3))%40;

      //
      // Refresh the screen
      //

      SCREEN_refresh();
      }

   //
   // Ellipse draw
   //

	VFX_pane_wipe(pane1, RGB_TRIPLET(0,0,128));
	VFX_pane_wipe(pane2, RGB_TRIPLET(0,0,128));
	VFX_pane_wipe(pane3, RGB_TRIPLET(0,0,128));

   S32 x = 1;
   state = 0;

   while (!state)
      {
      //
      // Check Windows message queue
      //

      SAL_serve_message_queue();

      for (i=0; i < 100; i++)
         {
         S32 ex = rand() % 319;
         S32 ey = rand() % 479;
         S32 ew = rand() % 10-1;
         S32 eh = rand() % 10-1;
         S32 ec = (x++ & 0x0ff);

         VFX_ellipse_draw(pane1,ex,ey,ew,eh,ec);
         VFX_ellipse_draw(pane2,ex,ey,ew,eh,ec);
         VFX_ellipse_draw(pane3,ex,ey,ew,eh,ec);
         }

      //
      // Refresh the screen
      //

      SCREEN_refresh();
      }

   //
   // Ellipse fill
   //

	VFX_pane_wipe(pane1, RGB_TRIPLET(0,0,128));
	VFX_pane_wipe(pane2, RGB_TRIPLET(0,0,128));
	VFX_pane_wipe(pane3, RGB_TRIPLET(0,0,128));

   x = 1;
   state = 0;

   while (!state)
      {
      //
      // Check Windows message queue
      //

      SAL_serve_message_queue();

      for (i=0; i < 100; i++)
         {
         S32 ex = rand() % 319;
         S32 ey = rand() % 479;
         S32 ew = rand() % 10-1;
         S32 eh = rand() % 10-1;
         S32 ec = (x++ & 0x0ff);

         VFX_ellipse_fill(pane1,ex,ey,ew,eh,ec);
         VFX_ellipse_fill(pane2,ex,ey,ew,eh,ec);
         VFX_ellipse_fill(pane3,ex,ey,ew,eh,ec);
         }

      //
      // Refresh the screen
      //

      SCREEN_refresh();
      }

   //
   // Flat polygons
   //

	VFX_pane_wipe(pane1, RGB_TRIPLET(0,0,128));
	VFX_pane_wipe(pane2, RGB_TRIPLET(0,0,128));
	VFX_pane_wipe(pane3, RGB_TRIPLET(0,0,128));

   x = 1;
   state = 0;

   while (!state)
      {
      //
      // Check Windows message queue
      //

      SAL_serve_message_queue();

      for (i=0; i < 10; i++)
         {
         SCRNVERTEX v[3];

         for (S32 j=0; j < 3; j++)
            {
            v[j].x     = (rand() % 999) - 500;
            v[j].y     = (rand() % 999) - 500;
            v[j].color = x & 0xff;
            }

         ++x;

         VFX_flat_polygon(pane1,3,v);
         VFX_flat_polygon(pane2,3,v);
         VFX_flat_polygon(pane3,3,v);
         }

      //
      // Refresh the screen
      //

      SCREEN_refresh();
      }

   //
   // Build translation tables
   //

   S32 R_bits,G_bits,B_bits;

   SAL_get_pixel_format(NULL, NULL,
                        NULL, NULL, &R_bits,
                        NULL, NULL, &G_bits,
                        NULL, NULL, &B_bits);

   for (i=0; i < 65536; i++)
      {
      VFX_RGB src,RGB;

      src = *VFX_RGB_value(i);

      U32 r = src.r;
      U32 g = src.g;
      U32 b = src.b;

      r = min(255, r + (256 / (1 << R_bits)));
      g = min(255, g + (256 / (1 << G_bits)));
      b = min(255, b + (256 / (1 << B_bits)));

      RGB   = src;
      RGB.r = (U8) r;

      R_xlat[i] = (U16) VFX_pixel_value(&RGB);

      RGB   = src;
      RGB.g = (U8) g;

      G_xlat[i] = (U16) VFX_pixel_value(&RGB);

      RGB   = src;
      RGB.b = (U8) b;

      B_xlat[i] = (U16) VFX_pixel_value(&RGB);
      }

   //
   // Translated polygons
   //

	VFX_pane_wipe(pane1, RGB_TRIPLET(0,0,0));
	VFX_pane_wipe(pane2, RGB_TRIPLET(0,0,0));
	VFX_pane_wipe(pane3, RGB_TRIPLET(0,0,0));

   state = 0;

   while (!state)
      {
      //
      // Check Windows message queue
      //

      SAL_serve_message_queue();

      for (i=0; i < 2; i++)
         {
         SCRNVERTEX v[3];

         for (S32 j=0; j < 3; j++)
            {
            v[j].x = (rand() % 999) - 500;
            v[j].y = (rand() % 999) - 500;
            }

         VFX_translate_polygon(pane1,3,v,R_xlat);
         VFX_translate_polygon(pane2,3,v,G_xlat);
         VFX_translate_polygon(pane3,3,v,B_xlat);
         }

      //
      // Refresh the screen
      //

      SCREEN_refresh();
      }

   //
   // Build translation tables
   //

   for (i=0; i < 65536; i++)
      {
      VFX_RGB src,RGB;

      src = *VFX_RGB_value(i);

      U32 r = src.r;
      U32 g = src.g;
      U32 b = src.b;

      r = min(255, r + (256 / (1 << (R_bits-3))));
      g = min(255, g + (256 / (1 << (G_bits-3))));
      b = min(255, b + (256 / (1 << (B_bits-3))));

      RGB   = src;
      RGB.r = (U8) r;

      R_xlat[i] = (U16) VFX_pixel_value(&RGB);

      RGB   = src;
      RGB.g = (U8) g;

      G_xlat[i] = (U16) VFX_pixel_value(&RGB);

      RGB   = src;
      RGB.b = (U8) b;

      B_xlat[i] = (U16) VFX_pixel_value(&RGB);
      }


   //
   // Shape area translate
   //

   base = 0;

   state = 0;

   while (!state)
      {
      //
      // Check Windows message queue
      //

      SAL_serve_message_queue();

	   VFX_pane_wipe(pane1, RGB_TRIPLET(64,64,64));
	   VFX_pane_wipe(pane2, RGB_TRIPLET(64,64,64));
	   VFX_pane_wipe(pane3, RGB_TRIPLET(64,64,64));

      S32 flags = 0;

      for (S32 y = -35; y < 228; y += 36)
         {
         for (S32 x = -40; x < 320; x += 50)
            {
            VFX_shape_area_translate(pane1, shape_buffer, 0, x+base, y, 
                              transform_buffer, 0, 0x10000, 0x10000, flags,
                              R_xlat);

            flags |= ST_REUSE;

            VFX_shape_area_translate(pane2, shape_buffer, 0, x+base, y, 
                              transform_buffer, 0, 0x10000, 0x10000, flags,
                              G_xlat);

            VFX_shape_area_translate(pane3, shape_buffer, 0, x+base, y, 
                              transform_buffer, 0, 0x10000, 0x10000, flags,
                              B_xlat);
            }
         }

      base = (base+3) % 50;

      //
      // Refresh the screen
      //

      SCREEN_refresh();
      }
}

//****************************************************************************
//
// Windows main() function
//
//****************************************************************************

int PASCAL WinMain(HINSTANCE hInstance, //)
                   HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine,     
                   int nCmdShow)
{
   //
   // Initialize system abstraction layer -- must succeed in order to continue
   //

   if (!SAL_startup(hInstance,
                    szAppName,
                    FALSE,
                    WinExit))
      {
      return 0;
      }

   //
   // Create application window
   // 

   hWnd = SAL_create_main_window();

   if (hWnd == NULL)
      {
      SAL_shutdown();
      return 0;
      }

   //
   // Register window procedure
   // 

   SAL_register_WNDPROC(WindowProc);

   //
   // Register exit handler 
   //

   atexit(AppExit);

   //
   // Call AppMain() function (does not return)
   //

   AppMain(lpCmdLine);

   return 0;
}

