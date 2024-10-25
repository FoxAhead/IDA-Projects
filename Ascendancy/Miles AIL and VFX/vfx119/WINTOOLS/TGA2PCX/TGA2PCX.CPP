//
// TGA2PCX
//
// (C) 1996-1997 Miles Design, Inc. / jmiles@pop.net
//
// Author: John Miles
//
// **************************************************************************
// *** UNSUPPORTED / UNDOCUMENTED WINVFX UTILITY TO SERVE AS EXAMPLE CODE ***
// ***                  FOR WU COLOR QUANTIZER CLASS                      ***
// **************************************************************************
//
//

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
#include "tga.h"
#include "pcx.h"
#include "rgbutils.h"

char szAppName[] = "WinVFX TGA2PCX";

//
// Window handle created by SAL
//

HWND hWnd;

S32 state;

//
// Windows/panes used by demo
//

VFX_WINDOW *screen;
PANE       *screen_pane;

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
            // Any other key advances test state
            //

            default:
               ++state;
               break;
            }
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
   //
   // Don't allow user to resize window
   //

   SAL_set_preference(SAL_ALLOW_WINDOW_RESIZE, NO);

   //
   // Parse command line to get input and output file names
   //

   S32 len = strlen(lpCmdLine);

   if (!len)
      {
      SAL_alert_box("Command Help","Type \"TGA2PCX filename[.tga]\" to convert filename.tga to filename.pcx");
      exit(0);
      }

   C8 in_fn [MAX_PATH];
   C8 out_fn[MAX_PATH];

   strcpy(in_fn,  lpCmdLine);
   strcpy(out_fn, lpCmdLine);

   C8 *dot = strrchr(in_fn,'.');
   if (dot != NULL)
      {
      *dot = 0;
      }

   dot = strrchr(out_fn,'.');
   if (dot != NULL)
      {
      *dot = 0;
      }

   strcat(in_fn,".TGA");
   strcat(out_fn,".PCX");

   SAL_debug_printf("Converting \"%s\" to \"%s\"\n",in_fn,out_fn);

   //
   // Load .TGA file
   //

   void *TGA = FILE_read(in_fn);

   if (TGA == NULL)
      {
      SAL_alert_box("Error","Could not read file %s", lpCmdLine);
      exit(0);
      }

   S32 iw,ih,sw,sh;

   VFX_RGB *RGB = TGA_parse(TGA, &iw, &ih);

   if (RGB == NULL)
      {
      exit(0);
      }

   SAL_debug_printf("TGA image (%d,%d)\n",iw,ih);

   //
   // Set 16bpp windowed mode (DirectDraw fullscreen mode may also be used
   // with VFX_FULLSCREEN, but may not be available to match image 
   // resolution)
   //

   if (!VFX_set_display_mode(sw = max(iw,320), 
                             sh = max(ih,200), 
                             16,
                             VFX_WINDOW_MODE,
                             TRUE))
      {
      exit(1);
      }

   screen      = VFX_window_construct(sw,sh);
   screen_pane = VFX_pane_construct(screen,0,0,sw-1,sh-1);

   S32 h = min(ih,sh);
   S32 w = min(iw,sw);

   //
   // Show initial image
   //

   S32 x,y;

   VFX_lock_window_surface(screen,VFX_BACK_SURFACE);

   for (y=0; y < h; y++)
      {
      VFX_RGB *in = &RGB[iw * y];

      for (x=0; x < w; x++)
         {
         VFX_pixel_write(screen_pane,
                         x,
                         y,
                         RGB_TRIPLET(in->r, in->g, in->b));
         ++in;
         }
      }

   VFX_unlock_window_surface(screen, TRUE);

   //
   // Create color quantizer object and pass pixel data to it
   //

   VFX_RGB palette[256];

   CQ quantizer;

   for (y=0; y < ih; y++)
      {
      for (x=0; x < iw; x++)
         {
         quantizer.add_color(&RGB[(iw*y)+x]);
         }
      }

   quantizer.quantize(palette,  
                      256);

   //
   // Remap and display result
   //

   U8 *out = (U8 *) malloc(iw * ih);

   if (out == NULL)
      {
      exit(0);
      }

   CMAP remap(palette, 256);

   VFX_lock_window_surface(screen,VFX_BACK_SURFACE);

   for (y=0; y < ih; y++)
      {
      for (x=0; x < iw; x++)
         {
         out[(y*iw)+x] = remap.nearest_neighbor(&RGB[(y*iw)+x],
                                                 0);

         VFX_RGB *p = &palette[out[(y*iw)+x]];

         VFX_pixel_write(screen_pane,
                         x,
                         y,
                         RGB_TRIPLET(p->r, p->g, p->b));
         }
      }

   VFX_unlock_window_surface(screen, TRUE);

   //
   // Save .PCX image
   //

   PCX_save(out_fn,
            iw,
            ih,
            out,
     (U8 *) palette);
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

