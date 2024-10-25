//****************************************************************************
//*                                                                          *
//*  System Abstraction Layer                                                *
//*                                                                          *
//*  W32SAL.CPP: API module and support routines for Win32/DirectX           *
//*                                                                          *
//*  32-bit protected-mode source compatible with Watcom 10.5/MSC 9.0        *
//*                                                                          *
//*  Version 1.00 of 23-May-96: Initial                                      *
//*          1.01 of 12-May-02: New desktop mode detection code              *
//*                             Paramon support for Win2K                    *
//*                             Improved handling of ALT-keys                *
//*                             Maximize button emulates Alt-Enter           *
//*          1.12 of  4-Oct-02: Added desktop mode functionality             *
//*          1.13 of 28-Mar-03: Invalidate stored window position in         *
//*                             SAL_set_display_mode()                       *
//*          1.14 of 18-Nov-05: Allow preferences to be set before calling   *
//*                             SAL_startup()                                *
//*                                                                          *
//*  Author: John Miles                                                      *
//*                                                                          *
//****************************************************************************
//*                                                                          *
//*  Copyright (C) 1996 Miles Design, Inc. / jmiles@pop.net                  *
//*                                                                          *
//****************************************************************************

#define DIRECTDRAW_VERSION 0x0500   // Ensure we can run with DDraw 5 and up

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <windowsx.h>
#include <winuser.h>
#include <mmsystem.h>

#include <stdio.h>
#include <conio.h>
#include <dos.h>
#include <malloc.h>
#include <direct.h>
#include <io.h>
#include <time.h>
#include <limits.h>

#define INITGUID
#include <ddraw.h>

#include "sal.h"

//
// Configuration equates
//

#define DDRAW_DYNAMIC 1       // TRUE to load/unload DDRAW.DLL dynamically

//****************************************************************************
//*                                                                          *
//*  SAL statics and globals                                                 *
//*                                                                          *
//****************************************************************************

#define SAL_info_printf if (!SAL_get_preference(SAL_QUIET)) SAL_debug_printf

enum SAL_SURFACE_SOURCE
{
   S_DDRAW,
   S_MEM
};

struct SURFDESC
{
   S32 width;
   S32 height;
   S32 bpp;

   SAL_SURFACE_SOURCE source;

   union
      {
      LPDIRECTDRAWSURFACE3 lpDDS;
      void                *ptr;
      }
   object;
};

//
// Common variables
//

C8        *application_icon;
C8         icon_name_buffer[MAX_PATH];

S32        desktop_w;                 // Windows desktop width, height
S32        desktop_h;
S32        desktop_bpp;               // Windows video mode BPP
S32        desktop_refresh;           // Refresh rate in Hz
U32        desktop_R_bitmask;         // Desktop high-color pixel format
U32        desktop_G_bitmask;        
U32        desktop_B_bitmask;

DEVMODE    desktop_mode;              // Windows DEVMODE structure
S32        desktop_mode_valid;        // FALSE if desktop DEVMODE could not be reliably determined

S32        cursor_state;              // Copy of Windows mouse hide/show state
S32        show_count;                // System mouse cursor show count

S32        WPS_lock;                  // TRUE to ignore WM_WINDOWPOSCHANGED messages

char       debug_log_filename[256];
S32        debug_start_time;
S32        log_to_file;               // TRUE if user wants debug log

S32        app_minimized;             // TRUE if this SAL app has been minimized
S32        app_active;                // TRUE if this SAL app has input focus
S32        app_terminated;            // TRUE if app has received its quit message

SALEXITCB  exit_callback;             // Address of mandatory exit callback
SALFOCUSCB focus_callback;            // Address of focus callback, if any
WNDPROC    window_callback;           // Address of WNDPROC, if any
HANDLE     hSem;                      // Semaphore to limit instances

S32        mode_change_request;       // TRUE to toggle window/fullscreen

HINSTANCE  hAppInstance;              // Application instance handle
HINSTANCE  hDLLInstance;              // DLL instance handle
char       szAppName[512];            // Application name
HWND       hWnd;                      // Handle to application window
HANDLE     hHook;                     // Handle to Windows hook object

S32        mode_change_allowed;       // TRUE if window/fullscreen toggle allowed
S32        current_display_mode;      // SAL_FULLSCREEN / SAL_WINDOW / SAL_DESKTOP
S32        current_bpp;               // Mode info set by last call to 
S32        current_size_X;            //  SAL_set_display_mode
S32        current_size_Y;
S32        requested_size_X;          // Mode info sent to last call to 
S32        requested_size_Y;          //  SAL_set_display_mode
S32        requested_bpp;             

LOGPALETTE       *pLogPal;            // LOGPALETTE structure
BITMAPINFO       *pbmi;               // BITMAPINFO structure
BITMAPINFOHEADER *pbmih;              // Pointer to pbmi header

HBITMAP           DefaultBitmap;      // 

SAL_RGB  palette_state[256];          // Current state of all DAC registers

//
// DirectDraw (full-screen or windowed mode) variables and related data
//

SALDDSTARTUPCB      lpDDStartup;      // DirectDraw startup function
SALDDSHUTDOWNCB     lpDDShutdown;     // DirectDraw shutdown function

SAL_DDRAWINFO       DDraw;            // DirectDraw object/surface info

S32                 DDraw_active;     // DirectDraw active if TRUE
HINSTANCE           DDraw_lib_handle; // handle to ddraw library

DWORD               lock_flags;       // Flags passed to IDDSurface::Lock

//
// CreateDIBSection() (windowed mode) variables and related data
//

SAL_WINAREA area;                     // Location/size of window client area

U32         DIB_R_bitmask;            // DIB high-color pixel format
U32         DIB_G_bitmask;
U32         DIB_B_bitmask;

S32         DIB_active;               // CreateDIBSection() active if TRUE

U8         *lpDIBBuffer;              // DIB image buffer
HBITMAP     hDIB;                     // Handle returned from CreateDIBSection
HPALETTE    hPalette;                 // Handle to palette if 8-bit mode in use

S32         palette_change_request;   // TRUE to signal palette update

RECT        original_window_rect;     // Default size of DIB window (valid if left != LONG_MAX)
SAL_WINAREA original_area;            // Default size of client area (valid if width != -1)

RECT       unconstrained_rect;        // Default area of mouse constraint
S32        constrain_state;           // 1 if mouse limited to window area
S32        constrain_request;         // 1 if mouse should be constrained at next movement

#define ARY_CNT(x) (sizeof((x)) / sizeof((x)[0]))

S32 xmit_timeout;
S32 using_port = -1;

S32 data_ports[] = { 0x378, 0x3bc, 0x278 };
S32 stat_ports[] = { 0x379, 0x3bd, 0x279 };

//
// Establish default preferences at static-construction time,
// so they can be set prior to startup
//

S32 SAL_preference[N_SAL_PREFS];      // Preferences array

struct PREFMGR
{
   PREFMGR()
      {
      SAL_set_preference(SAL_ALLOW_FRONT_LOCK,         DEFAULT_AFL);
      SAL_set_preference(SAL_BUFFER_IF_NO_LFB,         DEFAULT_BINL);
      SAL_set_preference(SAL_MAX_VIDEO_PAGES,          DEFAULT_MVP);
      SAL_set_preference(SAL_ALLOW_WINDOW_RESIZE,      DEFAULT_AWR);
      SAL_set_preference(SAL_PREVENT_ALT_MENU_POPUP,   DEFAULT_PAMP);
      SAL_set_preference(SAL_ALWAYS_ON_TOP,            DEFAULT_SAOT);
      SAL_set_preference(SAL_MAXIMIZE_TO_FULLSCREEN,   DEFAULT_MTF);
      SAL_set_preference(SAL_USE_DDRAW_IN_WINDOW,      DEFAULT_UDIW);
      SAL_set_preference(SAL_USE_PAGE_FLIPPING,        DEFAULT_UPF);
      SAL_set_preference(SAL_USE_DDRAW_CLIPPER,        DEFAULT_UDDC);
      SAL_set_preference(SAL_TOGGLE_DESKTOP_WINDOW,    DEFAULT_TDW);
      SAL_set_preference(SAL_USE_DDRAW_IN_DESKTOP,     DEFAULT_UDID);
      SAL_set_preference(SAL_SLEEP_WHILE_INACTIVE,     DEFAULT_SWI);
      SAL_set_preference(SAL_QUIET,                    DEFAULT_SQMODE);
      SAL_set_preference(SAL_USE_PARAMON,              DEFAULT_SUP);
      }
};

static PREFMGR preference_manager;

/*************************************************************/
//
// permit_IO()
//
/*************************************************************/

int permit_IO(S32 port)
{  
#if 1
   typedef (NTAPI *pfn_NtSetInformation)(HANDLE,DWORD,void*,DWORD);

   //
   // Get access to NTDLL.DLL undocumented functionality
   //

   WORD err = SetErrorMode(0x8000);

   HMODULE module = LoadLibrary("ntdll.dll");

   SetErrorMode(err);

   if (module == NULL)
      {
      //
      // Not running under NT, OK to hit ports without any further 
      // tinkering
      //

      return TRUE;
      }

   //
   // Process must assert the SE_TCB_NAME privilege before
   // calling NtSetInformationProcess()
   //

   TOKEN_PRIVILEGES tp;
   HANDLE hToken = NULL;

   //    
   // First, retrieve a handle to the process token with the proper access
   //

   if (!OpenProcessToken(GetCurrentProcess(), 
                         TOKEN_ADJUST_PRIVILEGES,
                        &hToken))
      {
      //
      // Not running under NT, OK to hit ports without any further 
      // tinkering
      //

      FreeLibrary(module);
      return TRUE;
      }

   //
   // Look up the LUID for the TCB Name privilege
   //

   if (!LookupPrivilegeValue(NULL, 
                             SE_TCB_NAME, 
                            &tp.Privileges[0].Luid)) 
      {
      CloseHandle(hToken);
      FreeLibrary(module);
      return FALSE;
      }

   //
   // Enable the TCB Name privilege in the process token
   //

   tp.PrivilegeCount           = 1;
   tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

   if (!AdjustTokenPrivileges(hToken, 
                              FALSE, 
                             &tp, 
                              0, 
                              NULL, 
                              0) || GetLastError() != ERROR_SUCCESS) 
      {
      CloseHandle(hToken);
      FreeLibrary(module);
      return FALSE;
      }

   //
   // Run this process at IOPL=3 so I/O ports can be accessed freely
   //
   // Undocumented NtSetInformationProcess() function is called with hardwired
   // constants from DDK header files
   //
      
   ULONG Iopl = 3;

   pfn_NtSetInformation setinfo = (pfn_NtSetInformation) 
      GetProcAddress(module, "NtSetInformationProcess");

   LONG rc = setinfo((HANDLE) -1,             // NtCurrentProcess()
                               16,            // ProcessUserModeIOPL
                              &Iopl,
                               sizeof(Iopl));

   //
   // Free allocated resources and return whether or not it's safe to 
   // access the I/O ports
   //

   CloseHandle(hToken);
   FreeLibrary(module);

   if (rc == 0)
      {
      return TRUE;
      }

   return FALSE;

#else

   //
   // Use PortTalk driver (http://www.beyondlogic.org/porttalk/porttalk.htm)
   // to change IOPL map for process
   //

   HANDLE h = CreateFile("\\\\.\\PortTalk", 
         GENERIC_READ, 
         0, 
         NULL,
         OPEN_EXISTING, 
         FILE_ATTRIBUTE_NORMAL, 
         NULL);

   if (h == INVALID_HANDLE_VALUE) 
      {
      return FALSE;
      }

   DWORD BytesReturned = 0;

   int result = DeviceIoControl(h,            
                                0x10,         
                                NULL,         
                                0,            
                                NULL,         
                                0,            
                                &BytesReturned,
                                NULL);
   if (!result)
      {
      return FALSE;
      }

   int offset = port / 8;
   
   result = DeviceIoControl(h,             
                            0x18,          
                           &offset,        
                            3,             
                            NULL,          
                            0,             
                           &BytesReturned, 
                            NULL);
   if (!result)
      {
      return FALSE;
      }

   DWORD dwProcessId = GetCurrentProcessId();

   result = DeviceIoControl(h,                      
                            0x04,                   
                           &dwProcessId,           
                            sizeof(dwProcessId),    
                            NULL,                   
                            0,                      
                           &BytesReturned,         
                            NULL);
   Sleep(20);
   return result;
#endif
}

/*************************************************************/
//
// inp(), outp()
//
/*************************************************************/

void outp(int port, int d)
{
   _asm 
      {
      mov edx,port
      mov eax,d
      out dx,al          
      }
}

int inp(int port)
{
   int result;

   _asm 
      {
      mov edx,port
      xor eax,eax
      in al,dx
      mov result,eax
      }

   return result;
}

/*************************************************************/
//
// send_char()
//
/*************************************************************/

S32 send_char(S32 ch)
{
   //
   // Write low nibble
   //

   outp(data_ports[using_port], ch | 0x10);

   //
   // Wait until receiver acknowledges nibble or timeout occurs
   //

   S32 i;

   for (i=0; i < xmit_timeout; i++)
      {
      S32 r = inp(stat_ports[using_port]);

      if (r == -1)
         {
         return 0;
         }

      if (!(r & 0x80))
         {
         break;
         }
      }

   if (i == xmit_timeout)
      {
      //
      // Clear nibble flag and return 0 if receiver fails 
      // to acknowledge transmission
      //
      //

      outp(data_ports[using_port],0);
      return 0;
      }

   //
   // Write high nibble
   //

   outp(data_ports[using_port], ch >> 4);

   //
   // Wait until receiver acknowledges nibble or timeout occurs
   //

   for (i=0; i < xmit_timeout; i++)
      {
      if (inp(stat_ports[using_port]) & 0x80)
         {
         break;
         }
      }

   if (i == xmit_timeout)
      {
      //
      // Return 0 if receiver fails to acknowledge transmission
      //

      return 0;
      }

   //
   // Return 1 if character received successfully
   //

   return 1;
}

//****************************************************************************
//*                                                                          *
//*  DLLMain() function to acquire DLL instance handle, etc.                 *
//*                                                                          *
//****************************************************************************

BOOL WINAPI DllMain(HINSTANCE hinstDLL,//)
                    DWORD     fdwReason,
                    LPVOID    lpvReserved)
{
   if (fdwReason == DLL_PROCESS_ATTACH)
      {
      hDLLInstance = hinstDLL;
      }

   return TRUE;
}

//****************************************************************************
//*                                                                          *
//*  Serve Windows message queue, returning 0 if WM_QUIT message received    *
//*                                                                          *
//****************************************************************************

void serve_queue(void)
{
   MSG msg;

   if (app_terminated)
      {
      return;
      }

   //
   // Serve message queue
   //

   while (PeekMessage( &msg, NULL, 0, 0, PM_NOREMOVE))
      {
      if (!GetMessage(&msg, NULL, 0, 0 ))
         {
         app_active     = FALSE;
         app_terminated = TRUE;

         (exit_callback)();

         //
         // Return statement should not be reached
         //

         return;
         }

      TranslateMessage(&msg); 
      DispatchMessage(&msg);
      }
}

//****************************************************************************
//*                                                                          *
//*  Return rectangle containing client-area boundaries in screenspace       *
//*                                                                          *
//****************************************************************************

RECT *client_screen_rect(void)
{
   static RECT  rect;
   POINT        ul,lr;

   GetClientRect(hWnd, &rect);

   ul.x = rect.left; 
   ul.y = rect.top; 
   lr.x = rect.right; 
   lr.y = rect.bottom; 

   if (GetMenu(hWnd) != NULL)
      {
      ul.y -= GetSystemMetrics(SM_CYMENU);
      }

   ClientToScreen(hWnd, &ul); 
   ClientToScreen(hWnd, &lr); 

   SetRect(&rect, ul.x, ul.y, 
                  lr.x-1, lr.y-1); 

   return &rect;
}

//****************************************************************************
//*                                                                          *
//*  Obtain RGB mask values corresponding to Windows desktop format          *
//*                                                                          *
//*  Returns desktop bits-per-pixel value                                    *
//*                                                                          *
//*  Optimum blit speed is obtained in windowed mode by using these          *
//*  mask values to create the DIB section                                   *
//*                                                                          *
//*  Currently assumes R-G-B component order; other formats may cause        *
//*  suboptimal performance                                                  *
//*                                                                          *
//****************************************************************************

S32 get_GDI_pixel_format(U32 *R, U32 *G, U32 *B)
{
   HDC      hdc;
   COLORREF color,save;
   S32      bpp;

   hdc = GetDC(hWnd);

   //
   // Get # of bits per pixel
   //

   bpp = GetDeviceCaps(hdc, BITSPIXEL) * 
         GetDeviceCaps(hdc, PLANES);

   //
   // If in palettized mode, exit
   //

   if (bpp == 8)
      {
      ReleaseDC(hWnd, hdc);

      *R = 0;
      *G = 0;
      *B = 0;

      return bpp;
      }

   //
   // Preserve upper-left pixel value
   //

   GdiFlush();
   save = GetPixel(hdc,0,0);
   GdiFlush();

   //
   // Write pixel value in 8-8-8 format with 5th bit from MSB = 1
   // >5-bit RGB components will read back identically
   //  5-bit RGB components will read back 0
   //
   // (JM: This would seem to be off by one, in that a 5-bit color
   // component should preserve the 5th-order bit, but Windows does not
   // appear to work that way...)
   //

   SetPixel(hdc,0,0,RGB(0x08,0x08,0x08));

   GdiFlush();
   Sleep(100);

   //
   // Retrieve pixel in 8-8-8 format, and look for position of '1' 
   // bit in component fields
   //
   // (JM: Does not work properly under Win2K with NVidia drivers in 16bpp mode,
   // so we'll use this routine only as a fallback)
   //

   color = GetPixel(hdc,0,0) & 0xffffff;

   switch (color)
      {
      //
      // 0x000000 = 5-5-5
      //

      case 0x000000:
         
         SAL_info_printf("(5-5-5)\n");

         *R = 0x007c00;
         *G = 0x0003e0;
         *B = 0x00001f;
         break;

      //
      // 0x000800 = 5-6-5
      //

      case 0x000800:
         
         SAL_info_printf("(5-6-5)\n");

         *R = 0x00f800;
         *G = 0x0007e0;
         *B = 0x00001f;
         break;

      //
      // 0x080808 = 8-8-8
      //

      case 0x080808:

         SAL_info_printf("(8-8-8)\n");

         *R = 0xff0000;
         *G = 0x00ff00;
         *B = 0x0000ff;
         break;

      default:

         SAL_info_printf("(Unrecognized, using ");

         if ((bpp == 15) || (bpp == 16))
            {
            SAL_info_printf("(5-5-5)");

            *R = 0x007c00;
            *G = 0x0003e0;
            *B = 0x00001f;
            }
         else
            {
            SAL_info_printf("8-8-8");

            *R = 0xff0000;
            *G = 0x00ff00;
            *B = 0x0000ff;
            }

         SAL_info_printf(")\n");
         break;
      }

   //
   // Restore initial pixel value
   //

   SetPixel(hdc,0,0,save);

   ReleaseDC(hWnd, hdc);

   return bpp;
}

void get_desktop_format(U32 *R, //)
                        U32 *G, 
                        U32 *B,
                        S32 *X_size,
                        S32 *Y_size,
                        S32 *BPP,
                        S32 *refresh_rate)
{
   //
   // Get desktop size (actually, the screen resolution of the
   // primary display monitor)
   //

   *X_size = GetSystemMetrics(SM_CXSCREEN);
   *Y_size = GetSystemMetrics(SM_CYSCREEN);

   //
   // Get # of bytes per pixel
   //
       
   HDC dc = GetDC(hWnd);

   *BPP = GetDeviceCaps(dc, BITSPIXEL) * 
          GetDeviceCaps(dc, PLANES);

   S32 pixelsize = *BPP / 8;

   SAL_info_printf("SAL: Desktop format %dx%dx%dbpp",
      *X_size,
      *Y_size,
      *BPP);

   //
   // Detect modes other than 15/16 bpp
   //

   if (pixelsize <= 1)
      {
      ReleaseDC(hWnd, dc);

      SAL_info_printf(" (Palettized)");

      *R = 0;
      *G = 0;
      *B = 0;
      }
   else if (pixelsize > 2)
      {
      //
      // 24/32bpp or higher format
      //

      ReleaseDC(hWnd, dc);

      SAL_info_printf(" (8-8-8)");

      *R = 0xff0000;
      *G = 0x00ff00;
      *B = 0x0000ff;
      }
   else
      {
      //
      // Code from Bink to determine 15/16bpp masks...
      //

      U8 buf[sizeof(BITMAPINFOHEADER) + 256 * sizeof(RGBQUAD)];

      BITMAPINFO *bi = (BITMAPINFO *) buf;

      HBITMAP hbm;

      memset(bi,
             0,
             sizeof(BITMAPINFOHEADER) + 256 * sizeof(RGBQUAD));

      bi->bmiHeader.biSize = sizeof(BITMAPINFOHEADER);

      hbm = CreateCompatibleBitmap(dc,1,1);

      if (hbm == 0)
         {
         //
         // Per JKR, this can fail on pre-OSR2 Win95 boxes.  Use old method,
         // rejecting any erroneous recognition of true-color mode in favor of 
         // 5-5-5 masks
         //

         get_GDI_pixel_format(R, G, B);

         if (*R == 0xff0000)
            {
            *R = 0x007c00;
            *G = 0x0003e0;
            *B = 0x00001f;
            }
         }
      else
         {
         //
         // Following line intentionally duplicated
         //

         GetDIBits(dc,hbm,0,1,NULL,bi,DIB_RGB_COLORS);
         GetDIBits(dc,hbm,0,1,NULL,bi,DIB_RGB_COLORS);

         DeleteObject(hbm);
         ReleaseDC(hWnd, dc);

         if ((bi->bmiHeader.biCompression == BI_BITFIELDS) 
              &&
            ((*((U32*) &bi->bmiColors[0])) == 0xf800))
            {
            SAL_info_printf(" 0x%.04X (5-6-5)",
               (*((U32*) &bi->bmiColors[0])));

            *R = 0x00f800;
            *G = 0x0007e0;
            *B = 0x00001f;
            }
         else
            {
            SAL_info_printf(" 0x%.04X (5-5-5)",
               (*((U32*) &bi->bmiColors[0])));

            *R = 0x007c00;
            *G = 0x0003e0;
            *B = 0x00001f;
            }
         }

      ReleaseDC(hWnd, dc);
      }

   //
   // Finally, look up current mode with EnumDisplaySettings() to try to 
   // determine its refresh rate
   //

   *refresh_rate      = 0;
   desktop_mode_valid = FALSE;

   if (EnumDisplaySettings(NULL,
                           ENUM_CURRENT_SETTINGS,
                          &desktop_mode))
      {
      //
      // Make sure we got sensible values back from EnumDisplaySettings() --
      // some versions of Win9X may not be reliable
      //

      if (((S32) desktop_mode.dmBitsPerPel == *BPP)    &&
          ((S32) desktop_mode.dmPelsWidth  == *X_size) &&
          ((S32) desktop_mode.dmPelsHeight == *Y_size))
         {
         desktop_mode_valid = TRUE;

         *refresh_rate = desktop_mode.dmDisplayFrequency;
         }
      }

   if (*refresh_rate)
      {
      SAL_info_printf(", %d Hz",*refresh_rate);
      }

   SAL_info_printf("\n");
}

//****************************************************************************
//*                                                                          *
//*  Configure window for desktop mode (DDraw only) display                  *
//*                                                                          *
//****************************************************************************

void set_desktop_mode(S32 force_taskbar_update)
{
   //
   // Set flag to indicate fullscreen transition in progress
   //
   // This will suppress our handling of WM_WINDOWPOSCHANGED, so that
   // transitioning from windowed to fullscreen will not reset the client 
   // area to the entire desktop.
   //

   ++WPS_lock;

   //
   // Disable caption menu
   //

   SetWindowLong(hWnd, 
                 GWL_STYLE, 
                 GetWindowLong(hWnd, GWL_STYLE) | WS_POPUP);

   SetWindowLong(hWnd, 
                 GWL_STYLE, 
                 GetWindowLong(hWnd, GWL_STYLE) & ~(WS_OVERLAPPED  | 
                                                    WS_CAPTION     | 
                                                    WS_SYSMENU     | 
                                                    WS_MINIMIZEBOX | 
                                                    WS_MAXIMIZEBOX | 
                                                    WS_THICKFRAME));
   //
   // Set window boundaries to cover entire desktop, and show it
   //

   area.w = desktop_w;
   area.h = desktop_h;
   area.x = 0;
   area.y = 0;

   SetWindowPos(hWnd, 
                HWND_TOP, 
                0,
                0,
                desktop_w,
                desktop_h,
                SWP_NOCOPYBITS | SWP_NOZORDER);

   ShowWindow(hWnd, SW_SHOWNORMAL);

   //
   // If this mode switch is affecting a pre-existing app window, force the 
   // taskbar to update itself, then set the focus back to our window
   //
   // We don't do this for the first call in an application because it causes
   // the DOS box to fail to regain the input focus when the app exits
   //
   // (This actually causes the taskbar to hide itself, since we've created a
   // fullscreen window.  On some systems, there's a delay before the taskbar
   // goes away on its own during mode switches, which is fixed by the 
   // SetWindowPos() call)
   //

   if (force_taskbar_update)
      {
      HWND Thwnd = FindWindow("Shell_traywnd", "");

      if (Thwnd != NULL)
         {
         SetWindowPos(Thwnd,0,0,0,0,0,SWP_SHOWWINDOW);
         }

      SetFocus(hWnd);
      }

   --WPS_lock;
}

//****************************************************************************
//*                                                                          *
//*  Configure window for fullscreen mode (DDraw only) display               *
//*                                                                          *
//****************************************************************************

void set_fullscreen_mode(void)
{
   //
   // Set flag to indicate fullscreen transition in progress
   //
   // This will suppress our handling of WM_WINDOWPOSCHANGED, so that
   // transitioning from windowed to fullscreen will not reset the client 
   // area to the entire desktop.
   //

   ++WPS_lock;

   //
   // Disable caption menu
   //

   SetWindowLong(hWnd, 
                 GWL_STYLE, 
                 GetWindowLong(hWnd, GWL_STYLE) | WS_POPUP);

   SetWindowLong(hWnd, 
                 GWL_STYLE, 
                 GetWindowLong(hWnd, GWL_STYLE) & ~(WS_OVERLAPPED  | 
                                                    WS_CAPTION     | 
                                                    WS_SYSMENU     | 
                                                    WS_MINIMIZEBOX | 
                                                    WS_MAXIMIZEBOX | 
                                                    WS_THICKFRAME));
   //
   // Set window boundaries to cover entire desktop, and show it
   //

   SetWindowPos(hWnd, 
                HWND_TOP, 
                0,
                0,
                desktop_w,
                desktop_h,
                SWP_NOCOPYBITS | SWP_NOZORDER);

   ShowWindow(hWnd, SW_SHOWNORMAL);

   --WPS_lock;
}

//****************************************************************************
//*                                                                          *
//*  Configure window for windowed-mode (DIB or DDraw) display               *
//*                                                                          *
//****************************************************************************

void set_windowed_mode(S32 display_size_X, //)
                       S32 display_size_Y)
{
   S32  retry;
   RECT client_rect;
   RECT window_rect;

   ++WPS_lock;

   //
   // Enable caption menu and user preferences
   //

   SetWindowLong(hWnd, 
                 GWL_STYLE, 
                 GetWindowLong(hWnd, GWL_STYLE) & ~WS_POPUP);

   SetWindowLong(hWnd, 
                 GWL_STYLE, 
                 GetWindowLong(hWnd, GWL_STYLE) | (WS_OVERLAPPED  | 
                                                   WS_CAPTION     | 
                                                   WS_SYSMENU     | 
                                                   WS_MINIMIZEBOX));

   if (SAL_get_preference(SAL_ALLOW_WINDOW_RESIZE))
      {
      SetWindowLong(hWnd, 
                    GWL_STYLE, 
                    GetWindowLong(hWnd, GWL_STYLE) | WS_THICKFRAME |
                                                     WS_MAXIMIZEBOX);
      }

   if (SAL_get_preference(SAL_MAXIMIZE_TO_FULLSCREEN))
      {
      SetWindowLong(hWnd, 
                    GWL_STYLE, 
                    GetWindowLong(hWnd, GWL_STYLE) | WS_MAXIMIZEBOX);
      }

   if (SAL_get_preference(SAL_ALWAYS_ON_TOP))
      {
      SetWindowLong(hWnd, 
                    GWL_EXSTYLE, 
                    GetWindowLong(hWnd, GWL_EXSTYLE) | WS_EX_TOPMOST);
      }
   else
      {
      SetWindowLong(hWnd, 
                    GWL_EXSTYLE, 
                    GetWindowLong(hWnd, GWL_EXSTYLE) & ~WS_EX_TOPMOST);
      }

   //
   // If area not already established, center window's client area on
   // desktop, and size it to correspond to the display size for optimum 
   // performance (no stretching needed)
   //

   if (area.w == -1)
      {
      area.w = display_size_X;
      area.h = display_size_Y;

      area.x = ((desktop_w - area.w ) / 2);
      area.y = ((desktop_h - area.h) / 2);
      }

   //
   // Calculate adjusted position of window
   //
   // Do not allow overall window size to exceed desktop size; keep 
   // dividing height and width by 2 until entire window fits
   //
   // If window is offscreen (or almost entirely offscreen), center it
   //

   do
      {
      retry = 0;

      window_rect.left   = area.x;
      window_rect.right  = area.x + area.w - 1;
      window_rect.top    = area.y;
      window_rect.bottom = area.y + area.h - 1;

      //
      // Don't adjust window rect to compensate for a menu -- SAL is
      // designed to treat menu bars as if they were part of the
      // client area, for refresh and window-sizing purposes
      //

      AdjustWindowRectEx(&window_rect,
                          GetWindowLong(hWnd, GWL_STYLE),
                          0, //(GetMenu(hWnd) != NULL),
                          GetWindowLong(hWnd, GWL_EXSTYLE));

      if ((window_rect.right - window_rect.left + 1) > desktop_w)
         {
         area.w >>= 1;
         area.x = ((desktop_w - area.w ) / 2);
         retry = 1;
         }

      if ((window_rect.bottom - window_rect.top + 1) > desktop_h)
         {
         area.h >>= 1;
         area.y = ((desktop_h - area.h) / 2);
         retry = 1;
         }

      if ((window_rect.left   >= (desktop_w-16)) ||
          (window_rect.top    >= (desktop_h-16)) ||
          (window_rect.right  <= 16)          ||
          (window_rect.bottom <= 16))
         {
         area.x = ((desktop_w - area.w ) / 2);
         area.y = ((desktop_h - area.h) / 2);
         retry = 1;
         }
      }
   while (retry);

   //
   // Save window and client areas for restoration if maximize button pressed
   //

   original_window_rect = window_rect;
   original_area        = area;

   //
   // Set window size and position
   //

   SetWindowPos(hWnd, 
                HWND_TOP, 
                window_rect.left,
                window_rect.top,
                window_rect.right  - window_rect.left + 1,
                window_rect.bottom - window_rect.top  + 1,
                SWP_NOCOPYBITS | SWP_NOZORDER);

   GetClientRect(hWnd, 
                &client_rect);

   SAL_info_printf("SAL: Window at (%d,%d), client size = (%d,%d)\n",
      window_rect.left,
      window_rect.top,
      client_rect.right,
      client_rect.bottom);

   //
   // Make window visible
   //

   ShowWindow(hWnd, SW_SHOWNORMAL);

   //
   // If mouse is constrained, limit its travel to the window area
   //

   if (constrain_state)    
      {
      constrain_request = 1;
      }

   --WPS_lock;
}

//****************************************************************************
//*                                                                          *
//*  Mouse/keyboard event management                                         *
//*                                                                          *
//****************************************************************************

void MOUSE_event(unsigned long wParam, unsigned long lParam)
{
}

void KEYDOWN_event(unsigned long wParam, unsigned long lParam)
{
}

void KEYUP_event(unsigned long wParam, unsigned long lParam)
{
}

void CHAR_event(unsigned long wParam, unsigned long lParam)
{
}

//****************************************************************************
//*                                                                          *
//*  Shut down CreateDIBSection() services                                   *
//*                                                                          *
//****************************************************************************

void DIB_shutdown(void)
{
   if (constrain_state)
      {
      ClipCursor(&unconstrained_rect);
      constrain_request = 0;
      }

   if (DIB_active && SAL_is_app_active())
      {
      SAL_wipe_surface(SAL_BACK_SURFACE, 0);
      SAL_flip_surface();
      }

   DIB_active = 0;

   if (hDIB != NULL)
      {
      DeleteObject(hDIB);
      hDIB = NULL;
      }

   if (hPalette != NULL)
      {
      DeleteObject(hPalette);
      hPalette = NULL;
      }
}

//****************************************************************************
//*                                                                          *
//*  Start up CreateDIBSection() services for windowed display               *
//*                                                                          *
//****************************************************************************

S32 DIB_startup(S32   display_size_X,//)
                S32   display_size_Y,
                S32   display_bpp)
{
   HDC hdc;

   //
   // Init DIB globals
   //

   hDIB        = NULL;
   lpDIBBuffer = NULL;
   hPalette    = NULL;

   pbmih->biSize          =  sizeof(*pbmih);
   pbmih->biWidth         =  display_size_X;
   pbmih->biHeight        = -display_size_Y;
   pbmih->biPlanes        =  1;
   pbmih->biBitCount      =  (U16) display_bpp;
   pbmih->biSizeImage     =  0;
   pbmih->biXPelsPerMeter =  0;
   pbmih->biYPelsPerMeter =  0;
   pbmih->biClrUsed       =  0;
   pbmih->biClrImportant  =  0;

   //
   // If DIB and desktop are both in high-color mode, set DIB to desktop
   // pixel format for maximum throughput
   // 
   // Otherwise, set DIB to 5-6-5 mode if 16BPP DIB requested, or 8-8-8 mode
   // if 24/32 BPP DIB requested
   //
   // Finally, if 8BPP DIB requested, create GDI palette object based on 
   // current logical palette
   //

   switch (display_bpp)
      {
      case 8:
   
         pbmih->biCompression = BI_RGB;

         hPalette = CreatePalette(pLogPal);
         palette_change_request = TRUE;
         break;

      case 15:
      case 16:

         pbmih->biCompression = BI_BITFIELDS;

         if ((desktop_bpp == 15) || (desktop_bpp == 16))
            {
            DIB_R_bitmask = *(U32 *) (&(pbmi->bmiColors[0])) = desktop_R_bitmask;
            DIB_G_bitmask = *(U32 *) (&(pbmi->bmiColors[1])) = desktop_G_bitmask;
            DIB_B_bitmask = *(U32 *) (&(pbmi->bmiColors[2])) = desktop_B_bitmask;
            }
         else
            {
            DIB_R_bitmask = *(U32 *) (&(pbmi->bmiColors[0])) = 0x00f800;
            DIB_G_bitmask = *(U32 *) (&(pbmi->bmiColors[1])) = 0x0007e0;
            DIB_B_bitmask = *(U32 *) (&(pbmi->bmiColors[2])) = 0x00001f;
            }
         break;

      case 24:
      case 32:

         pbmih->biCompression = BI_BITFIELDS;

         DIB_R_bitmask = *(U32 *) (&(pbmi->bmiColors[0])) = 0xff0000;
         DIB_G_bitmask = *(U32 *) (&(pbmi->bmiColors[1])) = 0x00ff00;
         DIB_B_bitmask = *(U32 *) (&(pbmi->bmiColors[2])) = 0x0000ff;
         break;
      }

   //
   // Allocate the DIB section ("back buffer")
   //

   hdc = GetDC(hWnd);

   hDIB = CreateDIBSection(hdc,             // Device context
                           pbmi,            // BITMAPINFO structure
                           DIB_RGB_COLORS,  // Color data type
                (void **) &lpDIBBuffer,     // Address of image map pointer
                           NULL,            // File
                           0);              // Bitmap file offset

   ReleaseDC(hWnd, hdc);

   if (hDIB == NULL)
      {
      SAL_alert_box(NULL,"CreateDIBSection() failed\n");
      DIB_shutdown();

      return FALSE;
      }

   //
   // Set global flag to indicate CreateDIBSection() is active
   // 

   DIB_active = 1;

   return TRUE;
}

//****************************************************************************
//*                                                                          *
//*  Copy current contents of DIB buffer to output window                    *
//*                                                                          *
//****************************************************************************

void DIB_refresh_surface(void)
{
   HDC hdc;

   hdc = GetDC(hWnd);

   //
   // Select palette if desktop running in 8-bit mode
   //
   // If palette has changed, realize it
   //

   if (desktop_bpp == 8)
      {
      SelectPalette(hdc, 
                    hPalette, 
                    0);

      if (palette_change_request)
         {
         palette_change_request = 0;
         RealizePalette(hdc);
         }
      }

   //
   // Disable Boolean operations during stretching
   //

   SetStretchBltMode(hdc, COLORONCOLOR);

   //
   // Compensate for menu
   //

   S32 sy = 0;

   if (GetMenu(hWnd) != NULL)
      {
      sy = -GetSystemMetrics(SM_CYMENU);
      }

   //
   // Stretch bitmap to conform to the size of the output window
   //

   StretchDIBits(hdc,            // Destination DC
                 0,              // Destination X
                 0,              // Destination Y
                 area.w,         // Destination (client area) width
                 area.h,         // Destination (client area) height 
                 0,              // Source X
                 sy,             // Source Y
                 current_size_X, // Source (back buffer) width
                 current_size_Y, // Source (back buffer) height
                 lpDIBBuffer,    // Pointer to source (back buffer)
                 pbmi,           // Bitmap info for back buffer
                 DIB_RGB_COLORS, // Bitmap contains RGB values
                 SRCCOPY);       // Do normal copy with stretching

   ReleaseDC(hWnd, hdc);
}

//****************************************************************************
//*                                                                          *
//*  Copy partial contents of DDraw back buffer to output window             *
//*                                                                          *
//****************************************************************************

void DIB_refresh_region(SAL_REGION *region)
{
   HDC hdc;

   hdc = GetDC(hWnd);

   //
   // Select palette if desktop running in 8-bit mode
   //
   // If palette has changed, realize it
   //

   if (desktop_bpp == 8)
      {
      SelectPalette(hdc, 
                    hPalette, 
                    0);

      if (palette_change_request)
         {
         palette_change_request = 0;
         RealizePalette(hdc);
         }
      }

   //
   // Disable Boolean operations during stretching
   //

   SetStretchBltMode(hdc, COLORONCOLOR);

   //
   // Compensate for menu
   //

   S32 sy = 0;

   if (GetMenu(hWnd) != NULL)
      {
      sy = -GetSystemMetrics(SM_CYMENU);
      }

   //
   // Get coordinates of region to blit
   //

   S32 l = region->x0;
   S32 t = region->y0;
   S32 w = region->x1 - region->x0 + 1;
   S32 h = region->y1 - region->y0 + 1;

   S32 sl = l;
   S32 st = current_size_Y - (region->y1 + 1) + sy;

   //
   // Stretch bitmap to conform to the size of the output window
   //

   StretchDIBits(hdc,            // Destination DC
                 l,              // Destination X
                 t,              // Destination Y
                 w,              // Destination (client area) width
                 h,              // Destination (client area) height 
                 sl,             // Source X
                 st,             // Source Y
                 w,              // Source (back buffer) width
                 h,              // Source (back buffer) height
                 lpDIBBuffer,    // Pointer to source (back buffer)
                 pbmi,           // Bitmap info for back buffer
                 DIB_RGB_COLORS, // Bitmap contains RGB values
                 SRCCOPY);       // Do normal copy with stretching

   ReleaseDC(hWnd, hdc);
}

//****************************************************************************
//*                                                                          *
//*  Wipe CreateDIBSection() surface                                         *
//*                                                                          *
//****************************************************************************

void DIB_wipe_surface           (S32        surface,//)
                                 U32        color)
{
   void *ptr;
   S32   w,h,bpp;

   if (surface == SAL_FRONT_SURFACE)
      {
      return;
      }
   if (surface == SAL_BACK_SURFACE)
      {
      ptr = lpDIBBuffer;
      w   = current_size_X;
      h   = current_size_Y;
      bpp = current_bpp;
      }
   else
      {
      SURFDESC *s = (SURFDESC *) surface;

      if (s->source != S_MEM)
         {
         return;
         }

      ptr = s->object.ptr;
      w   = s->width;
      h   = s->height;
      bpp = s->bpp;
      }

   if (bpp == 16)
      {
      U16 *p = (U16 *) ptr;

      for (S32 y=0; y < h; y++)
         {
         for (S32 x=0; x < w; x++)
            {
            *p++ = (U16) color;
            }
         }
      }
   else if (bpp == 32)
      {
      U32 *p = (U32 *) ptr;

      for (S32 y=0; y < h; y++)
         {
         for (S32 x=0; x < w; x++)
            {
            *p++ = color;
            }
         }
      }
   else if (bpp == 8)
      {
      memset(ptr,
             color,
             w * h * (bpp / 8));
      }

}

//****************************************************************************
//*                                                                          *
//*  Return pointer to CreateDIBSection() surface                            *
//*                                                                          *
//****************************************************************************

void DIB_lock_surface         (S32        surface,//)
                               U8       **ptr,
                               S32       *pitch)
{
   if (surface == SAL_FRONT_SURFACE)
      {
      return;
      }

   if (surface == SAL_BACK_SURFACE)
      {
      if (ptr != NULL)
         {
         *ptr = lpDIBBuffer;
         }

      if (pitch != NULL)
         {
         *pitch = current_size_X * (current_bpp / 8);
         }
      }
   else
      {
      SURFDESC *s = (SURFDESC *) surface;

      if (s->source != S_MEM)
         {
         return;
         }

      if (ptr != NULL)
         {
         *ptr = (U8 *) s->object.ptr;
         }

      if (pitch != NULL)
         {
         *pitch = s->width * (s->bpp / 8);
         }
      }
}

//****************************************************************************
//*                                                                          *
//*  Release pointer to CreateDIBSection() surface                           *
//*                                                                          *
//****************************************************************************

void DIB_unlock_surface        (S32        surface,//)
                                S32        perform_flip)
{
   if (surface != SAL_BACK_SURFACE)
      {
      return;
      }

   if (perform_flip)
      {
      SAL_flip_surface();
      }
}

#if DDRAW_DYNAMIC

//****************************************************************************
//*                                                                          *
//*  Explicitly load / unload DDRAW.DLL                                      *
//*                                                                          *
//****************************************************************************

static HRESULT (WINAPI *_DirectDrawCreate) (GUID         FAR *lpGUID, 
                                            LPDIRECTDRAW FAR *lplpDD, 
                                            IUnknown     FAR *pUnkOuter);

static void UnloadDDrawLibrary (HINSTANCE hDDLibrary)
{
   if (hDDLibrary)
      {
      _DirectDrawCreate = NULL;
      FreeLibrary(hDDLibrary);
      }
}

static BOOL32 LoadDDrawLibrary (HINSTANCE *hDDLibrary)
{
   HMODULE hModule;
   C8      szLibName[]= "ddraw.dll";
   
   if ((*hDDLibrary = LoadLibrary(szLibName)) != NULL)
      {
      if ((hModule = GetModuleHandle(szLibName)) != NULL)
         {
         _DirectDrawCreate = (long (__stdcall *)(struct _GUID *,struct IDirectDraw ** ,struct IUnknown *))
            GetProcAddress(hModule, "DirectDrawCreate");

         return (_DirectDrawCreate != NULL);
         }
      }

   return FALSE;
}

#endif

//****************************************************************************
//*                                                                          *
//*  Default DirectDraw object creation handler -- may be replaced by user-  *
//*  specified callback routine (e.g., for Direct3D support)                 *
//*                                                                          *
//****************************************************************************

HRESULT WINAPI DDraw_default_startup_handler(S32            display_size_X, //)
                                             S32            display_size_Y,
                                             S32            display_bpp,
                                             LPPALETTEENTRY initial_palette,
                                             S32            display_mode,
                                             SAL_DDRAWINFO *dest)
{
   DDSCAPS       ddscaps;
   HRESULT       result; 
   DDSURFACEDESC ddsd;

   //
   // Init DirectDraw objects to NULL
   //

   dest->lpDD         = NULL;
   dest->lpDDSPrimary = NULL;
   dest->lpDDSBack    = NULL;
   dest->lpDDPal      = NULL;
   dest->lpDDClipper  = NULL;

   //
   // Create DirectDraw object
   //

   LPDIRECTDRAW DD;

#if DDRAW_DYNAMIC
   if (DDraw_lib_handle == NULL)
      {
      if (LoadDDrawLibrary(&DDraw_lib_handle) == FALSE)
         {
         result = -1;
         }
      }

   if (_DirectDrawCreate)   
      {
      result = _DirectDrawCreate(NULL, 
                                &DD,
                                 NULL);
      }
#else
   result = DirectDrawCreate(NULL, 
                            &DD,
                             NULL);
#endif
   
   if (result != DD_OK)
      {
      SAL_alert_box(NULL,"DirectDrawCreate() failed, code %X\n",result);
      return result;
      }

   //
   // Get IDirectDraw2 interface
   // 

   if ((result = DD->QueryInterface(IID_IDirectDraw2, (void **) &dest->lpDD)) != DD_OK)
      {
      SAL_alert_box(NULL,"This application requires DirectX 5 or later\n");
      DD->Release();
      DD = NULL;
      return result;
      }

   DD->Release();
   DD = NULL;

   //
   // Initialize for fullscreen or windowed mode
   //

   if (display_mode != SAL_FULLSCREEN)
      {
      //
      // Set normal mode
      //

      result = dest->lpDD->SetCooperativeLevel(hWnd, DDSCL_NORMAL);

      if (result != DD_OK)
         {
         SAL_alert_box(NULL,"lpDD->SetCooperativeLevel() failed, code %X\n",result);
         return result;
         }
      }
   else
      {
      //
      // Set exclusive mode
      //

      result = dest->lpDD->SetCooperativeLevel(hWnd, 
                                               DDSCL_EXCLUSIVE  |
                                               DDSCL_FULLSCREEN |
                                               DDSCL_ALLOWREBOOT);

      if (result != DD_OK)
         {
         SAL_alert_box(NULL,"lpDD->SetCooperativeLevel() failed, code %X\n",result);
         return result;
         }

      //
      // Set up requested fullscreen display mode
      //
      // If the fullscreen mode being set is the same as the Windows desktop
      // mode, then specify the desktop's refresh rate as well to try to
      // avoid flicker, unwanted raster resizing, and unnecessary monitor 
      // resyncs
      // 
      // Note that under Win9X, dwRefreshRate MUST be 0.  Any other 
      // value -- even the current desktop rate -- will yield DDERR_INVALIDMODE 
      // (LSB 0x78).  This reflects the behavior of EnumDisplaySettings 
      // (i.e., its refusal to return anything but 0 for ENUM_CURRENT_SETTINGS 
      // under Win9X).  So it's theoretically safe to pass desktop_refresh 
      // to SetDisplayMode() under Win9X without bothering to check the OS
      // version.  To date, all machines tested have preserved the desktop
      // refresh rate when setting fullscreen mode at desktop resolution with
      // dwRefreshRate=0.
      //
      // Under Win2K, setting dwRefreshRate to 0 does not guarantee preservation
      // of the desktop's refresh rate (works on my K7/GF3/LCD, fails on MikeS's
      // K7/GF2/CRT), so we again pass the value obtained from 
      // EnumDisplaySettings(ENUM_CURRENT_SETTINGS).
      //
      // TODO: Test with CRT monitors under Win95, WinMe and WinXP!
      //

      S32 refresh_rate = 0;

      if ((display_size_X == desktop_w) &&
          (display_size_Y == desktop_h) &&
          (display_bpp    == desktop_bpp))
         {
         refresh_rate = desktop_refresh;

         SAL_info_printf("SAL: Calling lpDD->SetDisplayMode(%d,%d,%d,%d)\n",
            display_size_X,
            display_size_Y,
            display_bpp,
            desktop_refresh);
         }

      result = dest->lpDD->SetDisplayMode(display_size_X, 
                                          display_size_Y,
                                          display_bpp,
                                          refresh_rate,
                                          0);
      if (result != DD_OK)
         {
         SAL_alert_box(NULL,"lpDD->SetDisplayMode(%d,%d,%d) failed, code %X\n",
            display_size_X,
            display_size_Y,
            display_bpp,
            result);

         return result;
         }
      }

   //
   // Create the primary surface with up to SAL_MAX_VIDEO_PAGES-1 back buffers
   //
   // In fullscreen mode, the back buffers are created as surfaces 
   // attached to the primary buffer.  In windowed and desktop mode, 
   // a single back buffer is separately allocated from video memory.
   //

   LPDIRECTDRAWSURFACE DDSPrimary;
   LPDIRECTDRAWSURFACE DDSBack;

   S32 back_buffers = SAL_get_preference(SAL_MAX_VIDEO_PAGES) - 1;

   if (display_mode != SAL_FULLSCREEN)
      {
      back_buffers = 0;
      }

   while (1)
      {
      SAL_info_printf("SAL: Request surface with %d attached back buffer(s)\n",
         back_buffers);

      ddsd.dwSize          = sizeof(ddsd);
      ddsd.ddsCaps.dwCaps  = DDSCAPS_PRIMARYSURFACE | DDSCAPS_VIDEOMEMORY;
      ddsd.dwFlags         = DDSD_CAPS;

      if (back_buffers)
         {
         ddsd.dwFlags          |= DDSD_BACKBUFFERCOUNT;
         ddsd.ddsCaps.dwCaps   |= DDSCAPS_COMPLEX | DDSCAPS_FLIP;
         ddsd.dwBackBufferCount = back_buffers;
         }

      result = dest->lpDD->CreateSurface(&ddsd, 
                                         &DDSPrimary, 
                                          NULL);

      if (result == DD_OK)
         {
         break;
         }

      if (!back_buffers)
         {
         break;
         }

      back_buffers--;
      }

   if (result != DD_OK)
      {
      SAL_alert_box(NULL,"lpDD->CreateSurface() failed, code %X\n",result);
      return result;
      }
   else
      {
      SAL_info_printf("SAL: Primary surface created");

      if (back_buffers)
         {
         SAL_info_printf(" with %d back buffer(s)",back_buffers);
         }

      SAL_info_printf("\n");
      }

   if ((result = DDSPrimary->QueryInterface(IID_IDirectDrawSurface3, (void **) &dest->lpDDSPrimary)) != DD_OK)
      {
      SAL_alert_box(NULL,"This application requires DirectX 5 or later\n");
      DDSPrimary->Release();
      DDSPrimary = NULL;
      return result;
      }

   DDSPrimary->Release();
   DDSPrimary = NULL;

   //
   // Get pointer to back buffer surface
   //
   // If we have a back buffer, get it as an attached surface -- otherwise,
   // we must allocate a new memory surface to serve as the "back buffer"
   //

   if (back_buffers)
      {
      ddscaps.dwCaps = DDSCAPS_BACKBUFFER;
      result         = dest->lpDDSPrimary->GetAttachedSurface(&ddscaps, 
                                                              &dest->lpDDSBack);
      if (result != DD_OK)
         {
         SAL_alert_box(NULL,"lpDD->GetAttachedSurface() failed, code %X\n",result);
         return result;
         }
      }
   else
      {
      //
      // Allocate single back buffer surface from video memory (if 
      // MAX_VIDEO_PAGES > 1) or system memory (if MAX_VIDEO_PAGES = 1 or 
      // the back buffer isn't attached)
      //
      // TODO: this means it always comes from system memory...
      //

      DDSURFACEDESC ddsd;
                                                          
      memset(&ddsd, 0, sizeof(ddsd));

      ddsd.dwSize = sizeof(ddsd);
      ddsd.dwFlags = DDSD_CAPS | DDSD_HEIGHT | DDSD_WIDTH;

      ddsd.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN;

      if ((SAL_get_preference(SAL_MAX_VIDEO_PAGES) == 1) || 
         ((SAL_get_preference(SAL_MAX_VIDEO_PAGES) > 1) && (back_buffers == 0)))
         {
         ddsd.ddsCaps.dwCaps |= DDSCAPS_SYSTEMMEMORY;
         }

      ddsd.dwWidth  = display_size_X;
      ddsd.dwHeight = display_size_Y;

      result = dest->lpDD->CreateSurface(&ddsd, 
                                         &DDSBack,
                                          NULL);
      if (result != DD_OK)
         {
         SAL_alert_box(NULL,"lpDD->CreateSurface() failed to create back buffer, code %X\n",result);
         return result;
         }

      if ((result = DDSBack->QueryInterface(IID_IDirectDrawSurface3, (void **) &dest->lpDDSBack)) != DD_OK)
         {
         SAL_alert_box(NULL,"This application requires DirectX 5 or later\n");
         DDSBack->Release();
         DDSBack = NULL;
         return result;
         }

      DDSBack->Release();
      DDSBack = NULL;
      }

   //
   // If running in windowed mode, or if SAL_USE_DDRAW_CLIPPER=YES,
   // create a DirectDrawClipper object to associate the front buffer with 
   // the app window
   //

   if ((display_mode == SAL_WINDOW) || 
       (SAL_get_preference(SAL_USE_DDRAW_CLIPPER)))
      {
      result = dest->lpDD->CreateClipper(0, &dest->lpDDClipper, NULL);

      if (result != DD_OK)
         {
         SAL_alert_box(NULL,"lpDD->CreateClipper() failed, code %X\n",result);
         return FALSE;
         }

      result = dest->lpDDClipper->SetHWnd(0, hWnd);

      if (result != DD_OK)
         {
         SAL_alert_box(NULL,"Clipper->SetHWnd() failed, code %X\n",result);
         return FALSE;
         }

      result = dest->lpDDSPrimary->SetClipper(dest->lpDDClipper);

      if (result != DD_OK)
         {
         SAL_alert_box(NULL,"Surface->SetClipper failed, code %X\n",result);
         return FALSE;
         }
      }

   //
   // If 8 BPP mode in use, create DirectDraw palette object
   //

   if (display_bpp == 8)
      {
      result = dest->lpDD->CreatePalette(DDPCAPS_8BIT |
                                         DDPCAPS_INITIALIZE |
                                         DDPCAPS_ALLOW256,
                                         initial_palette,
                                        &dest->lpDDPal, 
                                         NULL);

      if (result != DD_OK)
         {
         SAL_alert_box(NULL,"lpDD->CreatePalette() failed, code %X\n",result);
         return result;
         }

      //
      // Associate default palette object with primary buffer
      //

      dest->lpDDSPrimary->SetPalette(dest->lpDDPal);
      }

   //
   // Return success
   //

   return DD_OK;
}

//****************************************************************************
//*                                                                          *
//*  Default DirectDraw object destruction handler -- may be replaced by     *
//*  user-specified callback routine (e.g., for Direct3D support)            *
//*                                                                          *
//****************************************************************************

void WINAPI DDraw_default_shutdown_handler(SAL_DDRAWINFO *dest)
{
   //
   // Free all DirectDraw objects
   //

   if (dest->lpDD != NULL)
      {
      if (dest->lpDDClipper != NULL)
         {
         dest->lpDDClipper->Release();
         dest->lpDDClipper = NULL;
         }

      if (dest->lpDDPal != NULL)
         {
         dest->lpDDPal->Release();
         dest->lpDDPal = NULL;
         }

      if (dest->lpDDSBack != NULL)
         {
         dest->lpDDSBack->Release();
         dest->lpDDSBack = NULL;
         }

      if (dest->lpDDSPrimary != NULL)
         {
         dest->lpDDSPrimary->Release();
         dest->lpDDSPrimary = NULL;
         }

      dest->lpDD->SetCooperativeLevel(hWnd, DDSCL_NORMAL);
      dest->lpDD->RestoreDisplayMode();
      dest->lpDD->Release();
      dest->lpDD = NULL;
      }

#if DDRAW_DYNAMIC
   UnloadDDrawLibrary(DDraw_lib_handle);
   DDraw_lib_handle = NULL;
#endif
}

//****************************************************************************
//*                                                                          *
//*  Shut down DirectDraw services                                           *
//*                                                                          *
//****************************************************************************

void DDraw_shutdown(void)
{
   //
   // Wipe all surface buffers to black if active
   //

   if (DDraw_active && SAL_is_app_active())
      {
      for (S32 i=0; i < SAL_display_page_count(); i++)
         {
         SAL_wipe_surface(SAL_BACK_SURFACE, 0);
         SAL_flip_surface();
         }
      }

   //
   // Clear global DirectDraw status flag
   //

   DDraw_active = 0;

   //
   // Call DirectDraw shutdown routine
   // 

   lpDDShutdown(&DDraw);

   //
   // Needed to permit proper operation of subsequent SetWindowLong()
   // calls to change WS_EX_TOPMOST attribute in GWL_EXSTYLE
   //

   if (SAL_get_preference(SAL_ALWAYS_ON_TOP))
      {
      SetWindowPos(hWnd, 
                     HWND_TOPMOST, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOCOPYBITS | SWP_NOREDRAW);
      }
   else
      {
      SetWindowPos(hWnd, 
                     HWND_NOTOPMOST, 0, 0, 0, 0,
                     SWP_NOMOVE | SWP_NOSIZE | SWP_NOCOPYBITS | SWP_NOREDRAW);
      }
}

//****************************************************************************
//*                                                                          *
//*  Start up DirectDraw services for windowed or fullscreen display         *
//*                                                                          *
//****************************************************************************

S32 DDraw_startup(S32   display_size_X,//)
                  S32   display_size_Y,
                  S32   display_bpp,
                  S32   display_mode)
{
   //
   // Call registered startup routine to initialize DirectDraw
   //
   // Note that the act of setting exclusive mode also sets WS_EX_TOPMOST 
   // extended style, which remains set even after DirectDraw is released
   //
   // A SetWindowPos() call will be needed to release this attribute, 
   // as SetWindowLong() will not remove the WS_EX_TOPMOST attribute 
   // otherwise
   //

   HRESULT result = lpDDStartup(display_size_X,
                                display_size_Y,
                                display_bpp,
                                pLogPal->palPalEntry,
                                display_mode,
                               &DDraw);

   if (result != DD_OK)
      {
      SAL_alert_box(NULL,"DirectDraw could not be initialized!  Error code %X\n",result);
      DDraw_shutdown();
      return FALSE;
      }

   //
   // Try to avoid taking Win16 lock when locking surface
   //

   lock_flags = DDLOCK_NOSYSLOCK;

   //
   // Set global flag to indicate DirectDraw is active
   // 

   DDraw_active = 1;

   return TRUE;
}

//****************************************************************************
//*                                                                          *
//*  Copy current contents of DDraw back buffer to output window             *
//*                                                                          *
//****************************************************************************

HRESULT DDraw_refresh_surface(void)
{
   HRESULT result;

   LPDIRECTDRAWCLIPPER clipper;

   if (((current_display_mode == SAL_WINDOW)  || 
         current_display_mode == SAL_DESKTOP) || 
       (DDraw.lpDDSPrimary->GetClipper(&clipper) == DD_OK))
      {
      //
      // In windowed mode, use the Blt() function for proper
      // clipping (e.g., if the window is moved partially offscreen)
      //
      // We must also do this if the application has installed a clipper
      // object
      // 
      // Destination rectangle must be explicitly specified -- note 
      // extra pixel/column in rectangle for Blt()'s benefit
      // 

      RECT dest_rect = *client_screen_rect();

      ++dest_rect.right;
      ++dest_rect.bottom;

      result = DDraw.lpDDSPrimary->Blt(&dest_rect,
                                       DDraw.lpDDSBack,
                                       NULL,
                                       DDBLT_WAIT,
                                       NULL);
      }
   else
      {
      //
      // In fullscreen mode, use the BltFast() function for maximum
      // speed on unclipped surface
      // 

      result = DDraw.lpDDSPrimary->BltFast(0, 
                                           0, 
                                           DDraw.lpDDSBack, 
                                           NULL, 
                                           (DDBLTFAST_NOCOLORKEY | 
                                           DDBLTFAST_WAIT));
      }

   return result;
}

//****************************************************************************
//*                                                                          *
//*  Copy partial contents of DDraw back buffer to output window             *
//*                                                                          *
//****************************************************************************

HRESULT DDraw_refresh_region(SAL_REGION *region)
{
   //
   // Destination (front buffer) rectangle is given in screen coordinates
   // Source rectangle is given in 0,0-relative surface coordinates
   //

   RECT dest_rect = *client_screen_rect();
   RECT src_rect;

   src_rect.left   = region->x0;
   src_rect.right  = region->x1 + 1;
   src_rect.top    = region->y0;
   src_rect.bottom = region->y1 + 1;

   S32 cx = dest_rect.left;
   S32 cy = dest_rect.top;

   dest_rect.left   = cx + region->x0;
   dest_rect.right  = cx + region->x1 + 1;
   dest_rect.top    = cy + region->y0;
   dest_rect.bottom = cy + region->y1 + 1;

   return DDraw.lpDDSPrimary->Blt(&dest_rect,
                                   DDraw.lpDDSBack,
                                  &src_rect,
                                   DDBLT_WAIT,
                                   NULL);
}        

//****************************************************************************
//*                                                                          *
//*  Flip DirectDraw surface                                                 *
//*                                                                          *
//****************************************************************************

void DDraw_flip_surface(void)
{
   HRESULT result;

   //
   // If surface has an attached clipper, simulate the flip by blitting
   //

   LPDIRECTDRAWCLIPPER clipper;

   if (DDraw.lpDDSPrimary->GetClipper(&clipper) == DD_OK)
      {
      SAL_blit_surface();
      return;
      }

   //
   // If surface is not flippable, simulate the flip by blitting
   //

   DDSCAPS caps;

   DDraw.lpDDSPrimary->GetCaps(&caps);

   if (!(caps.dwCaps & DDSCAPS_FLIP))
      {
      SAL_blit_surface();
      return;
      }

   //
   // Otherwise, perform the flip
   //

   while (1)
      {
      if (!SAL_is_app_active() && SAL_get_preference(SAL_SLEEP_WHILE_INACTIVE))
         {
         Sleep(10);
         }
      else
         {
         result = DDraw.lpDDSPrimary->Flip(NULL, 0);

         if (result == DD_OK)
            {
            break;
            }

         if (result == DDERR_SURFACELOST) 
            {
            DDraw.lpDDSPrimary->Restore();
            Sleep(100);
            }
         }

      serve_queue();
      } 
}

//****************************************************************************
//*                                                                          *
//*  Wipe DirectDraw surface                                                 *
//*                                                                          *
//****************************************************************************

void DDraw_wipe_surface           (S32        surface,//)
                                   U32        color)
{
   DDBLTFX             ddbltfx;
   HRESULT             result;
   LPDIRECTDRAWSURFACE3 lpdds;

   if ((surface == SAL_FRONT_SURFACE) && (!SAL_get_preference(SAL_ALLOW_FRONT_LOCK)))
      {
      surface = SAL_BACK_SURFACE;
      }

   if (surface == SAL_FRONT_SURFACE)
      {
      lpdds = DDraw.lpDDSPrimary;
      }
   else if (surface == SAL_BACK_SURFACE)
      {
      lpdds = DDraw.lpDDSBack;
      }
   else if (((SURFDESC *) surface)->source == S_DDRAW)
      {
      lpdds = ((SURFDESC *) surface)->object.lpDDS;
      }
   else
      {
      return;
      }

   ddbltfx.dwSize      = sizeof(ddbltfx);
   ddbltfx.dwFillColor = color;

   while (1)
      {
      if (!SAL_is_app_active() && SAL_get_preference(SAL_SLEEP_WHILE_INACTIVE))
         {
         Sleep(10);
         }
      else
         {
         result = lpdds->Blt(NULL, 
                             NULL,
                             NULL, 
                             DDBLT_COLORFILL,
                             &ddbltfx);

         if (result == DD_OK)
            {
            break;
            }

         if (result == DDERR_SURFACELOST) 
            {
            DDraw.lpDDSPrimary->Restore();
            Sleep(100);
            }
         }

      serve_queue();
      } 
}

//****************************************************************************
//*                                                                          *
//*  Return pointer to DirectDraw surface                                    *
//*                                                                          *
//****************************************************************************

void DDraw_lock_surface         (S32        surface, //)
                                 U8       **ptr,
                                 S32       *pitch)
{
   LPDIRECTDRAWSURFACE3 lpdds;
   HRESULT              result;
   DDSURFACEDESC        ddsd;

   ddsd.dwSize = sizeof(ddsd);

   if ((surface == SAL_FRONT_SURFACE) && (!SAL_get_preference(SAL_ALLOW_FRONT_LOCK)))
      {
      surface = SAL_BACK_SURFACE;
      }

   if (surface == SAL_FRONT_SURFACE)
      {
      lpdds = DDraw.lpDDSPrimary;
      }
   else if (surface == SAL_BACK_SURFACE)
      {
      lpdds = DDraw.lpDDSBack;
      }
   else if (((SURFDESC *) surface)->source == S_DDRAW)
      {
      lpdds = ((SURFDESC *) surface)->object.lpDDS;
      }
   else
      {
      return;
      }

   while (1)
      {
      if (!SAL_is_app_active() && SAL_get_preference(SAL_SLEEP_WHILE_INACTIVE))
         {
         Sleep(10);
         }
      else
         {
         result = lpdds->Lock(NULL, &ddsd, lock_flags, NULL);

         if ((result == DDERR_INVALIDPARAMS) && 
             (lock_flags & DDLOCK_NOSYSLOCK))
            {
            SAL_info_printf("SAL: DDLOCK_NOSYSLOCK not supported?\n");
            lock_flags &= ~DDLOCK_NOSYSLOCK;
            }

         if (result == DD_OK)
            {
            break;
            }

         if (result == DDERR_SURFACELOST) 
            {
            DDraw.lpDDSPrimary->Restore();
            Sleep(100);
            }
         }

      serve_queue();
      } 

   if (ptr != NULL)   
      {
      *ptr = (unsigned char *) ddsd.lpSurface;
      }

   if (pitch != NULL) 
      {
      if (ddsd.dwFlags & DDSD_PITCH)
         {
         *pitch = (S32) ddsd.lPitch;
         }
      else
         {
         *pitch = current_size_X * (current_bpp / 8);
         }
      }
}

//****************************************************************************
//*                                                                          *
//*  Release lock on DirectDraw surface                                      *
//*                                                                          *
//****************************************************************************

void DDraw_unlock_surface        (S32        surface,//)
                                  S32        perform_flip)
{
   LPDIRECTDRAWSURFACE3 lpdds;
   HRESULT              result;

   if ((surface == SAL_FRONT_SURFACE) && (!SAL_get_preference(SAL_ALLOW_FRONT_LOCK)))
      {
      surface = SAL_BACK_SURFACE;
      }

   if (surface == SAL_FRONT_SURFACE)
      {
      lpdds = DDraw.lpDDSPrimary;
      }
   else if (surface == SAL_BACK_SURFACE)
      {
      lpdds = DDraw.lpDDSBack;
      }
   else if (((SURFDESC *) surface)->source == S_DDRAW)
      {
      lpdds = ((SURFDESC *) surface)->object.lpDDS;
      }
   else
      {
      return;
      }

   while (1)
      {
      if (!SAL_is_app_active() && SAL_get_preference(SAL_SLEEP_WHILE_INACTIVE))
         {
         Sleep(10);
         }
      else
         {
         result = lpdds->Unlock(NULL);

         if ((result == DD_OK) || (result == DDERR_NOTLOCKED))
            {
            break;
            }

         if (result == DDERR_SURFACELOST) 
            {
            DDraw.lpDDSPrimary->Restore();
            Sleep(100);
            }
         }

      serve_queue();
      }

   if (perform_flip)
      {
      SAL_flip_surface();
      }
}

//****************************************************************************
//*                                                                          *
//* Set specified display mode                                               *
//*                                                                          *
//****************************************************************************

S32  set_display_mode        (S32   display_size_X,//)
                              S32   display_size_Y,
                              S32   display_bpp,
                              S32   display_mode,
                              S32   allow_mode_switch,
                              S32   changing_existing_mode)
{
   S32 result;

   //
   // Shut down current video mode handler
   //

   if (DDraw_active)
      {
      DDraw_shutdown();
      }

   if (DIB_active)
      {
      DIB_shutdown();
      }

   //
   // Get current Windows desktop display format (and masks, in high-color modes)
   //

   get_desktop_format(&desktop_R_bitmask,
                      &desktop_G_bitmask,
                      &desktop_B_bitmask,
                      &desktop_w,
                      &desktop_h,
                      &desktop_bpp,
                      &desktop_refresh);

   //
   // Hide or show mouse cursor, as appropriate
   //

   if (show_count < 1)
      {
      //
      // Hide mouse cursor if it's currently visible
      //

      if (cursor_state)
         {
         cursor_state = 0;
         ShowCursor(0);
         }
      }
   else
      {
      //
      // Show mouse cursor if it's currently hidden
      //

      if (!cursor_state)
         {
         cursor_state = 1;
         ShowCursor(1);
         }
      }

   //
   // Start up new video mode
   //

   if (display_mode == SAL_FULLSCREEN)
      {
      //
      // SAL_FULLSCREEN: Set up fullscreen video mode using DirectDraw
      //

      set_fullscreen_mode();

      SAL_info_printf("SAL: Setting fullscreen mode using DirectDraw\n");

      result = DDraw_startup(display_size_X,
                             display_size_Y,
                             display_bpp,
                             SAL_FULLSCREEN);
      }
   else if (display_mode == SAL_DESKTOP)
      {
      //
      // SAL_DESKTOP: Set up fullscreen desktop window using DirectDraw
      // or CreateDIBSection();

      set_desktop_mode(changing_existing_mode);

      SAL_info_printf("SAL: Setting desktop mode using ");

      display_size_X = desktop_w;
      display_size_Y = desktop_h;
      display_bpp    = desktop_bpp;

      if (SAL_get_preference(SAL_USE_DDRAW_IN_DESKTOP))
         {
         SAL_info_printf("DirectDraw\n");

         result = DDraw_startup(display_size_X,
                                display_size_Y,
                                display_bpp,
                                SAL_DESKTOP);
         }
      else
         {
         SAL_info_printf("CreateDIBSection()\n");

         result = DIB_startup(display_size_X,
                              display_size_Y,
                              display_bpp);
         }
      }
   else if (display_mode == SAL_WINDOW)
      {
      //
      // SAL_WINDOW: Set up window using CreateDIBSection(), unless we
      // explicitly specify we want to use DirectDraw for windowed mode
      // (must be set via preference)
      //

      set_windowed_mode(display_size_X, display_size_Y);

      SAL_info_printf("SAL: Setting window mode using ");

      //
      // Ensure DirectDraw isn't used at a bit depth which does not match
      // the primary (desktop) surface
      //

      if (SAL_get_preference(SAL_USE_DDRAW_IN_WINDOW) 
          &&
         (display_bpp == desktop_bpp))
         {
         SAL_info_printf("DirectDraw\n");

         result = DDraw_startup(display_size_X,
                                display_size_Y,
                                display_bpp,
                                SAL_WINDOW);

         }
      else
         {
         SAL_info_printf("CreateDIBSection()\n");

         result = DIB_startup(display_size_X,
                              display_size_Y,
                              display_bpp);
         }
      }
   else if (display_mode == SAL_TRY_FULLSCREEN)
      {
      //
      // SAL_TRY_FULLSCREEN: Use full-screen mode if possible/available, 
      //                     otherwise fall back automatically to windowed
      //                     mode
      //

      if (set_display_mode(display_size_X,
                           display_size_Y,
                           display_bpp,
                           SAL_FULLSCREEN,
                           allow_mode_switch,
                           changing_existing_mode))
         {
         return TRUE;
         }

      if (set_display_mode(display_size_X,
                           display_size_Y,
                           display_bpp,
                           SAL_WINDOW,
                           allow_mode_switch,
                           changing_existing_mode))
         {
         return TRUE;
         }
      }
   else
      {
      //
      // Unknown window mode, return failure
      //

      return FALSE;
      }

   //
   // If successful, update global variables to reflect new video mode
   //

   if (result)
      {
      mode_change_allowed  = allow_mode_switch;
      current_display_mode = display_mode;
      current_bpp          = display_bpp;
      current_size_X       = display_size_X;
      current_size_Y       = display_size_Y;
      }

   return result;
}

//****************************************************************************
//*                                                                          *
//*  Window message receiver procedure                                       *
//*                                                                          *
//****************************************************************************

long FAR PASCAL WndProc(HWND   hWindow, UINT   message,   //)
                        WPARAM wParam,  LPARAM lParam)
{
   RECT *rect;

   switch (message)
      {
      case WM_PAINT:

         //
         // If part of window is invalidated while app is not in foreground,
         // re-copy last DIB image to window
         //

         if ((!SAL_is_app_active()) && (current_display_mode == SAL_WINDOW))
            {
            if (SAL_get_preference(SAL_SLEEP_WHILE_INACTIVE))
               {
               SAL_info_printf("SAL: Refreshing inactive app window\n");
               }

            if (DIB_active)
               {
               DIB_refresh_surface();
               }
            else if (DDraw_active)
               {
               DDraw_refresh_surface();
               }
            }

         //
         // Windows sends a spurious WM_PAINT to the app when task-switching
         // away from a DirectDraw fullscreen app.  Swallow it, so the app
         // doesn't try to re-lock the surface to refresh the screen...
         //

         if (!SAL_is_app_active())
            {
            return DefWindowProc(hWindow, message, wParam, lParam);
            }

         break;

      case WM_SETFOCUS:

         if ((current_display_mode == SAL_WINDOW) && constrain_state)
            {
            constrain_request = 1;
            }

         if (focus_callback != NULL)
            {
            (focus_callback)(1);
            }
         break;

      case WM_KILLFOCUS:

         if ((current_display_mode == SAL_WINDOW) && constrain_state)
            {
            ClipCursor(&unconstrained_rect);
            constrain_request = 0;
            }

         if (focus_callback != NULL)
            {
            (focus_callback)(0);
            }
         break;


      case WM_ACTIVATEAPP:

         if (wParam)
            {
            if (!app_active && (!WPS_lock))
               {
               app_active = TRUE;
               SAL_info_printf("SAL: Activated!\n");

               if (current_display_mode == SAL_FULLSCREEN)
                  {
                  SetWindowLong(hWnd, 
                              GWL_STYLE, 
                              GetWindowLong(hWnd, 
                                             GWL_STYLE) & ~WS_SYSMENU);
                  }
               }
            }
         else
            {
            if (app_active && (!WPS_lock))
               {
               app_active = FALSE;
               SAL_info_printf("SAL: Deactivated!\n");

               if (current_display_mode == SAL_FULLSCREEN)
                  {
                  SetWindowLong(hWnd, 
                              GWL_STYLE, 
                              GetWindowLong(hWnd, 
                                             GWL_STYLE) | WS_SYSMENU);
                  }

               //
               // We are switching tasks, so if the application has hidden
               // the mouse cursor, restore it so that it will not vanish
               // if the user moves the mouse over the deactivated app window
               //
               // Cursor will be hidden again the first time the user moves 
               // the mouse inside the app window's client area, after the 
               // app has received the input focus once again.
               //

               if (!cursor_state)
                  {
                  cursor_state = 1;
                  ShowCursor(1);
                  }
               }
            }
         break;

      case WM_WINDOWPOSCHANGED:

         if ((current_display_mode == SAL_WINDOW) && (!WPS_lock))
            {
            //
            // If deactivating or minimizing, unconstrain the cursor
            //

            if (((LPWINDOWPOS) lParam)->flags & SWP_NOACTIVATE)
               {
               if (constrain_state)
                  {
                  ClipCursor(&unconstrained_rect);
                  constrain_request = 0;
                  }
               }
            else
               {
               rect = client_screen_rect();

               area.w = rect->right  - rect->left + 1;
               area.h = rect->bottom - rect->top + 1;
               area.x = rect->left;
               area.y = rect->top;

               if (constrain_state)
                  {
                  constrain_request = 1;
                  }
               }

            if (DIB_active)
               {
               DIB_refresh_surface();
               }
            else if (DDraw_active)
               {
               DDraw_refresh_surface();
               }
            }
         break;

      case WM_MENUCHAR:

         //
         // Inhibit beep when requesting fullscreen/windowed-mode toggle
         //

         return MNC_CLOSE << 16;
         break;

      case WM_SYSCOMMAND:

         switch (wParam & 0xffff0)
            {
            case SC_SCREENSAVE:
            case SC_MONITORPOWER:

               //
               // Inhibit all screen-saver activity
               //

               return 0;

            case SC_MINIMIZE:

               //
               // Beware of Win95 bug: This message is NOT sent if the 
               // user selects "Minimize All Windows" from the taskbar menu.
               // An alternate way to detect minimization in general appears
               // to be the SWP_NOACTIVATE flag test in WM_WINDOWPOSCHANGED
               // above.
               //

               SAL_info_printf("SAL: Minimize request\n");
               app_minimized = 1;
               break;

            case SC_RESTORE:
               
               SAL_info_printf("SAL: Restore request\n");
               app_minimized = 0;
               break;

            case SC_MAXIMIZE:

               SAL_info_printf("SAL: Maximize request\n");
               app_minimized = 0;

               if (current_display_mode == SAL_WINDOW) 
                  {
                  if (SAL_get_preference(SAL_MAXIMIZE_TO_FULLSCREEN))
                     {
                     mode_change_request = TRUE;

                     SetFocus(hWnd);

                     if (window_callback != NULL)
                        {
                        return (window_callback)(hWindow, WM_SYSKEYUP, VK_RETURN, lParam);
                        }

                     return 0;
                     }
                  else
                     {
                     if ((original_area.w           != -1) && 
                         (original_window_rect.left !=  LONG_MAX))
                        {
                        SetWindowPos(hWnd, 
                                     HWND_TOP, 
                                     original_window_rect.left,
                                     original_window_rect.top,
                                     original_window_rect.right  - original_window_rect.left + 1,
                                     original_window_rect.bottom - original_window_rect.top  + 1,
                                     SWP_NOCOPYBITS | SWP_NOZORDER);

                        area = original_area;
                        }

                     SetFocus(hWnd);                                
                     return 0;
                     }
                  }
               break;
            }

         break;

      case WM_PALETTECHANGED:

         if ((HWND) wParam == hWnd)
            {
            break;
            }

      case WM_QUERYNEWPALETTE:
                              
         if (DIB_active && (current_bpp == 8))
            {
            palette_change_request = TRUE;
            InvalidateRect(hWindow, 0, FALSE);
            }
         break;

      case WM_NCMOUSEMOVE:

         if (current_display_mode == SAL_WINDOW)
            {
            //
            // Mouse has moved into menu area of active window -- show it 
            // regardless of show_count, so that menu items can be selected
            //

            if (SAL_is_app_active())
               {
               if (!cursor_state)
                  {
                  cursor_state = 1;
                  ShowCursor(1);
                  }
               }
            }
         break;

      case WM_MOUSEMOVE:

         if (current_display_mode == SAL_WINDOW)
            {
            if (SAL_is_app_active())
               {
               //
               // Mouse has moved into window client area -- hide it if 
               // application is active, cursor is currently visible,
               // and show_count is less than 1
               //
               // Fall through to process MOUSE_event() case
               //

               if ((cursor_state) && (show_count < 1))
                  {
                  cursor_state = 0;
                  ShowCursor(0);
                  }

               //
               // If mouse constraint request is pending, constrain the mouse
               // as soon as it moves into the client area
               //
               // We do not want to constrain the mouse unless the pointer 
               // is in the client area, because problems would occur when 
               // the user right-clicks on the app's taskbar entry and causes 
               // the app to regain focus indirectly
               //

               if (constrain_request)
                  {
                  ClipCursor(client_screen_rect());
                  constrain_request = 0;
                  }
               }
            }


      case WM_LBUTTONDOWN:
      case WM_LBUTTONUP:
      case WM_RBUTTONDOWN:
      case WM_RBUTTONUP:

         MOUSE_event(wParam, lParam);
         break;

      case WM_SYSKEYDOWN:
      case WM_KEYDOWN:

         KEYDOWN_event(wParam, lParam);

         if (wParam == VK_MENU)
            {
            if (SAL_get_preference(SAL_PREVENT_ALT_MENU_POPUP))
               {
               //
               // If key pressed was ALT by itself, set wParam to 0 (invalid
               // key code) to prevent system menu from popping up and 
               // interfering with app
               //

               wParam = 0;
               }
            }
         break;

      case WM_SYSKEYUP:

         if (wParam == VK_RETURN)
            {
            SAL_info_printf("SAL: Request fullscreen/window toggle\n");
            mode_change_request = TRUE;
            }

         KEYUP_event(wParam, lParam);

         if (wParam == VK_MENU)
            {
            if (SAL_get_preference(SAL_PREVENT_ALT_MENU_POPUP))
               {
               //
               // If key pressed was ALT by itself, set wParam to 0 (invalid
               // key code) to prevent system menu from popping up and 
               // interfering with app
               //

               wParam = 0;
               }
            }

         break;

      case WM_KEYUP:

         if (wParam == VK_F11)
            {
            //
            // For compatibility with IE
            // 

            SAL_info_printf("SAL: Request fullscreen/window toggle\n");
            mode_change_request = TRUE;
            }

         KEYUP_event(wParam, lParam);
         break;

      case WM_CHAR:

         CHAR_event(wParam, lParam);
         break;

      case WM_DESTROY:

         app_active     = FALSE;
         app_terminated = TRUE;

         SAL_info_printf("SAL: Destroy message received\n");
         PostQuitMessage(0);
         break;
      }

   if (window_callback != NULL)
      {
      return (window_callback)(hWindow, message, wParam, lParam);
      }
   else
      {
      return DefWindowProc(hWindow, message, wParam, lParam);
      }
}

//****************************************************************************
//*                                                                          *
//*  Start up SAL services                                                   *
//*                                                                          *
//*  Initialize preferences                                                  *
//*                                                                          *
//*  Non-zero: Success                                                       *
//*         0: Failure                                                       *
//*        -1: Attempt to launch multiple instances                          *
//*                                                                          *
//****************************************************************************

DXDEF S32 WINAPI SAL_startup(HINSTANCE instance, //)
                             char     *app_name,
                             S32       allow_multiple_instances,
                             SALEXITCB exit_handler)
{
   //
   // Force floating-point inclusion so SAL_debug_printf() can print floats
   //

   volatile float fval;

   fval = 1.0F;

   //
   // If desired, reject any attempt to launch more than one instance of this 
   // application
   //

   if (!allow_multiple_instances)
      {
      //
      // Check for redundant startup by creating a semaphore and checking to
      // see if it already existed
      //
      // Semaphore will be destroyed automatically at shutdown time
      //

      hSem = CreateSemaphore(NULL,     
                             0,        
                             1,        
                             app_name);

      if ((hSem != NULL) && (GetLastError() == ERROR_ALREADY_EXISTS))
         {
         CloseHandle(hSem);

         SAL_debug_printf("SAL: Multiple instances not permitted, creation failed\n");
         return -1;
         }
      }

   //             
   // Set global instance/app name variables
   // 

   hAppInstance = instance;

   strncpy(szAppName,
           app_name,
           sizeof(szAppName));

   //
   // Generate startup message
   //

   SAL_info_printf("Starting SAL (%s): %s, HINSTANCE %X\n",
      __DATE__,
      app_name,
      instance);

   //
   // Register default DirectDraw creation/destruction handlers (to be used if
   // app does not register its own to support Direct3D or other specialized
   // need)
   //

   SAL_register_DDSTARTUP_callback  (DDraw_default_startup_handler);
   SAL_register_DDSHUTDOWN_callback (DDraw_default_shutdown_handler);

   //
   // Set (mandatory) exit callback function
   //

   if (exit_handler == NULL)
      {
      return 0;
      }

   exit_callback = exit_handler;

   //
   // Check for debugging logfile request (environment variable in DOS 
   // version, or WIN.INI entry in Windows version)
   //
   // If file logging enabled, append session date/timestamp to debug logfile
   //

   GetProfileString("SAL", "SALDebug", "None", debug_log_filename, sizeof(debug_log_filename));

   if (!strnicmp(debug_log_filename, "None", 4))
      {
      log_to_file = FALSE;
      }
   else
      {
      //
      // Create script file and set "debug" flag
      //
      // A leading '+' allows debug output to be appended to existing file
      //

      FILE *debugfile;

      if (debug_log_filename[0] == '+')
         {
         strcpy(debug_log_filename, &debug_log_filename[1]);
         debugfile = fopen(debug_log_filename,"a+t");
         }
      else
         {
         debugfile = fopen(debug_log_filename,"w+t");
         }

      if (debugfile == NULL)
         {
         SAL_debug_printf("SAL: Unable to open debug logfile \"%s\"\n",
            debug_log_filename);
         }
      else
         {
         //
         // Write header to log file
         //

         S32        elapstime;
         struct tm *adjtime;
         C8         loctime[32];

         time(&elapstime);
         adjtime = localtime(&elapstime);
         strcpy(loctime,asctime(adjtime));
         loctime[24] = 0;

         debug_start_time = timeGetTime();

         fprintf(debugfile,
                 "-------------------------------------------------------------------------------\n"
                 "SAL usage script generated by W32SAL V"SAL_VERSION"\n"
                 "Start time: %s\n"
                 "-------------------------------------------------------------------------------\n\n"
                 ,(C8 FAR *) loctime);

         log_to_file = TRUE;
         fclose(debugfile);
         }
      }

   //
   // Init globals 
   //

   application_icon       =  MAKEINTRESOURCE(IDI_APPLICATION);

   app_active             =  FALSE;  // App not activated yet
   app_terminated         =  FALSE;  // App not terminated yet
   app_minimized          =  FALSE;  // App not minimized by default

   WPS_lock               =  FALSE;  // Normal WM_WINDOWPOSCHANGED processing
   show_count             =  0;      // Mouse cursor show count
   cursor_state           =  1;      // (Windows cursor is on by default)
   constrain_state        =  0;      // Mouse is not constrained to window
   constrain_request      =  0;      // Mouse should not be constrained at next movement

   area.w                 = -1;      // DIB window area uninitialized

   focus_callback         =  NULL;
   window_callback        =  NULL;
   hWnd                   =  NULL;
   hHook                  =  NULL;
   mode_change_request    =  FALSE;
   hSem                   =  NULL;

   DIB_active             =  FALSE;
   DDraw_active           =  FALSE;

   mode_change_allowed    =  FALSE;
   current_display_mode   =  SAL_FULLSCREEN;
   current_bpp            =  0;
   current_size_X         =  0;
   current_size_Y         =  0;

   palette_change_request = FALSE;

   original_area.w           = -1;
   original_window_rect.left = -LONG_MAX;

   desktop_mode_valid        = FALSE;

   //
   // Get original mouse constraint area (normally entire screen)
   //

   GetClipCursor(&unconstrained_rect);

   //
   // Allocate palette and bitmap structures at startup time to avoid
   // memory fragmentation during mode switches
   //
   // Clear palette structure to black to avoid screen flash when
   // setting initial mode
   //

   pLogPal = (LOGPALETTE *) 
             malloc (sizeof(LOGPALETTE) + (sizeof(PALETTEENTRY) * 256));

   if (pLogPal == NULL)
      {
      return 0;
      }

   memset(pLogPal,0, sizeof(LOGPALETTE) + (sizeof(PALETTEENTRY) * 256));

   pLogPal->palVersion    = 0x300;
   pLogPal->palNumEntries = 256;

   pbmi = (BITMAPINFO *) 
          malloc(sizeof (BITMAPINFOHEADER) + (sizeof (RGBQUAD) * 256));

   if (pbmi == NULL)
      {
      free(pLogPal);
      return 0;
      }
 
   memset(pbmi, 0, sizeof (BITMAPINFOHEADER) + (sizeof (RGBQUAD) * 256));

   pbmih = &(pbmi->bmiHeader);

   //
   // Get initial Windows desktop display format (and masks, in high-color modes)
   //

   get_desktop_format(&desktop_R_bitmask,
                      &desktop_G_bitmask,
                      &desktop_B_bitmask,
                      &desktop_w,
                      &desktop_h,
                      &desktop_bpp,
                      &desktop_refresh);

   //
   // Indicate successful startup
   //

   return 1;
}

//****************************************************************************
//*                                                                          *
//*  System Abstraction Layer exit function                                  *
//*                                                                          *
//****************************************************************************

DXDEF void WINAPI SAL_shutdown(void)
{
   if (DDraw_active)
      {
      DDraw_shutdown();
      }

   if (DIB_active)
      {
      DIB_shutdown();
      }

   if (pbmi != NULL)
      {
      free(pbmi);
      pbmi = NULL;
      }

   if (pLogPal != NULL)
      {
      free(pLogPal);
      pLogPal = NULL;
      }

   //
   // If there's an MS-DOS prompt, make sure it gets the focus next
   // (handy for development purposes)
   //

   HWND scan = GetTopWindow(0);

   while (scan)
      {
      C8 string[256] = "";

      S32 result = GetWindowText(scan, string, sizeof(string));

      if (result)
         {
         if (strstr(string, "MS-DOS") != NULL)
            {
            SetForegroundWindow(scan);
            break;
            }
         }

      scan = GetWindow(scan, GW_HWNDNEXT);
      }
}

//****************************************************************************
//*                                                                          *
//*  Set SAL operational preferences and policies                            *
//*                                                                          *
//*  May be called by applications which need to alter the default           *
//*  behavior of the SAL system                                              *
//*                                                                          *
//****************************************************************************

DXDEF S32 WINAPI SAL_set_preference(U32 number, S32 value)
{
   S32 old;

   old = SAL_preference[number];

   SAL_preference[number] = value;

   return old;
}

//****************************************************************************
//*                                                                          *
//*  Get SAL operational preferences and policies                            *
//*                                                                          *
//****************************************************************************

DXDEF S32 WINAPI SAL_get_preference(U32 number)
{
   return SAL_preference[number];
}

//****************************************************************************
//*                                                                          *
//*  Monochrome debug printf() functions                                     *
//*                                                                          *
//*  Text written to logfile if WIN.INI / DOS environment option enabled     *
//*                                                                          *
//****************************************************************************

DXDEF void __cdecl SAL_debug_printf(char *fmt, ...)
{
   static char work_string[4096];
   FILE       *log;

   if ((fmt == NULL) || (strlen(fmt) > sizeof(work_string)))
      {
      strcpy(work_string, "(String missing or too large)");
      }
   else
      {
      va_list ap;

      va_start(ap, 
               fmt);

      vsprintf(work_string, 
               fmt, 
               ap);

      va_end  (ap);
      }

   if ((log_to_file) && (strlen(work_string)))
      {
      static S32 previous_newline = 1;

      log = fopen(debug_log_filename,"a+t");
      
      if (log != NULL)
         {
         if (previous_newline)
            {
            U32 t = timeGetTime() - debug_start_time;

            fprintf(log,"[%.02d:%.02d:%.02d.%.03d] %s",
               (t / 3600000L),
               ((t / 60000L) % 60L),
               ((t / 1000L)  % 60L),
               (t % 1000L),
               work_string);
            }
         else
            {
            fprintf(log,"%s",work_string);
            }

         fclose(log);

         previous_newline = (work_string[strlen(work_string)-1] == '\n');
         }
      }

   if (!SAL_get_preference(SAL_USE_PARAMON))
      {
      OutputDebugString(work_string);
      }
   else
      {
      //
      // If using_port==-1, we need to determine which parallel port, if any,
      // is connected to a PARAMON receiver terminal
      //
      // Try sending an LF character to each port in succession, until the 
      // port choices are exhausted or one of them returns without timing out
      //

      if (using_port == -1)
         {
         xmit_timeout = 1000;

         for (using_port=0; using_port < ARY_CNT(data_ports); using_port++)
            {
            if ((permit_IO(data_ports[using_port])) &&
                (permit_IO(stat_ports[using_port])))
               {
               if (send_char('\n')) 
                  {
                  xmit_timeout = 50000;
                  break;
                  }
               }
            }
         }              

      //
      // If all parallel ports have been tried without finding a PARAMON receiver,
      // send the text to OutputDebugString()
      //
      // Otherwise, send text to parallel port
      //

      if (using_port == ARY_CNT(data_ports))
         {
         OutputDebugString(work_string);
         return;
         }
      else
         {
         for (U32 i=0; i < strlen(work_string); i++)
            {
            send_char(work_string[i]);
            }
         }
      }
}

//****************************************************************************
//*                                                                          *
//*  Message box display function                                            *
//*                                                                          *
//****************************************************************************

DXDEF void __cdecl SAL_alert_box(C8 *caption, C8 *fmt, ...)
{
   static char work_string[4096];
   S32         restore_cursor;

   restore_cursor = cursor_state;

   if (!cursor_state)
      {
      ShowCursor(1);
      }

   if ((fmt == NULL) || (strlen(fmt) > sizeof(work_string)))
      {
      strcpy(work_string, "(String missing or too large)");
      }
   else
      {
      va_list ap;

      va_start(ap, 
               fmt);

      vsprintf(work_string, 
               fmt, 
               ap);

      va_end  (ap);
      }

   SAL_debug_printf("%s\n",work_string);

   //
   // If DirectDraw active, display GDI surface for dialog box
   // 

   if (DDraw_active)
      {
      DDraw.lpDD->FlipToGDISurface();
      }

   //
   // If in 8-bpp mode, save current palette and switch to standard palette
   // 

   if (caption == NULL)
      {
      MessageBox(hWnd, 
                 work_string,
                 "SAL Error", 
                 MB_OK);
      }
   else
      {
      MessageBox(hWnd, 
                 work_string,
                 caption,
                 MB_OK);
      }

   if (!restore_cursor)
      {
      ShowCursor(0);
      }
}

//****************************************************************************
//*                                                                          *
//*  Set Windows application icon                                            *
//*                                                                          *
//****************************************************************************

DXDEF void       WINAPI SAL_set_application_icon    (C8   *resource)
{
   if (!(U32(resource) & 0xffff0000))
      {
      application_icon = resource;
      }
   else
      {
      strcpy(icon_name_buffer, resource);
      application_icon = icon_name_buffer;
      }
}

//****************************************************************************
//*                                                                          *
//*  Create SAL application's main window and class                          *
//*                                                                          *
//****************************************************************************

DXDEF HWND WINAPI SAL_create_main_window_with_WNDCLASS(const WNDCLASSEX *wc)
{
   if (wc->lpfnWndProc == NULL)
      {
      ((WNDCLASSEX *) wc)->lpfnWndProc = WndProc;
      }

   RegisterClassEx(wc);

   //
   // Create application's main window
   //

   hWnd = CreateWindowEx(
       0,
       szAppName,
       szAppName,
       0,
       CW_USEDEFAULT,
       CW_USEDEFAULT,
       CW_USEDEFAULT,
       CW_USEDEFAULT,
       NULL,
       NULL,
       hAppInstance,
       NULL);

   if (!hWnd)
      {
      SAL_debug_printf("SAL: Invalid window handle!\n");
      return FALSE;
      }

   UpdateWindow(hWnd);
   SetFocus(hWnd);

   //
   // Set "activated" flag and return window handle to application
   //

   app_active = TRUE;

   return hWnd;
}

//****************************************************************************
//*                                                                          *
//*  Create SAL application's main window and class                          *
//*                                                                          *
//****************************************************************************

DXDEF HWND WINAPI SAL_create_main_window  (void)
{
   WNDCLASS wc;

   //
   // Set up and register application window class
   //

   wc.style         = CS_HREDRAW | CS_VREDRAW;
   wc.lpfnWndProc   = WndProc;
   wc.cbClsExtra    = 0;
   wc.cbWndExtra    = 0;
   wc.hInstance     = hAppInstance;
   wc.hIcon         = LoadIcon(hAppInstance, application_icon);
   wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
   wc.hbrBackground = NULL; //(HBRUSH) GetStockObject(BLACK_BRUSH);
   wc.lpszMenuName  = NULL;
   wc.lpszClassName = szAppName;

   RegisterClass(&wc);

   //
   // Create application's main window
   //

   hWnd = CreateWindowEx(
       0,
       szAppName,
       szAppName,
       0,
       CW_USEDEFAULT,
       CW_USEDEFAULT,
       CW_USEDEFAULT,
       CW_USEDEFAULT,
       NULL,
       NULL,
       hAppInstance,
       NULL);

   if (!hWnd)
      {
      SAL_debug_printf("SAL: Invalid window handle!\n");
      return FALSE;
      }

   UpdateWindow(hWnd);
   SetFocus(hWnd);

   //
   // Set "activated" flag and return window handle to application
   //

   app_active = TRUE;

   return hWnd;
}

//****************************************************************************
//*                                                                          *
//*  Set display mode and window size                                        *
//*                                                                          *
//****************************************************************************

DXDEF S32        WINAPI SAL_set_display_mode        (S32   display_size_X,//)
                                                     S32   display_size_Y,
                                                     S32   display_bpp,
                                                     S32   display_mode,
                                                     S32   allow_mode_switch)
{
   //
   // Record user's intended window size so that it can be restored when
   // toggling between windowed and desktop mode
   //

   area.w = -1;
   original_area.w = -1;

   requested_size_X = display_size_X;
   requested_size_Y = display_size_Y;
   requested_bpp    = display_bpp;

   static S32 first_time_called = FALSE;

   S32 result = set_display_mode(display_size_X,
                                 display_size_Y,
                                 display_bpp,
                                 display_mode,
                                 allow_mode_switch,
                                 first_time_called);

   first_time_called = TRUE;

   return result;
}

//****************************************************************************
//*                                                                          *
//*  Return current window mode                                              *
//*                                                                          *
//****************************************************************************

DXDEF S32 WINAPI  SAL_window_status           (void)
{
   return current_display_mode;
}

//****************************************************************************
//*                                                                          *
//*  Return area of client window in screen coordinates                      *
//*                                                                          *
//****************************************************************************

DXDEF void WINAPI SAL_client_area             (SAL_WINAREA *area)
{
   RECT *rect;

   if (current_display_mode == SAL_WINDOW)
      {
      rect = client_screen_rect();

      area->x = rect->left;
      area->y = rect->top;
      area->w = rect->right  - rect->left + 1;
      area->h = rect->bottom - rect->top  + 1;
      }
   else
      {
      area->x = 0;
      area->y = 0;
      area->w = current_size_X;
      area->h = current_size_Y;
      }
}

//****************************************************************************
//*                                                                          *
//*  Return area of entire window in screen coordinates                      *
//*                                                                          *
//****************************************************************************

DXDEF void WINAPI SAL_window_area             (SAL_WINAREA *area)
{
   RECT window_rect;

   if (current_display_mode == SAL_WINDOW)
      {
      GetWindowRect(hWnd, &window_rect);

      area->x = window_rect.left;
      area->y = window_rect.top;
      area->w = window_rect.right  - window_rect.left + 1;
      area->h = window_rect.bottom - window_rect.top  + 1;
      }
   else
      {
      area->x = 0;
      area->y = 0;
      area->w = current_size_X;
      area->h = current_size_Y;
      }
}

//****************************************************************************
//*                                                                          *
//*  Return TRUE if app has input focus                                      *
//*                                                                          *
//****************************************************************************

DXDEF S32 WINAPI  SAL_is_app_active           (void)
{
   return app_active;
}

//****************************************************************************
//*                                                                          *
//*  Register app function to be called when focus gained or lost            *
//*                                                                          *
//****************************************************************************

DXDEF SALFOCUSCB WINAPI SAL_register_focus_callback (SALFOCUSCB fn)
{
   SALFOCUSCB old;

   old = focus_callback;

   focus_callback = fn;

   return old;
}

//****************************************************************************
//*                                                                          *
//*  Register application WNDPROC function                                   *
//*                                                                          *
//****************************************************************************

DXDEF WNDPROC WINAPI SAL_register_WNDPROC     (WNDPROC fn)
{
   WNDPROC old;

   old = window_callback;

   window_callback = fn;

   return old;
}

//****************************************************************************
//*                                                                          *
//*  Service Windows message queue, handling any mode change request         *
//*                                                                          *
//****************************************************************************

DXDEF void WINAPI SAL_serve_message_queue(void)
{
   S32 result;

   serve_queue();

   if (mode_change_request && mode_change_allowed)
      {
      S32 set_size_X = current_size_X;
      S32 set_size_Y = current_size_Y;
      S32 set_bpp    = current_bpp;
      S32 set_mode   = current_display_mode;

      mode_change_request = 0;   

      if (SAL_get_preference(SAL_TOGGLE_DESKTOP_WINDOW))
         {
         if (current_display_mode == SAL_DESKTOP)
            {
            set_size_X = requested_size_X;
            set_size_Y = requested_size_Y;

            area.w = -1;

            set_mode = SAL_WINDOW;
            }
         else
            {
            set_mode = SAL_DESKTOP;
            }
         }
      else
         {
         if (current_display_mode == SAL_WINDOW)
            {
            set_mode = SAL_FULLSCREEN;
            }
         else
            {
            set_mode = SAL_WINDOW;
            }
         }

      result = set_display_mode(set_size_X, 
                                set_size_Y, 
                                set_bpp,    
                                set_mode,   
                                TRUE,
                                TRUE);      
                  

      //
      // If window mode toggle did not succeed, restore original mode
      //

      if (!result)
         {
         SAL_debug_printf("SAL: SAL_set_display_mode() failed, restoring old mode\n");

         set_display_mode(current_size_X,       
                          current_size_Y,       
                          current_bpp,          
                          current_display_mode, 
                          TRUE,                 
                          TRUE);                
         }
      }
}

//****************************************************************************
//*                                                                          *
//*  Set a single palette entry                                              *
//*                                                                          *
//****************************************************************************

DXDEF void WINAPI SAL_set_palette_entry      (S32        index,//)
                                              SAL_RGB   *entry,
                                              S32        wait_flag)
{

   //
   // Update global palette state
   //

   palette_state[index] = *entry;

   //
   // If we're not in 8BPP mode, bail out
   // 

   if (current_bpp != 8)
      {
      return;
      }

   //
   // Update palette array
   //

   pLogPal->palPalEntry[index].peRed   = pbmi->bmiColors[index].rgbRed   = (unsigned char) entry->r;
   pLogPal->palPalEntry[index].peGreen = pbmi->bmiColors[index].rgbGreen = (unsigned char) entry->g;
   pLogPal->palPalEntry[index].peBlue  = pbmi->bmiColors[index].rgbBlue  = (unsigned char) entry->b;
   pLogPal->palPalEntry[index].peFlags = NULL;

   //
   // Update DirectDraw palette, if appropriate
   //

   if (DDraw_active)
      {
      ++wait_flag;      // Unsupported in current DirectX release, avoid warning

      DDraw.lpDDPal->SetEntries(0,
                                index,
                                1,
                               &pLogPal->palPalEntry[index]);
      }

   if (DIB_active)
      {
      if (hPalette != NULL)
         {
         DeleteObject(hPalette);
         }

      hPalette = CreatePalette(pLogPal);

      palette_change_request = TRUE;
      }
}

//****************************************************************************
//*                                                                          *
//*  Retrieve a single palette entry                                         *
//*                                                                          *
//****************************************************************************

DXDEF void WINAPI SAL_get_palette_entry      (S32        index,//)
                                              SAL_RGB   *entry)
{
   *entry = palette_state[index];
}

//****************************************************************************
//*                                                                          *
//*  Set a range of palette entries                                          *
//*                                                                          *
//****************************************************************************

DXDEF void WINAPI SAL_set_palette_range      (S32        index,//)
                                              S32        num_entries,
                                              SAL_RGB   *entry_list,
                                              S32        wait_flag)
{
   S32 i;
   S32 j;

   //
   // Update global palette state
   //

   for (i=0; i < num_entries; i++)
      {
      palette_state[index+i] = entry_list[i];
      }

   //
   // If we're not in 8BPP mode, bail out
   // 

   if (current_bpp != 8)
      {
      return;
      }

   //
   // Update palette array
   //

   for (i=0, j=index; i < num_entries; i++, j++)
      {
      pLogPal->palPalEntry[j].peRed   = pbmi->bmiColors[j].rgbRed   = (unsigned char) entry_list[i].r;
      pLogPal->palPalEntry[j].peGreen = pbmi->bmiColors[j].rgbGreen = (unsigned char) entry_list[i].g;
      pLogPal->palPalEntry[j].peBlue  = pbmi->bmiColors[j].rgbBlue  = (unsigned char) entry_list[i].b;
      pLogPal->palPalEntry[j].peFlags = NULL;
      }

   //
   // Update DirectDraw palette, if appropriate
   //

   if (DDraw_active)
      {
      ++wait_flag;      // Unsupported in current DirectX release, avoid warning

      DDraw.lpDDPal->SetEntries(0,
                                index,
                                num_entries,
                               &pLogPal->palPalEntry[index]);
      }

   if (DIB_active)
      {
      if (hPalette != NULL)
         {
         DeleteObject(hPalette);
         }

      hPalette = CreatePalette(pLogPal);

      palette_change_request = TRUE;
      }
}
                                   
//****************************************************************************
//*                                                                          *
//*  Retrieve a range of palette entries                                     *
//*                                                                          *
//****************************************************************************

DXDEF void WINAPI SAL_get_palette_range      (S32        index,//)
                                              S32        num_entries,
                                              SAL_RGB   *entry_list)
{
   for (int i=0; i < num_entries; i++)
      {
      entry_list[i] = palette_state[index+i];
      }
}

//****************************************************************************
//*                                                                          *
//*  Make back surface visible                                               *
//*                                                                          *
//****************************************************************************

DXDEF void WINAPI SAL_flip_surface           (void)
{
   if (DDraw_active)
      {
      if (SAL_get_preference(SAL_USE_PAGE_FLIPPING))
         {
         DDraw_flip_surface();
         }
      else
         {
         SAL_blit_surface();
         }
      }
   else if (DIB_active)
      {
      SAL_blit_surface();
      }
}

//****************************************************************************
//*                                                                          *
//*  Use BltFast() to copy surface in DirectDraw, as an alternative to page- *
//*  flipping                                                                *
//*                                                                          *
//****************************************************************************

DXDEF void WINAPI SAL_blit_surface(void)
{
   HRESULT result;

   if (DDraw_active)
      {
      while (1)
         {
         if (!SAL_is_app_active() && SAL_get_preference(SAL_SLEEP_WHILE_INACTIVE))
            {
            Sleep(10);
            }
         else
            {
            result = DDraw_refresh_surface();

            if (result == DD_OK)
               {
               break;
               }
            else if (result == DDERR_SURFACELOST) 
               {
               DDraw.lpDDSPrimary->Restore();
               Sleep(100);
               }
            }

         serve_queue();
         } 
      }
   else
      {
      DIB_refresh_surface();
      }
}

//****************************************************************************
//*                                                                          *
//*  Copy a region (rather than the entire buffer) from the back buffer to   *
//*  the front buffer                                                        *
//*                                                                          *
//****************************************************************************

DXDEF void WINAPI SAL_blit_region (SAL_REGION *region)
{
   HRESULT result;

   if (DDraw_active)
      {
      while (1)
         {
         if (!SAL_is_app_active() && SAL_get_preference(SAL_SLEEP_WHILE_INACTIVE))
            {
            Sleep(10);
            }
         else
            {
            result = DDraw_refresh_region(region);

            if (result == DD_OK)
               {
               break;
               }
            else if (result == DDERR_SURFACELOST) 
               {
               DDraw.lpDDSPrimary->Restore();
               Sleep(100);
               }
            }

         serve_queue();
         } 
      }
   else
      {
      DIB_refresh_region(region);
      }
}

//****************************************************************************
//*                                                                          *
//*  Clear a surface to a desired color                                      *
//*                                                                          *
//****************************************************************************

DXDEF void WINAPI SAL_wipe_surface           (S32        surface,//)
                                              U32        color)
{
   if (DDraw_active)
      {
      DDraw_wipe_surface(surface, color);
      }
   else if (DIB_active)
      {
      DIB_wipe_surface(surface, color);
      }
}

//****************************************************************************
//*                                                                          *
//*  Request a pointer to a surface's memory block                           *
//*                                                                          *
//****************************************************************************

DXDEF void WINAPI SAL_lock_surface           (S32        surface,//)
                                              U8       **ptr,
                                              S32       *pitch)
{
   if (DDraw_active)
      {
      DDraw_lock_surface(surface, ptr, pitch);
      }
   else if (DIB_active)
      {
      DIB_lock_surface(surface, ptr, pitch);
      }
}

//****************************************************************************
//*                                                                          *
//*  Release surface memory pointer, optionally performing page flip         *
//*                                                                          *
//****************************************************************************

DXDEF void WINAPI SAL_unlock_surface        (S32        surface,//)
                                             S32        perform_flip)
{
   if (DDraw_active)
      {
      DDraw_unlock_surface(surface, perform_flip);
      }
   else if (DIB_active)
      {
      DIB_unlock_surface(surface, perform_flip);
      }
}

//****************************************************************************
//*                                                                          *
//*  Show system mouse cursor                                                *
//*                                                                          *
//****************************************************************************

DXDEF void WINAPI SAL_show_system_mouse      (void)
{
   ++show_count;

   if (show_count == 1)
      {
      //
      // Show count has become 1, so show mouse cursor if it's currently 
      // hidden
      //

      if (!cursor_state)
         {
         cursor_state = 1;
         ShowCursor(1);
         }
      }
}

//****************************************************************************
//*                                                                          *
//*  Hide system mouse cursor                                                *
//*                                                                          *
//****************************************************************************

DXDEF void WINAPI SAL_hide_system_mouse      (void)
{
   --show_count;

   if (show_count == 0)
      {
      //
      // Show count has become 0, so hide mouse cursor if it's currently
      // visible
      //

      if (cursor_state)
         {
         cursor_state = 0;
         ShowCursor(0);
         }
      }
}

//****************************************************************************
//*                                                                          *
//*  Constrain mouse to limits of client area window in DIB mode             *
//*                                                                          *
//****************************************************************************

DXDEF void WINAPI SAL_constrain_mouse(void)
{
   constrain_state = 1;

   if (current_display_mode == SAL_WINDOW)
      {
      constrain_request = 1;
      }
}

//****************************************************************************
//*                                                                          *
//*  Unconstrain mouse                                                       *
//*                                                                          *
//****************************************************************************

DXDEF void WINAPI SAL_unconstrain_mouse(void)
{
   constrain_state = 0;

   if (current_display_mode == SAL_WINDOW) 
      {
      ClipCursor(&unconstrained_rect);
      constrain_request = 0;
      }
}

//****************************************************************************
//*                                                                          *
//*  Get pixel format in current mode                                        *
//*                                                                          *
//****************************************************************************

DXDEF void WINAPI SAL_get_pixel_format(S32 *pixel_pitch, //)
                                       S32 *bytes_per_pixel,
                                       S32 *R_shift,
                                       U32 *R_mask,
                                       S32 *R_width,
                                       S32 *G_shift,
                                       U32 *G_mask,
                                       S32 *G_width,
                                       S32 *B_shift,
                                       U32 *B_mask,
                                       S32 *B_width)

{
   S32 red_shift;
   U32 red_mask;
   S32 red_width;
   S32 grn_shift;
   U32 grn_mask;
   S32 grn_width;
   S32 blu_shift;
   U32 blu_mask;
   S32 blu_width;
   S32 i;

   //
   // Handle palettized (8 BPP) modes
   //
   // Write 8-bit pixel pitch and visible bytes/pixel fields
   // If we're in 8BPP mode, exit without altering RGB fields
   //

   if (current_bpp == 8)
      {
      if (pixel_pitch     != NULL) *pixel_pitch     = 1;
      if (bytes_per_pixel != NULL) *bytes_per_pixel = 1;

      return;
      }

   //
   // Handle hi-color (16+ BPP) modes
   //
   // If using DirectDraw, do a GetPixelFormat() call
   // 
   // If using CreateDIBSection(), return mask values used to create DIB
   // 

   if (DDraw_active)
      {
      DDPIXELFORMAT ddpf;

      ddpf.dwSize = sizeof(ddpf);
      DDraw.lpDDSPrimary->GetPixelFormat(&ddpf);

      if (!(ddpf.dwFlags & DDPF_RGB))
         {
         SAL_alert_box(NULL,"SAL: DirectDraw pixel format not recognized\n");
         return;
         }

      red_mask = ddpf.dwRBitMask;
      grn_mask = ddpf.dwGBitMask;
      blu_mask = ddpf.dwBBitMask;
      }
   else if (DIB_active)
      {
      red_mask = DIB_R_bitmask;
      grn_mask = DIB_G_bitmask;
      blu_mask = DIB_B_bitmask;
      }

   if (pixel_pitch     != NULL) *pixel_pitch     = (current_bpp / 8);
   if (bytes_per_pixel != NULL) *bytes_per_pixel = (current_bpp / 8);

   //
   // Derive shift, width values from masks
   //

   for (i=31; i >= 0; i--)
      {
      if (red_mask & (1 << i))
         {
         red_shift = i;
         }

      if (grn_mask & (1 << i))
         {
         grn_shift = i;
         }

      if (blu_mask & (1 << i))
         {
         blu_shift = i;
         }
      }

   for (i=0; i <= 31; i++)
      {
      if (red_mask & (1 << i))
         {
         red_width = i - red_shift + 1;
         }

      if (grn_mask & (1 << i))
         {
         grn_width = i - grn_shift + 1;
         }

      if (blu_mask & (1 << i))
         {
         blu_width = i - blu_shift + 1;
         }
      }

   //
   // Pass all requested values back to the caller
   //

   if (R_shift != NULL) *R_shift = red_shift;
   if (G_shift != NULL) *G_shift = grn_shift;
   if (B_shift != NULL) *B_shift = blu_shift;

   if (R_mask  != NULL) *R_mask  = red_mask;
   if (G_mask  != NULL) *G_mask  = grn_mask;
   if (B_mask  != NULL) *B_mask  = blu_mask;

   if (R_width != NULL) *R_width = red_width;
   if (G_width != NULL) *G_width = grn_width;
   if (B_width != NULL) *B_width = blu_width;
}

//****************************************************************************
//*                                                                          *
//*  If in DirectDraw mode, flip page to GDI surface to allow message        *
//*  dialogs, etc.                                                           *
//*                                                                          *
//****************************************************************************

DXDEC void       WINAPI SAL_FlipToGDISurface        (void)
{
   if (DDraw_active)
      {
      DDraw.lpDD->FlipToGDISurface();
      }
}

//****************************************************************************
//*                                                                          *
//*  Get HDC corresponding to back buffer                                    *
//*                                                                          *
//****************************************************************************

DXDEF void WINAPI SAL_get_back_buffer_DC(HDC *dc)
{
   if (DDraw_active) 
      {
      DDraw.lpDDSBack->GetDC(dc);
      }
   else if (DIB_active) 
      {
      *dc = CreateCompatibleDC(0);
      DefaultBitmap = SelectBitmap(*dc, hDIB);
      }
}

//****************************************************************************
//*                                                                          *
//*  Release HDC corresponding to back buffer                                *
//*                                                                          *
//****************************************************************************

DXDEF void WINAPI SAL_release_back_buffer_DC(HDC dc)
{
   if (DDraw_active) 
      {
      DDraw.lpDDSBack->ReleaseDC(dc);
      }
   else if (DIB_active) 
      {
      SelectBitmap(dc, DefaultBitmap);
      DeleteDC(dc);
      DeleteObject(DefaultBitmap);
      }
}

//****************************************************************************
//*                                                                          *
//*  Return current physical resolution for graphics controller (for aspect  *
//*  ratio calculations, etc.)                                               *
//*                                                                          *
//****************************************************************************

DXDEF void       WINAPI SAL_display_resolution      (S32 *_X, //)
                                                     S32 *_Y)
{
   S32 X,Y;

   if (current_display_mode == SAL_FULLSCREEN)
      {
      X = current_size_X;
      Y = current_size_Y;
      }
   else
      {
      X = desktop_w;
      Y = desktop_h;
      }

   if (_X != NULL)
      {
      *_X = X;
      }

   if (_Y != NULL)
      {
      *_Y = Y;
      }
}

//****************************************************************************
//*                                                                          *
//*  Return actual dimensions of client window surface                       *
//*                                                                          *
//*  This may differ from SAL_client_area()'s width and height members in    *
//*  windowed mode, if the output window is stretched or scaled.  It will    *
//*  always reflect the size of the writable surface created in the last     *
//*  call to SAL_set_display_mode().                                         *
//*                                                                          *
//****************************************************************************

DXDEF void       WINAPI SAL_client_resolution      (S32 *_X, //)
                                                    S32 *_Y)
{
   S32 X,Y;

   X = current_size_X;
   Y = current_size_Y;

   if (_X != NULL)
      {
      *_X = X;
      }

   if (_Y != NULL)
      {
      *_Y = Y;
      }
}

//****************************************************************************
//*                                                                          *
//*  Return desktop mode info                                                *
//*                                                                          *
//****************************************************************************

DXDEF void WINAPI SAL_desktop_mode  (S32 *X_size,  //)
                                     S32 *Y_size,         
                                     S32 *BPP,            
                                     S32 *refresh_rate)
{
   if (X_size)       *X_size       = desktop_w;
   if (Y_size)       *Y_size       = desktop_h;
   if (BPP)          *BPP          = desktop_bpp;
   if (refresh_rate) *refresh_rate = desktop_refresh;
}

//****************************************************************************
//*                                                                          *
//*  Return desktop color format                                             *
//*                                                                          *
//****************************************************************************

DXDEF void WINAPI SAL_desktop_format          (U32 *R_mask, //)
                                               U32 *G_mask,              
                                               U32 *B_mask)
{
   if (R_mask) *R_mask = desktop_R_bitmask;
   if (G_mask) *G_mask = desktop_G_bitmask;
   if (B_mask) *B_mask = desktop_B_bitmask;
}

//****************************************************************************
//*                                                                          *
//*  Return number of display pages in flipping chain                        *
//*                                                                          *
//****************************************************************************

DXDEF S32 WINAPI SAL_display_page_count(void)
{
   if (DDraw_active)
      {
      //
      // Return # of back buffers associated with primary surface, plus
      // the front buffer
      //

      DDSURFACEDESC desc;
      desc.dwSize = sizeof(desc);

      if (DDraw.lpDDSPrimary->GetSurfaceDesc(&desc) != DD_OK)
         {
         return 0;
         }

      if (desc.dwFlags & DDSD_BACKBUFFERCOUNT)
         {
         return desc.dwBackBufferCount + 1;
         }
      else
         {
         return 2;
         }
      }
   else
      {
      //
      // Windowed DIB refresh mechanism emulates 2 pages
      //

      return 2;
      }
}

//****************************************************************************
//*                                                                          *
//*  Register DirectDraw startup handler                                     *
//*                                                                          *
//****************************************************************************

DXDEF SALDDSTARTUPCB WINAPI SAL_register_DDSTARTUP_callback (SALDDSTARTUPCB fn)
{
   SALDDSTARTUPCB old = lpDDStartup;

   lpDDStartup = fn;

   return old;
}

//****************************************************************************
//*                                                                          *
//*  Register DirectDraw shutdown handler                                    *
//*                                                                          *
//****************************************************************************

DXDEF SALDDSHUTDOWNCB WINAPI SAL_register_DDSHUTDOWN_callback (SALDDSHUTDOWNCB fn)
{
   SALDDSHUTDOWNCB old = lpDDShutdown;

   lpDDShutdown = fn;

   return old;
}

//****************************************************************************
//*                                                                          *
//*  Get copy of SAL's DirectDraw and DirectDrawSurface objects              *
//*                                                                          *
//****************************************************************************

DXDEF SAL_DDRAWINFO WINAPI SAL_get_DDRAW_info(void)
{
   return DDraw;
}

//****************************************************************************
//*                                                                          *
//*  Allocate surface conforming to current video format                     *
//*                                                                          *
//****************************************************************************

DXDEC S32  WINAPI SAL_allocate_video_surface (S32 width, //)
                                              S32 height)
{
   //
   // Allocate explicit-surface descriptor
   //

   SURFDESC *s = (SURFDESC *) malloc(sizeof(SURFDESC));

   if (s == NULL)
      {
      return -1;
      }

   s->width  = width;
   s->height = height;
   s->bpp    = current_bpp;

   if (DDraw_active)
      {
      s->source = S_DDRAW;

      LPDIRECTDRAWSURFACE  dds;
      LPDIRECTDRAWSURFACE3 ptr;
      DDSURFACEDESC        ddsd;
      HRESULT              result;
                                                          
      memset(&ddsd, 0, sizeof(ddsd));

      ddsd.dwSize = sizeof(ddsd);
      ddsd.dwFlags = DDSD_CAPS | DDSD_HEIGHT | DDSD_WIDTH;

      ddsd.ddsCaps.dwCaps = DDSCAPS_OFFSCREENPLAIN | DDSCAPS_VIDEOMEMORY;

      ddsd.dwWidth  = width;
      ddsd.dwHeight = height;

      result = DDraw.lpDD->CreateSurface(&ddsd, 
                                         &dds,
                                          NULL);
      if (result != DD_OK)
         {
         return -1;
         }

      if ((result = dds->QueryInterface(IID_IDirectDrawSurface3, (void **) &ptr)) != DD_OK)
         {
         dds->Release();
         return -1;
         }

      dds->Release();

      s->object.lpDDS = ptr;
      }
   else
      {
      s->source = S_MEM;

      s->object.ptr = malloc(width * height * current_bpp);

      if (s->object.ptr == NULL)
         {
         return -1;
         }
      }

   return (S32) s;
}

//****************************************************************************
//*                                                                          *
//*  Release explicitly-allocated surface                                    *
//*                                                                          *
//****************************************************************************

DXDEC void WINAPI SAL_release_video_surface  (S32        surface)
{
   if ((surface == SAL_FRONT_SURFACE) || (surface == SAL_BACK_SURFACE))
      {
      //
      // Can't explicitly release front/back surface!
      //

      return;
      }

   //
   // Otherwise, must deallocate surface using whatever method was used
   // to allocate it
   //

   SURFDESC *s = (SURFDESC *) surface;

   if (s->source == S_MEM)
      {
      free(s->object.ptr);
      }
   else if (s->source == S_DDRAW)
      {
      s->object.lpDDS->Release();
      }

   free(s);
}

//****************************************************************************
//*                                                                          *
//*  Wait for vertical retrace interval to begin, if running DirectDraw      *
//*                                                                          *
//****************************************************************************

DXDEC void WINAPI SAL_wait_for_vblank  (void)
{
   if (DDraw_active)
      {
      DDraw.lpDD->WaitForVerticalBlank(DDWAITVB_BLOCKBEGIN, 0);
      }
}

