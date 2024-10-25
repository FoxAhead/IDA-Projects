//
// .TGA to .SHP conversion utility
//

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <windowsx.h>

#include "mmsystem.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <math.h>
#include <io.h>
#include <fcntl.h>
#include <float.h>

#include "winvfx.h"
#include "tga.h"
#include "rgbutils.h"
#include "stdtpl.h"

char szAppName[] = "WinVFX TGA2SHP";

//
// Window handle created by SAL
//

HWND hWnd;

//
// Shape table header structure with first offset pair
//

struct VOFFSET
{
   U32 shape;
   U32 colors;
};

struct VS : public VFX_SHAPETABLE
{
   VOFFSET offset[1];
};

//
// Shape description structure
//

struct SHAPEDESC
{
   SHAPEDESC *next;
   SHAPEDESC *prev;
   S32        index;

   inline void initialize(const void *object)
      {
      }

   inline void shutdown(void)
      {
      }

   inline void display(void)
      {
      }

   VS     *shape;          // Single VFX shape lifted from TGA screen
   S32     size;           // # of bytes allocated for shape table

   VFX_RGB palette[256];   // Palette and color count for shape
   S32     n_colors;

   S32     x;              // Origin for test rendering pass
   S32     y;
};

Pool<SHAPEDESC,256> shape_list;

//
// Extended VFX_RGB used to test for RGB equality
//

struct VRGB : public VFX_RGB
{
	operator == (VRGB * ptr)
      {
      return ((r == ptr->r) && (g == ptr->g) && (b == ptr->b));
      }

	operator == (VRGB ptr)
      {
      return ((r == ptr.r) && (g == ptr.g) && (b == ptr.b));
      }
};

//
// 8-bpp WinVFX provider accessed through indirect function
// calls to allow both 8- and 16-bpp providers to be used by the same 
// application
//
// Note that only 16-bpp applications (apps which call VFX_set_display_mode()
// in WINVFX16.DLL) should attempt to do this!  If an 8-bpp application calls
// any function in WINVFX16.DLL, unexpected results may occur since no valid
// 16-bpp display pixel format is available for use by WINVFX16.  
// 

// ----------------- Functions needed from WINVFX8 -------------------

S32  (WINAPI *VFX8_shape_scan)            (PANE           *pane, 
                                           U32             transparent_color,
                                           S32             hotX, 
                                           S32             hotY, 
                                           VFX_SHAPETABLE *shape_table);

VFX_WINDOW * 
     (WINAPI *VFX8_window_construct)      (S32             width, 
                                           S32             height);
            
void *      
     (WINAPI *VFX8_assign_window_buffer)  (VFX_WINDOW     *window,
                                           void           *buffer,
                                           S32             pitch);
            
PANE * 
     (WINAPI *VFX8_pane_construct)        (VFX_WINDOW     *window, 
                                           S32             x0, 
                                           S32             y0, 
                                           S32             x1, 
                                           S32             y1);

S32  (WINAPI *VFX8_pane_wipe)             (PANE           *pane, 
                                           U32             color);
                                           
//                                       
// Misc. globals
//

VFX_WINDOW *screen;
PANE       *screen_pane;

VFX_WINDOW *shape;
PANE       *shape_pane;

S32 iw,ih,sw,sh;  // Image and screen height/width

VRGB *RGB;        // Source data image

VRGB transparent; // Transparent color from bottom-right pixel of source image

S32  n_shapes;    // Total # of shapes grabbed

//****************************************************************************
//*                                                                          *
//*  Read all or part of a file into memory, returning memory location       *
//*  or NULL on error                                                        *
//*                                                                          *
//*  Memory will be allocated if dest==NULL                                  *
//*                                                                          *
//****************************************************************************

void * FILE_read (C8   *filename, //)     
                  void *dest         = NULL,
                  S32   len          = -1,
                  S32   start_offset = 0)

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
//*                                                                          *
//*  Write file at *buf of length len                                        *
//*                                                                          *
//*  Overwrites any existing file                                            *
//*                                                                          *
//*  Returns 0 on error, else 1                                              *
//*                                                                          *
//****************************************************************************

S32 FILE_write(C8   *filename, //)
               void *buf, 
               U32   len)
{
   HANDLE handle;
   U32    nbytes;

   handle = CreateFile(filename,
                       GENERIC_WRITE,
                       0,
                       NULL,
                       CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL,
                       NULL);

   if (handle == INVALID_HANDLE_VALUE)
      {
      return 0;
      }

   if ((!WriteFile(handle,
                   buf,
                   len,
                  &nbytes,
                   NULL)) || (nbytes != len))
      {
      return 0;
      }   

   CloseHandle(handle);

   return 1;
}

//****************************************************************************
//
// Exit handlers to shut down component libraries
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
//  Update view to show progress
//
//****************************************************************************

void update(void)
{
   //
   // Lock surface for rendering
   //

   VFX_lock_window_surface(screen, VFX_BACK_SURFACE);

   //
   // Draw remaining parts of TGA image
   //

   VRGB *in = RGB;

   for (S32 y=0; y < ih; y++)
      {
      for (S32 x=0; x < iw; x++)
         {
         VFX_pixel_write(screen_pane,
                         x,
                         y,
                         RGB_TRIPLET(in->r, in->g, in->b));
         ++in;
         }
      }

   //
   // Draw shapes acquired so far to verify correct acquisition
   //

   for (S32 index=0; index < shape_list.list_size; index++)
      {
      SHAPEDESC *entry = &shape_list.list[index];

      if (entry->index == -1)
         {
         continue;
         }

      VFX_shape_draw(screen_pane,
                     entry->shape,
                     0,
                     entry->x,
                     entry->y);
      }

   //
   // Release surface lock and refresh screen
   //

   VFX_unlock_window_surface(screen, TRUE);
}

//****************************************************************************
//
//  Find first shape defined in image, quantize it, and lift it
//
//****************************************************************************

S32 lift_shape(void)
{
   S32 x,y;

   //
   // Find top-left pixel of first shape definition on page
   //
   // (This is the hot spot color, if it doesn't match the next pixel over)
   //

   S32 x0=-1;
   S32 y0=-1;

   for (y=0; (y < ih) && (x0 == -1); y++)
      {
      for (x=0; x < iw; x++)
         {
         if (RGB[(y*iw)+x] == transparent)
            {
            continue;
            }

         x0 = x;
         y0 = y;
         break;
         }
      }

   //
   // No shapes found, return -1 to indicate source page empty
   //

   if (x0 == -1)
      {
      return -1;
      }

   //
   // Get border color = color of next pixel to right 
   //

   VRGB border = RGB[(y0*iw)+(x0+1)];

   //
   // Find bottom of first shape definition on page
   //
   // This is defined by the first pixel, going down the left edge of the
   // border, which has another border pixel to its immediate right
   //

   S32 y1=-1;

   for (y=y0+1; y < ih; y++)
      {
      if (RGB[(y*iw)+(x0+1)] == border)
         {
         y1 = y;
         break;
         }

      if (!(RGB[(y*iw)+x] == border))
         {
         SAL_alert_box("Error","Could not find bottom edge of shape");
         exit(1);
         }
      }

   if (y1 == -1)
      {
      SAL_alert_box("Error","Could not find bottom edge of shape");
      exit(1);
      }

   //
   // Find right edge of first shape definition on page
   //
   // This is defined by the first pixel, going across the top edge of the
   // border, which has another border pixel immediately below it
   //

   S32 x1=-1;

   for (x=x0+1; x < iw; x++)
      {
      if (RGB[((y0+1)*iw)+x] == border)
         {
         x1 = x;
         break;
         }

      if (!(RGB[(y*iw)+x] == border))
         {
         SAL_alert_box("Error","Could not find right edge of shape");
         exit(1);
         }
      }

   if (x1 == -1)
      {
      SAL_alert_box("Error","Could not find right edge of shape");
      exit(1);
      }

   //
   // Find shape's origin ("hot spot")
   //
   // If the upper-left border pixel matches the border, then the shape's 
   // origin is at (0,0) relative to its pane.  Otherwise, the shape's origin
   // is marked by an occurence of the upper-left border pixel color in the
   // body of the shape.  In the latter case, we must restore the origin
   // pixel from the lower-right border pixel before proceeding to lift the
   // shape.
   //

   S32 hotx = -1;
   S32 hoty = -1;

   VRGB hot_color = RGB[(y0*iw)+x0];

   if (hot_color == border)
      {
      //
      // No explicit hot spot defined, so define the origin as the upper-
      // left corner of the actual shape area (one pixel inside the border)
      //

      hotx = x0+1;
      hoty = y0+1;
      }
   else
      {
      for (y=y0+1; (y <= y1) && (hotx == -1); y++)
         {
         for (x=x0; x <= x1; x++)
            {
            if (RGB[(y*iw)+x] == hot_color)
               {
               hotx = x;
               hoty = y;

               if (RGB[(y1*iw)+x1] == border)
                  {
                  SAL_alert_box("Error","Lower-right border pixel must be set to desired shape origin color");
                  exit(1);
                  }

               RGB[(y*iw)+x] = RGB[(y1*iw)+x1];
               break;
               }
            }
         }

      if (hotx == -1)
         {
         SAL_alert_box("Error","Shape origin point not found");
         exit(1);
         }
      }

   //
   // Set shape bounds inside bounding box
   //

   ++x0;
   ++y0;
   --x1;
   --y1;

   //
   // Validate coordinates of shape area
   //

   if ((x1 < x0) || (y1 < y0))
      {
      SAL_alert_box("Error","Empty or malformed shape bounding box");
      exit(1);
      }

   //
   // Allocate shape entry
   //

   S32 index = shape_list.allocate();

   assert(index != -1);

   SHAPEDESC *entry = &shape_list.list[index];

   entry->x = hotx;
   entry->y = hoty;

   //
   // Create local pane for 8-bpp shape acquisition
   //

   PANE pane = *shape_pane;

   pane.x0 = x0;
   pane.x1 = x1;
   pane.y0 = y0;
   pane.y1 = y1;

   //
   // Create color quantizer object and pass pixel data to it
   //
   // Output color count = 255 (colors 0-254 usable, 255=transparent)
   //

   CQ quantizer;

   for (y=y0; y <= y1; y++)
      {
      for (x=x0; x <= x1; x++)
         {
         quantizer.add_color(&RGB[(y*iw)+x]);
         }
      }

   entry->n_colors = 255;

   quantizer.quantize(entry->palette,  
                      entry->n_colors);

   //
   // Construct 8-bit copy of shape on working page
   //

   U8 *out = (U8 *) shape->buffer;

   CMAP remap(entry->palette, 
              entry->n_colors);

   for (y=y0; y <= y1; y++)
      {
      for (x=x0; x <= x1; x++)
         {
         if (RGB[(y*iw)+x] == transparent)
            {
            out[(y*iw)+x] = PAL_TRANSPARENT;
            }
         else
            {
            out[(y*iw)+x] = remap.nearest_neighbor(&RGB[(y*iw)+x],
                                                    0);
            }
         }
      }

   //
   // Call 8-bit VFX provider to get memory needed to contain shape 
   // plus its color table
   //

   entry->size = VFX8_shape_scan(&pane,
                                  PAL_TRANSPARENT,
                                  hotx-x0,
                                  hoty-y0,
                                  NULL);

   U32 ctable_offset = entry->size;

   entry->size += (4 + (4 * entry->n_colors));

   entry->shape = (VS *) malloc(entry->size);

   if (entry->shape == NULL)
      {
      SAL_alert_box("Error","Can't allocate %d bytes for VFX shape",
         entry->size);
      exit(1);
      }

   //
   // Acquire VFX shape from working page
   //

   SAL_debug_printf("TGA2SHP: Acquiring shape %d from pane (%d,%d) (%d,%d), origin (%d,%d)\n",
      index,pane.x0,pane.y0,pane.x1,pane.y1,hotx-x0,hoty-y0);

   S32 result = VFX8_shape_scan(&pane,
                                 PAL_TRANSPARENT,
                                 hotx-x0,
                                 hoty-y0,
                                 entry->shape);

   if (result < 0)
      {
      SAL_alert_box("Error","Code %d returned by VFX_shape_scan()",result);
      exit(1);
      }

   //
   // Append color table to shape definition
   //

   U32 *c = (U32 *) (&((U8 *) entry->shape)[ctable_offset]);

   *c++ = entry->n_colors;

   for (S32 i=0; i < entry->n_colors; i++)
      {
      U32 cword = 0;
      
      cword =                (entry->palette[i].b >> 2);
      cword = (cword << 8) + (entry->palette[i].g >> 2);
      cword = (cword << 8) + (entry->palette[i].r >> 2);
      cword = (cword << 8) + i;

      *c++ = cword;
      }

   ((VS *) (entry->shape))->offset[0].colors = ctable_offset;

   //
   // Erase shape definition from image page, so that the next one can be
   // found...
   //

   for (y=y0-1; y <= y1+1; y++)
      {
      for (x=x0-1; x <= x1+1; x++)
         {
         RGB[(y*iw)+x] = transparent;
         }
      }

   update();

   return index;
}

//****************************************************************************
//
// Windows main() function
//
//****************************************************************************

int PASCAL WinMain(HINSTANCE hInstance, //)
                   HINSTANCE hPrevInstance,
                   LPSTR     lpCmdLine,     
                   int       nCmdShow)
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
   // Register exit handler 
   //

   atexit(AppExit);

   //
   // Parse command line to get input and output file names
   //

   S32 len = strlen(lpCmdLine);

   if (!len)
      {
      SAL_alert_box("Command Help","Type \"TGA2SHP filename[.tga]\" to convert filename.tga to filename.shp");
      return 0;
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
   strcat(out_fn,".SHP");

   SAL_debug_printf("Converting \"%s\" to \"%s\"\n",in_fn,out_fn);

   //
   // Load 8BPP and 16BPP VFX libraries
   //

   HINSTANCE VFX8 = LoadLibrary("WINVFX8.DLL");

   if (VFX8 == NULL)
      {
      SAL_alert_box("Error","WINVFX8.DLL not found");
      return 0;
      }

   HINSTANCE VFX16 = LoadLibrary("WINVFX16.DLL");

   if (VFX16 == NULL)
      {
      SAL_alert_box("Error","WINVFX16.DLL not found");
      return 0;
      }

   //
   // Get procedure addresses for VFX functions
   //

   *(U32 *) (&VFX8_shape_scan)             = (U32) GetProcAddress(VFX8,"VFX_shape_scan");
   *(U32 *) (&VFX8_window_construct)       = (U32) GetProcAddress(VFX8,"VFX_window_construct");
   *(U32 *) (&VFX8_assign_window_buffer)   = (U32) GetProcAddress(VFX8,"VFX_assign_window_buffer");
   *(U32 *) (&VFX8_pane_construct)         = (U32) GetProcAddress(VFX8,"VFX_pane_construct");
   *(U32 *) (&VFX8_pane_wipe)              = (U32) GetProcAddress(VFX8,"VFX_pane_wipe");

   //
   // Load .TGA file
   //

   void *TGA = FILE_read(in_fn);

   if (TGA == NULL)
      {
      SAL_alert_box("Error","Could not read file %s", lpCmdLine);
      return 0;
      }

   RGB = (VRGB *) TGA_parse(TGA, &iw, &ih);

   if (RGB == NULL)
      {
      exit(0);
      }

   SAL_debug_printf("TGA image (%d,%d)\n",iw,ih);

   //
   // Create 16bpp display window large enough to show .TGA file and window
   // title
   //
   // Note that we can still make calls to WINVFX8 to acquire the 8bpp VFX
   // shape, even though the display mode has been established by calling 
   // WINVFX16!
   //
   // The reverse is NOT true -- many WINVFX16 calls will behave incorrectly 
   // if called prior to WINVFX16.DLL's VFX_set_display_mode() handler.
   //

   if (!VFX_set_display_mode(sw = max(iw,320), 
                             sh = max(ih,200), 
                             16, 
                             VFX_WINDOW_MODE, 
                             FALSE))
      {
      return 0;
      }

   screen      = VFX_window_construct(sw,sh);
   screen_pane = VFX_pane_construct(screen,0,0,sw-1,sh-1);

   //
   // Show initial .TGA image
   // 

   update();

   SAL_show_system_mouse();

   //
   // Get transparent color used on this frame
   //

   transparent = RGB[(iw * (ih-1)) + (iw-1)];

   SAL_debug_printf("Transparency key = (%d,%d,%d)\n",
      transparent.r,
      transparent.g,
      transparent.b);

   //
   // Set up 8bpp working window and pane 
   //

   shape      = VFX8_window_construct(iw,ih);
   shape_pane = VFX8_pane_construct(shape,0,0,iw-1,ih-1);

   VFX8_assign_window_buffer(shape, NULL, -1);

   VFX8_pane_wipe(shape_pane, PAL_TRANSPARENT);

   //
   // Initialize empty shape list
   //

   shape_list.reset();
   n_shapes = 0;

   //
   // Pass 1: Scan and process shape definitions
   //

   while (1)
      {
      //
      // Get first shape on screen, until none left
      //

      if (lift_shape() == -1)
         {
         break;
         }

      ++n_shapes;
      }

   if (n_shapes == 0)
      {
      SAL_alert_box("Error","No valid shapes found");
      return 0;
      }

   //
   // Pass 2: Merge shapes into single table
   //

   S32 header_size = 8 + (8 * n_shapes);
   S32 table_size  = header_size;
   S32 version     = SHAPE_FILE_VERSION;

   for (S32 index=0; index < shape_list.list_size; index++)
      {
      SHAPEDESC *entry = &shape_list.list[index];

      if (entry->index == -1)
         {
         continue;
         }

      table_size += (entry->size - sizeof(VS));
      version     =  entry->shape->version;
      }

   VS *master = (VS *) malloc(table_size);

   if (master == NULL)
      {
      SAL_alert_box("Error","Could not allocate output shape table");
      return 0;
      }

   master->version     = version;
   master->shape_count = n_shapes;
   
   void *copy_target = &((U8 *) master)[header_size];
   S32   n = 0;

   for (index=0; index < shape_list.list_size; index++)
      {
      SHAPEDESC *entry = &shape_list.list[index];

      if (entry->index == -1)
         {
         continue;
         }

      memcpy(copy_target,
             &((U8 *) entry->shape)[sizeof(VS)],
             entry->size - sizeof(VS));

      S32 fixup = ((U32) copy_target - (U32) master) - sizeof(VS);

      master->offset[n].shape  = entry->shape->offset[0].shape  + fixup;
      master->offset[n].colors = entry->shape->offset[0].colors + fixup;

      copy_target = &((U8 *) copy_target)[entry->size - sizeof(VS)];
      ++n;
      }

   //
   // Write shape table to disk 
   //

   if (!FILE_write(out_fn,
                   master,
                   table_size))
      {
      SAL_alert_box("Error","Could not write file \"%s\" -- write-protected or disk full?",
         out_fn);
      return 0;
      }

   //
   // Free VFX libraries
   //

   FreeLibrary(VFX8);
   FreeLibrary(VFX16);

   return 0;
}
