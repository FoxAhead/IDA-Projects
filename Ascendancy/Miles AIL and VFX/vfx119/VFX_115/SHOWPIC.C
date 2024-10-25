//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
//лл                                                                        лл
//лл  SHOWPIC.C                                                             лл
//лл                                                                        лл
//лл  386FX LBM, PCX, and GIF viewer                                        лл
//лл                                                                        лл
//лл  Version 0.10 of 10-Dec-92: Created                                    лл
//лл  Version 1.00 of  1-Mar-93: Initial release                            лл
//лл  Version 1.10 of  1-Mar-93: New shape format                           лл
//лл  Version 1.10 of  3-Dec-93: Updated to use new WINDOW structure        лл
//лл  Version 1.20 of 16-Feb-94: Added .FLI & .FLC support                  лл
//лл  Version 1.21 of 12-Aug-95: Use 1024x768x256 mode                      лл
//лл                                                                        лл
//лл  Project: 386FX Sound & Light(TM)                                      лл
//лл  Authors: John Lemberger, John Miles                                   лл
//лл                                                                        лл
//лл  80386 C source compatible with WATCOM C v9.0 or later                 лл
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

#include <stdio.h>
#include <malloc.h>
#include <dos.h>
#include <stdlib.h>
#include <io.h>
#include <fcntl.h>
#include <string.h>
#include <conio.h>

#include "vfx.h"
#include "dll.h"
#include "flic.h"

WINDOW window;
PANE pane;

FLIC flic;

RGB palette[256];
RGB black[256];

#define LBM 1
#define PCX 2
#define GIF 3
#define SHP 4

#undef min
#define min(a,b) ((a) < (b) ? (a) : (b))

/************************************************************/
void flic_info(FLIC *flic)
{
   printf("Size      :  0x%08x (%d)\n",flic->header->size,flic->header->size);
   printf("Type      :  %s\n",
      flic->header->type==0x0af11?".FLI" :
      flic->header->type==0x0af12?".FLC" : "????");
   printf("Frames    :  %d\n",flic->header->frames     );
   printf("Width     :  %d\n",flic->header->width      );
   printf("Height    :  %d\n",flic->header->height     );
   printf("Depth     :  %d\n",flic->header->depth      );
   printf("Speed     :  %d  ",flic->header->speed      );
      printf("%s\n",
         flic->header->type==0x0af11 ? "1/70ths of a second":
         flic->header->type==0x0af12 ? "milliseconds" : "????");
   printf("X aspect  :  %d\n",flic->header->aspectx    );
   printf("Y aspect  :  %d\n",flic->header->aspecty    );
}

/************************************************************/
void shape_info(UBYTE *fpic, ULONG shape_number)
{
   LONG temp;

   printf("# shapes  :  %d\n", VFX_shape_count(fpic));
   printf("# unique  :  %d\n", VFX_shape_list(fpic,NULL));
   printf("# palettes:  %d\n", VFX_shape_palette_list(fpic, NULL));
   printf("Shape #   :  %d\n", shape_number);
   temp = VFX_shape_bounds(fpic, shape_number);
   printf("Bounds    :  %d, %d\n",temp >> 16, (temp << 16) >> 16);
   temp = VFX_shape_origin(fpic, shape_number);
   printf("Origin    :  %d, %d\n",temp >> 16, (temp << 16) >> 16);
   temp = VFX_shape_resolution(fpic, shape_number);
   printf("Resolution:  %d, %d\n",temp >> 16, (temp << 16) >> 16);
   temp = VFX_shape_minxy(fpic, shape_number);
   printf("MinXY     :  %d, %d\n",temp >> 16, (temp << 16) >> 16);
}
/************************************************************/
void fail(int errcode)
{
   static char errs[][80] =
     {{ "Error: Input file format must be .LBM, .PCX, .GIF, .SHP, .FLI, or .FLC"},
      { "Error: Not enough memory available"                             },
      { "Error: Could not open input file"                               },
      { "Error: Shape number out of range"                               },
      { "Error: Incorrect shape file version -- rebuild with GETSHAPE"   },
      { "Error: Bad frame in .FLI or .FLC"                               },
      { "Error: Frame number out of range"                               }
     };

   VFX_shutdown_driver();
   printf("%s\n",errs[errcode]);

   if (errcode == 5 || errcode == 6)
      flic_info(&flic);

   fcloseall();
   exit(errcode+1);
}

/************************************************************/
//
// Standard C routine for determining a VFX driver's full pathname
// 
// program:  The full pathname of the calling program (argv[0]).  This
//           pathname is assumed to contain the DRV\ directory in which
//           the application's VFX DLL drivers reside.
//
// filename: The filename (only) of the desired DLL driver.
//
// dest:     DLL_pathname() will write a copy of the calling application's
//           directory pathname to *dest, and will then append the
//           string \drv\filename.  The resulting pathname can be used
//           to access the specified DLL in a standardized manner.
// 
// Returns:  A pointer to *dest.
// 
// To ensure proper operation in network and other non-standard DOS 
// environments, the *dest array should be no smaller than 256 bytes.
// 
/************************************************************/

BYTE *DLL_pathname(BYTE *program, BYTE *filename, BYTE *dest)
{
   WORD i;

   strcpy(dest,program);
   strupr(dest);

   for (i=strlen(dest)-1;i>=0;i--)
      if (dest[i] == '\\')
         {
         dest[i] = 0;
         break;
         }

   strcat(dest,"\\DRV\\");
   strcat(dest,filename);

   return dest;
}

/************************************************************/
void main(int argc, char *argv[])
{
   LONG i;
   ULONG shape_number;
   LONG resolution,max_x,max_y,minxy;
   VFX_DESC *VFX;
   LONG w,h;
   void *DLL,*drvr;
	UBYTE *window_buffer;
   void *GIF_scratch;
   LONG fpic_type;
   LONG flic_status;
   UBYTE *fpic;
   ULONG frame_count=0;
   ULONG flic_new_colors = 0;
   LONG  temp, bound_x, bound_y, origin_x, origin_y;

   printf("SHOWPIC V1.21     1024x768        Copyright (C) 1992-1994 Non-Linear Arts, Inc.\n\n");

   if (argc < 2)
      {
      printf("Usage: SHOWPIC infile [frame||shape number] [/NS]\n\n");
      printf("where: infile = 256-color .LBM, .PCX, .GIF, .FLI, .FLC or 386FX .SHP\n");
      printf("       frame number = frame in .FLI or .FLC file to display\n");
      printf("       shape number = shape in .SHP file to display\n");
      printf("       /NS = No Scaling to screen size; show actual size or smaller\n");

      exit(1);      
      }

   //
   // Load VESA768.DLL
   //

   DLL = FILE_read("DRV\\VESA768.DLL",NULL);

   if (DLL == NULL)
      {
      printf("Could not open DRV\\VESA768.DLL\n");
      exit(1);
      }

   drvr = DLL_load(DLL,DLLMEM_ALLOC | DLLSRC_MEM,NULL);

   if (drvr == NULL)     
      {
      printf("Invalid DLL image\n");
      exit(1);
      }

   free(DLL);

   //
   // Register the driver with the API
   //

   VFX_register_driver(drvr);

   VFX = VFX_describe_driver();

   w = VFX->scrn_width;
   h = VFX->scrn_height;

   //
   // Check for .LBM or .PCX extension
   //

   fpic_type = 0;

   if ( stricmp(".LBM",&argv[1][strlen(argv[1])-4]) == 0 )
      fpic_type=LBM;
   else if ( stricmp(".PCX",&argv[1][strlen(argv[1])-4]) == 0 )
      fpic_type=PCX;
   else if ( stricmp(".GIF",&argv[1][strlen(argv[1])-4]) == 0 )
      fpic_type=GIF;
   else if ( stricmp(".SHP",&argv[1][strlen(argv[1])-4]) == 0 )
      fpic_type=SHP;
   else if ( stricmp(".FLI",&argv[1][strlen(argv[1])-4]) == 0 )
      fpic_type=FLI;
   else if ( stricmp(".FLC",&argv[1][strlen(argv[1])-4]) == 0 )
      fpic_type=FLC;
   else
      fail(0);

   //
   // Load file
   //

   if ((fpic=FILE_read(argv[1],NULL)) == NULL) fail(2);

   VFX_init_driver();

   //
   // Get default palette
   //

   for (i=0;i<=255;i++)
      VFX_DAC_read(i,&palette[i]);

   //
   // Get resolution of image
   //

   shape_number = 0;

   switch (fpic_type)
      {
      case LBM:
         resolution = VFX_ILBM_resolution(fpic);
         VFX_ILBM_palette(fpic, palette);
         break;

      case PCX:
         resolution = VFX_PCX_resolution(fpic);
         VFX_PCX_palette(fpic, FILE_size(argv[1]), palette);
         break;

      case GIF:
         resolution = VFX_GIF_resolution(fpic);
         VFX_GIF_palette(fpic, palette);
         break;

      case SHP:
         shape_number=atoi(argv[2]);
         if (VFX_shape_count(fpic) <= shape_number)
            fail(3);

         resolution = VFX_shape_resolution(fpic, shape_number);
         VFX_shape_palette(fpic,shape_number,palette);
         break;

      case FLI:
      case FLC:
         flic.header = (FLIC_HEADER *)fpic;
         flic.frame  = NULL;
         flic.chunk  = NULL;

         shape_number=atoi(argv[2]);
         if (flic.header->frames < shape_number)
            fail(6);

         resolution = (flic.header->width << 16) | flic.header->height;
         break;

      default:
         resolution = 0;
         fail(0);
      }
   max_x=(resolution>>16)-1;
   max_y=(resolution&0x0ffff)-1;

   //
   // Set up pane and window
   //

	window_buffer = calloc((resolution >> 16) * (resolution & 0x0ffff),1);
	window.buffer = window_buffer;
   window.stencil = window.shadow = NULL;
	pane.x0= 0;
	pane.y0= 0;
	pane.x1=window.x_max = max_x;
	pane.y1=window.y_max = max_y;
	pane.window = &window;

   for (i=0;i<=255;i++)
      {
      black[i].r=0;
      black[i].g=0;
      black[i].b=0;

      VFX_DAC_write(i,&black[0]);
      }

   VFX_pane_wipe(&pane,39);

   if (fpic_type == FLI || fpic_type == FLC)
      {
      //
      // Loop thru frames in FLIC
      //

      while ( !kbhit() && (shape_number!=frame_count || !shape_number) )
         {
         if ( (flic_status = FLIC_frame_draw(&pane,&flic,&palette[0])) == -1 )
            fail(5);

         flic_new_colors |= flic_status & FLIC_NEW_COLORS;

         if (!shape_number || shape_number==++frame_count)
            {
            if ((strstr(argv[argc-1],"/ns")!=NULL) ||
                (strstr(argv[argc-1],"/NS")!=NULL))
               VFX_window_refresh(&window,0,0,min(w-1,max_x),min(h-1,max_y));
            else
               VFX_window_refresh(&window,0,0,w-1,h-1);

            if (flic_new_colors)
               {
               flic_new_colors = 0;

               for (i=0;i<=255;i++)
                  {
                  VFX_DAC_write(i,&palette[i]);
                  }
               }
            }
         }
      }
   else if ( fpic_type == SHP && !strcmpi(argv[2], "ALL") )
      {
      //
      // Set up pane and window
      //
      free(window_buffer);

      temp = VFX_shape_bounds(fpic, shape_number);
      bound_x = temp >> 16;
      bound_y = (temp << 16) >> 16;

	   window_buffer = calloc((bound_x+1) * (bound_y+1),1);
	   window.buffer = window_buffer;
      window.stencil = window.shadow = NULL;
	   pane.x0= 0;
	   pane.y0= 0;
	   pane.x1=window.x_max = bound_x;
	   pane.y1=window.y_max = bound_y;
	   pane.window = &window;

      //
      // Loop thru shapes in file
      //

      shape_number = 0;
      while ( !kbhit() )
         {
         temp = VFX_shape_origin(fpic, shape_number);
         origin_x = temp >> 16;
         origin_y = (temp << 16) >> 16;

         VFX_pane_wipe(&pane, 0);

         minxy=VFX_shape_minxy(fpic, shape_number);
         VFX_shape_draw(&pane,fpic,shape_number,origin_x,origin_y);
         VFX_shape_palette(fpic,shape_number,palette);

         if ((strstr(argv[argc-1],"/ns")!=NULL) ||
            (strstr(argv[argc-1],"/NS")!=NULL))
            VFX_window_refresh(&window,0,0,min(w-1,max_x),min(h-1,max_y));
         else
            VFX_window_refresh(&window,0,0,w-1,h-1);

         for (i=0;i<=255;i++)
            VFX_DAC_write(i,&palette[i]);

         if ( VFX_shape_count(fpic) <= ++shape_number )
            shape_number=0;
         }
      }
   else
      {
      //
      // Draw image
      //

      switch (fpic_type)
         {
         case LBM:
            VFX_ILBM_draw(&pane,fpic);
            break;

         case PCX:
            VFX_PCX_draw(&pane,fpic);
            break;

         case GIF:
            if ( (GIF_scratch=malloc(GIF_SCRATCH_SIZE))==NULL )
               fail(1);
            VFX_GIF_draw(&pane,fpic,GIF_scratch);
            free(GIF_scratch);
            break;

         case SHP:
            minxy=VFX_shape_minxy(fpic, shape_number);
            VFX_shape_draw(&pane,fpic,shape_number,-(minxy>>16),-(minxy<<16>>16)); 
            break;

         default:
            fail(0);
         }
   
      if ((strstr(argv[argc-1],"/ns") != NULL) ||
         (strstr(argv[argc-1],"/NS") != NULL))
         VFX_window_refresh(&window,0,0,min(w-1,max_x),min(h-1,max_y));
      else
         VFX_window_refresh(&window,0,0,w-1,h-1);

      VFX_window_fade(&window,palette,30);

      while (kbhit()) getch();
      }
   getch();

   VFX_window_fade(&window,black,30);

   VFX_shutdown_driver();
   
   if (fpic_type == FLI || fpic_type == FLC)
      {
      printf("Filename  :  %s \n",argv[1]);
      flic_info(&flic);
      }
   else if (fpic_type == SHP)
      {
      printf("Filename  :  %s \n",argv[1]);
      shape_info(fpic, shape_number);
      }
   else
      printf("Image size: %d x %d\n",max_x+1,max_y+1);

   free(window_buffer);
}











