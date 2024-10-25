//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
//лл                                                                        лл
//лл  CTEST.C                                                               лл
//лл                                                                        лл
//лл  386FX VFX test program                                                лл
//лл                                                                        лл
//лл  Version 1.10 of  3-Dec-93: Initial release                            лл
//лл                                                                        лл
//лл  Project: 386FX Sound & Light(TM)                                      лл
//лл  Authors: John Lemberger                                               лл
//лл                                                                        лл
//лл  80386 C source compatible with WATCOM C v9.0 or later                 лл
//лл                                 MetaWare C v3.1 or later               лл
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
#include <stdlib.h>
#include <dos.h>
#include <conio.h>
#include <string.h>

#include "vfx.h"
#include "dll.h"

/*************************************************************/
void main (int argc, char *argv[])
{
   WINDOW window,panewindow, tempwindow;
   PANE backpane,pane1,pane2,pane3,temppane;
   VFX_DESC *VFX;
   LONG i,x,y,z,sx,sy,x1,y1,base;
   LONG sdx,sdy;
   LONG w,h;
	UBYTE *window_buffer;
   void *DLL,*drvr;
   POINT in, out, origin;
   void *font_buffer;
   FONT *font_header;
   LONG character, x_offset;
   LONG dummy;
   UBYTE colors[256];
   UBYTE *shape_buffer;
   UBYTE *transform_buffer;
   long ex,ey,ew,eh,ec;
   UBYTE *fpic;
   RGB palette[256];
   void *GIF_scratch;
   LONG scrollbufsize;
   UBYTE *scrollbuffer;
   LONG pixels, seed1, seed2, seed3, intervals;
   LONG flags;

   //
   // Get name of driver to use
   //

   if (argc != 2)
      {
      printf("\nUsage example: CTEST drv\\vesa480.dll\n");
      exit(1);
      }

   //
   // Load the driver DLL
   //

   DLL = FILE_read(argv[1],NULL);

   if (DLL == NULL)
      {
      printf("Missing or invalid 386FX driver\n");
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

   printf("\n  Driver name: %s\n",argv[1]);
   printf(" Screen width: %d\n",w);
   printf("Screen height: %d\n",h);
   getch();

   VFX_init_driver();

   //
   // Assign window structs & buffers
   //

	window_buffer = calloc(640 * 400,1);
	window.buffer = window_buffer;
	window.x_max = 639;
	window.y_max = 399;
   window.stencil = NULL;
   window.shadow  = NULL;

	backpane.window = &window;
	backpane.x0 = 0;
	backpane.y0 = 0;
	backpane.x1 = 639;
	backpane.y1 = 399;

	panewindow.buffer = window_buffer + 640;
	panewindow.x_max = 639;
	panewindow.y_max = 397;
   panewindow.stencil = NULL;
   panewindow.shadow  = NULL;

	pane1.window = &panewindow;
	pane1.x0 = -160;
	pane1.y0 = -100;
	pane1.x1 =  159;
	pane1.y1 =   99;

 	pane2.window = &panewindow;
	pane2.x0 =  160;
	pane2.y0 =  100;
	pane2.x1 =  479;
	pane2.y1 =  299;

 	pane3.window = &panewindow;
	pane3.x0 =  480;
	pane3.y0 =  300;
	pane3.x1 =  800;
	pane3.y1 =  500;

	tempwindow.buffer = calloc(320 * 200,1);
	tempwindow.x_max = 319;
	tempwindow.y_max = 199;
   tempwindow.stencil = NULL;
   tempwindow.shadow  = NULL;

	temppane.window = &tempwindow;
	temppane.x0 = 0;
	temppane.y0 = 0;
	temppane.x1 = 319;
	temppane.y1 = 199;

   font_buffer = FILE_read("demo.fnt",NULL);
   shape_buffer = FILE_read("demo.shp",NULL);
   transform_buffer = (UBYTE *) calloc(320 * 200, 1);

   font_header = font_buffer;

   for (x=0;x<256;x++)
      colors[x]=x;

   colors[font_header->font_background]=255;

   VFX_pane_wipe(&backpane,15);
   VFX_pane_wipe(&pane1,8);
   VFX_pane_wipe(&pane2,8);
   VFX_pane_wipe(&pane3,8);
   VFX_window_refresh(&window,0,0,w-1,h-1);

   //---------------------------------------------------------------------
   //
   // Function tests begin
   //
   //---------------------------------------------------------------------

   //
   // Point transform
   //

   origin.x=160;
   origin.y=100;


   x=0;
   VFX_pane_wipe(&pane1,8);
   VFX_pane_wipe(&pane2,8);
   VFX_pane_wipe(&pane3,8);

   for (z=0; z<=3600; z+=100)
      {
      if (kbhit()) break;

      out.x=in.x=160;
      out.y=in.y=75;

      for (y=0;y<200;y+=10)
         {
         in.y = 75 - y;

         VFX_point_transform(&in, &out, &origin, z,
            DOUBLE_TO_FIXED16(1.6), DOUBLE_TO_FIXED16(1) );

         VFX_pixel_write(&pane1,out.x,out.y,3);
         VFX_pixel_write(&pane2,out.x,out.y,3);
         VFX_pixel_write(&pane3,out.x,out.y,3);
         }

      VFX_window_refresh(&window,0,0,w-1,h-1);
      }
   getch();


   //
   // Lines
   //

   VFX_pane_wipe(&pane1,8);
   VFX_pane_wipe(&pane2,8);
   VFX_pane_wipe(&pane3,8);

   x=1;
   while (!kbhit())
      {
      x =rand()%400 - 40;
      x1=rand()%400 - 40;
      y =rand()%350 - 25;
      y1=rand()%350 - 25;
      VFX_line_draw(&pane1,x,y,x1,y1,0,x++);
      VFX_line_draw(&pane2,x,y,x1,y1,0,x++);
      VFX_line_draw(&pane3,x,y,x1,y1,0,x++);
      VFX_window_refresh(&window,0,0,w-1,h-1);
      }
   getch();


   //
   // Rectangle hash
   //

   VFX_pane_wipe(&pane1,8);
   VFX_pane_wipe(&pane2,8);
   VFX_pane_wipe(&pane3,8);

   VFX_rectangle_hash(&pane1, 80, 50, 240, 150, 0);
   VFX_rectangle_hash(&pane2, 80, 50, 240, 150, 0);
   VFX_rectangle_hash(&pane3, 80, 50, 240, 150, 0);

   VFX_window_refresh(&window,0,0,w-1,h-1);

   getch();

   VFX_pane_wipe(&pane1,8);
   VFX_pane_wipe(&pane2,8);
   VFX_pane_wipe(&pane3,8);

   VFX_rectangle_hash(&pane1, -10, -10, 330, 210, 0);
   VFX_rectangle_hash(&pane2, -10, -10, 330, 210, 0);
   VFX_rectangle_hash(&pane3, -10, -10, 330, 210, 0);

   VFX_window_refresh(&window,0,0,w-1,h-1);

   getch();

   //
   // Shape draw
   //

   base = 0;
   while (!kbhit())
      {
	   VFX_pane_wipe(&pane1,8);
	   VFX_pane_wipe(&pane2,8);
	   VFX_pane_wipe(&pane3,8);

      for (y=-35;y<228;y+=36)
         for (x=-40;x<320;x+=50)
            {
            VFX_shape_draw(&pane1,shape_buffer,0,x+base,y+base);
            VFX_shape_draw(&pane2,shape_buffer,0,x+base,y+base);
            VFX_shape_draw(&pane3,shape_buffer,0,x+base,y+base);
            }

      base = (base+3+(rand()%3))%40;

      VFX_window_refresh(&window,0,0,w-1,h-1);
      }
   getch();


   //
   // Shape transform
   //

   z=0;
   base = 0;
   sx=0x10000;
   sy=0x10000;
   sdx = 0x1000;
   sdy = 0x1000;

   while (!kbhit())
      {
      z+=100;
      z = z > 3599 ? 0 : z;
   
      if (sx > 0x20000)
         sdx = -0x1000;
      if (sx < 0x02000)
         sdx = 0x1000;
      sx += sdx;

      if (sy > 0x20000)
         sdy = -0x1000;
      if (sy < 0x02000)
         sdy = 0x1000;
      sy += sdy;

      VFX_pane_wipe(&pane1,8);
      VFX_pane_wipe(&pane2,8);
      VFX_pane_wipe(&pane3,8);

      flags = 0;

      for (y=-35;y<228;y+=36)
         for (x=-40;x<320;x+=50)
            {
            VFX_shape_transform(&pane1,shape_buffer,0,x+base,y+base,
               transform_buffer, z, sx, sy, flags);
            VFX_shape_transform(&pane2,shape_buffer,0,x+base,y+base,
               transform_buffer, z, sx, sy, flags);
            VFX_shape_transform(&pane3,shape_buffer,0,x+base,y+base,
               transform_buffer, z, sx, sy, flags);
            flags = ST_REUSE;
            }

      base = (base+3+(rand()%3))%40;

      VFX_window_refresh(&window,0,0,w-1,h-1);
      }
   getch();

   //
   // Pane scroll
   //

   x=y=2;

   while (!kbhit())
      {
      scrollbufsize = VFX_pane_scroll(&pane2, x,y, PS_WRAP, 0);
      scrollbuffer = malloc(scrollbufsize);
      scrollbufsize = VFX_pane_scroll(&pane2, x,y, PS_WRAP, (LONG) scrollbuffer);
      free(scrollbuffer);

      VFX_pane_copy(&pane2,0,0, &pane1,0,0, NO_COLOR);
      VFX_pane_copy(&pane2,0,0, &pane3,0,0, NO_COLOR);

      VFX_window_refresh(&window,0,0,w-1,h-1);
      }

   getch();

   //
   // Ellipses
   //

   VFX_pane_wipe(&pane1,8);
   VFX_pane_wipe(&pane2,8);
   VFX_pane_wipe(&pane3,8);

   x=1;
   while (!kbhit())
      {
      ex = rand()%319;
      ey = rand()%199;
      ew = rand()%10-1;
      eh = rand()%10-1;
      ec = (x++ & 0x0ff);

      VFX_ellipse_draw(&pane1,ex,ey,ew,eh,ec);
      VFX_ellipse_draw(&pane2,ex,ey,ew,eh,ec);
      VFX_ellipse_draw(&pane3,ex,ey,ew,eh,ec);

      VFX_window_refresh(&window,0,0,w-1,h-1);
      }
   getch();

   VFX_pane_wipe(&pane1,8);
   VFX_pane_wipe(&pane2,8);
   VFX_pane_wipe(&pane3,8);
   x=1;
   while (!kbhit())
      {
      ex = rand()%319;
      ey = rand()%199;
      ew = rand()%10-1;
      eh = rand()%10-1;
      ec = (x++ & 0x0ff);

      VFX_ellipse_fill(&pane1,ex,ey,ew,eh,ec);
      VFX_ellipse_fill(&pane2,ex,ey,ew,eh,ec);
      VFX_ellipse_fill(&pane3,ex,ey,ew,eh,ec);

      VFX_window_refresh(&window,0,0,w-1,h-1);
      }
   getch();

   VFX_pane_wipe(&pane1,8);
   VFX_pane_wipe(&pane2,8);
   VFX_pane_wipe(&pane3,8);
   x=1;
   while (!kbhit())
      {
      ex = rand()%319;
      ey = rand()%199;
      ew = rand()%319;
      eh = rand()%199;
      ec = (x++ & 0x0ff);

      VFX_ellipse_draw(&pane1,ex,ey,ew,eh,ec);
      VFX_ellipse_draw(&pane2,ex,ey,ew,eh,ec);
      VFX_ellipse_draw(&pane3,ex,ey,ew,eh,ec);

      VFX_window_refresh(&window,0,0,w-1,h-1);
      }
   getch();
   VFX_pane_wipe(&pane1,8);
   VFX_pane_wipe(&pane2,8);
   VFX_pane_wipe(&pane3,8);
   x=1;
   while (!kbhit())
      {
      ex = rand()%319;
      ey = rand()%199;
      ew = rand()%319;
      eh = rand()%199;
      ec = (x++ & 0x0ff);

      VFX_ellipse_fill(&pane1,ex,ey,ew,eh,ec);
      VFX_ellipse_fill(&pane2,ex,ey,ew,eh,ec);
      VFX_ellipse_fill(&pane3,ex,ey,ew,eh,ec);

      VFX_window_refresh(&window,0,0,w-1,h-1);
      }
   getch();

   //
   // Character functions
   //

   y=1;
   for (x=20;x>-317;x--)
      {
      if (kbhit()) break;

      VFX_pane_wipe(&pane1,8);
      VFX_pane_wipe(&pane2,8);
      VFX_pane_wipe(&pane3,8);

      x_offset=0;
      for (character=0;character<font_header->char_count;character++)
         {
         dummy=VFX_character_draw(&pane1, x+x_offset, y, font_buffer, character, NULL);
         dummy=VFX_character_draw(&pane2, x+x_offset, y, font_buffer, character, NULL);
         dummy=VFX_character_draw(&pane3, x+x_offset, y, font_buffer, character, NULL);

         dummy=VFX_character_draw(&pane1, x+x_offset, y+10, font_buffer, character, colors);
         dummy=VFX_character_draw(&pane2, x+x_offset, y+10, font_buffer, character, colors);
         x_offset+=VFX_character_draw(&pane3, x+x_offset, y+10, font_buffer, character, colors);
         }

      VFX_window_refresh(&window,0,0,w-1,h-1);
      }
   getch();

   VFX_pane_wipe(&pane1,8);
   VFX_pane_wipe(&pane2,8);
   VFX_pane_wipe(&pane3,8);

   x=1;
   for (y=-75;y>-505;y--)
      {
      if (kbhit()) break;

      VFX_pane_wipe(&pane1,8);
      VFX_pane_wipe(&pane2,8);
      VFX_pane_wipe(&pane3,8);

      x_offset=0;
      for (character=0;character<font_header->char_count;character++)
         {
         dummy=VFX_character_draw(&pane1, x, y+x_offset, font_buffer, character, NULL);
         dummy=VFX_character_draw(&pane1, x+10, y+x_offset, font_buffer, character, colors);
         dummy=VFX_character_draw(&pane2, x, y+x_offset, font_buffer, character, NULL);
         dummy=VFX_character_draw(&pane2, x+10, y+x_offset, font_buffer, character, colors);
         dummy=VFX_character_draw(&pane3, x, y+x_offset, font_buffer, character, NULL);
         dummy=VFX_character_draw(&pane3, x+10, y+x_offset, font_buffer, character, colors);
         x_offset+=VFX_font_height(font_buffer);
         }

      VFX_window_refresh(&window,0,0,w-1,h-1);

      }
   getch();

   //
   // LBM draw
   //

   fpic=FILE_read("nlavga.lbm",NULL);
   VFX_ILBM_palette(fpic, palette);

   for (i=0;i<=255;i++)
      VFX_DAC_write(i,&palette[i]);

   VFX_ILBM_draw(&pane1,fpic);
   VFX_ILBM_draw(&pane2,fpic);
   VFX_ILBM_draw(&pane3,fpic);

   VFX_window_refresh(&window,0,0,w-1,h-1);

   getch();

   //
   // Pixel fade
   //

   VFX_pane_wipe(&temppane,254);

   intervals = 25;
   pixels = PIXELS_IN_PANE(pane1) / intervals;
   seed1 = seed2 = seed3 = 0;
   for (i=0;i<intervals && !kbhit() ;i++)
      {
      seed1 = VFX_pixel_fade(&temppane, &pane1, pixels, seed1);
      seed2 = VFX_pixel_fade(&temppane, &pane2, pixels, seed2);
      seed3 = VFX_pixel_fade(&temppane, &pane3, pixels, seed3);
      VFX_window_refresh(&window,0,0,w-1,h-1);
      }

   getch();

   //
   // PCX draw
   //

   fpic=FILE_read("nlavga.pcx",NULL);
   VFX_PCX_palette(fpic, FILE_size("nlavga.pcx"), palette);

   for (i=0;i<=255;i++)
      VFX_DAC_write(i,&palette[i]);

   VFX_PCX_draw(&pane1,fpic);
   VFX_PCX_draw(&pane2,fpic);
   VFX_PCX_draw(&pane3,fpic);

   VFX_window_refresh(&window,0,0,w-1,h-1);

   getch();

   //
   // Pixel fade
   //

   intervals = 25;
   pixels = PIXELS_IN_PANE(pane1) / intervals;
   seed1 = seed2 = seed3 = 0;
   for (i=0;i<intervals && !kbhit() ;i++)
      {
      seed1 = VFX_pixel_fade(&temppane, &pane1, pixels, seed1);
      seed2 = VFX_pixel_fade(&temppane, &pane2, pixels, seed2);
      seed3 = VFX_pixel_fade(&temppane, &pane3, pixels, seed3);
      VFX_window_refresh(&window,0,0,w-1,h-1);
      }

   getch();

   //
   // GIF draw
   //
   fpic=FILE_read("nlavga.GIF",NULL);
   VFX_GIF_palette(fpic, palette);

   for (i=0;i<=255;i++)
      VFX_DAC_write(i,&palette[i]);

   GIF_scratch=malloc(GIF_SCRATCH_SIZE);

   VFX_GIF_draw(&pane1,fpic,GIF_scratch);
   VFX_GIF_draw(&pane2,fpic,GIF_scratch);
   VFX_GIF_draw(&pane3,fpic,GIF_scratch);

   free(GIF_scratch);

   VFX_window_refresh(&window,0,0,w-1,h-1);

   getch();

   VFX_shutdown_driver();
}


