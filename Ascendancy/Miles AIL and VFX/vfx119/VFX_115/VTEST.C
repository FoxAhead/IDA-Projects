//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
//лл                                                                        лл
//лл  VTEST.C                                                               лл
//лл                                                                        лл
//лл  386FX VFX test program                                                лл
//лл                                                                        лл
//лл  Version 0.10 of 24-Jan-93: Preliminary release                        лл
//лл  Version 1.00 of  1-Mar-93: Initial release                            лл
//лл  Version 1.01 of 16-Nov-93: MetaWare support added                     лл
//лл  Version 1.10 of  3-Dec-93: Updated to use new WINDOW structure        лл
//лл                             Updated VFX_pixel_fade() call              лл
//лл                                                                        лл
//лл  Project: 386FX Sound & Light(TM)                                      лл
//лл  Authors: Ken Arnold, John Miles                                       лл
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
   WINDOW window,window2;
   PANE pane,pane2,pane3;
   VFX_DESC *VFX;
   LONG x,y,base,x1,y1;
   LONG w,h;
	UBYTE *window_buffer;
   void *DLL,*drvr;
   RGB ct1,ct2,ct3;
   POINT in, out, origin;
   void *font_buffer;
   FONT *font_header;
   LONG character, x_offset, x_offset1;
   UBYTE colors[256];
   UBYTE *shape_buffer;
   UBYTE *fpic;
   LONG i,pixels,seed,intervals;
   RGB palette[256];

   //
   // Get name of driver to use
   //

   if (argc != 2)
      {
      printf("\nUsage example: VTEST drv\\vesa480.dll\n");
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
   window.stencil = window.shadow = NULL;
	window.x_max = 639;
	window.y_max = 399;

	window2.buffer = calloc(640 * 400,1);
   window2.stencil = window2.shadow = NULL;
	window2.x_max = 639;
	window2.y_max = 399;

	pane.window = &window;
	pane.x0 = 0;
	pane.y0 = 0;
	pane.x1 = 639;
	pane.y1 = 399;

 	pane2.window = &window2;
	pane2.x0 = 0;
	pane2.y0 = 0;
	pane2.x1 = 639;
	pane2.y1 = 399;

 	pane3.window = &window;
	pane3.x0 = 0;
	pane3.y0 = 20;
	pane3.x1 = 19;
	pane3.y1 = 399;

   font_buffer = FILE_read("demo.fnt",NULL);
   shape_buffer = FILE_read("demo.shp",NULL);

   font_header = font_buffer;

   for (x=0;x<256;x++)
      colors[x]=x;

   colors[font_header->font_background]=255;

   VFX_pane_wipe(&pane,0);
   VFX_window_refresh(&window,0,0,w-1,h-1);

   //
   // LBM draw
   //

   fpic=FILE_read("logo400.lbm",NULL);
   VFX_ILBM_palette(fpic, palette);

   for (i=0;i<=255;i++)
      VFX_DAC_write(i,&palette[i]);

   VFX_ILBM_draw(&pane2,fpic);

   //
   // Pixel fade
   //

   intervals = 25;
   pixels = PIXELS_IN_PANE(pane) / intervals;
   seed = 0;
   for (i=0;i<intervals;i++)
      {
      seed = VFX_pixel_fade(&pane2, &pane, pixels, seed);
      VFX_window_refresh(&window,0,0,w-1,h-1);
      if (kbhit())
         {
         VFX_pane_copy(&pane2, 0,0, &pane, 0,0, NO_COLOR);
         VFX_window_refresh(&window,0,0,w-1,h-1);
         getch();
         break;
         }
      }

   if (!kbhit()) getch();

   VFX_pane_wipe(&pane2,8);

   //
   // Pixel fade
   //

   intervals = 25;
   pixels = PIXELS_IN_PANE(pane) / intervals;
   seed = 0;
   for (i=0;i<intervals;i++)
      {
      seed = VFX_pixel_fade(&pane2, &pane, pixels, seed);
      VFX_window_refresh(&window,0,0,w-1,h-1);
      if (kbhit())
         {
         VFX_pane_copy(&pane2, 0,0, &pane, 0,0, NO_COLOR);
         break;
         }
      }
   VFX_window_refresh(&window,0,0,w-1,h-1);

   if (kbhit()) getch();

   free(window2.buffer);

 	pane2.window = &window;
	pane2.x0 = 20;
	pane2.y0 = 0;
	pane2.x1 = 619;
	pane2.y1 = 19;

   //
   // Character Draw
   //
   x1=1;
   y=1;
   for (x=40 ,y1=h-350 ; x>-633 && y1>-1010 ; x-- ,y1-- )
      {
      if (kbhit()) break;

      VFX_pane_wipe(&pane2,8);
      VFX_pane_wipe(&pane3,8);

      x_offset=0;
      x_offset1=0;
      for (character=0;character<font_header->char_count;character++)
         {
         VFX_character_draw(&pane2, x+x_offset, y, font_buffer, character, NULL);
         x_offset += VFX_character_draw(&pane2, x+x_offset, y+10, font_buffer, character, colors);
         VFX_character_draw(&pane3, x1,    y1+x_offset1, font_buffer, character, NULL);
         VFX_character_draw(&pane3, x1+10, y1+x_offset1, font_buffer, character, colors);
         x_offset1 += VFX_font_height(font_buffer);
         }
      VFX_pane_refresh(&pane2, pane2.x0, pane2.y0, pane2.x1, pane2.y1);
      VFX_pane_refresh(&pane3, pane3.x0, pane3.y0, pane3.x1, pane3.y1);
      }
   getch();

   //
   // Point transform
   //

   origin.x=320;
   origin.y=200;

   out.x=in.x=320;
   out.y=in.y=150;

   x=0;
   VFX_pane_wipe(&pane,8);
   for (x=0; x<=3600; x+=100)
      {
      if (kbhit()) break;

      VFX_point_transform(&in, &out, &origin, x,
         DOUBLE_TO_FIXED16(1.6), DOUBLE_TO_FIXED16(1) );
      VFX_pixel_write(&pane,out.x,out.y,3);
      VFX_window_refresh(&window,0,0,w-1,h-1);
      }
   getch();

   //
   // Ellipses
   //

   VFX_pane_wipe(&pane,8);
   x=1;
   while (!kbhit())
      {
      y=rand()%399;
      VFX_line_draw(&pane,y,y,y,y,0,x++);
      VFX_window_refresh(&window,0,0,w-1,h-1);
      }
   getch();
   x=1;
   while (!kbhit())
      {
      VFX_ellipse_draw(&pane,rand()%639,rand()%399,rand()%10-1,rand()%10-1,x++ & 0x0ff);
      VFX_window_refresh(&window,0,0,w-1,h-1);
      }
   getch();

   VFX_pane_wipe(&pane,8);
   x=1;
   while (!kbhit())
      {
      VFX_ellipse_fill(&pane,rand()%639,rand()%399,rand()%10-1,rand()%10-1,x++ & 0x0ff);
      VFX_window_refresh(&window,0,0,w-1,h-1);
      }
   getch();

   VFX_pane_wipe(&pane,8);
   x=1;
   while (!kbhit())
      {
      VFX_ellipse_draw(&pane,rand()%639,rand()%399,rand()%639,rand()%399,x++ & 0x0ff);
      VFX_window_refresh(&window,0,0,w-1,h-1);
      }
   getch();
   VFX_pane_wipe(&pane,8);
   x=1;
   while (!kbhit())
      {
      VFX_ellipse_fill(&pane,rand()%639,rand()%399,rand()%639,rand()%399,x++ & 0x0ff);
      VFX_window_refresh(&window,0,0,w-1,h-1);
      }
   getch();

   //
   // Shape draw
   //

   base = 0;
   while (!kbhit())
      {
	   VFX_pane_wipe(&pane,8);

      for (y=-35;y<455;y+=36)
         for (x=-40;x<680;x+=50)
            VFX_shape_draw(&pane,shape_buffer,0,x+base,y+base);

      base = (base+3+(rand()%3))%40;

      VFX_window_refresh(&window,0,0,w-1,h-1);
      }
   getch();

   //
   // Test window read & scaling
   //

   //
   // No scaling
   //

   VFX_window_read(&window,0,0,w-1,h-1);
   VFX_window_refresh(&window,0,0,w-1,h-1);
   getch();

   //
   // Y scaling
   // 

   for (x=0,y=0;y<=(h/4);y+=(h/8))
      {
      if (kbhit()) break;

      VFX_window_read(&window,x,y,w-x-1,h-y-1);
      VFX_window_refresh(&window,0,0,w-1,h-1);
      }
   getch();

	VFX_pane_wipe(&pane,8);
   for (y=-35;y<455;y+=36)
      for (x=-40;x<680;x+=50)
         VFX_shape_draw(&pane,shape_buffer,0,x+base,y+base);
   VFX_window_refresh(&window,0,0,w-1,h-1);

   //
   // XY scaling
   //

   for ( x=0,y=0; y<=(h/4); y+=(h/8),x+=(w/8) )
      {
      if (kbhit()) break;

      VFX_window_read(&window,x,y,w-x-1,h-y-1);
      VFX_window_refresh(&window,0,0,w-1,h-1);
      }
   getch();

   //
   // Shape draw
   //

	window.x_max = 319;
	window.y_max = 199;

   base = 0;
   while (!kbhit())
      {
	   VFX_pane_wipe(&pane,8);

      for (y=-35;y<455;y+=36)
         for (x=-40;x<680;x+=50)
            VFX_shape_draw(&pane,shape_buffer,0,x+base,y+base);

      base = (base+3+(rand()%3))%40;

      VFX_window_refresh(&window,0,0,w-1,h-1);
      }
   getch();

   //
   // Test area wipe
   //

   for (x=w/2,y=h/2;y>0;x--,y--)
      {
      if (kbhit()) break;

      VFX_area_wipe(w/2-x,h/2-y,w/2+x-1,h/2+y-1,x&0xff);
      }
   getch();

   //
   // Test DAC read & write
   //

   VFX_DAC_read(1,&ct1);                  // Save color value
   VFX_DAC_read(2,&ct2);                  // Save color value
   VFX_area_wipe(0,0,w-1,h-1,1);        
   VFX_area_wipe(w/4,h/4,w-w/4,h-h/4,2);        
   x=y=0;

   while (!kbhit())
      {
      ct3.r =    ++x & 0x3f;              // Compute new value
      ct3.g = (x>>3) & 0x3f;
      ct3.b = (x>>6) & 0x3f;

      VFX_DAC_write(1,&ct3);              // Write next value

      ct3.r =    --y & 0x3f;              // Compute new value
      ct3.g = (y>>3) & 0x3f;
      ct3.b = (y>>6) & 0x3f;

      VFX_wait_vblank();                  // Avoid flicker on color change
      VFX_DAC_write(2,&ct3);              // Write next value
      }
   getch();

   VFX_DAC_write(1,&ct1);                 // Restore color value
   VFX_DAC_write(2,&ct2);                 // Restore color value

   VFX_shutdown_driver();
}

