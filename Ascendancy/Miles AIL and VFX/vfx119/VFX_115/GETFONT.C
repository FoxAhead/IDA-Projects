//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
//лл                                                                        лл
//лл  GETFONT.C                                                             лл
//лл                                                                        лл
//лл  386FX font creation utility                                           лл
//лл                                                                        лл
//лл  Version 0.10 of 10-Dec-92: Created                                    лл
//лл  Version 1.00 of  1-Mar-93: Initial release                            лл
//лл  Version 1.01 of 19-May-93: PCX files require explicit background      лл
//лл  Version 1.10 of  3-Dec-93: Updated to use new WINDOW structure        лл
//лл  Version 1.11 of 11-Aug-95: Works with >320x200 input resolutions      лл
//лл  Version 1.20 of 24-Oct-97: Append palette to end of font file         лл
//лл                                                                        лл
//лл  Project: 386FX Sound & Light(TM)                                      лл
//лл  Authors: John Lemberger, John Miles                                   лл
//лл                                                                        лл
//лл  80386 C source compatible with WATCOM C v9.0 or later                 лл
//лл                                                                        лл
//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
//лл                                                                        лл
//лл  Copyright (C) 1992-1997 Miles Design, Inc.                            лл
//лл                                                                        лл
//лл  Miles Design, Inc.                                                    лл
//лл  8301 Elander Drive                                                    лл
//лл  Austin, TX 78750                                                      лл
//лл                                                                        лл
//лл  (512) 345-2642 / jmiles@pop.net                                       лл
//лл                                                                        лл
//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

#include <stdio.h>
#include <malloc.h>
#include <dos.h>
#include <stdlib.h>
#include <io.h>
#include <fcntl.h>
#include <string.h>

#include "vfx.h"

WINDOW window;
PANE pane;
FONT fobj;

LONG bkgnd, grid;  
LONG cx,cy,rows,cols,cell,cell_cnt;
UBYTE *fpic;
LONG fpic_type;
UBYTE *fontdata;
ULONG *offsets;
ULONG *fontdatalong;
FILE *outfile;
LONG file_length;

#define LBM 1
#define PCX 2
#define GIF 3

#define X_BAS(c) (((c)%cols)*(cx+1)+1)
#define Y_BAS(c) (((c)/cols)*(cy+1)+1)

/******************************************/
void *load_file(BYTE *filename)
{
   LONG file_handle;
   void *buffer;

   if ( (file_handle=open(filename,O_RDONLY|O_BINARY))==-1L )
      return NULL;
   if ( (file_length=filelength(file_handle))==-1L )
      return NULL;
   if ( (buffer = malloc(file_length))==NULL )
      return NULL;
   if ( read(file_handle,buffer,file_length)==-1L )
      return NULL;
   close(file_handle);

   return buffer;
}

/************************************************************/
void fail(LONG errcode)
{
   static BYTE errmsgs[][128] =
     {{ "Error: Input file must be in .LBM, .PCX, or .GIF format"   },
      { "Error: Insufficient memory available"                      },
      { "Error: Could not open input file"                          },
      { "Error: Could not open output file"                         },
      { "Error: Font background and grid must be different colors"  },
      { "Error: Empty character set or invalid grid"                },
      { "Error: Missing or invalid grid"                            },
      { "Error: Could not write to output file"                     },
      { "Error: Background color must be specified for .PCX files"  }};

   printf("%s\n",errmsgs[errcode]);

   fcloseall();
   exit(errcode+1);
}

/************************************************************/
LONG width(LONG cell_number)
{
   LONG n,x,y,ix,iy,done,use_grid;
                           
   ix = X_BAS(cell_number)+cx-1;  
   iy = Y_BAS(cell_number);           
   use_grid = (VFX_pixel_read(&pane,ix,iy)==grid);

   for (x=done=0;(x<cx) && (!done);x++)
      {
      for (y=0;(y<cy) && (!done);y++)
         {
         n = VFX_pixel_read(&pane,ix-x,iy+y);
         if (use_grid)
            done=(n!=grid);
         else
            done=(n!=bkgnd);
         }
      }
                                                
   if (!done)
      return -use_grid;
   else
      return cx-(x-1);                             
}

/************************************************************/
void main(int argc, BYTE *argv[])
{
   LONG f,i,j,x,y,tx,ty;
   LONG k,n,resolution,max_x,max_y;
   LONG chars;
	UBYTE *window_buffer;
   void *GIF_scratch;
   RGB palette[256];

   printf("GETFONT V1.20                     Copyright (C) 1992-1994 Non-Linear Arts, Inc.\n\n");

   if (argc != 3 && argc != 4)
      {
      printf("Usage: GETFONT infile outfile [background_color]\n\n");
      printf("where: infile = 256-color .LBM, .PCX, or .GIF image file\n");
      printf("       outfile = 386FX standard binary font file\n");
      printf("       background_color = force use of background color 0-255\n");
      exit(1);      
      }

   //
   // Check for .LBM or .PCX extension
   //

   if ( stricmp(".LBM",&argv[1][strlen(argv[1])-4]) == 0 )
      fpic_type=LBM;
   else if ( stricmp(".PCX",&argv[1][strlen(argv[1])-4]) == 0 )
      fpic_type=PCX;
   else if ( stricmp(".GIF",&argv[1][strlen(argv[1])-4]) == 0 )
      fpic_type=GIF;
   else
      fail(0);

   //
   // Load file
   //

   if ((fpic=load_file(argv[1])) == NULL) fail(2);
   if ((outfile = fopen(argv[2],"w+b")) == NULL) fail(3);

   //
   // Get resolution of image
   //

   switch (fpic_type)
      {
      case LBM:
         resolution = VFX_ILBM_resolution(fpic);
         VFX_ILBM_palette(fpic, palette);
         break;
      case PCX:
         resolution = VFX_PCX_resolution(fpic);
         VFX_PCX_palette(fpic, file_length, palette);
         break;
      case GIF:
         resolution = VFX_GIF_resolution(fpic);
         VFX_GIF_palette(fpic, palette);
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
   pane.x0 = 0;
	pane.y0 = 0;
	pane.x1 = window.x_max = max_x;
	pane.y1 = window.y_max = max_y;
	pane.window = &window;

   fontdata = malloc(2048*2048*2);
   offsets = malloc(2048*2048*2);

   if ((offsets == NULL) || (fontdata == NULL))
      {
      fail(1);
      }

   //
   // Draw image
   //

   switch (fpic_type)
      {
      case LBM:
         bkgnd = VFX_ILBM_draw(&pane,fpic);
         break;

      case PCX:
         if (argc < 4)
            fail(8);

         VFX_PCX_draw(&pane,fpic);
         break;

      case GIF:
         if ( (GIF_scratch=malloc(GIF_SCRATCH_SIZE))==NULL )
            fail(1);
         bkgnd = VFX_GIF_draw(&pane,fpic,GIF_scratch);
         free(GIF_scratch);
         break;

      default:
         fail(0);
      }

   if (argc > 3)
      bkgnd = atoi(argv[3]);

   //
   // Compile font from pane image
   //

   chars = 0;

   //
   // Read grid color from upper-leftmost pixel
   //

   grid = VFX_pixel_read(&pane,0,0);

   //
   // Background color may not equal grid color
   //

   if (bkgnd == grid)
      fail(4);

   for (cy=0;cy<max_y;cy++)
      if (VFX_pixel_read(&pane,1,cy+1) == grid)
         break;

   for (cx=0;cx<max_x;cx++)
      if (VFX_pixel_read(&pane,cx+1,1) == grid)
         break;

   if ((!cx) || (!cy))
      fail(5);

   if ((cx==max_x) || (cy==max_y))
      fail(6);

   //
   // Find the # of cells, and test grid integrity
   //

   y=max_y;
   while (VFX_pixel_read(&pane,0,y) != grid)
      y--;
   rows = y/(cy+1);

   x=max_x;
   while (VFX_pixel_read(&pane,x,0) != grid)
      x--;
   cols = x/(cx+1);

   if ((y%(cy+1)) || (x%(cx+1)))
      fail(6);

   cell_cnt = rows*cols;
   for (f=k=cell=0;cell<cell_cnt;cell++)
      {
      if ((n=width(cell))==-1)
         break;
      offsets[cell]=k;
      k=k+(n*cy)+4;
      tx=X_BAS(cell);
      ty=Y_BAS(cell);

      fontdatalong=(ULONG *)&fontdata[f];       
      *fontdatalong=n;

      f+=4;
      for (y=0;y<cy;y++)
         for (x=0;x<n;x++)
            fontdata[f++]=VFX_pixel_read(&pane,tx+x,ty+y);

      ++chars;
      }

   for (j=0;j<cell;j++)
      offsets[j]+=(sizeof(fobj)+4*cell); 

   fobj.version = '.'*256 + '2';
   fobj.char_count = cell;
   fobj.char_height = cy;
   fobj.font_background = bkgnd;

   if (fwrite(&fobj,sizeof(fobj),1,outfile) != 1)
      fail(7);

   fflush(outfile);
   i=fileno(outfile);

   if (fwrite(offsets, sizeof(long), cell, outfile) < cell)
      fail(7);
   if (fwrite(fontdata, sizeof(char), f, outfile) < f)
      fail(7);
   if (fwrite(palette, sizeof(RGB), 256, outfile) != 256)
      fail(7);

   printf("Compilation successful: %u character(s) written to '%s'\n",chars,argv[2]);

   exit(0);
}


