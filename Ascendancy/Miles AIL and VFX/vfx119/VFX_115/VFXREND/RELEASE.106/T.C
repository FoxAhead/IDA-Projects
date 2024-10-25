//
// VFXREND test bed
//

#include <conio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <dos.h>
#include <math.h>

#include "vfxrend.h"

unsigned char *texture_lines[256];

unsigned char buffer[4096];

VFX_VERTEX sv[4];
VFX_TEXTURE txt;

#define TEXTURE_WIDTH 64

/******************************************/
void main(void)
{
   int i,j;
   int a,b,c;
   union REGS inregs,outregs;

   PANE pane;
   WINDOW window;

   window.buffer = (UBYTE *) 0x0a0000;
   window.x_max = 319;
   window.y_max = 199;
   window.stencil = NULL;
   window.shadow  = NULL;

   pane.window = &window;
   pane.x0 = pane.y0 = 0;
   pane.x1 = 319;
   pane.y1 = 199;

   inregs.x.eax = 0x13;
   int386(0x10,&inregs,&outregs);

   memset((void *) 0xa0000,1,64000);

   for (i=0;i<256;i++)
      {
      texture_lines[i] = (buffer + (TEXTURE_WIDTH * i));
      }

   for (j=0;j<64;j++)
      for (i=0;i<64;i++)
         {
         if ((!(i&3)) || (!(j&3)))
            buffer[j*64+i] = 14;
         else
            buffer[j*64+i] = 12;
         }

   txt.V_addrs = (void *) texture_lines;
   txt.height = 64;
   txt.width = 64;

   VFX_set_Gouraud_dither_level(0,0x7fff);

   sv[0].x = 20;
   sv[0].y = 50;
   sv[0].u = DOUBLE_TO_FIXED16(0.0);
   sv[0].v = DOUBLE_TO_FIXED16(0.0);
   sv[0].w = DOUBLE_TO_FIXED30(1.0);            // Z = 1, W = 1 ("near")
   sv[0].c = DOUBLE_TO_FIXED16(5);

   sv[1].x = 300;
   sv[1].y = 50;
   sv[1].u = DOUBLE_TO_FIXED16(63.0);
   sv[1].v = DOUBLE_TO_FIXED16(0.0);
   sv[1].w = DOUBLE_TO_FIXED30(1.0);
   sv[1].c = DOUBLE_TO_FIXED16(10.0);

   sv[2].x = 162;
   sv[2].y = 149;
   sv[2].u = DOUBLE_TO_FIXED16(63 * 0.025);     // Z = 40, W = 0.025 ("far")
   sv[2].v = DOUBLE_TO_FIXED16(63 * 0.025);
   sv[2].w = DOUBLE_TO_FIXED30(0.025);
   sv[2].c = DOUBLE_TO_FIXED16(10.0);
   
   sv[3].x = 158;
   sv[3].y = 149;
   sv[3].u = DOUBLE_TO_FIXED16(0 * 0.025);
   sv[3].v = DOUBLE_TO_FIXED16(63 * 0.025);
   sv[3].w = DOUBLE_TO_FIXED30(0.025);
   sv[3].c = DOUBLE_TO_FIXED16(5.0);

   a = *(int *) 0x46c;

   for (i=0;i<500;i++)
      VFX_polygon_render(&pane,sv,4,
         (MAP_PERSPECT | SHD_NONE | SMP_FINE   | TIL_NONE  | XP_NONE),
         0,
         &txt,
         NULL,
         NULL);

   b = *(int *) 0x46c;
   printf("Perspective time: %u\n",b-a);

   sv[2].u = DOUBLE_TO_FIXED16(63);        
   sv[2].v = DOUBLE_TO_FIXED16(63);
   sv[3].u = DOUBLE_TO_FIXED16(0);
   sv[3].v = DOUBLE_TO_FIXED16(63);

   a = *(int *) 0x46c;

   for (i=0;i<500;i++)
      VFX_polygon_render(&pane,sv,4,
         (MAP_AFFINE | SHD_NONE | SMP_FINE   | TIL_NONE  | XP_NONE),
         0,
         &txt,
         NULL,
         NULL);

   b = *(int *) 0x46c;
   printf("Affine time: %u\n",b-a);

   a = *(int *) 0x46c;

   for (i=0;i<500;i++)
      VFX_polygon_render(&pane,sv,4,
         (MAP_SOLID | SHD_R_GOURAUD),
         0,
         NULL,
         NULL,
         NULL);

   b = *(int *) 0x46c;
   printf("Gouraud time: %u\n",b-a);

   a = *(int *) 0x46c;

   for (i=0;i<500;i++)
      VFX_polygon_render(&pane,sv,4,
         (MAP_SOLID | SHD_FLAT),
         0,
         NULL,
         NULL,
         NULL);

   b = *(int *) 0x46c;
   printf("Solid time: %u\n",b-a);

}
