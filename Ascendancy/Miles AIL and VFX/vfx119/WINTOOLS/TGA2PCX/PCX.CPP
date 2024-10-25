//****************************************************************************
//*                                                                          *
//* PCX.CPP: PCX file reader/writer                                          *
//*                                                                          *
//* 32-bit protected-mode source compatible with MSVC 10.2                   *
//*                                                                          *
//* Version 1.00 of 28-Jan-97: Initial                                       *
//*                                                                          *
//* Author: Billy Zelsnack                                                   *
//*                                                                          *
//****************************************************************************
//*                                                                          *
//* Copyright (C) 1997 Miles Design, Inc.                                    *
//*                                                                          *
//****************************************************************************

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#include "pcx.h"

typedef struct
   {
   unsigned char manufacturer;   // 10
   unsigned char version;        // 5
   unsigned char encoding;       // 1
   unsigned char bitsperpixel;   // 8
   short         x0;
   short         y0;
   short         x1;
   short         y1;             // size inclusive
   short         wide;
   short         tall;
   unsigned char colormap[48];
   unsigned char reserved;       // 0
   unsigned char numcolorplanes; // 1
   short         bytesperline;   // always even (but see note below...)
   short         paletteinfo;    // 1
   short         screenWide;
   short         screenTall;
   unsigned char filler[54];     // 0
}
PCXHEADER;

/***************************************************************************/
static void encodePcxLine(FILE **fp, unsigned char *buf, int wide)
{
   static unsigned char blank[16384];
   int numbytes, count, ctr, color;

   if ((*fp) == NULL)
      {
      return;
      }

   numbytes = 0;
   ctr = 0;
   
   while (ctr < wide)
      {
      count = 1;
      color = buf[ctr++];

      while ((ctr < wide) && (count < 63))
         {
         if (buf[ctr] != color)
            {
            break;
            }

         ctr++;
         count++;
         }

      if ((count > 1) || ((color & 0xc0) == 0xc0))
         {
         blank[numbytes++] = 192 + count;
      
         if (numbytes >= 16384)
            {
            fclose(*fp);
            (*fp) = NULL;
            return;
            }
         }

      blank[numbytes++] = color;
   
      if (numbytes >= 16384)
         {
         fclose(*fp);
         (*fp) = NULL;
         return;
         }
      }

   if (fwrite(blank,numbytes,1,*fp) != 1)
      {
      fclose(*fp);
      (*fp) = NULL;
      }
}

/***************************************************************************/
unsigned char *PCX_load (char *filename, //)
                         int  *wide,
                         int  *tall)
{
   static unsigned char line[16384];
   unsigned char       *ptr,color;
   PCXHEADER            header;
   FILE                *fp;
   int                  bytesPerLine,i,j,ctr,count;

   fp = fopen(filename,"rb");

   if (fp==NULL)
      {
      return 0;
      }

   fseek(fp,0,SEEK_SET);

   fread(&header, sizeof(PCXHEADER), 1, fp);

   if (header.manufacturer != 10)
      {
      fclose(fp);
      return 0;
      }

   if (header.version != 5)
      {
      fclose(fp);
      return 0;
      }

   if (header.encoding != 1)
      {
      fclose(fp);
      return 0;
      }
   
   if (header.bitsperpixel != 8)
      {
      fclose(fp);
      return 0;
      }

   (*wide) = (header.x1-header.x0)+1;
   (*tall) = (header.y1-header.y0)+1;

   bytesPerLine = header.bytesperline * header.numcolorplanes;

   if (bytesPerLine < 0)
      {
      fclose(fp);
      return 0;
      }

   if (bytesPerLine > 16384)
      {
      fclose(fp);
      return 0;
      }

   ptr = (unsigned char *) malloc((*wide) * (*tall));

   for (j=0; j < (*tall); j++)
      {
      ctr = 0;

      while (ctr < bytesPerLine)
         {
         fread(&color,1,1,fp);

         if (feof(fp))
            {
            break;
            }

         count = 1;

         if ((color & 192) == 192)
            {
            count = color & 63;
   
            fread(&color,1,1,fp);

            if (feof(fp))
               {
               break;
               }
            }

         for (i=0; i < count; i++)
            {
            line[ctr++] = color;
            }
         }

      memcpy(ptr + (*wide) * j,
             line,
            (*wide));
      }

   fclose(fp);
   return ptr;
}

/***************************************************************************/
unsigned char *PCX_load_palette (char *filename)
{
   unsigned char *ptr;
   FILE          *fp;
   PCXHEADER      header;

   fp = fopen(filename,"rb");

   if (fp == NULL)
      {
      return NULL;
      }

   fseek(fp,0,SEEK_SET);

   fread(&header,sizeof(PCXHEADER),1,fp);

   if (header.manufacturer != 10)
      {
      fclose(fp);
      return NULL;
      }

   if (header.version != 5)
      {
      fclose(fp);
      return NULL;
      }

   if (header.encoding != 1)
      {
      fclose(fp);
      return NULL;
      }
   
   if (header.bitsperpixel != 8)
      {
      fclose(fp);
      return NULL;
      }

   fseek(fp, -768, SEEK_END);

   ptr = (unsigned char*) malloc(768);

   fread(ptr, 768, 1, fp);

   fclose(fp);
   return ptr;
}

/***************************************************************************/
int PCX_save (char          *filename, //)
              int            wide,
              int            tall,
              unsigned char *data,
              unsigned char *pal)
{
   int x0,y0,x1,y1,j;
   unsigned char id;
   PCXHEADER pcxheader;
   FILE *fp;

   x0 = 0;
   y0 = 0;
   x1 = wide - 1;
   y1 = tall - 1;

   fp = fopen(filename,"wb");

   if (fp == NULL)
      {
      return 0;
      }

   fseek(fp,0L,SEEK_SET);

   pcxheader.manufacturer = 10;
   pcxheader.version      = 5;
   pcxheader.encoding     = 1;
   pcxheader.bitsperpixel = 8;
   pcxheader.x0           = x0;
   pcxheader.y0           = y0;
   pcxheader.x1           = x1;
   pcxheader.y1           = y1;
   pcxheader.wide         = 0;
   pcxheader.tall         = 0;

   memcpy(pcxheader.colormap,
          pal,
          48);

   pcxheader.reserved       = 0;
   pcxheader.numcolorplanes = 1;

   //
   // WARNING!
   //
   // PCX "standard" requires even-length lines, but if extra pad byte
   // is added to 'bytesperline', DPaint displays odd-width images
   // incorrectly
   //

   pcxheader.bytesperline   = ((x1-x0)+1);
   pcxheader.paletteinfo    = 1;
   pcxheader.screenWide     = 0;
   pcxheader.screenTall     = 0;

   memset(pcxheader.filler,
          0,
          54);

   if (fwrite(&pcxheader, sizeof(PCXHEADER), 1, fp) != 1)
      {
      fclose(fp);
      return 0;
      }

   for (j=0; j < tall; j++)
      {
      encodePcxLine(&fp, data + j * wide, wide);
      }

   id = 0x0c;

   if (fwrite(&id, 1, 1, fp) != 1)
      {
      fclose(fp);
      return 0;
      }

   if (fwrite(pal,768,1,fp) != 1)
      {
      fclose(fp);
      return 0;
      }

   fclose(fp);
   return 1;
}

