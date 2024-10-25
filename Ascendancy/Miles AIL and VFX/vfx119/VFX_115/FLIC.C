//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
//лл                                                                        лл
//лл  FLIC.C                                                                лл
//лл                                                                        лл
//лл  386FX FLIC player routines                                            лл
//лл                                                                        лл
//лл  Version 1.00 of 15-Feb-94: Initial version                            лл
//лл                                                                        лл
//лл  Project: 386FX Sound & Light(TM)                                      лл
//лл  Authors: John Lemberger                                               лл
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

#include "flic.h"
#include "dll.h"

LONG FLIC_LITERAL_decode(PANE *pane, FLIC *flic)
{
   FLEX_PTR position, pixel;
   LONG i;

   pixel.v = pane->window->buffer;
   position.v = (void *)( (LONG)(flic->chunk) + 6 );

   for (i=0; i < (flic->chunk->size >> 2) ; i++)
      *pixel.d++ = *position.d++;
   for (i=0; i < (flic->chunk->size & 3) ; i++)
      *pixel.b++ = *position.b++;

   return 0;
}

LONG FLIC_DELTA_FLC_decode(PANE *pane, FLIC *flic)
{
   LONG ret=0;
   ULONG i, k;
   LONG j, psize;
   WORD y=0,opcode;
   UWORD lines;
   UWORD packets;

   FLEX_PTR position, pixel;

   position.v = (void *)( (LONG)(flic->chunk) + 6 );

   lines = *position.w++;

   for (i=0; i<lines; i++)
      {
      opcode = (WORD) *position.w++;

      while (opcode < 0)
         {
         switch (opcode & 0x0c000)
            {
            case 0x0c000:
               y -= opcode;               // Add skip line count
               break;
            case 0x08000:                 // Write last byte in line
               pixel.b=pane->window->buffer + (y+1) * flic->header->width -1;
               *pixel.b = (unsigned char) opcode;
               break;
            default:
               break;
            }

         opcode = *position.w++;
         }

      packets = opcode;                   // number of packets

      pixel.b = pane->window->buffer + ( y++ * (flic->header->width) );

      for (k=0; k<packets; k++)
         {
         pixel.b += *position.b++;        // Add skip pixels

         psize = (LONG) *position.b++;    

         if ( psize < 0 )
            {
            for (j=0; j<(-psize); j++)
               {
               *pixel.w++ = *position.w;
               }
            position.w++;
            }
         else
            {
            for (j=0; j <psize; j++)
               {
               *pixel.w++ = *position.w++;
               }
            }
         }

      }

   return ret;
}

LONG FLIC_DELTA_FLI_decode(PANE *pane, FLIC *flic)
{
   LONG ret=0;
   ULONG i, k;
   LONG j, psize;
   UWORD skip_lines,lines;
   unsigned char packets;
   FLEX_PTR position, pixel;

   position.v = (void *)( (LONG)(flic->chunk) + 6 );

   skip_lines = *position.w++;

   lines = *position.w++;

   for (i=0; i<lines; i++)
      {
      pixel.b = pane->window->buffer + (skip_lines+i)*flic->header->width;
      packets = *position.b++;            // number of packets

      for (k=0; k<packets; k++)
         {
         pixel.b += *position.b++;

         psize = (signed char) *position.b++;    
         
         if ( psize < 0 )
            {
            for (j=0; j<(-psize); j++)
               {
               *pixel.b++ = *position.b;
               }
            position.b++;
            }
         else
            {
            for (j=0; j <psize; j++)
               {
               *pixel.b++ = *position.b++;
               }
            }
         }
      }

   return ret;
}


LONG FLIC_BYTE_RUN_decode(PANE *pane, FLIC *flic)
{
   LONG ret=0;
   ULONG i;
   LONG j, psize;
   ULONG y=0;
   unsigned char *pixel;
   FLEX_PTR position;

   pixel = pane->window->buffer;

   position.v = (void *)( (LONG)(flic->chunk) + 6 );

   for (i=0; i<flic->header->height; i++)
      {
      position.b++;           // Skip over number of packets

      y=0;
      while (y < flic->header->width)
         {
         psize = (signed char) *position.b++;    
         
         if ( psize < 0 )
            {
            for (j=0; j < (-psize); j++)
               {
               *pixel++ = *position.b++;
               y++;
               }
            }
         else
            {
            for (j=0; j<psize; j++)
               {
               *pixel++ = *position.b;
               y++;
               }
            position.b++;
            }
         }
      }

   return ret;
}

LONG FLIC_COLOR_64_decode(FLIC *flic, RGB *palette)
{
   UWORD packets;
   ULONG i,j,color,count;
   FLEX_PTR position;

   position.v = (void *)( (LONG)(flic->chunk) + 6 );

   packets = *position.w++;

   color =0;

   for (i=0; i<packets; i++)
      {
      color += *position.b++;
      count = *position.b++;
      count = (count==0) ? 256 : count;

      for (j=0; j<count; j++)
         {
         palette[color].r  =*position.b++;
         palette[color].g  =*position.b++;
         palette[color++].b=*position.b++;
         }
      }

   return FLIC_NEW_COLORS;
}

LONG FLIC_COLOR_256_decode(FLIC *flic, RGB *palette)
{
   UWORD packets;
   ULONG i,j,color,count;
   FLEX_PTR position;

   position.v = (void *)( (LONG)(flic->chunk) + 6 );

   packets = *position.w++;

   color =0;

   for (i=0; i<packets; i++)
      {
      color += *position.b++;
      count = *position.b++;
      count = (count==0) ? 256 : count;

      for (j=0; j<count; j++)
         {
         palette[color].r  =*position.b++ >> 2;
         palette[color].g  =*position.b++ >> 2;
         palette[color++].b=*position.b++ >> 2;
         }
      }

   return FLIC_NEW_COLORS;
}


LONG FLIC_frame_decode(PANE *pane, FLIC *flic, RGB *palette)
{
   LONG  ret=0;
   LONG  i, chunks;

   chunks = flic->frame->chunks;

   flic->chunk = (void *)((LONG)flic->frame + 16);

   for (i=0; i < chunks; i++)
      {
      switch (flic->chunk->type)
         {
         case FLIC_COLOR_256:
            ret |= FLIC_COLOR_256_decode(flic, palette);
            break;
         case FLIC_DELTA_FLC:
            ret |= FLIC_DELTA_FLC_decode(pane, flic);
            break;
         case FLIC_COLOR_64:
            ret |= FLIC_COLOR_64_decode(flic, palette);
            break;
         case FLIC_DELTA_FLI:
            ret |= FLIC_DELTA_FLI_decode(pane, flic);
            break;
         case FLIC_BLACK:
            VFX_pane_wipe(pane,0);
            break;
         case FLIC_BYTE_RUN:
            ret |= FLIC_BYTE_RUN_decode(pane, flic);
            break;
         case FLIC_LITERAL:
            ret |= FLIC_LITERAL_decode(pane, flic);
            break;
         case FLIC_PSTAMP:
            // Ignore this one
            break;
         default:
            printf("FLIC_UNKNOWN\n");
            break;
         }
      flic->chunk = (void *)((LONG)(flic->chunk) + flic->chunk->size);
      }
   flic->frame = (void *)((LONG)flic->frame + (LONG)(flic->frame->size));

   return ret;
}

LONG FLIC_frame_draw(PANE *pane, FLIC *flic, RGB *palette)
{
   LONG  ret=0;

   //
   // Set position to frame 1 if this is the first time in
   //

   if ( flic->frame == 0 )
      {
      //
      // Add new FLC offsets to old FLI file
      //

      if (flic->header->type == FLI)
         flic->header->oframe1 = sizeof(FLIC_HEADER);

      flic->frame=(void *)((LONG)flic->header+(LONG)flic->header->oframe1);
      }

   //
   // Set position to frame 2 if at end of file
   //

   if ( (LONG)(flic->frame) >= (LONG)(flic->header) + flic->header->size )
      flic->frame = (void *)( (LONG)(flic->header) + flic->header->oframe2);

   if ( flic->frame->type == FLIC_FRAME )
      ret |= FLIC_frame_decode(pane, flic, palette);
   else
      ret = -1;

  return ret;
}
