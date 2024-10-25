//****************************************************************************
//*                                                                          *
//* RGBUTILS.H: RGB color manipulation library                               *
//*                                                                          *
//* 32-bit protected-mode source compatible with MSVC 10.2                   *
//*                                                                          *
//* Version 1.00 of 28-Jan-97: Initial, derived from IMAGEMAN RGBUTILS.H     *
//*                                                                          *
//* Author: John Miles                                                       *
//*                                                                          *
//****************************************************************************
//*                                                                          *
//* Copyright (C) 1997 Miles Design, Inc.                                    *
//*                                                                          *
//****************************************************************************

#ifndef RGBUTILS_H
#define RGBUTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <limits.h>
#include <string.h>

#include "typedefs.h"

#ifndef VFX_RGB_DEFINED
#define VFX_RGB_DEFINED

  typedef struct
     {
     U8 r;     // 8 bits per component
     U8 g;
     U8 b;
     }
  VFX_RGB;

#endif

class RGB_BOX
{
public:
    S32 r0;    // min value, exclusive
    S32 r1;    // max value, inclusive

    S32 g0;  
    S32 g1;

    S32 b0;  
    S32 b1;

    S32 vol;
};

class CQT
{
public:
   S32 table[33][33][33];
};

class CMAP
{
   S16       *best;
   S16       *second_best;
   VFX_RGB   *palette;
   U32        colors;

public:
   //
   // Color remapping functions
   //

   CMAP(VFX_RGB *palette, U32 colors);
  ~CMAP();

   U8 nearest_neighbor (VFX_RGB *triplet, S32 dither);
};

class CQ
{
   CQT wt;
   CQT mr;
   CQT mg;
   CQT mb;

   SINGLE *m2;

   SINGLE Var   (RGB_BOX *cube);
   void   M3d   (S32     *vwt,  S32 *vmr, S32 *vmg, S32 *vmb, SINGLE *m2);
   S32    Vol   (RGB_BOX *cube,                  CQT *mmt);
   S32    Bottom(RGB_BOX *cube, U8 dir,          CQT *mmt);
   S32    Top   (RGB_BOX *cube, U8 dir, S32 pos, CQT *mmt);

   SINGLE Maximize(RGB_BOX *cube,
                   U8       dir, 
                   S32      first, 
                   S32      last, 
                   S32     *cut,
                   S32      whole_r, 
                   S32      whole_g, 
                   S32      whole_b, 
                   S32      whole_w);

   S32 Cut(RGB_BOX *set1, RGB_BOX *set2);

public:
   CQ();
  ~CQ();

   //
   // Color quantization functions
   //

   void  reset     (void);
   void  add_color (VFX_RGB *triplet);
   U32   quantize  (VFX_RGB *out, U32 colors);
};

//****************************************************************************
//*                                                                          *
//* VFX RGB color manipulation library                                       *
//*                                                                          *
//* 32-bit protected-mode source compatible with MSVC 10.2                   *
//*                                                                          *
//* Version 1.00 of 28-Jan-97: Initial, derived from IMAGEMAN RGBUTILS.H     *
//*                                                                          *
//* Author: John Miles                                                       *
//*                                                                          *
//****************************************************************************
//*                                                                          *
//* Copyright (C) 1997 Miles Design, Inc.                                    *
//*                                                                          *
//****************************************************************************
//*                                                                          *
//*  Contains C++ implementation of Wu's color quantizer (v. 2)              *
//*  (See Graphics Gems vol. II, pp. 126-133)                                *
//*                                                                          *
//*  Author:     Xiaolin Wu                                                  *
//*              Dept. of Computer Science                                   *
//*              Univ. of Western Ontario                                    *
//*              London, Ontario N6A 5B7                                     *
//*              wu@csd.uwo.ca                                               *
//*                                                                          *
//*  Algorithm:  Greedy orthogonal bipartition of RGB space for variance     *
//*              minimization aided by inclusion-exclusion tricks.           *
//*                                                                          *
//*  The author thanks Tom Lane at Tom_Lane@G.GP.CS.CMU.EDU for much         *
//*  additional documentation and a cure to a previous bug.                  *
//*  Free to distribute, comments and suggestions are appreciated.           *
//*                                                                          *
//*  Modifications:                                                          *
//*                                                                          *
//*  25-Sep-93: (John Miles) Modified to use 386FX 32-bit types and          *
//*                          class-style API; added CMAP_class (nearest-     *
//*                          neighbor mapping)                               *
//*                                                                          *
//*  28-Jan-97: (John Miles) Modified to use TYPEDEFS.H, ported to C++       *
//*                                                                          *
//****************************************************************************

#define RGBU_RED   2
#define RGBU_GREEN 1   
#define RGBU_BLUE  0

//****************************************************************************
//
// At conclusion of the histogram step, we can interpret
//   wt[r] [g] [b] = sum over voxel of P(c)
//   mr[r] [g] [b] = sum over voxel of r*P(c), similarly for mg, mb
//   m2[r] [g] [b] = sum over voxel of c^2*P(c)
//
// Actually each of these should be divided by 'size' to give the usual
// interpretation of P() as ranging from 0 to 1, but we needn't do that here.
//
// We convert histogram into cumulative moments so that we can 
// rapidly calculate the sums of the above quantities over any desired box.
//
//****************************************************************************

void CQ::M3d(S32 *vwt, S32 *vmr, S32 *vmg, S32 *vmb, SINGLE *m2)
{
   U32    ind1, ind2;
   U8     i, r, g, b;
   S32    line, line_r, line_g, line_b,
          area[33], area_r[33], area_g[33], area_b[33];
   SINGLE line2, area2[33];

   for (r=1; r<=32; ++r)
     {
     for (i=0; i<=32; ++i)
        {
        area2[i] = 0.0F;
        area[i] = area_r[i] = area_g[i] = area_b[i] = 0;
        }

     for (g=1; g<=32; ++g)
        {
        line2 = 0.0F;
        line = line_r = line_g = line_b = 0;

        for (b=1; b<=32; ++b)
           {
           //
           // [r] [g] [b]
           //

           ind1 = (r<<10) + (r<<6) + r + (g<<5) + g + b;

           line   += vwt[ind1];
           line_r += vmr[ind1]; 
           line_g += vmg[ind1]; 
           line_b += vmb[ind1];

           line2  += m2[ind1];

           area[b]   += line;
           area_r[b] += line_r;
           area_g[b] += line_g;
           area_b[b] += line_b;

           area2[b] += line2;

           //
           // [r-1] [g] [b]
           //

           ind2 = ind1 - (33*33);

           vwt[ind1] = vwt[ind2] + area  [b];
           vmr[ind1] = vmr[ind2] + area_r[b];
           vmg[ind1] = vmg[ind2] + area_g[b];
           vmb[ind1] = vmb[ind2] + area_b[b];

           m2[ind1] = m2[ind2] + area2[b];
           }
        }
     }
}

//****************************************************************************
//
// Compute sum over a box of any given statistic
//
//****************************************************************************

S32 CQ::Vol(RGB_BOX *cube, CQT *mmt)
{
   return (mmt->table [cube->r1] [cube->g1] [cube->b1] 
          -mmt->table [cube->r1] [cube->g1] [cube->b0]
          -mmt->table [cube->r1] [cube->g0] [cube->b1]
          +mmt->table [cube->r1] [cube->g0] [cube->b0]
          -mmt->table [cube->r0] [cube->g1] [cube->b1]
          +mmt->table [cube->r0] [cube->g1] [cube->b0]
          +mmt->table [cube->r0] [cube->g0] [cube->b1]
          -mmt->table [cube->r0] [cube->g0] [cube->b0]);
}

//****************************************************************************
//
// The next two routines allow a slightly more efficient calculation
// of Vol() for a proposed subbox of a given box.  The sum of Top()
// and Bottom() is the Vol() of a subbox split in the given direction
// and with the specified new upper bound.
//
// Compute part of Vol(cube, mmt) that doesn't depend on r1, g1, or b1
// (depending on dir)
//
//****************************************************************************

S32 CQ::Bottom(RGB_BOX *cube, U8 dir, CQT *mmt)
{
   switch (dir)
      {
      case RGBU_RED   : return (-mmt->table [cube->r0] [cube->g1] [cube->b1]
                           +mmt->table [cube->r0] [cube->g1] [cube->b0]
                           +mmt->table [cube->r0] [cube->g0] [cube->b1]
                           -mmt->table [cube->r0] [cube->g0] [cube->b0]);
                                
                                
      case RGBU_GREEN : return (-mmt->table [cube->r1] [cube->g0] [cube->b1]
                           +mmt->table [cube->r1] [cube->g0] [cube->b0]
                           +mmt->table [cube->r0] [cube->g0] [cube->b1]
                           -mmt->table [cube->r0] [cube->g0] [cube->b0]);
                                
      case RGBU_BLUE  : return (-mmt->table [cube->r1] [cube->g1] [cube->b0]
                           +mmt->table [cube->r1] [cube->g0] [cube->b0]
                           +mmt->table [cube->r0] [cube->g1] [cube->b0]
                           -mmt->table [cube->r0] [cube->g0] [cube->b0]);
      }

   return 0;
}

//****************************************************************************
//
// Compute remainder of Vol(cube, mmt), substituting pos for
// r1, g1, or b1 (depending on dir)
//
//****************************************************************************

S32 CQ::Top(RGB_BOX *cube, U8 dir, S32 pos, CQT *mmt)
{
   switch (dir)
      {
      case RGBU_RED   : return (mmt->table  [pos] [cube->g1] [cube->b1]  
                          -mmt->table  [pos] [cube->g1] [cube->b0]
                          -mmt->table  [pos] [cube->g0] [cube->b1]
                          +mmt->table  [pos] [cube->g0] [cube->b0]);
                               
      case RGBU_GREEN : return (mmt->table  [cube->r1] [pos] [cube->b1] 
                          -mmt->table  [cube->r1] [pos] [cube->b0]
                          -mmt->table  [cube->r0] [pos] [cube->b1]
                          +mmt->table  [cube->r0] [pos] [cube->b0]);
                               
      case RGBU_BLUE  : return (mmt->table  [cube->r1] [cube->g1] [pos]
                          -mmt->table  [cube->r1] [cube->g0] [pos]
                          -mmt->table  [cube->r0] [cube->g1] [pos]
                          +mmt->table  [cube->r0] [cube->g0] [pos]);
      }

   return 0;
}

//****************************************************************************
//
// Compute the weighted variance of a box
// NB: as with the raw statistics, this is really the variance * size
//
//****************************************************************************

SINGLE CQ::Var(RGB_BOX *cube)
{
   SINGLE dr, dg, db, xx;

   dr = (SINGLE) Vol(cube, &mr); 
   dg = (SINGLE) Vol(cube, &mg); 
   db = (SINGLE) Vol(cube, &mb);

   xx = m2 [cube->r1*33*33 + cube->g1*33 + cube->b1] 
       -m2 [cube->r1*33*33 + cube->g1*33 + cube->b0]
       -m2 [cube->r1*33*33 + cube->g0*33 + cube->b1]
       +m2 [cube->r1*33*33 + cube->g0*33 + cube->b0]
       -m2 [cube->r0*33*33 + cube->g1*33 + cube->b1]
       +m2 [cube->r0*33*33 + cube->g1*33 + cube->b0]
       +m2 [cube->r0*33*33 + cube->g0*33 + cube->b1]
       -m2 [cube->r0*33*33 + cube->g0*33 + cube->b0];

   return (xx - (dr*dr + dg*dg + db*db) / (SINGLE) Vol(cube, &wt));    
}

//****************************************************************************
//
// We want to minimize the sum of the variances of two subboxes.
// The sum(c^2) terms can be ignored since their sum over both subboxes
// is the same (the sum for the whole box) no matter where we split.
// The remaining terms have a minus sign in the variance formula,
// so we drop the minus sign and MAXIMIZE the sum of the two terms.
//
//****************************************************************************

SINGLE CQ::Maximize(RGB_BOX *cube, //)
                   U8    dir, 
                   S32     first, 
                   S32     last, 
                   S32    *cut,
                   S32     whole_r, 
                   S32     whole_g, 
                   S32     whole_b, 
                   S32     whole_w)
{
   S32    half_r, half_g, half_b, half_w;
   S32    base_r, base_g, base_b, base_w;
   S32    i;
   SINGLE temp, max;

   base_r = Bottom(cube, dir, &mr);
   base_g = Bottom(cube, dir, &mg);
   base_b = Bottom(cube, dir, &mb);
   base_w = Bottom(cube, dir, &wt);

   max = 0.0F;
   *cut = -1;

   for (i=first; i<last; ++i)
      {
      half_r = base_r + Top(cube, dir, i, &mr);
      half_g = base_g + Top(cube, dir, i, &mg);
      half_b = base_b + Top(cube, dir, i, &mb);
      half_w = base_w + Top(cube, dir, i, &wt);

      //
      // Now half_x is sum over lower half of box, if split at i 
      //
      // Subbox could be empty of pixels; never split into an empty box
      // 

      if (half_w == 0)
         continue;

      temp = ((SINGLE) half_r*half_r +
              (SINGLE) half_g*half_g +
              (SINGLE) half_b*half_b) / half_w;

      half_r = whole_r - half_r;
      half_g = whole_g - half_g;
      half_b = whole_b - half_b;
      half_w = whole_w - half_w;

      //
      // Subbox could be empty of pixels; never split into an empty box
      // 

      if (half_w == 0)
         continue;

      temp += ((SINGLE) half_r*half_r +
               (SINGLE) half_g*half_g +
               (SINGLE) half_b*half_b) / half_w;

      if (temp > max)
         {
         max=temp;
         *cut=i;
         }
      }

   return max;
}

S32 CQ::Cut(RGB_BOX *set1, RGB_BOX *set2)
{
   U8     dir;
   S32    cutr, cutg, cutb;
   SINGLE maxr, maxg, maxb;
   S32    whole_r, whole_g, whole_b, whole_w;

   whole_r = Vol(set1, &mr);
   whole_g = Vol(set1, &mg);
   whole_b = Vol(set1, &mb);
   whole_w = Vol(set1, &wt);

   maxr = Maximize(set1, RGBU_RED,   set1->r0+1, set1->r1, &cutr,
                   whole_r, whole_g, whole_b, whole_w);

   maxg = Maximize(set1, RGBU_GREEN, set1->g0+1, set1->g1, &cutg,
                   whole_r, whole_g, whole_b, whole_w);

   maxb = Maximize(set1, RGBU_BLUE,  set1->b0+1, set1->b1, &cutb,
                   whole_r, whole_g, whole_b, whole_w);

   if ((maxr >= maxg) && (maxr >= maxb))
      {
      dir = RGBU_RED;
                            
      if (cutr < 0)
         return 0;
      }
   else
      if ((maxg >= maxr) && (maxg >= maxb))
         {
         dir = RGBU_GREEN;

         if (cutg < 0)
            return 0;
         }
      else
         {
         dir = RGBU_BLUE;

         if (cutb < 0)
            return 0;
         }

    set2->r1 = set1->r1;
    set2->g1 = set1->g1;
    set2->b1 = set1->b1;

    switch (dir)
      {
      case RGBU_RED:

          set2->r0 = set1->r1 = cutr;
          set2->g0 = set1->g0;
          set2->b0 = set1->b0;
          break;

      case RGBU_GREEN:

          set2->g0 = set1->g1 = cutg;
          set2->r0 = set1->r0;
          set2->b0 = set1->b0;
          break;

      case RGBU_BLUE:

          set2->b0 = set1->b1 = cutb;
          set2->r0 = set1->r0;
          set2->g0 = set1->g0;
          break;
      }

    set1->vol = (set1->r1 - set1->r0) *
                (set1->g1 - set1->g0) *
                (set1->b1 - set1->b0);

    set2->vol = (set2->r1 - set2->r0) *
                (set2->g1 - set2->g0) *
                (set2->b1 - set2->b0);

    return 1;
}

//****************************************************************************
//
// Construct an instance of class CQ
//
// Note: Each instance requires approx. 800K for histographic data,
// etc.
//
//****************************************************************************

CQ::CQ(void)
{
   //
   // Warning: virtual functions unsupported!
   //
   
   memset(this, 0, sizeof(*this));

   m2 = (SINGLE *) calloc(33*33*33,sizeof(SINGLE));

   reset();
}

//****************************************************************************
//
// Free an instance of CQ
//
//****************************************************************************

CQ::~CQ(void)
{
   free(m2);
}

//****************************************************************************
//
// Initialize color histogram
//
// Histogram is in elements 1..HISTSIZE along each axis,
// element 0 is for base or marginal value
//
//****************************************************************************

void CQ::reset(void)
{
   U32 i, j, k;
   
   for (i=0; i<33; ++i)
      for (j=0; j<33; ++j)
         for (k=0; k<33; ++k)
            {
            wt.table [i] [j] [k] = 0;
            mr.table [i] [j] [k] = 0;
            mg.table [i] [j] [k] = 0;
            mb.table [i] [j] [k] = 0;

            m2[i*33*33 + j*33 + k] = 0.0F;
            }
}

//****************************************************************************
//
// Build 3D color histogram of color counts
//
//****************************************************************************

void CQ::add_color(VFX_RGB *triplet)
{
   static S32 table[256];
   static S32 table_valid = 0;
   S32        r, g, b;
   S32        inr, ing, inb;
   S32        i;

   //
   // Build table of squares, if not already valid
   // 

   if (!table_valid)
      {
      for (i=0; i<256; ++i)
         {
         table[i] = i*i;
         }

      table_valid = 1;
      }
      
   r = triplet->r; 
   g = triplet->g; 
   b = triplet->b;

   inr = (r >> 3) + 1; 
   ing = (g >> 3) + 1; 
   inb = (b >> 3) + 1;

   wt.table [inr] [ing] [inb]++;
   mr.table [inr] [ing] [inb] += r;
   mg.table [inr] [ing] [inb] += g;
   mb.table [inr] [ing] [inb] += b;

   m2 [inr*33*33 + ing*33 + inb] += (SINGLE)(table[r] + table[g] + table[b]);
}

//****************************************************************************
//
// Generate optimal color palette based on input
//
//****************************************************************************

U32 CQ::quantize(VFX_RGB *out, U32 colors)

{
   RGB_BOX *cube;
   U32      next;
   U32      k,i;
   S32      weight;
   SINGLE  *vv, temp;

   if (colors == 0)
      {
      return 0;
      }

   if (colors > 256)
      {
      colors = 256;
      }

   if ((vv = (SINGLE *) calloc(colors,sizeof(SINGLE))) == NULL)
      return 0;

   if ((cube = (RGB_BOX *) calloc(colors,sizeof(RGB_BOX))) == NULL)
      {
      free(vv);
      return 0;
      }

   M3d((S32 *)    &wt.table,
       (S32 *)    &mr.table,
       (S32 *)    &mg.table,
       (S32 *)    &mb.table,
       (SINGLE *) m2);

   cube[0].r0 = cube[0].g0 = cube[0].b0 = 0;
   cube[0].r1 = cube[0].g1 = cube[0].b1 = 32;

   next = 0;

   for (i=1; i < colors; ++i)
      {
      if (Cut(&cube[next], &cube[i]))
         {
         //
         // Volume test ensures we won't try to cut one-cell box
         //

         vv[next] = (cube[next].vol > 1) ?
                    Var(&cube[next]) : 0.0F;

         vv[i]    = (cube[i].vol > 1)    ?
                    Var(&cube[i])    : 0.0F;
         }
      else
         {
         //
         // Don't try to split this box again
         // 

         vv[next] = 0.0F;
         i--;
         }

      next = 0; temp = vv[0];

      for (k=1; k <= i; ++k)
         {
         if (vv[k] > temp)
            {
            temp = vv[k];
            next = k;
            }
         }

      if (temp <= 0.0F)
         {
         colors = i+1;
         break;
         }
      }

   for (k=0; k < colors; ++k)
      {
      weight = Vol(&cube[k], &wt);

      if (weight)
         {
         out[k].r = (U8) (Vol(&cube[k], &mr) / weight);
         out[k].g = (U8) (Vol(&cube[k], &mg) / weight);
         out[k].b = (U8) (Vol(&cube[k], &mb) / weight);
         }
      else
         {
         out[k].r = out[k].g = out[k].b = 0;
         }
      }

   free(cube);
   free(vv);

   return colors;
}

/***************************************************************************/
//
// CMAP_class notes:
//
// Like CQ above, the CMAP functions require 8-bit RGB values
// for proper operation, and operate at 5-bit resolution internally.
//
/***************************************************************************/

/***************************************************************************/
//
// Construct an instance of CMAP_class
//
/***************************************************************************/

CMAP::CMAP(VFX_RGB *_palette, U32 _colors)
{
   U32 i;

   //
   // Warning: virtual functions unsupported!
   //
   
   memset(this, 0, sizeof(*this));

   best        = (S16 *) calloc(32768, sizeof(S16));
   second_best = (S16 *) calloc(32768, sizeof(S16));

   //
   // Initialize all RGB scoreboard values to -1 (unmapped)
   //

   for (i=0; i < 32768; i++)
      {
      best[i]        = -1;
      second_best[i] = -1;
      }

   palette = _palette;
   colors  = _colors;
}

/***************************************************************************/
//
// Free an instance of CMAP
//
/***************************************************************************/

CMAP::~CMAP()
{
   if (best != NULL)
      {
      free(best);
      best = NULL;
      }

   if (second_best != NULL)
      {
      free(second_best);
      second_best = NULL;
      }
}

/***************************************************************************/
//
// Find palette color whose RGB value is closest to *triplet
//
// Minimize sum of square axis displacements; true Euclidean 
// distance is not needed for comparisons
//
/***************************************************************************/

U8 CMAP::nearest_neighbor(VFX_RGB *triplet, S32 dither)
{
   U32        r,g,b,key,c1,c2,min,dist;
   S32        i,dr,dg,db;
   static U32 square[511];
   static U32 square_valid = 0;

   //
   // Convert 8-bit RGB to 5-bit RGB
   //

   r = triplet->r;
   g = triplet->g;
   b = triplet->b;

   //
   // If dithering, set up to return best or second-best match
   //

   S16 *choice = best;

   if (dither)
      {
      if ((rand() & 0x0f) >= dither)
         {
         choice = second_best;
         }
      }

   //
   // See if this triplet has already been remapped; if so, return
   // proper value immediately
   //

   key = ((r>>3) << 10) | ((g>>3) << 5) | (b>>3);

   if (choice[key] != -1)
      {
      return (U8) choice[key];
      }

   //
   // Build square[] table if not already valid
   //

   if (!square_valid)
      {
      for (i=-255; i<=255; i++)
         {
         square[i+255] = i*i;
         }

      square_valid = 1;
      }

   //
   // Find first- and second- best-fit palette entry
   //

   i   =  colors;
   min =  ULONG_MAX;
   c1  =  0;

   while (i > 0)
      {
      i--;
   
      dr = (S32) palette[i].r - (S32) r + 255;
      dg = (S32) palette[i].g - (S32) g + 255;
      db = (S32) palette[i].b - (S32) b + 255;

      dist = square[dr] + square[dg] + square[db];

      if (dist <= min)
         {
         c1 = i;

         if (dist > 0)
            {
            min = dist;
            }
         else
            {
            break;
            }
         }
      }

   i   =  colors;
   min =  ULONG_MAX;
   c2  = -1;

   while (i > 0)
      {
      i--;

      if (i == (S32) c1)
         {
         continue;
         }
   
      dr = (S32) palette[i].r - (S32) r + 255;
      dg = (S32) palette[i].g - (S32) g + 255;
      db = (S32) palette[i].b - (S32) b + 255;

      dist = square[dr] + square[dg] + square[db];

      if (dist <= min)
         {
         c2 = i;

         if (dist > 0)
            {
            min = dist;
            }
         else
            {
            break;
            }
         }
      }

   //
   // Log match in best-fit and second-best-fit scoreboards to avoid 
   // redundant searches later
   //

   best       [key] = (S16) c1;
   second_best[key] = (S16) c2;

   return (U8) choice[key];
}

#endif
