//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
//лл                                                                        лл
//лл  VFXREND.H: General-purpose polygon rendering package                  лл
//лл                                                                        лл
//лл  Source compatible with 32-bit 80386 C/C++                             лл
//лл                                                                        лл
//лл  V1.00 of  6-Nov-93: Initial version                                   лл
//лл  V1.01 of 22-Nov-93: MetaWare support, new SMP_ equates                лл
//лл  V1.02 of 13-Dec-93: Screen coords changed to integers                 лл
//лл  V1.03 of 16-Jan-94: Signed LONG screen coords                         лл
//лл                      Indirect Gouraud shading added                    лл
//лл                      Clipping code merged                              лл
//лл                      VFX_polygon_render() now uses panes               лл
//лл                                                                        лл
//лл  Project: 386FX Sound & Light(TM)                                      лл
//лл   Author: John Miles, John Lemberger                                   лл
//лл                                                                        лл
//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
//лл                                                                        лл
//лл  Copyright (C) 1993 Miles Design, Inc.                                 лл
//лл  Copyright (C) 1994 Non-Linear Arts, Inc.                              лл
//лл                                                                        лл
//лл  Non-Linear Arts, Inc.                                                 лл
//лл  3415 Greystone Drive                                                  лл
//лл  Suite 200                                                             лл
//лл  Austin, TX 78731                                                      лл
//лл                                                                        лл
//лл  Support: (512) 346-9595 / FAX (512) 346-9596 / BBS (512) 454-9990     лл
//лл                                                                        лл
//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

#ifndef VFXREND_H
#define VFXREND_H

#include "vfx.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef TYPEDEFS
#define TYPEDEFS

typedef unsigned char  UBYTE;
typedef unsigned short UWORD;
typedef unsigned long  ULONG;
typedef char  BYTE;
typedef short WORD;
typedef long  LONG;
typedef float FLOAT;

typedef long  FIXED16;          // 16:16 fixed-point type [-32K,+32K]
typedef long  FIXED30;          // 2:30 fixed-point type [-1.999,+1.999]

#endif

#define INT_TO_FIXED16(x)       (((long)(int)(x)) << 16)
#define DOUBLE_TO_FIXED16(x)    ((long) ((x) * 65536.0 + 0.5))
#define FIXED16_TO_DOUBLE(x)    (((double)(x)) / 65536.0)
#define FIXED16_TO_INT(x)       ((int) ((x)<0 ? -(-(x) >> 16) : (x) >> 16))
#define ROUND_FIXED16_TO_INT(x) ((int) ((x)<0 ? -((32768-(x)) >> 16) : ((x)+32768) >> 16))

#define FIXED16_TO_FIXED30(x)   ((x) << 14)
#define FIXED30_TO_FIXED16(x)   ((x) >> 14)
#define FIXED30_TO_DOUBLE(x)    (((double)x) / 1073741824.0)
#define DOUBLE_TO_FIXED30(x)    ((long) (x * 1073741824.0 + 0.5))

//
// MetaWare support
//

#ifdef __HIGHC__
#define cdecl _CC(_REVERSE_PARMS | _NEAR_CALL)
#pragma Global_aliasing_convention("_%r");
#pragma Align_members(1)

#ifndef FAR_PTR_DEF
#define FAR_PTR_DEF

typedef struct   // Union used to build far pointers under MetaWare
{
   ULONG off;
   UWORD seg;
}
fp_ovl;

typedef union
{
   _Far void *ptr;
   fp_ovl part;
}
FARPTR;

#endif
#endif

//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
//лл                                                                        лл
//лл Polygon description = list of POLYVERTEX structures                    лл
//лл                                                                        лл
//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

typedef struct
{
   //
   // x,y are output coordinates given at integer precision
   //

   LONG x;
   LONG y;

   FIXED16 c;

   //
   // u,v used with PERSPECT or AFFINE mapping
   // w   used with PERSPECT mapping only
   //
   // If MAPPING=PERSPECT, then u = texture x / viewspace z
   //                           v = texture y / viewspace z
   //                           w =       1.0 / viewspace z
   //
   //   If MAPPING=AFFINE, then u = texture x
   //                           v = texture y
   //                           w = don't care
   //

   FIXED16 u;
   FIXED16 v;
   FIXED30 w;
}
VFX_VERTEX;               

//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
//лл                                                                        лл
//лл Texture description structure                                          лл
//лл                                                                        лл
//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

typedef struct
{
   void **V_addrs;      // Pointer to beginning of V-baseline address table

   ULONG width;         // Tiling limits
   ULONG height;
}
VFX_TEXTURE;

//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
//лл                                                                        лл
//лл Polygon rendering and clipping functions                               лл
//лл                                                                        лл
//лл             pane: Pointer to VFX PANE structure                        лл
//лл                                                                        лл
//лл vlist, nvertices: List of VFX_VERTEX structures describing a convex or лл
//лл                   horizontally concave polygon.                        лл
//лл                                                                        лл
//лл        operation: Desired rendering operation(s); see below            лл
//лл                                                                        лл
//лл          texture: Texture map source parameter, or NULL if no texture  лл
//лл                   mapping requested                                    лл
//лл                                                                        лл
//лл           cueing: For flat lighting (MAP_ILLUM | SHD_FLAT), points to  лл
//лл                   a 256-byte lookaside table for each pixel color in   лл
//лл                   polygonal area.  For Gouraud lighting (MAP_ILLUM |   лл
//лл                   SHD_GOURAUD), points to a [][256]-byte lookaside     лл
//лл                   table, where the first dimension [] corresponds to   лл
//лл                   the maximum possible vertex[].c cueing level.        лл
//лл                                                                        лл
//лл                   The cueing table is also used for MAP_AFFINE and     лл
//лл                   MAP_PERSPECT, when invoked with SHD_FLAT or          лл
//лл                   SHD_GOURAUD.  In this case, the MAP_ILLUM parameter  лл
//лл                   should not be specified.                             лл
//лл                                                                        лл
//лл     translucency: Used when XP_XLUCENT accompanies MAP_AFFINE or       лл
//лл                   MAP_PERSPECT, this should point to a 256-byte color  лл
//лл                   lookaside table to translate the pixels underlying   лл
//лл                   transparent areas in the texture-mapped polygon.     лл
//лл                                                                        лл
//лл                   When SHD_I_GOURAUD is in effect, *translucency       лл
//лл                   points to a 256-byte table which contains output     лл
//лл                   color values corresponding to the interpolated       лл
//лл                   vertex[].c values.                                   лл
//лл                                                                        лл
//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

//
// WARNING: Do not call VFX_polygon_render() with any flag combination that
//          does not correspond to a valid entry in VFXREND.ASM's BUILD table!
//

#define MAP_ILLUM     0x0000  // Translate existing pixels only (flat/Gouraud)
#define MAP_SOLID     0x0200  // Draw solid polygon only (flat/Gouraud)
#define MAP_AFFINE    0x0400  // Draw affine texture map 
#define MAP_PERSPECT  0x0600  // Draw perspective texture map
                      
#define SHD_NONE      0x0000  // No shading
#define SHD_FLAT      0x0080  // Output translated via 256-byte flat shading
#define SHD_GOURAUD   0x0040  // Outout translated via Gouraud lookaside
#define SHD_I_GOURAUD 0x00c0  // Output written as indirect Gouraud fill
#define SHD_R_GOURAUD 0x0100  // Output written as palette-range Gouraud fill

#define SMP_FINE      0x0000  // Normal (1:1) texture sampling
#define SMP_COARSE    0x0020  // Subsample texture by 2:1
                      
#define TIL_NONE      0x0000  // No tiling
#define TIL_LOG       0x0010  // Tiling in binary-power increments only (2^n)
#define TIL_LIN       0x0008  // Tiling in linear (arbitrary) increments
                      
#define XP_NONE       0x0000  // No transparency processing
#define XP_SKIP       0x0001  // Skip transparent pixels
#define XP_FLAT       0x0002  // Draw transparent pixels as v[0].c
#define XP_XLUCENT    0x0003  // Draw transparent pixels as translucency[scrn]
#define XP_R_GOURAUD  0x0004  // Draw transparent pixels with Gouraud shading
#define XP_I_GOURAUD  0x0007  // Draw transparent pixels with indirect shading

extern void cdecl VFX_polygon_render(
   PANE        *pane,
   VFX_VERTEX  *vlist, 
   ULONG        nvertices,
   ULONG        operation,
   ULONG        color,
   VFX_TEXTURE *texture,
   void        *cueing, 
   void        *translucency);

extern void cdecl VFX_polygon_clip_XY_and_render(
   PANE        *pane,
   VFX_VERTEX  *vlist, 
   ULONG        nvertices,
   ULONG        operation,
   ULONG        color,
   VFX_TEXTURE *texture,
   void        *cueing, 
   void        *translucency);

extern FIXED30 cdecl F16_div_to_F30 (FIXED16 dividend, FIXED16 divisor);
extern FIXED30 cdecl F30_reciprocal (FIXED16 value);
extern FIXED16 cdecl mul_F30        (FIXED16 M1,       FIXED30 M2);
                                                          
//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
//лл                                                                        лл
//лл Set the dither level (nominally 0x8000,0; 0,0=no dithering) for        лл
//лл Gouraud shading effects                                                лл
//лл                                                                        лл
//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

extern void cdecl VFX_set_Gouraud_dither_level(FIXED16 dither_1, 
   FIXED16 dither_2);

#ifdef __cplusplus
}
#endif

//
// MetaWare support
//

#ifdef __HIGHC__
#pragma Global_aliasing_convention();
#endif

#endif


