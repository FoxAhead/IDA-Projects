//лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
//лл                                                                        лл
//лл  FLIC.H: C structure definitions                                       лл
//лл                                                                        лл
//лл  Source compatible with 32-bit 80386 C/C++                             лл
//лл                                                                        лл
//лл  Version 1.00 of 15-Feb-94: Initial version                            лл
//лл                                                                        лл
//лл  For use with API version 1.00                                         лл
//лл                                                                        лл
//лл  Project: 386FX Sound & Light(TM)                                      лл
//лл   Author: John Lemberger                                               лл
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

#include "vfx.h"

#ifndef FLIC_H
#define FLIC_H

#ifdef __cplusplus
extern "C" {
#endif

#define  FLI         0xaf11
#define  FLC         0xaf12

#define  FLIC_FRAME       0xf1fa
#define  FLIC_CHUNK       0xf100

#define  FLIC_PSTAMP      18
#define  FLIC_COPY        16
#define  FLIC_LITERAL     16
#define  FLIC_BLACK       13
#define  FLIC_BYTE_RUN    15
#define  FLIC_DELTA_FLI   12
#define  FLIC_DELTA_FLC    7
#define  FLIC_COLOR_256    4
#define  FLIC_COLOR_64    11


#define  FLIC_NEW_COLORS  0x0F000000

//
// Original structures taken from:
// "The Flic File Format", Jim Kent, March 1993, Dr. Dobb's Journal, #198
//

typedef struct _FLIC_HEADER
{
   ULONG size;             // size of entire file
   UWORD type;             // file-format identifier: .FLC=AF12, .FLI=AF11
   UWORD frames;           // number of frames in flic
   UWORD width;            // screen width in pixels
   UWORD height;           // screen height in pixels   
   UWORD depth;            // bits per pixel (always 8)
   UWORD flags;            // set to hex 0003   
   ULONG speed;            // time delay between frames: .FLI in 1/70 sec
                           //                            .FLC in milliseconds 
                            
   UWORD reserved1;        // set to 0
                              
   ULONG created;          // MSDOS formatted date and time (.FLC only)   
   ULONG creator;          // Animator pro puts serial number here
   ULONG updated;          // MSDOS formatted date and time (.FLC only)
   ULONG updater;          // Animator pro puts serial number here
   UWORD aspectx;          // x-axis aspect ratio of creating machine (.FLC)
   UWORD aspecty;          // y-axis aspect ration of creating machine (.FLC)
                           // 320x200 = 6:5

                           
   UBYTE reserved2[38];    // set to 0
                           
   ULONG oframe1;          // file offset of first frame (.FLC only)
   ULONG oframe2;          // file offset of second frame (.FLC only)

   UBYTE reserved3[40];    // set to 0
}
FLIC_HEADER;


typedef struct _FLIC_CHUNK
{
   ULONG size;             // chunk size, including subchunks & header
   UWORD type;             // prefix chunk identifier, always 0xf100
   UWORD chunks;           // number of subchunks;
   UBYTE reserved[8];      // set to 0
}
FLIC_CHUNK_HEADER;


typedef struct _FLIC_FRAME
{
   ULONG size;             // frame chunk size, including subchunks & header
   UWORD type;             // prefix chunk identifier, always 0xf1fa
   UWORD chunks;           // number of subchunks;
   UBYTE reserved[8];      // set to 0
}
FLIC_FRAME_HEADER;


typedef struct _FLIC
{
   FLIC_HEADER        *header;
   FLIC_FRAME_HEADER  *frame;
   FLIC_CHUNK_HEADER  *chunk;
}
FLIC;

extern LONG FLIC_frame_draw(PANE *pane, FLIC *flic, RGB *palette);

#ifdef __cplusplus
}
#endif

#endif
