/****************************************************************************
*
*                        	  The SuperVGA Kit
*
*                   Copyright (C) 1994 SciTech Software
*                           All rights reserved.
*
* Filename:     $RCSfile: svga.h $
* Version:      $Revision: 1.1 $
*
* Language:     ANSI C
* Environment:  IBM PC (MSDOS) Real Mode and 16/32 bit Protected Mode.
*
* Description:  Header file for the small SuperVGA test library.
*               This library provides a simplified interface to SuperVGA
*               cards that have a VESA VBE (or with the Universal VESA
*               VBE installed). This library requires at least a
*               VBE 1.2 interface to function correctly.
*
*				For performance in protected modes, the SuperVGA Kit
*				internally caches the video memory selector in the FS
*				registes.
*
*               NOTE: This library only works in the large or flat models.
*
* $Id: svga.h 1.1 1994/08/22 12:27:14 kjb release $
*
****************************************************************************/

#ifndef __SVGA_H
#define __SVGA_H

#ifndef __DEBUG_H
#include "debug.h"
#endif

/*--------------------------- Global Variables ----------------------------*/

extern  int     maxx,maxy;          /* Maximum coordinate values        */
extern	long	maxcolor,defcolor;	/* Maximum and default colors		*/
extern  int     maxpage;            /* Maximum video page number        */
extern  int     bytesperline;       /* Bytes in a logical scanline      */
extern  int		bytesperpixel;		/* Bytes in a pixel (if > 1)		*/
extern  bool    twobanks;           /* True if separate banks available */
extern  int     memory;             /* Memory on board in k             */
extern  short   modeList[];         /* List of available video modes    */
extern  char    OEMString[];        /* OEM string from VBE              */
extern	bool	extendedflipping;	/* True if we have extended flipping*/
extern	bool	widedac;			/* True if wide dac is supported	*/

/* Pixel format information - used by the rgbColor() routine to build
 * the correct pixel format, but you can use it yourself to build scanline
 * information in the desired format.
 */

extern	uchar	redMask,greenMask,blueMask;
extern	int		redPos,redAdjust;
extern	int		greenPos,greenAdjust;
extern 	int		bluePos,blueAdjust;

typedef enum {
    memPL       = 3,                /* Planar memory model              */
    memPK       = 4,                /* Packed pixel memory model        */
    memRGB      = 6,                /* Direct color RGB memory model    */
    memYUV      = 7,                /* Direct color YUV memory model    */
    } memModels;

typedef struct {
	uchar	red;
	uchar	green;
	uchar	blue;
	} palette;

/*------------------------- Function Prototypes ---------------------------*/

#ifdef  __cplusplus
extern "C" {            /* Use "C" linkage when in C++ mode */
#endif

/* In svga.c */

int initSuperVGA(bool enableSpecialFeatures);
bool setSuperVGAMode(int mode);
void restoreMode(void);
bool getSuperVGAModeInfo(int mode,int *xres,int *yres,int *bytesperline,
    int *bitsperpixel,int *memmodel,int *maxpage,long *pagesize);
bool setSuperVGADisplayStart(int x,int y);
bool set8BitPalette(void);
bool set6BitPalette(void);
void setPalette(int start, int num, palette *palbuf);
void getPalette(int start, int num, palette *palbuf);
long rgbColor(uchar r,uchar g,uchar b);
void writeText(int x,int y,char *str,long color);

/* In svga.asm */

void _cdecl setActivePage(int page);
void _cdecl setVisualPage(int page);
void _cdecl setBank(int bank);
void _cdecl setReadBank(int bank);

extern void (_cdecl *putPixel)(int x,int y,long color);
extern void (_cdecl *clear)(long color);
extern void (_cdecl *line)(int x1,int y1,int x2,int y2,long color);

#ifdef  __cplusplus
}                       /* End of "C" linkage for C++   */
#endif

#endif  /* __SVGA_H */
