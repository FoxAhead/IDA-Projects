/****************************************************************************
*
*                        	  The SuperVGA Kit
*
*                   Copyright (C) 1994 SciTech Software.
*                           All rights reserved.
*
* Filename:     $RCSfile: vesavbe.h $
* Version:      $Revision: 1.1 $
*
* Language:     ANSI C
* Environment:  IBM PC (MSDOS) Real Mode and 16/32 bit Protected Mode.
*
* Description:  Header file declaring the structures used to comminucate
*               with a VESA VBE compliant BIOS.
*
*               MUST be compiled in the large model.
*
* $Id: vesavbe.h 1.1 1994/08/22 12:27:00 kjb release $
*
****************************************************************************/

#ifndef __VESAVBE_H
#define __VESAVBE_H

#ifndef __DEBUG_H
#include "debug.h"
#endif

/*---------------------- Macros and type definitions ----------------------*/

/* Note that to avoid compiler alignment problems (presently DJGPP doesnt
 * seem to support packing to a byte boundary) we declare the structures
 * to simply be simple char array's, and provide a set of macros for
 * extracting 16 and 32 bit values from the structures. Horrible but the
 * only possible solution for the time being.
 */

/* SuperVGA information block */

typedef struct {
    char    VESASignature[4];       /* 'VESA' 4 byte signature          */
	char    VESAVersion[2];         /* VBE version number               */
	char	OEMStringPtr[4];        /* Far pointer to OEM string        */
	char    Capabilities[4];        /* Capabilities of video card       */
	char	VideoModePtr[4];        /* Far pointer to supported modes   */
	char    TotalMemory[2];         /* Number of 64kb memory blocks     */
    char    reserved[232];          /* Pad to 256 byte block size       */
    } VgaInfoBlock;

/* SuperVGA mode information block */

typedef struct {
	char    ModeAttributes[2];      /* Mode attributes                  */
	char    WinAAttributes;         /* Window A attributes              */
	char    WinBAttributes;         /* Window B attributes              */
	char    WinGranularity[2];      /* Window granularity in k          */
	char    WinSize[2];             /* Window size in k                 */
	char    WinASegment[2];         /* Window A segment                 */
	char    WinBSegment[2];         /* Window B segment                 */
	char    WinFuncPtr[4];          /* Far pointer to window function   */
	char    BytesPerScanLine[2];    /* Bytes per scanline               */
	char    XResolution[2];         /* Horizontal resolution            */
	char    YResolution[2];         /* Vertical resolution              */
	char    XCharSize;              /* Character cell width             */
    char    YCharSize;              /* Character cell height            */
    char    NumberOfPlanes;         /* Number of memory planes          */
    char    BitsPerPixel;           /* Bits per pixel                   */
    char    NumberOfBanks;          /* Number of CGA style banks        */
    char    MemoryModel;            /* Memory model type                */
    char    BankSize;               /* Size of CGA style banks          */
    char    NumberOfImagePages;     /* Number of images pages           */
    char    res1;                   /* Reserved                         */
    char    RedMaskSize;            /* Size of direct color red mask    */
    char    RedFieldPosition;       /* Bit posn of lsb of red mask      */
    char    GreenMaskSize;          /* Size of direct color green mask  */
    char    GreenFieldPosition;     /* Bit posn of lsb of green mask    */
    char    BlueMaskSize;           /* Size of direct color blue mask   */
    char    BlueFieldPosition;      /* Bit posn of lsb of blue mask     */
    char    RsvdMaskSize;           /* Size of direct color res mask    */
    char    RsvdFieldPosition;      /* Bit posn of lsb of res mask      */
    char    DirectColorModeInfo;    /* Direct color mode attributes     */
    char    res2[216];              /* Pad to 256 byte block size       */
	} ModeInfoBlock;

#define	getShort(a)	(*((short*)&(a)))
#define	getLong(a)	(*((long*)&(a)))

#endif  /* __VESAVBE_H */
