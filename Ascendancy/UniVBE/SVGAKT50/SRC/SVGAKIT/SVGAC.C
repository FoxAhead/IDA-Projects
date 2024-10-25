/****************************************************************************
*
*                        	  The SuperVGA Kit
*
*                   Copyright (C) 1994 SciTech Software
*                           All rights reserved.
*
* Filename:     $RCSfile: svgac.c $
* Version:      $Revision: 1.1 $
*
* Language:     ANSI C
* Environment:  IBM PC (MSDOS) Real Mode and 16/32 bit Protected Mode.
*
* Description:  Simple library to collect together the functions in the
*               SuperVGA test library for use in other C programs. The
*               support is reasonably low level, so you can do what you
*               want. The set of routines in this source file are general
*               SuperVGA routines and are independant of the video mode
*               selected.
*
*               MUST be compiled in the large model.
*
* $Id: svgac.c 1.1 1994/08/22 12:27:00 kjb release $
*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dos.h>
#include "pmode.h"
#include "svga.h"
#include "vesavbe.h"

/*---------------------------- Global Variables ---------------------------*/

#define MAXMODES    50              /* Maximum modes available in list  */

int     maxx,maxy,memory;
long	maxcolor,defcolor;
int     maxpage,bytesperline,bytesperpixel;
uchar	redMask,greenMask,blueMask;
int		redPos,redAdjust;
int		greenPos,greenAdjust;
int		bluePos,blueAdjust;
bool    twobanks = false;
short   modeList[MAXMODES];
char    OEMString[80];

bool    extendedflipping = false;   /* True for extended flipping enable*/
bool	widedac = false;			/* True for 8 bit DAC support		*/
int     oldMode = 0x3;              /* Old video mode number            */
bool    old50Lines;                 /* Was old mode 80x50?              */
int     curBank;                    /* Current read/write bank          */
int     bankShift;                 	/* Bank granularity adjust factor   */
long    pagesize;                   /* Page size for current mode       */
void    *bankSwitch;           		/* Pointer to bank switch routine   */
void    *writeBank;					/* Pointer to write bank routine	*/
void    *readBank;					/* Pointer to read bank routine     */
uint	VESABuf_sel;				/* Selector for VESABuf (1k size)	*/
uint	VESABuf_off;				/* Offset for VESABuf (1k size)		*/
uint	VESABuf_rseg;				/* Real mode segment of VESABuf		*/
uint	VESABuf_roff;				/* Real mode offset of VESABuf		*/
int		oldFS;						/* Old value of FS selector			*/
void 	(_cdecl *line)(int x1,int y1,int x2,int y2,long color);
void 	(_cdecl *putPixel)(int x,int y,long color);
void 	(_cdecl *clear)(long color);

extern	uchar font8x16[];			/* Bitmap font definition			*/

/*----------------------------- Implementation ----------------------------*/

/* Declare all video mode dependent routines */

int _cdecl _setFS(uint sel);
void _cdecl _clear16(long color);
void _cdecl _clear256(long color);
void _cdecl _clear32k(long color);
void _cdecl _clear16m(long color);
void _cdecl _clear4G(long color);
void _cdecl _putPixel16(int x,int y,long color);
void _cdecl _putPixel256(int x,int y,long color);
void _cdecl _putPixel32k(int x,int y,long color);
void _cdecl _putPixel16m(int x,int y,long color);
void _cdecl _putPixel4G(int x,int y,long color);
void _cdecl _line16(int x1,int y1,int x2,int y2,long color);
void _cdecl _line256(int x1,int y1,int x2,int y2,long color);
void _cdecl _line32k(int x1,int y1,int x2,int y2,long color);
void _cdecl _line16m(int x1,int y1,int x2,int y2,long color);
void _cdecl _line4G(int x1,int y1,int x2,int y2,long color);
void _cdecl _EMU_line(int x1,int y1,int x2,int y2,long color);

PRIVATE void CallVBE(RMREGS *regs, void *buffer, int size)
/****************************************************************************
*
* Function:		CallVBE
* Parameters:	regs	- Registers to load when calling VBE
*				buffer	- Buffer to copy VBE info block to
*				size	- Size of buffer to fill
*
* Description:	Calls the VESA VBE and passes in a buffer for the VBE to
*				store information in, which is then copied into the users
*				buffers space. This works in protected mode as the buffer
*				passed to the VESA VBE is allocated in conventional
*				memory, and is then copied into the users memory block.
*
****************************************************************************/
{
	RMSREGS	sregs;

	sregs.es = VESABuf_rseg;
	regs->x.di = VESABuf_roff;
	PM_int86x(0x10, regs, regs, &sregs);
	PM_memcpynf(buffer, VESABuf_sel, VESABuf_off, size);
}

PRIVATE void exitSuperVGA(void)
/****************************************************************************
*
* Function:		exitSuperVGA
*
* Description:	Cleans up after using the SuperVGA library. We need to
*				de-allocate any real mode memory that we have allocated
*				during the operation of the library, and any protected
*				mode pointers etc.
*
****************************************************************************/
{
	PM_freeRealSeg(VESABuf_sel,VESABuf_off);
}

PUBLIC int initSuperVGA(bool enableSpecialFeatures)
/****************************************************************************
*
* Function:     initSuperVGA
* Parameters:	enableSpecialFeatures	- True to enable enhanced features
* Returns:      VBE version number for the SuperVGA (0 if no SuperVGA).
*
* Description:  Detects if a VESA VBE compliant SuperVGA is out there, and
*               initialises the library if one is. The VBE version number
*               is specified with the major version number in the high
*               byte and the minor version number in the low byte. So
*               version 1.2 is the number 0x102.
*
****************************************************************************/
{
	VgaInfoBlock    vgaInfo;
	ModeInfoBlock   modeInfo;
	RMREGS      	regs;
	short			*p;
	uint			sel,off;
	ulong			addr;
	int				i;

	/* Allocate a global buffer for communicating with the VESA VBE */
	if (!PM_allocRealSeg(1024, &VESABuf_sel,  &VESABuf_off, &VESABuf_rseg,
			&VESABuf_roff)) {
		fprintf(stderr, "PM_allocRealSeg failed!\n");
		exit(1);
		}

    regs.x.ax = 0x4F00;     /* Get SuperVGA information */
	CallVBE(&regs, &vgaInfo, sizeof(vgaInfo));
	if (regs.x.ax != 0x004F)
		return false;
	if (strncmp(vgaInfo.VESASignature,"VESA",4) != 0)
		return false;

	/* Copy relevent information from the mode block into our globals.
	 * Note that the video mode list _may_ be built in the information
	 * block that we have passed, so we _must_ copy this from here
	 * into our our storage if we want to continue to use it. Note
	 * that we filter out the mode 0x6A, which some BIOSes include as
	 * well as the 0x102 mode for 800x600x16.
	 */

	addr = getLong(vgaInfo.VideoModePtr);
	PM_mapRealPointer(&sel,&off,addr >> 16, addr & 0xFFFF);
	for (i = 0; PM_getWord(sel,off) != 0xFFFF; off += 2,i++) {
		if (PM_getWord(sel,off) != 0x6A)
			modeList[i] = PM_getWord(sel,off);
		}
	modeList[i] = -1;
	memory = getShort(vgaInfo.TotalMemory) * 64;
	addr = getLong(vgaInfo.OEMStringPtr);
	PM_mapRealPointer(&sel,&off,addr >> 16, addr & 0xFFFF);
	PM_memcpynf(OEMString,sel,off,sizeof(OEMString));

	/* Determine if the board supports separate read/write banks */
	for (p = modeList; *p != -1; p++) {
		regs.x.ax = 0x4F01;					/* Get SuperVGA mode info   */
		regs.x.cx = *p;
        CallVBE(&regs, &modeInfo, sizeof(modeInfo));
        if (regs.x.ax == 0x004F &&
				(modeInfo.MemoryModel == 3 || modeInfo.MemoryModel == 4)) {
			modeInfo.WinBAttributes &= 0x7;
			twobanks = (modeInfo.WinBAttributes == 0x3);

			/* Check for support of extended page flipping and wide palettes.
			 * We need to initialise a video mode to do this.
			 */

			if (enableSpecialFeatures) {
				setSuperVGAMode(*p);
				extendedflipping = setSuperVGADisplayStart(10,10);
				widedac = set8BitPalette() && set6BitPalette();
				restoreMode();
				}
			break;
			}
		}

	atexit(exitSuperVGA);	/* Ensure our exit routine is always called	*/

	return getShort(vgaInfo.VESAVersion);
}

PRIVATE void computePageInfo(ModeInfoBlock *modeInfo,int *maxpage,
	long *pagesize)
/****************************************************************************
*
* Function:     computePageInfo
* Parameters:   modeInfo    - Pointer to valid mode information block
*               maxpage     - Number of display pages - 1
*               pagesize    - Size of each logical display page in bytes
*
* Description:  Computes the number of image pages and size of each image
*               page for a specified video mode.
*
****************************************************************************/
{
    long    memsize,size;

	if (!extendedflipping) {
		if (modeInfo->MemoryModel == memPL)
			memsize = 256 * 1024L;
		else memsize = 64 * 1024L;
		}
	else
		memsize = memory * 1024L;

	size = (long)getShort(modeInfo->BytesPerScanLine) *
		   (long)getShort(modeInfo->YResolution);
	if (modeInfo->BitsPerPixel == 4) {
        /* We have a 16 color video mode, so round up the page size to
         * 8k, 16k, 32k or 64k boundaries depending on how large it is.
         */

        size = (size + 0x1FFFL) & 0xFFFFE000L;
        if (size != 0x2000) {
            size = (size + 0x3FFFL) & 0xFFFFC000L;
            if (size != 0x4000) {
                size = (size + 0x7FFFL) & 0xFFFF8000L;
				if (size != 0x8000)
                    size = (size + 0xFFFFL) & 0xFFFF0000L;
                }
            }
        }
    else
        size = (size + 0xFFFFL) & 0xFFFF0000L;

	if (modeInfo->MemoryModel == memPL)
        memsize /= 4;
    if (size <= memsize)
        *maxpage = (memsize / size) - 1;
    else
        *maxpage = 0;
    *pagesize = size;
}

PUBLIC bool getSuperVGAModeInfo(int mode,int *xres,int *yres,
    int *bytesperline,int *bitsperpixel,int *memmodel,int *maxpage,
    long *pagesize)
/****************************************************************************
*
* Function:     getSuperVGAModeInfo
* Parameters:   mode            - Mode to get information about
*               xres            - Place to store x resolution
*               yres            - Place to store y resolution
*               bytesperline    - Bytes per scanline
*               bitsperpixel    - Place to store bits per pixel (2^n colors)
*               memmodel        - Memory model for mode (planar, packed etc)
*               maxpage         - Number of display pages - 1
*               pagesize        - Size of each logical display page in bytes
* Returns:      True if mode number was valid, false if not.
*
* Description:  Obtains information about a specific video mode from the
*               VBE. You should use this function to find the video mode
*               you wish to set, as the new VBE 2.0 mode numbers may be
*               completely arbitrary.
*
****************************************************************************/
{
    ModeInfoBlock   modeInfo;
	RMREGS      	regs;

	if (mode <= 0x13) {
        /* This is a standard VGA mode, so fill in the required information
		 * ourselves.
         */

        switch (mode) {
            case 0x0D:
				getShort(modeInfo.XResolution) = 320;
				getShort(modeInfo.YResolution) = 200;
				getShort(modeInfo.BytesPerScanLine) = 40;
				modeInfo.BitsPerPixel = 4;
				modeInfo.MemoryModel = memPL;
				break;
			case 0x0E:
				getShort(modeInfo.XResolution) = 640;
				getShort(modeInfo.YResolution) = 200;
				getShort(modeInfo.BytesPerScanLine) = 80;
                modeInfo.BitsPerPixel = 4;
                modeInfo.MemoryModel = memPL;
                break;
			case 0x10:
				getShort(modeInfo.XResolution) = 640;
				getShort(modeInfo.YResolution) = 350;
				getShort(modeInfo.BytesPerScanLine) = 80;
                modeInfo.BitsPerPixel = 4;
                modeInfo.MemoryModel = memPL;
                break;
            case 0x12:
				getShort(modeInfo.XResolution) = 640;
				getShort(modeInfo.YResolution) = 480;
				getShort(modeInfo.BytesPerScanLine) = 80;
                modeInfo.BitsPerPixel = 4;
                modeInfo.MemoryModel = memPL;
                break;
            case 0x13:
				getShort(modeInfo.XResolution) = 320;
				getShort(modeInfo.YResolution) = 200;
				getShort(modeInfo.BytesPerScanLine) = 320;
                modeInfo.BitsPerPixel = 8;
                modeInfo.MemoryModel = memPK;
                break;
            default:
                return false;
            }
        }
    else {
        /* This is a VESA mode, so call the BIOS to get information about
		 * it.
         */

		regs.x.ax = 0x4F01;				/* Get mode information         */
		regs.x.cx = mode;
		CallVBE(&regs, &modeInfo, sizeof(modeInfo));
		if (regs.x.ax != 0x004F)
			return false;
		if ((getShort(modeInfo.ModeAttributes) & 0x1) == 0)
			return false;
		}
	*xres = getShort(modeInfo.XResolution);
	*yres = getShort(modeInfo.YResolution);
	*bytesperline = getShort(modeInfo.BytesPerScanLine);
	*memmodel = modeInfo.MemoryModel;
	*bitsperpixel = modeInfo.BitsPerPixel;

	/* Emulate RGB modes using a 3 3 2 palette arrangement by default */
	redMask = 0x7;		redPos = 5;		redAdjust = 5;
	greenMask = 0x7;	greenPos = 2;	greenAdjust = 5;
	blueMask = 0x3;		bluePos = 0;	blueAdjust = 6;

	if (*memmodel == memPK && *bitsperpixel > 8) {
		/* Support old style definitions, which some BIOS'es still use :-( */
		*memmodel = memRGB;
		switch (*bitsperpixel) {
			case 15:
				redMask = 0x1F;		redPos = 10;	redAdjust = 3;
				greenMask = 0x1F;	greenPos = 5;	greenAdjust = 3;
				blueMask = 0x1F;	bluePos = 0;	blueAdjust = 3;
				break;
			case 16:
				redMask = 0x1F;		redPos = 11;	redAdjust = 3;
				greenMask = 0x3F;	greenPos = 5;	greenAdjust = 2;
				blueMask = 0x1F;	bluePos = 0;	blueAdjust = 3;
				break;
			case 24:
			case 32:
				redMask = 0xFF;		redPos = 16;	redAdjust = 0;
				greenMask = 0xFF;	greenPos = 8;	greenAdjust = 0;
				blueMask = 0xFF;	bluePos = 0;	blueAdjust = 0;
				break;
			}
		}
	else if (*memmodel == memRGB) {
        /* Convert the 32k direct color modes of VBE 1.2+ BIOSes to
         * be recognised as 15 bits per pixel modes.
         */

        if (*bitsperpixel == 16 && modeInfo.RsvdMaskSize == 1)
			*bitsperpixel = 15;

		/* Save direct color info mask positions etc */

		redMask = (0xFF >> (redAdjust = 8 - modeInfo.RedMaskSize));
		redPos = modeInfo.RedFieldPosition;
		greenMask = (0xFF >> (greenAdjust = 8 - modeInfo.GreenMaskSize));
		greenPos = modeInfo.GreenFieldPosition;
		blueMask = (0xFF >> (blueAdjust = 8 - modeInfo.BlueMaskSize));
		bluePos = modeInfo.BlueFieldPosition;
		}
	switch (*bitsperpixel) {
		case 15:
		case 16:
			bytesperpixel = 2;
			break;
		case 24:
			bytesperpixel = 3;
			break;
		case 32:
			bytesperpixel = 4;
			break;
		default:
			bytesperpixel = 1;
			break;
		}
	computePageInfo(&modeInfo,maxpage,pagesize);
	return true;
}

PUBLIC bool setSuperVGAMode(int mode)
/****************************************************************************
*
* Function:     setSuperVGAMode
* Parameters:   mode    - SuperVGA video mode to set.
* Returns:      True if the mode was set, false if not.
*
* Description:  Attempts to set the specified video mode. This routine
*               assumes that the library and SuperVGA have been initialised
*               with the initSuperVGA() routine first.
*
****************************************************************************/
{
    ModeInfoBlock   modeInfo;
	RMREGS      	regs;
	int             bitsperpixel,memmodel;

	regs.x.ax = 0x0F00;
	PM_int86(0x10, &regs, &regs);
    oldMode = regs.x.ax & 0x7F;         /* Save old video mode          */
    old50Lines = false;                 /* Default to 25 line mode      */
    if (oldMode == 0x3) {
        regs.x.ax = 0x1130;
        regs.x.bx = 0;
        regs.x.dx = 0;
		PM_int86(0x10,&regs,&regs);
        old50Lines = (regs.h.dl == 49);
        }

    regs.x.ax = 0x4F02;
    regs.x.bx = mode;
	PM_int86(0x10,&regs,&regs);      	/* Set the video mode           */
    if (regs.x.ax != 0x004F)
        return false;

    getSuperVGAModeInfo(mode,&maxx,&maxy,&bytesperline,&bitsperpixel,
        &memmodel,&maxpage,&pagesize);
    maxx--; maxy--;

	/* Now set up the vectors to the correct routines for the video
	 * mode type.
	 */

	switch (bitsperpixel) {
		case 4:
			clear = _clear16;
			putPixel = _putPixel16;
			line = _line16;
			maxcolor = defcolor = 15;
			break;
		case 8:
			clear = _clear256;
			putPixel = _putPixel256;
			line = _line256;
			maxcolor = 255;
			defcolor = 15;
			break;
		case 15:
			clear = _clear32k;
			putPixel = _putPixel32k;
			line = _line32k;
			maxcolor = defcolor = 0x7FFF;
			break;
		case 16:
			clear = _clear32k;
			putPixel = _putPixel32k;
			line = _line32k;
			maxcolor = defcolor = 0xFFFF;
			break;
		case 24:
			clear = _clear16m;
			putPixel = _putPixel16m;
			line = _line16m;
			maxcolor = defcolor = 0xFFFFFF;
			break;
		case 32:
			clear = _clear4G;
			putPixel = _putPixel4G;
			line = _line4G;
			maxcolor = defcolor = 0xFFFFFF;
			break;
		}

	if (mode <= 0x13) {
		/* This is a normal VGA style mode, so we need to determine the
		 * correct information for bank switching from the BIOS
		 */

		if (mode == 0x13)
			mode = 0x101;
		else
			mode = 0x102;
		}
	regs.x.ax = 0x4F01;				/* Get mode information         */
	regs.x.cx = mode;
	CallVBE(&regs, &modeInfo, sizeof(modeInfo));
	bankShift = 0;
	while ((64 >> bankShift) != getShort(modeInfo.WinGranularity))
		bankShift++;
	curBank = -1;

	/* Create a pointer to the real mode function for bank switching. In
	 * protected mode it is extremely complicated and slow to call a
	 * real mode function from low level assembly language, so we simply
	 * set the routine to NULL so that the Int 10h interface will be used
	 * instead.
	 */
	if (_PM_modeType == PM_realMode)
		bankSwitch = (void *)getLong(modeInfo.WinFuncPtr);
	else bankSwitch = NULL;

	/* Now set up the vectors to the appropriate bank switching routines.
	 * If the Universal VESA VBE is installed, we can move the bank
	 * switching routines from there into our own code space for speed
	 * (especially under protected mode).
	 */

	writeBank = readBank = NULL;
#ifdef	PM386
	{
		uint	sel,off;
		RMSREGS	sregs;

		regs.x.ax = 0x4F0A;
		regs.x.bx = 0xFE01;
		regs.x.dx = 0x0500;
		PM_int86x(0x10, &regs, &regs, &sregs);
		if (regs.x.ax == 0x004F) {
			PM_mapRealPointer(&sel,&off,sregs.es,regs.x.di);
			writeBank = malloc(regs.x.dx);
			PM_memcpynf(writeBank,sel,off,regs.x.dx);
			}

		regs.x.ax = 0x4F0A;
		regs.x.bx = 0xFE01;
		regs.x.dx = 0x0501;
		PM_int86x(0x10, &regs, &regs, &sregs);
		if (regs.x.ax == 0x004F) {
			PM_mapRealPointer(&sel,&off,sregs.es,regs.x.di);
			readBank = malloc(regs.x.dx);
			PM_memcpynf(readBank,sel,off,regs.x.dx);
			}
	}
#endif

	oldFS = _setFS(PM_getVGASelector());	/* Set FS to VGA selector	*/
	return true;
}

PUBLIC void restoreMode(void)
/****************************************************************************
*
* Function:     restoreMode
*
* Description:  Restore the previous video mode in use before the SuperVGA
*               mode was set. This routine will also restore the 50 line
*               display mode if this mode was previously set.
*
****************************************************************************/
{
	RMREGS	regs;

	_setFS(oldFS);					/* Restore value of FS selector	*/
	free(readBank);					/* Free the relocated reoutines	*/
	free(writeBank);				/* if any were allocated		*/
	regs.x.ax = oldMode;
	PM_int86(0x10,&regs,&regs);     /* Set the old video mode       */
	if (old50Lines) {
		regs.x.ax = 0x1112;
		regs.x.bx = 0;
		PM_int86(0x10,&regs,&regs);	/* Restore 50 line mode         */
		}
}

bool setSuperVGADisplayStart(int x,int y)
/****************************************************************************
*
* Function:     setDisplayStart
* Parameters:   x,y - Position of the first pixel to display
* Returns:		True if function was successful.
*
* Description:  Sets the new starting display position to implement
*               hardware scrolling.
*
****************************************************************************/
{
	RMREGS  regs;

	regs.x.ax = 0x4F07;
	regs.x.bx = 0x0000;
	regs.x.cx = x;
	regs.x.dx = y;
	PM_int86(0x10,&regs,&regs);
	if (regs.x.ax != 0x004F)
		return false;
	return true;
}

bool set8BitPalette(void)
/****************************************************************************
*
* Function:		set8BitPalette
* Returns:		True if 8 bit wide palette has been set.
*
* Description:	Attempts to set the system into the 8 bit wide palette
*				mode if supported by the VBE. Returns true on success, false
*				otherwise.
*
****************************************************************************/
{
	RMREGS  regs;

	regs.x.ax = 0x4F08;         /* Set DAC service                      */
	regs.x.bx = 0x0800;         /* BH := 8, BL := 0 (set DAC width)     */
	PM_int86(0x10,&regs,&regs);
	if (regs.x.ax != 0x004F)
		return false;           /* Function failed, no wide dac         */
	if (regs.h.bh == 6)
		return false;
	regs.x.ax = 0x4F08;
	regs.x.bx = 0x0001;         /* Get DAC width (should now be 8)      */
	PM_int86(0x10,&regs,&regs);
	if (regs.x.ax != 0x004F)
		return false;
	if (regs.h.bh != 8)
		return false;
	return true;
}

bool set6BitPalette(void)
/****************************************************************************
*
* Function:		set6BitPalette
* Returns:		True if 6 bit wide palette has been set.
*
* Description:	Attempts to set the system back into the 6 bit wide palette
*				mode if supported by the VBE. Returns true on success, false
*				otherwise.
*
****************************************************************************/
{
	RMREGS  regs;

	regs.x.ax = 0x4F08;
	regs.x.bx = 0x0600;
	PM_int86(0x10,&regs,&regs);	/* Restore to 6 bit DAC               */
	if (regs.x.ax != 0x004F)
        return true;
	if (regs.h.bh != 6)
		return false;
	return true;
}

void setPalette(int start, int num, palette *palbuf)
/****************************************************************************
*
* Function:		setPalette
* Parameters:	start	- Starting index number
*				num		- Number of entries to program
*				palbuf	- Buffer of palette values to program
*
* Description:	Sets the palette values. The values should be in the
*				range 0-63 if the palette is in the 6 bit mode, or 0-255
*				if the palette is in the 8 bit mode. The palette is
*				programmed via the BIOS.
*
****************************************************************************/
{
	RMREGS	regs;
	RMSREGS	sregs;

	regs.x.ax = 0x1012;
	regs.x.bx = start;
	regs.x.cx = num;
	sregs.es = VESABuf_rseg;
	regs.x.dx = VESABuf_roff;
	PM_memcpyfn(VESABuf_sel,VESABuf_off, palbuf, num * 3);
	PM_int86x(0x10, &regs, &regs, &sregs);
}

void getPalette(int start, int num, palette *palbuf)
/****************************************************************************
*
* Function:		getPalette
* Parameters:	start	- Starting index number
*				num		- Number of entries to read
*				red		- Array of red values (0-63 or 0-255)
*				green	- Array of green values (0-63 or 0-255)
*				blue	- Array of blue values (0-63 or 0-255)
*
* Description:	Reads the current palette values.
*
****************************************************************************/
{
	RMREGS	regs;
	RMSREGS	sregs;

	regs.x.ax = 0x1017;
	regs.x.bx = start;
	regs.x.cx = num;
	sregs.es = VESABuf_rseg;
	regs.x.dx = VESABuf_roff;
	PM_int86x(0x10, &regs, &regs, &sregs);
	PM_memcpynf(palbuf, VESABuf_sel,VESABuf_off, num * 3);
}

long rgbColor(uchar r,uchar g,uchar b)
/****************************************************************************
*
* Function:     rgbColor
*
* Returns:      Value representing the color. The value is converted from
*               24 bit RGB space into the appropriate color for the
*               video mode.
*
****************************************************************************/
{
	return ((long)((r >> redAdjust) & redMask) << redPos)
		 | ((long)((g >> greenAdjust) & greenMask) << greenPos)
		 | ((long)((b >> blueAdjust) & blueMask) << bluePos);
}

PUBLIC void _cdecl _EMU_line(int x1,int y1,int x2,int y2,long color)
/****************************************************************************
*
* Function:     line
* Parameters:   x1,y1       - First endpoint of line
*               x2,y2       - Second endpoint of line
*               color       - Color to draw the line in
*
* Description:  Scan convert a line segment using the MidPoint Digital
*               Differential Analyser algorithm.
*
****************************************************************************/
{
	int     d;                      /* Decision variable                */
	int     dx,dy;                  /* Dx and Dy values for the line    */
	int     Eincr,NEincr;           /* Decision variable increments     */
	int     yincr;                  /* Increment for y values           */
	int     t;                      /* Counters etc.                    */

	dx = ABS(x2 - x1);
	dy = ABS(y2 - y1);

	if (dy <= dx) {

		/* We have a line with a slope between -1 and 1
		 *
         * Ensure that we are always scan converting the line from left to
         * right to ensure that we produce the same line from P1 to P0 as the
         * line from P0 to P1.
         */

        if (x2 < x1) {
            t = x2; x2 = x1; x1 = t;    /* Swap X coordinates           */
            t = y2; y2 = y1; y1 = t;    /* Swap Y coordinates           */
            }

        if (y2 > y1)
            yincr = 1;
        else
            yincr = -1;

        d = 2*dy - dx;              /* Initial decision variable value  */
        Eincr = 2*dy;               /* Increment to move to E pixel     */
        NEincr = 2*(dy - dx);       /* Increment to move to NE pixel    */

        putPixel(x1,y1,color);      /* Draw the first point at (x1,y1)  */

        /* Incrementally determine the positions of the remaining pixels
         */

        for (x1++; x1 <= x2; x1++) {
            if (d < 0) {
                d += Eincr;         /* Choose the Eastern Pixel         */
                }
            else {
                d += NEincr;        /* Choose the North Eastern Pixel   */
                y1 += yincr;        /* (or SE pixel for dx/dy < 0!)     */
                }
            putPixel(x1,y1,color);  /* Draw the point                   */
            }
        }
    else {

        /* We have a line with a slope between -1 and 1 (ie: includes
         * vertical lines). We must swap our x and y coordinates for this.
         *
         * Ensure that we are always scan converting the line from left to
         * right to ensure that we produce the same line from P1 to P0 as the
         * line from P0 to P1.
         */

        if (y2 < y1) {
            t = x2; x2 = x1; x1 = t;    /* Swap X coordinates           */
            t = y2; y2 = y1; y1 = t;    /* Swap Y coordinates           */
            }

        if (x2 > x1)
            yincr = 1;
        else
            yincr = -1;

        d = 2*dx - dy;              /* Initial decision variable value  */
        Eincr = 2*dx;               /* Increment to move to E pixel     */
        NEincr = 2*(dx - dy);       /* Increment to move to NE pixel    */

        putPixel(x1,y1,color);      /* Draw the first point at (x1,y1)  */

        /* Incrementally determine the positions of the remaining pixels
         */

        for (y1++; y1 <= y2; y1++) {
            if (d < 0) {
                d += Eincr;         /* Choose the Eastern Pixel         */
                }
            else {
                d += NEincr;        /* Choose the North Eastern Pixel   */
                x1 += yincr;        /* (or SE pixel for dx/dy < 0!)     */
                }
            putPixel(x1,y1,color);  /* Draw the point                   */
            }
        }
}

PUBLIC void writeText(int x,int y,char *str,long color)
/****************************************************************************
*
* Function:     writeText
* Parameters:   x,y     - Position to begin drawing string at
*               str     - String to draw
*
* Description:  Draws a string using the BIOS 8x16 video font by plotting
*               each pixel in the characters individually. This should
*               work for all video modes.
*
****************************************************************************/
{
    uchar           byte;
    int             i,j,k,length,ch;
	uchar          	*font;

	font = font8x16;
    length = strlen(str);
    for (k = 0; k < length; k++) {
        ch = str[k];
        for (j = 0; j < 16; j++) {
            byte = *(font + ch * 16 + j);
            for (i = 0; i < 8; i++) {
                if ((byte & 0x80) != 0)
                    putPixel(x+i,y+j,color);
                byte <<= 1;
                }
            }
        x += 8;
		}
}
