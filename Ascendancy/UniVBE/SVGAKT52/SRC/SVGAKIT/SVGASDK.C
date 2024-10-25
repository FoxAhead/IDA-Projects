/****************************************************************************
*
*			The SuperVGA Kit - UniVBE Software Development Kit
*
*                   Copyright (C) 1994 SciTech Software
*                           All rights reserved.
*
* Filename:     $RCSfile: svgasdk.c $
* Version:      $Revision: 1.2 $
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
*               MUST be compiled in the LARGE or FLAT models.
*
* $Id: svgasdk.c 1.2 1995/09/16 10:45:10 kjb release $
*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dos.h>
#include "pmpro.h"
#include "svga.h"

/* If we are compiling for either 32 bit protected mode or 16 bit Windows,
 * then we can use the VBE 2.0 protected mode functions and linear
 * framebuffer code.
 */

#if	defined(PM386) || defined(__WINDOWS16__)
#define	USE_VBE20
#endif

/*---------------------------- Global Variables ---------------------------*/

#define MAXMODES    70				/* Maximum modes available in list  */

PUBLIC	int     maxx,maxy,memory;
PUBLIC	ulong	maxcolor,defcolor;
PUBLIC	int     maxpage,bytesperline,bytesperpixel,bitsperpixel;
PUBLIC	long	bytesperline_lin;
PUBLIC	long	linearAddr = 0;
PUBLIC	ushort	modeList[MAXMODES];
PUBLIC	char    OEMString[80];
PUBLIC	int		capabilities;
PUBLIC	uchar	redMask,greenMask,blueMask;
PUBLIC	int		redPos,redAdjust;
PUBLIC	int		greenPos,greenAdjust;
PUBLIC	int		bluePos,blueAdjust;
PUBLIC	int     curBank;
PUBLIC	bool	haveVirtualBuffer = false;
PUBLIC	bool	virtualBuffer;
PUBLIC	bool	useVirtualBuffer = true;
PUBLIC	void	*videoMem;
PUBLIC	ulong	originOffset;
PUBLIC	ushort	bankOffset;
PUBLIC	void 	(_ASMAPI *SV_putPixel)(int x,int y,ulong color);
PUBLIC	void 	(_ASMAPI *SV_line)(int x1,int y1,int x2,int y2,ulong color);
PUBLIC	void 	(_ASMAPI *SV_clear)(ulong color);
PUBLIC	void 	(_ASMAPI *SV_setActivePage)(int page);

/* The following globals are used by the VESAVBE.C module */

PUBLIC	uint		VESABuf_len = 1024;	/* Length of VESABuf			*/
PUBLIC	uint		VESABuf_sel = 0;	/* Selector for VESABuf         */
PUBLIC	uint		VESABuf_off;		/* Offset for VESABuf           */
PUBLIC	uint		VESABuf_rseg;		/* Real mode segment of VESABuf */
PUBLIC	uint		VESABuf_roff;		/* Real mode offset of VESABuf  */

PRIVATE bool    old50Lines;         /* Was old mode 80x50?              */
PUBLIC	int		VBEVersion;			/* Version of VBE in use			*/
PUBLIC	int     bankShift;          /* Bank granularity adjust factor   */
PUBLIC	long    pagesize;           /* Page size for current mode       */
PUBLIC	void    *setBankRM;			/* Pointer to direct VBE bank code	*/
PUBLIC	void	*setBankPtr;		/* Pointer to bank switch code		*/

void _ASMAPI VBE_setBankA(void);	/* VBE setBank routine single bank	*/
void _ASMAPI VBE_setBankAB(void);	/* VBE setBank routine dual banks	*/

#ifdef	USE_VBE20
void _ASMAPI VBE20_setBankA(void);	/* VBE 2.0 setBank single bank		*/
void _ASMAPI VBE20_setBankAB(void);	/* VBE 2.0 setBank dual banks		*/
void _ASMAPI VBE20_setBankA_ES(void);	/* VBE 2.0 setBank for MMIO		*/
void _ASMAPI VBE20_setBankAB_ES(void);	/* VBE 2.0 setBank for MMIO		*/
PUBLIC	void    *setBank20 = NULL;	/* Pointer to set bank routine		*/
PUBLIC	void	*setCRT20 = NULL;	/* Pointer to set CRT routine		*/
PUBLIC	void	*setPal20 = NULL;	/* Pointer to set palette routine	*/
extern	short	VBE_MMIOSel;		/* Selector to MMIO registers		*/
#endif

extern	uchar font8x16[];			/* Bitmap font definition			*/

/*----------------------------- Implementation ----------------------------*/

/* Declare all banked framebuffer routines */

void _ASMAPI _setActivePage(int page);
void _ASMAPI VGA_setPalette(int start,int num,VBE_palette *pal,bool waitVRT);
void _ASMAPI VBE20_setPalette(int start,int num,VBE_palette *pal,bool waitVRT);
void _ASMAPI _clear16(ulong color);
void _ASMAPI _clear256(ulong color);
void _ASMAPI _clear32k(ulong color);
void _ASMAPI _clear16m(ulong color);
void _ASMAPI _clear4G(ulong color);
void _ASMAPI _putPixel16(int x,int y,ulong color);
void _ASMAPI _putPixel256(int x,int y,ulong color);
void _ASMAPI _putPixel32k(int x,int y,ulong color);
void _ASMAPI _putPixel16m(int x,int y,ulong color);
void _ASMAPI _putPixel4G(int x,int y,ulong color);
void _ASMAPI _line16(int x1,int y1,int x2,int y2,ulong color);
void _ASMAPI _line256(int x1,int y1,int x2,int y2,ulong color);
void _ASMAPI _line32k(int x1,int y1,int x2,int y2,ulong color);
void _ASMAPI _line16m(int x1,int y1,int x2,int y2,ulong color);
void _ASMAPI _line4G(int x1,int y1,int x2,int y2,ulong color);

/* Declare all the linear framebuffer routines */

#ifdef	USE_VBE20
#ifdef	__WINDOWS16__
void _ASMAPI linsdk_enable32(void);
#endif
void _ASMAPI _setActivePageLin(int page);
void _ASMAPI _clear256Lin(ulong color);
void _ASMAPI _clear32kLin(ulong color);
void _ASMAPI _clear16mLin(ulong color);
void _ASMAPI _clear4GLin(ulong color);
void _ASMAPI _putPixel256Lin(int x,int y,ulong color);
void _ASMAPI _putPixel32kLin(int x,int y,ulong color);
void _ASMAPI _putPixel16mLin(int x,int y,ulong color);
void _ASMAPI _putPixel4GLin(int x,int y,ulong color);
void _ASMAPI _line256Lin(int x1,int y1,int x2,int y2,ulong color);
void _ASMAPI _line32kLin(int x1,int y1,int x2,int y2,ulong color);
void _ASMAPI _line16mLin(int x1,int y1,int x2,int y2,ulong color);
void _ASMAPI _line4GLin(int x1,int y1,int x2,int y2,ulong color);
#endif

/*----------------------------- Implementation ----------------------------*/

PRIVATE void ExitVBEBuf(void)
{ PM_freeRealSeg(VESABuf_sel,VESABuf_off); }

void _PUBAPI VBE_initRMBuf(void)
/****************************************************************************
*
* Function:		VBE_initRMBuf
*
* Description:	Initialises the VBE transfer buffer in real mode memory.
*				This routine is called by the VESAVBE module every time
*				it needs to use the transfer buffer, so we simply allocate
*				it once and then return.
*
****************************************************************************/
{
	if (!VESABuf_sel) {
		/* Allocate a global buffer for communicating with the VESA VBE */
		if (!PM_allocRealSeg(VESABuf_len, &VESABuf_sel, &VESABuf_off,
				&VESABuf_rseg, &VESABuf_roff))
			exit(1);
		atexit(ExitVBEBuf);
		}
}

void SV_nop(void) {}

PUBLIC int SV_init(void)
/****************************************************************************
*
* Function:     SV_init
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
	VBE_vgaInfo		vgaInfo;
	VBE_modeInfo	modeInfo;
	int				i;
	ushort   		*p,tmodeList[MAXMODES];

	if ((VBEVersion = VBE_detect(&vgaInfo)) == 0)
		return 0;

	/* Copy relevent information from the mode block into our globals.
	 * Note that the video mode list _may_ be built in the information
	 * block that we have passed, so we _must_ copy this from here
	 * into our our storage if we want to continue to use it. Note
	 * that we filter out the mode 0x6A, which some BIOSes include as
	 * well as the 0x102 mode for 800x600x16.
	 */
	for (i = 0, p = vgaInfo.VideoModePtr; *p != 0xFFFF; p++) {
		if (*p >= 0x100)
			tmodeList[i++] = *p;
		}
	tmodeList[i] = -1;

	/* Now build our global list of available video modes, filtering out
	 * those modes that are not available or not graphics modes. A VBE
	 * implementation may put modes in the mode list that are not available
	 * on the current hardware configuration, so we need to check for this.
	 */
	for (i= 0,p = tmodeList; *p != 0xFFFF; p++) {
		if (!VBE_getModeInfo(*p,&modeInfo))
			continue;
		if ((modeInfo.ModeAttributes & vbeMdGraphMode) == 0)
			continue;
		if (!linearAddr && (modeInfo.ModeAttributes & vbeMdLinear))
			linearAddr = modeInfo.PhysBasePtr;
		modeList[i++] = *p;
		}
	modeList[i] = -1;
	memory = vgaInfo.TotalMemory * 64;
	capabilities = (int)vgaInfo.Capabilities;
	strcpy(OEMString,vgaInfo.OemStringPtr);
#ifndef	REALMODE
	if (VBEVersion >= 0x200 && VF_available()) {
		int		codeLen;
		void 	*bankFunc;
		haveVirtualBuffer = VBE_getBankFunc32(&codeLen,&bankFunc,0,0);
		}
	else haveVirtualBuffer = false;
#endif

#ifdef	__WINDOWS16__
    linsdk_enable32();    /* Enable 32 bit linear framebuffer module  */
#endif
	return VBEVersion;
}

PUBLIC bool SV_setMode(int mode)
/****************************************************************************
*
* Function:     SV_setMode
* Parameters:   mode    - SuperVGA video mode to set.
* Returns:      True if the mode was set, false if not.
*
* Description:  Attempts to set the specified video mode. This routine
*               assumes that the library and SuperVGA have been initialised
*               with the SV_init() routine first.
*
****************************************************************************/
{
	VBE_modeInfo	modeInfo;
	RMREGS      	regs;
	int				imode = mode & ~(vbeDontClear | vbeLinearBuffer);
	int				cntMode = VBE_getVideoMode();

	if (imode < 0x100 && imode != 0x13)
		return false;
	if (imode != cntMode && cntMode <= 3) {
		old50Lines = false;             /* Default to 25 line mode      */
		if (cntMode == 0x3) {
			regs.x.ax = 0x1130;
			regs.x.bx = 0;
			regs.x.dx = 0;
			PM_int86(0x10,&regs,&regs);
			old50Lines = (regs.h.dl == 49);
			}
		}

	if (!VBE_setVideoMode(mode))		/* Set the video mode			*/
		return false;

	/* Initialise global variables for current video mode dimensions	*/

	if (imode == 0x13) {
		/* Special case for VGA mode 13h */
		maxx = 319;
		maxy = 199;
		bytesperline_lin = bytesperline = 320;
		bitsperpixel = 8;
		maxpage = 0;
		pagesize = 0x10000L;
		bankShift = 0;
		}
	else {
		VBE_getModeInfo(imode,&modeInfo);
		maxx = modeInfo.XResolution-1;
		maxy = modeInfo.YResolution-1;
		bytesperline_lin = bytesperline = modeInfo.BytesPerScanLine;
		bitsperpixel = modeInfo.BitsPerPixel;
		maxpage = modeInfo.NumberOfImagePages;
		pagesize = VBE_getPageSize(&modeInfo);
		bankShift = 0;
		while ((64 >> bankShift) != modeInfo.WinGranularity)
			bankShift++;
		}
	curBank = -1;

	/* Emulate RGB modes using a 3 3 2 palette arrangement by default */

	redMask = 0x7;		redPos = 5;		redAdjust = 5;
	greenMask = 0x7;	greenPos = 2;	greenAdjust = 5;
	blueMask = 0x3;		bluePos = 0;	blueAdjust = 6;

	if (imode != 0x13 && modeInfo.MemoryModel == vbeMemRGB) {
		/* Save direct color info mask positions etc */

		redMask = (0xFF >> (redAdjust = 8 - modeInfo.RedMaskSize));
		redPos = modeInfo.RedFieldPosition;
		greenMask = (0xFF >> (greenAdjust = 8 - modeInfo.GreenMaskSize));
		greenPos = modeInfo.GreenFieldPosition;
		blueMask = (0xFF >> (blueAdjust = 8 - modeInfo.BlueMaskSize));
		bluePos = modeInfo.BlueFieldPosition;
		}

	switch (bitsperpixel) {
		case 15:
		case 16:	bytesperpixel = 2;	break;
		case 24:	bytesperpixel = 3;	break;
		case 32:	bytesperpixel = 4;	break;
		default:	bytesperpixel = 1;	break;
		}

	/* Set up a pointer to the appopriate bank switching code to use */
	if (imode == 0x13) {
		setBankPtr = (void*)SV_nop;
		}
	else {
		if ((modeInfo.WinAAttributes & 0x7) != 0x7) {
#ifdef	USE_VBE20
			if (VBEVersion >= 0x200) {
				if (VBE_MMIOSel)
					setBankPtr = VBE20_setBankAB_ES;
				else setBankPtr = VBE20_setBankAB;
				}
			else
#endif
				setBankPtr = VBE_setBankAB;
			}
		else {
#ifdef	USE_VBE20
			if (VBEVersion >= 0x200) {
				if (VBE_MMIOSel)
					setBankPtr = VBE20_setBankA_ES;
				else setBankPtr = VBE20_setBankA;
				}
			else
#endif
				setBankPtr = VBE_setBankA;
			}

#ifdef	REALMODE
		setBankRM = (void *)modeInfo.WinFuncPtr;
#else
		setBankRM = NULL;
#endif
		}

    if ((videoMem = VBE_getBankedPointer(&modeInfo)) == NULL) {
        SV_restoreMode();
		exit(1);
        }
	virtualBuffer = false;
	SV_setActivePage = _setActivePage;
#ifdef	USE_VBE20
	VBE_freePMCode();
	setBank20 = VBE_getSetBank();
	setCRT20 = VBE_getSetDisplayStart();
	setPal20 = VBE_getSetPalette();
	if (mode & vbeLinearBuffer) {
#ifdef	PM386
		if ((videoMem = VBE_getLinearPointer(&modeInfo)) == NULL) {
			SV_restoreMode();
			exit(1);
			}
#else
		uint videoSel = VBE_getLinearSelector(&modeInfo);
		if (!videoSel) {
			SV_restoreMode();
			exit(1);
			}
        videoMem = MK_FP(videoSel,0);
#endif
		SV_setActivePage = _setActivePageLin;
		}
	else if (haveVirtualBuffer && useVirtualBuffer && bitsperpixel > 4) {
		/* See if we can use the VFlat virtual linear framebuffer. This
		 * does however require VBE 2.0 and the virtual flat linear
		 * framebuffer device support. 
		 */
		void *bankFunc,*p;
		int codeLen;
		VBE_getBankFunc32(&codeLen,&bankFunc,0,bankShift);
		VF_exit();
		if ((p = VF_init((ulong)modeInfo.WinASegment << 4,modeInfo.WinSize,
				codeLen,bankFunc)) != NULL) {
			videoMem = p;
			SV_setActivePage = _setActivePageLin;
			virtualBuffer = true;
			mode |= vbeLinearBuffer;
			}
		}
#endif

	/* Now set up the vectors to the correct routines for the video
	 * mode type.
	 */
	switch (bitsperpixel) {
		case 4:
			SV_clear = _clear16;
			SV_putPixel = _putPixel16;
			SV_line = _line16;
			maxcolor = defcolor = 15;
			bytesperpixel = 1;
			break;
		case 8:
			SV_clear = _clear256;
			SV_putPixel = _putPixel256;
			SV_line = _line256;
			maxcolor = 255;
			defcolor = 15;
			bytesperpixel = 1;
#ifdef	USE_VBE20
			if (mode & vbeLinearBuffer) {
				SV_clear = _clear256Lin;
				SV_putPixel = _putPixel256Lin;
				SV_line = _line256Lin;
				}
#endif
			break;
		case 15:
		case 16:
			SV_clear = _clear32k;
			SV_putPixel = _putPixel32k;
			SV_line = _line32k;
			maxcolor = defcolor = SV_rgbColor(0xFF,0xFF,0xFF);
			bytesperpixel = 2;
#ifdef	USE_VBE20
			if (mode & vbeLinearBuffer) {
				SV_clear = _clear32kLin;
				SV_putPixel = _putPixel32kLin;
				SV_line = _line32kLin;
				}
#endif
			break;
		case 24:
			SV_clear = _clear16m;
			SV_putPixel = _putPixel16m;
			SV_line = _line16m;
			maxcolor = defcolor = SV_rgbColor(0xFF,0xFF,0xFF);
			bytesperpixel = 3;
#ifdef	USE_VBE20
			if (mode & vbeLinearBuffer) {
				SV_clear = _clear16mLin;
				SV_putPixel = _putPixel16mLin;
				SV_line = _line16mLin;
				}
#endif
			break;
		case 32:
			SV_clear = _clear4G;
			SV_putPixel = _putPixel4G;
			SV_line = _line4G;
			maxcolor = defcolor = SV_rgbColor(0xFF,0xFF,0xFF);
			bytesperpixel = 4;
#ifdef	USE_VBE20
			if (mode & vbeLinearBuffer) {
				SV_clear = _clear4GLin;
				SV_putPixel = _putPixel4GLin;
				SV_line = _line4GLin;
				}
#endif
			break;
		}

	PM_saveDS();
	if (bitsperpixel == 8) {
		/* Program the default VGA palette. Note that we have stored the
		 * default palette in 8 bits per primary format for maximum
		 * resolution on 8 bit DAC's. Since by default the mode will be
		 * in 6 bit format, we need to shift it right two bits to convert
		 * the palette before we program it (SV_setPalette wont do any
		 * palette conversion).
		 */
		int i;
		VBE_palette t[256];
		for (i = 0; i < 256; i++) {
			t[i].red = VGA8_defPal[i].red >> 2;
			t[i].green = VGA8_defPal[i].green >> 2;
			t[i].blue = VGA8_defPal[i].blue >> 2;
			}
		SV_setPalette(0,256,t,-1);
		}
	SV_setActivePage(0);
	return true;
}

PUBLIC void SV_restoreMode(void)
/****************************************************************************
*
* Function:     SV_restoreMode
*
* Description:  Restore the previous video mode in use before the SuperVGA
*               mode was set. This routine will also restore the 50 line
*               display mode if this mode was previously set.
*
****************************************************************************/
{
	RMREGS	regs;

#ifdef	USE_VBE20
	VF_exit();
	VBE_freePMCode();				/* Free up protected mode code	*/
#endif
	VBE_setVideoMode(0x3);			/* Reset to text mode       	*/
	if (old50Lines) {
		regs.x.ax = 0x1112;
		regs.x.bx = 0;
		PM_int86(0x10,&regs,&regs);	/* Restore 50 line mode         */
		}
}

PUBLIC bool SV_set8BitDAC(void)
/****************************************************************************
*
* Function:		SV_set8BitDAC
* Returns:		True if 8 bit wide palette has been set.
*
* Description:	Attempts to set the system into the 8 bit wide palette
*				mode if supported by the VBE. Returns true on success, false
*				otherwise.
*
****************************************************************************/
{
	if (!VBE_setDACWidth(8))
		return false;
	if (VBE_getDACWidth() != 8)
		return false;
	return true;
}

PUBLIC bool SV_set6BitDAC(void)
/****************************************************************************
*
* Function:		SV_set6BitDAC
* Returns:		True if 6 bit wide palette has been set.
*
****************************************************************************/
{
	if (!VBE_setDACWidth(6))
		return false;
	return true;
}

PUBLIC bool SV_setBytesPerLine(int bytes)
/****************************************************************************
*
* Function:		SV_setBytesPerLine
* Parameters:	bytes	- New bytes per line value
* Returns:		True on success, false on failure.
*
* Description:	Sets the scanline length to a specified bytes per line
*				value. This function only works with VBE 2.0.
*
****************************************************************************/
{
	int	newbytes,xres,yres;

	if (!VBE_setBytesPerLine(bytes,&newbytes,&xres,&yres))
		return false;
	bytesperline_lin = bytesperline = newbytes;
	maxx = xres-1;
	maxy = yres-1;
	return true;
}

PUBLIC bool SV_setPixelsPerLine(int xMax)
/****************************************************************************
*
* Function:		SV_setPixelsPerLine
* Parameters:	xMax	- New pixels per line value
* Returns:		True on success, false on failure.
*
* Description:	Sets the scanline length to a specified pixels per line
*				value. This function only works with VBE 1.2 and above.
*
****************************************************************************/
{
	int	newbytes,xres,yres;

	if (!VBE_setPixelsPerLine(xMax,&newbytes,&xres,&yres))
		return false;
	bytesperline_lin = bytesperline = newbytes;
	maxx = xres-1;
	maxy = yres-1;
	return true;
}

PUBLIC void SV_setPalette(int start,int num,VBE_palette *pal,int maxProg)
/****************************************************************************
*
* Function:		SV_setPalette
* Parameters:   start   - Starting palette index to program
*               num     - Number of palette indexes to program
*               pal     - Palette buffer containing values
*               waitVRT - Wait for vertical retrace flag
* Returns:      True on success, false on failure
*
* Description:  Sets the palette by interleaving blocks of values with
*               the vertical retrace interval. We use the VBE 2.0 palette
*               interface routines if possible, and have a VGA style
*               routine for VBE 1.2 implementations.
*
****************************************************************************/
{
	int waitFlag,count;

	if (maxProg == -1) {
		waitFlag = 0x00;
		count = num;
		}
	else {
		waitFlag = 0x80;
		count = (num > maxProg) ? maxProg : num;
		}

	while (num) {
		if (VBEVersion < 0x200)
			VGA_setPalette(start,count,pal,waitFlag);
#ifdef	USE_VBE20
		else if (setPal20)
			VBE20_setPalette(start,count,pal,waitFlag);
#endif
		else VBE_setPalette(start,count,pal,waitFlag);
		start += count;
		pal += count;
		num -= count;
		count = (num > maxProg) ? maxProg : num;
		}
}

PUBLIC ulong SV_rgbColor(uchar r,uchar g,uchar b)
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
	return ((ulong)((r >> redAdjust) & redMask) << redPos)
		 | ((ulong)((g >> greenAdjust) & greenMask) << greenPos)
		 | ((ulong)((b >> blueAdjust) & blueMask) << bluePos);
}

PUBLIC void SV_writeText(int x,int y,char *str,ulong color)
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
					SV_putPixel(x+i,y+j,color);
				byte <<= 1;
				}
			}
		x += 8;
		}
}

PUBLIC int SV_getModeName(char *buf,VBE_modeInfo *mi,ushort mode,bool useLinear)
/****************************************************************************
*
* Function:     SV_getModeName
* Parameters:   buf			- Buffer to put mode name into
*				mi			- Pointer to VBE mode info block
*				mode		- Mode number for the mode
*				useLinear	- True if we should the linear buffer if available
* Returns:		Mode number to set mode with (with appropriate flags added)
*
* Description:	Puts the name of the video mode in a standard format into
*				the string buffer, and returns the mode number to be used
*				to set the video mode.
*
****************************************************************************/
{
	char	buf2[80];
	int		attr = mi->ModeAttributes;

	if (!(attr & vbeMdGraphMode))
		return 0;
	if ((attr & vbeMdNonBanked) && !useLinear)
		return 0;

	sprintf(buf,"%4d x %4d %d bit (%2d page",mi->XResolution,mi->YResolution,
		mi->BitsPerPixel,mi->NumberOfImagePages+1);
	if (useLinear) {
		if (!(attr & vbeMdNonBanked) && (attr & vbeMdLinear))
			sprintf(buf2,", Banked+Linear");
		else if (attr & vbeMdLinear)
			sprintf(buf2,", Linear Only");
		else sprintf(buf2,", Banked Only");
#ifdef	USE_VBE20
		/* Use the linear framebuffer mode if available */
		if (attr & vbeMdLinear)
			mode |= vbeLinearBuffer;
#endif
		}
	else sprintf(buf2,", Banked Only");
	strcat(buf,buf2);
	if (attr & vbeMdNonVGA)
		sprintf(buf2,", NonVGA)");
	else sprintf(buf2,")");
	strcat(buf,buf2);
	return mode;
}
