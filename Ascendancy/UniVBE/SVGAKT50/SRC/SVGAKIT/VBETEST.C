/****************************************************************************
*
*				  VBETest - VESA VBE stress test program
*
*                   Copyright (C) 1994 SciTech Software.
*                           All rights reserved.
*
* Filename:     $RCSfile: vbetest.c $
* Version:      $Revision: 1.1 $
*
* Language:     ANSI C
* Environment:  IBM PC (MS DOS)
*
* Description:	VBETest test program. This program is designed to stress
*				test a VESA VBE implementation, and check it for full
*				conformance with the VBE standard that it claims to conform
*				to (supports only standards >= 1.2 standard).
*
*				This program uses the SuperVGA test kit to perform all
*				graphics output when testing the appropriate video modes
*				for conformance (and thus only works on 386 and above
*				machines).
*
*               MUST be compiled in the large memory model.
*
*				This program is freely distributable in the executable
*				form. The source code is under the same restrictions as
*				the SuperVGA kit it belong in.
*
* $Id: vbetest.c 1.1 1994/08/22 12:27:00 kjb release $
*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <dos.h>
#include <string.h>
#include <conio.h>
#include <ctype.h>
#include "svga.h"
#include "getopt.h"

/*----------------------------- Implementation ----------------------------*/

/* Special UniVBE Information Block */

typedef struct {
	char    SuperVGAName[50];		/* Name of installed SuperVGA		*/
	char	DACName[50];			/* Name of installed DAC			*/
	short	SuperVGA;				/* UniVBE SuperVGA id number		*/
	short	ChipID;					/* UniVBE Chipset id number			*/
	short	Memory;					/* Amount of memory installed		*/
	short	DacID;					/* UniVBE DAC id number				*/
	} UniVBEInfo;

/* SuperVGA information block */

typedef struct {
    char    VESASignature[4];       /* 'VESA' 4 byte signature          */
	short   VESAVersion;            /* VBE version number               */
	long	OEMStringPtr;           /* Far pointer to OEM string        */
	long    Capabilities;           /* Capabilities of video card       */
	long	VideoModePtr;           /* Far pointer to supported modes   */
    short   TotalMemory;            /* Number of 64kb memory blocks     */
	char    reserved[232];          /* Pad to 256 byte block size       */
	UniVBEInfo	far *univbeInfo;	/* Special UniVBE information block	*/
	} VgaInfoBlock;

/* SuperVGA mode information block */

typedef struct {
    short   ModeAttributes;         /* Mode attributes                  */
    char    WinAAttributes;         /* Window A attributes              */
    char    WinBAttributes;         /* Window B attributes              */
    short   WinGranularity;         /* Window granularity in k          */
    short   WinSize;                /* Window size in k                 */
    short   WinASegment;            /* Window A segment                 */
    short   WinBSegment;            /* Window B segment                 */
	long    WinFuncPtr;            	/* Far pointer to window function   */
    short   BytesPerScanLine;       /* Bytes per scanline               */
    short   XResolution;            /* Horizontal resolution            */
    short   YResolution;            /* Vertical resolution              */
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

typedef struct {
	int		ax,bx,cx,dx,si,di,es,ds;
	} regs;

FILE	*logfile = NULL;
int		CP_x,CP_y,VBEVersion,maxbanks,VBEFunc = 0,numErrors = 0,bits = 0;
int		VBEMode = 0;
bool	failed = false;
bool	verbose = false;
bool	doPageTest = false;
short	modelist[100];

#include "version.c"

/* Table of memory model names */

char *memModelNames[] = {
	"Text Mode",
	"CGA Graphics",
	"Hercules Graphics",
	"4-plane planar",
	"Packed Pixel",
	"Non-chain 4, 256 color",
	"Direct Color RGB",
	"Direct Color YUV",
	};

int queryCpu(void);

void out(const char *fmt, ... )
{
	va_list argptr;

	va_start(argptr, fmt);
	vfprintf(stdout, fmt, argptr);
	if (logfile)
		vfprintf(logfile, fmt, argptr);
	va_end(argptr);
}

void log(const char *fmt, ... )
{
	va_list argptr;

	va_start(argptr, fmt);
	if (logfile) {
		vfprintf(logfile, fmt, argptr);
		fflush(logfile);
		}
	va_end(argptr);
}

/* Routine to convert the input value to its binary representation */

char *binary(unsigned value)
{
	static char	buf[11] = "00000000b";
	unsigned    mask = 0x80;
	int         i;

	for (i = 0; i < 8; i++) {
		buf[i] = value & mask ? '1' : '0';
		mask >>= 1;
		}

	return buf;
}

bool checkEscape(void)
/****************************************************************************
*
* Function:		checkEscape
* Returns:		True if key was hit to advance to next test.
*
* Description:	Checks if ESC has been hit, and exits if so.
*
****************************************************************************/
{
	if (kbhit()) {
		int ch = getch();
		if (ch == 0) getch();
		if (ch == 0x1B) {
			restoreMode();
			exit(1);
			}
		return true;
		}
	return false;
}

void startCheck(int _VBEFunc)
/****************************************************************************
*
* Function:		startCheck
* Parameters:	_VBEFunc	- VBE Function number we are currently checking
*
* Description:	Begins the logging of errors for this function.
*
****************************************************************************/
{
	log("Checking function %02Xh ... ", VBEFunc = _VBEFunc);
	numErrors = 0;
}

void endCheck(void)
/****************************************************************************
*
* Function:		endCheck
*
* Description:	Ends the checking of a particular VBE function.
*
****************************************************************************/
{
	if (numErrors == 0)
		log("Passed.\n");
	else
		log("\n%d errors logged for function %02Xh.\n", numErrors, VBEFunc);
}

void startModeCheck(int mode)
/****************************************************************************
*
* Function:		startModeCheck
* Parameters:	mode	- VBE mode number being checked
*
* Description:	Begins the logging of errors for this mode.
*
****************************************************************************/
{
	log("Checking mode %02Xh ... ", VBEMode = mode);
	if (verbose) log("\n");
	numErrors = 0;
}

void endModeCheck(void)
/****************************************************************************
*
* Function:		endModeCheck
*
* Description:	Ends the checking of a particular VBE mode.
*
****************************************************************************/
{
	if (numErrors == 0)
		log("Passed.\n");
	else
		log("\n%d errors logged for mode %02Xh.\n", numErrors, VBEMode);
}

void fail(const char *msg, ... )
/****************************************************************************
*
* Function:		fail
* Parameters:	msg	- Message describing error
*
* Description:	Logs a failure message to the log file outlining the problem
*				that was encountered.
*
****************************************************************************/
{
	va_list argptr;

	if (numErrors == 0)
		log("\n\n");
	numErrors++;
	failed = true;

	va_start(argptr, msg);
	fprintf(logfile,"    ");
	vfprintf(logfile, msg, argptr);
	va_end(argptr);
}

bool callVBE(regs *r)
/****************************************************************************
*
* Function:		callVBE
* Parameters:	r	- Structure holding register values to load
* Returns:		True if successful, false if function failed
*
* Description:	Loads the appropriate registers with the values from
*				the register structure and executes and int 10h to call
*				the VBE. It checks to ensure that register values are
*				preserved across all calls correctly and ensures that the
*               function executed successfully.
*
****************************************************************************/
{
	union REGS		rg;
	struct SREGS	sr;
	int				mask;

	rg.x.ax = r->ax;	rg.x.bx = r->bx;
	rg.x.cx = r->cx;	rg.x.dx = r->dx;
	rg.x.si = r->si;	rg.x.di = r->di;
	sr.es = r->es;		sr.ds = r->ds;
	int86x(0x10,&rg,&rg,&sr);

	if ((r->ax >> 8) != 0x4F) return TRUE;

	/* Check to ensure all register are preserved across call. We define
	 * the mask to be a one for a register that must be preserved, and
	 * a zero for a register that can change. AX is always the result
	 * code, so this leave 7 bits to represent each register.
	 */

	switch (r->ax & 0xFF) {
		case 0x00:	mask = 0x7F;	break;
		case 0x01:	mask = 0x7F;	break;
		case 0x02:	mask = 0x7F;	break;
		case 0x03:	mask = 0x7E;	break;
		case 0x04:	if ((r->dx & 0xFF) == 0)
						mask = 0x7E;		/* State size call		*/
					else mask = 0x7F;		/* Other calls			*/
					break;
		case 0x05:	if ((r->bx >> 8) == 0)
						mask = 0x7F;		/* Set window call		*/
					else mask = 0x7B;		/* Get window call		*/
					break;
		case 0x06:	mask = 0x78;	break;
		case 0x07:	if (r->bx == 0)
						mask = 0x7F;		/* Set display start	*/
					else mask = 0x78;		/* Get display start	*/
					break;
		case 0x08:	mask = 0x7E;	break;
		default:	mask = 0;
		}

	if ((mask & 0x01) && (r->bx != rg.x.bx))
		fail("Function %02Xh failed to preserve BX\n", r->ax & 0xFF);
	if ((mask & 0x02) && (r->cx != rg.x.cx))
		fail("Function %02Xh failed to preserve CX\n", r->ax & 0xFF);
	if ((mask & 0x04) && (r->dx != rg.x.dx))
		fail("Function %02Xh failed to preserve DX\n", r->ax & 0xFF);
	if (r->si != rg.x.si)
		fail("Function %02Xh failed to preserve SI\n", r->ax & 0xFF);
	if (r->di != rg.x.di)
		fail("Function %02Xh failed to preserve DI\n", r->ax & 0xFF);
	if (r->ds != sr.ds)
		fail("Function %02Xh failed to preserve DS\n", r->ax & 0xFF);
	if (r->es != sr.es)
		fail("Function %02Xh failed to preserve ES\n", r->ax & 0xFF);

	r->ax = rg.x.ax;	r->bx = rg.x.bx;
	r->cx = rg.x.cx;	r->dx = rg.x.dx;
	r->si = rg.x.si;	r->di = rg.x.di;
	r->es = sr.es;		r->ds = sr.ds;

	return (r->ax == 0x004F);
}

void checkFunction00h(void)
/****************************************************************************
*
* Function:		checkFunction00h
*
* Description:	Calls function 00h to determine if a VESA VBE is present,
*				and check it for conformance.
*
****************************************************************************/
{
	VgaInfoBlock    vgaInfo;
	regs			r;
	short			i,*modes;

	r.es = SEG(&vgaInfo);
	r.di = OFF(&vgaInfo);
	r.ax = 0x4F00;
	if (callVBE(&r)) {
		if (vgaInfo.VESAVersion < 0x102) {
			out("Detected a VBE %d.%d interface. This program only checks interfaces that\n",
				vgaInfo.VESAVersion >> 0x8,vgaInfo.VESAVersion & 0xF);
			out("conform to the VBE 1.2 or later specifications.\n");
			exit(1);
			}

		printf("VBE %d.%d Interface detected - checking for conformance\n\n",
			vgaInfo.VESAVersion >> 0x8,vgaInfo.VESAVersion & 0xF);

		log("VBE Version:  %d.%d\n",vgaInfo.VESAVersion >> 0x8,
			vgaInfo.VESAVersion & 0xF);
		log("OEMString:    %s\n",vgaInfo.OEMStringPtr);
		log("Capabilities: %s (%04Xh)\n",binary(vgaInfo.Capabilities),
			vgaInfo.Capabilities);
		log("Total Memory: %d Kb\n",memory = vgaInfo.TotalMemory * 64);
		if (verbose && vgaInfo.univbeInfo) {
			log("\nUniVBE is installed. Current configuration:\n");
			log("    %s\n", vgaInfo.univbeInfo->SuperVGAName);
			log("    %s\n", vgaInfo.univbeInfo->DACName);
			}
		log("\nAvailable Modes:\n\n");

        modes = (short*)vgaInfo.VideoModePtr;
		i = 0;
		while (*modes != -1) {
			modelist[i] = *modes;
			log("%04Xh ",*modes++);
			if ((++i % 10) == 0)
				log("\n");
			}
		modelist[i] = -1;
		log("\n\n");
		startCheck(0x00);
		if (vgaInfo.TotalMemory == 0)
			fail("TotalMemory field is zero!");
		endCheck();

		VBEVersion = vgaInfo.VESAVersion;
		maxbanks = vgaInfo.TotalMemory;
		}
	else {
		out("VESA VBE interface not detected.\n");
		exit(1);
		}
}

void checkFunction01h(void)
/****************************************************************************
*
* Function:		checkFunction01h
*
* Description:	Calls function 01h to obtain information about all
*				available video modes, checking the values returned in the
*				structure.
*
****************************************************************************/
{
	ModeInfoBlock	modeInfo;
	regs			r;
	short			*modes;

	startCheck(0x01);
	for (modes = modelist; *modes != -1; modes++) {
		r.es = SEG(&modeInfo);
		r.di = OFF(&modeInfo);
		r.ax = 0x4F01;
		r.cx = *modes;
		if (callVBE(&r)) {
			/* Ignore unsupported and text modes */
			if ((modeInfo.ModeAttributes & 0x1) == 0)
				continue;
			if ((modeInfo.ModeAttributes & 0x10) == 0)
				continue;
			if (modeInfo.WinGranularity > 64 || modeInfo.WinGranularity == 0)
				fail("Bad window granularity factor: %d\n",modeInfo.WinGranularity);
			if (modeInfo.WinSize > 64 || modeInfo.WinSize == 0)
				fail("Bad window size: %d\n",modeInfo.WinSize);
			if ((modeInfo.WinAAttributes & 0x1) && modeInfo.WinASegment == 0)
				fail("Bad window A segment value: %04Xh\n", modeInfo.WinASegment);
			if ((modeInfo.WinBAttributes & 0x1) && modeInfo.WinBSegment == 0)
				fail("Bad window B segment value: %04Xh\n", modeInfo.WinBSegment);
			if (modeInfo.WinFuncPtr == NULL)
				fail("NULL window function pointer\n");
			}
		else
			fail("Video mode %03Xh not available yet listed in mode list\n", *modes);
		}
	endCheck();
}

void checkFunction02h(void)
/****************************************************************************
*
* Function:		checkFunction02h
*
* Description:	Calls function 02h to set each of the available video modes,
*				draw a pattern and display status information about each
*				video mode.
*
****************************************************************************/
{
	ModeInfoBlock	modeInfo;
	regs			r;
	short			*modes;

	startCheck(0x02);
	for (modes = modelist; *modes != -1; modes++) {
		r.es = SEG(&modeInfo);
		r.di = OFF(&modeInfo);
		r.ax = 0x4F01;
		r.cx = *modes;
		if (callVBE(&r)) {
			if ((modeInfo.ModeAttributes & 0x1) == 0)
				continue;
			r.ax = 0x4F02;
			r.bx = *modes;
			if (callVBE(&r)) {
				r.ax = 0x4F03;
				callVBE(&r);
				if (r.bx != *modes)
					fail("Function 03h did not return same video mode number (%04Xh instead of %04Xh)\n", r.bx, *modes);
				}
			}
		}
	r.ax = 0x3;
	callVBE(&r);
	endCheck();
}

void checkFunction04h(void)
/****************************************************************************
*
* Function:		checkFunction04h
*
* Description:	Calls function 04h to save and restore the SuperVGA
*				video state.
*
****************************************************************************/
{
	regs			r;
	int				size;
	void			*savebuf;

	startCheck(0x04);
	r.ax = 0x4F04;
	r.dx = 0x0000;
	r.cx = 0x000F;
	if (!callVBE(&r))
		fail("Function 04h subfunction 00h failed.\n");
	size = r.bx * 64;
	if (size < 960)
		fail("Invalid buffer size.\n");
	if ((savebuf = malloc(size)) == NULL)
		exit(1);

	r.ax = 0x4F04;
	r.dx = 0x0001;
	r.cx = 0x000F;
	r.es = SEG(savebuf);
	r.bx = OFF(savebuf);
	if (!callVBE(&r))
		fail("Function 04h subfunction 01h failed.\n");

	r.ax = 0x4F04;
	r.dx = 0x0002;
	r.cx = 0x000F;
	r.es = SEG(savebuf);
	r.bx = OFF(savebuf);
	if (!callVBE(&r))
		fail("Function 04h subfunction 02h failed.\n");

	r.ax = 0x3;
	callVBE(&r);

	free(savebuf);
	endCheck();
}

void checkFunction05h(void)
/****************************************************************************
*
* Function:		checkFunction05h
*
* Description:	Calls function 05h to change the video memory banks from
*				the first bank all the way down to the last bank, and
*				to read the bank values back again.
*
****************************************************************************/
{
	ModeInfoBlock	modeInfo;
	regs			r;
	int				bank;
	bool			twobanks;

	startCheck(0x05);

	r.es = SEG(&modeInfo);
	r.di = OFF(&modeInfo);
	r.ax = 0x4F01;
	r.cx = 0x102;
	callVBE(&r);
	twobanks = modeInfo.WinBAttributes & 0x1;

	r.ax = 0x4F02;
	r.bx = 0x102;
	if (!callVBE(&r))
		fail("Could not set 800x600x16 color mode\n");

	for (bank = 0; bank < maxbanks; bank++) {
		r.ax = 0x4F05;
		r.bx = 0x0000;
		r.dx = bank;
		if (!callVBE(&r))
			fail("Bank switch routine failed.\n");
		r.ax = 0x4F05;
		r.bx = 0x0100;
		if (!callVBE(&r))
			fail("Bank switch routine failed.\n");
		if (r.dx != bank)
			fail("Differing bank 1 value returned (%04Xh instead of %04Xh)\n", r.dx, bank);

		if (twobanks) {
			r.ax = 0x4F05;
			r.bx = 0x0001;
			r.dx = bank;
			if (!callVBE(&r))
				fail("Bank switch routine failed.\n");
			r.ax = 0x4F05;
			r.bx = 0x0101;
			if (!callVBE(&r))
				fail("Bank switch routine failed.\n");
			if (r.dx != bank)
				fail("Differing bank 2 value returned (%04Xh instead of %04Xh)\n", r.dx, bank);
			}
		}

	r.ax = 0x3;
	callVBE(&r);
	endCheck();
}

void clearAllPages(void)
/****************************************************************************
*
* Function:		clearAllPages
*
* Description:	Clears the entire video memory to black.
*
****************************************************************************/
{
	int		i;
	char	far *vmem = MK_FP(0xA000,0x0000);

	for (i = 0; i < maxbanks; i++) {
		setBank(i);
		memset(vmem,0,0x7FFF);
		memset(vmem+0x7FFF,0,0x7FFF);
		}
}

void setDisplayStart(int x,int y)
/****************************************************************************
*
* Function:     setDisplayStart
* Parameters:   x,y - Position of the first pixel to display
*
* Description:  Sets the new starting display position to implement
*               hardware scrolling.
*
****************************************************************************/
{
	regs	r;

	if (extendedflipping) {
		r.ax = 0x4F07;
		r.bx = 0x0000;
		r.cx = x;
		r.dx = y;
		callVBE(&r);
		r.ax = 0x4F07;
		r.bx = 0x0001;
		callVBE(&r);
		if (abs(r.cx-x) > 8 || r.dx != y) {
			fail("Invalid values returned by Function 07h subfunction 01h (cx = %04Xh, dx = %04Xh)\n", r.cx, r.dx);
			fail("Should have been cx = %04Xh (can be rounded down), dx = %04Xh\n", x, y);
			}
		}
}

void setScanlineLength(int width,int *bytesperline,int *maxx,int *maxy)
/****************************************************************************
*
* Function:		setScanlineLength
* Parameters:	width			- New scanline width to set in pixels
*				bytesperline	- New bytes per line value
*				maxx			- New maximum X coordinate
*				maxy			- New maximum Y coordinate
*
* Description:	Attempts to set the logical scanline length using the
*				VBE function 06h to set up a logical display buffer.
*
****************************************************************************/
{
	regs	r,r2;

	r.ax = 0x4F06;
	r.bx = 0x0000;
	r.cx = width;
	if (!callVBE(&r))
		fail("Function 06h subfunction 00h failed.\n");

	r2.ax = 0x4F06;
	r2.bx = 0x0001;
	if (!callVBE(&r2))
		fail("Function 06h subfunction 01h failed.\n");

	if (r.bx != r2.bx)
		fail("Differing bytes per scanline values (%04Xh instead of %04Xh).\n",
			r2.bx, r.bx);
	if (r.cx != r2.cx)
		fail("Differing pixels per scanline values (%04Xh instead of %04Xh).\n",
			r2.cx, r.cx);
	if (r.dx != r2.dx)
		fail("Differing maximum scanline values (%04Xh instead of %04Xh).\n",
			r2.dx, r.dx);

	*bytesperline = r.bx;
	*maxx = r.cx-1;
	*maxy = r.dx-1;
}

void moire(void)
/****************************************************************************
*
* Function:     moire
*
* Description:  Draws a simple Moire pattern on the display screen using
*               lines.
*
****************************************************************************/
{
	int     i,value;

	clearAllPages();
	if (maxcolor <= 255) {
		for (i = 0; i < maxx; i += 10) {
			line(maxx/2,maxy/2,i,0,i % maxcolor);
			line(maxx/2,maxy/2,i,maxy,(i+1) % maxcolor);
			}
		for (i = 0; i < maxy; i += 10) {
			line(maxx/2,maxy/2,0,i,(i+2) % maxcolor);
			line(maxx/2,maxy/2,maxx,i,(i+3) % maxcolor);
			}
		}
	else {
		for (i = 0; i < maxx; i++) {
			line(maxx/2,maxy/2,i,0,rgbColor(((i*255L)/maxx),0,0));
			line(maxx/2,maxy/2,i,maxy,rgbColor(0,((i*255L)/maxx),0));
			}
		for (i = 0; i < maxy; i++) {
			value = (i*255L)/maxy;
			line(maxx/2,maxy/2,0,i,rgbColor(value,0,255 - value));
			line(maxx/2,maxy/2,maxx,i,rgbColor(0,255 - value,value));
			}
		}
	line(0,0,maxx,0,defcolor);
	line(0,0,0,maxy,defcolor);
	line(maxx,0,maxx,maxy,defcolor);
	line(0,maxy,maxx,maxy,defcolor);
}

void gprintf(const char *fmt, ... )
/****************************************************************************
*
* Function:		gprintf
* Parameters:	fmt	- Format string to display
*
* Description:	Displays a string in the current display mode.
*
****************************************************************************/
{
	va_list argptr;
	char	buf[255];

	va_start(argptr, fmt);
	vsprintf(buf,fmt,argptr);
	writeText(CP_x,CP_y,buf,defcolor);
	if (verbose) log("    %s\n", buf);
	CP_y += 16;
	va_end(argptr);
}

void dumpModeInfo(int mode,int displayAll)
/****************************************************************************
*
* Function:     dumpModeInfo
* Parameters:   mode    	- Mode number to dump info for
*				displayAll	- Should we display all mode info?
*
* Description:  Dumps the information about the specific mode to the
*               display.
*
****************************************************************************/
{
	ModeInfoBlock   modeInfo;
	union REGS      regs;
	struct SREGS    sregs;

	sregs.es = FP_SEG(&modeInfo);
	regs.x.di = FP_OFF(&modeInfo);
    regs.x.ax = 0x4F01;
    regs.x.cx = mode;
    int86x(0x10,&regs,&regs,&sregs);
	if ((modeInfo.ModeAttributes & 0x1) == 0)
		return;
	CP_x = CP_y = 5;
	if (verbose)
		log("\nMode information:\n");
	gprintf("Mode number:     %04Xh",mode);
	if (displayAll) {
		gprintf("ModeAttributes:  %s (%04Xh)",binary(modeInfo.ModeAttributes),
			modeInfo.ModeAttributes);
		gprintf("WinAAttributes:  %s (%04Xh)",binary(modeInfo.WinAAttributes),
			modeInfo.WinAAttributes);
		gprintf("WinBAttributes:  %s (%04Xh)",binary(modeInfo.WinBAttributes),
			modeInfo.WinBAttributes);
		gprintf("WinGranulatiry:  %d",modeInfo.WinGranularity);
		gprintf("WinSize:         %d",modeInfo.WinSize);
		gprintf("WinASegment:     %04Xh",modeInfo.WinASegment);
		gprintf("WinBSegment:     %04Xh",modeInfo.WinBSegment);
		gprintf("WinFuncPtr:      %04X:%04X",FP_SEG(modeInfo.WinFuncPtr),
			FP_OFF(modeInfo.WinFuncPtr));
		}
	if (modeInfo.ModeAttributes & 0x10) {
		gprintf("Resolution:      %d x %d x %d bits per pixel (%02Xh BytesPerLine)",
			modeInfo.XResolution,modeInfo.YResolution,modeInfo.BitsPerPixel,
			modeInfo.BytesPerScanLine);
		if (displayAll) {
			gprintf("MemoryModel:     %s",memModelNames[modeInfo.MemoryModel]);
			gprintf("");
			gprintf("CharSize:        %d x %d",
				modeInfo.XCharSize,modeInfo.YCharSize);
			if (modeInfo.MemoryModel >= 6) {
				gprintf("Red Component:   %d bits, position %d",
					modeInfo.RedMaskSize,modeInfo.RedFieldPosition);
				gprintf("Green Component: %d bits, position %d",
					modeInfo.GreenMaskSize,modeInfo.GreenFieldPosition);
				gprintf("Blue Component:  %d bits, position %d",
					modeInfo.BlueMaskSize,modeInfo.BlueFieldPosition);
				gprintf("Rsvd Component:  %d bits, position %d",
					modeInfo.RsvdMaskSize,modeInfo.RsvdFieldPosition);
				gprintf("DirectColorInfo: %s (%d)",
					binary(modeInfo.DirectColorModeInfo),
					modeInfo.DirectColorModeInfo);
				}
			}
		}
	else {
		gprintf("Resolution:      %d x %d Text Mode (%d x %d charsize)",
			modeInfo.XResolution,modeInfo.YResolution,
			modeInfo.XCharSize,modeInfo.YCharSize);
		}
	gprintf("NumberOfPages:   %d",modeInfo.NumberOfImagePages+1);
	if (verbose)
		log("\n");
}

void pageTest(int mode)
/****************************************************************************
*
* Function:		pageTest
*
* Description:	Interactive debugging of CRTC paging. We render an image to
*				each of the available display pages, and then flip through
*				the pages one by one, or to a specified display page
*				depending on what the user specifies. We finish when the
*				users hits the enter key (or quit on ESC).
*
****************************************************************************/
{
	int     i,ch,vpage,done = 0;
	char    buf[80];

	/* Cycle through each of the display pages, printing the page number
	 * so that we can identify the page correctly.
	 */

	for (i = 0; i <= maxpage; i++) {
		setActivePage(i);
		moire();
		dumpModeInfo(mode,false);
		gprintf("");
		gprintf("Page %d of %d", i+1, maxpage+1);
		gprintf("u   - Move up one page");
		gprintf("d   - Move down one page");
		gprintf("U   - Cycle up continuously (any key to stop)");
		gprintf("D   - Cycle down continuously (any key to stop)");
		gprintf("1-9 - Display specified page");
		line(0,0,maxx,0,defcolor);
		line(0,0,0,maxy,defcolor);
		line(maxx,0,maxx,maxy,defcolor);
		line(0,maxy,maxx,maxy,defcolor);
		}
	vpage = 0;
	while (!done) {
		setVisualPage(vpage);
		ch = getch();
		if (ch == 0) getch();
		switch (ch) {
			case 'u':
				if (++vpage > maxpage)
					vpage = 0;
				break;
			case 'd':
				if (--vpage < 0)
					vpage = maxpage;
				break;
			case 'U':
				while (!kbhit()) {
					if (++vpage > maxpage)
						vpage = 0;
					setVisualPage(vpage);
					}
				getch();
				break;
			case 'D':
				while (!kbhit()) {
					if (--vpage < 0)
						vpage = maxpage;
					setVisualPage(vpage);
					}
				getch();
				break;
			case 0xD:
				done = 1;
				break;
			case 0x1B:
				restoreMode();
				exit(1);
			default:
				ch -= '1';
				if (ch >= 0 && ch <= maxpage)
					vpage = ch;
				break;
			}
		}
	setActivePage(0);
}

void scrollTest(void)
/****************************************************************************
*
* Function:		scrollTest
*
* Description:	Checks the CRT display start routines to scroll the display
*				page up and then back down again.
*
****************************************************************************/
{
	int		i,max;

	if (extendedflipping) {
		if (maxcolor == 15)
			max = (memory*256L) / bytesperline - maxy;
		else
			max = (memory*1024L) / bytesperline - maxy;
		if (max > maxy) max = maxy+1;
		if (max < 0)	return;

		setDisplayStart(0,0);
		for (i = 0; i < max; i++) {			/* Scroll the display up    */
			setDisplayStart(0,i);
			if (checkEscape())
				return;
			}
		if (checkEscape())
			return;
		for (i--; i >= 0; i--) { 			/* Scroll the display down  */
			setDisplayStart(0,i);
			if (checkEscape())
				return;
			}
		}
}

void virtualTest(void)
/****************************************************************************
*
* Function:		virtualTest
*
* Description:	Checks the CRT logical scanline length routines, setting
*				up a virtual display buffer and scrolling around within
*				this buffer.
*
****************************************************************************/
{
	int		i,x,y,scrollx,scrolly,oldmaxx,oldmaxy,max;
	char	buf[80];

	if (extendedflipping) {
		/* Find the largest value that we can set the virtual buffer width
		 * to that the VBE supports
		 */

		switch (maxcolor) {
			case 0xF:		max = (memory*2048L) / (maxy+1);	break;
			case 0xFF:		max = (memory*1024L) / (maxy+1);	break;
			case 0x7FFF:
			case 0xFFFF:	max = (memory*512L) / (maxy+1);		break;
			case 0xFFFFFF:	max = (memory*341L) / (maxy+1);		break;
			}
		oldmaxx = maxx;
		oldmaxy = maxy;
		for (i = max; i > oldmaxx+1; i--) {
			setScanlineLength(i,&bytesperline,&maxx,&maxy);
			if (maxx > oldmaxx+1 && maxx < max)
				break;				/* Large value has been set			*/
			}

		/* Perform huge horizontal scroll */

		setDisplayStart(0,0);
		clearAllPages();
		moire();
		writeText(20,20,"Function 06h - Set/Get Logical Scan Line Length",defcolor);
		if (maxx == oldmaxx)
			sprintf(buf,"Virtual buffer could not be resized (still %d x %d pixels)",maxx+1,maxy+1);
		else
			sprintf(buf,"Virtual buffer now set to %d x %d pixels",maxx+1,maxy+1);
		writeText(20,40,buf,defcolor);
		if (verbose) log("    %s\n", buf);
		scrollx = maxx-oldmaxx;
		scrolly = maxy-oldmaxy;
		for (x = y = 0; x <= scrollx; x++) {
			setDisplayStart(x,y);
			if (checkEscape())
				return;
			}
		for (x = scrollx,y = 0; y <= scrolly; y++) {
			setDisplayStart(x,y);
			if (checkEscape())
				return;
			}
		for (x = scrollx,y = scrolly; x >= 0; x--) {
			setDisplayStart(x,y);
			if (checkEscape())
				return;
			}
		for (x = 0,y = scrolly; y >= 0; y--) {
			setDisplayStart(x,y);
			if (checkEscape())
				return;
			}
		if (maxx == oldmaxx) return;

		/* Now perform huge vertical scroll */

		delay(750);
		setScanlineLength(oldmaxx,&bytesperline,&maxx,&maxy);
		clearAllPages();
		moire();
		writeText(20,20,"Function 06h - Set/Get Logical Scan Line Length",defcolor);
		sprintf(buf,"Virtual buffer now set to %d x %d pixels",maxx+1,maxy+1);
		writeText(20,40,buf,defcolor);
		if (verbose) log("    %s\n",buf);
		scrolly = maxy-oldmaxy;
		for (y = 0; y <= scrolly; y++) {
			setDisplayStart(0,y);
			if (checkEscape())
				return;
			}
		for (y = scrolly; y >= 0; y--) {
			setDisplayStart(0,y);
			if (checkEscape())
				return;
			}
		}
}

void wideDACTest(void)
/****************************************************************************
*
* Function:		wideDACTest
*
* Description:  Displays a set of color values using the wide DAC support
*				if available.
*
****************************************************************************/
{
	int		i,bits,x,y;
	palette	pal[256];
	palette	oldpal[256];
	regs	r;

	getPalette(0, 256, oldpal);

	/* Set the DAC into the 8 bit mode if possible */

	r.ax = 0x4F08;         /* Set DAC service                      */
	r.bx = 0x0800;         /* BH := 8, BL := 0 (set DAC width)     */
	if (!callVBE(&r))
		bits = 6;
	else bits = r.bx >> 8;
	if (bits != 6 && bits != 8)
		fail("Function 08h subfunction 0h returned incorrect value (bh = %d)\n", bits);

	r.ax = 0x4F08;
	r.bx = 0x0001;         /* Get DAC width (should now be 8)      */
	if (!callVBE(&r))
		fail("Function 08h subfunction 01h failed.\n");
	if ((r.bx >> 8) != bits)
		fail("Functions 08h subfunction 01h returned incorrect value (%d instead of %d)\n", r.bx >> 8, bits);

	memset(pal,0,256*3);
	for (i = 0; i < 256; i += 4) {
		pal[64 + (i >> 2)].red = i;
		pal[128 + (i >> 2)].green = i;
		pal[192 + (i >> 2)].blue = i;
		}

	pal[defcolor].red = 255;
	pal[defcolor].green = 255;
	pal[defcolor].blue = 255;
	setPalette(0,256,pal);

	clear(0);
	line(0,0,maxx,0,defcolor);
	line(0,0,0,maxy,defcolor);
	line(maxx,0,maxx,maxy,defcolor);
	line(0,maxy,maxx,maxy,defcolor);

	x = y = 20;
	writeText(x,y,"Function 08h - Set/Get DAC width",defcolor);
	y += 32;
	if (bits == 8) {
		if (verbose) log("    8 bit wide DAC supported\n");
		writeText(x,y,"You should see a smooth transition of colors",defcolor);
		y += 16;
		writeText(x,y,"If the colors are broken into 4 lots, the wide DAC is not working",defcolor);
		y += 32;

		for (i = 0; i < 192; i++) {
			line(x+i, y,    x+i, y+32,  64+i/3);
			line(x+i, y+32, x+i, y+64,  128+i/3);
			line(x+i, y+64, x+i, y+96,  192+i/3);
			}
		}
	else {
		writeText(x,y,"BIOS does not support 8 bit wide DAC.",defcolor);
		if (verbose) log("    8 bit wide DAC NOT supported\n");
		}

	delay(750);

	if (!set6BitPalette())
		fail("Could not return to 6 bit DAC mode.\n");
	setPalette(0, 256, oldpal);
}

void checkGraphicsFunctions(void)
/****************************************************************************
*
* Function:		checkGraphicsFunctions
*
* Description:	Intialises all of the available video modes, and performs
*				testing on all the modes. We call upon the SuperVGA
*				test kit to perform the graphics output for us for each
*				video mode.
*
****************************************************************************/
{
	ModeInfoBlock	modeInfo;
	regs			r;
	short			*modes;

	initSuperVGA(true);

	for (modes = modelist; *modes != -1; modes++) {
		r.es = SEG(&modeInfo);
		r.di = OFF(&modeInfo);
		r.ax = 0x4F01;
		r.cx = *modes;
		if (bits >= 0x100 && *modes != bits)
			continue;
		if (callVBE(&r)) {
			if ((modeInfo.ModeAttributes & 0x1) == 0)
				continue;
			if (modeInfo.MemoryModel < 3)
				continue;
			if (bits != 0 && bits < 0x100 && modeInfo.BitsPerPixel != bits)
				continue;
			startModeCheck(*modes);
			setSuperVGAMode(*modes);
			checkEscape();
			if (doPageTest)
				pageTest(*modes);
			else {
				moire();
				dumpModeInfo(*modes,true);
				scrollTest();
				checkEscape();
				delay(750);
				}
			if (maxcolor == 255)
				wideDACTest();
			checkEscape();
			if (!doPageTest)
				virtualTest();
			delay(750);
			restoreMode();
			endModeCheck();
			}
		checkEscape();
		}
}

void banner(void)
{
	out("VBETest - VESA VBE stress test program (Version %s)\n", version);
	out("          Copyright (C) 1994 SciTech Software\n\n");
}

void help(void)
{
	banner();
	printf("Usage: vbetest [-vph] [-b<bits>] [-m<mode>]\n\n");
	printf("By specifying the number of 'bits' to test, you can restrict VBETest to\n");
	printf("run the time consuming graphical test only for the modes with the specified\n");
	printf("number of bits per pixel. Likewise you can specify a single 'mode' (in hex).\n\n");
	printf("For example:\n");
	printf("    vbetest -b8   - Test all 8 bits per pixel (256 color) video modes\n");
	printf("    vbetest -m101 - Test only mode 101h (640x480x256)\n\n");
	printf("Options are:\n");
	printf("    -v    - Dump verbose debugging information to the VBETEST.LOG file\n");
	printf("    -p    - Interactive CRTC paging (otherwise uses CRTC scrolling)\n");
	printf("    -b<x> - Only test modes with 'x' bits per pixel\n");
	printf("    -m<x> - Only test mode with internal mode number 'x'\n");
	printf("    -h    - Display this help information\n");
	exit(1);
}

void main(int argc, char *argv[])
{
	int			option;
	char		*argument;

	if (queryCpu() < 4) {
		printf("This program contains '386 specific instructions, and will not work on\n");
		printf("this machine - sorry\n");
		}

	do {
		option = getopt(argc,argv,"vVpPhHb:B:m:M:",&argument);
		if (isascii(option))
			option = tolower(option);
		switch(option) {
			case 'v':
				verbose = true;
				break;
			case 'p':
				doPageTest = true;
				break;
			case 'b':
				bits = atoi(argument);
				break;
			case 'm':
				sscanf(argument, "%x", &bits);
				break;
			case 'h':
			case PARAMETER:
			case INVALID:
				help();
			}
		} while (option != ALLDONE);

	if ((logfile = fopen("vbetest.log","wt")) == NULL) {
		out("Unable to open log file!!\n");
		exit(1);
		}

	banner();
    printf("This program will test every function in the VESA VBE interface specifications\n");
	printf("for correct conformance. If any errors are encountered, they will be logged to\n");
	printf("the file 'vbetest.log' in the current directory.\n\n");
	printf("Hit any key to start, or ESC anytime to cancel.\n");

	if (getch() == 0x1B)
		exit(1);

	checkFunction00h();
	checkFunction01h();
	checkFunction02h();
	checkFunction04h();
	checkFunction05h();

	checkGraphicsFunctions();

	log("\n");
	if (failed)
		out("Video BIOS failed conformance test. Check log report for details.\n");
	else if (!extendedflipping) {
		out("Video BIOS passed most tests, but does not implement extended CRT\n");
		out("addressing, used by some newer programs (like Microsoft Flight\n");
		out("simulator\n");
		}
	else
		out("Congratulations! Video BIOS passed all conformance tests.\n");
}
