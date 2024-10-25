/****************************************************************************
*
*                        	  The SuperVGA Kit
*
*                   Copyright (C) 1994 SciTech Software
*                           All rights reserved.
*
* Filename:     $RCSfile: profile.c $
* Version:      $Revision: 1.1 $
*
* Language:     ANSI C
* Environment:  IBM PC (MSDOS) Real Mode and 16/32 bit Protected Mode.
*
* Description:  Simple program to profile the speed of certain operations
*				for the SuperVGA Kit. This is great way to test the
*				performance of different SuperVGA card and different
*				compiler configurations. It is also helps to highlight
*				where the 32 bit protected mode interface of UniVBE can
*				be very beneficial for 32 bit application development.
*
*				Note, this library uses the Zen Timer Library for
*				microsecond accuracy timing of the routines.
*
*               MUST be compiled in the large or flat models.
*
* $Id: profile.c 1.1 1994/08/22 12:27:00 kjb release $
*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dos.h>
#include <conio.h>
#include "pmode.h"
#include "svga.h"
#include "ztimer.h"

/*----------------------------- Implementation ----------------------------*/

float	pixelTime;
long	numPixels;
float	pixelsPerSec;
float	lineTime;
long	numLines;
float	linesPerSec;
float	clearTime;
long	numClears;
float	clearsPerSec;
float	bitBltTime;
long	numBitBlts;
float	bitBltsPerSec;

#include "version.c"

/* External assembly language routine to perform a full screen Blt from
 * system memory, using fast REP MOVSD strings instructions for entire
 * 64k banks - about as optimal as you will ever get for a full screen
 * Blt.
 */

extern void _cdecl bltImage(char *image,int numBanks,int lastBytes);

void profilePixels(void)
/****************************************************************************
*
* Function:		profilePixels
*
* Description:	Tests the speed of pixel drawing, by filling the entire
*				frame buffer with pixels.
*
****************************************************************************/
{
	int		i,j,k,max;
	long	step,color;

	switch (maxcolor) {
		case 0xF:		max = 2;	break;
		case 0xFF:
		case 0x7FFF:
		case 0xFFFF:	max = 5;	break;
		default:		max = 5;
		}

	clear(0);
	step = (maxcolor <= 0xFF) ? 1 : maxcolor / max;
	ULZTimerOn();
	for (k = 0,color = 1; k < max; k++, color += step) {
		for (j = 0; j <= maxy; j++)
			for (i = 0; i <= maxx; i++)
				putPixel(i,j,color);
		}
	ULZTimerOff();
	pixelTime = ULZTimerCount() * ULZTIMER_RES;
	numPixels = (long)(maxx+1) * (maxy+1) * max;
	pixelsPerSec = numPixels / pixelTime;
}

int _random(int max)
{
	return (rand() % (max+1));
}

#define	MAXLINES	1000

int x[MAXLINES];
int y[MAXLINES];

void profileLines(void)
/****************************************************************************
*
* Function:		profileLines
*
* Description:	Test the speed of line drawing in the specified video
*				mode. We blast out a whole bunch of random lines as fast
*				as possible.
*
****************************************************************************/
{
	int		i,j,max;
	long	step,color;

	switch (maxcolor) {
		case 0xF:		max = 20;	break;
		case 0xFF:
		case 0x7FFF:
		case 0xFFFF:	max = 30;	break;
		default:		max = 20;
		}

	srand(1000);
    for (i = 0; i < MAXLINES; i++) {
		x[i] = _random(maxx);
		y[i] = _random(maxy);
		}

	clear(0);
	step = (maxcolor <= 0xFF) ? 1 : maxcolor / max;
	ULZTimerOn();
	for (j = 0, color = 1; j < max; j++, color += step) {
		for (i = 0; i < MAXLINES-1; i++)
			line(x[i],y[i],x[i+1],y[i+1],color);
		}
	ULZTimerOff();
	lineTime = ULZTimerCount() * ULZTIMER_RES;
	numLines = (long)MAXLINES * max;
	linesPerSec = numLines / lineTime;
}

void profileClears(void)
/****************************************************************************
*
* Function:		profileClears
*
* Description:	Test the speed of screen clearing to a specific color.
*
****************************************************************************/
{
	int		i,max;
	long	step,color;

	switch (maxcolor) {
		case 0xF:		max = 1000;	break;
		case 0xFF:		max = 300;	break;
		case 0x7FFF:
		case 0xFFFF:	max = 150;	break;
		case 0xFFFFFF:	max = 30;	break;
		default:		max = 50;	break;
		}

	step = (maxcolor <= 0xFF) ? 1 : maxcolor / max;
	ULZTimerOn();
	for (i = 0, color = 0; i < max; i++, color += step)
		clear(color);
	ULZTimerOff();
	clearTime = ULZTimerCount() * ULZTIMER_RES;
	numClears = max;
	clearsPerSec = numClears / clearTime;
}

void profileBitBlt(void)
/****************************************************************************
*
* Function:		profileBitBlt
*
* Description:	Test the speed of blitting full size image from system RAM
*				to video RAM.
*
*				NOTE: The bitBlt'ing routine used blt's and entire display
*					  memory frame at a time, which is as optimal as you
*					  can get. Thus the results of this profiling test will
*					  give you a good idea of what you can expect as the
*					  absolute best case in real world performance.
*
****************************************************************************/
{
	int		i,numBanks,max;
	uint	lastBytes;
	ulong	imageSize;
	uint	screenSel;
	char	*image,*dst;

	switch (maxcolor) {
        case 0xFF:      max = 150;  break;
		case 0x7FFF:
        case 0xFFFF:    max = 75;  break;
        default:        max = 30;
		}

	screenSel = PM_getVGASelector();
	imageSize = (long)bytesperline * (maxy+1);
#ifndef	PM386
	if (imageSize > 0x10000) {
		bitBltTime = -1;
		return;
		}
#endif
	numBanks = imageSize / 0x10000;
	lastBytes = imageSize % 0x10000;
	image = malloc(imageSize);
	if (image == NULL) {
		bitBltTime = -1;
		return;
		}

	// Copy the current image from the frame buffer into our system memory
	// buffer (which will still contain an image from the profileLines()
	// routine).

	dst = image;
	for (i = 0; i < numBanks; i++) {		// Blt all full memory banks
		setBank(i);
		PM_memcpynf(dst,screenSel,0,0x10000);
		dst += 0x10000;
		}
	if (lastBytes) {
		setBank(i);
		PM_memcpynf(dst,screenSel,0,lastBytes);	// Blt the last partial bank
		}

	// Now blt the image from system RAM back to the video frame buffer
	clear(0);
	ULZTimerOn();
	for (i = 0; i < max; i++)
		bltImage(image,numBanks,lastBytes);
	ULZTimerOff();
	bitBltTime = ULZTimerCount() * ULZTIMER_RES;
	numBitBlts = max;
	bitBltsPerSec = numBitBlts / bitBltTime;

	free(image);
}

void dumpMode(int mode)
{
	int		xres,yres,bytesperline,bitsperpixel,memmodel,maxpage;
	long	pagesize;

	getSuperVGAModeInfo(mode,&xres,&yres,&bytesperline,&bitsperpixel,
		&memmodel,&maxpage,&pagesize);
	if (memmodel >= memPL)
		printf("    %03X - %dx%d\t%d bits per pixel\n", mode,
			xres, yres, bitsperpixel);
}

void help(void)
{
	short	*modes;

	printf("Profile - SuperVGA Kit performance profiling program (Version %s)\n", version);
	printf("          Copyright (C) 1994 SciTech Software\n\n");
	printf("Usage: profile [mode]\n\n");
	printf("Available modes are:\n");
	dumpMode(0x0D);
	dumpMode(0x10);
	dumpMode(0x12);
	dumpMode(0x13);
	for (modes = modeList; *modes != -1; modes++)
		dumpMode(*modes);
	exit(1);
}

int main(int argc, char *argv[])
{
	int	mode;

	if (initSuperVGA(false) < 0x102) {
		printf("This program requires a VESA VBE 1.2 compatible SuperVGA. Try installing\n");
		printf("the Universal VESA VBE for your video card, or contact your video card\n");
        printf("vendor and ask for a suitable TSR\n");
        exit(1);
        }
    if (argc != 2)
		help();

	sscanf(argv[1], "%X", &mode);
	ZTimerInit();

	if (setSuperVGAMode(mode)) {
		profilePixels();
		profileLines();
		if (maxcolor > 0xF)
			profileBitBlt();
		profileClears();
		restoreMode();

		printf("Profiling results for %dx%d %ld color (%s):\n",
			maxx+1,maxy+1,maxcolor+1,
#ifdef	PM386
			"32 bit protected mode");
#elif	defined(PM286)
			"16 bit protected mode");
#else
			"16 bit real mode");
#endif
		printf("\n");
		printf("%.1fs for %8ld pixels  (%.2f pixels/s)\n", pixelTime, numPixels, pixelsPerSec);
		printf("%.1fs for %8ld lines   (%.2f lines/s)\n", lineTime, numLines, linesPerSec);
		printf("%.1fs for %8ld clears  (%.2f clears/s)\n", clearTime, numClears, clearsPerSec);
		if (maxcolor > 0xF && bitBltTime != -1)
			printf("%.1fs for %8ld bitBlts (%.2f bitBlt/s)\n", bitBltTime, numBitBlts, bitBltsPerSec);
		}
	else printf("Could not set specified video mode\n");
	return 0;
}
