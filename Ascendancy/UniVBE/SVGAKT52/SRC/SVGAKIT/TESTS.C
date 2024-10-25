/****************************************************************************
*
*			The SuperVGA Kit - UniVBE Software Development Kit
*
*                   Copyright (C) 1994 SciTech Software
*                           All rights reserved.
*
* Filename:     $RCSfile: tests.c $
* Version:      $Revision: 1.2 $
*
* Language:     ANSI C
* Environment:  IBM PC (MSDOS) Real Mode and 16/32 bit Protected Mode.
*
* Description:  Simple module to test the operation of the SuperVGA
*               bank switching code and page flipping code for the
*               all supported video modes.
*
*               MUST be compiled in the large or flat models.
*
* $Id: tests.c 1.2 1995/09/16 10:45:10 kjb release $
*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>
#include <ctype.h>
#include "svga.h"
#include "ztimer.h"

/*---------------------------- Global Variables ---------------------------*/

PRIVATE	int     x,y;

/*----------------------------- Implementation ----------------------------*/

/* Keyboard handlers provided by main application	*/
int KeyHit(void);
int GetChar(void);

void us_delay(long us)
/****************************************************************************
*
* Function:		us_delay
* Parameters:	us	- Number of microseconds to delay for
*
* Description:	Delays for the specified number of microseconds. We simply
*				use the Zen Timer routines to do this for us, since the
*				delay() function is not normally supported across all
*				compilers.
*
****************************************************************************/
{
	ZTimerInit();
	LZTimerOn();
	while (LZTimerLap() < us)
		;
	LZTimerOff();
}

void moire(ulong defcolor)
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

	if (maxcolor >= 0x7FFFL) {
		for (i = 0; i < maxx; i++) {
			SV_line(maxx/2,maxy/2,i,0,SV_rgbColor((uchar)((i*255L)/maxx),0,0));
			SV_line(maxx/2,maxy/2,i,maxy,SV_rgbColor(0,(uchar)((i*255L)/maxx),0));
			}
		for (i = 0; i < maxy; i++) {
			value = (int)((i*255L)/maxy);
			SV_line(maxx/2,maxy/2,0,i,SV_rgbColor((uchar)value,0,(uchar)(255 - value)));
			SV_line(maxx/2,maxy/2,maxx,i,SV_rgbColor(0,(uchar)(255 - value),(uchar)value));
			}
		}
	else {
		for (i = 0; i < maxx; i += 5) {
			SV_line(maxx/2,maxy/2,i,0,i % maxcolor);
			SV_line(maxx/2,maxy/2,i,maxy,(i+1) % maxcolor);
			}
		for (i = 0; i < maxy; i += 5) {
			SV_line(maxx/2,maxy/2,0,i,(i+2) % maxcolor);
			SV_line(maxx/2,maxy/2,maxx,i,(i+3) % maxcolor);
			}
		}
	SV_line(0,0,maxx,0,defcolor);
	SV_line(0,0,0,maxy,defcolor);
	SV_line(maxx,0,maxx,maxy,defcolor);
	SV_line(0,maxy,maxx,maxy,defcolor);
}

void displayModeInfo(void)
/****************************************************************************
*
* Function:     displayModeInfo
*
* Description:  Display the information about the video mode.
*
****************************************************************************/
{
	char    buf[80];

	sprintf(buf,"Video mode: %d x %d %d bit",maxx+1,maxy+1,bitsperpixel);
	SV_writeText(x,y,buf,defcolor);    y += 16;
	if (VBE_getVideoMode() & vbeLinearBuffer) {
		sprintf(buf,"Using linear frame buffer");
		SV_writeText(x,y,buf,defcolor);    y += 16;
		}
	else if (virtualBuffer) {
		sprintf(buf,"Using *virtual* linear frame buffer");
		SV_writeText(x,y,buf,defcolor);    y += 16;
		}
}

void moireTest(void)
/****************************************************************************
*
* Function:     moireTest
*
* Description:  Draws a simple Moire pattern on the display screen using
*               lines, and waits for a key press.
*
****************************************************************************/
{
	char    buf[80];

	moire(defcolor);
	if (maxx > 360) {
		x = 80;
		y = 80;
		SV_writeText(x,y,"Bank switching test",defcolor);  y += 32;
		displayModeInfo();
		sprintf(buf,"Maximum x: %d, Maximum y: %d, BytesPerLine %d, Pages: %d",
			maxx,maxy,bytesperline,maxpage+1);
		SV_writeText(x,y,buf,defcolor);    y += 32;
		SV_writeText(x,y,"You should see a colorful Moire pattern on the screen",defcolor);
		y += 16;
		}
	else {
		x = 40;
		y = 40;
		displayModeInfo();
		}
	SV_writeText(x,y,"Press any key to continue",defcolor);
	y += 32;
	GetChar();
}

void pageFlipTest(bool waitVRT)
/****************************************************************************
*
* Function:     pageFlipTest
*
* Description:  Animates a line on the display using page flipping if
*               page flipping is active.
*
****************************************************************************/
{
	int     i,j,istep,jstep,apage,vpage,fpsRate = 0;
	ulong	color,lastCount = 0,newCount;
    char    buf[80];

	if (maxpage != 0) {
		vpage = 0;
		apage = 1;
		SV_setActivePage(apage);
		SV_setVisualPage(vpage,waitVRT);
		i = 0;
		j = maxy;
		istep = 2;
		jstep = -2;
		color = 15;
		if (maxcolor > 255)
			color = defcolor;
		ZTimerInit();
		LZTimerOn();
		while (!KeyHit()) {
			SV_setActivePage(apage);
			SV_clear(0);
			sprintf(buf,"%3d.%d fps", fpsRate / 10, fpsRate % 10);
			SV_writeText(4,4,buf,defcolor);
			sprintf(buf,"Page %d of %d", apage+1, maxpage+1);
			if (maxx <= 360) {
				SV_writeText(4,80,"Page flipping - should be no flicker",defcolor);
				SV_writeText(4,100,buf,defcolor);
                }
			else {
				SV_writeText(80,80,"Page flipping - should be no flicker",defcolor);
				SV_writeText(80,100,buf,defcolor);
				}
			SV_line(i,0,maxx-i,maxy,color);
			SV_line(0,maxy-j,maxx,j,color);
			SV_line(0,0,maxx,0,defcolor);
			SV_line(0,0,0,maxy,defcolor);
			SV_line(maxx,0,maxx,maxy,defcolor);
			SV_line(0,maxy,maxx,maxy,defcolor);
			vpage = ++vpage % (maxpage+1);
			SV_setVisualPage(vpage,waitVRT);
			apage = ++apage % (maxpage+1);
			i += istep;
			if (i > maxx) {
				i = maxx-2;
				istep = -2;
				}
			if (i < 0)  i = istep = 2;
			j += jstep;
			if (j > maxy) {
				j = maxy-2;
				jstep = -2;
				}
			if (j < 0)  j = jstep = 2;

			/* Compute the frames per second rate after going through an entire
			 * set of display pages.
			 */
			if (apage == 0) {
				newCount = LZTimerLap();
				fpsRate = (int)(10000000L / (newCount - lastCount)) * (maxpage+1);
				lastCount = newCount;
                }
			}
		LZTimerOff();
		GetChar();                /* Swallow keypress */
		}
	SV_setActivePage(0);
	SV_setVisualPage(0,false);
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
	int		i,x,y,scrollx,scrolly,oldmaxx,oldmaxy,oldbytesperline,max;
	char	buf[80];

	if (!VBE_setDisplayStart(10,10,false))
    	return;
	if (maxx == 319 && maxy == 199 && maxpage == 0)
		return;
	SV_setMode(VBE_getVideoMode());

	/* Set up for the widest possible virtual display buffer */

	oldmaxx = maxx;
	oldmaxy = maxy;
	oldbytesperline = bytesperline;

	/* Find the largest value that we can set the virtual buffer width
	 * to that the VBE supports
	 */
	switch (bitsperpixel) {
		case 4:		max = (int)((memory*2048L) / (maxy+1));	break;
		case 8:		max = (int)((memory*1024L) / (maxy+1));	break;
		case 15:
		case 16:	max = (int)((memory*512L) / (maxy+1));	break;
		case 24:	max = (int)((memory*341L) / (maxy+1));	break;
		case 32:	max = (int)((memory*256L) / (maxy+1));	break;
		}

	for (i = max; i > oldmaxx+1; i--) {
		if (!SV_setPixelsPerLine(i))
			continue;
		if (maxx > oldmaxx+1 && maxx < max)
			break;				/* Large value has been set			*/
		}

	/* Perform huge horizontal scroll */

	VBE_setDisplayStart(0,0,false);
	SV_clear(0);
	moire(defcolor);
	if (maxx == oldmaxx) {
		sprintf(buf,"Virtual buffer not resizeable in this mode (still %d x %d pixels)",maxx+1,maxy+1);
		SV_writeText(20,40,buf,defcolor);
		SV_writeText(20,60,"Press any key to begin vertical scrolling",defcolor);
		goto StartVerticalScroll;
		}
	else
		sprintf(buf,"Virtual buffer now set to %d x %d pixels",maxx+1,maxy+1);
	SV_writeText(20,40,buf,defcolor);
	SV_writeText(20,60,"Press any key to begin virtual scrolling",defcolor);
	GetChar();
	scrollx = maxx-oldmaxx;
	scrolly = maxy-oldmaxy;
	for (x = y = 0; x <= scrollx; x++) {
		VBE_setDisplayStart(x,y,false);
		us_delay(1000);
		if (KeyHit())
			goto DoneHorizontal;
		}
	for (x = scrollx,y = 0; y <= scrolly; y++) {
		VBE_setDisplayStart(x,y,false);
		us_delay(1000);
		if (KeyHit())
			goto DoneHorizontal;
		}
	for (x = scrollx,y = scrolly; x >= 0; x--) {
		VBE_setDisplayStart(x,y,false);
		us_delay(1000);
		if (KeyHit())
			goto DoneHorizontal;
		}
	for (x = 0,y = scrolly; y >= 0; y--) {
		VBE_setDisplayStart(x,y,false);
		us_delay(1000);
		if (KeyHit())
			goto DoneHorizontal;
		}

DoneHorizontal:
	GetChar();
	if (maxx == oldmaxx) goto ResetMode;

	/* Now perform huge vertical scroll */

	VBE_setDisplayStart(0,0,false);
	if (VBEVersion < 0x200)
		SV_setPixelsPerLine(oldmaxx+1);
	else SV_setBytesPerLine(oldbytesperline);
	maxx = oldmaxx;
	SV_clear(0);
	moire(defcolor);
	sprintf(buf,"Virtual buffer now set to %d x %d pixels",maxx+1,maxy+1);
	SV_writeText(20,40,buf,defcolor);
	SV_writeText(20,60,"Press any key to begin virtual scrolling",defcolor);
StartVerticalScroll:
	GetChar();
	scrolly = maxy-oldmaxy;
	for (y = 0; y <= scrolly; y++) {
		VBE_setDisplayStart(0,y,false);
		us_delay(1000);
		if (KeyHit())
			goto DoneVertical;
		}
	for (y = scrolly; y >= 0; y--) {
		VBE_setDisplayStart(0,y,false);
		us_delay(1000);
		if (KeyHit())
			goto DoneVertical;
		}
DoneVertical:
	GetChar();
ResetMode:
	SV_setMode(VBE_getVideoMode());
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
	int			i;
	VBE_palette	pal[256];

	if (!SV_set8BitDAC()) return;

	memset(pal,0,256*sizeof(VBE_palette));
	for (i = 0; i < 256; i += 4) {
		pal[64 + (i >> 2)].red = i;
		pal[128 + (i >> 2)].green = i;
		pal[192 + (i >> 2)].blue = i;
		}

	pal[(int)defcolor].red = 255;
	pal[(int)defcolor].green = 255;
	pal[(int)defcolor].blue = 255;
	SV_setPalette(0,256,pal,-1);

	SV_clear(0);
	SV_line(0,0,maxx,0,defcolor);
	SV_line(0,0,0,maxy,defcolor);
	SV_line(maxx,0,maxx,maxy,defcolor);
	SV_line(0,maxy,maxx,maxy,defcolor);

	if (maxx > 360) {
		x = 80;
		y = 80;
		}
	else {
		x = 40;
		y = 40;
		}

	SV_writeText(x,y,"Wide DAC test",defcolor);
	y += 32;
	if (maxx > 360) {
		SV_writeText(x,y,"You should see a smooth transition of colors",defcolor);
		y += 16;
		SV_writeText(x,y,"If the colors are broken into 4 lots, the wide DAC is not working",defcolor);
		y += 32;
		}

	for (i = 0; i < 192; i++) {
		SV_line(x+i, y,    x+i, y+32,  64+i/3);
		SV_line(x+i, y+32, x+i, y+64,  128+i/3);
		SV_line(x+i, y+64, x+i, y+96,  192+i/3);
		}

	GetChar();
	SV_set6BitDAC();
}

void fadePalette(VBE_palette *pal,VBE_palette *fullIntensity,int numColors,
	int startIndex,uchar intensity)
/****************************************************************************
*
* Function:		fadePalette
* Parameters:	pal				- Palette to fade
*				fullIntensity	- Palette of full intensity values
*               numColors		- Number of colors to fade
*               startIndex		- Starting index in palette
*				intensity		- Intensity value for entries (0-255)
*
* Description:  Fades each of the palette values in the palette by the
*				specified intensity value. The values to fade from are
*				contained in the 'fullItensity' array, which should be at
*				least numColors in size.
*
****************************************************************************/
{
	uchar	*p,*fi;
	int		i;

	p = (uchar*)&pal[startIndex];
	fi = (uchar*)fullIntensity;
	for (i = 0; i < numColors; i++) {
		*p++ = (*fi++ * intensity) / (uchar)255;
		*p++ = (*fi++ * intensity) / (uchar)255;
		*p++ = (*fi++ * intensity) / (uchar)255;
		p++; fi++;
		}
}

void paletteTest(int maxProgram)
/****************************************************************************
*
* Function:		paletteTest
*
* Description:	Performs a palette programming test by displaying all the
*				colors in the palette and then quickly fading the values
*				out then in again.
*
****************************************************************************/
{
	int			i;
	VBE_palette	pal[256],tmp[256];

	SV_clear(0);
	moire(63);
	if (maxx > 360) {
		x = 80;	y = 80;
		}
	else {
		x = 40;	y = 40;
		}

	SV_writeText(x,y,"Palette programming test",63);
	y += 32;
	SV_writeText(x,y,"Hit a key to fade palette",63);

	memset(pal,0,256*sizeof(VBE_palette));
	for (i = 0; i < 64; i++) {
		pal[i].red = pal[i].green = pal[i].blue = i;
		pal[64 + i].red = i;
		pal[128 + i].green = i;
		pal[192 + i].blue = i;
		}

	SV_setPalette(0,256,pal,-1);
	GetChar();

	/* Palette fade out */
	for (i = 63; i >= 0; i--) {
		fadePalette(tmp,pal,256,0,i*4);
		SV_setPalette(0,256,tmp,maxProgram);
		}

	/* Palette fade in */
	for (i = 0; i <= 63; i++) {
		fadePalette(tmp,pal,256,0,i*4);
		SV_setPalette(0,256,tmp,maxProgram);
		}
	GetChar();
}

bool doTest(ushort mode,bool widedac,bool doPalette,bool doVirtual,
	bool doRetrace,int maxProgram)
{
	if (!SV_setMode(mode))
		return false;
	else {
		moireTest();
		pageFlipTest(doRetrace);
		if (doPalette && maxcolor == 255) {
			paletteTest(maxProgram);
			if (widedac)
				wideDACTest();
			}
		if (doVirtual)
			virtualTest();
		SV_restoreMode();
		}
	return true;
}

