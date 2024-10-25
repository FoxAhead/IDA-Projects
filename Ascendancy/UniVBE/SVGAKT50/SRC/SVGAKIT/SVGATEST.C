/****************************************************************************
*
*                        	  The SuperVGA Kit
*
*                   Copyright (C) 1994 SciTech Software
*                           All rights reserved.
*
* Filename:     $RCSfile: svgatest.c $
* Version:      $Revision: 1.1 $
*
* Language:     ANSI C
* Environment:  IBM PC (MSDOS) Real Mode and 16/32 bit Protected Mode.
*
* Description:  Simple program to test the operation of the SuperVGA
*               bank switching code and page flipping code for the
*               all supported video modes.
*
*               MUST be compiled in the large or flat models.
*
* $Id: svgatest.c 1.1 1994/08/22 12:27:00 kjb release $
*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dos.h>
#include <conio.h>
#include "pmode.h"
#include "svga.h"

/*---------------------------- Global Variables ---------------------------*/

int     x,y;

/* External routines */

#ifdef	REALMODE
void _cdecl _copyTest256(void);
void _cdecl _copyTest16(void);
#endif

int _cdecl queryCpu(void);

#include "version.c"

/*----------------------------- Implementation ----------------------------*/

void clearText(void)
/****************************************************************************
*
* Function:     clearText
*
* Description:  Clears the current text display mode.
*
****************************************************************************/
{
	RMREGS	regs;

	regs.x.cx = 0;
	regs.h.dl = 80;
	regs.h.dh = 50;
	regs.h.ah = 0x06;
	regs.h.al = 50;
	regs.h.bh = 0x07;
	PM_int86(0x10,&regs,&regs);      /* Scroll display up    */
	regs.x.dx = 0;
	regs.h.bh = 0;
    regs.h.ah = 0x02;
	PM_int86(0x10,&regs,&regs);      /* Home the cursor      */
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
    int     i;
	uint    value;

	clear(0);
	if (maxcolor >= 0x7FFFL) {
		for (i = 0; i < maxx; i++) {
			line(maxx/2,maxy/2,i,0,rgbColor((uchar)((i*255L)/maxx),0,0));
			line(maxx/2,maxy/2,i,maxy,rgbColor(0,(uchar)((i*255L)/maxx),0));
			}
		for (i = 0; i < maxy; i++) {
			value = (i*255L)/maxy;
			line(maxx/2,maxy/2,0,i,rgbColor((uchar)value,0,(uchar)(255 - value)));
			line(maxx/2,maxy/2,maxx,i,rgbColor(0,(uchar)(255 - value),(uchar)value));
			}
		}
	else {
		for (i = 0; i < maxx; i += 5) {
			line(maxx/2,maxy/2,i,0,i % maxcolor);
			line(maxx/2,maxy/2,i,maxy,(i+1) % maxcolor);
			}
		for (i = 0; i < maxy; i += 5) {
			line(maxx/2,maxy/2,0,i,(i+2) % maxcolor);
			line(maxx/2,maxy/2,maxx,i,(i+3) % maxcolor);
			}
		}
	line(0,0,maxx,0,defcolor);
    line(0,0,0,maxy,defcolor);
    line(maxx,0,maxx,maxy,defcolor);
	line(0,maxy,maxx,maxy,defcolor);

	if (maxx != 319) {
		x = 80;
		y = 80;
		writeText(x,y,"Bank switching test",defcolor);  y += 32;
		sprintf(buf,"Video mode: %d x %d %ld color",maxx+1,maxy+1, maxcolor+1);
		writeText(x,y,buf,defcolor);    y += 16;
		sprintf(buf,"Maximum x: %d, Maximum y: %d, BytesPerLine %d, Pages: %d",
			maxx,maxy,bytesperline,maxpage+1);
		writeText(x,y,buf,defcolor);    y += 32;
		writeText(x,y,"You should see a colorful Moire pattern on the screen",defcolor);
		y += 16;
		}
	else {
		x = 40;
		y = 40;
		}
	writeText(x,y,"Press any key to continue",defcolor);
	y += 32;
	getch();
}

void readWriteTest(void)
/****************************************************************************
*
* Function:     readWriteTest
*
* Description:  Test the separate read/write bank routines if available.
*               We do this by copying the top 100 scanlines of video memory
*               to another location in video memory.
*
*               This test is desgined to work only in 640 wide video modes.
*
****************************************************************************/
{
#ifdef	REALMODE
	if (twobanks && maxpage != 0 && (maxx == 799) && (maxcolor == 15)) {
		writeText(x,y,"To test the separate read/write banks, the top half of",defcolor);
		y += 16;
		writeText(x,y,"this display page should be moved to the bottom half of",defcolor);
		y += 16;
		writeText(x,y,"the second display page",defcolor);
		setActivePage(1);
		clear(0);
		setVisualPage(1);
		_copyTest16();
		x = y = 80;
		writeText(x,y,"Press any key to continue",defcolor);
		getch();
		}
	if (twobanks && (maxx == 639) && (maxcolor == 255)) {
		_copyTest256();
		writeText(x,y,"To test the separate read/write banks, the top 100 scanlines of",defcolor);
		y += 16;
		writeText(x,y,"this display page should be moved to start at scanline 205.",defcolor);
		y += 16;
		writeText(x,y,"This ensures that a bank boundary will have been crossed",defcolor);
		y += 78;
		writeText(x,y,"Press any key to continue",defcolor);
		getch();
		}
#endif
}

void pageFlipTest(void)
/****************************************************************************
*
* Function:     pageFlipTest
*
* Description:  Animates a line on the display using page flipping if
*               page flipping is active.
*
****************************************************************************/
{
    int     i,j,istep,jstep,color,apage,vpage;
    char    buf[80];

    if (maxpage != 0) {
        vpage = 0;
        apage = 1;
        setActivePage(apage);
		setVisualPage(vpage);
        i = 0;
        j = maxy;
        istep = 2;
		jstep = -2;
		color = 15;
		if (maxcolor > 255)
			color = maxcolor;
        while (!kbhit()) {
            setActivePage(apage);
			clear(0);
			sprintf(buf,"Page %d of %d", apage+1, maxpage+1);
            if (maxx == 319) {
                writeText(0,80,"Page flipping - should be no flicker",defcolor);
                writeText(0,100,buf,defcolor);
                }
			else {
                writeText(80,80,"Page flipping - should be no flicker",defcolor);
                writeText(80,100,buf,defcolor);
                }
            line(i,0,maxx-i,maxy,color);
            line(0,maxy-j,maxx,j,color);
			line(0,0,maxx,0,defcolor);
			line(0,0,0,maxy,defcolor);
			line(maxx,0,maxx,maxy,defcolor);
			line(0,maxy,maxx,maxy,defcolor);
			vpage = ++vpage % (maxpage+1);
			setVisualPage(vpage);
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
			}
		getch();                /* Swallow keypress */
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
	int		i;
	palette	pal[256];

	if (widedac) {
		if (!set8BitPalette()) return;

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

		if (maxx != 319) {
			x = 80;
			y = 80;
			}
		else {
			x = 40;
			y = 40;
			}

		writeText(x,y,"Wide DAC test",defcolor);
		y += 32;
		if (maxx != 319) {
			writeText(x,y,"You should see a smooth transition of colors",defcolor);
			y += 16;
			writeText(x,y,"If the colors are broken into 4 lots, the wide DAC is not working",defcolor);
			y += 32;
			}

		for (i = 0; i < 192; i++) {
			line(x+i, y,    x+i, y+32,  64+i/3);
			line(x+i, y+32, x+i, y+64,  128+i/3);
			line(x+i, y+64, x+i, y+96,  192+i/3);
			}

		getch();
		set6BitPalette();
		}
}

void testingComplete(void)
/****************************************************************************
*
* Function:     testingComplete
*
* Description:  Clears the first display page and puts up a message.
*
****************************************************************************/
{
	setActivePage(0);
	setVisualPage(0);
	clear(0);

	if (maxx == 319) {
		writeText(0,40,"Testing complete",defcolor);
		writeText(0,60,"press any key to return to text mode",defcolor);
		}
	else
		writeText(80,80,"Testing complete - press any key to return to text mode",defcolor);
	getch();
}

void test16(void)
{
	int     i,choice,maxmenu;
    int     xres,yres,bitsperpixel,memmodel,maxpage;
    long    pagesize;
	int     menu[10];

	while (true) {
		clearText();
		printf("16 color tests\n\n");
		printf("Which video mode to test:\n\n");

        maxmenu = 0;

		/* Add standard VGA modes to menu */

		getSuperVGAModeInfo(menu[maxmenu] = 0x0D,&xres,&yres,&bytesperline,
                &bitsperpixel,&memmodel,&maxpage,&pagesize);
		printf("    [%d] - %d x %d 16 color (%d page)\n",maxmenu++,
			xres,yres,maxpage+1);

		getSuperVGAModeInfo(menu[maxmenu] = 0x0E,&xres,&yres,&bytesperline,
				&bitsperpixel,&memmodel,&maxpage,&pagesize);
		printf("    [%d] - %d x %d 16 color (%d page)\n",maxmenu++,
			xres,yres,maxpage+1);

		getSuperVGAModeInfo(menu[maxmenu] = 0x10,&xres,&yres,&bytesperline,
				&bitsperpixel,&memmodel,&maxpage,&pagesize);
		printf("    [%d] - %d x %d 16 color (%d page)\n",maxmenu++,
			xres,yres,maxpage+1);

		getSuperVGAModeInfo(menu[maxmenu] = 0x12,&xres,&yres,&bytesperline,
				&bitsperpixel,&memmodel,&maxpage,&pagesize);
		printf("    [%d] - %d x %d 16 color (%d page)\n",maxmenu++,
			xres,yres,maxpage+1);

		for (i = 0; modeList[i] != -1; i++) {
            /* Filter out the 256 color packed pixel video modes */

            if (!getSuperVGAModeInfo(modeList[i],&xres,&yres,&bytesperline,
                    &bitsperpixel,&memmodel,&maxpage,&pagesize))
                continue;
			if ((bitsperpixel == 4) && (memmodel == memPL)) {
				printf("    [%d] - %d x %d 16 color (%d page)\n",maxmenu,
					xres,yres,maxpage+1);
				menu[maxmenu++] = modeList[i];
				}
			}
		printf("    [Q] - Quit\n\n");
        printf("Choice: ");
        fflush(stdout);

		choice = getch();
		if (choice == 'q' || choice == 'Q' || choice == 0x1B)
            break;
		choice -= '0';
		if (0 <= choice && choice < maxmenu) {
            if (!setSuperVGAMode(menu[choice])) {
                printf("\n");
                printf("ERROR: Video mode did not set correctly!\n\n");
                printf("\nPress any key to continue...\n");
                getch();
                }
			else {
				moireTest();
				readWriteTest();
				pageFlipTest();
				testingComplete();
				restoreMode();
				}
            }
        }
}

void test256(void)
{
    int     i,choice,maxmenu;
    int     xres,yres,bitsperpixel,memmodel,maxpage;
    long    pagesize;
	int     menu[10];

	while (true) {
		clearText();
		printf("256 color tests\n\n");
		printf("Which video mode to test:\n\n");

        maxmenu = 0;

		/* Add standard VGA modes to menu */

        getSuperVGAModeInfo(menu[maxmenu] = 0x13,&xres,&yres,&bytesperline,
				&bitsperpixel,&memmodel,&maxpage,&pagesize);
		printf("    [%d] - %d x %d 256 color (%d page)\n",maxmenu++,
            xres,yres,maxpage+1);

        for (i = 0; modeList[i] != -1; i++) {
            /* Filter out the 256 color packed pixel video modes */

            if (!getSuperVGAModeInfo(modeList[i],&xres,&yres,&bytesperline,
                    &bitsperpixel,&memmodel,&maxpage,&pagesize))
                continue;
            if ((bitsperpixel == 8) && (memmodel == memPK)) {
				printf("    [%d] - %d x %d 256 color (%d page)\n",maxmenu,
					xres,yres,maxpage+1);
				menu[maxmenu++] = modeList[i];
				}
			}
		printf("    [Q] - Quit\n\n");
        printf("Choice: ");
        fflush(stdout);

		choice = getch();
		if (choice == 'q' || choice == 'Q' || choice == 0x1B)
			break;
		choice -= '0';
		if (0 <= choice && choice < maxmenu) {
            if (!setSuperVGAMode(menu[choice])) {
                printf("\n");
                printf("ERROR: Video mode did not set correctly!\n\n");
                printf("\nPress any key to continue...\n");
                getch();
                }
			else {
				moireTest();
				readWriteTest();
				wideDACTest();
				pageFlipTest();
				testingComplete();
				restoreMode();
				}
            }
        }
}

void testDirectColor(long colors)
{
	int     i,choice,maxmenu,numbits;
	int     xres,yres,bitsperpixel,memmodel,maxpage;
	long    pagesize;
	int     menu[10];

	while (true) {
		clearText();
		printf("%ld color tests\n\n", colors+1);
		printf("Which video mode to test:\n\n");

		if (colors == 0x7FFFL)
			numbits = 15;
		else if (colors == 0xFFFFL)
			numbits = 16;
		else numbits = 24;

		maxmenu = 0;

		for (i = 0; modeList[i] != -1; i++) {
			/* Filter out the appropriate video modes */

			if (!getSuperVGAModeInfo(modeList[i],&xres,&yres,&bytesperline,
					&bitsperpixel,&memmodel,&maxpage,&pagesize))
				continue;
			if (bitsperpixel == numbits || (numbits == 24 && bitsperpixel == 32)) {
				printf("    [%d] - %d x %d %ld color (%d page)\n",maxmenu,
					xres,yres,colors+1,maxpage+1);
				menu[maxmenu++] = modeList[i];
				}
			}
		printf("    [Q] - Quit\n\n");
        printf("Choice: ");
        fflush(stdout);

		choice = getch();
		if (choice == 'q' || choice == 'Q' || choice == 0x1B)
			break;
		choice -= '0';
		if (0 <= choice && choice < maxmenu) {
            if (!setSuperVGAMode(menu[choice])) {
                printf("\n");
                printf("ERROR: Video mode did not set correctly!\n\n");
                printf("\nPress any key to continue...\n");
                getch();
                }
			else {
				moireTest();
				pageFlipTest();
				testingComplete();
				restoreMode();
				}
            }
        }
}

int main(void)
{
    int     vbever, choice,highspeed = false;
    RMREGS  regs;

    if (queryCpu() < 4) {
        printf("This program contains '386 specific instructions, and will not work on\n");
        printf("this machine - sorry\n");
        }

	if ((vbever = initSuperVGA(true)) < 0x102) {
		printf("This program requires a VESA VBE 1.2 compatible SuperVGA. Try installing\n");
		printf("the Universal VESA VBE for your video card, or contact your video card\n");
        printf("vendor and ask for a suitable TSR\n");
        exit(1);
		}

	if (_PM_modeType == PM_386) {
		/* Determine if the UniVBE's high speed protected mode interface is
		 * there and functioning, simply so we can report this to the user.
		 */

		regs.x.ax = 0x4F0A;
		regs.x.bx = 0xFE01;
		regs.x.dx = 0x0500;
		PM_int86(0x10, &regs, &regs);
		if (regs.x.ax == 0x004F)
			highspeed = true;
		}

	while (true) {
		clearText();
		printf("The SuperVGA Kit test program (Version %s)\n",version);
		printf("Copyright (C) 1994 SciTech Software - All Rights Reserved\n\n");
		printf("Currently running in ");
		switch (_PM_modeType) {
			case PM_realMode:
				printf("16 bit real mode\n\n");
				break;
			case PM_286:
				printf("16 bit protected mode\n\n");
				break;
			case PM_386:
				printf("32 bit protected mode\n\n");
				break;
			}

		printf("VBE OEM string: %s\n",OEMString);
		printf("VBE Version:    %d.%d\n", vbever >> 8, vbever & 0xFF);
		printf("Memory:         %dk\n",memory);
        printf("\n");
		printf("Separate read/write banks:                  %s\n", twobanks ? "Yes" : "No");
		printf("Extended page flipping:                     %s\n", extendedflipping ? "Yes" : "No");
		printf("8 bit wide DAC support:                     %s\n", widedac ? "Yes" : "No");
		printf("Using high speed protected mode interface:  %s\n", highspeed ? "Yes" : "No");
		printf("\n");
		printf("Select color mode to test:\n\n");
		printf("    [0] - 16 color modes\n");
		printf("    [1] - 256 color modes\n");
		printf("    [2] - 32,768 color modes\n");
		printf("    [3] - 65,536 color modes\n");
		printf("    [4] - 16,777,216 color modes\n");
		printf("    [Q] - Quit\n\n");
		printf("Choice: ");
        fflush(stdout);

		choice = getch();
		if (choice == 'q' || choice == 'Q' || choice == 0x1B)
			break;

		switch (choice) {
			case '0':	test16();					break;
			case '1':	test256();					break;
			case '2':	testDirectColor(0x7FFFL);	break;
			case '3':	testDirectColor(0xFFFFL);	break;
			case '4':	testDirectColor(0xFFFFFFL);	break;
			}
		}
	printf("\n");
	return 0;
}
