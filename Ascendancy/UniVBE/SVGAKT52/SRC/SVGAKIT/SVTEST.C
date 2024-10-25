/****************************************************************************
*
*			The SuperVGA Kit - UniVBE Software Development Kit
*
*                   Copyright (C) 1994 SciTech Software
*                           All rights reserved.
*
* Filename:     $RCSfile: svtest.c $
* Version:      $Revision: 1.2 $
*
* Language:     ANSI C
* Environment:  IBM PC (MSDOS) Real Mode and 16/32 bit Protected Mode.
*
* Description:  Simple program to test the operation of the SuperVGA
*               bank switching code and page flipping code for the
*               all supported video modes.
*
*				Can also be compiled to use the UVBELib linkable library
*				version of UniVBE for direct device support. Contact
*				SciTech Software for licensing information on this library.
*
*               MUST be compiled in the LARGE or FLAT models.
*
* $Id: svtest.c 1.2 1995/09/16 10:45:10 kjb release $
*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>
#include <ctype.h>
#include "getopt.h"
#include "pmode.h"
#include "svga.h"

#ifdef	USE_UVBELIB
#include "uvbelib.h"
#endif

/*---------------------------- Global Variables ---------------------------*/

PRIVATE int     VBE_version;
PRIVATE	int		extCRTC,maxProgram = 256;
PRIVATE bool	widedac,doRetrace = true,doVirtual = true,doPalette = true;
PRIVATE bool    useLinear = true;
PRIVATE bool    ignoreVBE = false;
PRIVATE	char	optionStr[] = "ip:vanbh";

#include "version.c"

bool doTest(ushort mode,bool widedac,bool doPalette,bool doVirtual,
	bool doRetrace,int maxProgram);

/*----------------------------- Implementation ----------------------------*/

void banner(void)
/****************************************************************************
*
* Function:		banner
*
* Description:	Displays the sign-on banner.
*
****************************************************************************/
{
	printf("SVTest - VESA VBE SuperVGA Library test program (");
	switch (PM_getModeType()) {
		case PM_realMode:
			printf("16 bit real mode)\n");
			break;
		case PM_286:
			printf("16 bit protected mode)\n");
			break;
		case PM_386:
			printf("32 bit protected mode)\n");
			break;
		}
	printf("         Release %s.%s (%s)\n\n",
		release_major,release_minor,release_date);
	printf("%s\n", copyright_str);
	printf("\n");
}

void help(void)
/****************************************************************************
*
* Function:     help
*
* Description:  Provide command line usage information.
*
****************************************************************************/
{
	banner();
	printf("Options are:\n");
#ifdef	USE_UVBELIB
	printf("    -i       - Dont use underlying VBE 2.0 if any is present\n");
#endif
	printf("    -p<num>  - Program 'num' palette values per retrace (default 256)\n");
	printf("    -n       - Dont do virtual screen test\n");
	printf("    -a       - Dont do palette tests\n");
	printf("    -v       - Don't wait for vertical retrace during CRT start programming\n");
	printf("    -b       - Only use banked video modes (linear modes are used by default)\n");
	exit(1);
}

void parseArguments(int argc,char *argv[])
/****************************************************************************
*
* Function:     parseArguments
* Parameters:   argc    - Number of command line arguments
*               argv    - Array of command line arguments
*
* Description:  Parses the command line and forces detection of specific
*               SuperVGA's if specified.
*
****************************************************************************/
{
	int     i,option;
	char    *argument;

    /* Parse command line options */

	i = i;
	do {
		option = getopt(argc,argv,optionStr,&argument);
		switch (option) {
			case 'i':
				ignoreVBE = true;
				break;
			case 'p':
				maxProgram = atoi(argument);
				break;
			case 'b':
				useLinear = false;
				break;
			case 'v':
				doRetrace = false;
				break;
			case 'n':
				doVirtual = false;
				break;
			case 'a':
				doPalette = false;
				break;
			case ALLDONE:
				break;
			case 'h':
			case PARAMETER:
			case INVALID:
			default:
				help();
			}
		} while (option != ALLDONE);
}

int KeyHit(void)
{ return kbhit(); }

int GetChar(void)
{ return getch(); }

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

bool doChoice(int *menu,int maxmenu)
{
	int	choice;

	printf("    [Q] - Quit\n\n");
	printf("Choice: ");
	fflush(stdout);

    choice = getch();
    choice = tolower(choice);
	if (choice == 'q' || choice == 0x1B)
		return true;
	if (choice >= 'a')
		choice = choice - 'a' + 10;
	else choice -= '0';
	if (0 <= choice && choice < maxmenu) {
		if (!doTest(menu[choice],widedac,doPalette,doVirtual,doRetrace,
				maxProgram)) {
			printf("\n");
			printf("ERROR: Video mode did not set correctly!\n\n");
			printf("\nPress any key to continue...\n");
			GetChar();
			}
		}
	return false;
}

int addMode(int num,int *menu,int maxmenu,VBE_modeInfo *mi,int mode)
{
	int	attr = mi->ModeAttributes;

	if ((attr & vbeMdNonBanked) && !useLinear)
		return maxmenu;

	printf("    [%c] - %4d x %4d %d bit (%2d page",num,
		mi->XResolution,mi->YResolution,mi->BitsPerPixel,mi->NumberOfImagePages+1);
	if (useLinear) {
		if (!(attr & vbeMdNonBanked) && (attr & vbeMdLinear))
			printf(", Banked+Linear");
		else if (attr & vbeMdLinear)
			printf(", Linear Only");
		else printf(", Banked Only");
#ifndef	REALMODE
		/* Use the linear framebuffer mode if available */
		if (attr & vbeMdLinear)
			mode |= vbeLinearBuffer;
#endif
		}
	else printf(", Banked Only");
	if (attr & vbeMdNonVGA)
		printf(", NonVGA)\n");
	else printf(")\n");
	menu[maxmenu++] = mode;
	return maxmenu;
}

void test16(ushort *modeList)
{
	int				maxmenu,menu[20];
	char			num;
	ushort			*modes;
	VBE_modeInfo	mi;

	while (true) {
		clearText();
		banner();
		printf("Which video mode to test:\n\n");

		maxmenu = 0;
		for (modes = modeList; *modes != 0xFFFF; modes++) {
			if (!VBE_getModeInfo(*modes,&mi))
				continue;
			if (mi.BitsPerPixel != 4)
				continue;
			if (maxmenu < 10)
				num = '0' + maxmenu;
			else num = 'A' + maxmenu - 10;
			maxmenu = addMode(num,menu,maxmenu,&mi,*modes);
			}
		if (doChoice(menu,maxmenu))
			break;
		}
}

void test256(ushort *modeList)
{
	int				maxmenu,menu[20];
	char			num;
	ushort			*modes;
	VBE_modeInfo	mi;

	while (true) {
		clearText();
		banner();
		printf("Which video mode to test:\n\n");

		maxmenu = 0;
		for (modes = modeList; *modes != 0xFFFF; modes++) {
			if (!VBE_getModeInfo(*modes,&mi))
				continue;
			if (mi.BitsPerPixel != 8 || mi.XResolution == 0)
				continue;
			if (maxmenu < 10)
				num = '0' + maxmenu;
			else num = 'A' + maxmenu - 10;
			maxmenu = addMode(num,menu,maxmenu,&mi,*modes);
			}
		if (doChoice(menu,maxmenu))
			break;
		}
}

void testDirectColor(ushort *modeList,long colors)
{
	int				maxmenu,numbits,menu[20];
	char			num;
	ushort			*modes;
	VBE_modeInfo	mi;

	while (true) {
		clearText();
		banner();
		printf("Which video mode to test:\n\n");

		if (colors == 0x7FFFL)
			numbits = 15;
		else if (colors == 0xFFFFL)
			numbits = 16;
		else if (colors == 0xFFFFFFL)
			numbits = 24;
		else numbits = 32;

		maxmenu = 0;

		for (modes = modeList; *modes != 0xFFFF; modes++) {
			if (!VBE_getModeInfo(*modes,&mi))
				continue;
			if (mi.BitsPerPixel == numbits) {
				if (maxmenu < 10)
					num = '0' + maxmenu;
				else num = 'A' + maxmenu - 10;
				maxmenu = addMode(num,menu,maxmenu,&mi,*modes);
				}
			}
		if (doChoice(menu,maxmenu))
			break;
		}
}

int getValidGraphicsMode(void)
{
	ushort			*modes;
	VBE_modeInfo	mi;

	for (modes = modeList; *modes != 0xFFFF; modes++) {
		if (!VBE_getModeInfo(*modes,&mi))
			continue;
		if (mi.ModeAttributes & vbeMdGraphMode)
			return *modes;
		}
	printf("Could not find valid video mode!!!\n");
	return -1;
}

void testVBEModes(void)
{
	int	choice;

	while (true) {
		clearText();
		banner();

		printf("VBE OEM string: %s\n",OEMString);
		printf("VBE Version:    %d.%d with %d Kb memory\n", VBEVersion >> 8,
			VBEVersion & 0xFF,memory);
        printf("\n");
		printf("Extended CRTC addressing:   %s\n", extCRTC ? "Yes" : "No");
		printf("8 bit wide DAC support:     %s\n", widedac ? "Yes" : "No");
		printf("Linear framebuffer support: ");
		if (linearAddr) {
			printf("Yes (located at %d Mb)\n", (ulong)linearAddr >> 20);
			}
		else printf("No\n");
		printf("\n");
		printf("Select color mode to test:\n\n");
		printf("    [0] - 4 bits per pixel modes\n");
		printf("    [1] - 8 bits per pixel modes\n");
		printf("    [2] - 15 bits per pixel modes\n");
		printf("    [3] - 16 bits per pixel modes\n");
		printf("    [4] - 24 bits per pixel modes\n");
		printf("    [5] - 32 bits per pixel modes\n");
		printf("    [Q] - Quit\n\n");
		printf("Choice: ");
        fflush(stdout);

		choice = getch();
		if (choice == 'q' || choice == 'Q' || choice == 0x1B)
			break;

		switch (choice) {
			case '0':	test16(modeList);						break;
			case '1':	test256(modeList);						break;
			case '2':	testDirectColor(modeList,0x7FFFL);		break;
			case '3':	testDirectColor(modeList,0xFFFFL);		break;
			case '4':	testDirectColor(modeList,0xFFFFFFL);	break;
			case '5':	testDirectColor(modeList,0xFFFFFFFFL);	break;
			}
		}
}

int main(int argc,char *argv[])
{
/*	if (SV_queryCpu() < SV_cpu386) {
		printf("This program contains '386 specific instructions, and will not work on\n");
		printf("this machine - sorry\n");
		}*/

	parseArguments(argc,argv);
#ifdef	USE_UVBELIB
	UV_install("",ignoreVBE,true);
#endif

    if ((VBE_version = SV_init()) < 0x102) {
		printf("This program requires a VESA VBE 1.2 or higher compatible SuperVGA. Try\n");
		printf("installing the Universal VESA VBE for your video card, or contact your\n");
		printf("video card vendor and ask for a suitable TSR\n");
		exit(1);
		}
	widedac = capabilities & vbe8BitDAC;
	SV_setMode(getValidGraphicsMode());
	extCRTC = VBE_setDisplayStart(10,10,false);
	SV_restoreMode();
    if (VBE_version < 0x200)
		useLinear = false;

	testVBEModes();
	printf("\n");
#ifdef	USE_UVBELIB
	UV_exit();
#endif
	return 0;
}
