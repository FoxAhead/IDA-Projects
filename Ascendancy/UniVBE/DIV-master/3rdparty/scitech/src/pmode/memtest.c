/****************************************************************************
*
*						  Protected Mode Library
*
*                   Copyright (C) 1996 SciTech Software.
*							All rights reserved.
*
* Filename:		$Workfile:   memtest.c  $
* Version:		$Revision:   1.1  $
*
* Language:		ANSI C
* Environment:	any
*
* Description:	Test program to determine just how much memory can be
*				allocated with the compiler in use. Compile and link
*				with the appropriate command line for your DOS extender.
*
*				Functions tested:	malloc()
*									PM_availableMemory()
*
* $Date:   10 Feb 1996 14:49:08  $ $Author:   KendallB  $
*
****************************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <conio.h>
#include <math.h>
#include "pmode.h"

#ifdef	__16BIT__
#define	MAXALLOC	64
#else
#define	MAXALLOC	5000
#endif

int main(void)
{
	int		i;
	ulong	allocs;
	ulong	physical,total;
	char	*p,*pa[MAXALLOC];

    printf("Program running in ");
	switch (PM_getModeType()) {
		case PM_realMode:
			printf("real mode.\n\n");
			break;
		case PM_286:
			printf("16 bit protected mode.\n\n");
			break;
		case PM_386:
			printf("32 bit protected mode.\n\n");
			break;
		}

	printf("Memory available at start:\n");
	PM_availableMemory(&physical,&total);
	printf("   Physical memory:           %ld Kb\n", physical / 1024);
	printf("   Total (including virtual): %ld Kb\n", total / 1024);
	printf("\n");
	for (allocs = i = 0; i < MAXALLOC; i++) {
		if ((pa[i] = malloc(10*1024)) != 0) {	/* in 10k blocks 	*/
			p = pa[allocs];
			memset(p, 0, 10*1024); /* touch every byte 				*/
			*p = 'x';           /* do something, anything with		*/
			p[1023] = 'y';      /* the allocated memory      		*/
			allocs++;
			printf("Allocated %lu bytes\r", 10*(allocs << 10));
			}
		else break;
		if (kbhit() && (getch() == 0x1B))
			break;
		}

	printf("\n\nAllocated total of %lu bytes\n", 10 * (allocs << 10));

	printf("\nMemory available at end:\n");
	PM_availableMemory(&physical,&total);
	printf("   Physical memory:           %ld Kb\n", physical / 1024);
	printf("   Total (including virtual): %ld Kb\n", total / 1024);

	for (i = allocs-1; i >= 0; i--)
		free(pa[i]);

    printf("\nMemory available after freeing all blocks (note that under protected mode\n");
    printf("this will most likely not be correct after freeing blocks):\n\n");
	PM_availableMemory(&physical,&total);
	printf("   Physical memory:           %ld Kb\n", physical / 1024);
	printf("   Total (including virtual): %ld Kb\n", total / 1024);

	return 0;
}
