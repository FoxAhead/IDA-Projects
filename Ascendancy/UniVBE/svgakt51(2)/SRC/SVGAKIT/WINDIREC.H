/****************************************************************************
*
*				   WinDirect - Windows full screen interface
*
*                   Copyright (C) 1994-95 SciTech Software.
*							All rights reserved.
*
* Filename:		$RCSfile: windirec.h $
* Version:		$Revision: 1.1 $
*
* Language:		ANSI C
* Environment:	IBM PC (MS DOS)
*
* Description:	Header file for enabling and disabling the Windows 3.1 and
*				Windows '95 full screen video mode.
*
* $Id: windirec.h 1.1 1995/02/06 16:30:45 kjb release $
*
****************************************************************************/

#ifndef	__WINDIRECT_H
#define	__WINDIRECT_H

#ifndef	__WINDOWS_H
#include <windows.h>
#endif

/*------------------------- Function Prototypes ---------------------------*/

#ifdef	__cplusplus
extern "C" {			/* Use "C" linkage when in C++ mode	*/
#endif

HWND	WIN_startFullScreen(BOOL lockTask);
void	WIN_restoreGDI(void);

#ifdef	__cplusplus
}						/* End of "C" linkage for C++	*/
#endif

#endif	/* __WINDIRECT_H */

