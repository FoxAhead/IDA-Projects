/****************************************************************************
*
*				   WinDirect - Windows full screen interface
*
*                   Copyright (C) 1994-95 SciTech Software.
*							All rights reserved.
*
* Filename:		$RCSfile: windirec.c $
* Version:		$Revision: 1.1 $
*
* Language:		ANSI C
* Environment:	IBM PC (MS DOS)
*
* Description:	Functions for enabling and disabling the Windows 3.1 and
*				Windows '95 full screen video mode.
*
* $Id: windirec.c 1.1 1995/02/06 16:26:07 kjb release $
*
****************************************************************************/

#include "windirec.h"

/*---------------------------- Implementation -----------------------------*/

// DisplayDib() error return codes
#define DISPLAYDIB_NOERROR          0x0000  // success
#define DISPLAYDIB_NOTSUPPORTED     0x0001  // function not supported
#define DISPLAYDIB_INVALIDDIB       0x0002  // null or invalid DIB header
#define DISPLAYDIB_INVALIDFORMAT    0x0003  // invalid DIB format
#define DISPLAYDIB_INVALIDTASK      0x0004  // not called from current task

// flags for <wFlags> parameter of DisplayDib()
#define DISPLAYDIB_NOPALETTE        0x0010  // don't set palette
#define DISPLAYDIB_NOCENTER         0x0020  // don't center image
#define DISPLAYDIB_NOWAIT           0x0040  // don't wait before returning
#define DISPLAYDIB_NOIMAGE          0x0080  // don't draw image
#define DISPLAYDIB_ZOOM2            0x0100  // stretch by 2
#define DISPLAYDIB_DONTLOCKTASK     0x0200  // don't lock current task
#define DISPLAYDIB_TEST             0x0400  // testing the command
#define DISPLAYDIB_NOFLIP           0x0800  // dont page flip
#define DISPLAYDIB_BEGIN            0x8000  // start of multiple calls
#define DISPLAYDIB_END              0x4000  // end of multiple calls

#define DISPLAYDIB_MODE             0x000F  // mask for display mode
#define DISPLAYDIB_MODE_DEFAULT     0x0000  // default display mode
#define DISPLAYDIB_MODE_320x200x8   0x0001  // 320-by-200
#define DISPLAYDIB_MODE_320x240x8   0x0005  // 320-by-240

// function prototypes
UINT FAR PASCAL DisplayDib(LPBITMAPINFOHEADER lpbi, LPSTR lpBits, WORD wFlags);
UINT FAR PASCAL DisplayDibEx(LPBITMAPINFOHEADER lpbi, int x, int y, LPSTR lpBits, WORD wFlags);

HWND WIN_startFullScreen(BOOL lockTask)
/****************************************************************************
*
* Function:		WIN_startFullScreen
* Parameters:   lockTask    - True if task should be locked
* Returns:		Handle to window to use for event handling
*
* Description:  Attempts to put the systen into full screen VGA mode, thereby
*				shutting down the GDI and giving the appliction full control
*				of the hardwared.
*
*				This routine also obtains a handle to the currently focused
*				window in the application, and captures all events into this
*				window for the duration of the full screen mode. This window
*				handle should be used for all subsequent event manipulation
*				by the program until WIN_restoreGDI() is called (ie: all
*				calls to GetMessage() etc should pass this HWND as the first
*				parameter).
*
****************************************************************************/
{
	HWND	hwnd = GetFocus();
	WORD 	flags = DISPLAYDIB_MODE_320x200x8 | DISPLAYDIB_BEGIN | DISPLAYDIB_NOWAIT;

	if (!lockTask)
		flags |= DISPLAYDIB_DONTLOCKTASK;
	DisplayDib(NULL, NULL, flags);
	SetCapture(hwnd);
    return hwnd;
}

void WIN_restoreGDI(void)
/****************************************************************************
*
* Function:		WIN_restoreGDI
*
* Description:  Restore the GDI back to normal operation after full screen
*				graphics have been completed.
*
****************************************************************************/
{
	DisplayDib(NULL, NULL, DISPLAYDIB_END | DISPLAYDIB_DONTLOCKTASK
		| DISPLAYDIB_NOWAIT);
	ReleaseCapture();
}
 
