/*****************************************************************************\
*                                                                             *
* scrnsave.h    Windows NT 3.1 screensaver defines and definitions.           *
*                                                                             *
*               Version 1.0                                                   *
*                                                                             *
*               NOTE: windows.h must be #included first                       *
*                                                                             *
*  Windows NT NOTE:   (Differences from Win 3.1 Screensavers)                 *
*                                                                             *
*               All Screensavers are required to have a Description string    *
*               of no more than 25 chars for display by the Control Panel's   *
*               Desktop applet.  This is string 1 in the resource string      *
*               table of the Windows 32-bit screen saver .SCR (.EXE) file.    *
*                                                                             *
*               Passwords for Windows NT Screen Savers are handled by the     *
*               Winlogon process.  If the registry value:                     *
*                                                                             *
*               HKEY_CURRENT_USER\Control Panel\Desktop\ScreenSaverIsSecure   *
*                                                                             *
*               is nonzero, Winlogon will ask for the User's login password   *
*               before allowing the Screen Saver to exit.  All password data  *
*               and dialogs have been removed from individual Screensavers.   *
*                                                                             *
*                                                                             *
*               Copyright (c) 1992, Microsoft Corp.  All rights reserved.     *
*                                                                             *
\*****************************************************************************/

#ifndef _INC_SCRNSAVE
#define _INC_SCRNSAVE

#ifndef RC_INVOKED
#pragma pack(1)         /* Assume byte packing throughout */
#endif /* !RC_INVOKED */

#ifdef __cplusplus
extern "C" {            /* Assume C declarations for C++ */
#endif	/* __cplusplus */


/* MANDATORY string required in .RC file 
 * This string should contain a less than 25 char name/description of the
 * screen saver.  This string is what will be seen by the user in the Control
 * Panel's Desktop applet screen saver listbox.
 */

#define IDS_DESCRIPTION      1

/* Icon resource ID.
 *
 * This should be the first icon used and must have this resource number.
 * This is needed as the first icon in the file will be grabbed
 */
#define ID_APP      100
#define DLG_SCRNSAVECONFIGURE   2003

#define idsIsPassword           1000
#define idsIniFile              1001
#define idsScreenSaver          1002
#define idsPassword             1003
#define idsDifferentPW          1004
#define idsChangePW             1005
#define idsBadOldPW             1006
#define idsAppName              1007
#define idsNoHelpMemory         1008
#define idsHelpFile             1009

/* This function is the Window Procedure for the screen saver.  It is
 * up to the programmer to handle any of the messages that wish to be
 * interpretted.  Any unused messages are then passed back to
 * DefScreenSaverProc if desired which will take default action on any
 * unprocessed message...
 */
LRESULT WINAPI ScreenSaverProc (HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

/* This function performs default message processing.  Currently handles
 * the following messages:
 *
 * WM_SYSCOMMAND:   return FALSE if wParam is SC_SCREENSAVE or SC_CLOSE
 *
 * WM_DESTROY:      PostQuitMessage(0)
 *
 * WM_SETCURSOR:    By default, this will set the cursor to a null cursor,
 *                  thereby removing it from the screen.
 *
 * WM_LBUTTONDOWN:
 * WM_MBUTTONDOWN:
 * WM_RBUTTONDOWN:
 * WM_KEYDOWN:
 * WM_KEYUP:
 * WM_MOUSEMOVE:    By default, these will cause the program to terminate.
 *                  Unless the password option is enabled.  In that case
 *                  the DlgGetPassword() dialog box is brought up.
 *
 * WM_NCACTIVATE:
 * WM_ACTIVATEAPP:
 * WM_ACTIVATE:     By default, if the wParam parameter is FALSE (signifying
 *                  that transfer is being taken away from the application),
 *                  then the program will terminate.  Termination is
 *                  accomplished by generating a WM_CLOSE message.  This way,
 *                  if the user sets something up in the WM_CREATE, a
 *                  WM_DESTROY will be generated and it can be destroyed
 *                  properly.
 *                  This message is ignored, however is the password option
 *                  is enabled.
 */
LRESULT WINAPI DefScreenSaverProc (HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

/* A function is also needed for configuring the screen saver.  The function
 * should be exactly like it is below and must be exported such that the
 * program can use MAKEPROCINSTANCE on it and call up a dialog box. Further-
 * more, the template used for the dialog must be called
 * ScreenSaverConfigure to allow the main function to access it...
 */
BOOL WINAPI ScreenSaverConfigureDialog (HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

/* To allow the programmer the ability to register child control windows, this
 * function is called prior to the creation of the dialog box.  Any
 * registering that is required should be done here, or return TRUE if none
 * is needed...
 */
BOOL WINAPI RegisterDialogClasses (HANDLE hInst);

/* The following functions are called by DefScreenSaverProc and must
 * be exported by all screensavers using this model.
 */

/*
 * There are only three other points that should be of notice:
 * 1) The screen saver must have a string declared as 'szAppName' contaning the
 *     name of the screen saver, and it must be declared as a global.
 * 2) The screen saver EXE file should be renamed to a file with a SCR
 *     extension so that the screen saver dialog from the control panel can
 *     find it when is searches for screen savers.
 */
#define WS_GT   (WS_GROUP | WS_TABSTOP)

#define MAXFILELEN         13
#define TITLEBARNAMELEN    40
#define APPNAMEBUFFERLEN   40
#define BUFFLEN           255

/* The following globals are defined in scrnsave.lib */
extern HANDLE hMainInstance;
extern HWND   hMainWindow;
extern TCHAR  szName[TITLEBARNAMELEN];
extern TCHAR  szAppName[APPNAMEBUFFERLEN];
extern TCHAR  szIniFile[MAXFILELEN];
extern TCHAR  szScreenSaver[22];
extern TCHAR  szHelpFile[MAXFILELEN];
extern TCHAR  szNoHelpMemory[BUFFLEN];
extern UINT   MyHelpMessage;

#ifdef __cplusplus
}
#endif	/* __cplusplus */

#ifndef RC_INVOKED
#pragma pack()
#endif  /* !RC_INVOKED */

#endif  /* !_INC_SCRNSAVE */
