/*
 *  wdefwin.h	default windowing calls
 *
 *  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
 */
#ifndef _WDEFWIN_H_INCLUDED
#ifdef __cplusplus
extern "C" {
#endif

#ifndef __SW_BW
  #error wdefwin.h is for use the default windowing system, use the /bw switch
#endif

#if ( defined(__OS2__) && defined(__386__) ) || defined(__NT__) || \
    defined(__WINDOWS_386__) || defined(__WINDOWS__)
extern int _dwDeleteOnClose( int handle );
extern int _dwSetAboutDlg( const char *title, const char *text );
extern int _dwSetAppTitle( const char *title );
extern int _dwSetConTitle( int handle, const char *title );
extern int _dwYield( void );
extern int _dwShutDown( void );
#else
  #error You cannot use the default windowing system in a non GUI environment
  #error Make sure you use the /bt= switch to select the target system
#endif  

#define _WDEFWIN_H_INCLUDED
#ifdef __cplusplus
};
#endif
#endif
