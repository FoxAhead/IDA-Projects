/*
 *  wsample.h	WATCOM Execution Sampler include file
 *
 *  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
 */
#ifndef _WSAMPLE_H_INCLUDED
#ifdef __cplusplus
extern "C" {
#endif
#ifdef _MARK_ON
  extern void __mark( char __far * );
  #ifdef __386__
    #pragma aux __mark = 0xcc parm nomemory [dx eax] modify exact nomemory [];
  #else
    #pragma aux __mark = 0xcc parm nomemory [dx ax] modify exact nomemory [];
  #endif
  #define _MARK_( x )	__mark( x )
#else
  #define _MARK_( x )
#endif
#define _WSAMPLE_H_INCLUDED
#ifdef __cplusplus
};
#endif
#endif
