/*
 *  setjmp.h
 *
 *  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
 */
#ifndef _SETJMP_H_INCLUDED
#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned int jmp_buf[13];

extern int  _setjmp( jmp_buf __env );
#define setjmp(__env)	  _setjmp(__env)
#if defined(__386__)
 #pragma aux _setjmp parm caller [eax] modify [8087];
#else
 #pragma aux _setjmp modify [8087];
#endif

extern void longjmp( jmp_buf __env, int __val );

#pragma aux	longjmp aborts;

#define _SETJMP_H_INCLUDED
#ifdef __cplusplus
};
#endif
#endif
