/*
 *  stdarg.h	Variable argument macros
 *		definitions for use with variable argument lists
 *
 *  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
 */
#ifndef _STDARG_H_INCLUDED
#ifdef __cplusplus
extern "C" {
#endif

#if defined(__HUGE__) || defined(__SW_ZU)
typedef char __far *va_list[1];

#define va_start(ap,pn) ((ap)[0]=(char __far *)&pn+\
    ((sizeof(pn)+sizeof(int)-1)&~(sizeof(int)-1)),(void)0)
#define va_arg(ap,type)     ((ap)[0]+=\
    ((sizeof(type)+sizeof(int)-1)&~(sizeof(int)-1)),\
    (*(type __far *)((ap)[0]-((sizeof(type)+sizeof(int)-1)&~(sizeof(int)-1)))))
#define va_end(ap)	    ((ap)[0]=0,(void)0)
#else
typedef char *va_list[1];

#define va_start(ap,pn) ((ap)[0]=(char *)&pn+\
    ((sizeof(pn)+sizeof(int)-1)&~(sizeof(int)-1)),(void)0)
#define va_arg(ap,type)     ((ap)[0]+=\
    ((sizeof(type)+sizeof(int)-1)&~(sizeof(int)-1)),\
    (*(type *)((ap)[0]-((sizeof(type)+sizeof(int)-1)&~(sizeof(int)-1)))))
#define va_end(ap)	    ((ap)[0]=0,(void)0)
#endif

#define _STDARG_H_INCLUDED
#ifdef __cplusplus
};
#endif
#endif
