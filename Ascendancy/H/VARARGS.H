/*
 *  varargs.h	Variable argument macros (UNIX System V definition)
 *		definitions for use with variable argument lists
 *
 *  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
 */
#ifndef _VARARGS_H_INCLUDED
#ifdef __cplusplus
extern "C" {
#endif

#ifndef _STDARG_H_INCLUDED
 #include <stdarg.h>
#else
 #error stdarg.h has already been included
#endif

#define va_alist	void *__alist, ...
#define va_dcl

#undef va_start
#if defined(__HUGE__) || defined(__SW_ZU)
#define va_start(ap)	((ap)[0]=(void __far *)&__alist,(void)0)
#else
#define va_start(ap)	((ap)[0]=(void *)&__alist,(void)0)
#endif

#define _VARARGS_H_INCLUDED
#ifdef __cplusplus
};
#endif
#endif
