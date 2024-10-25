/*
 *  assert.h
 *
 *  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
 */
#ifdef __cplusplus
extern "C" {
#endif
#undef assert

#ifdef NDEBUG
 #define assert(__ignore) ((void)0)
#else
 extern void __assert( int, char *, char *, int );
#if !defined(NO_EXT_KEYS) /* extensions enabled */
 #define assert(expr)   ((expr)?(void)0:__assert(0,#expr,__FILE__,__LINE__))
#else
 #define assert(expr)	__assert(expr,#expr,__FILE__,__LINE__)
#endif
#endif
#ifdef __cplusplus
};
#endif
