/****************************************************************************
*
*                   Copyright (C) 1993 SciTech Software
*                           All rights reserved.
*
* Filename:     $RCSfile: debug.h $
* Version:      $Revision: 1.3 $
*
* Language:     ANSI C
* Environment:  any
*
* Description:  General header file for portable code.
*
* $Id: debug.h 1.3 1994/08/22 07:57:55 kjb release $
*
****************************************************************************/

#ifndef __DEBUG_H
#define __DEBUG_H

#ifdef  DEBUG
#       define D(x) x
#else
#       define D(x)
#endif

#if     defined(__MSDOS__) || defined(__DOS__) || defined(M_I86)
#ifndef	__MSDOS__
#		define __MSDOS__
#endif
#       define MS(x) x
#       define OS(x)
#       define UX(x)
#       define IR(x)
#       define _8086        /* We know we have an 8086 type processor   */
#if defined(__COMPACT__) || defined(__LARGE__) || defined(__HUGE__)
#       define LDATA
#ifndef NULL
#       define NULL 0L
#endif
#else
#ifndef NULL
#       define NULL 0
#endif
#if defined(DJGPP) || defined(EMX)
#       define near
#       define far
#       define cdecl
#		define _cdecl
#endif
#endif
#elif   defined(__OS2__)        /* Compiling for 32 bit OS/2            */
#       define MS(x)
#       define OS(x) x
#       define UX(x)
#       define IR(x)
#       define _80386       /* We know we have an 80386 type processor  */
#       define MAXFILE  255     /* These are defined in <dir.h>, but    */
#       define MAXDIR   255     /* on OS/2 machines, we just define     */
#       define MAXPATH  255     /* them all to be the same size         */
#       define near             /* Near and far do not exist under      */
#       define far              /* 32 bit OS/2                          */
#ifndef NULL
#       define NULL 0L
#endif
#else                           /* Assume UNIX compilation              */
#       define MS(x)
#       define OS(x)
#       define UX(x) x
#if     defined(__IRIS4D__)     /* Compiling for the SGI Iris 4D        */
#       define IR(x) x
#else
#       define IR(x)
#endif
#       define O_BINARY 0       /* no binary input mode in UNIX open()  */
#       define MAXFILE  255     /* These are defined in <dir.h>, but    */
#       define MAXDIR   255     /* on UNIX machines, we just define     */
#       define MAXPATH  255     /* them all to be the same size         */
#       define far              /* Near and far do not exist under      */
#       define near             /* UNIX or the Iris.                    */
#       define cdecl
#		define _cdecl
#ifndef NULL
#       define NULL ((void *)0)
#endif
#define	PUBAPI					/* UNIX has no _cdecl keywords			*/
#endif

#define PRIVATE static
#define PUBLIC

/* PUBAPI is used to declare calling conventions used for publicly
 * accessible functions. You can override this from the command line to
 * compile with another calling convetion (note that if you change this
 * declaration you will need to re-compile all libraries with the same
 * calling conventions). By default we use the default calling conventions
 * for the compiler being used (Watcom uses register based conventions
 * by default).
 */

#ifndef	PUBAPI
#define PUBAPI                  /* Use default calling conventions      */
#endif

/****************************************************************************
*
*   SEG(p)      Evaluates to the segment portion of an 8086 address.
*   OFF(p)      Evaluates to the offset portion of an 8086 address.
*   FP(s,o)     Creates a far pointer given a segment offset pair.
*   PHYS(p)     Evaluates to a long holding a physical address
*
****************************************************************************/

#ifdef  _8086
#       define SEG(p)   ( (unsigned)(((unsigned long)((void far *)(p))) >> 16))
#       define OFF(p)   ( (unsigned)(p) )
#       define FP(s,o)  ( (void far *)( ((unsigned long)(s) << 16) +  \
						  (unsigned long)(o) ))
#       define PHYS(p)  ( (unsigned long)OFF(p) +                       \
                          ((unsigned long)SEG(p) << 4))
#else
#       define PHYS(p)  (p)
#endif  /* _8086 */

/****************************************************************************
*
*   NUMELE(array)       Evaluates to the array size in elements
*   LASTELE(array)      Evaluates to a pointer to the last element
*   INBOUNDS(array,p)   Evaluates to true if p points into the array
*   RANGE(a,b,c)        Evaluates to true if a <= b <= c
*   MAX(a,b)            Evaluates to a or b, whichever is larger
*   MIN(a,b)            Evaluates to a or b, whichever is smaller
*   ABS(a)              Evaluates to the absolute value of a
*   NBITS(type)         Returns the number of bits in a variable of the
*                       indicated type
*   MAXINT              Evaluates to the value of the largest signed integer
*
****************************************************************************/

#define NUMELE(a)       (sizeof(a)/sizeof(*(a)))
#define LASTELE(a)      ((a) + (NUMELE(a)-1))
#ifdef  LDATA
#define TOOHIGH(a,p)    ((long)PHYS(p) - (long)PHYS(a) > (long)(NUMELE(a)-1))
#define TOOLOW(a,p)     ((long)PHYS(p) - (long)PHYS(a) < 0)
#else
#define TOOHIGH(a,p)    ((long)(p) - (long)(a) > (long)(NUMELE(a)-1))
#define TOOLOW(a,p)     ((long)(p) - (long)(a) < 0)
#endif
#define INBOUNDS(a,p)   ( ! (TOOHIGH(a,p) || TOOLOW(a,p)) )

#define _IS(t,x) (((t)1 << (x)) != 0)   /* Evaluates true if the width of */
                                        /* variable of type t is < x.     */
                                        /* The != 0 assures that the      */
                                        /* answer is 1 or 0               */

#define NBITS(t) (4 * (1 + _IS(t,4) + _IS(t,8) + _IS(t,12) + _IS(t,16) \
                         + _IS(t,20) + _IS(t,24) + _IS(t,28) + _IS(t,32)))

#define MAXINT          (((unsigned)~0) >> 1)

#ifndef MAX
#       define MAX(a,b) ( ((a) > (b)) ? (a) : (b))
#endif
#ifndef MIN
#       define MIN(a,b) ( ((a) < (b)) ? (a) : (b))
#endif
#ifndef ABS
#       define ABS(a)   ((a) >= 0 ? (a) : -(a))
#endif
#ifndef	SIGN
#		define SIGN(a)	((a) > 0 ? 1 : -1)
#endif

#define RANGE(a,b,c)    ( (a) <= (b) && (b) <= (c) )

/* General typedefs */

#ifndef __GENDEFS
#define __GENDEFS
typedef unsigned char   uchar;
typedef unsigned short  ushort;
typedef unsigned int    uint;
typedef unsigned long   ulong;
typedef short			bool;
#endif  /* __GENDEFS */

/* Boolean truth values */

#define false       ((bool)0)
#define true        ((bool)1)
#define FALSE       ((bool)0)
#define TRUE        ((bool)1)
#define NO          ((bool)0)
#define YES         ((bool)1)

#endif  /* __DEBUG_H */
