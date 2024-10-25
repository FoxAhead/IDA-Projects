/*
 *  mem.h	Memory manipulation functions
 *
 *  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
 */
#ifndef _PTRDIFF_T_DEFINED_
#define _PTRDIFF_T_DEFINED_
 #if defined(__HUGE__)
  typedef long	ptrdiff_t;
 #else
  typedef int	ptrdiff_t;
 #endif
#endif

#include <string.h>
