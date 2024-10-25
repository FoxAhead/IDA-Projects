//
//  new.h -- C++ default storage allocators
//
//  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
//
#ifndef _NEW_H_INCLUDED

#ifndef __cplusplus
#error new.h is for use with C++
#else

#include <stddef.h>

#ifndef _PFV_DEFINED_
#define _PFV_DEFINED_
 typedef void (*PFV)( void );
#endif
#ifndef _PFU_DEFINED_
#define _PFU_DEFINED_
 typedef int (*PFU)( unsigned );
#endif
#ifndef _PNH_DEFINED_
#define _PNH_DEFINED_
 typedef int (*_PNH)( unsigned );
#endif

void *operator new( size_t );
void *operator new( size_t, void * );
void *operator new []( size_t );
void *operator new []( size_t, void * );
void operator delete( void * );
void operator delete []( void * );
PFV set_new_handler( PFV );
PFU _set_new_handler( PFU );

#endif
#define _NEW_H_INCLUDED
#endif
