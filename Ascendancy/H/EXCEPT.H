//
//  except.h -- C++ default exception handlers
//
//  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
//
#ifndef _EXCEPT_H_INCLUDED

#ifndef __cplusplus
#error except.h is for use with C++
#else

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

#ifndef _WATCOM_EXCEPTION_DEFINED_
#define _WATCOM_EXCEPTION_DEFINED_
 class __WATCOM_exception {
 };
#endif

void terminate( void );
PFV set_terminate( PFV );
void unexpected( void );
PFV set_unexpected( PFV );

#endif
#define _EXCEPT_H_INCLUDED
#endif
