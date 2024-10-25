/*
 *    SOMBTYPES.H
 *    System Object Model Base Data Types
 *
 *    Copyright (c) International Business Machines Corporation
 *                  1991, 1992
 *
 *    @(#)sombtypes.h 1.1 5/13/92 12:55:17 [5/14/92] (c)IBM Corp. 1992
 */

#ifndef sombtypes_h
#define sombtypes_h

/*--------------------------------------------------------------
 * Base data types
 */

#include <stdarg.h>

#ifndef NULL
   #ifdef __cplusplus
      #define NULL 0
   #else
     #define NULL ((void *)0)
   #endif
#endif

typedef char integer1;
typedef short integer2;
typedef unsigned short uinteger2;
typedef long integer4;
typedef unsigned long uinteger4;
typedef float float4;
typedef double float8;
typedef char *zString;                 /* NULL terminated string */
typedef char *fString;                 /* non-terminated string  */
typedef char **somId;
typedef void *somToken;                /* Uninterpretted value   */
typedef void *somMToken;               /* Method token           */
typedef void *somDToken;               /* Data token             */


#define SOM_DynamicMethod  1
#define SOM_StaticMethod   0

/*
 *    Comment macros for arguments
 */
#define IN
#define OUT
#define INOUT


#endif /* sombtypes_h */
