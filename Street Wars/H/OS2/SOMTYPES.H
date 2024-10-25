/*
 *    SOMTYPES.H
 *    System Object Model typedefs
 *
 *    Copyright (c) International Business Machines Corporation
 *                  1991, 1992
 *
 *    @(#)somtypes.h 1.20 2/13/92 23:56:53 [2/20/92] (c)IBM Corp. 1992
 */

#ifndef somtypes_h
#define somtypes_h

#include <stdarg.h>

/*--------------------------------------------------------------
 * Base data types
 */

#ifndef NULL
#define NULL ((void *) 0)
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

typedef integer4 somMOffset;
typedef integer4 somDOffset;
typedef integer4 somMData;

/*
 *   Instances
 */

typedef struct SOMAny_struct {
    struct somMethodTabStruct *mtab;
    integer1 body[1];
} SOMAny;

/*  Define the three startup classes to avoid bootstrap problems */
#define SOMObject SOMAny
#define SOMClass SOMAny
#define SOMClassMgr SOMAny

#ifdef __IBMC__
  #pragma linkage( somMethodProc, system )
#endif
typedef integer4 SOMLINK somMethodProc(void);

/*
 *   Method Table
 */

typedef struct somMethodTabStruct {
    SOMClass *classObject;
    somMethodProc *entries[1];
} somMethodTab;

/*
 *   Class data structure
 */

typedef struct {
    SOMClass *classObject;
} somClassDataStructure;

/*
 *   Trait object structure
 */
typedef struct {
    somMethodTab *mtab;
    SOMAny *target;
    SOMAny *realSelf;
} SOMTraitAny;

/*
 *   Method descriptor record
 */

typedef struct somMethodDataStruct {
    somId id;
    uinteger4 type;                    /* 0=static, 1=dynamic */
    somId descriptor;
    somMToken offset;                  /* not valid for dynamic methods */
    somMethodProc *method;
    somMethodProc *redispatchStub;
    somMethodProc *applyStub;
} somMethodData;

/*
 * Typedef for Static Method table that we generate in the .ih file.
 */

typedef struct somStaticMethodStruct {
    somMToken *classData;
    somId *methodId;
    somId *methodDescriptor;
    somMethodProc *method;
    somMethodProc *redispatchStub;
    somMethodProc *applyStub;
} somStaticMethod_t;

/*
 * Typedef for Override Method table that we generate in the .ih file.
 */

typedef struct somOverideMethodStruct {
    somId *methodId;
    somMethodProc *method;
} somOverrideMethod_t;

#define SOM_DynamicMethod  1
#define SOM_StaticMethod   0

/*
 *    Comment macros for arguments
 */
#define IN
#define OUT
#define INOUT

/*
 *    Old style name support
 */

typedef somMethodProc *somMethodPtr;

/* The following synonyms provide OS/2-style typedefs */

#ifndef FLOAT4
#define FLOAT4                  float4
#endif

#ifndef FLOAT8
#define FLOAT8                  double
#endif

#ifndef SOMID
#define SOMID                   somId
#endif

#ifndef SOMTOKEN
#define SOMTOKEN                somToken
#endif

#ifndef SOMANY
#define SOMANY                  SOMAny
#endif

#ifndef SOMCLASS
#define SOMCLASS                SOMClass
#endif

#ifndef SOMOBJECT
#define SOMOBJECT               SOMObject
#endif

#ifndef SOMMETHODTAB
#define SOMMETHODTAB            somMethodTab
#endif

#ifndef SOMMETHODDATA
#define SOMMETHODDATA           somMethodData
#endif

#ifndef SOMMETHODPTR
#define SOMMETHODPTR            somMethodPtr
#endif

#ifndef SOMTRAITANY
#define SOMTRAITANY             SOMTraitAny
#endif

#ifndef SOMCLASSDATASTRUCT
#define SOMCLASSDATASTRUCT      somClassDataStructure
#endif

#endif  /* somtypes_h */
