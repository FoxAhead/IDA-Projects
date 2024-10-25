/*
 *    SOM.H
 *    First level include file for System Object Model
 *
 *    Copyright (c) International Business Machines Corporation
 *                  1991, 1992, 1993
 *
 *    @(#)som.h 1.20 3/17/93 19:48:07 [3/17/93] (c)IBM Corp. 1993
 */

#ifndef som_h
#define som_h

#include <somnames.h>

#ifdef __cplusplus
#define SOMEXTERN extern "C"
#else
#define SOMEXTERN extern
#endif

/*  Define SOMLINK unless it is already defined
 */
#ifndef SOMLINK
  #ifdef __IBMCPP__ 
    #define SOMLINK _System
  #else
    #ifdef _CL386
      #define SOMLINK _syscall
    #else
      #define SOMLINK
    #endif
  #endif
#endif

#ifdef __IBMC__
  #pragma linkage(somAssert                 , system)
  #pragma linkage(somBeginPersistentIds     , system)
  #pragma linkage(somCheckId                , system)
  #pragma linkage(somCompareIds             , system)
  #pragma linkage(somConstructClass         , system)
  #pragma linkage(somDataResolve            , system)
  #pragma linkage(somEndPersistentIds       , system)
  #pragma linkage(somEnvironmentNew         , system)
  #pragma linkage(somGenericApply           , system)
  #pragma linkage(somGetClass               , system)
  #pragma linkage(somIdFromString           , system)
  #pragma linkage(somLPrintf                , system)
  #pragma linkage(somParentResolve          , system)
  #pragma linkage(somPrefixLevel            , system)
  #pragma linkage(somPrintf                 , system)
  #pragma linkage(somRegisterId             , system)
  #pragma linkage(somResolve                , system)
  #pragma linkage(somSetExpectedIds         , system)
  #pragma linkage(somStringFromId           , system)
  #pragma linkage(somTest                   , system)
  #pragma linkage(somTestCls                , system)
  #pragma linkage(somTotalRegIds            , system)
  #pragma linkage(somUniqueKey              , system)
  #pragma linkage(somVprintf                , system)
  #pragma linkage(somTD_classInitRoutine    , system)
  #pragma linkage(somTD_SOMCalloc           , system)
  #pragma linkage(somTD_SOMClassInitFuncName, system)
  #pragma linkage(somTD_SOMDeleteModule     , system)
  #pragma linkage(somTD_SOMError            , system)
  #pragma linkage(somTD_SOMFree             , system)
  #pragma linkage(somTD_SOMLoadModule       , system)
  #pragma linkage(somTD_SOMMalloc           , system)
  #pragma linkage(somTD_SOMOutCharRoutine   , system)
  #pragma linkage(somTD_SOMRealloc          , system)
#endif

#include <stdarg.h>
#include <stddef.h>
#include <somtypes.h>
#include <somerr.h>
#include <somcdev.h>

/*----------------------------------------------------------------------
 *  Typedefs for pointers to functions
 */

typedef void    SOMLINK somTD_classInitRoutine(SOMClass *, SOMClass *);
typedef int     SOMLINK somTD_SOMOutCharRoutine(char);
typedef int     SOMLINK somTD_SOMLoadModule(IN zString /* className */,
                                        IN zString     /* fileName */,
                                        IN zString     /* functionName */,
                                        IN integer4    /* majorVersion */,
                                        IN integer4    /* minorVersion */,
                                        OUT somToken * /* modHandle */);
typedef int     SOMLINK somTD_SOMDeleteModule(IN somToken /* modHandle */);
typedef zString SOMLINK somTD_SOMClassInitFuncName(void);
typedef void *  SOMLINK somTD_SOMMalloc(IN size_t /* nbytes */);
typedef void *  SOMLINK somTD_SOMCalloc(IN size_t /* element_count */,
                                        IN size_t /* element_size */);
typedef void *  SOMLINK somTD_SOMRealloc(IN void * /* memory */,
                                         IN size_t /* nbytes */);
typedef void    SOMLINK somTD_SOMFree(IN void * /* memory */);
typedef void    SOMLINK somTD_SOMError(IN int      /* code */,
                                       IN zString  /* fileName */,
                                       IN int      /* lineNum */);

/*----------------------------------------------------------------------
 *  Misc. procedures:
 */

/*
 *  Create and initialize the SOM environment
 *
 *  Can be called repeatedly
 *
 *  Will be called automatically when first object (including a class
 *  object) is created, if it has not already been done.
 *
 *  Returns the SOMClassMgrObject
 */

SOMEXTERN SOMClassMgr * SOMLINK somEnvironmentNew (void);

/*----------------------------------------------------------------------
 *  String Manager: stem <somsm>
 */
/* makes sure that the id is registered and in normal form, returns */
/* the id */
SOMEXTERN somId SOMLINK somCheckId (somId id);

/* Same as somCheckId except returns 1 (true) if this is the first */
/* time the string associated with this id has been registered, */
/* returns 0 (false) otherwise */
SOMEXTERN int SOMLINK somRegisterId(somId id);

SOMEXTERN somId SOMLINK somIdFromString (zString aString);

SOMEXTERN zString SOMLINK somStringFromId (somId id);

SOMEXTERN int SOMLINK somCompareIds(somId id1, somId id2);

/* Returns the total number of ids that have been registered so far, */
/* you can use this to advise the SOM runtime concerning expected */
/* number of ids in later executions of your program, via a call to */
/* somSetExpectedIds defined below */
SOMEXTERN unsigned long SOMLINK somTotalRegIds(void);

/* Tells the SOM runtime how many unique ids you expect to use during */
/* the execution of your program, this can improve space and time */
/* utilization slightly, this routine must be called before the SOM */
/* environment is created to have any effect */
SOMEXTERN void SOMLINK somSetExpectedIds(unsigned long numIds);

/* Returns the unique key for this id, this key will be the same as the */
/* key in another id if and only if the other id refers to the same */
/* name as this one */
SOMEXTERN unsigned long SOMLINK somUniqueKey(somId id);

/* Tells the id manager that strings for any new ids that are */
/* registered will never be freed or otherwise modified. This allows */
/* the id manager to just use a pointer to the string in the */
/* unregistered id as the master copy of the ids string. Thus saving */
/* space */
/* Under normal use (where ids are static varibles) the string */
/* associated with an id would only be freed if the code module in */
/* which it occured was unloaded */
SOMEXTERN void SOMLINK somBeginPersistentIds(void);

/* Tells the id manager that strings for any new ids that are */
/* registered may be freed or otherwise modified.  Therefore the id */
/* manager must copy the strings inorder to remember the name of an */
/* id. */
SOMEXTERN void SOMLINK somEndPersistentIds(void);

/*----------------------------------------------------------------------
 *  Root object: SOMObject, stem <somob>
 */
#include <somobj.h>

/*----------------------------------------------------------------------
 *  Root meta class: SOMClass, stem <sommc>
 */
#include <somcls.h>

/*----------------------------------------------------------------------
 *  Class Manager: SOMClassMgr, stem <somcm>
 */
#include <somcm.h>

/* Global class manager object */
SOMEXTERN SOMClassMgr *SOMClassMgrObject;

/*----------------------------------------------------------------------
 *  Dispatch meta class: SOMClassDispatch, stem <sommd>
 */

/*---------------------------------------------------------------------
 *  Basic offset based method resolution, this is used in every method
 *  class that uses offset resolution
 *  It returns the appropriate method procedure for the method
 *  identified by <mdata>, Mdata id the 32 bit value stored in the
 *  class data structure in the entry with the methods name. I.e., if
 *  a object, obj, of class, Foo, has a method, bar, then:
 *      somResolve(obj, FooClassData.bar)
 *  will return the appropriate method procedure for bar.
 *  The way that <mdata> identifies a method and the algorithm used by
 *  somResolve to locate the appropriate method procedure is not part
 *  of the visible SOM architecture and is subject to change in
 *  subsequent releases.
 */
SOMEXTERN somMethodProc * SOMLINK somResolve(SOMAny *obj, somMToken mdata);
SOMEXTERN somMethodProc * SOMLINK somParentResolve(somMethodTab *parentMtab,
                                         somMToken mdata);
SOMEXTERN void * SOMLINK somDataResolve(SOMAny *obj, somDToken dataId);

/*---------------------------------------------------------------------
 *  Used to make class object creation an atomic operation, this is
 *  called by the generated <class name>NewClass routine.  You should
 *  never call this routine directly.
 */
SOMEXTERN void SOMLINK somConstructClass (
                    somTD_classInitRoutine *classInitRoutine,
                    SOMClass *parentClass,
                    SOMClass *metaClass,
                    somClassDataStructure *cds);

/*---------------------------------------------------------------------
 *  Generic apply function
 */
SOMEXTERN void SOMLINK somGenericApply (SOMAny *obj,
           somId methodID,
           somId methodDescriptor,
           va_list ap);

/*
 * Convenience function to obtain the class object for a given object
 */
#ifndef SOMObject_Class_Source
SOMEXTERN SOMClass * SOMLINK somGetClass (SOMAny *self);
#endif

/*
 * Uses <SOMOutCharRoutine> to output its arguments under control of the ANSI C
 * style format.  Returns the number of characters output.
 */
SOMEXTERN int SOMLINK somPrintf (zString fmt, ...);
/*
 * vprint form of somPrintf
 */
SOMEXTERN int SOMLINK somVprintf (zString fmt, va_list ap);
/*
 * Outputs (via somPrintf) blanks to prefix a line at the indicated level
 */
SOMEXTERN void SOMLINK somPrefixLevel (int level);
/*
 * Combines somPrefixLevel and somPrintf
 */
SOMEXTERN int SOMLINK somLPrintf (int level, zString fmt, ...);

/*
 *  Replaceable character output handler.
 *  Points to the character output routine to be used in development
 *  support.  Initialized to <somOutChar>, but may be reset at anytime.
 *  Should return 0 (false) if an error occurs and 1 (true) otherwise.
 */

SOMEXTERN somTD_SOMOutCharRoutine *SOMOutCharRoutine;

/*----------------------------------------------------------------------
 * Pointers to routines used to do dynamic code loading and deleting
 */

SOMEXTERN somTD_SOMLoadModule     *SOMLoadModule;
SOMEXTERN somTD_SOMDeleteModule   *SOMDeleteModule;
SOMEXTERN somTD_SOMClassInitFuncName *SOMClassInitFuncName;

/*----------------------------------------------------------------------
 *  Replaceable SOM Memory Management Interface
 *
 *  External procedure variables SOMCalloc, SOMFree, SOMMalloc, SOMRealloc
 *  have the same interface as their standard C-library analogs.
 */

SOMEXTERN somTD_SOMCalloc       *SOMCalloc;
SOMEXTERN somTD_SOMFree *SOMFree;
SOMEXTERN somTD_SOMMalloc       *SOMMalloc;
SOMEXTERN somTD_SOMRealloc *SOMRealloc;

/*----------------------------------------------------------------------
 *  Replaceable SOM Error handler
 */

SOMEXTERN somTD_SOMError *SOMError;

/*----------------------------------------------------------------------
 * Externals used in the implementation of SOM, but not part of the
 * SOM API.
 */

SOMEXTERN SOMAny * SOMLINK somTestCls(SOMAny *obj, SOMClass *classObj,
                                   zString fileName, int lineNumber);
SOMEXTERN void SOMLINK somTest(int condition, int severity, zString fileName,
                            int lineNum, zString msg);
SOMEXTERN void SOMLINK somAssert(int condition, int ecode,
                                 zString fileName, int lineNum, zString msg);

#endif
