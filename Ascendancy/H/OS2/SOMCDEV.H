/*
 *    SOMCDEV.H
 *    System Object Model development support for ANSI C
 *
 *    Copyright (c) International Business Machines Corporation
 *                  1991, 1992
 *
 *    @(#)somcdev.h 1.23 1/30/92 16:53:06 [1/30/92] (c)IBM Corp. 1992
 */

#ifndef somcdev_h
#define somcdev_h

/*
 *    Class data used in the C object model
 */

typedef struct {
    somMethodTab *parentMtab;
    integer4 instanceDataOffset;
    somMethodProc *wrappers[1];
} somCClassDataStructure;

/*
 *  Resolution macros
 */

#ifdef SOM_CPP1 /* Some C compilers prefer this form */

  #define SOM_Resolve(obj, cn, mn) \
    (( somTD_ ## cn ## _ ## mn ) \
    somResolve(SOM_TestCls(obj, cn ## ClassData.classObject), \
    cn ## ClassData.mn ))

  #define SOM_ResolveNoCheck(obj, cn, mn) \
    (( somTD_ ## cn ## _ ## mn ) \
    somResolve(obj, cn ## ClassData.mn ))

  #define SOM_ParentResolve(pcn, cn, mn) \
    (( somTD_ ## pcn ## _ ## mn ) \
    somParentResolve( cn ## CClassData.parentMtab, \
    pcn ## ClassData.mn ))

  /* Next form provided for emitter usage */
  #define SOM_ParentResolveE(pcn, cpmt, mn) \
    (( somTD_ ## pcn ## _ ## mn ) \
    somParentResolve( cpmt, \
    pcn ## ClassData.mn ))

#else /* ANSI conforming form */

  #define SOM_Resolve(obj, cn, mn) \
    (( somTD_ ## cn ## _ ## mn ) \
    somResolve(SOM_TestCls(obj, cn ## ClassData.classObject), \
    cn ## ClassData ## . ## mn ))

  #define SOM_ResolveNoCheck(obj, cn, mn) \
    (( somTD_ ## cn ## _ ## mn ) \
    somResolve(obj, cn ## ClassData ## . ## mn ))

  #define SOM_ParentResolve(pcn, cn, mn) \
    (( somTD_ ## pcn ## _ ## mn ) \
    somParentResolve( cn ## CClassData.parentMtab, \
    pcn ## ClassData ## . ## mn ))

  /* Next form provided for emitter usage */
  #define SOM_ParentResolveE(pcn, cpmt, mn) \
    (( somTD_ ## pcn ## _ ## mn ) \
    somParentResolve( cpmt, pcn ## ClassData ## . ## mn ))

#endif  /* _SOM_CPP1 */


#define SOM_DataResolve(obj, dataId) \
  (somDataResolve(obj, dataId))

/*  -------------------------------------------------------------------
 *  The following macros are for purposes of backward compatibility
 *  with prior versions of SOM.  There is no advantage to using them
 *  over a direct call to the corresponding routine.
 */

#define SOM_CompareValidIds(id1,id2) (somCompareIds(id1,id2))

#define SOM_CompareIds(id1,id2) (somCompareIds(id1,id2))

#define SOM_StringFromId(id) (somStringFromId(id))

#define SOM_IdFromString(str) (somIdFromString(str))

#define SOM_CheckId(id) (somCheckId(id))

/*
 * Macro to get class object
 */
#define SOM_GetClass(obj) ((obj->mtab)->classObject)

/*
 *   Development support macros and globals
 */

/* Check the validity of method resolution using the specified target  */
/* object.  Note: this macro makes programs bigger and slower.  After  */
/* you are confident that your program is running correctly you should */
/* turn off this macro by defining SOM_NoTest, or adding -DSOM_NoTest  */
/* to your makefile.                                                   */

#ifndef SOM_NoTest
#define SOM_TestCls(obj, class) (somTestCls(obj, class, __FILE__, __LINE__))
#define SOM_Measure
#else
#define SOM_TestCls(obj, class) (obj)
#endif

/* Control the printing of method and procedure entry messages, */
/* 0-none, 1-user, 2-core&user */
SOMEXTERN int SOM_TraceLevel;

/* Control the printing of warning messages, 0-none, 1-all */
SOMEXTERN int SOM_WarnLevel;

/* Control the printing of successful assertions, 0-none, 1-user, */
/* 2-core&user */
SOMEXTERN int SOM_AssertLevel;

/*
 *  Scans argv looking for flags -somt, -somtc, -soma -somac -somw setting
 *  SOM_TraceLevel, SOM_AssertLevel and SOM_WarnLevel as appropriate.
 *  argv is not modified
 */
#ifdef __IBMC__
  #pragma linkage(somCheckArgs, system)
#endif
SOMEXTERN void SOMLINK somCheckArgs(int argc, zString argv[]);

#define SOM_Error(c) ((*SOMError) (c,__FILE__, __LINE__))

#define SOM_NoTrace(c,m)

#ifdef _RETAIL
  #define SOM_Trace(c,m)
  #define SOM_TraceCore(c,m)
#else
  #define SOM_Trace(c,m) if (SOM_TraceLevel > 0) \
      somPrintf("\"%s\": %d:\tIn %s:%s \n", \
          __FILE__, __LINE__, c, m)

  #define SOM_TraceCore(c,m) if (SOM_TraceLevel > 1) \
      somPrintf("\"%s\": %d:\tIn %s:%s \n", \
          __FILE__, __LINE__, c, m)
#endif

#define SOM_Assert(condition,ecode) \
  (somAssert(condition, ecode, __FILE__, __LINE__, # condition))

#define SOM_AssertCore(condition,ecode) \
  (somAssertCore(condition, ecode, __FILE__, __LINE__, # condition))

#define SOM_Expect(condition) \
      somTest(condition, SOM_Warn, __FILE__, __LINE__, # condition)

#define SOM_WarnMsg(msg) \
  if (SOM_WarnLevel > 0) \
      somPrintf("\"%s\": %d:\tWarning: %s\n", __FILE__, __LINE__, msg)

#define SOM_Test(boolexp) \
    somTest(boolexp, SOM_Fatal, __FILE__, __LINE__, # boolexp)

#define SOM_TestC(boolexp) \
    somTest(boolexp, SOM_Warn, __FILE__, __LINE__, # boolexp)

/*
 *   Default method debug macro, can be overridden
 */
#ifndef SOMMethodDebug
#define SOMMethodDebug(c,m) SOM_Trace(c,m)
#endif

/*--------------------------------------------------------------------
 *  Error severity codes, these are added to the base error number to
 *  produce the full error code
 */

#define SOM_Ok        0x0
#define SOM_Warn      0x1

/* don't do anything */
#define SOM_Ignore    0x2

/* terminate the program */
#define SOM_Fatal     0x9

/* use to identify msg templates */
#define SOM_Template  0x5

#define SOM_FatalCode(code) (SOM_EB + (code)*10 + SOM_Fatal)
#define SOM_WarnCode(code) (SOM_EB + (code)*10 + SOM_Warn)
#define SOM_IgnoreCode(code) (SOM_EB + (code)*10 + SOM_Ignore)
#define SOM_OkCode(code) (SOM_EB + (code)*10 + SOM_Ok)
#define SOM_TemplateCode(code) (SOM_EB + (code)*10 + SOM_Template)


#endif /* somcdev_h */
