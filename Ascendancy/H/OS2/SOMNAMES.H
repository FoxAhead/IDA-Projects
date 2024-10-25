/*
 *    SOMNAMES.H
 *    System Object Model run-time external names
 *
 *    Copyright (c) International Business Machines Corporation
 *		    1991, 1992
 *
 *    @(#)somnames.h 1.18 1/30/92 16:53:31 [1/30/92] (c)IBM Corp. 1992
 */

#ifndef extnames_h
#define extnames_h

#ifdef SOM_USE_SHORT_EXTERNAL_NAMES

#define SOM_AssertLevel     somasl
#define SOM_TraceLevel	    somtrl
#define SOM_WarnLevel	    somwnl

#define SOMCalloc	    somcll
#define SOMClassMgrObject   somcmo
#define SOMDeleteModule     somdm
#define SOMError	    somerr
#define SOMFree 	    somfre
#define SOMOutCharRoutine   somout
#define SOMLoadModule	    somlm
#define SOMMalloc	    sommll
#define SOMRealloc	    somrll

#define somAssert	    somass
#define somBeginPersistentIds sombis
#define somCheckArgs	    somcka
#define somCheckId	    somcki
#define somCompareIds	    someqi
#define somConstructClass   somccl
#define somDataResolve	    somdrs
#define somEndPersistentIds someis
#define somEnvironmentNew   somen
#define somGenericApply     somga
#define somGetClass	    somgcl
#define somIdFromString     somifs
#define somLPrintf	    somlpn
#define somParentResolve    somprs
#define somPrefixLevel	    somplv
#define somPrintf	    sompnt
#define somRegisterId	    somrgi
#define somResolve	    somres
#define somSetExpectedIds   somsei
#define somStringFromId     somsfi
#define somTest 	    somtst
#define somTestCls	    somtcl
#define somTotalRegIds	    somtri
#define somUniqueKey	    somuky
#define somVprintf	    somvpt

#ifdef __IBMC__
  #pragma linkage(somass, system)
  #pragma linkage(sombis, system)
  #pragma linkage(somcka, system)
  #pragma linkage(somcki, system)
  #pragma linkage(someqi, system)
  #pragma linkage(somccl, system)
  #pragma linkage(someis, system)
  #pragma linkage(somen , system)
  #pragma linkage(somga , system)
  #pragma linkage(somgcl, system)
  #pragma linkage(somifs, system)
  #pragma linkage(somlpn, system)
  #pragma linkage(somprs, system)
  #pragma linkage(somplv, system)
  #pragma linkage(sompnt, system)
  #pragma linkage(somres, system)
  #pragma linkage(somrgi, system)
  #pragma linkage(somsei, system)
  #pragma linkage(somsfi, system)
  #pragma linkage(somtst, system)
  #pragma linkage(somtcl, system)
  #pragma linkage(somtri, system)
  #pragma linkage(somuky, system)
  #pragma linkage(somvpt, system)
#endif /* __IBMC__ */

#endif /* SOM_USE_SHORT_EXTERNAL_NAMES */

#endif /* extnames_h */
