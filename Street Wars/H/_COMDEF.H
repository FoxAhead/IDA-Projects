//
//  _comdef.h	Common Macro Definitions
//
//  Copyright by WATCOM International Corp. 1988-1996.  All rights reserved.
//
#ifndef _COMDEF_H_INCLUDED
#define _COMDEF_H_INCLUDED
#if !defined(_ENABLE_AUTODEPEND)
  #pragma read_only_file;
#endif
  #ifdef _WCDATA
    #error The macro _WCDATA is reserved for use by the runtime library.
  #endif
  #ifdef _WCNEAR
    #error The macro _WCNEAR is reserved for use by the runtime library.
  #endif
  #ifdef _WCFAR
    #error The macro _WCFAR is reserved for use by the runtime library.
  #endif
  #ifdef _WCHUGE
    #error The macro _WCHUGE is reserved for use by the runtime library.
  #endif
  #ifdef _WCI86NEAR
    #error The macro _WCI86NEAR is reserved for use by the runtime library.
  #endif
  #ifdef _WCI86FAR
    #error The macro _WCI86FAR is reserved for use by the runtime library.
  #endif
  #ifdef _WCI86HUGE
    #error The macro _WCI86HUGE is reserved for use by the runtime library.
  #endif
  #ifdef _WCINTERRUPT
    #error The macro _WCINTERRUPT is reserved for use by the runtime library.
  #endif
  #ifdef _WCUNALIGNED
    #error The macro _WCUNALIGNED is reserved for use by the runtime library.
  #endif
  #if defined(_M_IX86)
    #define _WCNEAR __near
    #define _WCFAR __far
    #define _WCHUGE __huge
    #define _WCINTERRUPT __interrupt
    #define _WCUNALIGNED
    #if defined(__386__)
      #define _WCI86NEAR
      #define _WCI86FAR
      #define _WCI86HUGE
    #else
      #define _WCI86NEAR __near
      #define _WCI86FAR __far
      #define _WCI86HUGE __huge
    #endif
  #elif defined(__AXP__)
    #define _WCNEAR
    #define _WCFAR
    #define _WCHUGE
    #define _WCI86NEAR
    #define _WCI86FAR
    #define _WCI86HUGE
    #define _WCINTERRUPT
    #define _WCUNALIGNED __unaligned
  #elif defined(__PPC__)
    #define _WCNEAR
    #define _WCFAR
    #define _WCHUGE
    #define _WCI86NEAR
    #define _WCI86FAR
    #define _WCI86HUGE
    #define _WCINTERRUPT
    #define _WCUNALIGNED __unaligned
  #else
    #define _WCNEAR
    #define _WCFAR
    #define _WCHUGE
    #define _WCI86NEAR
    #define _WCI86FAR
    #define _WCI86HUGE
    #define _WCINTERRUPT
    #define _WCUNALIGNED
  #endif
  #if defined(M_I86MH)
    #define _WCDATA _WCFAR
  #elif defined(__SW_ND) || defined(__FUNCTION_DATA_ACCESS)
    #define _WCDATA
  #else
    #define _WCDATA _WCNEAR
  #endif
  #if defined(__SW_BR)
    #if defined(__NT__)
      #define _WCRTLINK __declspec(dllimport)
      #define _WMRTLINK __declspec(dllimport)
      #define _WPRTLINK __declspec(dllimport)
    #elif defined(__OS2__) && (defined(__386__) || defined(__PPC__))
      #define _WCRTLINK
      #define _WMRTLINK
      #define _WPRTLINK
    #else
      #define _WCRTLINK
      #define _WMRTLINK
      #define _WPRTLINK
    #endif
  #else
    #ifndef _WCRTLINK
      #define _WCRTLINK
    #endif
    #ifndef _WMRTLINK
      #define _WMRTLINK
    #endif
    #ifndef _WPRTLINK
      #define _WPRTLINK
    #endif
  #endif
  // control import modifier on intrinsic functions
  #ifndef _WCIRTLINK
    #if defined(__INLINE_FUNCTIONS__)
      #define _WCIRTLINK
    #else
      #define _WCIRTLINK _WCRTLINK
    #endif
  #endif
  #ifndef _WMIRTLINK
    #if defined(__NO_MATH_OPS) || defined(__AXP__) || defined(__PPC__)
      #define _WMIRTLINK _WMRTLINK
    #else
      #define _WMIRTLINK
    #endif
  #endif
  #ifndef _WPIRTLINK
    #define _WPIRTLINK _WPRTLINK
  #endif
  /* for MS compatibility */
  #ifndef _CRTAPI1
    #define _CRTAPI1
  #endif
  #ifndef _CRTAPI2
    #define _CRTAPI2
  #endif
  #ifndef _CRTIMP
    #define _CRTIMP _WCRTLINK
  #endif
#endif
