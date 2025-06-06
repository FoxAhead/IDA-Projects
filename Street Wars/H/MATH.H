/*
 *  math.h	Math functions
 *
 *  Copyright by WATCOM International Corp. 1988-1996.  All rights reserved.
 */
#ifndef _MATH_H_INCLUDED
#define _MATH_H_INCLUDED
#if !defined(_ENABLE_AUTODEPEND)
  #pragma read_only_file;
#endif
#ifdef __cplusplus
extern "C" {
#endif

#ifndef _COMDEF_H_INCLUDED
 #include <_comdef.h>
#endif

#if defined(_M_IX86)
  #pragma pack(__push,1);
#else
  #pragma pack(__push,8);
#endif

#if defined(__FUNCTION_DATA_ACCESS)
 #define _HugeValue (*__get_HugeValue_ptr())
#elif defined(__SW_BR) || defined(_RTDLL) 
  #define _HugeValue _HugeValue_br
#endif
_WCRTLINK extern const double _WCDATA _HugeValue;
#define HUGE_VAL _HugeValue

_WMRTLINK extern double ceil( double __x );
_WMRTLINK extern double floor( double __x );
_WMRTLINK extern double frexp( double __value, int *__exp );
_WMRTLINK extern double ldexp( double __x, int __exp );
_WMRTLINK extern double modf( double __value, double *__iptr );
_WMIRTLINK extern double acos( double __x );
_WMIRTLINK extern double asin( double __x );
_WMIRTLINK extern double atan( double __x );
_WMIRTLINK extern double atan2( double __y, double __x );
_WMIRTLINK extern double cos( double __x );
_WMIRTLINK extern double cosh( double __x );
_WMIRTLINK extern double exp( double __x );
_WMIRTLINK extern double fabs( double __x );
_WMIRTLINK extern double fmod( double __x, double __y );
_WMIRTLINK extern double log( double __x );
_WMIRTLINK extern double log10( double __x );
_WMIRTLINK extern double pow( double __x, double __y );
_WMIRTLINK extern double sin( double __x );
_WMIRTLINK extern double sinh( double __x );
_WMIRTLINK extern double sqrt( double __x );
_WMIRTLINK extern double tan( double __x );
_WMIRTLINK extern double tanh( double __x );

/* non-ANSI */
#if !defined(NO_EXT_KEYS) /* extensions enabled */

struct _complex {
	double	x;
	double	y;
};
#ifndef __cplusplus
struct complex {
	double	x;
	double	y;
};
#endif

_WMRTLINK extern double	acosh( double __x );
_WMRTLINK extern double	asinh( double __x );
_WMRTLINK extern double	atanh( double __x );
_WMRTLINK extern double	cabs( struct _complex );
_WMRTLINK extern double	hypot( double __x, double __y );
_WMRTLINK extern double	j0( double __x );
_WMRTLINK extern double	j1( double __x );
_WMRTLINK extern double	jn( int __n, double __x );
_WMRTLINK extern double	log2( double __x );
_WMRTLINK extern double	y0( double __x );
_WMRTLINK extern double	y1( double __x );
_WMRTLINK extern double	yn( int __n, double __x );

/* The following struct is used to record errors detected in the math library.
 * matherr is called with a pointer to this struct for possible error recovery.
 */

struct _exception {
	int	type;		/* type of error, see below */
	char	*name;		/* name of math function */
	double	arg1;		/* value of first argument to function */
	double	arg2;		/* second argument (if indicated) */
	double	retval; 	/* default return value */
};
#ifndef __cplusplus
struct	exception {
	int	type;		/* type of error, see below */
	char	*name;		/* name of math function */
	double	arg1;		/* value of first argument to function */
	double	arg2;		/* second argument (if indicated) */
	double	retval; 	/* default return value */
};
#endif

#define DOMAIN		1	/* argument domain error */
#define SING		2	/* argument singularity  */
#define OVERFLOW	3	/* overflow range error  */
#define UNDERFLOW	4	/* underflow range error */
#define TLOSS		5	/* total loss of significance */
#define PLOSS		6	/* partial loss of significance */

_WMRTLINK extern int	matherr( struct _exception * );
_WMRTLINK extern double	_matherr( struct _exception * );
#endif /* EXTENSIONS */


#if !defined( __NO_MATH_OPS ) && defined(_M_IX86)
/*
    Defining the __NO_MATH_OPS macro will stop the compiler from recogizing
    the following functions as intrinsic operators.
*/
 #pragma intrinsic(log,cos,sin,tan,sqrt,fabs,pow,atan2,fmod)
 #pragma intrinsic(acos,asin,atan,cosh,exp,log10,sinh,tanh)
#endif
#pragma pack(__pop);
#ifdef __cplusplus
};
#endif
#endif
