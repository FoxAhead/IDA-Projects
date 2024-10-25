/*
 *  limits.h	Machine and OS limits
 *
 *  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
 */
#ifndef _LIMITS_H_INCLUDED

/*
 *  ANSI required limits
 */
#define CHAR_BIT    8		/*  number of bits in a byte	    */
#ifdef __CHAR_SIGNED__
 #define CHAR_MIN   (-128)	/*  minimum value of a char	    */
 #define CHAR_MAX   127 	/*  maximum value of a char	    */
#else
 #define CHAR_MIN   0		/*  minimum value of a char	    */
 #define CHAR_MAX   255 	/*  maximum value of a char	    */
#endif
#define MB_LEN_MAX  1		/*  maximum length of multibyte char	*/
#define SCHAR_MIN   (-128)	/*  minimum value of a signed char	*/
#define SCHAR_MAX   127 	/*  maximum value of a signed char	*/
#define UCHAR_MAX   255U	/*  maximum value of an unsigned char	*/

#define SHRT_MIN    (-32767-1)	/*  minimum value of a short int	*/
#define SHRT_MAX    32767	/*  maximum value of a short int	*/
#define USHRT_MAX   65535U	/*  maximum value of an unsigned short	*/
#define LONG_MAX    2147483647L     /*	maximum value of a long int	*/
#define LONG_MIN    (-2147483647L-1) /* minimum value of a long int	*/
#define ULONG_MAX   4294967295UL     /* maximum value of a unsigned long    */
#ifdef __386__
 #define INT_MIN    (-2147483647-1) /*	minimum value of an int 	*/
 #define INT_MAX    2147483647	    /*	maximum value of an int 	*/
 #define UINT_MAX   4294967295U     /*	maximum value of an unsigned int*/
#else
 #define INT_MIN    (-32767-1)	    /*	minimum value of an int 	*/
 #define INT_MAX    32767	    /*	maximum value of an int 	*/
 #define UINT_MAX   65535U	    /*	maximum value of an unsigned int    */
#endif

#define TZNAME_MAX  30		    /*	The maximum number of bytes	    */
				    /*	supported for the name of a time    */
				    /*	zone (not of the TZ variable).	    */


#define _LIMITS_H_INCLUDED
#endif
