/*
 *  time.h	Time functions
 *
 *  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
 */
#ifndef _TIME_H_INCLUDED
#ifdef __cplusplus
extern "C" {
#endif
#pragma pack(1)


#ifndef _SIZE_T_DEFINED_
#define _SIZE_T_DEFINED_
 typedef unsigned size_t;
#endif

#ifndef NULL
 #if defined(__SMALL__) || defined(__MEDIUM__) || defined(__386__)
  #define NULL   0
 #else
  #define NULL   0L
 #endif
#endif

#ifndef _TIME_T_DEFINED_
 #define _TIME_T_DEFINED_
 typedef unsigned long time_t;	 /* time value */
#endif

#define CLK_TCK 	100
#define CLOCKS_PER_SEC	100

#ifndef _CLOCK_T_DEFINED
 #define _CLOCK_T_DEFINED
 typedef unsigned long	clock_t;
#endif

struct	tm {
	int  tm_sec;	/* seconds after the minute -- [0,61] */
	int  tm_min;	/* minutes after the hour   -- [0,59] */
	int  tm_hour;	/* hours after midnight     -- [0,23] */
	int  tm_mday;	/* day of the month	    -- [1,31] */
	int  tm_mon;	/* months since January     -- [0,11] */
	int  tm_year;	/* years since 1900		      */
	int  tm_wday;	/* days since Sunday	    -- [0,6]  */
	int  tm_yday;	/* days since January 1     -- [0,365]*/
	int  tm_isdst;	/* Daylight Savings Time flag */
};

extern char *asctime( const struct tm *__timeptr );
extern clock_t clock( void );
extern char *ctime( const time_t *__timer );
extern double difftime( time_t __t1, time_t __t0 );
extern struct tm *gmtime( const time_t *__timer );
extern struct tm *localtime( const time_t *__timer );
extern time_t mktime( struct tm *__timeptr );
extern size_t strftime( char *__s, size_t __maxsiz, const char *__fmt,
		 const struct tm *__tp );
extern time_t time( time_t *__timer );

#ifndef __cplusplus
#define difftime(t1,t0) ((double)(t1)-(double)(t0))
#endif

#if !defined(NO_EXT_KEYS) /* extensions enabled */
extern char *_asctime( const struct tm *__timeptr, char *__buf );
extern char *_ctime( const time_t *__timer, char *__buf );
extern struct tm *_gmtime( const time_t *__timer, struct tm *__tmbuf );
extern struct tm *_localtime( const time_t *__timer, struct tm *__tmbuf );
extern char *_strdate( char *__buf );
extern char *_strtime( char *__buf );
#endif

extern void tzset( void );

 extern char	*tzname[2]; /*	time zone names */
 extern long	timezone;	/* # of seconds from GMT */
 extern int	daylight;	/* d.s.t. indicator */

#pragma pack()

#define _TIME_H_INCLUDED
#ifdef __cplusplus
};
#endif
#endif
