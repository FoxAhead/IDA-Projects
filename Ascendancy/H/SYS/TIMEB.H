/*
 *  sys/timeb.h     timeb structure used with ftime()
 *
 *  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
 */
#ifndef __TIMEB_H_INCLUDED
#ifdef __cplusplus
extern "C" {
#endif
#ifndef _TIME_T_DEFINED_
 #define _TIME_T_DEFINED_
 typedef unsigned long time_t;	 /* time value */
#endif

#pragma pack(1);
struct timeb {
    time_t		time;		/* seconds since Jan 1, 1970 UTC */
    unsigned short 	millitm;	/* milliseconds */
    short		timezone;	/* difference in minutes from UTC */
    short		dstflag;	/* nonzero if daylight savings time */
};
#pragma pack();

extern int ftime( struct timeb *__timeptr );

#define __TIMEB_H_INCLUDED
#ifdef __cplusplus
};
#endif
#endif
