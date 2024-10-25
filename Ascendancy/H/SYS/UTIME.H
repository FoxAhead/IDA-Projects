/*
 *  sys/utime.h utimbuf structure and prototypes
 *
 *  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
 */
#ifndef _UTIME_H_INCLUDED
#ifdef __cplusplus
extern "C" {
#endif


#pragma pack(1)

#ifndef _TIME_T_DEFINED_
 #define _TIME_T_DEFINED_
 typedef unsigned long time_t;	 /* time value */
#endif

struct utimbuf {
    time_t	actime; 	/* access time */
    time_t	modtime;	/* modification time */
};

/*
 *  POSIX 1003.1 Prototype
 */
extern int utime( const char *__path, const struct utimbuf * __times );

#pragma pack()
#define _UTIME_H_INCLUDED
#ifdef __cplusplus
};
#endif
#endif
