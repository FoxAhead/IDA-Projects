/*
 *  sys/locking.h	Flags for locking() function
 *
 *  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
 */
#ifndef __LOCKING_H_INCLUDED
#ifdef __cplusplus
extern "C" {
#endif

#define _LK_UNLCK   0	/* unlock region of a file */
#define LK_UNLCK    _LK_UNLCK
#define _LK_LOCK    1	/* lock a region of a file */
#define LK_LOCK     _LK_LOCK
#define _LK_NBLCK   2	/* non-blocking lock */
#define LK_NBLCK    _LK_NBLCK
#define _LK_RLCK    3	/* lock for writing */
#define LK_RLCK	    _LK_RLCK
#define _LK_NBRLCK  4	/* non-blocking lock for writing */
#define LK_NBRLCK   _LK_NBRLCK

extern int locking(int __handle,int __mode,unsigned long __nbyte);
extern int _locking(int __handle,int __mode,unsigned long __nbyte);

#define __LOCKING_H_INCLUDED
#ifdef __cplusplus
};
#endif
#endif
