/*
 *  search.h	Function prototypes for searching functions
 *
 *  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
 */
#ifndef _SEARCH_H_INCLUDED
#ifdef __cplusplus
extern "C" {
#endif

extern void *lfind(const void *__key, const void *__base, unsigned *__num,
	    unsigned __width, int (* __compare)(const void *, const void *));
extern void *lsearch(const void *__key, const void *__base, unsigned *__num,
	    unsigned __width, int (* __compare)(const void *, const void *));
#define _SEARCH_H_INCLUDED
#ifdef __cplusplus
};
#endif
#endif
