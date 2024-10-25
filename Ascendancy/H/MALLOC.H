/*
 *  malloc.h	Memory allocation functions
 *
 *  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
 */
#ifndef _MALLOC_H_INCLUDED
#ifdef __cplusplus
extern "C" {
#endif
#pragma pack(1);

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

#ifndef alloca
extern void  *alloca(size_t __size);
extern void  *__doalloca(size_t __size);
extern unsigned stackavail( void );
#pragma aux stackavail modify nomemory;

#define __ALLOCA_ALIGN( s )	(((s)+(sizeof(int)-1))&~(sizeof(int)-1))
#define __alloca( s )		__doalloca(__ALLOCA_ALIGN(s))

#define alloca( s ) 	((__ALLOCA_ALIGN(s)<stackavail())?__alloca(s):NULL)

#if defined(__386__)
#pragma aux     __doalloca =				\
	    "sub esp,eax"				\
	    parm nomemory [eax] value [esp] modify exact nomemory [esp];
#elif defined(__SMALL__) || defined(__MEDIUM__) /* small data models */
#pragma aux	__doalloca = 	\
	    "sub sp,ax"		\
	    parm nomemory [ax] value [sp] modify exact nomemory [sp];
#else						/* large data models */
#pragma aux	__doalloca = 	\
	    "sub sp,ax"		\
	    "mov ax,sp"		\
	    "mov dx,ss"		\
	    parm nomemory [ax] value [dx ax] modify exact nomemory [dx ax sp];
#endif
#endif

#define _HEAPOK 	0
#define _HEAPEMPTY	1	/* heap isn't initialized */
#define _HEAPBADBEGIN	2	/* heap header is corrupted */
#define _HEAPBADNODE	3	/* heap entry is corrupted */
#define _HEAPEND	4	/* end of heap entries (_heapwalk) */
#define _HEAPBADPTR	5	/* invalid heap entry pointer (_heapwalk) */

#define _USEDENTRY	0
#define _FREEENTRY	1

typedef struct _heapinfo {
    void __far		*_pentry;	/* heap pointer */
    size_t		_size;		/* heap entry size */
    int 		_useflag;	/* heap entry 'in-use' flag */
} _HEAPINFO;

extern int _heapenable( int __enabled );
extern int _heapchk( void );
extern int _nheapchk( void );
extern int _fheapchk( void );
extern int _heapset( unsigned int __fill );
extern int _nheapset( unsigned int __fill );
extern int _fheapset( unsigned int __fill );
extern int _heapwalk( struct _heapinfo *__entry );
extern int _nheapwalk( struct _heapinfo *__entry );
extern int _fheapwalk( struct _heapinfo *__entry );

extern void _heapgrow( void );
extern void _nheapgrow( void );
extern void _fheapgrow( void );
extern int _heapmin( void );
extern int _nheapmin( void );
extern int _fheapmin( void );
extern int _heapshrink( void );
extern int _nheapshrink( void );
extern int _fheapshrink( void );

extern int __nmemneed( size_t );
extern int __fmemneed( size_t );
extern void __far  *_fcalloc( size_t __n,size_t __size );
extern void __near *_ncalloc( size_t __n,size_t __size );
extern void *_expand( void *__ptr,size_t __size );
extern void __far  *_fexpand( void __far *__ptr,size_t __size );
extern void __near *_nexpand( void __near *__ptr,size_t __size );
extern void _ffree( void __far *__ptr );
extern void __far *_fmalloc( size_t __size );
extern unsigned int _freect( size_t __size );
extern void __huge *halloc( long __n,size_t __size );
extern void hfree( void __huge * );
extern void _nfree( void __near *__ptr );
extern void __near *_nmalloc( size_t __size );
extern void __near *_nrealloc( void __near *__ptr,size_t __size );
extern void __far  *_frealloc( void __far *__ptr,size_t __size );
extern size_t _msize( void *__ptr );
extern size_t _nmsize( void __near *__ptr );
extern size_t _fmsize( void __far *__ptr );
extern size_t _memavl( void );
extern size_t _memmax( void );
extern void *calloc( size_t __n,size_t __size );
extern void free( void *__ptr );
extern void *malloc( size_t __size );
extern void *realloc( void *__ptr,size_t __size );

#if __WATCOMC__ >= 900

/* based heap function prototypes */

#define	_NULLSEG	((__segment)0)
#define	_NULLOFF	((void __based(void) *)~0)

extern int _bfreeseg(__segment __seg);
extern __segment _bheapseg(size_t size);
extern void __based(void) *_bcalloc(__segment __seg,size_t __num,size_t __size);
extern void __based(void) *_bexpand(__segment __seg,void __based(void) *__mem,
				size_t __size);
extern void _bfree(__segment __seg,void __based(void) *__mem);
extern int _bheapchk(__segment __seg);
extern int _bheapmin(__segment __seg);
extern int _bheapset(__segment __seg,unsigned int __fill);
extern int _bheapwalk(__segment __seg,struct _heapinfo *__entry);
extern void __based(void) *_bmalloc(__segment __seg,size_t __size);
extern size_t _bmsize(__segment __seg,void __based(void) *__mem);
extern void __based(void) *_brealloc(__segment __seg,void __based(void) *__mem,
				size_t __size);
#endif
#pragma pack();
#define _MALLOC_H_INCLUDED
#ifdef __cplusplus
};
#endif
#endif
