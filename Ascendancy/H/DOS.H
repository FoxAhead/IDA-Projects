/*
 *  dos.h       Defines the structs and unions used to handle the input and
 *              output registers for the DOS and 386 DOS Extender interface
 *              routines.
 *
 *  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
 */
#ifndef _DOS_H_INCLUDED
#ifdef __cplusplus
extern "C" {
#endif

#include <i86.h>

#if defined(__WINDOWS_386__) || defined(__NT__) || ( defined(__OS2__) && defined(__386__) )
#define __far
#endif
#pragma pack(1);

/* dosexterror struct */

struct _DOSERROR {
        int exterror;
        char errclass;
        char action;
        char locus;
};
#ifndef __cplusplus
struct DOSERROR {
        int exterror;
        char class;
        char action;
        char locus;
};
#endif

struct dosdate_t {
        unsigned char day;      /* 1-31 */
        unsigned char month;    /* 1-12 */
        unsigned short year;    /* 1980-2099 */
        unsigned char dayofweek;/* 0-6 (0=Sunday) */
};
#define _dosdate_t dosdate_t

struct dostime_t {
        unsigned char hour;     /* 0-23 */
        unsigned char minute;   /* 0-59 */
        unsigned char second;   /* 0-59 */
        unsigned char hsecond;  /* 1/100 second; 0-99 */
};
#define _dostime_t dostime_t

struct find_t {
        char reserved[21];      /* reserved for use by DOS    */
        char attrib;            /* attribute byte for file    */
        unsigned short wr_time; /* time of last write to file */
        unsigned short wr_date; /* date of last write to file */
        unsigned long  size;    /* length of file in bytes    */
#if defined(__OS2__) || defined(__NT__)
        char name[256];         /* null-terminated filename   */
#else
        char name[13];          /* null-terminated filename   */
#endif
};
#define _find_t find_t

/* Critical error handler equates for _hardresume result parameter */

#define _HARDERR_IGNORE 0       /* Ignore the error */
#define _HARDERR_RETRY  1       /* Retry the operation */
#define _HARDERR_ABORT  2       /* Abort the program */
#define _HARDERR_FAIL   3       /* Fail the system call in progress */

/* File attribute constants for attribute field */

#define _A_NORMAL       0x00    /* Normal file - read/write permitted */
#define _A_RDONLY       0x01    /* Read-only file */
#define _A_HIDDEN       0x02    /* Hidden file */
#define _A_SYSTEM       0x04    /* System file */
#define _A_VOLID        0x08    /* Volume-ID entry */
#define _A_SUBDIR       0x10    /* Subdirectory */
#define _A_ARCH         0x20    /* Archive file */

#ifndef _DISKFREE_T_DEFINED_
#define _DISKFREE_T_DEFINED_
struct _diskfree_t {
        unsigned short total_clusters;
        unsigned short avail_clusters;
        unsigned short sectors_per_cluster;
        unsigned short bytes_per_sector;
};
#define diskfree_t _diskfree_t
#endif

extern int      bdos(int __dosfn, unsigned int __dx, unsigned int __al);
extern void     _chain_intr(register void (__interrupt __far *__handler)());
#if defined(__NT__) || ( defined(__OS2__) && defined(__386__) )
extern unsigned _dos_allocmem( unsigned __size, void **__storage );
#else
extern unsigned _dos_allocmem( unsigned __size, unsigned short *__seg );
#endif
extern unsigned _dos_close( int __handle );
extern unsigned _dos_commit( int __handle );
extern unsigned _dos_creat( const char *__path, unsigned __attr, int *__handle );
extern unsigned _dos_creatnew( const char *__path, unsigned __attr, int *__handle );
extern unsigned _dos_findfirst(const char *__path,unsigned __attr,struct find_t *__buf );
extern unsigned _dos_findnext( struct find_t *__buf );
extern unsigned _dos_findclose( struct find_t *__buf );
#if defined(__NT__) || ( defined(__OS2__) && defined(__386__) )
extern unsigned _dos_freemem( void *__storage );
#else
extern unsigned _dos_freemem( unsigned short __seg );
#endif
extern void     _dos_getdate( struct dosdate_t *__date );
extern unsigned _dos_getdiskfree( unsigned __drive, struct _diskfree_t *__diskspace);
extern unsigned	_getdiskfree( unsigned __drive, struct _diskfree_t *__diskspace);
extern void     _dos_getdrive( unsigned *__drive );
extern unsigned	_getdrive( void );
extern unsigned _dos_getfileattr( const char *__path, unsigned *__attr );
extern unsigned _dos_getftime( int __handle, unsigned short *__date,
                        unsigned short *__time );
extern void     _dos_gettime( struct dostime_t *__time );
extern void     (__interrupt __far *_dos_getvect(int __intnum))();
extern void     _dos_keep(unsigned __retcode,unsigned __memsize);

extern unsigned _dos_open( const char *__path, unsigned __mode, int *__handle );
extern unsigned _dos_read( int __handle, void __far *__buf, unsigned __count,
                    unsigned *__bytes );
extern unsigned _dos_setblock( unsigned __size, unsigned short __seg,
                        unsigned  *__maxsize );
extern unsigned _dos_setdate( struct dosdate_t *__date );
extern void     _dos_setdrive( unsigned __drivenum, unsigned *__drives );
extern unsigned _dos_setfileattr( const char *__path, unsigned __attr );
extern unsigned _dos_setftime(int __handle,unsigned short __date,unsigned short __time);
extern unsigned _dos_settime( struct dostime_t *__time );
extern void     _dos_setvect(int __intnum,void (__interrupt __far *__handler)());
extern unsigned _dos_write( int __handle, void const __far *__buf, unsigned __count,
                    unsigned *__bytes );
extern int      dosexterr(struct _DOSERROR *);
extern void     _harderr(register int (__far *__func)(unsigned __deverr,
                        unsigned __errcode,unsigned __far *__devhdr));
extern void     _hardresume(int __result);
extern void     _hardretn(int __error);
extern int      intdos(union REGS *, union REGS *);
extern int      intdosx(union REGS *, union REGS *, struct SREGS *);
extern void     sleep(unsigned __seconds);

#pragma pack();
#define _DOS_H_INCLUDED
#if defined(__WINDOWS_386__) || defined(__NT__) || ( defined(__OS2__) && defined(__386__) )
#undef __far
#endif
#ifdef __cplusplus
};
#endif
#endif
