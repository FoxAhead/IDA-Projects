/*
 *  direct.h	Defines the types and structures used by the directory routines
 *
 *  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
 */
#ifndef _DIRECT_H_INCLUDED
#ifdef __cplusplus
extern "C" {
#endif
#pragma pack(1);

#ifndef __TYPES_H_INCLUDED
 #include <sys/types.h>
#endif

#if defined(__OS2__) || defined(__NT__)
#define NAME_MAX	255		/* maximum filename for HPFS or NTFS */
#else
#define NAME_MAX	12		/* 8 chars + '.' +  3 chars */
#endif

typedef struct dirent {
    char	d_dta[ 21 ];		/* disk transfer area */
    char	d_attr; 		/* file's attribute */
    unsigned short int d_time;		/* file's time */
    unsigned short int d_date;		/* file's date */
    long	d_size; 		/* file's size */
    char	d_name[ NAME_MAX + 1 ]; /* file's name */
    unsigned short d_ino;		/* serial number (not used) */
    char	d_first;		/* flag for 1st time */
} DIR;

/* File attribute constants for d_attr field */

#define _A_NORMAL	0x00	/* Normal file - read/write permitted */
#define _A_RDONLY	0x01	/* Read-only file */
#define _A_HIDDEN	0x02	/* Hidden file */
#define _A_SYSTEM	0x04	/* System file */
#define _A_VOLID	0x08	/* Volume-ID entry */
#define _A_SUBDIR	0x10	/* Subdirectory */
#define _A_ARCH 	0x20	/* Archive file */

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

extern int	chdir( const char *__path );
extern int	closedir( DIR * );
extern char	*getcwd( char *__buf, unsigned __size );
extern unsigned	_getdrive( void );
extern unsigned	_getdiskfree( unsigned __drive, struct _diskfree_t *__diskspace);
extern int	mkdir( const char *__path );
extern DIR	*opendir( const char * );
extern struct dirent *readdir( DIR * );
extern int	rmdir( const char *__path );

#pragma pack();
#define _DIRECT_H_INCLUDED
#ifdef __cplusplus
};
#endif
#endif
