/*
 *  fcntl.h	File control options used by open
 *
 *  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
 */
#ifndef _FCNTL_H_INCLUDED
#ifdef __cplusplus
extern "C" {
#endif
#pragma pack(1);


#define O_RDONLY	0x0000	/* open for read only */
#define O_WRONLY	0x0001	/* open for write only */
#define O_RDWR		0x0002	/* open for read and write */
#define O_APPEND	0x0010	/* writes done at end of file */
#define O_CREAT 	0x0020	/* create new file */
#define O_TRUNC 	0x0040	/* truncate existing file */
#define O_NOINHERIT	0x0080	/* file is not inherited by child process */
#define O_TEXT		0x0100	/* text file */
#define O_BINARY	0x0200	/* binary file */
#define O_EXCL		0x0400	/* exclusive open */

/*
 *  POSIX 1003.1 Prototypes.
 */
extern int open( const char *__path, int __oflag, ... );
extern int sopen( const char *__path, int __oflag, int __share, ... );
#pragma pack();

#define _FCNTL_H_INCLUDED
#ifdef __cplusplus
};
#endif
#endif
