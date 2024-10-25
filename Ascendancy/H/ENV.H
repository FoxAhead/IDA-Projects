/*
 *  env.h	Environment string operations
 *
 *  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
 */
#ifndef _ENV_H_INCLUDED
#ifdef __cplusplus
extern "C" {
#endif

/*
 *  POSIX 1003.1 Prototypes.
 */
extern int clearenv( void );
extern char *getenv( const char *__name );
extern int setenv( const char *__name, const char *__newvalue, int __overwrite );
#if !defined(NO_EXT_KEYS) /* extensions enabled */
extern int putenv( const char *__env_string );
#endif

#define _ENV_H_INCLUDED
#ifdef __cplusplus
};
#endif
#endif
