/*
 *  process.h	Process spawning and related routines
 *
 *  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
 */
#ifndef _PROCESS_H_INCLUDED
#ifdef __cplusplus
extern "C" {
#endif


/*
 *  POSIX 1003.1 Prototypes
 */
extern int execl( const char *__path, const char *__arg0, ... );
extern int execle( const char *__path, const char *__arg0, ... );
extern int execlp( const char *__file, const char *__arg0, ... );
extern int execv( const char *__path, const char *const __argv[] );
extern int execve( const char *__path, const char *const __argv[], const char *const __envp[] );
extern int execvp( const char *__file, const char *const __argv[] );


/* mode flags for spawnxxx routines */
extern int __p_overlay;

#define P_WAIT	    0
#define P_NOWAIT    1
#define P_OVERLAY   __p_overlay
#define P_NOWAITO   3

/*
 *  Prototypes for non-POSIX functions
 */

extern int execlpe( const char *__file, const char *__arg0, ... );
extern int execvpe( const char *__file, const char *const __argv[], const char *const __envp[] );

/* values for __action_code used with cwait() */

#define WAIT_CHILD 0
#define WAIT_GRANDCHILD 1

#ifdef __386__
extern int _beginthread( register void (*__start_address)(void *),
     void *__stack_bottom, unsigned __stack_size,void *__arglist );
extern int cwait(int *__status,int __process_id,int __action_code);
extern void _endthread();
#else
extern int __far _beginthread( register void (__far *__start_address)(void __far *),
     void __far *__stack_bottom, unsigned __stack_size,void __far *__arglist );
extern int   cwait(int *__status,int __process_id,int __action_code);
extern void __far _endthread();
#ifdef __SW_ZU
  #define _beginthread( __sa, __sb, __ss, __al ) _beginthread( __sa, __sb, __ss, __al )
#else
  void __far *__chkstack( void __far * );
  #define _beginthread( __sa, __sb, __ss, __al ) _beginthread( __sa, __chkstack(__sb), __ss, __al )
#endif
#endif
extern void abort(void);
extern void exit(int __status);
extern void _exit(int __status);
extern char *getcmd(char *__buffer);
extern int _bgetcmd(char *__buffer, int __len);
extern char *getenv(const char *__name);
extern int putenv(const char *__string);
extern int spawnl(int __mode,const char *__path, const char *__arg0,...);
extern int spawnle(int __mode,const char *__path, const char *__arg0,...);
extern int spawnlp(int __mode,const char *__path, const char *__arg0,...);
extern int spawnlpe(int __mode,const char *__path, const char *__arg0,...);
extern int spawnv(int __mode,const char *__path,const char * const *__argv);
extern int spawnve(int __mode,const char *__path,const char * const *__argv,const char * const *__envp);
extern int spawnvp(int __mode,const char *__path,const char * const *__argv);
extern int spawnvpe(int __mode,const char *__path,const char * const *__argv,const char * const *__envp);
extern int system(const char *__cmd);

extern int getpid(void);
extern int wait(int *__status);


#define _PROCESS_H_INCLUDED
#ifdef __cplusplus
};
#endif
#endif
