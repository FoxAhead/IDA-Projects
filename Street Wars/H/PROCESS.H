/*
 *  process.h	Process spawning and related routines
 *
 *  Copyright by WATCOM International Corp. 1988-1996.  All rights reserved.
 */
#ifndef _PROCESS_H_INCLUDED
#define _PROCESS_H_INCLUDED
#if !defined(_ENABLE_AUTODEPEND)
  #pragma read_only_file;
#endif
#ifdef __cplusplus
extern "C" {
#endif

#ifndef _COMDEF_H_INCLUDED
 #include <_comdef.h>
#endif
 
#ifndef _WCHAR_T_DEFINED
#define _WCHAR_T_DEFINED
#define _WCHAR_T_DEFINED_
#ifdef __cplusplus
typedef long char wchar_t;
#else
typedef unsigned short wchar_t;
#endif
#endif

/*
 *  POSIX 1003.1 Prototypes
 */
_WCRTLINK extern int execl( const char *__path, const char *__arg0, ... );
_WCRTLINK extern int execle( const char *__path, const char *__arg0, ... );
_WCRTLINK extern int execlp( const char *__file, const char *__arg0, ... );
_WCRTLINK extern int execv( const char *__path, const char *const __argv[] );
_WCRTLINK extern int execve( const char *__path, const char *const __argv[], 
			    const char *const __envp[] );
_WCRTLINK extern int execvp( const char *__file, const char *const __argv[] );


/* mode flags for spawnxxx routines */
_WCRTLINK extern int __p_overlay;

#define P_WAIT	    0
#define P_NOWAIT    1
#define P_OVERLAY   __p_overlay
#define P_NOWAITO   3

/*
 *  Prototypes for non-POSIX functions
 */

_WCRTLINK extern int execlpe( const char *__file, const char *__arg0, ... );
_WCRTLINK extern int execvpe( const char *__file, const char *const __argv[], 
			      const char *const __envp[] );

#if defined(__386__) || defined(__AXP__) || defined(__PPC__)
#if defined(__NT__)
_WCRTLINK extern unsigned long _beginthread( 
                register void (*__start_address)(void *),
		unsigned __stack_size, void *__arglist );
_WCRTLINK extern unsigned long _beginthreadex( void *__security, 
		unsigned __stack_size, 
		register unsigned (__stdcall *__start_address)(void *),
		void *__arglist, unsigned __initflag, unsigned *__thrdaddr );
#pragma intrinsic(_beginthread,_beginthreadex);
_WCRTLINK extern void _endthreadex( unsigned __retval );
_WCRTLINK extern unsigned long __threadhandle( void );
#else
_WCRTLINK extern int  _beginthread( register void (*__start_address)(void *),
   void *__stack_bottom, unsigned __stack_size, void *__arglist );
#pragma intrinsic(_beginthread);
#endif
_WCRTLINK extern void _endthread();
#else
_WCRTLINK extern int _WCFAR  _beginthread( 
    register void (_WCFAR *__start_address)(void _WCFAR *),
    void _WCFAR *__stack_bottom, unsigned __stack_size, void _WCFAR *__arglist );
#pragma intrinsic(_beginthread);
_WCRTLINK extern void _WCFAR _endthread();
#ifndef __SW_ZU
  _WCRTLINK void _WCFAR *__chkstack( void _WCFAR * );
  #define _beginthread( __sa, __sb, __ss, __al ) \
  	  _beginthread( __sa, __chkstack(__sb), __ss, __al )
#endif
#endif

/* values for __action_code used with cwait() */

#define WAIT_CHILD 0
#define WAIT_GRANDCHILD 1

_WCRTLINK extern int   cwait( int *__status, int __process_id, 
			     int __action_code );
_WCRTLINK extern int   _cwait( int *__status, int __process_id, 
			     int __action_code );
_WCRTLINK extern void  abort( void );
_WCRTLINK extern void  exit( int __status );
_WCRTLINK extern void  _exit( int __status );
_WCRTLINK extern char *getcmd( char *__buffer );
_WCRTLINK extern int   _bgetcmd( char *__buffer, int __len );
_WCRTLINK extern char *_cmdname( char *__name );
_WCRTLINK extern char *getenv( const char *__name );
_WCRTLINK extern int   putenv( const char *__string );
_WCRTLINK extern int   spawnl( int __mode, const char *__path, 
			      const char *__arg0, ... );
_WCRTLINK extern int   spawnle( int __mode, const char *__path, 
			       const char *__arg0, ... );
_WCRTLINK extern int   spawnlp( int __mode, const char *__path, 
			       const char *__arg0, ... );
_WCRTLINK extern int   spawnlpe( int __mode, const char *__path, 
				const char *__arg0, ... );
_WCRTLINK extern int   spawnv( int __mode, const char *__path, 
			      const char * const *__argv );
_WCRTLINK extern int   spawnve( int __mode, const char *__path, 
			       const char * const *__argv, 
			       const char * const *__envp );
_WCRTLINK extern int   spawnvp( int __mode, const char *__path, 
			       const char * const *__argv );
_WCRTLINK extern int   spawnvpe( int __mode, const char *__path, 
				const char * const *__argv, 
				const char * const *__envp );
_WCRTLINK extern int   system( const char *__cmd );

_WCRTLINK extern wchar_t *  _wgetenv( const wchar_t *__name );
_WCRTLINK extern int	    _wsetenv( const wchar_t *__name,
				      const wchar_t *__newvalue, 
				      int __overwrite );
_WCRTLINK extern int	    _wputenv( const wchar_t *__env_string );

_WCRTLINK extern int	_wexecl( const wchar_t *__path, const wchar_t *__arg0, ... );
_WCRTLINK extern int	_wexecle( const wchar_t *__path, const wchar_t *__arg0, ... );
_WCRTLINK extern int	_wexeclp( const wchar_t *__file, const wchar_t *__arg0, ... );
_WCRTLINK extern int	_wexecv( const wchar_t *__path, const wchar_t *const __argv[] );
_WCRTLINK extern int	_wexecve( const wchar_t *__path, const wchar_t *const __argv[], 
				  const wchar_t *const __envp[] );
_WCRTLINK extern int	_wexecvp( const wchar_t *__file, const wchar_t *const __argv[] );
_WCRTLINK extern int	_wexeclpe( const wchar_t *__file, const wchar_t *__arg0, ... );
_WCRTLINK extern int	_wexecvpe( const wchar_t *__file, const wchar_t *const __argv[], 
				   const wchar_t *const __envp[] );
_WCRTLINK extern int	_wspawnl( int __mode, const wchar_t *__path, 
				  const wchar_t *__arg0, ... );
_WCRTLINK extern int	_wspawnle( int __mode, const wchar_t *__path, 
				   const wchar_t *__arg0, ... );
_WCRTLINK extern int	_wspawnlp( int __mode, const wchar_t *__path, 
				   const wchar_t *__arg0, ... );
_WCRTLINK extern int	_wspawnlpe( int __mode, const wchar_t *__path, 
				    const wchar_t *__arg0, ... );
_WCRTLINK extern int	_wspawnv( int __mode, const wchar_t *__path, 
				  const wchar_t * const *__argv );
_WCRTLINK extern int	_wspawnve( int __mode, const wchar_t *__path, 
				   const wchar_t * const *__argv, 
				   const wchar_t * const *__envp );
_WCRTLINK extern int	_wspawnvp( int __mode, const wchar_t *__path, 
				   const wchar_t * const *__argv );
_WCRTLINK extern int	_wspawnvpe( int __mode, const wchar_t *__path, 
				    const wchar_t * const *__argv, 
				    const wchar_t * const *__envp );
_WCRTLINK extern int	_wsystem( const wchar_t *__cmd );

#if defined(__NT__)
 // For use when access to the DLL startup is required.
 // this function pointer will be called after the C library startup
 // and before the C++ library startup.
 #if defined(_WINDOWS_)
  extern BOOL (WINAPI *_pRawDllMain)( HANDLE, DWORD, LPVOID );
 #else
  extern int (__stdcall *_pRawDllMain)( void *, unsigned, void * );
 #endif
#endif
_WCRTLINK extern int getpid( void );
_WCRTLINK extern int wait( int *__status );


#ifdef __cplusplus
};
#endif
#endif
