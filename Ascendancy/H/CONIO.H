/*
 *  conio.h	Console and Port I/O functions
 *
 *  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
 */
#ifndef _CONIO_H_INCLUDED
#ifdef __cplusplus
extern "C" {
#endif

#ifndef __VALIST
 #ifdef  __HUGE__
  typedef char __far *__va_list[1];
 #else
  typedef char *__va_list[1];
 #endif
 #define __VALIST
#endif

extern char *cgets(char *__buf);
extern int cputs(const char *__buf);
extern int cprintf(const char *__fmt,...);
extern int cscanf(const char *__fmt,...);
extern int getch(void);
extern int getche(void);
extern int kbhit(void);
extern unsigned inp(unsigned __port);
extern unsigned inpw(unsigned __port);
extern unsigned outp(unsigned __port, unsigned __value);
extern unsigned outpw(unsigned __port,unsigned __value);
#ifdef __386__
extern unsigned inpd(unsigned __port);
extern unsigned outpd(unsigned __port, unsigned __value);
#endif
extern int putch(int __c);
extern int ungetch(int __c);
extern int vcprintf( const char *__format, __va_list __arg );
extern int vcscanf( const char *__format, __va_list __arg );

#ifdef	__INLINE_FUNCTIONS__
 #pragma intrinsic(inp,inpw,outp,outpw)
 #ifdef __386__
  #pragma intrinsic(inpd,outpd)
 #endif
#endif

#define _CONIO_H_INCLUDED
#ifdef __cplusplus
};
#endif
#endif
