/****************************************************************************
*
*						 PM/Lite and PM/Pro Library
*
*					Copyright (C) 1994 SciTech Software.
*							All rights reserved.
*
* Filename:		$RCSfile: pmode.h $
* Version:		$Revision: 1.1 $
*
* Language:		ANSI C
* Environment:	Real mode and 16/32 bit Protected Mode under MSDOS
*
* Description:	Header file for the DOS extender independant protected
*				mode programming library. This library will need to be
*				included in all programs that use SciTech Software's
*				products that are to be compiled in protected mode.
*
*				This library provides pre-built selectors for the BIOS
*				data area and VGA frame buffer, and methods for allocating
*				your own selectors for physical memory. It also returns
*				appropriate selectors for accessing memory allocated in
*				the low DOS 1Mb memory area, and routines for accessing
*				memory through a selector and offset. By using selectors
*				for accessing memory outside of the applications linear
*				address space, your code will be fully DPMI compliant and
*				will run under Windows 3.1 and OS/2 2.x DOS boxes.
*
*				This Professional version of this library also provides
*				simplified interrupt handling, allowing all common interrupt
*				handlers to be hooked and handled directly with normal C
*				functions, both in 16 bit and 32 bit modes. Note however that
*				simplified handling does not mean slow performance! All low
*				level interrupt handling is done efficiently in assembler
*				for speed (well actually necessary to insulate the
*				application from the lack of far pointers in 32 bit PM). The
*				interrupt handlers currently supported are:
*
*					Mouse (0x33 callback)
*                   Timer Tick (0x8)
*					Keyboard (0x9)
*					Control C/Break (0x23/0x1B)
*					Critical Error (0x24)
*
*				Note that all interrupt handlers are correctly hooked to
*				ensure that control is always recieved in protected mode.
*
*				Works with the following:
*
*					Real Mode DOS (large memory model)
*
*				286 Extenders:
*
*					Windows 3.1 DPMI
*					Borland DPMI16
*
*				386 Extenders:
*
*					Windows 3.1 DPMI (Win32s)
*					Phar Lap TNT DOS Extender
*					FlashTek DOSX/X32-VM
*					Borland DPMI32
*					Rational DOS/4GW
*					DJGPP go32 for GNU C++			* NO SELECTORS YET!! *
*
*				Currently supports the following compilers:
*
*					Borland C++ 3.1
*					Borland C++ 4.0, 16 bit
*					Borland C++ 4.0, 32 bit
*					Microsoft Visual C++ 1.5, 16 bit * NOT TESTED YET	*
*					Microsoft Visual C++ 1.5, 32 bit * NOT TESTED YET	*
*					Symantec C++ 6.1, 16 bit
*					Symantec C++ 6.1, 32 bit
*					Watcom C++ 10.0, 16 bit
*					Watcom C++ 10.0, 32 bit
*					Metaware High C++ 3.21, 32 bit
*					DJGPP port of GNU C++, 32 bit	* NO SELECTORS YET!! *
*
* $Id: pmode.h 1.1 1994/08/22 07:46:56 kjb release $
*
****************************************************************************/

#ifndef	__PMODE_H
#define	__PMODE_H

#ifndef	__DOS_H
#include <dos.h>
#endif

/*--------------------------- Macros and Typedefs -------------------------*/

/* You will need to define one of the following before you compile this
 * library for it to work correctly with the DOS extender that you are
 * using. If none is specified, it is assumed you are compiling for DOS
 * real mode.
 *
 *		REALMODE	- Dos real mode
 *		WINDPMI16	- Windows 3.1 16 bit DPMI
 *		DPMI16		- Borland's DPMI16 DOS Power Pack Extender
 *		WINDPMI32	- Windows 3.1 32 bit DPMI
 *		TNT			- Phar Lap TNT DOS Extender
 *		DOSX		- Symantec C++ DOSX and Flashtek X32VM
 *		DPMI32		- Borland's DPMI32 DOS Power Pack Extender
 *		DOS4GW		- Rational DOS/4GW and DOS/4GW Professional
 *		DJGPP		- DJGPP port of GNU C++
 *
 * One of the following will be defined automatically for you when in
 * protected mode (REALMODE will be defined otherwise):
 *
 *		PM286	- 286 protected mode
 *		PM386	- 386 protected mode
 */

#if	defined(TNT) || defined(DOSX) || defined(DPMI32) || defined(DOS4GW)	\
	|| defined(DJGPP) || defined(WINDPMI32)
#define	PM386
#elif defined(DPMI16) || defined(WINDPMI16)
#define	PM286
#else
#define	REALMODE
#endif

/* Provide definitions for the real mode register structures passed to
 * the PM_int86() and PM_int86x() routines.
 */

#if defined(REALMODE) || defined(PM286) || defined(__SC__)
typedef union REGS RMREGS;
typedef struct SREGS RMSREGS;
#else
struct _RMWORDREGS {
	unsigned short ax, bx, cx, dx, si, di, cflag, flags;
	};

struct _RMBYTEREGS {
    unsigned char   al, ah, bl, bh, cl, ch, dl, dh;
	};

typedef union {
	struct  _RMWORDREGS x;
	struct  _RMBYTEREGS h;
	} RMREGS;

typedef struct {
	unsigned short  es;
	unsigned short  cs;
	unsigned short  ss;
	unsigned short	ds;
	} RMSREGS;
#endif

#ifdef DJGPP
#define	_cdecl		/* GCC doesn't know about _cdecl modifiers			*/
#endif

/* For the Metaware High C/C++ compiler, there is no _cdecl calling
 * convention. The conventions can be changed, but it is a complicated
 * process involving #pragmas, and all externally referenced functions
 * will use stack based calling conventions. We also need to change the
 * global aliasing conventions to use underscores for external function
 * and variables names, so that our assembler routines will link
 * correctly (except of course the main function - man what a PAIN!).
 */

#ifdef	__HIGHC__
#define	_cdecl
#pragma Global_aliasing_convention("_%r")
extern main();
#pragma Alias(main,"main")
#endif

#ifndef	__MSDOS__
#define	__MSDOS__
#endif

/* Define a macro for creating physical base addresses from segment:offset */

#define MK_PHYS(s,o)  (((unsigned long)(s) << 4) + (unsigned long)(o))

/* Define the different types of modes supported. This is a global variable
 * that can be used to determine the type at runtime which will contain
 * one of these values.
 */

typedef enum {
	PM_realMode,
	PM_286,
	PM_386,
	} PM_mode_enum;

/* Define the different types of interrupt handlers that we support		*/

typedef void (* _cdecl PM_intHandler)(void);
typedef void (* _cdecl PM_breakHandler)(int ctrlBreakHit);
typedef void (* _cdecl PM_criticalHandler)(int *ax,int *di);
typedef void (* _cdecl PM_mouseHandler)(unsigned mask, unsigned butstate,
	unsigned x,unsigned y);

extern int _PM_modeType;

/*--------------------------- Function Prototypes -------------------------*/

#ifdef	__cplusplus
extern "C" {			/* Use "C" linkage when in C++ mode	*/
#endif

/* Routines to access data through a selector and offset. For real mode
 * and 16 bit protected mode, the offset can only be a maximum of 64k.
 */

unsigned char _cdecl PM_getByte(unsigned s, unsigned o);
unsigned short _cdecl PM_getWord(unsigned s, unsigned o);
unsigned long _cdecl PM_getLong(unsigned s, unsigned o);
void _cdecl PM_setByte(unsigned s, unsigned o, unsigned char v);
void _cdecl PM_setWord(unsigned s, unsigned o, unsigned short v);
void _cdecl PM_setLong(unsigned s, unsigned o, unsigned long v);

/* Routines for copying data between the applications data space and
 * memory accessible through a selector and offset.
 */

void _cdecl PM_memcpynf(void *dst,unsigned src_s,unsigned src_o,unsigned n);
void _cdecl PM_memcpyfn(unsigned dst_s,unsigned dst_o,void *src,unsigned n);

/* Routine to return a selector to the BIOS data area at segment 0x40 */

unsigned PM_getBIOSSelector(void);

/* Routine to return a selector to the VGA frame buffer. The selector
 * will map to the correct portion of video memory depending on the
 * current video mode (0x3, 0x7 or graphics).
 */

unsigned PM_getVGASelector(void);

/* Routine to get a selector:offset for accessing a low 1Mb memory block.
 * You dont need to free this pointer, but in 16 bit protected mode
 * the selector allocated will be re-used the next time this routine is
 * called. If you need a permanent selector, allocate it with
 * PM_createSelector instead.
 */

void PM_mapRealPointer(unsigned *sel,unsigned *off,unsigned r_seg,
	unsigned r_off);

/* Routine to create an arbritray selector to physical memory */

unsigned PM_createSelector(unsigned long base,unsigned limit);
void PM_freeSelector(unsigned sel);

/* Routine to allocate a block of conventional memory below the 1Mb
 * limit so that it can be accessed from real mode. Ensure that you free
 * the segment when you are done with it.
 *
 * This routine returns a selector and offset to the segment that has been
 * allocated, and also returns the real mode segment and offset which can
 * be passed to real mode routines. Will return 0 if memory could not be
 * allocated.
 *
 * Please note that with some DOS extenders, memory allocated with the
 * following function cannot be freed, hence it will be allocated for the
 * life of your program. Thus if you need to call a bunch of different
 * real-mode routines in your program, allocate a single large buffer at
 * program startup that can be re-used throughout the program execution.
 */

int PM_allocRealSeg(unsigned size,unsigned *sel,unsigned *off,
	unsigned *r_seg,unsigned *r_off);
void PM_freeRealSeg(unsigned sel,unsigned off);

/* Routine to call a real mode assembly language procedure. Register
 * values are passed in and out in the 'regs' and 'sregs' structures. We
 * do not provide any method of copying data from the protected mode stack
 * to the real mode stack, so if you need to pass data to real mode, you will
 * need to write a real mode assembly language hook to recieve the values
 * in registers, and to pass the data through a real mode block allocated
 * with the PM_allocRealSeg() routine.
 */

void _cdecl PM_callRealMode(unsigned seg,unsigned off, RMREGS *regs,
	RMSREGS *sregs);

/* Routines to generate real mode interrupts using the same interface that
 * is used by int86() and int86x() in realmode. This routine is need to
 * call certain BIOS and DOS functions that are not supported by some
 * DOS extenders. No translation is done on any of the register values,
 * so they must be correctly set up and translated by the calling program.
 *
 * Normally the DOS extenders will allow you to use the normal int86()
 * function directly and will pass on unhandled calls to real mode to be
 * handled by the real mode handler. However calls to int86x() with real
 * mode segment values to be loaded will cause a GPF if used with the
 * standard int86x(), so you should use these routines if you know you
 * want to call a real mode handler.
 */

int PM_int86(int intno, RMREGS *in, RMREGS *out);
int PM_int86x(int intno, RMREGS *in, RMREGS *out,
	RMSREGS *sregs);

/*------------- Functions in Professional version only --------------------*/

/* Routine to install a mouse interrupt handling routine. The
 * mouse handler routine is a normal C function, and the PM library
 * will take care of passing the correct parameters to the function,
 * and switching to a local stack.
 *
 * Note that you _must_ lock the memory containing the mouse interrupt
 * handler with the PM_lockPages() function otherwise you may encounter
 * problems in virtual memory environments.
 */

int PM_setMouseHandler(int mask,PM_mouseHandler mh);
void PM_restoreMouseHandler(void);

/* Routine to reset the mouse driver, and re-install the current
 * mouse interrupt handler if one was currently installed (since the
 * mouse reset will automatically remove this handler.
 */

void PM_resetMouseDriver(int hardReset);

/* Routines to install and remove timer and keyboard interrupt handlers.
 * The handler routines are normal C functions. If the return value from
 * the function is PM_chainInt, the previous handler will be chained
 * to, otherwise the interrupt will simply return.
 *
 * Note that you _must_ lock the memory containing the interrupt
 * handlers with the PM_lockPages() function otherwise you may encounter
 * problems in virtual memory environments.
 */

void PM_setTimerHandler(PM_intHandler ih);
void _cdecl PM_chainPrevTimer(void);
void PM_restoreTimerHandler(void);
void PM_setKeyHandler(PM_intHandler ih);
void _cdecl PM_chainPrevKey(void);
void PM_restoreKeyHandler(void);

/* Routines to install and remove the control c/break interrupt handler.
 * The handler is a normal C functions, that takes a boolean flag as a
 * parameter. This flag will be 1 if the control break key caused the
 * interrupt, or 0 if Ctrl-C caused the interrupt.
 */

void PM_setBreakHandler(PM_breakHandler bh);
void PM_restoreBreakHandler(void);

/* Routines to install and remove the critical error handler. The handler
 * is a normal C function that takes a pointer to the value in register
 * AX a pointer to the value in DI that was passed up from DOS. These
 * values are used to determine the cause of the critical error, and to
 * handle it appropriately.
 */

void PM_setCriticalHandler(PM_criticalHandler ch);
void PM_restoreCriticalHandler(void);

/* Routine to lock and unlock regions of memory under a virtual memory
 * environment. These routines _must_ be used to lock all hardware
 * and mouse interrupt handlers installed, _AND_ any global data that
 * these handler manipulate, so that they will always be present in memory
 * to handle the incoming interrupts.
 *
 * Note that it is important to call the correct routine depending on
 * whether the area being locked is code or data, so that under 32 bit
 * PM we will get the selector value correct.
 */

typedef void (*__codePtr)();

int PM_lockDataPages(void *p,unsigned len);
int PM_unlockDataPages(void *p,unsigned len);
int PM_lockCodePages(__codePtr p,unsigned len);
int PM_unlockCodePages(__codePtr p,unsigned len);

#ifdef	__cplusplus
}						/* End of "C" linkage for C++	*/
#endif

#endif /* __PMODE_H */
