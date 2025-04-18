/*
 *  i86.h	Defines the structs and unions used to handle the input and
 *		output registers for the Intel x86 and 386 interrupt interface
 *		routines.
 *
 *  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
 */
#ifndef _I86_H_INCLUDED
#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(1);
#undef __FILLER
#if defined(__386__) && !defined(__WINDOWS_386__)
/* dword registers */

struct DWORDREGS {
	unsigned int eax;
	unsigned int ebx;
	unsigned int ecx;
	unsigned int edx;
	unsigned int esi;
	unsigned int edi;
	unsigned int cflag;
};
 #define __FILLER(a) unsigned short a;
#else
 #define __FILLER(a)
#endif

/* word registers */

struct WORDREGS {
	unsigned short ax;  __FILLER(_1)
	unsigned short bx;  __FILLER(_2)
	unsigned short cx;  __FILLER(_3)
	unsigned short dx;  __FILLER(_4)
	unsigned short si;  __FILLER(_5)
	unsigned short di;  __FILLER(_6)
#if defined(__WINDOWS_386__)
	unsigned short cflag;
#else
	unsigned int cflag;
#endif
};

/* byte registers */

struct BYTEREGS {
	unsigned char al, ah;  __FILLER(_1)
	unsigned char bl, bh;  __FILLER(_2)
	unsigned char cl, ch;  __FILLER(_3)
	unsigned char dl, dh;  __FILLER(_4)
};

/* general purpose registers union - overlays the corresponding dword,
 * word, and byte registers.
 */

union REGS {
#if defined(__386__) && !defined(__WINDOWS_386__)
	struct DWORDREGS x;
#else
	struct WORDREGS  x;
#endif
	struct WORDREGS  w;
	struct BYTEREGS  h;
};
#define _REGS REGS

/* segment registers */

struct SREGS {
	unsigned short es, cs, ss, ds;
#if defined(__386__)
	unsigned short fs, gs;
#endif
};
#define _SREGS SREGS
    

/* intr structs */

struct REGPACKB {
	unsigned char al, ah;  __FILLER(_1)
	unsigned char bl, bh;  __FILLER(_2)
	unsigned char cl, ch;  __FILLER(_3)
	unsigned char dl, dh;  __FILLER(_4)
};

struct REGPACKW {
	unsigned short ax;  __FILLER(_1)
	unsigned short bx;  __FILLER(_2)
	unsigned short cx;  __FILLER(_3)
	unsigned short dx;  __FILLER(_4)
	unsigned short bp;  __FILLER(_5)
	unsigned short si;  __FILLER(_6)
	unsigned short di;  __FILLER(_7)
	unsigned short ds;
	unsigned short es;
#if defined(__386__) && !defined(__WINDOWS_386__)
	unsigned short fs;
	unsigned short gs;
#endif
#if defined(__WINDOWS_386__)
	unsigned short flags;
#else
	unsigned int flags;
#endif
};

struct REGPACKX {
	unsigned int   eax, ebx, ecx, edx, ebp, esi, edi;
	unsigned short ds, es, fs, gs;
	unsigned int   flags;
};

union REGPACK {
	struct REGPACKB h;
	struct REGPACKW w;
#if defined(__386__) && !defined(__WINDOWS_386__)
	struct REGPACKX x;
#else
	struct REGPACKW x;
#endif
};

/* input parm to an 'interrupt' function is union INTPACK */
/* e.g.  interrupt int10( union INTPACK r ) {}		  */

struct INTPACKX {
	unsigned gs,fs,es,ds,edi,esi,ebp,esp,ebx,edx,ecx,eax,eip,cs,flags;
};
/*
   NOTE: The gs and fs fields will not be correct unless the compiler
	 is invoked with at least the /3 switch.
*/
struct INTPACKW {
	unsigned short gs;  __FILLER(_1)
	unsigned short fs;  __FILLER(_2)
	unsigned short es;  __FILLER(_3)
	unsigned short ds;  __FILLER(_4)
	unsigned short di;  __FILLER(_5)
	unsigned short si;  __FILLER(_6)
	unsigned short bp;  __FILLER(_7)
	unsigned short sp;  __FILLER(_8)
	unsigned short bx;  __FILLER(_9)
	unsigned short dx;  __FILLER(_a)
	unsigned short cx;  __FILLER(_b)
	unsigned short ax;  __FILLER(_c)
	unsigned short ip;  __FILLER(_d)
	unsigned short cs;  __FILLER(_e)
	unsigned flags;
};
struct INTPACKB {
#if defined(__386__)
	unsigned /*gs*/ :32,/*fs*/ :32,
		 /*es*/ :32,/*ds*/ :32,
		 /*edi*/:32,/*esi*/:32,
		 /*ebp*/:32,/*esp*/:32;
#else
	unsigned /*gs*/:16,/*fs*/:16,
		 /*es*/:16,/*ds*/:16,
		 /*di*/:16,/*si*/:16,
		 /*bp*/:16,/*sp*/:16;
#endif
	unsigned char bl, bh; __FILLER(_1)
	unsigned char dl, dh; __FILLER(_2)
	unsigned char cl, ch; __FILLER(_3)
	unsigned char al, ah; __FILLER(_4)
};
union  INTPACK {
	struct INTPACKB h;
	struct INTPACKW w;
#if defined(__386__)
	struct INTPACKX x;
#else
	struct INTPACKW x;
#endif
};

/* bits defined for flags field defined in REGPACKW and INTPACKW */

enum {
    INTR_CF	= 0x0001,	/* carry */
    INTR_PF	= 0x0004,	/* parity */
    INTR_AF	= 0x0010,	/* auxiliary carry */
    INTR_ZF	= 0x0040,	/* zero */
    INTR_SF	= 0x0080,	/* sign */
    INTR_TF	= 0x0100,	/* trace */
    INTR_IF	= 0x0200,	/* interrupt */
    INTR_DF	= 0x0400,	/* direction */
    INTR_OF	= 0x0800	/* overflow */
};

extern	void _disable( void );
extern	void _enable( void );

#ifdef	__INLINE_FUNCTIONS__
 #pragma intrinsic(_disable,_enable)
#endif

extern void	delay(unsigned int __milliseconds);
#if defined(__386__) && !defined(__WINDOWS_386__)
extern int	int386( int, union REGS *, union REGS * );
extern int	int386x( int, union REGS *, union REGS *, struct SREGS * );
#else
extern int	int86( int, union REGS *, union REGS * );
extern int	int86x( int, union REGS *, union REGS *, struct SREGS * );
#endif
extern void	intr( int, union REGPACK * );
extern void	nosound( void );
extern void	segread( struct SREGS * );
extern void	sound( unsigned __frequency );

/* macros to break 'far' pointers into segment and offset components */

#define  FP_OFF(__p) ((unsigned)(__p))
#define _FP_OFF(__p) ((unsigned)(__p))

#ifdef __386__
  unsigned short FP_SEG( void __far * );
  #pragma aux	 FP_SEG = parm caller [eax dx] value [dx];
#else
  #define FP_SEG(__p) ((unsigned)((unsigned long)(void __far*)(__p) >> 16))
#endif
#define _FP_SEG FP_SEG

/* make a far pointer from segment and offset */
#define MK_FP(__s,__o) (((unsigned short)(__s)):>((void __near *)(__o)))

#pragma pack();

#define _I86_H_INCLUDED
#ifdef __cplusplus
};
#endif
#endif
