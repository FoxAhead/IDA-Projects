/*
 *  bios.h	BIOS functions
 *
 *  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
 */
#ifndef _BIOS_H_INCLUDED
#ifdef __cplusplus
extern "C" {
#endif
#pragma pack(1);

struct	_diskinfo_t {		/* disk parameters */
	unsigned drive; 	/* drive number    */
	unsigned head;		/* head number	   */
	unsigned track; 	/* track number    */
	unsigned sector;	/* sector number   */
	unsigned nsectors;	/* number of sectors to read/write/compare  */
	void __far *buffer;	/* buffer to read to,write from, or compare */
};

#if !defined(NO_EXT_KEYS) /* extensions enabled */
#define diskinfo_t _diskinfo_t
#endif

/* constants for BIOS disk access functions */
#define _DISK_RESET	0
#define _DISK_STATUS	1
#define _DISK_READ	2
#define _DISK_WRITE	3
#define _DISK_VERIFY	4
#define _DISK_FORMAT	5

/* constants for BIOS serial communications (RS-232) support */

/* serial port services */

#define _COM_INIT	0	/* init serial port */
#define _COM_SEND	1	/* send character */
#define _COM_RECEIVE	2	/* receive character */
#define _COM_STATUS	3	/* get serial port status */

/* serial port initializers.  One and only one constant from each of the
 * following four groups - character size, stop bit, parity, and baud rate -
 * must be specified in the initialization byte.
 */

/* character size initializers */

#define _COM_CHR7	2	/* 7 bits characters */
#define _COM_CHR8	3	/* 8 bits characters */

/* stop bit values - on or off */

#define _COM_STOP1	0	/* 1 stop bit */
#define _COM_STOP2	4	/* 2 stop bits */

/*  parity initializers */

#define _COM_NOPARITY	0	/* no parity */
#define _COM_ODDPARITY	8	/* odd parity */
#define _COM_SPACEPARITY 16	/* space parity */
#define _COM_EVENPARITY 24	/* even parity */

/*  baud rate initializers */

#define _COM_110	0	/* 110 baud */
#define _COM_150	32	/* 150 baud */
#define _COM_300	64	/* 300 baud */
#define _COM_600	96	/* 600 baud */
#define _COM_1200	128	/* 1200 baud */
#define _COM_2400	160	/* 2400 baud */
#define _COM_4800	192	/* 4800 baud */
#define _COM_9600	224	/* 9600 baud */

/* keyboard services */

#define _KEYBRD_READ	    0	/* read next character from keyboard */
#define _KEYBRD_READY	    1	/* check for keystroke */
#define _KEYBRD_SHIFTSTATUS 2	/* get current shift key status */

/* services for enhanced keyboards */

#define _NKEYBRD_READ		0x10	/* read next character from keyboard */
#define _NKEYBRD_READY		0x11	/* check for keystroke */
#define _NKEYBRD_SHIFTSTATUS	0x12	/* get current shift key status */

/* printer services */

#define _PRINTER_WRITE	0	/* write character to printer */
#define _PRINTER_INIT	1	/* initialize printer */
#define _PRINTER_STATUS 2	/* get printer status */

/* time-of-day services */

#define _TIME_GETCLOCK	0	/* get current clock count */
#define _TIME_SETCLOCK	1	/* set current clock count */


extern unsigned short _bios_disk(unsigned __cmd,struct diskinfo_t *__diskinfo);
extern unsigned short _bios_equiplist(void);
extern unsigned short _bios_keybrd(unsigned __cmd);
extern unsigned short _bios_memsize(void);
extern unsigned short _bios_printer(unsigned __cmd,unsigned __port,unsigned __data);
extern unsigned short _bios_serialcom(unsigned __cmd,unsigned __port,unsigned __data);
extern unsigned short _bios_timeofday(unsigned __cmd,long *__timeval);


#ifdef	__INLINE_FUNCTIONS__
#pragma aux	_bios_equiplist = 0xcd 0x11 value [ax];
#pragma aux	_bios_keybrd	= 0x88 0xe6 0xcd 0x16 0x75 0x09 \
				  0x80 0xe6 0x0f \
				  0xfe 0xce 0x75 0x02 0x29 0xc0 \
				  parm [ah] value [ax] modify [dx];
#pragma aux	_bios_memsize	= 0xcd 0x12 value [ax];
#pragma aux	_bios_printer	= 0xcd 0x17 0x8a 0xc4 0xb4 0x00 \
				  parm [ah] [dx] [al] value [ax];
#pragma aux	_bios_serialcom = 0xcd 0x14 parm [ah] [dx] [al] value [ax];
#endif

#pragma pack();
#define _BIOS_H_INCLUDED
#ifdef __cplusplus
};
#endif
#endif
