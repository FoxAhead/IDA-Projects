/*
 *  bios98.h	NEC BIOS functions
 *
 *  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
 */
#ifndef _BIOS_H_INCLUDED
#ifdef __cplusplus
extern "C" {
#endif
#pragma pack(1);

struct	diskinfo_t {		/* disk parameters */
	unsigned command;
	unsigned drive; 	/* drive number    */
	unsigned head;		/* head number	   */
	unsigned cylinder;
	unsigned data_len;
	unsigned sector_len;
	unsigned sector;	/* sector number   */
	unsigned nsectors;	/* number of sectors to read/write/compare  */
#ifdef __386__
	void *buffer;		/* buffer to read to,write from, or compare */
	void *result;
#else
	void __far *buffer;	/* buffer to read to,write from, or compare */
	void __far *result;
#endif
};

/* constants for BIOS disk access functions */
/* disk services */
#define _DISK_VERIFY		0x01	/* verify disk sector */
#define _DISK_DIAGNOSTIC	0x02	/* read diagnostic */
#define _DISK_INITIALIZE	0x03	/* initialize */
#define _DISK_SENSE		0x04	/* sense disk sector */
#define _DISK_WRITE		0x05	/* disk write */
#define _DISK_READ		0x06	/* disk read */
#define _DISK_RECALIBRATE	0x07	/* recalibrate */
#define _DISK_ALTERNATE 	0x08	/* assign alternate track */
#define _DISK_WRITEDDAM 	0x09	/* write deleted data */
#define _DISK_READID		0x0A	/* read ID */
#define _DISK_BADTRACK		0x0B	/* format bad track */
#define _DISK_READDDAM		0x0C	/* read deleted data */
#define _DISK_FORMATTRACK	0x0D	/* format track */
#define _DISK_OPMODE		0x0E	/* set operation mode */
#define _DISK_RETRACT		0x0F	/* retract */
#define _DISK_SEEK		0x10	/* seek disk sector */
#define _DISK_FORMATDRIVE	0x8D	/* format drive */

#define _CMD_2HD		0x0090	/* 1MB flopy disk */
#define _CMD_2DD		0x0070	/* 640KB flopy disk */
#define _CMD_2D 		0x0050	/* 320KB flopy disk */
#define _CMD_HD 		0x0080	/* hard disk */

#define _CMD_SEEK		0x1000	/* seek operation */
#define _CMD_MF 		0x4000	/* double-density / single-density */
#define _CMD_MT 		0x8000	/* multi track / single track */
#define _CMD_RETRY		0x2000	/* retry operation */

/* constants for BIOS serial communications (RS-232) support */

/* serial port services */

#define _COM_INIT	0x00	/* init serial port */
#define _COM_INITX	0x01	/* init serial port (with X parameter) */
#define _COM_GETDTL	0x02	/* get data length */
#define _COM_SEND	0x03	/* send character */
#define _COM_RECEIVE	0x04	/* receive character */
#define _COM_COMMAND	0x05	/* get command status */
#define _COM_STATUS	0x06	/* get serial port status */

/* select port */

#define _COM_CH1		0x01	/* default port */
#define _COM_CH2		0x02	/* expansion board's port */
#define _COM_CH3		0x03	/* expansion board's port */

/* serial port initializers.  One and only one constant from each of the
 * following four groups - character size, stop bit, parity, and baud rate -
 * must be specified in the initialization byte.
 */

/* character size initializers */

#define _COM_CHR7		0x08	/* 7 bits characters */
#define _COM_CHR8		0x0C	/* 8 bits characters */

/* stop bit values - on or off */

#define _COM_STOP1		0x40	/* 1 stop bit */
#define _COM_STOP2		0xC0	/* 2 stop bit */

/*  parity initializers */

#define _COM_NOPARITY	0	/* no parity */
#define _COM_ODDPARITY	0x10	/* odd parity */
#define _COM_ODD	_COM_ODDPARITY	/* odd parity */
#define _COM_EVENPARITY 0x30	/* even parity */
#define _COM_EVEN	_COM_EVENPARITY /* even parity */

/*  baud rate initializers */

#define _COM_DEFAULT		0xFF	/* default baud */
#define _COM_75 		0x00	/* 75 baud */
#define _COM_150		0x01	/* 150 baud */
#define _COM_300		0x02	/* 300 baud */
#define _COM_600		0x03	/* 600 baud */
#define _COM_1200		0x04	/* 1200 baud */
#define _COM_2400		0x05	/* 2400 baud */
#define _COM_4800		0x06	/* 4800 baud */
#define _COM_9600		0x07	/* 9600 baud */

/* command */

#define _COM_TXEN		0x01	/* transmission enable */
#define _COM_DTR		0x02	/* data terminal ready */
#define _COM_RXEN		0x04	/* enable to receive */
#define _COM_SBRK		0x08	/* send brake character */
#define _COM_ER 		0x10	/* error reset */
#define _COM_RTS		0x20	/* request to send */
#define _COM_IR 		0x40	/* internal reset */

struct com_t {
	unsigned short baud;
	unsigned short mode;
	unsigned short command;
	unsigned short tx_time;
	unsigned short rx_time;
	unsigned short size;
#ifdef __386__
	void *buffer;
#else
	void __far *buffer;
#endif
};

/* keyboard services */

#define _KEYBRD_READ	    0	/* read next character from keyboard */
#define _KEYBRD_READY	    1	/* check for keystroke */
#define _KEYBRD_SHIFTSTATUS 2	/* get current shift key status */
#define _KEYBRD_INITIALIZE  3	/* init keyboard interface */
#define _KEYBRD_SENSE	    4	/* sense key input status */

/* printer services */

#define _PRINTER_WRITE	0x11	/* write character to printer */
#define _PRINTER_INIT	0x10	/* initialize printer */
#define _PRINTER_STATUS 0x12	/* get printer status */
/* MS-C compatible */
#define _PRN_INIT	_PRINTER_INIT	/* initialize printer */
#define _PRN_WRITE	_PRINTER_WRITE	/* write character to printer */
#define _PRN_STRING	0x30		/* write strings to printer */
#define _PRN_STATUS	_PRINTER_STATUS /* get printer status */

/* time-of-day services */

#define _TIME_GETCLOCK	0	/* get current clock count */
#define _TIME_SETCLOCK	1	/* set current clock count */


extern unsigned short _bios_disk(unsigned __cmd,struct diskinfo_t *__diskinfo);
extern unsigned short _bios_equiplist(void);
#ifdef __386__
extern unsigned short _bios_keybrd(unsigned,unsigned char *);
extern unsigned short _bios_memsize(void);
#endif
extern unsigned short _bios_printer(unsigned __cmd,unsigned char *_data);
extern unsigned short _bios_serialcom(unsigned __cmd,unsigned __port,struct com_t *__data);
extern unsigned short _bios_timeofday(unsigned __cmd,char *__timeval);


#ifdef	__INLINE_FUNCTIONS__
#ifdef __386__
#pragma aux	_bios_keybrd	= "cmp ah,0" /*_KEYBRD_READ*/ \
				  "je key_read" \
				  "cmp ah,3" /*_KEYBRD_INITIALIZE*/ \
				  "jne skip1" \
				  "key_read: int 0x18" \
				  "jmp short skip_end" \
				  "skip1: cmp ah,1" /*_KEYBRD_READY*/ \
				  "jne skip2" \
				  "int 0x18" \
				  "or bh,bh" \
				  "jne skip_end" \
				  "xor eax,eax" \
				  "jmp short skip_end" \
				  "skip2: cmp ah,2" /*_KEYBRD_SHIFTSTATUS*/ \
				  "jne skip3" \
				  "int 0x18" \
				  "xor ah,ah" \
				  "jmp short skip_end" \
				  "skip3: mov ecx,0010H" \
				  "add ebx,ecx" \
				  "dec ebx" \
				  "mov dl,ah" /*Keep function# in dl*/\
				  "L1: mov al,cl" \
				  "dec al" \
				  "int 18H" \
				  "mov [ebx],ah" \
				  "mov ah,dl" \
				  "dec ebx" \
				  "loop L1" \
				  "skip_end:" \
				  "and eax,0ffffH" \
				  parm [ah] [ebx] \
				  modify [eax ecx dl] \
				  value [ax]
#pragma aux	_bios_memsize	= "mov ebx, 0xa3fea" \
				  "mov al, [ebx]" \
				  "and eax, 7" \
				  "inc eax" \
				  "mov bl,0x80" \
				  "mul bl" \
				  "and eax,0ffffH" \
				  modify [eax ebx] value [ax];
#endif
#endif

#pragma pack();
#define _BIOS_H_INCLUDED
#ifdef __cplusplus
};
#endif
#endif
