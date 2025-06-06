/*
 *  jctype.h	Japanese character test macros
 *
 *  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
 */
#ifndef _JCTYPE_H_INCLUDED

/*
 *	 iskana(c)	 カナ・コード
 *	 iskpun(c)	 カナ句切文字
 *	 iskmoji(c)	 カナ文字
 *	 isalkana(c)	 英文字またはカナ文字
 *	 ispnkana(c)	 英句切文字またはカナ句切文字
 *	 isalnmkana(c)	 英数字またはカナ文字
 *	 isprkana(c)	 表示可能文字（空白を含む）
 *	 isgrkana(c)	 表示可能文字（空白を除く）
 *
 *	 iskanji(c)	 漢字第１バイト
 *	 iskanji2(c)	 漢字第２バイト
 *
 */

#include <ctype.h>

#define _K	0x01	/* Kana moji	  */
#define _KP	0x02	/* Kana punct.	  */
#define _J1	0x04	/* Kanji 1st byte */
#define _J2	0x08	/* Kanji 2nd byte */

#ifdef __cplusplus
extern "C" {
#endif
extern	int	iskana(int);
extern	int	iskpun(int);
extern	int	iskmoji(int);
extern	int	isalkana(int);
extern	int	ispnkana(int);
extern	int	isalnmkana(int);
extern	int	isprkana(int);
extern	int	isgrkana(int);
extern	int	iskanji(int);
extern	int	iskanji2(int);

/* kana, kanji type table */

#ifdef M_I86HM
extern const char __far _IsKTable[257];
#else
extern const char __near _IsKTable[257];
#endif
#ifdef __cplusplus
};
#endif

#define iskana(__c)	(_IsKTable[(unsigned char)(__c)+1] & (_K|_KP))
#define iskpun(__c)	(_IsKTable[(unsigned char)(__c)+1] & _KP)
#define iskmoji(__c)	(_IsKTable[(unsigned char)(__c)+1] & _K)
#define isalkana(__c)	(isalpha(__c) || iskmoji(__c))
#define ispnkana(__c)	(ispunct(__c) || iskpun(__c))
#define isalnmkana(__c) (isalnum(__c) || iskmoji(__c))
#define isprkana(__c)	(isprint(__c) || iskana(__c))
#define isgrkana(__c)	(isgraph(__c) || iskana(__c))

#define iskanji(__c)	(_IsKTable[(unsigned char)(__c)+1] & _J1)
#define iskanji2(__c)	(_IsKTable[(unsigned char)(__c)+1] & _J2)

#define _JCTYPE_H_INCLUDED
#endif
