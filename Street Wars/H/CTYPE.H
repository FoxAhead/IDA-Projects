/*
 *  ctype.h	Character Handling
 *
 *  Copyright by WATCOM International Corp. 1988-1996.  All rights reserved.
 */
#ifndef _CTYPE_H_INCLUDED
#define _CTYPE_H_INCLUDED
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

#ifndef _WCTYPE_T_DEFINED
#define _WCTYPE_T_DEFINED
#define _WCTYPE_T_DEFINED_
typedef wchar_t wint_t;
typedef wchar_t wctype_t;
#endif

#define _LOWER	0x80
#define _UPPER	0x40
#define _DIGIT	0x20
#define _XDIGT	0x10
#define _PRINT	0x08
#define _PUNCT	0x04
#define _SPACE	0x02
#define _CNTRL	0x01

_WCRTLINK extern int	isalnum(int);
_WCRTLINK extern int	isalpha(int);
_WCRTLINK extern int	iscntrl(int);
_WCRTLINK extern int	isdigit(int);
_WCRTLINK extern int	isgraph(int);
_WCRTLINK extern int	islower(int);
_WCRTLINK extern int	isprint(int);
_WCRTLINK extern int	ispunct(int);
_WCRTLINK extern int	isspace(int);
_WCRTLINK extern int	isupper(int);
_WCRTLINK extern int	isxdigit(int);
_WCRTLINK extern int	isleadbyte(int);
_WCRTLINK extern int	tolower(int);
_WCRTLINK extern int	_tolower(int);
_WCRTLINK extern int	toupper(int);
_WCRTLINK extern int	_toupper(int);
_WCRTLINK extern int	__iscsymf(int);
_WCRTLINK extern int	__iscsym(int);

_WCRTLINK extern int	iswalpha(wint_t);
_WCRTLINK extern int	iswalnum(wint_t);
_WCRTLINK extern int	iswascii(wint_t);
_WCRTLINK extern int	iswcntrl(wint_t);
_WCRTLINK extern int	iswprint(wint_t);
_WCRTLINK extern int	iswgraph(wint_t);
_WCRTLINK extern int	iswdigit(wint_t);
_WCRTLINK extern int	iswxdigit(wint_t);
_WCRTLINK extern int	iswlower(wint_t);
_WCRTLINK extern int	iswupper(wint_t);
_WCRTLINK extern int	iswspace(wint_t);
_WCRTLINK extern int	iswpunct(wint_t);

_WCRTLINK extern wctype_t wctype(const char *);
_WCRTLINK extern int	iswctype(wint_t,wctype_t);

_WCRTLINK extern wint_t	towlower(wint_t);
_WCRTLINK extern wint_t	towupper(wint_t);

#if !defined(NO_EXT_KEYS) /* extensions enabled */
 _WCRTLINK extern int	isascii(int);
 _WCRTLINK extern int	__isascii(int);
 #if !defined(__FUNCTION_DATA_ACCESS)
  #define isascii(__c) ((unsigned)(__c) <= 0x7f)
  #define __isascii(__c) ((unsigned)(__c) <= 0x7f)
 #endif
#endif

#if (defined(__SW_BR) || defined(_RTDLL))
 #define _IsTable _IsTable_br
#endif
_WCRTLINK extern const char _WCDATA _IsTable[257];

#if !defined(__FUNCTION_DATA_ACCESS)
#define isalnum(__c)   (_IsTable[(unsigned char)((__c)+1)] & \
						(_LOWER|_UPPER|_DIGIT))
#define isalpha(__c)   (_IsTable[(unsigned char)((__c)+1)] & (_LOWER|_UPPER))
#define iscntrl(__c)   (_IsTable[(unsigned char)((__c)+1)] & _CNTRL)
#define isdigit(__c)   (_IsTable[(unsigned char)((__c)+1)] & _DIGIT)
#define isgraph(__c)  ((_IsTable[(unsigned char)((__c)+1)] & \
						(_PRINT|_SPACE))==_PRINT)
#define islower(__c)   (_IsTable[(unsigned char)((__c)+1)] & _LOWER)
#define isprint(__c)   (_IsTable[(unsigned char)((__c)+1)] & _PRINT)
#define ispunct(__c)   (_IsTable[(unsigned char)((__c)+1)] & _PUNCT)
#define isspace(__c)   (_IsTable[(unsigned char)((__c)+1)] & _SPACE)
#define isupper(__c)   (_IsTable[(unsigned char)((__c)+1)] & _UPPER)
#define isxdigit(__c)  (_IsTable[(unsigned char)((__c)+1)] & _XDIGT)
#define __iscsymf(__c) (isalpha(__c)||((__c)=='_'))
#define __iscsym(__c)  (isalnum(__c)||((__c)=='_'))
#endif

#ifdef __cplusplus
};
#endif
#endif
