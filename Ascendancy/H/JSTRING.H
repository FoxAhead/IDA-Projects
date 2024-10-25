/*
 *  jstring.h	Japanese DBCS functions
 *
 *  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
 */
#ifndef _JSTRING_H_INCLUDED
#ifdef __cplusplus
extern "C" {
#endif

#ifndef _SIZE_T_DEFINED_
#define _SIZE_T_DEFINED_
typedef unsigned size_t;
#endif

#if defined(__SMALL__) || defined(__MEDIUM__) || defined(__386__)
 #define NULL	0
#else
 #define NULL	0L
#endif

/*
 * definitions for chkctype(), nthctype()
 */

#define CT_ANK	0	/* ANK */
#define CT_KJ1	1	/* 漢字第１バイト */
#define CT_KJ2	2	/* 漢字第２バイト */
#define CT_ILGL -1	/* イリーガル */

typedef unsigned char JCHAR;	/* 漢字カナ用ｃｈａｒ(char for Japan) */
typedef JCHAR	     *JSTRING;	/* 漢字文字列(string for Japan) */
typedef JCHAR __far *FJSTRING;	/* 漢字 far 文字列(far string for Japan) */
typedef unsigned short JMOJI;	/* 漢字コード(2byte code) */

/*
 *
 *	 漢字処理関数用プロトタイプ宣言
 *
 */

extern size_t	btom( const JCHAR * __s, size_t __nb );
extern size_t	mtob( const JCHAR * __s, size_t __nm );

extern JMOJI	hantozen( JMOJI __c );
extern JMOJI	zentohan( JMOJI __c );

extern int	chkctype( JCHAR __c, int __n );
extern int	nthctype( const JCHAR * __s, size_t __n );

extern JMOJI	jtolower( JMOJI __c );
extern JMOJI	jtoupper( JMOJI __c );
extern JMOJI	jtohira( JMOJI __c );
extern JMOJI	jtokata( JMOJI __c );

extern int	jisalpha( JMOJI __c );
extern int	jisdigit( JMOJI __c );
extern int	jishira( JMOJI __c );
extern int	jiskana( JMOJI __c );
extern int	jiskigou( JMOJI __c );
extern int	jisl0( JMOJI __c );
extern int	jisl1( JMOJI __c );
extern int	jisl2( JMOJI __c );
extern int	jislower( JMOJI __c );
extern int	jisprint( JMOJI __c );
extern int	jisspace( JMOJI __c );
extern int	jisupper( JMOJI __c );
extern int	jiszen( JMOJI __c );

extern JSTRING 	jgetmoji( const JCHAR * __s, JMOJI * __c );
extern unsigned short	jistojms( unsigned short __c );
extern unsigned short	jmstojis( unsigned short __msc );
extern void	jperror( const char *__msg );
extern JSTRING 	jputmoji( JCHAR * __s, JMOJI __c );
extern JSTRING 	jstradv( const JCHAR * __s, size_t __n );
extern JSTRING 	jstrcat( JCHAR * __to, const JCHAR * __from );
extern JSTRING 	jstrchr( const JCHAR * __s, JMOJI __c );
extern int	jstrcmp( const JCHAR * __s1, const JCHAR * __s2 );
extern size_t	jstrcspn( const JCHAR * __s1, const JCHAR * __s2 );
extern unsigned char * jstrerror( int __errnum );
extern int	jstricmp( const JCHAR * __s1, const JCHAR * __s2 );
extern size_t	jstrlen( const JCHAR * __s );
extern JSTRING 	jstrlwr( JCHAR * __s );
extern JSTRING 	jstrmatch( const JCHAR * __s1, const JCHAR * __s2 );
extern JSTRING 	jstrncat( JCHAR * __to, const JCHAR * __from, size_t __n );
extern int	jstrncmp( const JCHAR * __s1, const JCHAR * __s2, size_t __n );
extern JSTRING 	jstrncpy( JCHAR * __to, const JCHAR * __from, size_t __n );
extern int	jstrnicmp( const JCHAR * __s1, const JCHAR * __s2, size_t __n );
extern JSTRING 	jstrnset( JCHAR * __s, JMOJI __c, size_t __n );
extern JSTRING 	jstrrchr( const JCHAR * __s, JMOJI __c );
extern JSTRING 	jstrrev( JCHAR * __s );
extern JSTRING 	jstrset( JCHAR * __s, JMOJI __c );
extern JSTRING 	jstrskip( const JCHAR * __s1, const JCHAR * __s2 );
extern size_t	jstrspn( const JCHAR * __s1, const JCHAR * __s2 );
extern JSTRING 	jstrstr( const JCHAR * __s1, const JCHAR * __s2 );
extern JSTRING 	jstrtok( JCHAR * __targ, const JCHAR * __brk );
extern JSTRING 	jstrupr( JCHAR * __s );
/* ----------- memory model independent equivalents ----------- */
extern size_t	 __far	_fbtom( const JCHAR __far * __s, size_t __nb );
extern size_t	 __far	_fmtob( const JCHAR __far * __s, size_t __nm );
extern int	 __far	_fnthctype( const JCHAR __far * __string, size_t __n );
extern FJSTRING __far	_fjgetmoji( const JCHAR __far * __s, JMOJI __far * __c );
extern FJSTRING __far	_fjputmoji( JCHAR __far * __s, JMOJI __c );
extern FJSTRING __far	_fjstradv( const JCHAR __far * __s, size_t __n );
extern FJSTRING __far	_fjstrcat( JCHAR __far * __to, const JCHAR __far * __from );
extern FJSTRING __far	_fjstrchr( const JCHAR __far * __s, JMOJI __c );
extern int	 __far	_fjstrcmp( const JCHAR __far * __s1, const JCHAR __far * __s2 );
extern size_t	 __far	_fjstrcspn( const JCHAR __far * __s1, const JCHAR __far * __s2 );
extern int	 __far	_fjstricmp( const JCHAR __far * __s1, const JCHAR __far * __s2 );
extern size_t	 __far	_fjstrlen( const JCHAR __far * __s );
extern FJSTRING __far	_fjstrlwr( JCHAR __far * __s );
extern FJSTRING __far	_fjstrmatch( const JCHAR __far * __s1, const JCHAR __far * __s2 );
extern FJSTRING __far	_fjstrncat( JCHAR __far * __to, const JCHAR __far * __from, size_t __n );
extern int	 __far	_fjstrncmp( const JCHAR __far * __s1, const JCHAR __far * __s2, size_t __n );
extern FJSTRING __far	_fjstrncpy( JCHAR __far * __to, const JCHAR __far * __from, size_t __n );
extern int	 __far	_fjstrnicmp( const JCHAR __far * __s1, const JCHAR __far * __s2, size_t __n );
extern FJSTRING __far	_fjstrnset( JCHAR __far * __s, JMOJI __c, size_t __n );
extern FJSTRING __far	_fjstrrchr( const JCHAR __far * __s, JMOJI __c );
extern FJSTRING __far	_fjstrrev( JCHAR __far * __s );
extern FJSTRING __far	_fjstrset( JCHAR __far * __s, JMOJI __c );
extern FJSTRING __far	_fjstrskip( const JCHAR __far * __s1, const JCHAR __far * __s2 );
extern size_t	 __far	_fjstrspn( const JCHAR __far * __s1, const JCHAR __far * __s2 );
extern FJSTRING __far	_fjstrstr( const JCHAR __far * __s1, const JCHAR __far * __s2 );
extern FJSTRING __far	_fjstrtok( JCHAR __far * __targ, const JCHAR __far * __brk );
extern FJSTRING __far	_fjstrupr( JCHAR __far * __s );
/* ----------- end of memory model independent equivalents ----------- */

#define _JSTRING_H_INCLUDED
#ifdef __cplusplus
};
#endif
#endif
