/*
 *  mbstring.h	Multi-Byte Character Set (MBCS) functions
 *
 *  Copyright by WATCOM International Corp. 1988-1996.  All rights reserved.
 */
#ifndef _MBSTRING_H_INCLUDED
#define _MBSTRING_H_INCLUDED
#if !defined(_ENABLE_AUTODEPEND)
  #pragma read_only_file;
#endif
#ifdef __cplusplus
extern "C" {
#endif

#ifndef _COMDEF_H_INCLUDED
 #include <_comdef.h>
#endif

#ifndef _SIZE_T_DEFINED
#define _SIZE_T_DEFINED
#define _SIZE_T_DEFINED_
typedef unsigned size_t;
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

#ifndef NULL
 #if defined(__SMALL__) || defined(__MEDIUM__) || defined(__386__) || defined(__AXP__) || defined(__PPC__)
  #define NULL   0
 #else
  #define NULL   0L
 #endif
#endif

#ifndef _NLSCMPERROR
 #include <limits.h>
 #define _NLSCMPERROR INT_MAX
#endif

#ifndef MB_CUR_MAX
    #define MB_CUR_MAX	2
#endif
#ifndef MB_LEN_MAX
    #define MB_LEN_MAX	2
#endif

_WCRTLINK extern unsigned char *_mbscpy( unsigned char *__s1, const unsigned char *__s2 );
_WCRTLINK extern unsigned char *_mbsncpy( unsigned char *__s1, const unsigned char *__s2, size_t __n );
_WCRTLINK extern unsigned char *_mbsnbcpy( unsigned char *__s1, const unsigned char *__s2, size_t __n );
_WCRTLINK extern unsigned char *_mbscat( unsigned char *__s1, const unsigned char *__s2 );
_WCRTLINK extern unsigned char *_mbsncat( unsigned char *__s1, const unsigned char *__s2, size_t __n );
_WCRTLINK extern unsigned char *_mbsnbcat( unsigned char *__s1, const unsigned char *__s2, size_t __n );
_WCRTLINK extern unsigned char *_mbsdup( unsigned char *__src );

_WCRTLINK extern unsigned char *_mbschr( const unsigned char *__s, unsigned int __ch );
_WCRTLINK extern unsigned char *_mbsrchr( const unsigned char *__s, unsigned int __ch );
_WCRTLINK extern unsigned char *_mbsstr( const unsigned char *__s1, const unsigned char *__s2 );
_WCRTLINK extern unsigned char *_mbspbrk( const unsigned char *__s, const unsigned char *__charset );
_WCRTLINK extern unsigned char *_mbstok( unsigned char *__s, const unsigned char *__delim );

_WCRTLINK extern size_t _mbsspn( const unsigned char *__s, const unsigned char *__charset );
_WCRTLINK extern size_t _mbscspn( const unsigned char *__s, const unsigned char *__charset );
_WCRTLINK extern size_t _mbslen( const unsigned char *__s );

_WCRTLINK extern unsigned char *_mbsset( unsigned char *__s, unsigned int __ch );
_WCRTLINK extern unsigned char *_mbsnset( unsigned char *__s, unsigned int __ch, size_t __n );
_WCRTLINK extern unsigned char *_mbsnbset( unsigned char *__s, unsigned int __ch, size_t __n );
_WCRTLINK extern unsigned char *_mbsrev( unsigned char *__s );

_WCRTLINK extern int _mbscmp( const unsigned char *__s1, const unsigned char *__s2 );
_WCRTLINK extern int _mbsicmp( const unsigned char *__s1, const unsigned char *__s2 );
_WCRTLINK extern int _mbsncmp( const unsigned char *__s1, const unsigned char *__s2, size_t __n );
_WCRTLINK extern int _mbsnicmp( const unsigned char *__s1, const unsigned char *__s2, size_t __n );
_WCRTLINK extern int _mbsnbcmp( const unsigned char *__s1, const unsigned char *__s2, size_t __n );
_WCRTLINK extern int _mbsnbicmp( const unsigned char *__s1, const unsigned char *__s2, size_t __n );
_WCRTLINK extern int _mbcicmp( const unsigned char *__c1, const unsigned char *__c2 );

_WCRTLINK extern unsigned char *_mbsdec( const unsigned char *__s, const unsigned char *__ch );
_WCRTLINK extern unsigned char *_mbsinc( const unsigned char *__s );
_WCRTLINK extern void _mbccpy( unsigned char *__dest, const unsigned char *__ch );
_WCRTLINK extern int _mbccmp( const unsigned char *__s1, const unsigned char *__s2 );
_WCRTLINK extern size_t _mbclen( const unsigned char *__ch );
_WCRTLINK extern int _mbterm( const unsigned char *__ch );

_WCRTLINK extern size_t _mbsnbcnt( const unsigned char *__s, size_t __n );
_WCRTLINK extern size_t _mbsnccnt( const unsigned char *__s, size_t __n );
_WCRTLINK extern unsigned char *_mbsninc( const unsigned char *__s, size_t __count );
_WCRTLINK extern unsigned char *_mbsspnp( const unsigned char *__s, const unsigned char *__charset );

_WCRTLINK extern unsigned char *_mbslwr( unsigned char *__s );
_WCRTLINK extern unsigned char *_mbsupr( unsigned char *__s );

_WCRTLINK extern int wctomb( char *__s, wchar_t __wch );
_WCRTLINK extern size_t wcstombs( char *__s, const wchar_t *__pwcs, size_t __n );
_WCRTLINK extern int mbtowc( wchar_t *__pwc, const char *__s, size_t __n );
_WCRTLINK extern size_t mbstowcs( wchar_t *__pwcs, const char *__s, size_t __n );
_WCRTLINK extern int mblen( const char *__ch, size_t __n );

_WCRTLINK extern unsigned char *_mbvtop( unsigned int __ch, unsigned char *__addr );
_WCRTLINK extern unsigned int _mbsnextc( const unsigned char *__s );


/* Far versions */

#if !defined(NO_EXT_KEYS) /* extensions enabled */

_WCRTLINK extern unsigned char _WCFAR *_fmbscpy( unsigned char _WCFAR *__s1, const unsigned char _WCFAR *__s2 );
_WCRTLINK extern unsigned char _WCFAR *_fmbsncpy( unsigned char _WCFAR *__s1, const unsigned char _WCFAR *__s2, size_t __n );
_WCRTLINK extern unsigned char _WCFAR *_fmbsnbcpy( unsigned char _WCFAR *__s1, const unsigned char _WCFAR *__s2, size_t __n );
_WCRTLINK extern unsigned char _WCFAR *_fmbscat( unsigned char _WCFAR *__s1, const unsigned char _WCFAR *__s2 );
_WCRTLINK extern unsigned char _WCFAR *_fmbsncat( unsigned char _WCFAR *__s1, const unsigned char _WCFAR *__s2, size_t __n );
_WCRTLINK extern unsigned char _WCFAR *_fmbsnbcat( unsigned char _WCFAR *__s1, const unsigned char _WCFAR *__s2, size_t __n );
_WCRTLINK extern unsigned char _WCFAR *_fmbsdup( unsigned char _WCFAR *__src );

_WCRTLINK extern unsigned char _WCFAR *_fmbschr( const unsigned char _WCFAR *__s, unsigned int __ch );
_WCRTLINK extern unsigned char _WCFAR *_fmbsrchr( const unsigned char _WCFAR *__s, unsigned int __ch );
_WCRTLINK extern unsigned char _WCFAR *_fmbsstr( const unsigned char _WCFAR *__s1, const unsigned char _WCFAR *__s2 );
_WCRTLINK extern unsigned char _WCFAR *_fmbspbrk( const unsigned char _WCFAR *__s, const unsigned char _WCFAR *__charset );
_WCRTLINK extern unsigned char _WCFAR *_fmbstok( unsigned char _WCFAR *__s, const unsigned char _WCFAR *__delim );

_WCRTLINK extern size_t _fmbsspn( const unsigned char _WCFAR *__s, const unsigned char _WCFAR *__charset );
_WCRTLINK extern size_t _fmbscspn( const unsigned char _WCFAR *__s, const unsigned char _WCFAR *__charset );
_WCRTLINK extern size_t _fmbslen( const unsigned char _WCFAR *__s );

_WCRTLINK extern unsigned char _WCFAR *_fmbsset( unsigned char _WCFAR *__s, unsigned int __ch );
_WCRTLINK extern unsigned char _WCFAR *_fmbsnset( unsigned char _WCFAR *__s, unsigned int __ch, size_t __n );
_WCRTLINK extern unsigned char _WCFAR *_fmbsnbset( unsigned char _WCFAR *__s, unsigned int __ch, size_t __n );
_WCRTLINK extern unsigned char _WCFAR *_fmbsrev( unsigned char _WCFAR *__s );

_WCRTLINK extern int _fmbscmp( const unsigned char _WCFAR *__s1, const unsigned char _WCFAR *__s2 );
_WCRTLINK extern int _fmbsicmp( const unsigned char _WCFAR *__s1, const unsigned char _WCFAR *__s2 );
_WCRTLINK extern int _fmbsncmp( const unsigned char _WCFAR *__s1, const unsigned char _WCFAR *__s2, size_t __n );
_WCRTLINK extern int _fmbsnicmp( const unsigned char _WCFAR *__s1, const unsigned char _WCFAR *__s2, size_t __n );
_WCRTLINK extern int _fmbsnbcmp( const unsigned char _WCFAR *__s1, const unsigned char _WCFAR *__s2, size_t __n );
_WCRTLINK extern int _fmbsnbicmp( const unsigned char _WCFAR *__s1, const unsigned char _WCFAR *__s2, size_t __n );
_WCRTLINK extern int _fmbcicmp( const unsigned char _WCFAR *__c1, const unsigned char _WCFAR *__c2 );

_WCRTLINK extern unsigned char _WCFAR *_fmbsdec( const unsigned char _WCFAR *__s, const unsigned char _WCFAR *__ch );
_WCRTLINK extern unsigned char _WCFAR *_fmbsinc( const unsigned char _WCFAR *__s );
_WCRTLINK extern void _fmbccpy( unsigned char _WCFAR *__dest, const unsigned char _WCFAR *__ch );
_WCRTLINK extern int _fmbccmp( const unsigned char _WCFAR *__s1, const unsigned char _WCFAR *__s2 );
_WCRTLINK extern size_t _fmbclen( const unsigned char _WCFAR *__ch );
_WCRTLINK extern int _fmbterm( const unsigned char _WCFAR *__ch );

_WCRTLINK extern size_t _fmbsnbcnt( const unsigned char _WCFAR *__s, size_t __n );
_WCRTLINK extern size_t _fmbsnccnt( const unsigned char _WCFAR *__s, size_t __n );
_WCRTLINK extern unsigned char _WCFAR *_fmbsninc( const unsigned char _WCFAR *__s, size_t __count );
_WCRTLINK extern unsigned char _WCFAR *_fmbsspnp( const unsigned char _WCFAR *__s, const unsigned char _WCFAR *__charset );

_WCRTLINK extern unsigned char _WCFAR *_fmbslwr( unsigned char _WCFAR *__s );
_WCRTLINK extern unsigned char _WCFAR *_fmbsupr( unsigned char _WCFAR *__s );

_WCRTLINK extern int _fwctomb( char _WCFAR *__s, wchar_t __wch );
_WCRTLINK extern size_t _fwcstombs( char _WCFAR *__s, const wchar_t _WCFAR *__pwcs, size_t __n );
_WCRTLINK extern int _fmbtowc( wchar_t _WCFAR *__pwc, const char _WCFAR *__s, size_t __n );
_WCRTLINK extern size_t _fmbstowcs( wchar_t _WCFAR *__pwcs, const char _WCFAR *__s, size_t __n );
_WCRTLINK extern int _fmblen( const char _WCFAR *__ch, size_t __n );

_WCRTLINK extern unsigned char _WCFAR *_fmbvtop( unsigned int __ch, unsigned char _WCFAR *__addr );
_WCRTLINK extern unsigned int _fmbsnextc( const unsigned char _WCFAR *__s );

#endif


/* Character classification functions */
_WCRTLINK extern int (_ismbblead)( unsigned int __ch );
_WCRTLINK extern int _ismbbtrail( unsigned int __ch );

_WCRTLINK extern int _ismbcalnum( unsigned int __ch );
_WCRTLINK extern int _ismbcalpha( unsigned int __ch );
_WCRTLINK extern int _ismbccntrl( unsigned int __ch );
_WCRTLINK extern int _ismbcdigit( unsigned int __ch );
_WCRTLINK extern int _ismbcgraph( unsigned int __ch );
_WCRTLINK extern int _ismbclegal( unsigned int __ch );
_WCRTLINK extern int _ismbclower( unsigned int __ch );
_WCRTLINK extern int _ismbcprint( unsigned int __ch );
_WCRTLINK extern int _ismbcpunct( unsigned int __ch );
_WCRTLINK extern int _ismbcspace( unsigned int __ch );
_WCRTLINK extern int _ismbcupper( unsigned int __ch );
_WCRTLINK extern int _ismbcxdigit( unsigned int __ch );


/*
 * Character conversion routines applicable to all code pages.
 */
_WCRTLINK extern unsigned int	_mbbtombc( unsigned int __ch );
_WCRTLINK extern unsigned int	_mbctombb( unsigned int __ch );

_WCRTLINK extern unsigned int	_mbctolower( unsigned int __ch );
_WCRTLINK extern unsigned int	_mbctoupper( unsigned int __ch );


/*
 * Character conversion routines specific to code page 932 (Japanese).
 */
_WCRTLINK extern unsigned int	_mbdhantozen( unsigned int __ch );
_WCRTLINK extern unsigned int	_mbdzentohan( unsigned int __ch );

_WCRTLINK extern unsigned int	_mbdtolower( unsigned int __ch );
_WCRTLINK extern unsigned int	_mbdtoupper( unsigned int __ch );


/* Global data */
#if defined(__SW_BR) || defined(_RTDLL) 
 #define __MBCSIsTable __MBCSIsTable_br
 #define __IsDBCS      __IsDBCS_br
#endif
_WCRTLINK extern unsigned char	__MBCSIsTable[257];
_WCRTLINK extern int		__IsDBCS;


/* Flag used in __MBCSIsTable table */
#ifndef _MB_TABLE_FLAGS_DEFINED
    #define _MB_LEAD		0x01
    #define _MB_TABLE_FLAGS_DEFINED
#endif


/* Since only "C" locale supported, we can remap locale compare functions */
#define _mbscoll    	_mbscmp
#define _mbsicoll   	_mbsicmp
#define _mbsncoll   	_mbsncmp
#define _mbsnbcoll  	_mbsnbcmp
#define _mbsnicoll  	_mbsnicmp
#define _mbsnbicoll	_mbsnbicmp


/* _setmbcp parameter defines */
#define _MB_CP_SBCS     0
#define _MB_CP_OEM      (-2)
#define _MB_CP_ANSI     (-3)

/* MB control routines */
_WCRTLINK extern int _setmbcp( int );
_WCRTLINK extern int _getmbcp( void );


/* Implement small functions as macros for speed */
#if !defined(__FUNCTION_DATA_ACCESS)
 #ifndef _ismbblead
 #define _ismbblead(__b) ( __IsDBCS	\
			? ( __MBCSIsTable[(unsigned char)(__b)+1] & _MB_LEAD ) \
			: ( 0 ) )
 #endif
#endif
#ifndef _mbisblead
 #define _mbislead(__b)	_ismbblead(__b)
#endif


/**
 * types used by LIFEBOAT code
 **/
typedef unsigned char	_UCHAR;	    /* Character is unsigned type for DBCS */
typedef _UCHAR *	_USTRING;   /* String is unsigned type for DBCS */
typedef _UCHAR _WCFAR *	_FUSTRING;  /* Far string is unsigned type for DBCS */
typedef unsigned int	DBCODE;	    /* �����R�[�h (2-byte code) */

/**
 * character byte types 
 **/
#define _MBC_SINGLE	0	/* valid single-byte char */
#define _MBC_LEAD	1	/* Kanji 1st byte (lead byte) */
#define _MBC_TRAIL	2	/* Kanji 2nd byte (trailing byte) */
#define _MBC_ILLEGAL	(-1)	/* illegal character byte */

/**
 * prototypes used by LIFEBOAT code
 **/
_WCRTLINK extern unsigned char *_mbgetcode( unsigned char *, unsigned int *);
_WCRTLINK extern unsigned char _WCFAR *_fmbgetcode( unsigned char _WCFAR *, unsigned int *);
_WCRTLINK extern unsigned char *_mbputchar( unsigned char *, unsigned int );
_WCRTLINK extern unsigned char _WCFAR *_fmbputchar( unsigned char _WCFAR *, unsigned int );
_WCRTLINK extern int _mbsbtype( const unsigned char *, int );
_WCRTLINK extern int _fmbsbtype( const unsigned char _WCFAR *, int );
_WCRTLINK extern int _mbbtype( unsigned char, int );

/**
 * distinguish and translate Japanese DBCS
 **/
_WCRTLINK extern int _ismbchira( unsigned int );
_WCRTLINK extern int _ismbckata( unsigned int );
_WCRTLINK extern int _ismbcsymbol( unsigned int );
_WCRTLINK extern int _ismbcl0( unsigned int );
_WCRTLINK extern int _ismbcl1( unsigned int );
_WCRTLINK extern int _ismbcl2( unsigned int ); 
_WCRTLINK extern unsigned int _mbcjistojms( unsigned int );
_WCRTLINK extern unsigned int _mbcjmstojis( unsigned int );
_WCRTLINK extern unsigned int _mbctohira( unsigned int );
_WCRTLINK extern unsigned int _mbctokata( unsigned int );


#ifdef __cplusplus
};
#endif
#endif
