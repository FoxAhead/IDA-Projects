/*
 *  locale.h
 *
 *  Copyright by WATCOM International Corp. 1988-1994.  All rights reserved.
 */
#ifndef _LOCALE_H_INCLUDED
#ifdef __cplusplus
extern "C" {
#endif
#pragma pack(1)

#define LC_CTYPE	0
#define LC_NUMERIC	1
#define LC_TIME 	2
#define LC_COLLATE	3
#define LC_MONETARY	4
#define LC_MESSAGES	5
#define LC_ALL		6

struct	lconv {
	char *decimal_point;
	char *thousands_sep;
	char *int_curr_symbol;
	char *currency_symbol;
	char *mon_decimal_point;
	char *mon_thousands_sep;
	char *mon_grouping;
	char *grouping;
	char *positive_sign;
	char *negative_sign;
	char int_frac_digits;
	char frac_digits;
	char p_cs_precedes;
	char p_sep_by_space;
	char n_cs_precedes;
	char n_sep_by_space;
	char p_sign_posn;
	char n_sign_posn;
};

#ifndef NULL
 #if defined(__SMALL__) || defined(__MEDIUM__) || defined(__386__)
  #define NULL   0
 #else
  #define NULL   0L
 #endif
#endif

extern	char *setlocale(int __category,const char *__locale);
extern	struct lconv *localeconv(void);
#pragma pack()

#define _LOCALE_H_INCLUDED
#ifdef __cplusplus
};
#endif
#endif
