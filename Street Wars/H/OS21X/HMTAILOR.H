/*static char *SCCSID = "@(#)hmtailor.h	12.6 90/06/05";*/
/****************************************************************************\
*									     *
*  MODULE NAME: HMTAILOR.H						     *
*									     *
*	 IBM/Microsoft Confidential					     *
*									     *
*	 Copyright (c) IBM Corporation 1987, 1989			     *
*	 Copyright (c) Microsoft Corporation 1987, 1989 		     *
*									     *
*	 All Rights Reserved						     *
\****************************************************************************/
/****************************************************************************/
/* CHANGE ACTIVITY:							    */
/*									    */
/* FLAG  REASON  RLSE  DATE  ORIGIN		COMMENTS		    */
/* ---- -------- ---- ------ ------ ----------------------------------------*/
/* @PGE=DCR00002 0121 890926	     add support of multiple pages	    */
/* @BNZ=DCR01151 0200 900501	     changes to action bar Help pulldown    */
/****************************************************************************/

#define IDM_FILE	     0x7F00
#define IDM_SEARCH	     0x7F01
#define IDM_PRINT	     0x7F02
#define IDM_VIEWPORT	     0x7F05						 /* ->@PGE<- */

#define IDM_EDIT	     0x7F10
#define IDM_CLIP_COPY	     0x7F11
#define IDM_CLIP_CF	     0x7F12
#define IDM_CLIP_AF	     0x7F13
#define IDM_LIBRARIES	     0x7F14

#define IDM_OPTIONS	     0x7F20
#define IDM_VIEWPAGES	     0x7F21
#define IDM_TOC 	     0x7F23
#define IDM_OPTION_EXPLEVEL  0x7F24
#define IDM_OPTION_EXPBRANCH 0x7F25
#define IDM_OPTION_EXPALL    0x7F26
#define IDM_OPTION_COLBRANCH 0x7F27
#define IDM_OPTION_COLALL    0x7F28
#define IDM_PREVIOUS	     0x7F29

#define IDM_HELP	     0x7F30
#define IDM_HELPHELP	     0x7F31
#define IDM_HELP_EXTENDED    0x7F32
#define IDM_USING_HELP	     IDM_HELPHELP
#define IDM_GENERAL_HELP     IDM_HELP_EXTENDED
#define IDM_HELP_KEYS	     0x7F33
#define IDM_HELP_INDEX	     0x7F34

#define IDM_TUTORIAL	     0x7F37
