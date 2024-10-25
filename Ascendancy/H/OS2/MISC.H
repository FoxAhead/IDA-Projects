/*static char *SCCSID = "@(#)misc.h	6.3 92/05/08";*/

/************************************************************************/
/*                                                                      */
/* Driver Name: ADD/DM - Include Files                                  */
/*              ----------------------                                  */
/*                                                                      */
/* Source File Name: MISC.H                                             */
/*                                                                      */
/* Descriptive Name: Miscellaneous defines                              */
/*                                                                      */
/* Function:                                                            */
/*                                                                      */
/*                                                                      */
/*----------------------------------------------------------------------*/
/*                                                                      */
/* Copyright (C) 1992 IBM Corporation                                   */
/*                                                                      */
/* DISCLAIMER OF WARRANTIES.  The following [enclosed] code is          */
/* provided to you solely for the purpose of assisting you in           */
/* the development of your applications. The code is provided           */
/* "AS IS", without warranty of any kind. IBM shall not be liable       */
/* for any damages arising out of your use of this code, even if        */
/* they have been advised of the possibility of such damages.           */
/*                                                                      */
/*----------------------------------------------------------------------*/
/*                                                                      */
/* Change Log                                                           */
/*                                                                      */
/* Mark    Date      Programmer  Comment                                */
/* ----    ----      ----------  -------                                */
/* @nnnn   mm/dd/yy  NNN                                                */
/*                                                                      */
/*                                                                      */
/************************************************************************/

#define ASECTORSIZE     512
#define BYTETOSECTORSHIFT 9
#define SECTORTOBYTESHIFT 9

#define ERROR                   1
#define NO_ERROR                0

#define YES                     1
#define NO                      0

#define MAX_DRIVERS             32

#define KB  1024
#define MB  KB*KB
#define GB  MB*KB

