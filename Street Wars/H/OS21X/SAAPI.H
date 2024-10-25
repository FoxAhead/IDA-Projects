/***************************************************************************\
*
* Module Name: SAAPI.H
*
* SAA Presentation Manager Interface
*
* Copyright (c) International Business Machines Corporation 1981, 1988-1990
*
* =======================================================================
*
* Implemented for OS/2 by defining INCL_SAADEFS symbol and having a
* #include of OS2.H
*
*  INCL_SAADEFS                 - used to extract SAA definitions from files
*
\***************************************************************************/

/* extract SAA definitions out of following definitions */
#define INCL_SAADEFS

/* include non-common code too */
#define INCL_NOCOMMON

/* only Dev... Gpi... and Win... entry points are SAA */
#define INCL_WIN

/* actual definitions */
#include <os2.h>
