/***************************************************************************\
*
* Module Name: BSE.H
*
* This file includes the definitions necessary for writing Base OS/2 applications.
*
* Copyright (c) International Business Machines Corporation 1987-1990
*
* ===========================================================================
*
* The following symbols are used in this file for conditional sections.
*
*   INCL_BASE   -  ALL of OS/2 Base
*   INCL_DOS    -  OS/2 DOS Kernel
*   INCL_SUB    -  OS/2 VIO/KBD/MOU
*   INCL_DOSERRORS -  OS/2 Errors         - only included if symbol defined
*
\***************************************************************************/

#define INCL_BASEINCLUDED

/* if INCL_BASE defined then define all the symbols */
#ifdef INCL_BASE
    #define INCL_DOS
    #define INCL_SUB
    #define INCL_DOSERRORS
#endif /* INCL_BASE */

#include <bsedos.h>       /* Base definitions            */
#include <bsesub.h>       /* VIO/KBD/MOU definitions     */
#include <bseerr.h>       /* Base error code definitions */
