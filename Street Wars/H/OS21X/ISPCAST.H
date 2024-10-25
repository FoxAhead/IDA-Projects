/*************************************************************************\
*
* Module Name: ISPCAST.H
*
* OS/2 Dialog Manager typedefs for the communication block and
* declarations for the procedures used to call services of Dialog Manager
*
* (c) Copyright IBM Corporation, 1989-91. All rights reserved.
*
\*************************************************************************/

#ifndef ISPCAST_H
#define ISPCAST_H

#ifndef NO_EXT_KEYS                     /* Enable the C extension     */
#define _CDECL cdecl                    /*     keyword cdecl even if  */
#else                                   /*     extensions were        */
#define _CDECL                          /*     previously disabled.   */
#endif

#define DMCOMMBLOCK_ERROR_INFO_COUNT    6

/**********************************************************************/
/*              Typedef for the Error Information Array               */
/**********************************************************************/

typedef struct
{
  unsigned long int ReasonCode;         /* Dialog Manager Return Code */
  unsigned long int OS2ReturnCode;      /* DOS Return Code            */
} DMERRORINFO, far *PDMERRORINFO;

/**********************************************************************/
/*        Typedef for the Dialog Manager Communications Block         */
/**********************************************************************/

typedef struct
{
  unsigned long int ReturnCode;         /* Dialog Manager Return Code */
  unsigned long int ReasonCode;         /* Dialog Manager Reason Code */
  char InstanceID [8];                  /* Instance Identifier        */
  unsigned long int OS2ReturnCode;      /* DOS Return Code            */
  DMERRORINFO ErrorInfo [DMCOMMBLOCK_ERROR_INFO_COUNT];
                                        /* Error Information Array    */
  char Filler [60];                     /* Used by DM -- don't modify */
} DMCOMMBLOCK, far * PDMCOMMBLOCK;


/**********************************************************************/
/*                  Declarations for Dialog Manager                   */
/**********************************************************************/

int far _CDECL ISPCI  (PDMCOMMBLOCK, long int, char far *);
int far _CDECL ISPCI2 (PDMCOMMBLOCK, long int, char far *,
               long far *, void far *);

#endif
