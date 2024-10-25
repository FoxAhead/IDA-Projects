/*static char *SCCSID = "@(#)abios.h    6.4 92/05/08";*/

/************************************************************************/
/*                                                                      */
/* Driver Name: ADD/DM - Include Files                                  */
/*              ----------------------                                  */
/*                                                                      */
/* Source File Name: ABIOS.H                                            */
/*                                                                      */
/* Descriptive Name: ABIOS Structures/Defines for Disk and Diskette     */
/*                   and SCB Devices                                    */
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
/* 51531   08/04/92  MFA         Removable media control                */
/*                                                                      */
/*                                                                      */
/************************************************************************/

/*******************************/
/* ABIOS Entry Point Codes     */
/*******************************/

#define ABIOS_EP_START               0x00
#define ABIOS_EP_INTERRUPT           0x01
#define ABIOS_EP_TIMEOUT             0x02

/*******************************/
/* ABIOS Function Codes        */
/*******************************/

/* ABIOS Function Codes Common to all devices */

#define ABFC_DEFAULT_INT_HANDLER     0x00
#define ABFC_RET_LID_PARMS           0x01
#define ABFC_READ_DEVICE_PARMS       0x03
#define ABFC_SET_DEVICE_PARMS        0x04
#define ABFC_RESET_DEVICE            0x05

/* ABIOS Function Codes Specific to Diskette - Device ID 0x01 */

#define ABFC_DSKT_RESET_INTERRUPT    0x07
#define ABFC_DSKT_READ               0x08
#define ABFC_DSKT_WRITE              0x09
#define ABFC_DKST_FORMAT             0x0A
#define ABFC_DSKT_VERIFY             0x0B
#define ABFC_DSKT_READ_MEDIA_PARMS   0x0C
#define ABFC_DSKT_SET_MEDIA_TYPE     0x0D
#define ABFC_DSKT_READ_CHGSIGNAL     0x0E
#define ABFC_DSKT_TURN_OFF_MOTOR     0x0F
#define ABFC_DKST_INT_STATUS         0x10
#define ABFC_DSKT_GET_MEDIA_TYPE     0x11
#define ABFC_DSKT_LOCK               0x12   /* F26083 */
#define ABFC_DSKT_UNLOCK             0x13   /* F26083 */
#define ABFC_DSKT_EJECT              0x14   /* F26083 */
#define ABFC_DSKT_STATUS             0x16   /* F26083 */

/* ABIOS Function Codes Specific to Fixed Disk - Device ID 0x02 */

#define ABFC_DISK_READ               0x08
#define ABFC_DISK_WRITE              0x09
#define ABFC_DISK_WRITE_VERIFY       0x0A
#define ABFC_DISK_VERIFY             0x0B
#define ABFC_DISK_INTERRUPT_STATUS   0x0C
#define ABFC_DISK_SET_DMA_PACING     0x10
#define ABFC_DISK_RET_DMA_PACING     0x11
#define ABFC_DISK_TRANSFER_SCB       0x12
#define ABFC_DISK_DEALLOC_LID        0x14
#define ABFC_DISK_GET_SCSI_PARMS     0x1A

/* ABIOS Function Codes Specific to the SCSI Adapter - Device ID 0x17 */

#define ABFC_SCSIA_RET_DEVICE_CONFIG 0x0B
#define ABFC_SCSIA_RET_INTERRUPT_LID 0x0C
#define ABFC_SCSIA_ENABLE_CACHE      0x0D       /* ???? */
#define ABFC_SCSIA_DISABLE_CACHE     0x0E       /* ???? */
#define ABFC_SCSIA_CACHE_STATUS      0x0F       /* ???? */
#define ABFC_SCSIA_SET_DMA_PACING    0x10
#define ABFC_SCSIA_RET_DMA_PACING    0x11
#define ABFC_SCSIA_TRANSFER_SCB      0x12

/* ABIOS Function Codes Specific to the SCSI Peripheral Type - Device ID 0x18 */

#define ABFC_SCSIP_SET_DEV_TIMEOUT   0x10
#define ABFC_SCSIP_READ_DEV_TIMEOUT  0x11
#define ABFC_SCSIP_TRANSFER_SCB      0x12
#define ABFC_SCSIP_DEALLOC_SCSI_DEV  0x14
#define ABFC_SCSIP_ALLOC_SCSI_DEV    0x15
#define ABFC_SCSIP_RET_TYPE_COUNT    0x16
#define ABFC_SCSIP_ABORT             0x17

/*************************************************************************/
/*                                                                       */
/*   ABIOS REQUEST BLOCK STRUCTURES                                      */
/*                                                                       */
/*************************************************************************/

/*******************************/
/*  ABIOS Request Block Header */
/*******************************/

typedef struct _ABRBH  {                /* ABH */

  USHORT        Length;                 /* 00H -  Request Block Length  */
  USHORT        LID;                    /* 02H -  Logical ID            */
  USHORT        Unit;                   /* 04H -  Unit                  */
  USHORT        Function;               /* 06H -  Function              */
  ULONG         Reserved_1;             /* 08H -  Reserved              */
  USHORT        RC;                     /* 0CH -  Return Code           */
  USHORT        Timeout;                /* 0EH -  Time-Out              */

} ABRBH;

typedef ABRBH near *NPABRBH;

/***************************************/
/* Return LID Parms             - 0x01 */
/***************************************/

typedef struct _ABRB_RETLIDPARMS  {     /* ABRLP */

  ABRBH         abrbh;                  /* 00H - Request Block Header     */
  UCHAR         HwIntLevel;             /* 10H - Hardware Interrupt Level */
  UCHAR         ArbLevel;               /* 11H - Arbitration Level        */
  USHORT        DeviceID;               /* 12H - Device ID                */
  USHORT        cUnits;                 /* 14H - Count of Units           */
  USHORT        LIDFlags;               /* 16H - Logical ID Flags         */
  USHORT        RBLength;               /* 18H - Request Block Length     */
  UCHAR         SecDeviceID;            /* 1AH - Secondary Device ID      */
  UCHAR         Revision;               /* 1BH - Revision                 */
  ULONG         Reserved_1;             /* 1CH - Reserved, MBZ            */

} ABRB_RETLIDPARMS;

typedef ABRB_RETLIDPARMS near *NPABRB_RETLIDPARMS;

#define LF_16MB_SUPPORT         0x0020  /*????*/
#define LF_CONCURRENT           0x0008
#define LF_PHYSICAL_PTRS        0x0002
#define LF_LOGICAL_PTRS         0x0001


/******************************************************/
/* Diagnostics                                        */
/******************************************************/

typedef struct _ABRBDIAGS  {            /* ABD */

  UCHAR         Reserved_5;             /* Reserved                     */
  UCHAR         ErrorLogLength;         /* Error log length             */
  UCHAR         IntLevel;               /* Interrupt level              */
  UCHAR         ArbLevel;               /* Arbitration level            */
  USHORT        DeviceID;               /* Device ID                    */
  UCHAR         CmdtoCtrlr;             /* Command to controller        */
  UCHAR         St0;                    /*                              */
  UCHAR         St1;                    /*                              */
  UCHAR         St2;                    /*                              */
  UCHAR         Cylinder;               /*                              */
  UCHAR         Head;                   /*                              */
  UCHAR         Sector;                 /*                              */
  UCHAR         SectorSize;             /*                              */
} ABRBDIAGS;



/***************************************/
/* Read Device Parms (Diskette)   0x03 */
/***************************************/

typedef struct _ABRB_DSKT_READDEVPARMS { /* AB1RDP */

  ABRBH         abrbh;                  /* 00H - Request Block Header     */
  USHORT        SectorsPerTrack;        /* 10H - Sectors per track        */
  USHORT        BlockSize;              /* 12H - Size of sector in bytes  */
  USHORT        DevCtrlFlags;           /* 14H - Device Control Flags     */
  USHORT        UnitType;               /* 16H - Diskette Unit Type       */
  USHORT        Reserved_1;             /* 18H - Reserved, MBZ            */
  USHORT        Undefined_1;            /* 1AH - Undefined                */
  ULONG         MotorOffTime;           /* 1CH - Motor off time (usecs)   */
  ULONG         MotorStartTime;         /* 20H - Motor start time (usecs) */
  USHORT        Undefined_2;            /* 24H - Undefined                */
  USHORT        cCylinders;             /* 26H - Max Cylinders for drive  */
  USHORT        Undefined_3;            /* 28H - Undefined                */
  UCHAR         cHeads;                 /* 2AH - Number of heads          */
  UCHAR         RetryCount;             /* 2BH - Recommended retry count  */
  UCHAR         FillByte;               /* 2CH - Fill byte for format     */
  ULONG         HeadSettleTime;         /* 2DH - Head Settle Time         */
  UCHAR         ReadGap;                /* 31H - Gap length for RWV       */
  UCHAR         FormatGap;              /* 32H - Gap length for format    */
  UCHAR         DataLen;                /* 33H - Data Length              */

} ABRB_DSKT_READDEVPARMS;

typedef ABRB_DSKT_READDEVPARMS near *NPABRB_DSKT_READDEVPARMS;

/* BlockSize equates in ABRB_DSKT_READDEVPARMS & ABRB_DSKT_SETDEVPARMS */
#define DP_BLOCKSIZE_256        0x01    /* 256 bytes per sector        */
#define DP_BLOCKSIZE_512        0x02    /* 512 bytes per sector        */

/* DevCtrlFlag equates in ABRB_DSKT_READDEVPARMS                       */
#define DP_ABDEFGAPLEN          0x0040  /* ABIOS defines FORMAT GAP    */
#define DP_RECALREQUIRED        0x0008  /* Recalibrate is required     */
#define DP_CONCURRENT_DSKT      0x0004  /* Current diskette unit       */
#define DP_FORMATSUPPORTED      0x0002  /* Format Unit supported       */
#define DP_CHANGELINE_AVAIL     0x0001  /* Change line avail on drive  */

/* UnitType equates in ABRB_DSKT_READDEVPARMS                          */
#define DP_DRIVENOTPRES         0x00    /* Drive not present           */
#define DP_DRIVETYPE_360KB      0x01    /* 360  KB diskette drive      */
#define DP_DRIVETYPE_12OOKB     0x02    /* 1.2  MB diskette drive      */
#define DP_DRIVETYPE_720KB      0x03    /* 720  KB diskette drive      */
#define DP_DRIVETYPE_144OKB     0x04    /* 1.44 MB diskette drive      */
#define DP_DRIVETYPE_2880KB     0x06    /* 2.88 MB diskette drive      */

/***************************************/
/* Set Device Parms (Diskette)    0x04 */
/***************************************/

typedef struct _ABRB_DSKT_SETDEVPARMS { /* AB1SDP */

  ABRBH         abrbh;                  /* 00H - Request Block Header     */
  USHORT        Reserved_1;             /* 10H - Reserved, MBZ            */
  USHORT        BlockSize;              /* 12H - Block Size               */
  UCHAR         Undefined_1[29];        /* 14H - Undefined                */
  UCHAR         ReadGap;                /* 31H - Gap length for RWV       */
  UCHAR         Undefined_2;            /* 32H - Undefined                */
  UCHAR         DataLen;                /* 33H - Data Length              */

} ABRB_DSKT_SETDEVPARMS;

typedef ABRB_DSKT_SETDEVPARMS near *NPABRB_DSKT_SETDEVPARMS;


/****************************************************/
/* Reset/Initialize            (Diskette)     0x05  */
/****************************************************/
typedef struct _ABRB_DSKT_RESET  {      /* AB1RS */

  ABRBH         abrbh;                  /* 00H - Request Block Header      */
  USHORT        Reserved_1;             /* 10H - Reserved, MBZ             */

} ABRB_DSKT_RESET;

typedef ABRB_DSKT_RESET near *NPABRB_DSKT_RESET;


/****************************************************/
/* Disable Interrupt           (Diskette)     0x07  */
/****************************************************/
typedef struct _ABRB_DISABLE  {         /* AB1DI */

  ABRBH         abrbh;                  /* 00H - Request Block Header      */
  UCHAR         Undefined_1[8];         /* 10H - Undefined                 */
  USHORT        Reserved_1;             /* 18H - Reserved, MBZ             */

} ABRB_DSKT_DISABLE;

typedef ABRB_DSKT_DISABLE near *NPABRB_DSKT_DISABLE;


/******************************************************/
/* Read, Write, Verify (Diskette)    0x08,0x09,0x0B   */
/******************************************************/

typedef struct _ABRB_DSKT_RWV  {        /* AB1RWV */

  ABRBH         abrbh;                  /* 00H - Request Block Header      */
  USHORT        Reserved_1;             /* 10H - Reserved, MBZ             */
  ULONG         pIObuffer;              /* 12H - Logical ptr to I/O buffer */
  ULONG         Reserved_2;             /* 16H - Reserved, MBZ             */
  ULONG         ppIObuffer;             /* 1AH - Physical ptr to I/O buffer*/
  USHORT        Reserved_3;             /* 1EH - Reserved, MBZ             */
  ULONG         WaitTime;               /* 20H - Wait time before resuming */
  USHORT        cSectors;               /* 24H - Count of sectors to xfer  */
  USHORT        Cylinder;               /* 26H - Cylinder number (0-based) */
  USHORT        Undefined_1;            /* 28H - Undefined                 */
  UCHAR         Head;                   /* 2AH - Head number (0-based)     */
  UCHAR         Undefined_2[6];         /* 2BH - Undefined                 */
  USHORT        Sector;                 /* 31H - Sector number (1-based)   */
  ABRBDIAGS     DiagS;                  /* 33H - Diagnostic status         */
} ABRB_DSKT_RWV;

typedef ABRB_DSKT_RWV near *NPABRB_DSKT_RWV;


/******************************************************/
/* Format                        (Diskette)    0x0A   */
/******************************************************/

typedef struct _ABRB_DSKT_FORMAT  {     /* AB1FMT */

  ABRBH         abrbh;                  /* 00H - Request Block Header      */
  USHORT        Reserved_1;             /* 10H - Reserved, MBZ             */
  ULONG         pFormatTable;           /* 12H - Log ptr to format table   */
  ULONG         Reserved_2;             /* 16H - Reserved, MBZ             */
  ULONG         ppFormatTable;          /* 1AH - Phys ptr to format table  */
  USHORT        Reserved_3;             /* 1EH - Reserved, MBZ             */
  ULONG         WaitTime;               /* 20H - Wait time before resuming */
  USHORT        Subfunction;            /* 24H - Subfunction number        */
  USHORT        Cylinder;               /* 26H - Cylinder number (0-based) */
  USHORT        Undefined_1;            /* 28H - Undefined                 */
  UCHAR         Head;                   /* 2AH - Head number (0-based)     */
} ABRB_DSKT_FMT;

typedef ABRB_DSKT_FMT near *NPABRB_DSKT_FMT;

/***************************************/
/* Read Media Parms (Diskette)    0x0C */
/***************************************/

typedef struct _ABRB_DSKT_READMEDIAPARMS {   /* AB1RMP */

  ABRBH         abrbh;                  /* 00H - Request Block Header      */
  USHORT        SectorsPerTrack;        /* 10H - Sectors per track         */
  USHORT        BlockSize;              /* 12H - Size of sector in bytes   */
  USHORT        Undefined_1;            /* 14H - Undefined                 */
  USHORT        Reserved_1;             /* 16H - Reserved, MBZ             */
  UCHAR         Undefined_2[14];        /* 18H - Undefined                 */
  USHORT        cCylinders;             /* 26H - Number of cylinders       */
  USHORT        Undefined_3;            /* 28H - Undefined                 */
  UCHAR         cHeads;                 /* 2AH - Number of heads           */
  UCHAR         Undefined_4[6];         /* 2BH - Undefined                 */
  UCHAR         ReadGap;                /* 31H - Gap length for RWV        */
  UCHAR         FormatGap;              /* 32H - Gap length for format     */
  UCHAR         DataLen;                /* 33H - Data Length               */

} ABRB_DSKT_READMEDIAPARMS;

typedef ABRB_DSKT_READMEDIAPARMS near *NPABRB_DSKT_READMEDIAPARMS;

/***********************************************/
/* Set Media Type for Format (Diskette)   0x0D */
/***********************************************/

typedef struct _ABRB_DSKT_SETMEDIATYPE {   /* AB1SMT */

  ABRBH         abrbh;                  /* 00H - Request Block Header      */
  USHORT        SectorsPerTrack;        /* 10H - Sectors per track         */
  USHORT        BlockSize;              /* 12H - Size of sector in bytes   */
  USHORT        Undefined_1;            /* 14H - Undefined                 */
  USHORT        Reserved_1;             /* 16H - Reserved, MBZ             */
  UCHAR         Undefined_2[8];         /* 18H - Undefined                 */
  ULONG         WaitTime;               /* 20H - Wait time before resuming */
  USHORT        Undefined_3;            /* 24H - Undefined                 */
  USHORT        cTracks;                /* 26H - Number of tracks to format*/
  ULONG         Undefined_4;            /* 28H - Undefined                 */
  UCHAR         FillByte;               /* 2CH - Fill byte for format      */
  UCHAR         Undefined_5[5];         /* 2DH - Undefined                 */
  UCHAR         FormatGap;              /* 32H - Gap length for format     */

} ABRB_DSKT_SETMEDIATYPE;

typedef ABRB_DSKT_SETMEDIATYPE near *NPABRB_DSKT_SETMEDIATYPE;

/***********************************************/
/* Read Change Line Status   (Diskette)   0x0E */
/***********************************************/

typedef struct _ABRB_DSKT_READCHGLINE { /* AB1RCL */

  ABRBH         abrbh;                  /* 00H - Request Block Header      */
  UCHAR         ChangeLineStatus;       /* 10H - Change Line status        */
  UCHAR         Undefined_1[5];         /* 11H - Undefined                 */
  USHORT        Reserved_1;             /* 16H - Reserved, MBZ             */

} ABRB_DSKT_READCHGLINE;

typedef ABRB_DSKT_READCHGLINE near *NPABRB_DSKT_READCHGLINE;

/* ChangeLineStatus equates in ABRB_DSKT_REACHGLINE                       */
#define CHANGELINE_INACTIVE     0x00    /* Change Line Inactive           */
#define CHANGELINE_ACTIVE       0x06    /* Change Line Active             */


/***********************************************/
/* Turn Off Motor            (Diskette)   0x0F */
/***********************************************/

typedef struct _ABRB_DSKT_MOTOROFF  {   /* AB1MO  */

  ABRBH         abrbh;                  /* 00H - Request Block Header      */
  UCHAR         Undefined_1[6];         /* 10H - Undefined                 */
  USHORT        Reserved_1;             /* 16H - Reserved, MBZ             */

} ABRB_DSKT_MOTOROFF;

typedef ABRB_DSKT_MOTOROFF    near *NPABRB_DSKT_MOTOROFF;


/***********************************************/
/* Interrupt Status          (Diskette)   0x10 */
/***********************************************/

typedef struct _ABRB_DSKT_INTRSTATUS {  /* AB1IS */

  ABRBH         abrbh;                  /* 00H - Request Block Header      */
  UCHAR         InterruptStatus;        /* 10H - Interrupt Status          */
  UCHAR         Undefined_1[5];         /* 11H - Undefined                 */
  USHORT        Reserved_1;             /* 16H - Reserved, MBZ             */

} ABRB_DSKT_INTRSTATUS;

typedef ABRB_DSKT_INTRSTATUS near *NPABRB_DSKT_INTRSTATUS;

/* InterruptStatus equates in ABRB_DSKT_INTRSTATUS                        */
#define NO_INTERRUPT            0x00    /* No Interrupt                   */
#define INTERRUPT_PENDING       0x01    /* Interrupt Pending              */


/***********************************************/
/* Get Media Type            (Diskette)   0x11 */
/***********************************************/

typedef struct _ABRB_DSKT_GETMEDIATYPE { /* AB1GMT */

  ABRBH         abrbh;                  /* 00H - Request Block Header      */
  UCHAR         MediaType;              /* 10H - Diskette Media Type       */
  UCHAR         Undefined_1[5];         /* 11H - Undefined                 */
  USHORT        Reserved_1;             /* 16H - Reserved, MBZ             */

} ABRB_DSKT_GETMEDIATYPE;

typedef ABRB_DSKT_GETMEDIATYPE near *NPABRB_DSKT_GETMEDIATYPE;

/* MediaType equates in ABRB_DSKT_GETMEDIATYPE                            */
#define MEDIA1MB                     0x03
#define MEDIA2MB                     0x04
#define MEDIA4MB                     0x06

/*********************************************************/      /* F26083 */
/* Drive control Functions        (Diskette)   0x12 0x13 0x14 */ /* F26083 */
/*********************************************************/      /* F26083 */
#define AB_DRIVE_LOCKED   0x0001   /* 51531 */

typedef struct _ABRB_DSKT_CONTROL {    /* AB1GMT */       /* F26083 */

  ABRBH         abrbh;                  /* 00H - Request Block Header      */ /* F26083 */
  UCHAR         LockStatus;             /* 10H - Reserved                  */ /* F26083 */
  UCHAR         LockCount;              /* 11H - Reserved                  */ /* F26083 */

} ABRB_DSKT_CONTROL;                                      /* F26083 */

typedef ABRB_DSKT_CONTROL near *NPABRB_DSKT_CONTROL;     /* F26083 */


/***************************************/
/* Read Device Parms (Fixed Disk) 0x03 */
/***************************************/

typedef struct _ABRB_DISK_READDEVPARMS {  /* AB2RDP */

  ABRBH         abrbh;                  /* 00H - Request Block Header      */
  USHORT        SectorsPerTrack;        /* 10H - Sectors per track         */
  USHORT        BlockSize;              /* 12H - Size of sector in bytes   */
  USHORT        DevCtrlFlags;           /* 14H - Device Control Flags      */
  UCHAR         LUN;                    /* 16H - Logical Unit Number (SCSI)*/
  UCHAR         Undefined_1;            /* 17H - Undefined                 */
  ULONG         cCylinders;             /* 18H - Count of cylinders        */
  UCHAR         cHead;                  /* 1CH - Count of heads            */
  UCHAR         RetryCount;             /* 1DH - Suggested retry count     */
  USHORT        Undefined_2;            /* 1EH - Undefined                 */
  ULONG         cRBA;                   /* 20H - Count of RBAs on this unit*/
  ULONG         Reserved_1;             /* 24H - Reserved                  */
  USHORT        Reserved_2;             /* 28H - Reserved                  */
  USHORT        Undefined_3;            /* 2AH - Undefined                 */
  USHORT        MaxXferCount;           /* 2CH - Max blocks per transfer   */

} ABRB_DISK_READDEVPARMS;

typedef ABRB_DISK_READDEVPARMS near *NPABRB_DISK_READDEVPARMS;

/* DevCtrlFlag equates in ABRB_DISK_READDEVPARMS                           */
#define DP_SCBXFER              0x8000  /* SCB Transfer Function supported */
#define DP_SCSI_DEVICE          0x4000  /* Drive is SCSI device            */
#define DP_FORMAT_UNIT          0x1000  /* Format Unit supported           */
#define DP_FORMAT_TRACK         0x0800  /* Format Track supported          */
#define DP_ST506                0x0400  /* Drive is ST506 device           */
#define DP_CONCURRENT_DISK      0x0200  /* Concurrent disk unit per LID    */
#define DP_EJECTABLE            0x0100  /* Ejectable unit                  */
#define DP_MEDIA_ORGANIZATION   0x0080  /* 0=Random, 1=Sequential          */
#define DP_LOCKING_AVAIL        0x0040  /* Locking capability supported    */
#define DP_READABLE             0x0020  /* Unit is readable                */
#define DP_CACHE_AVAIL          0x0010  /* Caching is supported            */
#define DP_WRITE_FREQUENCY      0x0008  /* 0=Write once, 1=Write many      */
#define DP_CHGLINE_DISK         0x0004  /* Change line supported           */
#define DP_POWER                0x0002  /* 0=Power on, 1=Power off         */
#define DP_LOGDATAPTR           0x0001  /* Device needs logical data poineter */

/****************************************************/
/* Reset/Initialize               (Disk)      0x05  */
/****************************************************/
typedef struct _ABRB_DISK_RESET  {      /* AB2RS */

  ABRBH         abrbh;                  /* 00H - Request Block Header      */
  USHORT        Reserved_1;             /* 10H - Reserved, MBZ             */
  UCHAR         Undefined_1[22];        /* 12H - Undefined                 */
  ULONG         WaitTime;               /* 28H - Wait time before resuming */

} ABRB_DISK_RESET;

typedef ABRB_DISK_RESET near *NPABRB_DISK_RESET;


/************************************************************************/
/* Read, Write, WriteVerify, Verify (Fixed Disk)  0x08,0x09,0x0A,0x0B   */
/************************************************************************/

typedef struct _ABRB_DISK_RWV  {        /* AB2RWV */

  ABRBH         abrbh;                  /* 00H - Request Block Header      */
  USHORT        Reserved_1;             /* 10H - Reserved, MBZ             */
  ULONG         pIObuffer;              /* 12H - Logical ptr to I/O buffer */
  USHORT        Reserved_2;             /* 16H - Reserved, MBZ             */
  USHORT        Reserved_3;             /* 18H - Reserved, MBZ             */
  ULONG         ppIObuffer;             /* 1AH - Physical ptr to I/O buffer*/
  USHORT        Reserved_4;             /* 1EH - Reserved, MBZ             */
  ULONG         RBA;                    /* 20H - RBA                       */
  ULONG         Reserved_5;             /* 24H - Reserved, MBZ             */
  ULONG         WaitTime;               /* 28H - Wait time before resuming */
  USHORT        cBlocks;                /* 2CH - Count of blocks to xfer   */
  UCHAR         Flags;                  /* 2EH - Flags                     */
  USHORT        SoftError;              /* 2FH - Soft error word           */

} ABRB_DISK_RWV;

typedef ABRB_DISK_RWV near *NPABRB_DISK_RWV;

/* Flags equates in ABRB_DSKT_RWV                                         */
#define RW_DONT_CACHE           0x01    /* Dont cache this request        */

/***********************************************/
/* Interrupt Status          (Disk)       0x0C */
/***********************************************/

typedef struct _ABRB_DISK_INTRSTATUS  { /* AB2IS */

  ABRBH         abrbh;                  /* 00H - Request Block Header      */
  UCHAR         InterruptStatus;        /* 10H - Interrupt Status          */
  UCHAR         Undefined_1[5];         /* 11H - Undefined                 */
  USHORT        Reserved_1;             /* 16H - Reserved, MBZ             */

} ABRB_DISK_INTRSTATUS;

typedef ABRB_DISK_INTRSTATUS near *NPABRB_DISK_INTRSTATUS;

/* InterruptStatus equates in ABRB_DISK_INTRSTATUS                        */
#define NO_INTERRUPT            0x00    /* No Interrupt                   */
#define INTERRUPT_PENDING       0x01    /* Interrupt Pending              */


/***********************************************/
/* Set DMA Pacing            (Disk)       0x10 */
/***********************************************/

typedef struct _ABRB_DISK_SETDMAPACING {  /* AB2SDMA */

  ABRBH         abrbh;                  /* 00H - Request Block Header      */
  UCHAR         DMAPacing;              /* 10H - DMA Pacing value          */
  UCHAR         Undefined_1[5];         /* 11H - Undefined                 */
  USHORT        Reserved_1;             /* 16H - Reserved, MBZ             */
  UCHAR         Undefined_2[16];        /* 18H - Undefined                 */
  ULONG         WaitTime;               /* 28H - Wait Time before resuming */

} ABRB_DISK_SETDMAPACING;

typedef ABRB_DISK_SETDMAPACING near *NPABRB_DISK_SETDMAPACING;


/***********************************************/
/* Return DMA Pacing         (Disk)       0x11 */
/***********************************************/

typedef struct _ABRB_DISK_RETDMAPACING { /* AB2RDMA */

  ABRBH         abrbh;                  /* 00H - Request Block Header      */
  UCHAR         DMAPacing;              /* 10H - Current DMA pacing value  */
  UCHAR         Undefined_1[5];         /* 11H - Undefined                 */
  USHORT        Reserved_1;             /* 16H - Reserved, MBZ             */

} ABRB_DISK_RETDMAPACING;

typedef ABRB_DISK_RETDMAPACING near *NPABRB_DISK_RETDMAPACING;


#ifndef INCL_NO_SCB
/***********************************************/
/*  Transfer SCB Request Block  (Disk)  0x12   */
/***********************************************/

typedef struct _ABRB_DISK_XFERSCB  {    /* AB2XSCB */

  ABRBH         abrbh;                  /* 00H - Request Block Header       */
  ULONG         ppSCB;                  /* 10H - physical pointer to SCB    */
  USHORT        Reserved_1;             /* 14H - reserved, MBZ              */
  PSCBHDR       pSCBHdr;                /* 16H - logical pointer to SCB hdr */
  USHORT        Undefined_1;            /* 1AH - Undefined                  */
  USHORT        Reserved_2;             /* 1CH - reserved, MBZ              */
  PSCBHDR       pLastSCBHdr;            /* 1EH - logical ptr to last SCB hdr*/
  ULONG         Undefined_2;            /* 22H - Undefined                  */
  USHORT        Reserved_3;             /* 26H - reserved, MBZ              */
  ULONG         WaitTime;               /* 28H - Wait time before resuming  */
  USHORT        Reserved_4;             /* 2CH - reserved, MBZ              */
  UCHAR         Flags;                  /* 2EH - bits 7-1 reserved          */
                                        /* bit 0: 0-normal length SCB       */
                                        /*        1-long SCB                */
  USHORT        SoftError;              /* 2FH - Soft error word            */
  UCHAR         Undefined_3;            /* 31H - Undefined                  */
  UCHAR         Status;                 /* 32H - bits 7-1 reserved          */
                                        /* bit 0: 0-last SCB field not valid*/
                                        /*        1-last SCB field valid    */

} ABRB_DISK_XFERSCB;

typedef ABRB_DISK_XFERSCB near *NPABRB_DISK_XFERSCB;

#endif
/***********************************************/
/*  Deallocate LID              (Disk)  0x14   */
/***********************************************/

typedef struct _ABRB_DISK_DEALLOCLID {  /* AB2DL */

  ABRBH         abrbh;                  /* 00H - Request Block Header     */
  USHORT        Undefined_1;            /* 10H - Undefined                */
  USHORT        SCSIdisknum;            /* 12H - SCSI disk number         */
  USHORT        Undefined_2;            /* 14H - Undefined                */
  USHORT        Reserved_1;             /* 16H - Reserved, MBZ            */

} ABRB_DISK_DEALLOCLID;


typedef ABRB_DISK_DEALLOCLID near *NPABRB_DISK_DEALLOCLID;

/***********************************************/
/*  Get SCSI Parms              (Disk)  0x1A   */
/***********************************************/

typedef struct _ABRB_DISK_GETSCSIPARMS { /* AB2GSP */

  ABRBH         abrbh;                  /* 00H - Request Block Header     */
  USHORT        Reserved_1;             /* 10H - Reserved                 */
  UCHAR         PUN;                    /* 12H - SCSI PUN                 */
  UCHAR         LUN;                    /* 13H - SCSI LUN                 */
  UCHAR         LDN;                    /* 14H - SCSI LDN                 */
  UCHAR         AdapterIndex;           /* 15H - SCSI Adapter Index       */
  USHORT        Port;                   /* 16H - SCSI base port address   */

} ABRB_DISK_GETSCSIPARMS;

typedef ABRB_DISK_GETSCSIPARMS near *NPABRB_DISK_GETSCSIPARMS;


/****************************************************/
/* Reset/Initialize Adapter           (SCSIA) 0x05  */
/****************************************************/

typedef struct _ABRB_SCSIA_RESET_INIT  { /* AB17RSET */

  ABRBH         abrbh;                  /* 00H - Request Block Header      */
  UCHAR         ResetType;              /* 10H - Reset type                */
  UCHAR         Undefined_1[5];         /* 11H - Undefined                 */
  USHORT        Reserved_1;             /* 16H - Reserved, MBZ             */
  UCHAR         Undefined_2[16];        /* 18H - Undefined fields          */
  ULONG         WaitTime;               /* 28H - Wait time before resuming */
  UCHAR         Undefined_3[6];         /* 2CH - Undefined                 */
  UCHAR         Status;                 /* 32H - Status                    */

} ABRB_SCSIA_RESET_INIT;

typedef ABRB_SCSIA_RESET_INIT near *NPABRB_SCSIA_RESET_INIT;


/****************************************************/
/* Return Device Configuration Table  (SCSIA) 0x0B  */
/****************************************************/

typedef struct _ABRB_SCSIA_RETDEVICECFGTBL { /* AB17RDCT */

  ABRBH         abrbh;                  /* 00H - Request Block Header     */
  USHORT        Reserved_1;             /* 10H - Reserved                 */
  PBYTE         pDevCfgTbl;             /* 12H - Logical ptr to table     */
  USHORT        Reserved_2;             /* 16H - Reserved                 */

} ABRB_SCSIA_RETDEVICECFGTBL;

typedef ABRB_SCSIA_RETDEVICECFGTBL near *NPABRB_SCSIA_RETDEVICECFGTBL;


/****************************************************/
/* Return Interrupting Locical ID      (SCSIA) 0x0C */
/****************************************************/

typedef struct _ABRB_RETINTRLID { /* AB17RIL */

  ABRBH         abrbh;                  /* 00H - Request Block Header     */
  UCHAR         IntStatus;              /* 10H - Interrupt status         */
  UCHAR         Undefined_1;            /* 11H - Undefined                */
  USHORT        IntLID;                 /* 12H - Interrupting LID         */
  USHORT        Undefined_2;            /* 14H - Undefined                */
  USHORT        Reserved_1;             /* 16H - Reserved                 */

} ABRB_RETINTRLID;

typedef ABRB_RETINTRLID near *NPABRB_RETINTRLID;

/* Use the same equates for IntStatus as those defined for Interrupt   */
/* status in the Return Interrupt Status Disk ABIOS RB.                */


/****************************************************/
/* Read Device Parms                 (SCSIP)  0x03  */
/****************************************************/

typedef struct _ABRB_SCSIP_READDEVPARMS  {   /* AB18RDP */

  ABRBH         abrbh;                  /* 00H - Request Block Header     */
  USHORT        Reserved_1;             /* 10H - Reserved, MBZ            */
  UCHAR         SCB_Level;              /* 12H - SCB compatibility level  */
  UCHAR         AdapterIndex;           /* 13H - Adapter Index            */
  USHORT        DeviceFlags;            /* 14H - Device Flags             */
  UCHAR         LUN;                    /* 16H - Logical Unit Number      */
  UCHAR         PUN;                    /* 17H - Physical Unit Number     */
  UCHAR         Undefined_1[16];        /* 18H - Undefined fields         */
  USHORT        Reserved_2;             /* 28H - Reserved, MBZ            */

} ABRB_SCSIP_READDEVPARMS;

typedef ABRB_SCSIP_READDEVPARMS near *NPABRB_SCSIP_READDEVPARMS;

/* DeviceFlags equates in ABRB_SCSIP_READDEVPARMS                         */
#define DEVDEFECTIVE          0x0001    /* device found defective by POST */
#define POWEROFF              0x0002    /* device is currently powered off*/
#define CACHESUPPORT          0x0010    /* Adpater card cache supported   */


/****************************************************/
/* Reset/Initialize                  (SCSIP)  0x05  */
/****************************************************/

typedef struct _ABRB_SCSIP_RESET  {     /* AB18RS */

  ABRBH         abrbh;                  /* 00H - Request Block Header      */
  UCHAR         Undefined_1[6];         /* 10H - Undefined                 */
  USHORT        Reserved_1;             /* 16H - Reserved, MBZ             */
  UCHAR         Undefined_2[16];        /* 18H - Undefined fields          */
  ULONG         WaitTime;               /* 28H - Wait time before resuming */
  UCHAR         Undefined_3[6];         /* 2CH - Undefined                 */
  UCHAR         Status;                 /* 32H - Status                    */

} ABRB_SCSIP_RESET;

typedef ABRB_SCSIP_RESET near *NPABRB_SCSIP_RESET;

/****************************************************/
/* Set Device Time-Out               (SCSIP)  0x10  */
/****************************************************/

typedef struct _ABRB_SCSIP_SETTIMEOUT  {     /* AB18STO */

  ABRBH         abrbh;                  /* 00H - Request Block Header      */
  UCHAR         Timeout;                /* 10H - Time-out value            */
  UCHAR         Reserved_1;             /* 11H - Reserved, MBZ             */
  UCHAR         Undefined_1[4];         /* 12H - Undefined                 */
  USHORT        Reserved_2;             /* 16H - Reserved, MBZ             */
  UCHAR         Undefined_2[16];        /* 18H - Undefined fields          */
  ULONG         WaitTime;               /* 28H - Wait time before resuming */
  UCHAR         Undefined_3[6];         /* 2CH - Undefined                 */
  UCHAR         Status;                 /* 32H - Status                    */

} ABRB_SCSIP_SETTIMEOUT;

typedef ABRB_SCSIP_SETTIMEOUT near *NPABRB_SCSIP_SETTIMEOUT;


/****************************************************/
/* Read Device Time-Out              (SCSIP)  0x11  */
/****************************************************/

typedef struct _ABRB_SCSIP_READTIMEOUT  {   /* AB18RTO */

  ABRBH         abrbh;                  /* 00H - Request Block Header      */
  UCHAR         Timeout;                /* 10H - Time-out value            */
  UCHAR         Reserved_1;             /* 11H - Reserved, MBZ             */
  UCHAR         Undefined_1[4];         /* 12H - Undefined                 */
  USHORT        Reserved_2;             /* 16H - Reserved, MBZ             */

} ABRB_SCSIP_READTIMEOUT;

typedef ABRB_SCSIP_READTIMEOUT near *NPABRB_SCSIP_READTIMEOUT;


/****************************************************/
/* Transfer SCB                      (SCSIP)  0x12  */
/****************************************************/

typedef struct _ABRB_SCSIP_TRANSFERSCB { /* AB18TSCB */

  ABRBH         abrbh;                  /* 00H - Request Block Header       */
  ULONG         ppSCB;                  /* 10H - physical pointer to SCB    */
  USHORT        Reserved_1;             /* 14H - reserved, MBZ              */
  PSCBHDR       pSCBHdr;                /* 16H - logical pointer to SCB hdr */
  USHORT        Undefined_1;            /* 1AH - Undefined                  */
  USHORT        Reserved_2;             /* 1CH - reserved, MBZ              */
  UCHAR         Undefined_2[8];         /* 1EH - Undefined                  */
  USHORT        Reserved_3;             /* 26H - reserved, MBZ              */
  ULONG         WaitTime;               /* 28H - Wait time before resuming  */
  USHORT        Reserved_4;             /* 2CH - reserved, MBZ              */
  UCHAR         Flags;                  /* 2EH - bits 7-1 reserved          */
                                        /*       bit 0: 0-normal length SCB */
                                        /*              1-long SCB          */
  UCHAR         Undefined_3[3];         /* 2FH - Undefined                  */
  UCHAR         Status;                 /* 32H - bits 7-2 & 0 reserved      */
                                        /*       bit 1: 0 - CCSB not reqrd  */
                                        /*              1 - CCSB needed     */

} ABRB_SCSIP_TRANSFERSCB;

typedef ABRB_SCSIP_TRANSFERSCB near *NPABRB_SCSIP_TRANSFERSCB;

#define  NORMAL_SCB  0x00               /* Flags - Normal length SCB        */
#define  LONG_SCB    0x01               /* Flags - Long SCB                 */

#define  TSB_NOT_REQD   0x00            /* Status - TSB is not needed       */
#define  TSB_NEEDED     0x02            /* Status - TSB is needed           */


/****************************************************/
/* Deallocate SCSI Peripheral Device (SCSIP)  0x14  */
/****************************************************/

typedef struct _ABRB_SCSIP_DEALLOC      {   /* AB18DPD */

  ABRBH         abrbh;                  /* 00H - Request Block Header      */
  UCHAR         Undefined_1[6];         /* 10H - Undefined                 */
  USHORT        Reserved_1;             /* 16H - Reserved, MBZ             */

} ABRB_SCSIP_DEALLOC;

typedef ABRB_SCSIP_DEALLOC  near *NPABRB_SCSIP_DEALLOC;



/****************************************************/
/* Allocate SCSI Peripheral Device   (SCSIP)  0x15  */
/****************************************************/

typedef struct _ABRB_SCSIP_ALLOC  {     /* AB18APD */

  ABRBH         abrbh;                  /* 00H - Request Block Header      */
  UCHAR         DevType;                /* 10H - Device peripheral type    */
  UCHAR         DevFlags;               /* 11H - Device type flags         */
  USHORT        DevUnit;                /* 12H - nth device of this type   */
  USHORT        Undefined_1;            /* 14H - Undefined                 */
  USHORT        Reserved_1;             /* 16H - Reserved, MBZ             */
} ABRB_SCSIP_ALLOC;

typedef ABRB_SCSIP_ALLOC near *NPABRB_SCSIP_ALLOC;


/* DevFlags equates in RB_SCSIP_ALLOC                                   */
#define DEVTYPE_CDROM           0x05
#define DEVTYPE_REMOVABLE       0x80    /* Device media is removable    */


/****************************************************/
/* Return Peripheral Type Count      (SCSIP)  0x16  */
/****************************************************/

typedef struct _ABRB_SCSIP_RETCOUNT {   /* AB18RC  */

  ABRBH         abrbh;                  /* 00H - Request Block Header      */
  UCHAR         DevType;                /* 10H - Device Peripheral type    */
  UCHAR         DevFlags;               /* 11H - Device type flags         */
  USHORT        Undefined_1;            /* 12H - Undefined                 */
  USHORT        DevCount;               /* 14H - Count of device type      */
  USHORT        Reserved_1;             /* 16H - Reserved, MBZ             */

} ABRB_SCSIP_RETCOUNT;

typedef ABRB_SCSIP_RETCOUNT   near *NPABRB_SCSIP_RETCOUNT;


/****************************************************/
/* Abort                             (SCSIP)  0x17  */
/****************************************************/

typedef struct _ABRB_SCSIP_ABORT  {     /* AB18AB */

  ABRBH         abrbh;                  /* 00H - Request Block Header      */
  UCHAR         Undefined_1[6];         /* 10H - Undefined                 */
  USHORT        Reserved_1;             /* 16H - Reserved, MBZ             */
  UCHAR         Undefined_2[16];        /* 18H - Undefined fields          */
  ULONG         WaitTime;               /* 28H - Wait time before resuming */
  UCHAR         Undefined_3[6];         /* 2CH - Undefined                 */
  UCHAR         Status;                 /* 32H - Status                    */

} ABRB_SCSIP_ABORT;

typedef ABRB_SCSIP_ABORT near *NPABRB_SCSIP_ABORT;





#define GENERIC_ABRB_SIZE  128

/*******************************/
/* ABIOS Return Codes          */
/*******************************/

/* ABIOS Return Codes Common to all Functions */

#define ABRC_COMPLETEOK              0x0000
#define ABRC_STAGEONINTERRUPT        0x0001
#define ABRC_STAGEONTIME             0x0002
#define ABRC_NOTMYINTERRUPT          0x0005
#define ABRC_ATTENTION               0x0009
#define ABRC_SPURIOUSINTERRUPT       0x0081
#define ABRC_BUSY                    0x8000
#define ABRC_START                   0xFFFF

#define ABRC_UNSUPPORTED_LID         0xC000
#define ABRC_UNSUPPORTED_FUNCTION    0xC001
#define ABRC_UNSUPPORRTED_UNIT       0xC003
#define ABRC_UNSUPPORTED_RB_LEN      0xC004
#define ABRC_INVALID_PARM            0xC005

#define ABRC_ERRORBIT                0x8000
#define ABRC_RETRYBIT                0x0100
#define ABRC_ERRORMSK                0x00FF

/* ABIOS Return Codes Specific to Diskette - Device ID 0x01   */

#define ABRC_DSKT_WRITE_PROTECT      0x8003
#define ABRC_DSKT_MEDIA_CHANGED      0x8006
#define ABRC_DSKT_MEDIA_NOT_PRESENT  0x800D
#define ABRC_DSKT_NOCHGSIG           0x800E
#define ABRC_DSKT_INVALID_VALUE      0x800F
#define ABRC_DSKT_MEDIA_NOTSUPPORTED 0x8010
#define ABRC_DSKT_NO_MEDIA_SENSE     0x8011
#define ABRC_DSKT_RESET_FAIL         0x9009
#define ABRC_DSKT_ADDRMARK_NOTFND    0x9102
#define ABRC_DSKT_SECTOR_NOTFND      0x9104
#define ABRC_DSKT_DMA_IN_PROGRESS    0x9107
#define ABRC_DSKT_DMA_OVERRUN        0x9108
#define ABRC_DSKT_BAD_CRC            0x9110
#define ABRC_DSKT_BAD_CONTROLLER     0x9120   /* A120,B020                 */
#define ABRC_DSKT_BAD_SEEK           0x9140
#define ABRC_DSKT_GENERAL_ERROR      0x9180
#define ABRC_DSKT_UNKNOWN_MEDIA      0xC00C

/* ABIOS Return Codes Specific to Disk - Device ID 0x02   */

#define ABRC_DISK_DEV_NOT_POWERED_ON 0x8001   /*                           */
#define ABRC_DISK_DEV_BLOCK_INIT_ERR 0x8002   /*                           */
#define ABRC_DISK_DEV_NOT_ALLOCATED  0x8003   /*                           */
#define ABRC_DISK_DMA_ARB_INVALID    0x800F   /*                           */
#define ABRC_DISK_BAD_COMMAND        0x9001   /* 9101,A001,B001,B101       */
#define ABRC_DISK_ADDRMARK_NOTFND    0x9002   /* 9102,A002                 */
#define ABRC_DISK_WRITE_PROTECT      0x9003   /* 9103                      */
#define ABRC_DISK_RECORD_NOTFND      0x9004   /* 9104,A004                 */
#define ABRC_DISK_RESET_FAIL         0x9005   /* 9105,A005,A105            */
#define ABRC_DISK_MEDIA_CHANGED      0x9006   /* 9106                      */
#define ABRC_DISK_CTRL_PARM_FAIL     0x9007   /* 9107,A007,A107            */
#define ABRC_DISK_DMA_FAIL           0x9008   /* 9108                      */
#define ABRC_DISK_DEFECTIVE_SECTOR   0x900A   /*      A00A                 */
#define ABRC_DISK_BAD_TRACK          0x900B   /*      A00B                 */
#define ABRC_DISK_FORMAT_ERROR       0x900D   /*      A00D                 */
#define ABRC_DISK_CAM_RV             0x900E   /*      A00E                 */
#define ABRC_DISK_CRC                0x9010   /*      A010                 */
#define ABRC_DISK_DEVICE_FAILED      0x9014   /* 9114                      */
#define ABRC_DISK_BUS_FAULT          0x9015   /* 9115                      */
#define ABRC_DISK_BAD_CONTROLLER     0x9020   /* 9120,A020,A120,B020,B120  */
#define ABRC_DISK_EQUIP_CHECK        0x9021   /* 9121,A021,A121,B021,B121  */
#define ABRC_DISK_BAD_SEEK           0x9040   /* 9140,A040,A140            */
#define ABRC_DISK_DEVICE_NORESPONSE  0x9080   /* 9180,A080,A180,B080,B180  */
#define ABRC_DISK_DRIVE_NOTREADY     0x90AA   /* 91AA,A0AA,A1AA            */
#define ABRC_DISK_UNDEFINED_ERROR    0x90BB   /* 91BB,A0BB,A1BB,B0BB,B1BB  */
#define ABRC_DISK_WRITE_FAULT        0x90CC   /* 91CC,A0CC,A1CC            */
#define ABRC_DISK_STATUS_ERROR       0x90E0   /* 91E0                      */
#define ABRC_DISK_INCOMPLETE_SENSE   0x90FF   /* 91FF,A0FF,A1FF,B0FF,B1FF  */
#define ABRC_DISK_ECC_CORRECTED      0xA011   /*                           */

/****************************************************************/
/* Various diskette equates                                     */
/****************************************************************/

/* Equates specific to NEC Diskette Controller                              */
#define ABNEC                        0020     /* Level of NEC Controller    */
#define NEC_DSKT_READ                0xE6
#define NEC_DSKT_WRITE               0xC5
#define NEC_DSKT_FORMAT              0x4D

/* Other various diskette equates                                           */
#define ABDISKETTELID                0x0001
#define HW_CHANGELINE_ACTIVE         0x80
#define ABCHGLINEACTIVE              0x00FC


/****************************************************************/
/* Various Fixed Disk Equates                                   */
/****************************************************************/
#define ABRB_NOCACHE                 0x01  /* ABRB_Flags bit 0, set=dont cache*/
#define ABRETRYCOUNT                 0x05  /* Device Error Retry Limit        */


/*******************************/
/* ABIOS Device IDs            */
/*******************************/

#define DEVID_INTERNAL          0x00
#define DEVID_DISKETTE          0x01
#define DEVID_DISK              0x02
#define DEVID_VIDEO             0x03
#define DEVID_KEYBOARD          0x04
#define DEVID_PARALLEL          0x05
#define DEVID_ASYNC             0x06
#define DEVID_SYSTEMTIMER       0x07
#define DEVID_RTC               0x08
#define DEVID_SYSTEMSVCS        0x09
#define DEVID_NMI               0x0A
#define DEVID_MOUSE             0x0B
#define DEVID_NVRAM             0x0E
#define DEVID_DMA               0x0F
#define DEVID_POS               0x10
#define DEVID_SECURITY          0x16
#define DEVID_SCSIADAPTER       0x17
#define DEVID_GENERICSCSI       0x18
