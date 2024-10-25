/*static char *SCCSID = "@(#)scb.h      6.6 92/06/12";*/

/************************************************************************/
/*                                                                      */
/* Driver Name: ADD/DM - Include Files                                  */
/*              ----------------------                                  */
/*                                                                      */
/* Source File Name: SCB.H                                              */
/*                                                                      */
/* Descriptive Name: Subsystem Control Block (SCB) structures           */
/*                                                                      */
/* Function: Defines the Subsystem Control Block used by the Option     */
/*           Device Drivers written to SCSI.SYS (OS2SCSI.DMD)           */
/*           interfaces.                                                */
/*                                                                      */
/*           See ..\OEMSPEC\SCSISPEC.ASC for further information.       */
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
/* @6829   06/11/92  R. Berkoff  PTR CP20 B736829                       */
/*                               Modify default SCB Enable words        */
/*                                                                      */
/************************************************************************/

/**********************************************************************/
/* Subsystem Control Block Structure                                  */
/**********************************************************************/

typedef struct _SCB      SCB;
typedef struct _SCB FAR *PSCB;
typedef struct _SCB     *NPSCB;

typedef struct _TSB      TSB;
typedef struct _TSB FAR *PTSB;
typedef struct _TSB     *NPTSB;

typedef struct _SCBHDR      SCBHDR;
typedef struct _SCBHDR     *NPSCBHDR;
typedef struct _SCBHDR FAR *PSCBHDR;
/* ASM
PSCBHDR struc
        dd      ?
PSCBHDR ends
*/

typedef struct _SCBFORMAT      SCBFORMAT;
typedef struct _SCBFORMAT FAR *PSCBFORMAT;
typedef struct _SCBFORMAT     *NPSCBFORMAT;

/*********************************/
/*  ABIOS SCB Header             */
/*********************************/
typedef struct _SCBHDR {                /* ABSCB */

  USHORT        Reserved_1;             /* Reserved                        */
  PSCBHDR       pNextSCBHdr;            /* Logical ptr to next SCB header  */
  USHORT        Reserved_2[2];          /* Reserved                        */
  PTSB          pTSB;                   /* Logical ptr to TSB              */
  USHORT        Reserved_3[1];          /* reserved                        */
} SCBHDR;


/****************************************/
/*  SCSI Subsystem Control Block (SCB)  */
/****************************************/

typedef struct _SCB {                   /* SCB */

  USHORT        Cmd;                    /* SCB Command Code                   */
  USHORT        Enable;                 /* SCB Enable Word                    */
  ULONG         LBA;                    /* Logical Block Addr                 */
  ULONG         ppXferBuf;              /* Physical pointer to transfer buf   */
                                        /*  or scatter/gather list            */
  ULONG         XferBufLen;             /* Length of transfer or addr list    */
  ULONG         ppTSB;                  /* Physical pointer to TSB            */
  ULONG         ppNxtSCB;               /* Physical ptr to next SCB on chain  */
  union {

      struct _BLK {                     /* SCB */

          USHORT        BlockCnt;       /* Block count                        */
          USHORT        BlockSize;      /* Block length                       */
        } BLK;
      struct _CDB {                     /* SCB */

          UCHAR        SCSIcdb[12];
        } CDB;
    } EXT;
} SCB;


/**************************/
/* SCB Variant for FORMAT */
/**************************/

typedef struct _SCBFORMAT {             /* SCBFMT */

  USHORT        Cmd;                    /* SCB Command Code                   */
  USHORT        Enable;                 /* SCB Enable Word                    */
  USHORT        ModBits;                /* Modifier Bits  FD/CL               */
  USHORT        Interleave;             /* Interleave Factor                  */
  ULONG         ppXferBuf;              /* Physical pointer to transfer buf   */
                                        /*  or scatter/gather list            */
  ULONG         XferBufLen;             /* Length of transfer or addr list    */
  ULONG         ppTSB;                  /* Physical pointer to TSB            */
  ULONG         ppNxtSCB;               /* Physical ptr to next SCB on chain  */
  union {

      struct _BLK2 {                    /* SCBFMT */

          USHORT        BlockCnt;       /* Block count                        */
          USHORT        BlockSize;      /* Block length                       */
        } BLK2;
    } EXT;
} SCBFORMAT;

/****************/
/* SCBCmd codes */
/****************/

#define SCBREAD         0x1C01          /* SCB Read                           */
#define SCBWRITE        0x1C02          /* SCB Write                          */
#define SCBREADV        0x1C03          /* SCB Read with Verify               */
#define SCBWRITEV       0x1C04          /* SCB Write with Verify              */
#define SCBCMDSTATUS    0x1C07          /* SCB Get Command Complete Status    */
#define SCBCMDSENSE     0x1C08          /* SCB Req SCSI Sense Command         */
#define SCBDEVICECAP    0x1C09          /* SCB Read Device Capacity           */
#define SCBQUERYPOSINFO 0x1C0A          /* SCB Query Adapter POS Info         */
#define SCBDEVICEINQ    0x1C0B          /* SCB Device Inquiry                 */
#define SCBREASSIGNBLK  0x1C18          /* SCB Reassign Block                 */
#define SCBMAXLBA       0x1C1A          /* SCB Specify Maximum LBA            */
#define SCBSENDOTHER    0x241F          /* SCB Send Other SCSI Command        */
#define SCBPREFETCH     0x1C31          /* SCB Prefetch                       */
#define SCBFORMATUNIT   0x1C16          /* SCB Format Unit                    */

/********************/
/* SCBCmd Bit Flags */
/********************/

#define SCBCfND         0x0080          /* SCB Suppress Target Disconnect     */
#define SCBCfNS         0x0040          /* SCB Suppress Sync. Negotiation     */

/****************************************/
/* SCBEnable word bit flag definitions  */
/****************************************/
#define SCBEfRD         0x8000       /* I/O Control:  1=read,                 */
                                     /*               0=write                 */
#define SCBEfES         0x4000       /* Return TSB:   1=only on error,        */
                                     /*               0=always                */
#define SCBEfRE         0x2000       /* Retry enable: 1=enable retries,       */
                                     /*               0=disable retries       */
#define SCBEfPT         0x1000       /* SGList: 1=SCBXferBuf is SGList        */
                                     /*         0=SCBXferBuf is SCBXferBuf    */
#define SCBEfSS         0x0400       /* Suppress except: 1=suppress error     */
                                     /*                  0=don't suppress     */
#define SCBEfBB         0x0200       /* Bypass cache: 1=bypass cache          */
                                     /*               0=don't bypass          */
#define SCBEfCC         0x0001       /* Chain Condition: 1=chain              */
                                     /*                  0=no chain           */
/****************************************/
/* SCBEnable default word definitions   */
/****************************************/

#define SCBEWREAD            SCBEfRD+SCBEfES+SCBEfRE+SCBEfPT
#define SCBEWWRITE           SCBEfES+SCBEfRE+SCBEfPT
#define SCBEWREADV           SCBEfRD+SCBEfES+SCBEfRE+SCBEfBB
#define SCBEWWRITEV          SCBEfES+SCBEfRE+SCBEfPT
#define SCBEWCMDSTATUS       SCBEfRD+SCBEfES+SCBEfRE+SCBEfBB
#define SCBEWCMDSENSE        SCBEfRD+SCBEfES+SCBEfRE+SCBEfSS+SCBEfBB    //@6829
#define SCBEWDEVICECAP       SCBEfRD+SCBEfES+SCBEfRE+SCBEfBB
#define SCBEWDEVICEINQ       SCBEfRD+SCBEfES+SCBEfRE+SCBEfSS+SCBEfBB
#define SCBEWREASSIGNBLK     SCBEfES+SCBEfRE+SCBEfBB
#define SCBEWMAXLBA          0
#define SCBEWSENDOTHER       SCBEfES+SCBEfRE+SCBEfPT+SCBEfBB+SCBEfSS    //@6829
#define SCBEWPREFETCH        SCBEfRD+SCBEfES+SCBEfRE+SCBEfBB
#define SCBEWFORMATUNIT      SCBEfES+SCBEfRE+SCBEfBB
#define SCBEWDEFAULT         SCBEfES+SCBEfRE


/****************************/
/* Termination Status Block */
/****************************/

typedef struct _TSB {                /* TSB */

  USHORT        Status;              /* Ending status                         */
  USHORT        Retries;             /* Retry count                           */
  ULONG         ResidCnt;            /* Residual byte count                   */
  ULONG         ppResidBuf;          /* Residual physical buffer addr         */
  USHORT        StatusLen;           /* Additional status length              */
  UCHAR         SCSIStatus;          /* SCSI Status                           */
  UCHAR         CmdStatus;           /* Command status                        */
  UCHAR         DevError;            /* Device error code                     */
  UCHAR         CmdError;            /* Command error code                    */
  USHORT        DiagMod;             /* Diagnostic error modifier             */
  USHORT        CacheInfo;           /* Cache info word                       */
  ULONG         ppLastSCB;           /* Physical ptr to last SCB processed    */
} TSB;


/*****************************/
/* Bit Flags for TSB->Status */
/*****************************/

#define TSBSfNOERR      0x0001       /* No error has occured                  */
#define TSBSfSHORT      0x0002       /* Short length record encountered       */
#define TSBSfSPECCHK    0x0010       /* SCB Specification Check               */
#define TSBSfLONG       0x0020       /* Long record encountered               */
#define TSBSfHALT       0x0040       /* SCB Chain halted                      */
#define TSBSfINTREQ     0x0080       /* SCB Interrupt Requested               */
#define TSBSfRESIDOK    0x0100       /* Resid buffer data there               */
#define TSBSfSTATF      0x0200       /* Up to word 0F of TSB valid            */
#define TSBSfSTATX      0x0300       /* Extended TSB Format Stored            */
#define TSBSfOVERRUN    0x0400       /* Device Overrun                        */
#define TSBSfNOTINIT    0x0800       /* Device not initialized                */
#define TSBSfEXCEPT     0x1000       /* Major exception has occurred          */
#define TSBSfCHDIR      0x2000       /* Chain direction bit                   */
#define TSBSfSUSPEND    0x4000       /* SCB Suspended                         */
#define TSBSfXSTAT      0x8000       /* Extend end status word                */


/******************************/
/* Bit Flags for TSB->Retries */
/******************************/

#define     RC_ADAPTER_RETRY        0x8000    /* Adapter retry invoked       */
#define     RC_SYSTEN_CHECK_RETRY   0x0020    /* System interface check retry*/


/*******************************/
/* Equates for TSB->SCSIStatus */
/*******************************/

// Refer to SCSI.H (SCSI_STAT_*)


/******************************/
/* Equates for TSB->CmdStatus */
/******************************/

#define     CS_COMP_W_SUCCESS         0x01    /* Cmd comp w/ success         */
#define     CS_COMP_W_SUCCESS_RETRY   0x05    /* Cmd comp w/ suc. after retry*/
#define     CS_ADAPTER_HW_ERROR       0x07    /* Adapter hardware failure    */
#define     CS_IMM_CMD_COMP           0x0A    /* Immediate cmd comp          */
#define     CS_COMP_W_FAILURE         0x0C    /* Cmp comp w/ failure         */
#define     CS_COMMAND_ERROR          0x0E    /* Commnad error               */
#define     CS_SW_SEQUENCE_ERROR      0x0F    /* Software sequencing error   */


/*****************************/
/* Equates for TSB->CmdError */
/*****************************/

#define     CE_NO_ERROR               0x00    /* No error                    */
#define     CE_INVALID_PARM           0x01    /* Invalid parameter in SCB    */
#define     CE_CMD_NOT_SUPPORT        0x03    /* Commnad not supported       */
#define     CE_CMD_ABORT              0x04    /* Commnad aborted ( by system */
#define     CE_FORMAT_REJECT          0x07    /* Format reject-sequence error*/
#define     CE_ASSIGN_REJECT_1        0x08    /* Assign rej -cmd in progress */
#define     CE_ASSIGN_REJECT_2        0x09    /*          -dev already assign*/
#define     CE_CMD_REJECT             0x0A    /* Cmd rej -dev not assigned   */
#define     CE_MAX_LBA_EXCEED         0x0B    /* Max LBA exceeded            */
#define     CE_16_CARDSLOTADDR_EXCEED 0x0C    /* 16bits card slot addr range */
                                              /*                   exceeded  */
#define     CE_INVALID_DEV_FOR_CMD    0x13    /* Invalid device for commnan  */
#define     CE_ADAPTER_HW_ERR         0x20    /* Adapter hardware error      */
#define     CE_GLOBAL_CMD_TIMEOUT     0x21    /* Global commnad timeout      */
#define     CE_DMA_ERR                0x22    /* DMA error                   */
#define     CE_ADAP_BUFF_DEFECTIVE    0x23    /* Adapter buffer defective    */
#define     CE_CMD_ABORT_BY_ADAPT     0x24    /* Command aborted by adapter  */
#define     CE_ADAPT_DETECT_ERR       0x80    /* Adapt microprocessor        */
                                              /*         defected error      */

/*****************************/
/* Equates for TSB->DevError */
/*****************************/

#define     DE_NO_ERROR               0x00    /* No error                    */
#define     DE_SCSIBUS_RESET          0x01    /* SCSI bus reset occurred     */
#define     DE_SCSI_INTF_FAULT        0x02    /* SCSI interface fault        */
#define     DE_SCSI_SELCT_TIMEOUT     0x00    /* SCSI selection timeout      */
                                              /*      ( device not available)*/
#define     DE_SCSIBUS_FREE           0x00    /* Unexpected SCSI bus free    */
#define     DE_INV_SCSI_PHASE_SEQ     0x00    /* Invalid SCSI phase sequence */
#define     DE_SHORT_LEN_RECORD       0x00    /* Short length record         */


/********************************/
/* Bit Flags for TSB->CacheInfo */
/********************************/

#define     CI_CACHE_ENABLED        0x0800    /* Cache enabled               */
#define     CI_CACHE_RETRY_OCCUR    0x0400    /* Cache retry occurred        */
#define     CI_TOTAL_WRITE_HIT      0x0200    /* Total write hit             */
#define     CI_TOTAL_READ_HIt       0x0100    /* Total read hit              */

