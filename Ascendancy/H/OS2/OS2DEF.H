/****************************** Module Header ******************************\
*
* Module Name: OS2DEF.H
*
* OS/2 Common Definitions file
*
* Copyright (c) International Business Machines Corporation 1981, 1988-1992
*
* ===========================================================================
*
* Comments at the end of each typedef line give the name tags used in
* the assembler include version of this file.
*
* The assembler include version of this file excludes lines between NOINC
* and INC comments.
*
\***************************************************************************/

#pragma info( none )
#ifndef __CHKHDR__
   #pragma info( none )
#endif
#pragma info( restore )
#ifdef __cplusplus
      extern "C" {
#endif

#ifndef __OS2DEF__
#define __OS2DEF__

#define OS2DEF_INCLUDED



/* NOINC */
#define FAR         /* this will be deleted shortly */
#define NEAR        /* this will be deleted shortly */

#define APIENTRY    _System
#define EXPENTRY    _System

#define APIENTRY16  _Far16 _Pascal
#define PASCAL16    _Far16 _Pascal
#define CDECL16     _Far16 _Cdecl

#define VOID        void
/* INC */

typedef unsigned long  APIRET;
typedef unsigned short APIRET16;
typedef unsigned long  APIRET32;

#ifndef FALSE
   #define FALSE   0
#endif

#ifndef TRUE
   #define TRUE    1
#endif

#ifndef NULL
   #ifdef __cplusplus
      #define NULL 0
   #else
     #define NULL ((void *)0)
   #endif
#endif

typedef unsigned short   SHANDLE;
typedef unsigned long    LHANDLE;

#define NULLHANDLE    ( (LHANDLE) 0)
#define NULLSHANDLE   ( (SHANDLE) 0)

/* NOINC */
#define CHAR    char            /* ch  */
#define SHORT   short           /* s   */
#define LONG    long            /* l   */

#ifndef INCL_SAADEFS
   #define INT  int             /* i   */
#endif /* !INCL_SAADEFS */
/* INC */

typedef unsigned char  UCHAR;   /* uch */
typedef unsigned short USHORT;  /* us  */
typedef unsigned long  ULONG;   /* ul  */

#ifndef INCL_SAADEFS
   typedef unsigned int UINT;   /* ui  */
#endif /* !INCL_SAADEFS */

typedef UCHAR     * _Seg16 PUCHAR16;
typedef CHAR      * _Seg16 PCHAR16;

#ifdef __cplusplus
typedef char BYTE;     /* b   */

typedef char *PSZ;
typedef char *NPSZ;

typedef char *PCH;
typedef char *NPCH;
typedef const char *PCSZ;
#else
typedef unsigned char BYTE;     /* b   */

typedef unsigned char *PSZ;
typedef unsigned char *NPSZ;

typedef unsigned char *PCH;
typedef unsigned char *NPCH;
typedef unsigned char *PCSZ;
#endif

typedef int ( APIENTRY _PFN)  ();
typedef _PFN    *PFN;
typedef int ( APIENTRY _NPFN)  ();
typedef _NPFN   *NPFN;


typedef BYTE *PBYTE;
typedef BYTE *NPBYTE;

typedef CHAR *PCHAR;
typedef SHORT *PSHORT;
typedef LONG *PLONG;

#ifndef INCL_SAADEFS
   typedef INT *PINT;
#endif /* !INCL_SAADEFS */

typedef UCHAR *PUCHAR;
typedef USHORT *PUSHORT;
typedef ULONG *PULONG;

#ifndef INCL_SAADEFS
   typedef UINT *PUINT;
#endif /* !INCL_SAADEFS */

typedef VOID   *PVOID;
typedef PVOID  *PPVOID;
typedef VOID   * _Seg16  PVOID16;

typedef unsigned long BOOL;     /* f   */
typedef BOOL *PBOOL;

typedef unsigned short  BOOL16;
typedef BOOL16     * _Seg16 PBOOL16;

/* NOINC */
#define BOOL32    BOOL
#define PBOOL32   PBOOL
/* INC */

/* Quad-word */
/* NOINC */
typedef struct _QWORD          /* qword */
{
   ULONG   ulLo;
   ULONG   ulHi;
} QWORD;
typedef QWORD *PQWORD;
/* INC */

#ifndef INCL_SAADEFS
   typedef unsigned short SEL;     /* sel */
   typedef SEL *PSEL;

   /*** Useful Helper Macros */

   /* Create untyped far pointer from selector and offset */
   #define MAKEP( sel,off ) (( void * )( void * _Seg16 )( (sel) << 16 | (off) ))
   #define MAKE16P( sel,off ) (( void * _Seg16 )( (sel) << 16 | (off) ))

   /* Extract selector or offset from far pointer */
   /* Warning:the selectorof macro should not be used*/
   /* for 32 bit objects                             */
   #define SELECTOROF(ptr)     ((((ULONG)(ptr))>>13)|7)
   #define OFFSETOF(p)         (((PUSHORT)&(p))[0])
#endif  /* !INCL_SAADEFS */

/* Cast any variable to an instance of the specified type. */
#define MAKETYPE(v, type)   (*((type *)&v))

/* Calculate the byte offset of a field in a structure of type type. */
#define FIELDOFFSET(type, field)    ((SHORT)&(((type *)0)->field))

/* Combine l & h to form a 32 bit quantity. */
#define MAKEULONG(l, h)  ((ULONG)(((USHORT)(l)) | ((ULONG)((USHORT)(h))) << 16))
#define MAKELONG(l, h)   ((LONG)MAKEULONG(l, h))

/* Combine l & h to form a 16 bit quantity. */
#define MAKEUSHORT(l, h) (((USHORT)(l)) | ((USHORT)(h)) << 8)
#define MAKESHORT(l, h)  ((SHORT)MAKEUSHORT(l, h))

/* Extract high and low order parts of 16 and 32 bit quantity */
#define LOBYTE(w)       LOUCHAR(w)
#define HIBYTE(w)       HIUCHAR(w)
#define LOUCHAR(w)      ((UCHAR)(w))
#define HIUCHAR(w)      ((UCHAR)(((USHORT)(w) >> 8) & 0xff))
#define LOUSHORT(l)     ((USHORT)((ULONG)l))
#define HIUSHORT(l)     ((USHORT)(((ULONG)(l) >> 16) & 0xffff))

/*** Common Error definitions ****/

typedef ULONG ERRORID;  /* errid */
typedef ERRORID *PERRORID;

/* Combine severity and error code to produce ERRORID */
#define MAKEERRORID(sev, error) (ERRORID)(MAKEULONG((error), (sev)))

/* Extract error number from an errorid */
#define ERRORIDERROR(errid)            (LOUSHORT(errid))

/* Extract severity from an errorid */
#define ERRORIDSEV(errid)              (HIUSHORT(errid))

/* Severity codes */
#define SEVERITY_NOERROR                    0x0000
#define SEVERITY_WARNING                    0x0004
#define SEVERITY_ERROR                      0x0008
#define SEVERITY_SEVERE                     0x000C
#define SEVERITY_UNRECOVERABLE              0x0010

/* Base component error values */

#define WINERR_BASE     0x1000  /* Window Manager                  */
#define GPIERR_BASE     0x2000  /* Graphics Presentation Interface */
#define DEVERR_BASE     0x3000  /* Device Manager                  */
#define SPLERR_BASE     0x4000  /* Spooler                         */

/*** Common types used across components */

/*** Common DOS types */

typedef LHANDLE HMODULE;        /* hmod */
typedef LHANDLE PID;            /* pid  */
typedef LHANDLE TID;            /* tid  */

#ifndef INCL_SAADEFS
   typedef USHORT  SGID;        /* sgid */
#endif  /* !INCL_SAADEFS */

typedef HMODULE *PHMODULE;
typedef PID *PPID;
typedef TID *PTID;

#ifndef INCL_SAADEFS
   #ifndef __HSEM__
       #define __HSEM__
       typedef VOID *HSEM;      /* hsem */
       typedef HSEM *PHSEM;
   #endif
#endif  /* !INCL_SAADEFS */

/*** Common SUP types */

typedef LHANDLE   HAB;         /* hab  */
typedef HAB *PHAB;

/*** Common GPI/DEV types */

typedef LHANDLE   HPS;         /* hps  */
typedef HPS *PHPS;

typedef LHANDLE   HDC;         /* hdc  */
typedef HDC *PHDC;

typedef LHANDLE   HRGN;        /* hrgn */
typedef HRGN *PHRGN;

typedef LHANDLE   HBITMAP;     /* hbm  */
typedef HBITMAP *PHBITMAP;

typedef LHANDLE   HMF;         /* hmf  */
typedef HMF *PHMF;

typedef LHANDLE   HPAL;        /* hpal */
typedef HPAL *PHPAL;

typedef LONG     COLOR;        /* clr  */
typedef COLOR *PCOLOR;

typedef struct _POINTL         /* ptl  */
{
   LONG  x;
   LONG  y;
} POINTL;
typedef POINTL *PPOINTL;
typedef POINTL *NPPOINTL;

typedef struct _POINTS         /* pts */
{
   SHORT x;
   SHORT y;
} POINTS;
typedef POINTS *PPOINTS;

typedef struct _RECTL          /* rcl */
{
   LONG  xLeft;
   LONG  yBottom;
   LONG  xRight;
   LONG  yTop;
} RECTL;
typedef RECTL *PRECTL;
typedef RECTL *NPRECTL;

typedef CHAR STR8[8];          /* str8 */
typedef STR8 *PSTR8;

/*** common DEV/SPL types */

/* structure for Device Driver data */

typedef struct _DRIVDATA       /* driv */
{
   LONG    cb;
   LONG    lVersion;
   CHAR    szDeviceName[32];
   CHAR    abGeneralData[1];
} DRIVDATA;
typedef DRIVDATA *PDRIVDATA;

/* pointer data for DevOpenDC */

typedef PSZ *PDEVOPENDATA;

/* array indices for array parameter for DevOpenDC, SplQmOpen or SplQpOpen */

#define ADDRESS          0
#ifndef INCL_SAADEFS
   #define DRIVER_NAME      1
   #define DRIVER_DATA      2
   #define DATA_TYPE        3
   #define COMMENT          4
   #define PROC_NAME        5
   #define PROC_PARAMS      6
   #define SPL_PARAMS       7
   #define NETWORK_PARAMS   8

   /* structure definition as an alternative of the array parameter */

   typedef struct _DEVOPENSTRUC      /* dop */
   {
      PSZ        pszLogAddress;
      PSZ        pszDriverName;
      PDRIVDATA  pdriv;
      PSZ        pszDataType;
      PSZ        pszComment;
      PSZ        pszQueueProcName;
      PSZ        pszQueueProcParams;
      PSZ        pszSpoolerParams;
      PSZ        pszNetworkParams;
   } DEVOPENSTRUC;
   typedef DEVOPENSTRUC *PDEVOPENSTRUC;
#endif  /* !INCL_SAADEFS */

/* common PMWP object and PMSTDDLG drag data */

typedef struct _PRINTDEST     /* prntdst */
{
   ULONG        cb;
   LONG         lType;
   PSZ          pszToken;
   LONG         lCount;
   PDEVOPENDATA pdopData;
   ULONG        fl;
   PSZ          pszPrinter;
} PRINTDEST;
typedef PRINTDEST *PPRINTDEST;

#define PD_JOB_PROPERTY   0x0001      /* Flags for .fl field           */

/*** common AVIO/GPI types */

/* values of fsSelection field of FATTRS structure */
#define FATTR_SEL_ITALIC        0x0001
#define FATTR_SEL_UNDERSCORE    0x0002
#define FATTR_SEL_OUTLINE       0x0008
#define FATTR_SEL_STRIKEOUT     0x0010
#define FATTR_SEL_BOLD          0x0020

/* values of fsType field of FATTRS structure */
#define FATTR_TYPE_KERNING      0x0004
#define FATTR_TYPE_MBCS         0x0008
#define FATTR_TYPE_DBCS         0x0010
#define FATTR_TYPE_ANTIALIASED  0x0020

/* values of fsFontUse field of FATTRS structure */
#define FATTR_FONTUSE_NOMIX         0x0002
#define FATTR_FONTUSE_OUTLINE       0x0004
#define FATTR_FONTUSE_TRANSFORMABLE 0x0008
/* size for fields in the font structures */

#define FACESIZE 32

/* font struct for Vio/GpiCreateLogFont */

typedef struct _FATTRS            /* fat */
{
   USHORT  usRecordLength;
   USHORT  fsSelection;
   LONG    lMatch;
   CHAR    szFacename[FACESIZE];
   USHORT  idRegistry;
   USHORT  usCodePage;
   LONG    lMaxBaselineExt;
   LONG    lAveCharWidth;
   USHORT  fsType;
   USHORT  fsFontUse;
} FATTRS;
typedef FATTRS *PFATTRS;

/* values of fsType field of FONTMETRICS structure */
#define FM_TYPE_FIXED           0x0001
#define FM_TYPE_LICENSED        0x0002
#define FM_TYPE_KERNING         0x0004
#define FM_TYPE_DBCS            0x0010
#define FM_TYPE_MBCS            0x0018
#define FM_TYPE_64K             0x8000
#define FM_TYPE_ATOMS           0x4000
#define FM_TYPE_FAMTRUNC        0x2000
#define FM_TYPE_FACETRUNC       0x1000

/* values of fsDefn field of FONTMETRICS structure */
#define FM_DEFN_OUTLINE         0x0001
#define FM_DEFN_IFI             0x0002
#define FM_DEFN_WIN             0x0004
#define FM_DEFN_GENERIC         0x8000

/* values of fsSelection field of FONTMETRICS structure */
#define FM_SEL_ITALIC           0x0001
#define FM_SEL_UNDERSCORE       0x0002
#define FM_SEL_NEGATIVE         0x0004
#define FM_SEL_OUTLINE          0x0008          /* Hollow Outline Font */
#define FM_SEL_STRIKEOUT        0x0010
#define FM_SEL_BOLD             0x0020
#define FM_SEL_ISO9241_TESTED   0x0040

/* ISO 9241 is an international standard covering health and safety      */
/* in the work place for users of visual display terminals. Part 3 of    */
/* this standard covers clarity and legibility of text displayed on      */
/* computer screens, it places requirements on minimum sizes and         */
/* luminance contrast. The presence of FM_SEL_ISO9241_TESTED flag in the */
/* font metrics indicates that the font has been tested for compliance   */
/* to the standard. The FM_ISO_XXX flags indicate the results of the     */
/* test on the IBM 9515, 9517 and 9518 color displays at the supported   */
/* dimensions of 640x480 and 1024x768. To ensure compliance the          */
/* sXDeviceRes and sYDeviceRes must also match the target display        */
/* resolution.                                                           */

/* values of fbPassed/FailedISO field in the PANOSE structure */
#define FM_ISO_9518_640        0x01
#define FM_ISO_9515_640        0x02
#define FM_ISO_9515_1024       0x04
#define FM_ISO_9517_640        0x08
#define FM_ISO_9517_1024       0x10

/* values of fsCapabilities field of FONTMETRICS structure */
#define FM_CAP_NOMIX            0x0001

/* font metrics returned by GpiQueryFonts and others */

typedef struct _PANOSE   /* panose */
{
   BYTE    bFamilyType;
   BYTE    bSerifStyle;
   BYTE    bWeight;
   BYTE    bProportion;
   BYTE    bContrast;
   BYTE    bStrokeVariation;
   BYTE    bArmStyle;
   BYTE    bLetterform;
   BYTE    bMidline;
   BYTE    bXHeight;
   BYTE    fbPassedISO;
   BYTE    fbFailedISO;
} PANOSE;

typedef struct _FONTMETRICS     /* fm */
{
   CHAR    szFamilyname[FACESIZE];
   CHAR    szFacename[FACESIZE];
   USHORT  idRegistry;
   USHORT  usCodePage;
   LONG    lEmHeight;
   LONG    lXHeight;
   LONG    lMaxAscender;
   LONG    lMaxDescender;
   LONG    lLowerCaseAscent;
   LONG    lLowerCaseDescent;
   LONG    lInternalLeading;
   LONG    lExternalLeading;
   LONG    lAveCharWidth;
   LONG    lMaxCharInc;
   LONG    lEmInc;
   LONG    lMaxBaselineExt;
   SHORT   sCharSlope;
   SHORT   sInlineDir;
   SHORT   sCharRot;
   USHORT  usWeightClass;
   USHORT  usWidthClass;
   SHORT   sXDeviceRes;
   SHORT   sYDeviceRes;
   SHORT   sFirstChar;
   SHORT   sLastChar;
   SHORT   sDefaultChar;
   SHORT   sBreakChar;
   SHORT   sNominalPointSize;
   SHORT   sMinimumPointSize;
   SHORT   sMaximumPointSize;
   USHORT  fsType;
   USHORT  fsDefn;
   USHORT  fsSelection;
   USHORT  fsCapabilities;
   LONG    lSubscriptXSize;
   LONG    lSubscriptYSize;
   LONG    lSubscriptXOffset;
   LONG    lSubscriptYOffset;
   LONG    lSuperscriptXSize;
   LONG    lSuperscriptYSize;
   LONG    lSuperscriptXOffset;
   LONG    lSuperscriptYOffset;
   LONG    lUnderscoreSize;
   LONG    lUnderscorePosition;
   LONG    lStrikeoutSize;
   LONG    lStrikeoutPosition;
   SHORT   sKerningPairs;
   SHORT   sFamilyClass;
   LONG    lMatch;
   LONG    FamilyNameAtom;
   LONG    FaceNameAtom;
   PANOSE  panose;
} FONTMETRICS;
typedef FONTMETRICS *PFONTMETRICS;

/*** Common WIN types */

typedef LHANDLE HWND;      /* hwnd */
typedef HWND *PHWND;

typedef LHANDLE HMQ;       /* hmq */
typedef LHANDLE *PHMQ;

/* NOINC */
#define WRECT RECTL
#define PWRECT PRECTL
#define NPWRECT NPRECTL

#define WPOINT POINTL
#define PWPOINT PPOINTL
#define NPWPOINT NPPOINTL
/* INC */

typedef struct _ICONINFO {  /* icninf */
   ULONG   cb;                  /* size of ICONINFO structure */
   ULONG   fFormat;
   PSZ     pszFileName;         /* use when fFormat = ICON_FILE */
   HMODULE hmod;                /* use when fFormat = ICON_RESOURCE */
   ULONG   resid;               /* use when fFormat = ICON_RESOURCE */
   ULONG   cbIconData;          /* use when fFormat = ICON_DATA     */
   PVOID   pIconData;           /* use when fFormat = ICON_DATA     */
} ICONINFO;
typedef ICONINFO FAR *PICONINFO;

#define ICON_FILE     1         /* flags for fFormat */
#define ICON_RESOURCE 2
#define ICON_DATA     3
#define ICON_CLEAR    4

#endif /* __OS2DEF__ */

#ifdef __cplusplus
        }
#endif
#pragma info( none )
#ifndef __CHKHDR__
   #pragma info( restore )
#endif
#pragma info( restore )
/**************************** end of file **********************************/
