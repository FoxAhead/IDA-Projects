/***************************************************************************\
*
* Module Name: BSEDOS.H
*
* OS/2 Base Include File
*
* Copyright (c) International Business Machines Corporation 1987-1990
*
*****************************************************************************
*
* Subcomponents marked with "+" are partially included by default
*
*   #define:                To include:
*
* + INCL_DOSPROCESS         Process and thread support
*   INCL_DOSINFOSEG         InfoSeg support
* + INCL_DOSFILEMGR         File Management
* + INCL_DOSMEMMGR          Memory Management
* + INCL_DOSSEMAPHORES      Semaphore support
* + INCL_DOSDATETIME        Date/Time and Timer support
*   INCL_DOSMODULEMGR       Module manager
* + INCL_DOSRESOURCES       Resource support
*   INCL_DOSNLS             National Language Support
*   INCL_DOSSIGNALS         Signals
*   INCL_DOSMISC            Miscellaneous
*   INCL_DOSMONITORS        Monitors
*   INCL_DOSQUEUES          Queues
*   INCL_DOSSESMGR          Session Manager Support
*   INCL_DOSDEVICES         Device specific, ring 2 support
*   INCL_DOSNMPIPES         Named Pipes Support
*   INCL_DOSPROFILE         DosProfile API
*
\***************************************************************************/

#define INCL_DOSINCLUDED

#ifdef INCL_DOS

#define INCL_DOSPROCESS
#define INCL_DOSINFOSEG
#define INCL_DOSFILEMGR
#define INCL_DOSMEMMGR
#define INCL_DOSSEMAPHORES
#define INCL_DOSDATETIME
#define INCL_DOSMODULEMGR
#define INCL_DOSRESOURCES
#define INCL_DOSNLS
#define INCL_DOSSIGNALS
#define INCL_DOSMISC
#define INCL_DOSMONITORS
#define INCL_DOSQUEUES
#define INCL_DOSSESMGR
#define INCL_DOSDEVICES
#define INCL_DOSNMPIPES
#define INCL_DOSPFS
#define INCL_DOSPROFILE

#endif /* INCL_DOS */

#ifdef INCL_ERRORS
#define INCL_DOSERRORS
#endif /* INCL_ERRORS */

#if (defined(INCL_DOSPROCESS) || !defined(INCL_NOCOMMON))

/*** General services */


/***   DosBeep - Generates sound from speaker                   */

USHORT APIENTRY DosBeep(
        USHORT usFrequency,             /* frequency of sound in Hertz     */
        USHORT usDuration);             /* length of sound in milliseconds */

/*** Process and Thread support */

/***    DosExit - Exit a program
 *
 *      This call is issued when a thread completes its execution.
 *      The current thread is ended.
 */

VOID APIENTRY DosExit(
        USHORT fTerminate,              /* 0=end current thread, 1=end all */
        USHORT usExitCode );            /* program completion code         */

/* DosExit codes */

#define EXIT_THREAD         0
#define EXIT_PROCESS        1

#endif /* common INCL_DOSPROCESS stuff */

#ifdef INCL_DOSPROCESS

/***    _PIDINFO  structure of the address of the area where the
 *      ID's will be placed
 */

typedef struct _PIDINFO {
    PID pid;                            /* current process' process ID */
    TID tid;                            /* current process' thread ID  */
    PID pidParent;                      /* process ID of the parent    */
} PIDINFO;
typedef PIDINFO FAR *PPIDINFO;

typedef VOID (FAR *PFNTHREAD)(VOID);


/***    DosCreateThread - Create another thread of execution
 *
 *      Creates an asynchronous thread of execution under the
 *      current process
 */

USHORT APIENTRY DosCreateThread(
        PFNTHREAD pfnFun,               /* Starting Address for new thread */
        PTID pTid,                      /* Address to put new thread ID    */
        PBYTE pbStack);                 /* Address of stack for new thread */

/***    DosResumeThread - Resume the execution of a thread
 *
 *      This call restarts the execution of a thread
 *      previously stopped by a call to DosSuspendThread.
 */

USHORT APIENTRY DosResumeThread(
        TID tid);                       /* Thread ID */


/***    DosSuspendThread - Suspend the execution of a thread
 *
 *      This call temporarily suspends a thread's execution
 *      until a DosResumeThread call is made for that thread ID.
 */

USHORT APIENTRY DosSuspendThread(
        TID tid);                       /* Thread ID */

/* Action code values */

#define DCWA_PROCESS        0
#define DCWA_PROCESSTREE    1

/* Wait option values */

#define DCWW_WAIT   0
#define DCWW_NOWAIT 1

/***   _RESULTCODES - structure used by DosExecPgm and DosCWait
 *              First word is Termination code, second word is Exit code.
 *              For DosExecPgm, first word may instead be the Process ID.
 */

typedef struct _RESULTCODES {
    USHORT codeTerminate;               /* Termination Code -or- Process ID */
    USHORT codeResult;                  /* Exit Code                        */
} RESULTCODES;
typedef RESULTCODES FAR *PRESULTCODES;


/***    DosCwait - Wait for child termination
 *
 *      Places the current thread in a wait state until a child process
 *      has terminated, then returns the ending process' process ID and
 *      termination code.
 */

USHORT APIENTRY DosCwait(
        USHORT fScope,                  /* Action (execution) codes         */
        USHORT fwait,                   /* Wait options                     */
        PRESULTCODES prescResults,      /* Address to put return codes      */
        PPID ppidProcess,               /* Address to put process ID        */
        PID pidWaitProcess);            /* ProcessID of process to wait for */

/***   DosSleep - Delay Process Execution
 *
 *     Suspends the current thread for a specified time.
 *
 */

USHORT APIENTRY DosSleep(
        ULONG ulTime);         /* interval in milliseconds to delay execution */

/* codeTerminate values (also passed to ExitList routines) */

#define TC_EXIT          0
#define TC_HARDERROR     1
#define TC_TRAP          2
#define TC_KILLPROCESS   3

typedef VOID (PASCAL FAR *PFNEXITLIST)(USHORT);

/***    DosEnterCritSec - Enter critical section of execution
 *
 *      Disables thread switching for the current process
 */

USHORT APIENTRY DosEnterCritSec(VOID);

/***    DosExitCritSec - Exit critical section of execution
 *
 *      Re-enables thread switching for the current process
 */

USHORT APIENTRY DosExitCritSec(
        VOID);

/***    DosExitList - Routine list for process termination
 *
 *      Maintains a list of routines which are to be executed when the
 *      current process ends, normally or otherwise
 */

USHORT APIENTRY DosExitList(
        USHORT fFnCode,                 /* Function request code             */
        PFNEXITLIST pfnFunction);       /* Address of routine to be executed */

/* DosExitList functions */

#define EXLST_ADD       1
#define EXLST_REMOVE    2
#define EXLST_EXIT      3

/***    DosExecPgm - Execute a program
 *
 *      Allows a program to request another program be executed as a
 *      child process.  The requestor's process may optionally continue
 *      to execute asynchronous to the new program
 */

USHORT APIENTRY DosExecPgm(
        PCHAR pchFailName,              /* Object name buffer (address)       */
        SHORT cbFailName,               /* Object name buffer length          */
        USHORT fExecFlag,               /* 0=synchronous, 1=asynchronous with */
                                        /* return code discarded, 2=async     */
                                        /* with return code saved, 3=trace    */
                                        /* 4=asynch detached, 5=loaded but    */
                                        /* not executed                       */
        PSZ pszArgs,                    /* Address of argument strings        */
        PSZ pszEnv,                     /* Address of environment strings     */
        PRESULTCODES prescResults,      /* Address to put return codes        */
        PSZ pszPgmName);                /* Address of program filename        */

/* DosExecPgm functions */

#define EXEC_SYNC           0
#define EXEC_ASYNC          1
#define EXEC_ASYNCRESULT    2
#define EXEC_TRACE          3
#define EXEC_BACKGROUND     4
#define EXEC_LOAD           5

/***    DosGetPID - Return process ID
 *
 *      Returns the current process's process ID (PID), thread ID,
 *      and the PID of the process that spawned it
 */

USHORT APIENTRY DosGetPID(
        PPIDINFO ppidInfo);             /* _PIDINFO structure */


/***   DosGetPPid - Get a process's parent's PID
 *
 *     Allows the caller to obtain the parent process ID for any process
 *
 */

USHORT APIENTRY DosGetPPID(
        USHORT pidChild,      /* process id of process to find the parent pid */
        PUSHORT ppidParent);  /* where pid will be placed                     */

/***    DosGetPrty - Get Process's Priority
 *
 *      Allows the caller to learn the priority of a process or thread
 */

USHORT APIENTRY DosGetPrty(
        USHORT usScope,                 /* scope the request will have       */
        PUSHORT pusPriority,            /* Address to put priority           */
        USHORT pid);                    /* PID of process/thread of interest */

/***    DosSetPrty - Set Process Priority
 *
 *      Allows the caller to change the base priority or priority
 *      class of a child process or a thread in the current process
 */

USHORT APIENTRY DosSetPrty(
        USHORT usScope,                 /* Indicate scope of change       */
        USHORT fPrtyClass,              /* Priority class to set          */
        SHORT sChange,                  /* Priority delta to apply        */
        USHORT id);                     /* Process or Thread ID of target */

/* Priority scopes */

#define PRTYS_PROCESS       0
#define PRTYS_PROCESSTREE   1
#define PRTYS_THREAD        2

/* Priority classes */

#define PRTYC_NOCHANGE      0
#define PRTYC_IDLETIME      1
#define PRTYC_REGULAR       2
#define PRTYC_TIMECRITICAL  3
#define PRTYC_FOREGROUNDSERVER 4

/* Priority deltas */

#define PRTYD_MINIMUM     -31
#define PRTYD_MAXIMUM      31

/***    DosKillProcess - Terminate a Process
 *
 *      Terminates a child process and returns its termination code
 *      to its parent (if any)
 */

USHORT APIENTRY DosKillProcess(
        USHORT usScope,                 /* 0=kill child processes also,  */
                                        /* 1=kill only indicated process */
        PID pidProcess);                /* Process ID of process to end  */

#define DKP_PROCESSTREE     0
#define DKP_PROCESS         1

#endif /* INCL_DOSPROCESS */


/*** InfoSeg support */

#ifdef INCL_DOSINFOSEG

/* Global Info Seg */

typedef struct _GINFOSEG {
    ULONG   time;               /* time in seconds                           */
    ULONG   msecs;              /* milliseconds                              */
    UCHAR   hour;               /* hours                                     */
    UCHAR   minutes;            /* minutes                                   */
    UCHAR   seconds;            /* seconds                                   */
    UCHAR   hundredths;         /* hundredths                                */
    USHORT  timezone;           /* minutes from UTC                          */
    USHORT  cusecTimerInterval; /* timer interval (units = 0.0001 seconds)   */
    UCHAR   day;                /* day                                       */
    UCHAR   month;              /* month                                     */
    USHORT  year;               /* year                                      */
    UCHAR   weekday;            /* day of week                               */
    UCHAR   uchMajorVersion;    /* major version number                      */
    UCHAR   uchMinorVersion;    /* minor version number                      */
    UCHAR   chRevisionLetter;   /* revision letter                           */
    UCHAR   sgCurrent;          /* current foreground session                */
    UCHAR   sgMax;              /* maximum number of sessions                */
    UCHAR   cHugeShift;         /* shift count for huge elements             */
    UCHAR   fProtectModeOnly;   /* protect mode only indicator               */
    USHORT  pidForeground;      /* pid of last process in forground session  */
    UCHAR   fDynamicSched;      /* dynamic variation flag                    */
    UCHAR   csecMaxWait;        /* max wait in seconds                       */
    USHORT  cmsecMinSlice;      /* minimum timeslice (milliseconds)          */
    USHORT  cmsecMaxSlice;      /* maximum timeslice (milliseconds)          */
    USHORT  bootdrive;          /* drive from which the system was booted    */
    UCHAR   amecRAS[32];        /* system trace major code flag bits         */
    UCHAR   csgWindowableVioMax;/* maximum number of VIO windowable sessions */
    UCHAR   csgPMMax;           /* maximum number of pres. services sessions */
} GINFOSEG;
typedef GINFOSEG FAR *PGINFOSEG;

/* Local Info Seg */

typedef struct _LINFOSEG {
    PID     pidCurrent;        /* current process id                     */
    PID     pidParent;         /* process id of parent                   */
    USHORT  prtyCurrent;       /* priority of current thread             */
    TID     tidCurrent;        /* thread ID of current thread            */
    USHORT  sgCurrent;         /* session                                */
    UCHAR   rfProcStatus;      /* process status                         */
    UCHAR   dummy1;
    BOOL    fForeground;       /* current process has keyboard focus     */
    UCHAR   typeProcess;       /* process type                           */
    UCHAR   dummy2;
    SEL     selEnvironment;    /* environment selector                   */
    USHORT  offCmdLine;        /* command line offset                    */
    USHORT  cbDataSegment;     /* length of data segment                 */
    USHORT  cbStack;           /* stack size                             */
    USHORT  cbHeap;            /* heap size                              */
    HMODULE hmod;              /* module handle of the application       */
    SEL     selDS;             /* data segment handle of the application */
} LINFOSEG;
typedef LINFOSEG FAR *PLINFOSEG;

/* Process Type codes (local info seg typeProcess field) */

#define PT_FULLSCREEN       0       /* Full screen app.          */
#define PT_REALMODE         1       /* Real mode process         */
#define PT_WINDOWABLEVIO    2       /* VIO windowable app.       */
#define PT_PM               3       /* Presentation Manager app. */
#define PT_DETACHED         4       /* Detached app.             */

/* Process Status Flag definitions (local info seg rfProcStatus field) */

#define PS_EXITLIST         1       /* Thread is in exitlist routine */


/***    DosGetInfoSeg - Get address of system variables segment
 *
 *      Returns the address of a global and process local data segment used to
 *      determine the value of several items of general information.
 *
 */

USHORT APIENTRY DosGetInfoSeg(
        PSEL pselGlobal,                /* global segment selector (returned) */
        PSEL pselLocal);                /* local segment selector (returned)  */

/* Helper macros used to convert selector to PINFOSEG or LINFOSEG */

#define MAKEPGINFOSEG(sel)  ((PGINFOSEG)MAKEP(sel, 0))
#define MAKEPLINFOSEG(sel)  ((PLINFOSEG)MAKEP(sel, 0))

#endif /* INCL_DOSINFOSEG */

#ifndef INCL_SAADEFS

/*
 * CCHMAXPATH is the maximum fully qualified path name length including
 * the drive letter, colon, backslashes and terminating NULL.
 */
#define CCHMAXPATH      260

/*
 * CCHMAXPATHCOMP is the maximum individual path component name length
 * including a terminating NULL.
 */
#define CCHMAXPATHCOMP  256

#endif  /* !INCL_SAADEFS */

#if (defined(INCL_DOSFILEMGR) || !defined(INCL_NOCOMMON))

/*** File manager */



/* DosChgFilePtr() file position codes */

#define FILE_BEGIN      0x0000  /* Move relative to beginning of file     */
#define FILE_CURRENT    0x0001  /* Move relative to current fptr position */
#define FILE_END        0x0002  /* Move relative to end of file           */

/* DosFindFirst/Next Directory handle types */

#define HDIR_SYSTEM  0x0001     /* Use system handle (1)         */
#define HDIR_CREATE  0xFFFF     /* Allocate a new, unused handle */

/* DosCopy control bits; may be or'ed together */
#define DCPY_EXISTING   0x00001         /* Copy even if target exists */
#define DCPY_APPEND     0x00002         /* Append to existing file,   */
                                        /* do not replace             */

/* Dosopen/DosQFHandState/DosQueryFileInfo et al file attributes; also */
/* known as Dso File Mode bits... */

#define FILE_NORMAL     0x0000
#define FILE_READONLY   0x0001
#define FILE_HIDDEN     0x0002
#define FILE_SYSTEM     0x0004
#define FILE_DIRECTORY  0x0010
#define FILE_ARCHIVED   0x0020

/* DosOpen() actions */

#define FILE_EXISTED    0x0001
#define FILE_CREATED    0x0002
#define FILE_TRUNCATED  0x0003

/* DosOpen() open flags */

#define FILE_OPEN       0x0001
#define FILE_TRUNCATE   0x0002
#define FILE_CREATE     0x0010

/*     this nibble applies if file already exists                xxxx */

#define OPEN_ACTION_FAIL_IF_EXISTS     0x0000  /* ---- ---- ---- 0000 */
#define OPEN_ACTION_OPEN_IF_EXISTS     0x0001  /* ---- ---- ---- 0001 */
#define OPEN_ACTION_REPLACE_IF_EXISTS  0x0002  /* ---- ---- ---- 0010 */

/*     this nibble applies if file does not exist           xxxx      */

#define OPEN_ACTION_FAIL_IF_NEW        0x0000  /* ---- ---- 0000 ---- */
#define OPEN_ACTION_CREATE_IF_NEW      0x0010  /* ---- ---- 0001 ---- */

/* DosOpen/DosSetFHandState flags */

#define OPEN_ACCESS_READONLY        0x0000  /* ---- ---- ---- -000 */
#define OPEN_ACCESS_WRITEONLY       0x0001  /* ---- ---- ---- -001 */
#define OPEN_ACCESS_READWRITE       0x0002  /* ---- ---- ---- -010 */
#define OPEN_SHARE_DENYREADWRITE    0x0010  /* ---- ---- -001 ---- */
#define OPEN_SHARE_DENYWRITE        0x0020  /* ---- ---- -010 ---- */
#define OPEN_SHARE_DENYREAD         0x0030  /* ---- ---- -011 ---- */
#define OPEN_SHARE_DENYNONE         0x0040  /* ---- ---- -100 ---- */
#define OPEN_FLAGS_NOINHERIT        0x0080  /* ---- ---- 1--- ---- */
#define OPEN_FLAGS_NO_LOCALITY      0x0000  /* ---- -000 ---- ---- */
#define OPEN_FLAGS_SEQUENTIAL       0x0100  /* ---- -001 ---- ---- */
#define OPEN_FLAGS_RANDOM           0x0200  /* ---- -010 ---- ---- */
#define OPEN_FLAGS_RANDOMSEQUENTIAL 0x0300  /* ---- -011 ---- ---- */
#define OPEN_FLAGS_NO_CACHE         0x1000  /* ---1 ---- ---- ---- */
#define OPEN_FLAGS_FAIL_ON_ERROR    0x2000  /* --1- ---- ---- ---- */
#define OPEN_FLAGS_WRITE_THROUGH    0x4000  /* -1-- ---- ---- ---- */
#define OPEN_FLAGS_DASD             0x8000  /* 1--- ---- ---- ---- */


/* DosSearchPath() constants */

#define SEARCH_PATH            0x0000
#define SEARCH_CUR_DIRECTORY   0x0001
#define SEARCH_ENVIRONMENT     0x0002
#define SEARCH_IGNORENETERRS   0x0004

/************************************************************
DosFileIO
=========================================
************************************************************/
/* File IO command words */
#define FIO_LOCK        0       /* Lock Files          */
#define FIO_UNLOCK      1       /* Unlock Files        */
#define FIO_SEEK        2       /* Seek (set file ptr) */
#define FIO_READ        3       /* File Read           */
#define FIO_WRITE       4       /* File Write          */

/* Lock Sharing Modes */
#define FIO_NOSHARE     0       /* None      */
#define FIO_SHAREREAD   1       /* Read-Only */

typedef struct  _FIOLOCKCMD {           /* FLC  FileLockCmd prefix */
        USHORT  usCmd;          /* Cmd = FIO_LOCK           */
        USHORT  cLockCnt;       /* Lock records that follow */
        ULONG   cTimeOut;       /* in Msec                  */
} FIOLOCKCMD;
typedef FIOLOCKCMD FAR *PFIOLOCKCMD;


typedef struct  _FIOLOCKREC {           /* FLR FileLockRecord              */
        USHORT  fShare;                 /* FIO_NOSHARE or FIO_SHAREREAD    */
        ULONG   cbStart;                /* Starting offset for lock region */
        ULONG   cbLength;               /* Length of lock region           */
} FIOLOCKREC;
typedef FIOLOCKREC FAR *PFIOLOCKREC;


typedef struct  _FIOUNLOCKCMD {         /* FUC FileUnlockCmd prefix   */
        USHORT  usCmd;                  /* Cmd = FIO_UNLOCK           */
        USHORT  cUnlockCnt;             /* Unlock records that follow */
} FIOUNLOCKCMD;
typedef FIOUNLOCKCMD FAR *PFIOUNLOCKCMD;


typedef struct  _FIOUNLOCKREC {         /* FUR FileUnlockRecord              */
        ULONG   cbStart;                /* Starting offset for unlock region */
        ULONG   cbLength;               /* Length of unlock region           */
} FIOUNLOCKREC;
typedef FIOUNLOCKREC FAR *PFIOUNLOCKREC;


typedef struct  _FIOSEEKCMD {           /* Seek command structure             */
        USHORT  usCmd;                  /* Cmd = FIO_SEEK                     */
        USHORT  fsMethod;               /* One of : FPM_BEGINNING,            */
                                        /* FPM_CURRENT,or FPM_END             */
        ULONG   cbDistance;             /* Byte offset for seek               */
        ULONG   cbNewPosition;          /* Bytes from start of file after     */
                                        /* seek                               */
} FIOSEEKCMD;
typedef FIOSEEKCMD FAR *PFIOSEEKCMD;


typedef struct  _FIOREADWRITE {         /* RWC Read&Write command structure */
        USHORT  usCmd;                  /* Cmd = FIO_READ or FIO_WRITE      */
        PVOID   pbBuffer;               /* Pointer to data buffer           */
        USHORT  cbBufferLen;            /* Bytes in buffer or max size      */
        USHORT  cbActualLen;            /* Bytes actually read/written      */
} FIOREADWRITE;
typedef FIOREADWRITE FAR *PFIOREADWRITE;


/************************************************************
EA Info Levels & Find First/Next
=========================================
API's: DosFindFirst, DosQueryFileInfo, DosQueryPathInfo, DosSetFileInfo,
       DosSetPathInfo
************************************************************/

/* File info levels: All listed API's */
#define FIL_STANDARD            1       /* Info level 1, standard file info */
#define FIL_QUERYEASIZE         2       /* Level 2, return Full EA size     */
#define FIL_QUERYEASFROMLIST    3       /* Level 3, return requested EA's   */

/* File info levels: Dos...PathInfo only */
#define FIL_QUERYFULLNAME       5       /* Level 5, return fully qualified  */
                                        /* name of file                     */
#define FIL_NAMEISVALID         6       /* Level 6, check validity of file/path
                                           name for this FSD                */



/* DosFindNotifyFirst() */
#define FNOTIL_STANDARD 1       /* Find-Notify Info level 1: Return
                                   standard directory change info */


/* DosFsAttach() */
/* Attact or detach */
#define FSATTACH       0       /* Attach file server */
#define FSDETACH       1       /* Detach file server */


/* DosFsCtl() */
/* Routing type */
#define FSCTL_HANDLE    1       /* File Handle directs req routing */
#define FSCTL_PATHNAME  2       /* Path Name directs req routing   */
#define FSCTL_FSDNAME   3       /* FSD Name directs req routing    */


/* DosQueryFSAttach() */
/* Information level types (defines method of query) */
#define FSAIL_QUERYNAME 1       /* Return data for a Drive or Device */
#define FSAIL_DEVNUMBER 2       /* Return data for Ordinal Device #  */
#define FSAIL_DRVNUMBER 3       /* Return data for Ordinal Drive #   */

/* Item types (from data structure item "iType") */
#define FSAT_CHARDEV    1       /* Resident character device    */
#define FSAT_PSEUDODEV  2       /* Pusedu-character device      */
#define FSAT_LOCALDRV   3       /* Local drive                  */
#define FSAT_REMOTEDRV  4       /* Remote drive attached to FSD */

typedef struct  _FSQBUFFER {            /* Data structure for QFSAttach       */
        USHORT  iType;                  /* Item type                          */
        USHORT  cbName;                 /* Length of item name, sans NULL     */
        UCHAR   szName[1];              /* ASCIIZ item name                   */
        USHORT  cbFSDName;              /* Length of FSD name, sans NULL      */
        UCHAR   szFSDName[1];           /* ASCIIZ FSD name                    */
        USHORT  cbFSAData;              /* Length of FSD Attach data returned */
        UCHAR   rgFSAData[1];           /* FSD Attach data from FSD           */
} FSQBUFFER;
typedef FSQBUFFER FAR *PFSQBUFFER;


/***********
File System Drive Information&gml DosQueryFSInfo DosSetFSInfo
***********/

/* FS Drive Info Levels */
#define FSIL_ALLOC      1       /* Drive allocation info (Query only) */
#define FSIL_VOLSER     2       /* Drive Volum/Serial info            */

/* DosQueryFHType() */
/* Handle classes (low 8 bits of Handle Type) */
#define FHT_DISKFILE    0x0000          /* Disk file handle        */
#define FHT_CHRDEV      0x0001          /* Character device handle */
#define FHT_PIPE        0x0002          /* Pipe handle             */

/* Handle bits (high 8 bits of Handle Type) */
#define FHB_DSKREMOTE           0x8000  /* Remote disk             */
#define FHB_CHRDEVREMOTE        0x8000  /* Remote character device */
#define FHB_PIPEREMOTE          0x8000  /* Remote pipe             */

typedef SHANDLE HFILE;      /* hf */
typedef HFILE FAR *PHFILE;

#ifndef INCL_SAADEFS

/* File time and date types */

typedef struct _FTIME {          /* ftime */
    unsigned twosecs : 5;
    unsigned minutes : 6;
    unsigned hours   : 5;
} FTIME;
typedef FTIME FAR *PFTIME;

typedef struct _FDATE {          /* fdate */
    unsigned day     : 5;
    unsigned month   : 4;
    unsigned year    : 7;
} FDATE;
typedef FDATE FAR *PFDATE;

typedef struct _FILEFINDBUF {   /* findbuf */
    FDATE  fdateCreation;
    FTIME  ftimeCreation;
    FDATE  fdateLastAccess;
    FTIME  ftimeLastAccess;
    FDATE  fdateLastWrite;
    FTIME  ftimeLastWrite;
    ULONG  cbFile;
    ULONG  cbFileAlloc;
    USHORT attrFile;
    UCHAR  cchName;
    CHAR   achName[CCHMAXPATHCOMP];
} FILEFINDBUF;
typedef FILEFINDBUF FAR *PFILEFINDBUF;

typedef struct _FILEFINDBUF2 {  /* findbuf2 */
    FDATE  fdateCreation;
    FTIME  ftimeCreation;
    FDATE  fdateLastAccess;
    FTIME  ftimeLastAccess;
    FDATE  fdateLastWrite;
    FTIME  ftimeLastWrite;
    ULONG  cbFile;
    ULONG  cbFileAlloc;
    USHORT attrFile;
    ULONG  cbList;
    UCHAR  cchName;
    CHAR   achName[CCHMAXPATHCOMP];
} FILEFINDBUF2;
typedef FILEFINDBUF2 FAR *PFILEFINDBUF2;

/* extended attribute structures */

typedef struct _GEA {       /* gea                            */
    BYTE cbName;            /* name length not including NULL */
    CHAR szName[1];         /* attribute name                 */
} GEA;
typedef GEA far *PGEA;

typedef struct _GEALIST {   /* geal                                         */
    ULONG  cbList;          /* total bytes of structure including full list */
    GEA list[1];            /* variable length GEA structures               */
} GEALIST;
typedef GEALIST far * PGEALIST;

typedef struct _FEA {       /* fea                            */
    BYTE fea;               /* flags                          */
    BYTE cbName;            /* name length not including NULL */
    USHORT cbValue;         /* value length                   */
} FEA;
typedef FEA far *PFEA;

/* flags for _FEA.fEA */

#define FEA_NEEDEA 0x80     /* need EA bit */

typedef struct _FEALIST {   /* feal                                         */
    ULONG  cbList;          /* total bytes of structure including full list */
    FEA list[1];            /* variable length FEA structures               */
} FEALIST;
typedef FEALIST far * PFEALIST;

typedef struct _EAOP {      /* eaop            */
    PGEALIST fpGEAList;     /* general EA list */
    PFEALIST fpFEAList;     /* full EA list    */
    ULONG  oError;
} EAOP;
typedef EAOP far * PEAOP;

/*
 * Equates for the types of EAs that follow the convention that we have
 * established.
 *
 * Values 0xFFFE thru 0x8000 are reserved.
 * Values 0x0000 thru 0x7fff are user definable.
 */

#define     EAT_BINARY           0xFFFE /* length preceeded binary            */
#define     EAT_ASCII            0xFFFD /* length preceeded ASCII             */
#define     EAT_BITMAP           0xFFFB /* length preceeded bitmap            */
#define     EAT_METAFILE         0xFFFA /* length preceeded metafile          */
#define     EAT_ICON             0xFFF9 /* length preceeded icon              */
#define     EAT_EA               0xFFEE /* length preceeded ASCII ext. attr.  */
                                        /* name of associated data (#include) */
#define     EAT_MVMT             0xFFDF /* multi-valued, multi-typed field    */
#define     EAT_MVST             0xFFDE /* multi-valued, single-typed field   */
#define     EAT_ASN1             0xFFDD /* ASN.1 field                        */

#endif  /* !INCL_SAADEFS */

/***   DosOpen - Open file
 *
 *     Creates or opens a specified file.
 *
 */

USHORT APIENTRY DosOpen(
        PSZ pszFname,                   /* path name of file to be opened */
        PHFILE phfOpen,                 /* file handle (returned )        */
        PUSHORT pusAction,              /* action taken (returned)        */
        ULONG ulFSize,                  /* file's new size                */
        USHORT usAttr,                  /* file attribute                 */
        USHORT fsOpenFlags,             /* action take if file exists     */
        USHORT fsOpenMode,              /* open mode                      */
        ULONG ulReserved);              /* reserved (must be 0)           */


/***    DosOpen2 - Open a File
 *
 *      (See also DosOpen, above).
 *
 *      Creates the specified file (if necessary) and opens it
 *
 *      Supports Extended Attributes (EA).
 */

USHORT APIENTRY DosOpen2 (
        PSZ pszFname,                   /* File path name                 */
        PHFILE phfOpen,                 /* New file's handle              */
        PUSHORT pusAction,              /* Action taken - 1=file existed, */
                                        /* 2=file was created             */
        ULONG ulFSize,                  /* File primary allocation        */
        USHORT usAttr,                  /* File attributes                */
        USHORT usOpenFlags,             /* Open function type             */
        ULONG usOpenMode,               /* Open mode of the file          */
        PEAOP pvEABuf,                  /* EA structure pointer           */
        ULONG ulReserved);              /* Reserved (must be zero)        */

/***   DosClose - Close file handle
 *
 *     Closes a specific file handle.
 *
 */

USHORT APIENTRY DosClose(
        HFILE hf);                      /* file handle */


/***   DosRead - Read from file
 *
 *     Reads the specified number of bytes from a file or device to a buffer
 *     location.
 *
 */

USHORT APIENTRY DosRead(
        HFILE hf,                       /* file handle                     */
        PVOID pBuf,                     /* input buffer                    */
        USHORT cbBuf,                   /* number of bytes to be read      */
        PUSHORT pcbBytesRead);          /* number of bytes read (returned) */


/***   DosWrite - Synchronous Write to file
 *
 *     Transfers the specified number of bytes from a buffer to the specified
 *     file, synchronously with respect to the requesting process's execution.
 *
 */

USHORT APIENTRY DosWrite(
        HFILE hf,                       /* file handle                        */
        PVOID pBuf,                     /* output buffer                      */
        USHORT cbBuf,                   /* number of bytes to be written      */
        PUSHORT pcbBytesWritten );      /* number of bytes written (returned) */


/***   DosShutdown - File System Shutdown
 *
 *
 *
 */

USHORT APIENTRY DosShutdown (
        ULONG ulReserved);     /* reserved */


/***    FileStatus - structure of information list used by DosQFileInfo */

typedef struct _FILESTATUS {     /* fsts  */
    FDATE  fdateCreation;               /* date of file creation   */
    FTIME  ftimeCreation;               /* time of file creation   */
    FDATE  fdateLastAccess;             /* date of last access     */
    FTIME  ftimeLastAccess;             /* time of last access     */
    FDATE  fdateLastWrite;              /* date of last write      */
    FTIME  ftimeLastWrite;              /* time of last write      */
    ULONG  cbFile;                      /* file size (end of data) */
    ULONG  cbFileAlloc;                 /* file allocated size     */
    USHORT attrFile;                    /* attributes of the file  */
} FILESTATUS;
typedef FILESTATUS FAR *PFILESTATUS;

typedef struct _FILESTATUS2 {    /* fsts2 */
    FDATE   fdateCreation;
    FTIME   ftimeCreation;
    FDATE   fdateLastAccess;
    FTIME   ftimeLastAccess;
    FDATE   fdateLastWrite;
    FTIME   ftimeLastWrite;
    ULONG   cbFile;
    ULONG   cbFileAlloc;
    USHORT  attrFile;
    ULONG   cbList;
} FILESTATUS2;
typedef FILESTATUS2 FAR *PFILESTATUS2;

/***    FSAllocate - structure of file system allocation */

typedef struct _FSALLOCATE {
    ULONG  idFileSystem;                /* file system ID                     */
    ULONG  cSectorUnit;                 /* number sectors per allocation unit */
    ULONG  cUnit;                       /* number of allocation units         */
    ULONG  cUnitAvail;                  /* avalaible allocation units         */
    USHORT cbSector;                    /* bytes per sector                   */
} FSALLOCATE;
typedef FSALLOCATE FAR *PFSALLOCATE;

typedef struct _VOLUMELABEL { /* vol */
    BYTE cch;
    CHAR szVolLabel[12];
} VOLUMELABEL;
typedef VOLUMELABEL FAR *PVOLUMELABEL;

typedef struct _FSINFO {    /* fsinf */
    FDATE fdateCreation;
    FTIME ftimeCreation;
    VOLUMELABEL vol;
} FSINFO;
typedef FSINFO FAR *PFSINFO;

/* HANDTYPE values */

#define HANDTYPE_FILE     0x0000
#define HANDTYPE_DEVICE   0x0001
#define HANDTYPE_PIPE     0x0002
#define HANDTYPE_NETWORK  0x8000

typedef struct _FILELOCK {    /* flock */
    LONG lOffset;
    LONG lRange;
} FILELOCK;
typedef FILELOCK FAR *PFILELOCK;

typedef SHANDLE HDIR;        /* hdir */
typedef HDIR FAR *PHDIR;


/***    DosDelete - Delete file
 *
 *      Removes a directory entry associated with a filename.
 *
 */

USHORT APIENTRY DosDelete(
        PSZ pszFName,                   /* name of file to be deleted */
        ULONG ulReserved);              /* reserved (must be 0)       */


/***   DosDupHandle - Duplicate file handle
 *
 *     Returns a new file handle for an open file that refers to the same file
 *     at the same position.
 *
 */

USHORT APIENTRY DosDupHandle(
        HFILE hfOld,                    /* current file handle        */
        PHFILE phfNew);                 /* new file handle (returned) */
/***   DosQFHandState - Query file handle state
 *
 *     Queries the state of the specified file.
 *
 */

USHORT APIENTRY DosQFHandState(
        HFILE hf,                       /* file handle                  */
        PUSHORT pfsOpenMode);           /* file handle state (returned) */


/***   DosSetFHandState - Set file handle state
 *
 *     Sets the state of the specified file.
 *
 */

USHORT APIENTRY DosSetFHandState(
        HFILE hf,                       /* file handle       */
        USHORT fsState);                /* file handle state */


/***   DosQHandType - Query handle type
 *
 *     Determines whether a handle references a file or a device.
 *
 */

USHORT APIENTRY DosQHandType(
        HFILE hf,                       /* file handle                        */
        PUSHORT pfsType,                /* handle type (returned)             */
        PUSHORT pusDevAttr);            /* device driver attribute (returned) */

/***   DosReadAsync - Asynchronous read from file
 *
 *     Transfers the specified number of bytes from a file to a buffer,
 *     asynchronously with the requesting process execution.
 *
 */

USHORT APIENTRY DosReadAsync (
        HFILE hf,                       /* file handle                     */
        PULONG hsemRam,                 /* ram semaphore                   */
                                        /* (signals end of read operation) */
        PUSHORT pusErrCode,             /* return code (returned)          */
        PVOID pBuf,                     /* input buffer                    */
        USHORT cbBuf,                   /* number of bytes to be read      */
        PUSHORT pcbBytesRead);          /* number of bytes read (returned) */


/***   DosWriteAsync - Asynchronous write to file
 *
 *     Transers the specified number of bytes to a file from a buffer
 *     asynchronously with respect to the requesting process's execution.
 *
 */

USHORT APIENTRY DosWriteAsync(
        HFILE hf,                       /* file handle                        */
        PULONG hsemRam,                 /* ram semaphore                      */
                                        /* (indicates end of write operation) */
        PUSHORT pusErrCode,             /* return code (returned)             */
        PVOID pBuf,                     /* output buffer                      */
        USHORT cbBuf,                   /* number of bytes to be written      */
        PUSHORT pcbBytesWritten);       /* number of bytes written (returned) */


/***   DosFindFirst - Find first matching file
 *
 *     Finds the first set of filenames that match a given file specification.
 *
 */

USHORT APIENTRY DosFindFirst(
        PSZ pszFSpec,          /* path name of files to be found              */
        PHDIR phdir,           /* directory handle                            */
        USHORT usAttr,         /* attribute used to search for the files      */
        PFILEFINDBUF pffb,     /* result buffer                               */
        USHORT cbBuf,          /* length of result buffer                     */
        PUSHORT pcSearch,      /* number of matching entries in result buffer */
        ULONG ulReserved);     /* reserved (must be 0)                        */

/***    DosFindFirst2 - Find First Matching File, version 2
 *
 *      (See also DosFindFirst, above).
 *
 *      Finds the first filename that matches the specified file
 *      specification
 *
 *      Supports FileInfoLevel (for EA).
 */

USHORT APIENTRY  DosFindFirst2 (
        PSZ pszFSpec,                   /* File path name            */
        PHDIR phdir,                    /* Directory search handle   */
        USHORT usAttr,                  /* Search attribute          */
        PVOID pBuf,                     /* Result buffer             */
        USHORT cbBuf,                   /* Result buffer length      */
        PUSHORT pcSearch,               /* Number of entries to find */
        USHORT usInfoLevel,             /* Request level             */
        ULONG ulReserved);              /* Reserved (must be 0)      */

/***   DosFindNext - Find next matching file
 *
 *     Locates the next set of directory entries that match the name specified
 *     in the previous DosFindFirst or DosFindNext call.
 *
 */

USHORT APIENTRY DosFindNext(
        HDIR hdir,                      /* directory handle          */
        PFILEFINDBUF pffb,              /* result buffer             */
        USHORT cbBuf,                   /* length of result buffer   */
        PUSHORT pcSearch);              /* number of entries to find */

/***   DosFindClose - Close find handle
 *
 *     Closes the association between a directory handle and a DosFindFirst or
 *     DosFindNext directory search function.
 *
 */

USHORT APIENTRY DosFindClose(
        HDIR hdir);                     /* directory handle */


/***    DosFindNotifyFirst - Start Monitoring a Directory for Change
 *
 *      Waits for changes (Create,Delete,Mkdir,Rmdir,Rename,Attribute,Close)
 *      to take place against the specified path.  The number of changes
 *      is specified in the change count parameter.
 *
 */

USHORT APIENTRY  DosFindNotifyFirst (
        PSZ pszPath,                    /* Path spec                   */
        PHDIR hdir,                     /* Directory search handle     */
        USHORT usAttr,                  /* Search attribute            */
        PBYTE pBuf,                     /* Result buffer               */
        USHORT cbBuf,                   /* Result buffer length        */
        PUSHORT pcChg,                  /* Number of changes required  */
        USHORT usInfoLevel,             /* Request level               */
        ULONG ulTimeOut,                /* Timeout or Duration of call */
        ULONG ulReserved);              /* Reserved (must be 0)        */

/***    DosFindNotifyNext - Return Directory Change Information
 *
 *      Waits for changes (Create,Delete,Mkdir,Rmdir,Rename,Attribute,Close)
 *      to take place against the specified DirHandle.  The number of changes
 *      is specified in the change count parameter.
 *
 */

USHORT APIENTRY  DosFindNotifyNext (
        HDIR hdir,                      /* Directory handle            */
        PVOID pBuf,                     /* Result buffer               */
        USHORT cbBuf,                   /* Result buffer length        */
        PUSHORT pcChg,                  /* Number of required          */
        ULONG ulTimeOut);               /* Timeout or Duration of call */


/***    DosFindNotifyClose - Close FindNotify Handle
 *
 *      Closes the association between a directory handle and a
 *      osFindNotifyFirst or DosFindNotifyNext function
 */

USHORT APIENTRY  DosFindNotifyClose (
        HDIR hdir );                    /* Directory watch handle */



/***    DosFsAttach - Creates and Detroys FSD Connections
 *
 *      Attaches or detaches drive from a remote FSD or a psuedo-character
 *      device name to/from a local or remote FSD
 */

USHORT APIENTRY DosFSAttach (
        PSZ pszDevName,                 /* device name        */
        PSZ pszFSD,                     /* FSD name           */
        PBYTE pData,                    /* data buffer        */
        USHORT cbData,                  /* data buffer length */
        USHORT fsOp,                    /* open flag          */
        ULONG ulReserved);              /* reserved           */



/***    DosQFsAttach - Query Attached FSD Information
 *
 *      Query information about an attached remote file system or about
 *      a character device or about a psuedo-character device attacted
 *      to a local or remote FSD
 */

USHORT APIENTRY DosQFSAttach (
        PSZ pszDev,                     /* device name        */
        USHORT usOrdinal,               /* ordinal            */
        USHORT usInfoLevel,             /* FSAinfolevel       */
        PBYTE pFSAttBuf,                /* Data buffer        */
        PUSHORT cbBuf,                  /* Data buffer length */
        ULONG ulReserved);              /* reserved           */



/***    DosFSCtl - File System Control
 *
 *      Allow an extended standard interface between an application
 *      and an FSD
 */

USHORT APIENTRY DosFSCtl (
        PBYTE pDate,                    /* Data area            */
        USHORT cbData,                  /* Data length maximum  */
        PUSHORT pcbData,                /* Data length          */
        PBYTE pParms,                   /* Parameter list       */
        USHORT cbParms,                 /* Parameter length max */
        PUSHORT pcbParms,               /* Parameter length     */
        USHORT usFunCode,               /* Function code        */
        PSZ pszRoute,                   /* Route name           */
        HFILE hf,                       /* File handle          */
        USHORT usRouteMethod,           /* Route method         */
        ULONG ulReserved);              /* reserved             */



/***   DosNewSize - Change file size
 *
 *     Changes the size of a file.
 *
 */

USHORT APIENTRY DosNewSize(
        HFILE hf,                       /* file handle     */
        ULONG ulNewSize);               /* file's new size */


/***   DosBufReset - Commit File's cache buffers
 *
 *     Flushes a requesting process's cache buffers for a specific file handle.
 *
 */

USHORT APIENTRY DosBufReset(
        HFILE hf);                      /* file handle                    */


/***   DosChgFilePtr - Change (move) file read/write pointer
 *
 *     moves the read/write pointer in accordance with the method specified.
 *
 */

USHORT APIENTRY DosChgFilePtr(
        HFILE hf,                       /* file handle                     */
        LONG lOffset,                   /* distance to move in bytes       */
        USHORT fsMethod,                /* method of moving                */
        PULONG pulNewOffset);           /* new pointer location (returned) */


/***  DosFileLocks - File lock manager
 *
 *    Locks and unlocks a range in an opened file
 *
 */

USHORT APIENTRY DosFileLocks(
        HFILE hf,                       /* file handle          */
        PLONG pUnlock,                  /* range to be unlocked */
        PLONG pLock);                   /* range to be locked   */


/***   DosMove - Move a file
 *
 *     moves a specified file.
 *
 */

USHORT APIENTRY DosMove(
        PSZ pszOld,                     /* old path name                  */
        PSZ pszNew,                     /* new path name                  */
        ULONG ulReserved);              /* reserved (must be 0)           */

/***   DosCopy - Copy file
 *
 *     copies file
 *
 */

USHORT APIENTRY  DosCopy (
        PSZ pszSrc,                     /* old path name                   */
        PSZ pszDst,                     /* new path name                   */
        USHORT usOpt,                   /* operation mode                  */
        ULONG ulReserved);              /* reserved (must be 0)            */


/***    DosEditName - Transform source string using editing string
 *
 *      Transform a source string into a destination string using an
 *      editing string and OS/2 meta editing semantics.
 *
 */

USHORT APIENTRY  DosEditName (
        USHORT usEditLevel,             /* Level of meta editing semantics  */
        PSZ pszSrc,                     /* String to transform              */
        PSZ pszEdit,                    /* Editing string                   */
        PBYTE pszDst,                   /* Destination string buffer        */
        USHORT cbDst);                  /* Destination string buffer length */


/***    DosFileIO - Multiple Lock, Unlock, Seek, Read and Write I/O.
 *
 *      Combines the above File I/O operations into a single API providing
 *      improved performance.
 */

USHORT APIENTRY  DosFileIO (
        HFILE hf,                       /* File handle                    */
        PBYTE pbCmd,                    /* Pointer to command list buffer */
        USHORT cbCmd,                   /* Command list length            */
        PLONG pulErr);                  /* Pointer to error offset        */

/***   DosMkDir - make subdirectory
 *
 *     Creates a specified directory
 *
 */

USHORT APIENTRY DosMkDir(
        PSZ pszDirName,                 /* new directory name             */
        ULONG usReserved);              /* reserved (must be 0)           */

/***    DosMkdir2 - Make Subdirectory
 *
 *      (see DosMkdir, above)
 *
 *      Creates the specified directory (supports Extended Attributes)
 */

USHORT APIENTRY  DosMkDir2 (
        PSZ pszDir,                     /* New directory name   */
        PEAOP pBuf,                     /* EA structure pointer */
        ULONG ulReserved);              /* Reserved (must be 0) */

/***   DosRmDir - Remove subdirectory
 *
 *     Removes a subdirectory from the specified disk.
 *
 */

USHORT APIENTRY DosRmDir(
        PSZ pszDir,                     /* directory name                 */
        ULONG ulReserved);              /* reserved (must be 0)           */


/***   DosSelectDisk - Select default drive
 *
 *     Selects the drive specified as the default drive for the calling
 *     process.
 *
 */

USHORT APIENTRY DosSelectDisk(
        USHORT usDrvNum);               /* new default drive number       */


/***   DosQCurDisk - Query current disk
 *
 *     Determines the current default drive for the requesting process.
 *
 */

USHORT APIENTRY DosQCurDisk(
        PUSHORT pusDrvNum,            /* default drive number (returned)     */
        PULONG pulLogDrvMap);         /* bit map of logical drives (returned)*/


/***   DosChDir - Change current directory
 *
 *     Defines the current directory for the requesting process.
 *
 */

USHORT APIENTRY DosChDir(
        PSZ pszDir,                     /* directory path name            */
        ULONG ulReserved);              /* reserved (must be 0)           */


/***   DosQCurDir - Query current directory
 *
 *     Gets the full path name of the current directory for the requesting
 *     process for the specified drive.
 *
 */

USHORT APIENTRY DosQCurDir(
        USHORT usDrvNum,                /* drive number                    */
        PBYTE pszPathBuf,               /* directory path name (returned)  */
        PUSHORT pcbPathBuf);            /* length of directory path buffer */
                                        /* (returned)                      */


/***   DosQFSInfo - Query file system information
 *
 *     Queries information from a file system device.
 *
 */

USHORT APIENTRY DosQFSInfo(
        USHORT usDrvNum,             /* logical drive number                  */
        USHORT usInfoLevel,          /* level of file information required    */
        PBYTE pbInfo,                /* storage area for information returned */
        USHORT cbInfo);              /* length of storage area                */


/***   DosSetFSInfo - Set file system information
 *
 *     Sets information for a file system device.
 *
 */

USHORT APIENTRY DosSetFSInfo(
        USHORT usDrvNum,      /* drive number                                 */
        USHORT usInfoLevel,   /* level of file information to be set          */
        PBYTE pBuf,           /* storage area for new file system information */
        USHORT cbBuf);        /* length of storage area                       */


/***   DosQVerify - Query verify setting
 *
 *     Returns the value of the verify flag.
 *
 */

USHORT APIENTRY DosQVerify(
        PUSHORT pfVerifyOn);            /* current verify mode (returned)     */


/***   DosSetVerify - Set/reset verify switch
 *
 *     Sets the verify switch.
 *
 */

USHORT APIENTRY DosSetVerify(
        USHORT fVerify);                /* new verify mode                    */


/***   DosSetMaxFH - Set maximum file handles
 *
 *     Defines the maximum number of file handles for the current process.
 *
 */

USHORT APIENTRY DosSetMaxFH(
        USHORT usHandles);           /* number of file handles to be provided */

/***   DosQFileInfo - Query file information
 *
 *     Returns information for a specific file.
 *
 */

USHORT APIENTRY DosQFileInfo(
        HFILE hf,                    /* file handle                           */
        USHORT usInfoLevel,          /* level of file information required    */
        PBYTE pInfoBuf,              /* storage area for returned information */
        USHORT cbInfoBuf);           /* length of storage area                */


/***   DosSetFileInfo - Set file information
 *
 *     Specifies information for a file
 *
 */

USHORT APIENTRY DosSetFileInfo(
        HFILE hf,                      /* file handle                         */
        USHORT usInfoLevel,            /* level of file information being set */
        PBYTE pInfoBuf,                /* storage area for file information   */
        USHORT cbInfoBuf);             /* length of storage area              */


/***    DosQPathInfo - Query a Path's Information
 *
 *      Returns information for a specific file or directory
 */

USHORT APIENTRY  DosQPathInfo (
        PSZ pszPath,                    /* Path string             */
        USHORT usInfoLevel,             /* Path data required      */
        PBYTE pInfoBuf,                 /* Path data buffer        */
        USHORT cbInfoBuf,               /* Path data buffer size   */
        ULONG ulReserved);              /* Reserved (must be zero) */


/***    DosSetPathInfo - Set a Path's Information
 *
 *      Specifies information for a file or directory
 */

USHORT APIENTRY  DosSetPathInfo (
        PSZ  pszPath,                   /* Path string             */
        USHORT usInfoLevel,             /* Path info data required */
        PBYTE pInfoBuf,                 /* Path info buffer        */
        USHORT cbInfoBuf,               /* Path info buffer size   */
        USHORT usFlags,                 /* Path info flags         */
        ULONG ulReserved);              /* Reserved (must be zero) */


/***   DosQFileMode - Query file mode
 *
 *     Queries the mode (attribute) of the specified file.
 *
 */

USHORT APIENTRY DosQFileMode(
        PSZ pszFname,                   /* file path name                     */
        PUSHORT pusAttr,                /* current file attribute (returned)  */
        ULONG ulReserved);              /* reserved (must be 0)               */


/***   DosSetFileMode - Set file mode
 *
 *     Changes the mode (attribute) of the specified file.
 *
 */

USHORT APIENTRY DosSetFileMode(
        PSZ pszFName,                   /* file path name                     */
        USHORT usAttr,                  /* new attribute of file              */
        ULONG ulReserved);              /* reserved (must be 0)               */

/***    DosEnumAttribute - Enumerate a file or directory's extended attributes
 *
 *      Enumerates information for a specific file or subdirectory
 *
 */

USHORT APIENTRY DosEnumAttribute(
        USHORT ,                        /* RefType - indicates handle or path */
        PVOID,                          /* Pointer to file handle or path     */
        ULONG,                          /* Starting entry in EA list          */
        PVOID,                          /* Data buffer                        */
        ULONG,                          /* Data buffer size                   */
        PULONG,                         /* Number of entries to return        */
        ULONG,                          /* Info level                         */
        ULONG );                        /* Reserved (must be zero)            */


typedef struct _DENA1 {  /* level 1 info returned from DosEnumAttribute */
  UCHAR  reserved;       /* 0                                           */
  UCHAR  cbName;         /* length of name exculding NULL               */
  USHORT cbValue;        /* length of value                             */
  UCHAR  szName[1];      /* variable length asciiz name                 */
} DENA1;
typedef DENA1 FAR *PDENA1;


#endif /* common INCL_DOSFILEMGR */

#if (defined(INCL_DOSMEMMGR) || !defined(INCL_NOCOMMON))
/*** Memory management */


/***   DosAllocSeg - Allocate segment
 *
 *     Allocates a segment of memory to a requesting process.
 *
 */

USHORT APIENTRY DosAllocSeg(
        USHORT cbSize,         /* number of bytes requested                   */
        PSEL pSel,             /* sector allocated (returned)                 */
        USHORT fsAlloc);       /* sharing attributes of the allocated segment */


/***   DosReallocSeg - Change segment size
 *
 *     Changes the size of a segment already allocated.
 *
 */

USHORT APIENTRY DosReallocSeg(
        USHORT cbNewSize,            /* new size requested in bytes           */
        SEL sel);                    /* selector of the segment to be resized */


/***   DosFreeSeg - Free segment
 *
 *     Deallocates a memory segment.
 *
 */

USHORT APIENTRY DosFreeSeg(
        SEL sel);                      /* selector of the segment to be freed */


/***   DosGivSeg - Give access to segment
 *
 *     Gives another process access to a shared memory segment.
 *
 */

USHORT APIENTRY DosGiveSeg(
        SEL sel,                        /* segment selector of the memory */
                                        /* segment to be shared           */
        PID pid,                        /* process ID of recipient        */
        PSEL pSelRecipient);            /* recipients segment selector    */
                                        /* (returned)                     */


/***   DosGetSeg - Access segment
 *
 *     Gets access to a shared memory segment.
 *
 */

USHORT APIENTRY DosGetSeg(
        SEL sel);                       /* selector to access                 */


/***   DosSizeSeg - Get size of a segment.                      */

USHORT APIENTRY DosSizeSeg(
        SEL sel,                        /* segment selector of which size */
                                        /* is to be found                 */
        PULONG pcbSize);                /* size in bytes (returned)       */

/* Segment attribute flags (used with DosAllocSeg) */

#define SEG_NONSHARED       0x0000
#define SEG_GIVEABLE        0x0001
#define SEG_GETTABLE        0x0002
#define SEG_DISCARDABLE     0x0004

#endif /* common INCL_DOSMEMMGR */

#ifdef INCL_DOSMEMMGR


/***   DosAllocHuge - Allocate huge memory
 *
 *     Allocates multiple segments of memory.
 *
 */

USHORT APIENTRY DosAllocHuge(
        USHORT cSegs,          /* number of 64k segments                      */
        USHORT cbPartialSeg,   /* number of bytes in last non-64k segment     */
        PSEL psel,             /* selector allocated (returned)               */
        USHORT cMaxSegs,       /* max number of 64k segments                  */
        USHORT fsAlloc);       /* sharing attributes of the allocated segment */


/***   DosReallocHuge - Change huge memory size
 *
 *     Changes the size of memory originally allocated by DosAllocHuge.
 *
 */

USHORT APIENTRY DosReallocHuge(
        USHORT cSegs,              /* number of 64k segments requested        */
        USHORT cbPartialSeg,       /* number of bytes in last non-64k segment */
        SEL sel);                  /* selector                                */


/***   DosGetHugeShift - Get shift count
 *
 *    Returns a shift count used to derive the selectors that address memory
 *    allocated with DosAllocHuge.
 *
 */

USHORT APIENTRY DosGetHugeShift(
        PUSHORT pusShiftCount);         /* shift count (returned)             */


/***   DosAllocShrSeg - Allocate shared segment
 *
 *     Allocates a shared memory segment to a process.
 *
 */

USHORT APIENTRY DosAllocShrSeg(
        USHORT cbSeg,          /* number of bytes requested                   */
        PSZ pszSegName,        /* symbolic name associated with shared memory */
        PSEL psel);            /* selector of allocated segment (returned)    */


/***   DosLockSeg - Lock segment in memory
 *
 *     Locks a discardable segment in memory.
 *
 */

USHORT APIENTRY DosLockSeg(
        SEL sel);                       /* selector of segment to be locked   */


/***   DosUnlockSeg - Unlock segment
 *
 *     Unlocks a discardable segment.
 *
 */

USHORT APIENTRY DosUnlockSeg(
        SEL sel);                       /* selector of segment to be unlocked */


/***   DosGetShrSeg - Access shared segment
 *
 *     Accesses a shared memory segment previously allocated by another
 *     process.
 *
 */

USHORT APIENTRY DosGetShrSeg(
        PSZ pszSegName,                 /* name string associated with the   */
                                        /* shared memory segment             */
        PSEL psel);                     /* selector of shared memory segment */
                                        /* (returned)                        */


/***   DosMemAvail - Get size of largest free memory block
 *
 *     Returns the size of the largest block of free memory.
 *
 */

USHORT APIENTRY DosMemAvail(
        PULONG pcbFree);             /* size of largest free block (returned) */


/***   DosCreateCSAlias - Create CS alias
 *
 *     Creates a code segment alias descriptor for a data segment passed as
 *     input.
 *
 */

USHORT APIENTRY DosCreateCSAlias(
        SEL selDs,                      /* data segment selector           */
        PSEL pselCS);                   /* selector of code segment allias */
                                        /* descriptor (returned)           */


/***   DosSubAlloc - Suballocate memory within segment
 *
 *     Allocates memory from a segment previously allocated by DosAllocSeg or
 *     DosAllocShrSeg and initialized by DosSubSet.
 *
 */

USHORT APIENTRY DosSubAlloc(
        SEL sel,                  /* segment selector from which memory       */
                                  /* is to be allocated                       */
        PUSHORT ousOffset,        /* offset to the block allocated (returned) */
        USHORT cb);               /* size of memory block requested in bytes  */


/***   DosSubFree - Free memory suballocated within segment
 *
 *     Frees memory previously allocated by DosSubAlloc.
 *
 */

USHORT APIENTRY DosSubFree(
        SEL sel,                    /* segment selector from which            */
                                    /* memory is to be freed                  */
        USHORT offBlock,            /* offset of memory block to free         */
        USHORT cb);                 /* size of the block to be freed in bytes */


/***   DosSubSet - Initialize or set allocated memory
 *
 *     Used to initialize a segment for suballocation or to increase the size
 *     a previously initialized, suballocated segment.
 *
 */

USHORT APIENTRY DosSubSet(
        SEL sel,                       /* selector of the target data segment */
        USHORT fFlags,                 /* 0=increasing size of a segment      */
                                       /* 1=initializing a segment            */
        USHORT cbNew);                 /* size of the segment in bytes        */

#endif /* INCL_DOSMEMMGR */

#if (defined(INCL_DOSSEMAPHORES) || !defined(INCL_NOCOMMON))

/*** Semaphore support */

#define SEM_INDEFINITE_WAIT         -1L
#define SEM_IMMEDIATE_RETURN         0L

/***   DosSemClear - Clear (release) semaphore
 *
 *     Unconditionally clears a semaphore. If any threads were blocked on the
 *     semaphore, they are restarted.
 *
 */

USHORT APIENTRY DosSemClear(
        HSEM hsem);                     /* semaphore handle                   */


/***   DosSemSet - Set Semaphore Owned
 *
 *     Unconditionally sets a seaphore.
 *
 */

USHORT APIENTRY DosSemSet(
        HSEM hsem);                     /* semaphore handle                   */


/***   DosSemWait - Wait for semaphore to clear
 *
 *     Blocks the current thread until an indicated semaphore clears, but does
 *     not establish ownership of this semaphore.
 *
 */

USHORT APIENTRY DosSemWait(
        HSEM hsem,                      /* semaphore handle                   */
        LONG lTimeOut);                 /* timeout (in milliseconds)          */


/***   DosSemSetWait - Set semaphore and wait for next clear
 *
 *     Blocks the current thread until the next DosSemClear is issued. However,
 *     DosSemSetWait does not establish ownership of this semaphore.
 *
 */

USHORT APIENTRY DosSemSetWait(
        HSEM hsem,                      /* semaphore handle                   */
        LONG lTimeOut);                 /* timeout (in milliseconds)          */


/***   DosSemRequest - Request semaphore
 *
 *     Obtains a semaphore. If the semaphore is already owned, the requesting
 *     thread is placed in a wait state until the semaphore is released or
 *     until a time out occures.
 *
 */

USHORT APIENTRY DosSemRequest(
        HSEM hsem,                      /* semaphore handle                   */
        LONG lTimeOut);                 /* timeout (in milliseconds)          */

#endif /* common INCL_DOSSEMAPHORES */

#ifdef INCL_DOSSEMAPHORES

typedef LHANDLE HSYSSEM;
typedef HSYSSEM FAR *PHSYSSEM;


/***   DosCreateSem - Create system semaphore
 *
 *     Creates a system semaphore used by semaphore manipulation calls such as
 *     DosSemRequest, DosSemClear, DosSemSet, DosSemSetWait, DosSemWait, and
 *     DosMuxSemWait.
 *
 */

USHORT APIENTRY DosCreateSem(
        USHORT fExclusive,              /* indicate no exclusive ownership    */
        PHSYSSEM phsem,                 /* semaphore handle (returned)        */
        PSZ pszSemName);                /* semaphore name string              */

#define CSEM_PRIVATE    0
#define CSEM_PUBLIC     1


/***   DosOpenSem - Open existing system semaphore
 *
 *     Opens a system semaphore.
 *
 */

USHORT APIENTRY DosOpenSem(
        PHSEM phsem,                    /* semaphore handle (returned)        */
        PSZ pszSemName);                /* semaphore name string              */


/***   DosCloseSem - Close system semaphore
 *
 *     Closes a specific system semaphore.
 *
 */

USHORT APIENTRY DosCloseSem(
        HSEM hsem);                     /* semaphore handle                   */

typedef struct _MUXSEM {
    USHORT zero;                        /* zero             */
    HSEM   hsem;                        /* semaphore handle */
} MUXSEM;
typedef MUXSEM FAR *PMUXSEM;

typedef struct _MUXSEMLIST {
    USHORT  cmxs;                         /* count of MUXSEM structures */
    MUXSEM  amxs[16];                     /* array of MUXSEM structures */
} MUXSEMLIST;
typedef MUXSEMLIST FAR *PMUXSEMLIST;

/*
 * Since a MUXSEMLIST structure is actually a variable length
 * structure, the following macro may be used to define a MUXSEMLIST
 * structure having size elements, named "name".
 */
#define DEFINEMUXSEMLIST(name, size) \
    struct {                         \
        USHORT cmxs;                 \
        MUXSEM amxs[size];           \
    } name;

/*
 * This function actually takes a far pointer to a MUXSEMLIST structure
 * as its second parameter, but in order to allow its use with the
 * DEFINEMUXSEMLIST macro, it is declared here as PVOID.
 */


/***   DosMuxSemWait - Wait for one of n semaphores to clear
 *
 *     Blocks a current thread until one of the specefied semaphores clear.
 *
 */

USHORT APIENTRY DosMuxSemWait(
        PUSHORT pisemCleared,           /* index number of event (returned)   */
        PVOID pmsxl,                    /* semaphore list                     */
        LONG lTimeOut);                 /* timeout (in milliseconds)          */


/*** Fast safe ram semaphores */

typedef struct _DOSFSRSEM {
    USHORT cb;                            /* length of this structure (bytes) */
    PID    pid;                           /* Process ID of the owner or zero  */
    TID    tid;                           /* Thread ID of the owner or zero   */
    USHORT cUsage;                        /* Reference count                  */
    USHORT client;                        /* 16 bit field for use by owner    */
    ULONG  sem;                           /* OS/2 Ram Semaphore               */
} DOSFSRSEM;
typedef DOSFSRSEM FAR *PDOSFSRSEM;


/***   DosFSRamSemRequest - Safe ram semaphore request
 *
 *     Obtains a ram seaphore and records the current owner for potential
 *     cleanup by a dos exit list routine.
 *
 */

USHORT APIENTRY DosFSRamSemRequest(
        PDOSFSRSEM pdosfsrs,            /* Address of the fast-safe    */
                                        /* RamSemaphore data structure */
        LONG lTimeOut);                 /* timeout, in milliseconds    */


/***   DosFSRamSemClear - Clear (release) a fast-safe ram semaphore */

USHORT APIENTRY DosFSRamSemClear(
        PDOSFSRSEM pdosfsrs);           /* Address of the fast-safe    */
                                        /* RamSemaphore data structure */

#endif /* INCL_DOSSEMAPHORES */

#if (defined(INCL_DOSDATETIME) || !defined(INCL_NOCOMMON))

/*** Time support */

typedef struct _DATETIME {
    UCHAR   hours;                        /* current hour                   */
    UCHAR   minutes;                      /* current minute                 */
    UCHAR   seconds;                      /* current second                 */
    UCHAR   hundredths;                   /* current hundredths of a second */
    UCHAR   day;                          /* current day                    */
    UCHAR   month;                        /* current month                  */
    USHORT  year;                         /* current year                   */
    SHORT   timezone;                     /* minutes of time west of GMT    */
    UCHAR   weekday;                      /* current day of week            */
} DATETIME;
typedef DATETIME FAR *PDATETIME;


/***   DosGetDateTime - Get current date and time
 *
 *     Gets the current date and time maintained by the operating system.
 *
 */

USHORT APIENTRY DosGetDateTime(
        PDATETIME pdatetime);           /* date/time structure (returned)     */


/***   DosSetDateTime - Set current date and time
 *
 *     Used to set the date and time that are maintained by the operating
 *     system.
 *
 */

USHORT APIENTRY DosSetDateTime(
        PDATETIME pdatetime);           /* date/time structure                */


#endif /* common INCL_DOSDATETIME */

#ifdef INCL_DOSDATETIME

typedef SHANDLE HTIMER;
typedef HTIMER FAR *PHTIMER;


/***   DosTimerAsync - Start asynchronous time delay
 *
 *     Starts a timer that runs asynchronously to the thread issuing the
 *     request and clears a sytem semaphore when the specified interval
 *     expires.
 *
 */

USHORT APIENTRY DosTimerAsync(
        ULONG ulTime,                   /* time (in milliseconds) before      */
                                        /* semaphore is cleared               */
        HSEM hsem,                      /* system semaphore handle            */
        PHTIMER phtimer);               /* timer handle (returned)            */


/***   DosTimerStart - Start periodic interval timer
 *
 *     Starts a periodic interval timer that runs asynchronously to the thread
 *     issuing the request.
 *
 */

USHORT APIENTRY DosTimerStart(
        ULONG ulTime,                   /* time (in milliseconds) before      */
                                        /* semaphore is cleared               */
        HSEM hsem,                      /* system semaphore handle            */
        PHTIMER phtimer);               /* timer handle (returned)            */


/***   DosTimerStop - Stop interval timer
 *
 *     Stops a periodic interval timer started by DosTimerStart, or an
 *     asynchronous timer started by DosTimerAsync.
 *
 */

USHORT APIENTRY DosTimerStop(
        HTIMER htimer);                 /* handle of the timer                */

#endif /* INCL_DOSDATETIME */


/*** Module manager */

#ifdef INCL_DOSMODULEMGR


/***   DosLoadModule - Load dynamic link module
 *
 *     Loads a dynamic link module and returns a handle for the module.
 *
 */

USHORT APIENTRY DosLoadModule(
        PSZ pszFailName,                /* object name buffer                 */
        USHORT cbFileName,              /* length of object name buffer       */
        PSZ pszModName,                 /* dynamic link module name string    */
        PHMODULE hmod);                 /* module handle (returned)           */


/***   DosFreeModule - Free dynamic link module
 *
 *     Frees the reference to a dynamic link module for a process. When the
 *     dynamic link module is no longer needed by any process, the module is
 *     freed from system memory.
 *
 */

USHORT APIENTRY DosFreeModule(
        HMODULE hmod);                  /* module handle                      */


/***   DosGetProcAddr - Get dynamic link procedure address
 *
 *     Returns a far address to a desired procedure within a dynamic link
 *     module.
 *
 */

USHORT APIENTRY DosGetProcAddr(
        HMODULE hmod,          /* handle of module where procedure is located */
        PSZ pszProcName,       /* name of module where procedure is located   */
        PFN FAR * ppfnProcAddr);        /* procedure address (returned)       */



/***   DosGetModHandle - Get dynamic link module handle
 *
 *     Returns a handle to a previously loaded dynamic link module.
 *
 */

USHORT APIENTRY DosGetModHandle(
        PSZ pszModName,                 /* dynamic link module name           */
        PHMODULE phmod);                /* module handle (returned)           */


/***   DosGetModName - Get dynamic link module name
 *
 *     Returns the fully qualified drive, path, filename, and extension
 *     associated with a referenced module handle.
 *
 */

USHORT APIENTRY DosGetModName(
        HMODULE hmod,            /* module handle                             */
        USHORT cbBuf,            /* max length of buffer where name is stored */
        PCHAR pchBuf);           /* buffer (returned) where info is stored    */

#endif /* INCL_DOSMODULEMGR */

#if (defined(INCL_DOSRESOURCES) || !defined(INCL_NOCOMMON))

/*** Resource support */

/* Predefined resource types */

#define RT_POINTER      1   /* mouse pointer shape */
#define RT_BITMAP       2   /* bitmap */
#define RT_MENU         3   /* menu template */
#define RT_DIALOG       4   /* dialog template */
#define RT_STRING       5   /* string tables */
#define RT_FONTDIR      6   /* font directory */
#define RT_FONT         7   /* font */
#define RT_ACCELTABLE   8   /* accelerator tables */
#define RT_RCDATA       9   /* binary data */
#define RT_MESSAGE      10  /* error msg     tables */
#define RT_DLGINCLUDE   11  /* dialog include file name */
#define RT_VKEYTBL      12  /* key to vkey tables */
#define RT_KEYTBL       13  /* key to UGL tables */
#define RT_CHARTBL      14  /* glyph to character tables */
#define RT_DISPLAYINFO  15  /* screen display information */
#define RT_FKASHORT     16  /* function key area short form */
#define RT_FKALONG      17  /* function key area long form */

#define RT_HELPTABLE    18  /* Help table for IPFC */
#define RT_HELPSUBTABLE 19  /* Help subtable for IPFC */

#define RT_FDDIR        20  /* DBCS uniq/font driver directory */
#define RT_FD           21  /* DBCS uniq/font driver */
#define RT_MAX          22  /* 1st unused Resource Type */

#endif /* common INCL_DOSRESOURCES */

#ifdef INCL_DOSRESOURCES


/***   DosGetResource - Get resource segment selector
 *
 *     Returns the segment selector of the specified resource segment.
 *
 */

USHORT APIENTRY DosGetResource(
        HMODULE hmod,                   /* module handle                */
        USHORT idType,                  /* resource type ID             */
        USHORT idName,                  /* resource name ID             */
        PSEL psel);                     /* resource selector (returned) */


/***   DosGetResource2 - Get resource far pointer
 *
 *     Returns a far pointer to the specified resource data.
 *
 */

USHORT APIENTRY DosGetResource2(
        HMODULE hmod,                   /* module handle                   */
        USHORT idType,                  /* resource type ID                */
        USHORT idName,                  /* resource name ID                */
        PVOID FAR * ppData);            /* resource far pointer (returned) */


/***   DosFreeResource - Free Resource
 *
 *     Deallocates memory of a resource.
 *
 */

USHORT APIENTRY DosFreeResource(
        PVOID pData);                   /* resource pointer */


#endif /* INCL_DOSRESOURCES */


/*** NLS Support */

#ifdef INCL_DOSNLS

/***   _COUNTRYCODE is used by DOSGETCTRYINFO to store
 *              the country code and code page
 */

typedef struct _COUNTRYCODE {
    USHORT country;                     /* country code */
    USHORT codepage;                    /* code page    */
} COUNTRYCODE;
typedef COUNTRYCODE FAR *PCOUNTRYCODE;

/***   _COUNTRYINFO is used by DOSGETCTRYINFO to store
 *              various country-dependent data items
 */

typedef struct _COUNTRYINFO {
    USHORT country;                     /* country code                   */
    USHORT codepage;                    /* code page                      */
    USHORT fsDateFmt;                   /* date format                    */
    CHAR   szCurrency[5];               /* currency indicator             */
    CHAR   szThousandsSeparator[2];     /* thousands separator            */
    CHAR   szDecimal[2];                /* decimal separator              */
    CHAR   szDateSeparator[2];          /* date separator                 */
    CHAR   szTimeSeparator[2];          /* time separator                 */
    UCHAR  fsCurrencyFmt;               /* bit fields for currency format */
    UCHAR  cDecimalPlace;               /* currency decimal places        */
    UCHAR  fsTimeFmt;                   /* Time format (AM/PM or 24 hr)   */
    USHORT abReserved1[2];              /* reserved (0)                   */
    CHAR   szDataSeparator[2];          /* Data list separator            */
    USHORT abReserved2[5];              /* reserved (0)                   */
} COUNTRYINFO;
typedef COUNTRYINFO FAR *PCOUNTRYINFO;


/***   DosGetCtryInfo - Get country information
 *
 *     Obtains contry dependent formatting information that resides in the
 *     country information file.
 *
 */

USHORT APIENTRY DosGetCtryInfo(
        USHORT  cbBuf,              /* length of data area provided           */
        PCOUNTRYCODE pctryc,        /* input data structure                   */
        PCOUNTRYINFO pctryi,        /* data area to be filled by the function */
        PUSHORT pcbCtryInfo);       /* length of data (returned)              */


/***   DosGetDBCSEv - Get DBCS environmental vector
 *
 *     Obtains a DBCS (double byte character set) environmental vector that
 *     resides in the country information file
 *
 */

USHORT APIENTRY DosGetDBCSEv(
        USHORT cbBuf,                 /* length of data area provided         */
        PCOUNTRYCODE pctryc,          /* input data structure                 */
        PCHAR pchBuf);                /* data area to contain the information */


/***   DosCaseMap - Perform case mapping
 *
 *     Performs case mapping on a string of binary values that represent ASCII
 *     characters.
 *
 */

USHORT APIENTRY DosCaseMap(
        USHORT usLen,                  /* length of string to case map        */
        PCOUNTRYCODE pctryc,           /* input data structure                */
        PCHAR pchStr);                 /* address of string to be case mapped */


/***   DosGetCollate - Get collate table
 *
 *     Obtains a collating sequence table (for characters 00H through FFH) that
 *     resides in the country information file. It is used by the SORT utility
 *     to sort text according to the collating sequence.
 *
 */

USHORT APIENTRY DosGetCollate(
        USHORT usLen,               /* length of data area provided           */
        PCOUNTRYCODE pctryc,        /* input data structure                   */
        PCHAR pchBuf,               /* data area to contain the collate table */
        PUSHORT pcbTable);          /* length of table (returned)             */


/***   DosGetCp - Get process code page
 *
 *     Allows a process to query the current process code page and the prepared
 *     system code pages.
 *
 */

USHORT APIENTRY DosGetCp(
        USHORT cbBuf,                   /* length of CodePageList in bytes    */
        PUSHORT pBuf,                   /* CodePageList (returned)            */
        PUSHORT pcbCodePgLst);          /* length of returned list            */


/***   DosSetCp - Set code page
 *
 *     Allows a process to set its code page and the session's display code
 *     page and keyboard code page.
 *
 */

USHORT APIENTRY DosSetCp(
        USHORT usCodePage,              /* code page identifier               */
        USHORT usReserved);             /* reserved (must be set to 0)        */

/*** DosSetProcCp - Set process code page
 *
 *     Allows a process to set it's own code page.
 */

USHORT APIENTRY DosSetProcCp(
        USHORT usCodePage,              /* Code page identifier word          */
        USHORT usReserved);             /* Reserved (must be set to 0)        */

#endif /* INCL_DOSNLS */


/*** Signal support */

#ifdef INCL_DOSSIGNALS

/* Signal Numbers for DosSetSigHandler  */

#define SIG_CTRLC           1       /* Control C            */
#define SIG_BROKENPIPE      2       /* Broken Pipe          */
#define SIG_KILLPROCESS     3       /* Program Termination  */
#define SIG_CTRLBREAK       4       /* Control Break        */
#define SIG_PFLG_A          5       /* Process Flag A       */
#define SIG_PFLG_B          6       /* Process Flag B       */
#define SIG_PFLG_C          7       /* Process Flag C       */
#define SIG_CSIGNALS        8       /* number of signals plus one */

/* Flag Numbers for DosFlagProcess      */

#define PFLG_A              0       /* Process Flag A       */
#define PFLG_B              1       /* Process Flag B       */
#define PFLG_C              2       /* Process Flag C       */

/* Signal actions */

#define SIGA_KILL           0
#define SIGA_IGNORE         1
#define SIGA_ACCEPT         2
#define SIGA_ERROR          3
#define SIGA_ACKNOWLEDGE    4

/* DosHoldSignal constants */

#define HLDSIG_ENABLE       0
#define HLDSIG_DISABLE      1

/* DosFlagProcess codes */

#define FLGP_SUBTREE        0
#define FLGP_PID            1

typedef VOID (PASCAL FAR *PFNSIGHANDLER)(USHORT, USHORT);

/***    DosSetSigHandler - Handle Signal
 *
 *      Notifies OS/2 of a handler for a signal.  It may also be used
 *      to ignore a signal or install a default action for a signal.
 */

USHORT APIENTRY DosSetSigHandler(
        PFNSIGHANDLER pfnSigHandler,    /* Signal handler address      */
        PFNSIGHANDLER FAR * ppfnPrev,   /* Address of previous handler */
        PUSHORT pfAction,               /* Address of previous action  */
        USHORT fAction,                 /* Indicate request type       */
        USHORT usSigNum);               /* Signal number               */


/***    DosFlagProcess - Issue signal
 *
 *      Used to send a signal event to an arbitrary process or
 *      command subtree.
 */

USHORT APIENTRY DosFlagProcess(
        PID pid,                        /* Process ID to signal              */
        USHORT fScope,                  /* 0=notify entire subtree, 1=notify */
                                        /* only the indicated process        */
        USHORT usFlagNum,               /* Flag number                       */
        USHORT usFlagArg);              /* Flag argument                     */

/***    DosHoldSignal - Disable / Enable signals
 *
 *      Used to termporarily disable or enable signal processing
 *      for the current process.
 */

USHORT APIENTRY DosHoldSignal(
        USHORT fDisable);               /* 0=enable signal, 1=disable signal */

/***    DosSendSignal - Send Signal to Command Subtree Process Handler
 *
 *      Used to send a signal to last process (leaf-most) in command subtree
 *      that has a handler installed
 */

USHORT APIENTRY DosSendSignal(
        USHORT idProcess,               /* process ID of the root process */
                                        /* of the subtree                 */
        USHORT  usSigNumber);           /* signal number to send          */

#endif /* INCL_DOSSIGNALS */


/*** Monitor support */

#ifdef INCL_DOSMONITORS

typedef SHANDLE HMONITOR;    /* hmon */
typedef HMONITOR FAR *PHMONITOR;


/***   DosMonOpen - Open connection to device monitor
 *
 *     Gains access to a character device data stream.
 *
 */

USHORT APIENTRY DosMonOpen(
        PSZ pszDevName,                 /* Device name string (returned)      */
        PHMONITOR phmon);               /* Monitor handle (returned)          */


/***   DosMonClose - Close connection to device monitor
 *
 *     Terminates character device monitoring. All monitor buffers associated
 *     with this process are flushed and closed.
 *
 */

USHORT APIENTRY DosMonClose(
        HMONITOR hmon);                 /* handle from previous DosMonOpen */


/***   DosMonReg - Register set of buffers as monitor
 *
 *     Establishes an input and output buffer structure to monitor an I/O
 *     stream for a character device.
 *
 */

USHORT APIENTRY DosMonReg(
        HMONITOR hmon,                  /* handle from DosMonOpen       */
        PBYTE pbInBuf,                  /* input buffer                 */
        PBYTE pbOutBuf,                 /* output buffer                */
        USHORT fPosition,               /* position preference flag     */
        USHORT usIndex);                /* index of data stream for the */
                                        /* device being monitered       */


/***   DosMonRead - Read input from monitor structure
 *
 *     Waits for and moves a data recorrd from the input buffer of a registered
 *     character device monitor and places it in a private data area where the
 *     monitor can freely access it.
 *
 */

USHORT APIENTRY DosMonRead(
        PBYTE pbInBuf,                  /* monitor input buffer               */
        UCHAR fWait,                    /* block/run indicator                */
        PBYTE pbDataBuf,                /* buffer into which records are read */
        PUSHORT pcbData);               /* length of the data buffer/number   */
                                        /* of bytes moved                     */


/***   DosMonWrite - Write output to monitor structure
 *
 *     Moves a filtered data record from the monitor's private data area into
 *     the monitor's output buffer.
 *
 */

USHORT APIENTRY DosMonWrite(
        PBYTE pbOutBuf,                /* monitor output buffer               */
        PBYTE pbDataBuf,               /* buffer from which records are taken */
        USHORT cbData);                /* number of bytes in the data record  */


#endif /* INCL_DOSMONITORS */


/*** Pipe and queue support */

#ifdef INCL_DOSQUEUES
#if (defined(INCL_DOSFILEMGR) || !defined(INCL_NOCOMMON))

typedef SHANDLE HQUEUE;  /* hq */
typedef HQUEUE FAR *PHQUEUE;

/***    DosMakePipe - Create a Pipe */

USHORT APIENTRY DosMakePipe(
        PHFILE phfRead,                 /* Addr to place the read handle  */
        PHFILE phfWrite,                /* Addr to place the write handle */
        USHORT cb);                     /* Size to reserve for the pipe   */

/***    DosCloseQueue - Close a Queue
 *
 *      close a queue which is in use by the requesting process
 *
 */

USHORT APIENTRY DosCloseQueue(
        HQUEUE hqueue);                 /* queue handle */

/***    DosCreateQueue - Create a Queue
 *
 *      creates a queue to be owned by the requesting process
 *
 */

USHORT APIENTRY DosCreateQueue(
        PHQUEUE phqueue,                /* read/write handle of queue  */
        USHORT fQueueOrder,             /* 0=FIFO queue, 1=LIFO queue, */
                                        /* 2=Priority queue            */
        PSZ pszQueueName);              /* name of the queue           */

/***    DosOpenQueue - Open a Queue
 *
 *      opens a queue for the current process
 *
 */

USHORT APIENTRY DosOpenQueue(
        PUSHORT ppidOwner,              /* PID of queue owner */
        PHQUEUE phqueue,                /* queue handle       */
        PSZ pszQueueName);              /* queue name         */

/***    DosPeekQueue - Peek at a Queue
 *
 *      retrieves an element from a queue without removing it from the queue
 *
 */

USHORT APIENTRY DosPeekQueue(
        HQUEUE hqueue,                  /* queue handle                   */
        PULONG pqresc,                  /* pointer to request             */
        PUSHORT pcbElement,             /* length of datum returned       */
        PULONG ppBuf,                   /* pointer to address of datum    */
        PUSHORT pElemCode,              /* indicator of datum returned    */
        UCHAR fwait,                    /* wait indicator for empty queue */
        PBYTE pbElemPrty,               /* priority of element            */
        ULONG hsem);                    /* semaphore handle               */

/***    DosPurgeQueue - Purge a Queue
 *
 *      purges all elements from a queue
 *
 */

USHORT APIENTRY DosPurgeQueue(
        HQUEUE hqueue);                 /* queue handle */

/***    DosQueryQueue - Query size of a Queue
 *
 *      returns the number of elements in a queue
 *
 */

USHORT APIENTRY DosQueryQueue(
        HQUEUE hqueue,                  /* queue handle                   */
        PUSHORT pcElem);                /* pointer for number of elements */

/***    DosReadQueue - Read from a Queue
 *
 *      retrieves an element from a queue
 *
 */

USHORT APIENTRY DosReadQueue(
        HQUEUE hqueue,                  /* queue handle                   */
        PULONG pqresc,                  /* pointer to request             */
        PUSHORT pcbElem,                /* length of datum returned       */
        PULONG ppBuf,                   /* pointer to address of datum    */
        USHORT usElem,                  /* indicator of datum returned    */
        UCHAR fWait,                    /* wait indicator for empty queue */
        PBYTE pbElemPrty,               /* priority of element            */
        HSEM hsem);                     /* semaphore handle               */

/***    DosWriteQueue - Write to a Queue
 *
 *      adds an element to a queue
 *
 */

USHORT APIENTRY DosWriteQueue(
        HQUEUE hqueue,                  /* queue handle        */
        USHORT usRequest,               /* request             */
        USHORT cbBuf,                   /* length of datum     */
        PBYTE pBuf,                     /* address of datum    */
        UCHAR fPriority);               /* priority of element */


#else /* INCL_DOSFILEMGR || !INCL_NOCOMMON */
#error PHFILE not defined - define INCL_DOSFILEMGR or undefine INCL_NOCOMMON
#endif /* INCL_DOSFILEMGR || !INCL_NOCOMMON */
#endif /* INCL_DOSQUEUES */

#ifdef INCL_DOSMISC

/***   DosError - Enable hard error processing
 *
 *     Allows a process to disable user notification (from OS/2) on hard errors
 *     and program exceptions.
 *
 */

USHORT APIENTRY DosError(
        USHORT fEnable);                /* action flag (bit field)            */


/***   DosSetVec - Establish handler for exception vector
 *
 *     Allows a process to register an address to be used when a machine
 *     exception occurs.
 *
 */

USHORT APIENTRY DosSetVec(
        USHORT usVecNum,               /* number of the vector to be          */
                                       /* serviced by this routine            */
        PFN pfnFun,                    /* handler routine                     */
        PFN FAR *ppfnPrev);            /* previous handler address (returned) */

/***   DosGetMessage - System message with variable text
 *
 *     Retrieves a message from a message file and inserts variable information
 *     into the body of the message.
 *
 */

USHORT APIENTRY DosGetMessage(
        PCHAR FAR * ppchVTable ,     /* table of variables to insert          */
        USHORT  usVCount,            /* number of variables                   */
        PCHAR pchBuf,                /* data area (where message is returned) */
        USHORT cbBuf,                /* length of data area                   */
        USHORT usMsgNum,             /* number of the message requested       */
        PSZ pszFileName,             /* message path and file name            */
        PUSHORT pcbMsg);             /* length of message (returned)          */


/***   DosErrClass - Classify error codes
 *
 *     Helps OS/2 applications respnd to error codes (return codes) received
 *     from the OS/2 API.
 *
 */

USHORT APIENTRY DosErrClass(
        USHORT usErrCode,               /* error code for analysis            */
        PUSHORT pusClass,               /* error classification (returned)    */
        PUSHORT pfsAction,              /* recommended action (returned)      */
        PUSHORT pusLocus);              /* origin of the error (returned)     */


/***   DosInsMessage - Insert variable text strings in message
 *
 *     Inserts variable text string information into the body of a message.
 *     This is useful when messages are loaded before insertion text strings
 *     are known.
 *
 */

USHORT APIENTRY DosInsMessage(
        PCHAR FAR * ppchVTable,         /* table of variables to insert   */
        USHORT usVCount,                /* number of variables            */
        PSZ pszMsg,                     /* address of input message       */
        USHORT cbMsg,                   /* length of input message        */
        PCHAR pchBuf,                   /* data area address to return    */
                                        /* message to                     */
        USHORT cbBuf,                   /* length of data area (returned) */
        PUSHORT pcbMsg);                /* length of updated messsage     */


/***   DosPutMessage - Output message text to indicated handle
 *
 *     Outputs the message in a buffer passed by a caller to the specified
 *     handle. The function formats the buffer to prevent words from wrapping
 *     if displayed to a screen.
 *
 */

USHORT APIENTRY DosPutMessage(
        USHORT hf,                      /* handle of output file/device     */
        USHORT cbMsg,                   /* length of message                */
        PCHAR pchMsg);                  /* message buffer that contains the */
                                        /* message to be output             */



/***   DosPtrace - Interface for program debugging
 *
 *     Provides an interface into the OS/2 kernel to facilitate program
 *     debugging.
 *
 */

USHORT APIENTRY DosPtrace(
       PBYTE pPtraceBuf);               /* Ptrace buffer */

/* definition for DOSQSYSINFO */
#define Q_MAX_PATH_LENGTH        (0)       /* index for query max path length */

/***    DosQSysInfo - query system constants
 *
 *      Returns system constants like the maximum path name length.
 *
 */

USHORT APIENTRY  DosQSysInfo (
        USHORT index,                   /* Index of constant requested */
        PBYTE pBuf,                     /* Pointer to return buffer    */
        USHORT cbBuf);                  /* return buffer size          */

/***   DosGetEnv - Get address of process environment string
 *
 *     Returns the address of the process environment string for the current
 *     process.
 *
 */

USHORT APIENTRY DosGetEnv(
        PUSHORT pselEnv,                /* selector for the environment   */
                                        /* segment (returned)             */
        PUSHORT pOffsetCmd);            /* command line offset (returned) */


/***   DosScanEnv - Scan an environment segment
 *
 *     Scans (searches) an environment segment for an envirnment variable.
 *
 */

USHORT APIENTRY DosScanEnv(
        PSZ pszVarName,                /* environment variable name           */
        PSZ FAR * ppszResult);         /* search result pointer (returned)    */


/***   DosSearchPath - Search path for file name
 *
 *     Provides a general path search mechanism which allows applications to
 *     find files residing along paths. The path string may come from the
 *     process environment, or be supplied directly by the caller.
 *
 */

USHORT APIENTRY DosSearchPath(
        USHORT fsSearch,                /* function control vector            */
        PSZ pszPath,                    /* search path reference              */
        PSZ pszFName,                   /* file name                          */
        PBYTE pBuf,                     /* search result buffer               */
        USHORT cbBuf);                  /* search result buffer length        */


/***   DosGetVersion - Get OS/2 version number   */

USHORT APIENTRY DosGetVersion(
        PUSHORT pVer);                  /* version number (returned)          */


/*** DosGetMachineMode - Return current mode of processor
 *
 *   Returns the current mode of the processor, whether the processor is
 *   running in the DOS mode or the OS/2 mode. This allows an application to
 *   determine whether a dynamic link call is valid or not.
 *
 */

USHORT APIENTRY DosGetMachineMode(
        PBYTE pMachMode);               /* current processor mode (returned)  */

#endif /* INCL_DOSMISC */


/*** Session manager support */

#ifdef INCL_DOSSESMGR

/* DOSSTARTSESSION data structure definition */

typedef struct _STARTDATA {
    USHORT Length;        /* length of data structure in bytes                */
    USHORT Related;       /* 0 = independent session, 1 = child session       */
    USHORT FgBg;          /* 0 = start in foreground, 1 = start in background */
    USHORT TraceOpt;      /* 0 = no trace, 1 = trace                          */
    PSZ    PgmTitle;      /* address of program title                         */
    PSZ    PgmName;       /* address of program name                          */
    PBYTE  PgmInputs;     /* input arguments                                  */
    PBYTE  TermQ;         /* address of program queue name                    */
    PBYTE  Environment;   /* environment string                               */
    USHORT InheritOpt;    /* where are handles and environment inherited from */
                          /* 0 = inherit from shell , 1 = inherit from caller */
    USHORT SessionType;   /* session type                                     */
    PSZ    IconFile;      /* address of icon definition                       */
    ULONG  PgmHandle;     /* program handle                                   */
    USHORT PgmControl;    /* initial state of windowed application            */
    USHORT InitXPos;      /* x coordinate of initial session window           */
    USHORT InitYPos;      /* y coordinate of initial session window           */
    USHORT InitXSize;     /* initial size of x                                */
    USHORT InitYSize;     /* initial size of y                                */
} STARTDATA;
typedef STARTDATA FAR *PSTARTDATA;


/* DOSSETSESSION data structure definition */

typedef struct _STATUSDATA {
    USHORT Length;                 /* length of this data structure           */
    USHORT SelectInd;              /* 0=leave setting unchanged, 1=selectable */
                                   /* 2=non-selectable                        */
    USHORT BondInd;                /* which session to bring to foreground    */
} STATUSDATA;
typedef STATUSDATA FAR *PSTATUSDATA;


/* DOSSMREGISTERDD data structure definition */

typedef struct _REGISTERDATA {
    USHORT Length;                 /* length of this data structure           */
    USHORT NotifType;              /* type of notification                    */
    PCHAR  DDName;                 /* device driver name                      */
} REGISTERDATA;
typedef REGISTERDATA FAR *PREGISTERDATA;


/*** DosStartSession - Start session
 *
 *   Provides an application program interface to start another session and
 *   specify the name of the program to start in the session.
 *
 */

USHORT APIENTRY DosStartSession(
        PSTARTDATA pstdata,             /* start session data structure       */
        PUSHORT pidSession,             /* session ID (returned)              */
        PUSHORT ppid);                  /* process ID (returned)              */


/***   DosSetSession - Set session status
 *
 *     Sets the status of a child session.
 *
 */

USHORT APIENTRY DosSetSession(
        USHORT idSession,               /* session ID                         */
        PSTATUSDATA pstsdata);          /* session status data structure      */


/***   DosSelectSession - Select foreground session
 *
 *     Allows a parent session to switch one of its child sessions to the
 *     foreground
 *
 */

USHORT APIENTRY DosSelectSession(
        USHORT idSession,               /* session ID                         */
        ULONG usReserved);              /* reserved (must be 0)               */


/***   DosStopSession - Stop session
 *
 *     Terminates a session previously started with DosStartSession.
 *
 */

USHORT APIENTRY DosStopSession(
        USHORT fScope,                  /* target option                      */
        USHORT isSession,               /* session ID                         */
        ULONG ulReserved);              /* reserved (must be 0)               */


/***   DosSmRegisterDD - Register device driver
 *
 *     Allows a device driver to receive session switch notification.
 *
 */

USHORT APIENTRY DosSmRegisterDD(
        PREGISTERDATA pregdata);        /* register data structure            */


/***   DosQAppType - Return the application type of an executable file */

USHORT APIENTRY DosQAppType(
        PSZ pszPrgName,                 /* file name of executable file       */
        PUSHORT pusType);               /* application type                   */


#define Q_MAX_PATH_LENGTH       (0)     /* index for query max path length */


#endif /* INCL_DOSSESMGR */


/*** Device support */

#ifdef INCL_DOSDEVICES


/***   DosDevConfig - Get device configuration
 *
 *     Gets information about attached devices.
 *
 */

USHORT APIENTRY DosDevConfig(
        PVOID pDevInfo,                 /* returned information               */
        USHORT usItem,                  /* what device information is needed  */
        USHORT usReserved);             /* reserved, should be set to 0       */


/***   DosDevIOCtl - I/O control for devices
 *
 *     Performs control functions on a device specified by an opened device
 *     handle.
 *
 */

USHORT APIENTRY DosDevIOCtl(
        PVOID pData,                    /* data area                          */
        PVOID pParms,                   /* command specific argument list     */
        USHORT usFun,                   /* device specific function code      */
        USHORT usCategory,              /* device category                    */
        HFILE hDev);                    /* device handle                      */

/***    DosDevIOCtl2 - Perform Control Functions Directly On Device, with lengths
 *
 *      Control functions on the device specified by the opened
 *      handle
 */

USHORT APIENTRY  DosDevIOCtl2 (
        PVOID pData,                    /* Data area                      */
        USHORT cbData,                  /* Length of data area            */
        PVOID pParm,                    /* Command-specific argument list */
        USHORT cbParm,                  /* Length of argument list        */
        USHORT usFun,                   /* Device-specific function code  */
        USHORT usCategory,              /* Device category                */
        HFILE hDev);                    /* Device handle returned by Open */

/***   DosCLIAccess - Request CLI/STI privilege
 *
 *     Requests I/O privilege for disabling and enabling interrupts. Access to
 *     ports must be granted via DosPortAccess.
 *
 */

USHORT APIENTRY DosCLIAccess(
        VOID);



/***   DosPortAccess - Request port access
 *
 *     Requests or releases access to ports for I/O privilege.
 *
 */

USHORT APIENTRY DosPortAccess(
        USHORT usReserved,              /* reserved (must be set to 0)        */
        USHORT fRelease,                /* 0=request access, 1=release access */
        USHORT usFirstPort,             /* first port number                  */
        USHORT usLastPort);             /* last port number                   */


/***   DosPhysicalDisk - Partitionable disk support
 *
 *     Obtains information on partitionable disks.
 *
 */

USHORT APIENTRY DosPhysicalDisk(
        USHORT usFun,                 /* type of information to obtain        */
        PBYTE pOut,                   /* pointer to return buffer             */
        USHORT cbOut,                 /* return buffer length                 */
        PBYTE pParm,                  /* pointer to user-supplied information */
        USHORT cbParm);               /* length of user-supplied information  */


/***   DosR2StackRealloc - Reallocate ring 2 stack
 *
 *     Changes the size of a thread's ring 2 stack
 *
 */

USHORT APIENTRY DosR2StackRealloc(
        USHORT cbStack);                /* ring 2 stack's new size in bytes */


/***   DosCallback Ring 2 call to ring 3 routine
 *
 *     Provided so a Ring 2 IOPL segment can call a Ring 3 allocation segment.
 *
 */

VOID   APIENTRY DosCallback(
        PFN pfn);                       /* Address of the ring 3 routine */
                                        /* to be called                  */

#endif /* INCL_DOSDEVICES */

#ifdef INCL_DOSNMPIPES

typedef SHANDLE HPIPE;
typedef HPIPE FAR *PHPIPE;

typedef struct _AVAILDATA   {       /* PeekNMPipe Bytes Available record  */
        USHORT  cbpipe;             /* bytes left in the pipe             */
        USHORT  cbmessage;          /* bytes left in current message      */
} AVAILDATA;
typedef AVAILDATA FAR *PAVAILDATA;

/*** DosCallNmPipe - Procedure call transaction
 *
 *   Performs a procedure call transaction using a message pipe.
 *
 */

USHORT APIENTRY DosCallNmPipe(
        PSZ pszName,            /* Name of the pipe to be opened              */
        PBYTE pInBuf,           /* Address of the buffer to write to the pipe */
        USHORT cbInBuf,         /* Number of bytes to be written              */
        PBYTE pbOutBuf,         /* Address of the buffer for returned data    */
        USHORT cbOutBuf,        /* Maximum size (in bytes) of returned data   */
        PUSHORT pcbRead,        /* Number of bytes actually read (returned)   */
        ULONG ulTimeOut);       /* Maximum wait time                          */

/*** DosConnectNmPipe - Connect named pipe
 *
 *   Enables a new client to obtain handle-based access to a named pipe
 *   through DosOpen.
 *
 */

USHORT APIENTRY DosConnectNmPipe(
        HPIPE hp);                      /* Pipe Handle                        */

/*** DosDisConnectNmPipe - Disconnect named pipe
 *
 *   Forces a named pipe to close.
 *
 */

USHORT APIENTRY DosDisConnectNmPipe(
        HPIPE hp);                      /* Pipe Handle                        */

/*** DosMakeNmPipe - Create a named pipe
 *
 *   Creates the specified named pipe and returns its handle.
 *
 */

USHORT APIENTRY DosMakeNmPipe(
        PSZ pszName,                    /* Pipe Name                          */
        PHPIPE php,                     /* Returned pipe handle               */
        USHORT fsOpenMode,              /* DOS open mode of pipe              */
        USHORT fsPipeMode,              /* Pipe open mode                     */
        USHORT cbOutBuf,                /* Advisory outgoing buffer size      */
        USHORT cbInBuf,                 /* Advisory incoming buffer size      */
        ULONG ulTimeOut);               /* Timeout for DosWaitNmPipe          */

/*** DosPeekNmPipe - Peek named pipe
 *
 *   Reads pipe without removing the read data from the pipe
 *
 */

USHORT APIENTRY DosPeekNmPipe(
        HPIPE hp,                       /* Pipe handle                        */
        PBYTE pBuf,                     /* Address of user buffer             */
        USHORT cbBuf,                   /* Buffer length                      */
        PUSHORT pcbRead,                /* Bytes read                         */
        PAVAILDATA pAvail,              /* Bytes available                    */
        PUSHORT pfsState);              /* Pipe state                         */

/*** DosQNmPHandState - Query named pipe state
 *
 *   Returns information for a named pipe's specific handle state.
 *
 */

USHORT APIENTRY DosQNmPHandState(
        HPIPE hp,                       /* Pipe handle                        */
        PUSHORT pfsState);              /* Pipe handle state                  */

/*** DosQNmPipeInfo - Query named pipe info
 *
 *   Returns information for a named pipe
 *
 */

USHORT APIENTRY DosQNmPipeInfo(
        HPIPE hp,                       /* Pipe handle                        */
        USHORT usInfoLevel,             /* Pipe data required                 */
        PBYTE pBuf,                     /* Pipe data buffer                   */
        USHORT cb);                     /* Pipe data buffer size              */

/*** DosQNmPipeSemState - Query named pipe operations
 *
 *   Returns information about named pipes attached to a specific system
 *   semaphore
 *
 */

USHORT APIENTRY DosQNmPipeSemState(
        HSEM hsem,                      /* Semaphore handle                   */
        PBYTE pBuf,                     /* Address of returned info           */
        USHORT cb);                     /* Length of InfoBuff                 */



/*** DosSetNmPHandState - Set named pipe handle state
 *
 *   Returns information about named pipes specific handle state.
 *
 */

USHORT APIENTRY DosSetNmPHandState(
        HPIPE hp,                       /* Pipe handle                        */
        USHORT fsState);                /* Pipe handle state                  */

USHORT APIENTRY  DosSetNmPipeSem (
        HPIPE hp,                       /* File handle      */
        HSEM hsem,                      /* Semaphore handle */
        USHORT usKeyVal);               /* Key              */

/*** DosTransactNmPipe - Perform transaction
 *
 *   Performs a transaction, write followed by a read, on a message pipe.
 *
 */

USHORT APIENTRY DosTransactNmPipe(
        HPIPE hp,                       /* Pipe handle                        */
        PBYTE pOutBuf,                  /* Write buffer address               */
        USHORT cbOut,                   /* Write buffer length                */
        PBYTE pInBuf,                   /* Read buffer address                */
        USHORT cbIn,                    /* Read buffer length                 */
        PUSHORT pcbRead);               /* Bytes read (returned)              */

/*** DosWaitNmPipe - Wait named pipe instance
 *
 *   Waits for the availability of a named pipe instance.
 *
 */

USHORT APIENTRY DosWaitNmPipe(
        PSZ pszName,                    /* Pipe name                          */
        ULONG ulTimeOut);               /* Maximum wait time                  */


/*** Data structures and equates used with named pipes ***/

struct   npi_data1 {               /* PipeInfo data block (returned, level 1) */
   USHORT npi_obuflen;          /* length of outgoing I/O buffer */
   USHORT npi_ibuflen;          /* length of incoming I/O buffer */
   UCHAR  npi_maxicnt;          /* maximum number of instances   */
   UCHAR  npi_curicnt;          /* current number of instances   */
   UCHAR  npi_namlen;           /* length of pipe name           */
   char  npi_name[1];                   /* start of name                 */
}; /* npi_data1 */

struct   npss  {                        /* QNmPipeSemState information record */
   UCHAR  npss_status;          /* type of record, 0=EOI, 1=read ok,  */
                                        /*   2 = write ok, 3 = pipe closed    */
   UCHAR  npss_flag;            /* additional info, 01=waiting thread */
   USHORT npss_key;             /* user's key value                   */
   USHORT npss_avail;           /* available data/space if status=1/2 */
}; /* npss */

/* values in npss_status */
#define  NPSS_EOI    0                  /* End Of Information    */
#define  NPSS_RDATA  1                  /* read data available   */
#define  NPSS_WSPACE 2                  /* write space available */
#define  NPSS_CLOSE  3                  /* pipe in CLOSING state */

/* values in npss_flag */
#define  NPSS_WAIT   0x01              /* waiting thread on other end of pipe */

/* defined bits in pipe mode */
#define  NP_NBLK     0x8000             /* non-blocking read/write */
#define  NP_SERVER   0x4000             /* set if server end       */
#define  NP_WMESG    0x0400             /* write messages          */
#define  NP_RMESG    0x0100             /* read as messages        */
#define  NP_ICOUNT   0x00FF             /* instance count field    */


/* Named pipes may be in one of several states depending on the actions
 * that have been taken on it by the server end and client end.  The
 * following state/action table summarizes the valid state transitions:
 *
 * Current state   Action                 Next state
 *
 *  <none>         server DosMakeNmPipe   DISCONNECTED
 *  DISCONNECTED   server connect         LISTENING
 *  LISTENING      client open            CONNECTED
 *  CONNECTED      server disconn         DISCONNECTED
 *  CONNECTED      client close           CLOSING
 *  CLOSING        server disconn         DISCONNECTED
 *  CONNECTED      server close           CLOSING
 *  <any other>    server close           <pipe deallocated>
 *
 * If a server disconnects his end of the pipe, the client end will enter a
 * special state in which any future operations (except close) on the file
 * descriptor associated with the pipe will return an error.
 */

/*
 * Values for named pipe state
 */

#define  NP_DISCONNECTED   1     /* after pipe creation or Disconnect */
#define  NP_LISTENING      2     /* after DosNmPipeConnect            */
#define  NP_CONNECTED      3     /* after Client open                 */
#define  NP_CLOSING        4     /* after Client or Server close      */

#endif /* INCL_DOSNMPIPES */
#ifdef INCL_DOSPFS

/*** DosPFSActivate - Activate font
 *
 *   Specifies the code page and font to make active for the specified printer
 *   and Process ID
 *
 */

USHORT APIENTRY DosPFSActivate(
        PVOID hspl,                     /* Temporary spool file handle        */
        PULONG pfnAct,                  /* Number of bytes written (returned) */
        PSZ pszPName,                   /* Printer name string                */
        USHORT usCodePage,              /* Code page to make active           */
        USHORT usFontId,                /* Font ID to make active             */
        USHORT usSFN,                   /* System file number                 */
        ULONG ulReserved);              /* Reserved, set to 0                 */

/*** DosPFSCloseUser - Close Font User Interface
 *
 *   Indicates to the Font Switcher that the specified process has closed its
 *   spool file. The font Switcher may then free any resources being used to
 *   track code page and font switching for a process.
 *
 */

USHORT APIENTRY DosPFSCloseUser(
        PSZ pszPName,                   /* Printer name string                */
        USHORT usSFN,                   /* System file number                 */
        ULONG ulReserved);              /* Reserved, set to 0                 */

/*** DosPFSInit - Initialize code page and fpnt
 *
 *   Allows the FontSwitcher ti initialize code page and font switching for a
 *   specified printer.
 *
 */

USHORT APIENTRY DosPFSInit(
        PUSHORT pusHdw,                 /* Hdw font definition list           */
        PSZ pszFontPath,                /* File pathname of the font          */
                                        /* file to use                        */
        PSZ pszPType,                   /* Printer type string                */
        PSZ pszPName,                   /* Printer name string                */
        USHORT usSpool,                 /* Number of spool instances          */
        ULONG ulReserved);              /* Reserved                           */

/*** DosPFSQueryAct - Query active font
 *
 *   Queries the active code page and font for the specified printer and
 *   Process ID.
 *
 */


USHORT APIENTRY DosPFSQueryAct(
        PSZ pszPname,                   /* Printer name string                */
        PUSHORT pusCodePage,            /* Code page return                   */
        PUSHORT pusFontId,              /* Font ID return                     */
        USHORT usSFN,                   /* System file number                 */
        ULONG ulReserved);              /* Reserved, set to 0                 */

/*** DosPFSVerifyFont - Verify font
 *
 *   Indicates whether the specified code page and font within that code page
 *   are available in the font file for the specified printer.
 *
 */

USHORT APIENTRY DosPFSVerifyFont(
        PSZ pszPName,                   /* Printer name string                */
        USHORT usCodePage,              /* Code page to validate              */
        USHORT usFontId,                /* Font ID to validate                */
        ULONG ulReserved);              /* Reserved, set to 0                 */

#endif /* INCL_DOSPFS */

/*** DosPFS API Support */

#ifdef INCL_DOSPFS

typedef USHORT  (PASCAL FAR *PFNACT)(PVOID, PCH, USHORT);



#endif /* INCL_DOSPFS */


/*** DosProfile API support */

#ifdef INCL_DOSPROFILE

/* DosProfile ordinal number */

#define PROF_ORDINAL     133

/* DosProfile usType */

#define PROF_SYSTEM      0
#define PROF_USER        1
#define PROF_USEDD       2
#define PROF_KERNEL      4
#define PROF_VERBOSE     8
#define PROF_ENABLE     16

/* DosProfile usFunc */

#define PROF_ALLOC       0
#define PROF_CLEAR       1
#define PROF_ON          2
#define PROF_OFF         3
#define PROF_DUMP        4
#define PROF_FREE        5

/* DosProfile tic count granularity (DWORD) */

#define PROF_SHIFT       2

/* DosProfile module name string length */

#define PROF_MOD_NAME_SIZE   10

/* DosProfile error code for end of data */

#define PROF_END_OF_DATA     13

#endif /* INCL_DOSPROFILE */
