/***************************************************************************\
*
* Module Name: BSESUB.H
*
* OS/2 Base Include File
*
* Copyright (c) 1987-1990  IBM Corporation
*
*****************************************************************************
*
* Subcomponents marked with "+" are partially included by default
*   #define:                To include:
*
*   INCL_KBD                KBD
*   INCL_VIO                VIO
*   INCL_MOU                MOU
*
\***************************************************************************/

#ifdef INCL_SUB

#define INCL_KBD
#define INCL_VIO
#define INCL_MOU

#endif /* INCL_SUB */

#ifdef INCL_KBD

typedef SHANDLE         HKBD;
typedef HKBD    far *   PHKBD;


/***   KbdRegister - register keyboard subsystem within a session */

USHORT APIENTRY KbdRegister(
        PSZ pszModName,    /* dynamic link module name                    */
        PSZ pszEntryPt,    /* entry point name                            */
        ULONG FunMask);    /* function mask of functions being registered */

#define KR_KBDCHARIN        0x00000001L
#define KR_KBDPEEK          0x00000002L
#define KR_KBDFLUSHBUFFER   0x00000004L
#define KR_KBDGETSTATUS     0x00000008L
#define KR_KBDSETSTATUS     0x00000010L
#define KR_KBDSTRINGIN      0x00000020L
#define KR_KBDOPEN          0x00000040L
#define KR_KBDCLOSE         0x00000080L
#define KR_KBDGETFOCUS      0x00000100L
#define KR_KBDFREEFOCUS     0x00000200L
#define KR_KBDGETCP         0x00000400L
#define KR_KBDSETCP         0x00000800L
#define KR_KBDXLATE         0x00001000L
#define KR_KBDSETCUSTXT     0x00002000L

#define IO_WAIT     0
#define IO_NOWAIT   1


/***   KbdDeRegister - Deregister keyboard subsytem
 *
 *     Deregisters a keyboard subsystem previously registered within a session.
 *     Only the process that issued the KbdRegister may issue KbdDeRegister.
 *
 */

USHORT APIENTRY KbdDeRegister ( void );

/* KBDKEYINFO structure, for KbdCharIn and KbdPeek                      */

typedef struct _KBDKEYINFO {
        UCHAR    chChar;    /* ASCII character code                     */
        UCHAR    chScan;    /* Scan Code                                */
        UCHAR    fbStatus;  /* State of the character                   */
        UCHAR    bNlsShift; /* Reserved (must equal 0)                  */
        USHORT   fsState;   /* state of the shift keys                  */
        ULONG    time;      /* time stamp of key stroke (ms since ipl)  */
        }KBDKEYINFO;
typedef KBDKEYINFO far *PKBDKEYINFO;


/***   KbdCharIn - Read character, Scan code                            */

USHORT APIENTRY KbdCharIn(
        PKBDKEYINFO pkbci,      /* structure indicated just above       */
        USHORT      fWait,      /* 0=wait for character, 1=no wait      */
        HKBD        hkbd);      /* keyboard handle                      */


/***   KbdPeek - Peek at character, scan code
 *
 *     Returns the character data record, if available, from the keyboard
 *     without removing it from the buffer.
 *
 */

USHORT APIENTRY KbdPeek(
        PKBDKEYINFO  pkbci,     /* structure indicated just above       */
        HKBD         hkbd );    /* keyboard handle                      */

/* structure for KbdStringIn() */

typedef struct _STRINGINBUF {
        USHORT cb;              /* input buffer length                  */
        USHORT cchIn;           /* received input length                */
        } STRINGINBUF;
typedef STRINGINBUF far *PSTRINGINBUF;


/***   KbdStringIn - Read character string
 *
 *     Reads a character string (character codes only) from the keyboard.
 *
 */

USHORT APIENTRY KbdStringIn(
        PCH           pch,      /* buffer for the character string      */
        PSTRINGINBUF  pchIn,    /* structure indicated just above       */
        USHORT        fsWait,   /* indicated if wait for character      */
        HKBD          hkbd  );  /* keyboard handle                      */


/***   KbdFlushBuffer - Flush key stroke buffer
 *
 *     clears the key stroke buffer
 *
 */

USHORT APIENTRY KbdFlushBuffer(
        HKBD hkbd);             /* keyboard handle                      */

/* KBDINFO structure, for KbdSet/GetStatus */
typedef struct _KBDINFO {
        USHORT cb;           /* length in bytes of this structure       */
        USHORT fsMask;       /* bit mask of functions to be altered     */
        USHORT chTurnAround; /* define TurnAround character             */
        USHORT fsInterim;    /* interim character flags                 */
        USHORT fsState;      /* shift states                            */
        }KBDINFO;
typedef KBDINFO far *PKBDINFO;


/***   KbdSetStatus - Set keyboard status
 *
 *     Sets the characteristics of the keyboard
 *
 */

USHORT APIENTRY KbdSetStatus(
        PKBDINFO    pkbdinfo,   /* data structure indicated above       */
        HKBD        hkbd );     /* keyboard handle                      */


/***   KbdGetStatus - Get keyboard status
 *
 *      Gets the current state of the keyboard.
 *
 */

USHORT APIENTRY KbdGetStatus(
        PKBDINFO    pkbdinfo,   /* data structure indicated above       */
        HKBD        hdbd  );    /* keyboard handle                      */


/***   KbdSetCp - Set the code page
 *
 *     Allows the process to set the code page used to translate key strokes
 *     received from the keyboard.
 *
 */

USHORT APIENTRY KbdSetCp(
        USHORT  usReserved,     /* reserved (set to 0)                  */
        USHORT  pidCP,          /* code page ID                         */
        HKBD    hdbd );         /* keyboard handle                      */


/***   KbdGetCp - Get loaded code page ID's
 *
 *     Allows a process to query the code page currently in use to translate
 *     scan codes to ASCII characters.
 *
 */

USHORT APIENTRY KbdGetCp(
        ULONG     ulReserved,   /* reserved (set to 0)                  */
        PUSHORT   pidCP,        /* code page ID                         */
        HKBD      hkbd);        /* keyboard handle                      */


/***   KbdOpen - Open a logical Keyboard
 *
 *     Creates a new logical keyboard.
 *
 */

USHORT APIENTRY KbdOpen(
        PHKBD phkbd);           /* keyboard handle                      */


/***   Kbdclose - Close a logical keyboard
 *
 *     Ends the existing logical keyboard identified by the keyboard handle.
 *
 */

USHORT APIENTRY KbdClose(
        HKBD hkbd);              /* keyboard handle                     */


/***   KbdGetFocus - Get keyboard focus
 *
 *     Binds the logical keyboard to the physical keyboard.
 *
 */

USHORT APIENTRY KbdGetFocus(
        USHORT  fWait,          /* indicate if wait                     */
        HKBD    hkbd);          /* keyboard handle                      */


/***   KbdFreeFocus - Free keyboard focus
 *
 *     Frees the logical to physical keyboard bond created by KbdGetFocus.
 *
 */

USHORT APIENTRY KbdFreeFocus(
        HKBD hkbd);             /* Keyboard handle                      */


/***   KbdSynch - Synchronize keyboard access
 *
 *     Synchronizes access for a keyboard subsystem to the keyboard device
 *     driver.
 *
 */

USHORT APIENTRY KbdSynch(
        USHORT fsWait);   /* indicate if wait for access to the device driver*/

/*** KbdSetFgnd - Set foreground keyboard priority
 *
 *   Raises the priority of the foreground keyboard's thread.
 *
 */

USHORT APIENTRY KbdSetFgnd( VOID );


/* structure for KbdGetHWID() */
typedef struct _KBDHWID {  /* kbhw */
   USHORT cb;                           /* length in byte of the structure */
   USHORT idKbd;                        /* attached keyboard's hardware id */
   USHORT usReserved1;                  /* reserved (set to 0)             */
   USHORT usReserved2;                  /* reserved (set to 0)             */
} KBDHWID;
typedef KBDHWID far *PKBDHWID;

/*** KbdGetHWID - Get Keyboard Hardware ID
 *
 *   Returns the attached keyboards hardware generated inentification value
 *
 */
USHORT APIENTRY KbdGetHWID (
        PKBDHWID pkbdhwid,              /* Keyboard ID structure (returned) */
        HKBD hkbd);                     /* keyboard handle                  */

/* structure for KbdXlate() */
typedef struct _KBDTRANS {
        UCHAR      chChar;    /* ASCII character code             */
        UCHAR      chScan;    /* scan code                        */
        UCHAR      fbStatus;  /* State of the character           */
        UCHAR      bNlsShift; /* shift status (reserved set to 0) */
        USHORT     fsState;   /* shift state                      */
        ULONG      time;
        USHORT     fsDD;
        USHORT     fsXlate;
        USHORT     fsShift;
        USHORT     sZero;
        } KBDTRANS;
typedef KBDTRANS far *PKBDTRANS;


/***   KbdXlate - Translate scan code
 *
 *     Translates scan code and shift states into ASCII code.
 *
 */

USHORT APIENTRY KbdXlate(
        PKBDTRANS  pkbdtrans,   /* Translation record (format as above) */
        HKBD       hkbd );      /* keyboard handle                      */


/***   KbdSetCustXt - Set custom code page
 *
 *     Installs on the specified handle the code page pointed to in this call.
 *     This code page will affect only this handle.
 *
 */

USHORT APIENTRY KbdSetCustXt(
        PUSHORT  usCodePage,    /* Translation table                    */
        HKBD     hkbd );        /* keyboard handle                      */

#endif /* INCL_KBD */

#ifdef INCL_VIO

typedef SHANDLE         HVIO;
typedef HVIO    far *   PHVIO;

/* first parameter registration constants */
#define VR_VIOGETCURPOS     0x00000001L
#define VR_VIOGETCURTYPE    0x00000002L
#define VR_VIOGETMODE       0x00000004L
#define VR_VIOGETBUF        0x00000008L
#define VR_VIOGETPHYSBUF    0x00000010L
#define VR_VIOSETCURPOS     0x00000020L
#define VR_VIOSETCURTYPE    0x00000040L
#define VR_VIOSETMODE       0x00000080L
#define VR_VIOSHOWBUF       0x00000100L
#define VR_VIOREADCHARSTR   0x00000200L
#define VR_VIOREADCELLSTR   0x00000400L
#define VR_VIOWRTNCHAR      0x00000800L
#define VR_VIOWRTNATTR      0x00001000L
#define VR_VIOWRTNCELL      0x00002000L
#define VR_VIOWRTTTY        0x00004000L
#define VR_VIOWRTCHARSTR    0x00008000L

#define VR_VIOWRTCHARSTRATT 0x00010000L
#define VR_VIOWRTCELLSTR    0x00020000L
#define VR_VIOSCROLLUP      0x00040000L
#define VR_VIOSCROLLDN      0x00080000L
#define VR_VIOSCROLLLF      0x00100000L
#define VR_VIOSCROLLRT      0x00200000L
#define VR_VIOSETANSI       0x00400000L
#define VR_VIOGETANSI       0x00800000L
#define VR_VIOPRTSC         0x01000000L
#define VR_VIOSCRLOCK       0x02000000L
#define VR_VIOSCRUNLOCK     0x04000000L
#define VR_VIOSAVREDRAWWAIT 0x08000000L
#define VR_VIOSAVREDRAWUNDO 0x10000000L
#define VR_VIOPOPUP         0x20000000L
#define VR_VIOENDPOPUP      0x40000000L
#define VR_VIOPRTSCTOGGLE   0x80000000L

/* second parameter registration constants */
#define VR_VIOMODEWAIT      0x00000001L
#define VR_VIOMODEUNDO      0x00000002L
#define VR_VIOGETFONT       0x00000004L
#define VR_VIOGETCONFIG     0x00000008L
#define VR_VIOSETCP         0x00000010L
#define VR_VIOGETCP         0x00000020L
#define VR_VIOSETFONT       0x00000040L
#define VR_VIOGETSTATE      0x00000080L
#define VR_VIOSETSTATE      0x00000100L


/***   VioRegister - Register video subsystem
 *
 *     Registers an alternate video subsystem within a session.
 *
 */

USHORT APIENTRY VioRegister(
        PSZ    pszModName,      /* dynamic link module name                 */
        PSZ    pszEntryName,    /* entry point name                         */
        ULONG  flFun1,          /* bit mask (each bit id's a video function */
        ULONG  flFun2);         /* bit mask (each bit id's a video function */

/***   VioDeRegister - DeRegister video subsystem
 *
 *     Deregisters a video subsystem previously registered within a session.
 *     VioDeRegister must be issued by the same process that issued the
 *     previous VioRegister. After VioDeRegister is issued, subsequent video
 *     calls are processed by the base video subsystem.
 *
 */

USHORT APIENTRY VioDeRegister ( void );


/***   VioGlobalReg - Register video subsystem for all fullscreen sessions
 *
 *     Registers an alternate video subsystem for all fullscreen sessions.
 *
 */

USHORT APIENTRY VioGlobalReg(
        PSZ    pszModName,      /* dynamic link module name                 */
        PSZ    pszEntryName,    /* entry point name                         */
        ULONG  flFun1,          /* bit mask (each bit id's a video function */
        ULONG  flFun2,          /* bit mask (each bit id's a video function */
        LONG   viorsvd);          /* reserved, must be 0                      */

/***   VioGetBuf - Get Logical video buffer address
 *
 *     VioGetBuf returns the address of the logical video buffer (LVB).
 *
 */

USHORT APIENTRY VioGetBuf(
        PULONG     pLVB,        /* pointer to logical video buffer      */
        PUSHORT    pcbLVB,      /* length of buffer                     */
        HVIO       hvio);       /* vio handle                           */


/***   VioGetCurPos - Get cursor position
 *
 *     Returns the cursor position.
 *
 */

USHORT APIENTRY VioGetCurPos(
        PUSHORT    pusRow,      /* Current row position of cursor       */
        PUSHORT    pusColumn,   /* current column position of cursor    */
        HVIO       hvio );      /* vio handle                           */


/***   VioSetCurPos - Set cursor position
 *
 *     Sets the cursor position.
 *
 */

USHORT APIENTRY VioSetCurPos(
        USHORT  usRow,          /* new cursor row position              */
        USHORT  usColumn,       /* new cursor column position           */
        HVIO    hvio);          /* video handle                         */

/* structure for VioSet/GetCurType() */
typedef struct _VIOCURSORINFO {
        USHORT   yStart; /* cursor start line                           */
        USHORT   cEnd;   /* cursor end line                             */
        USHORT   cx;     /* cursor width                                */
        USHORT   attr;   /* -1=hidden cursor, any other=normal cursor   */
        } VIOCURSORINFO;
typedef VIOCURSORINFO FAR *PVIOCURSORINFO;


/***   VioGetCurType - Get cursor type
 *
 *     Returns the cursor type.
 *
 */

USHORT APIENTRY VioGetCurType(
       PVIOCURSORINFO pvioCursorInfo, /* structure indicated above (returned) */
       HVIO           hvio );         /* Vio handle                           */


/***   VioSetCurType - Set the cursor type
 *
 *     Sets the cursor type
 *
 */

USHORT APIENTRY VioSetCurType(
        PVIOCURSORINFO pvioCursorInfo, /* structure indicated just above */
        HVIO           hvio );         /* video handle                   */

/* structure for VioSet/GetMode() */
typedef struct _VIOMODEINFO {
        USHORT cb;      /* length of the entire data structure          */
        UCHAR  fbType;  /* bit mask of mode being set                   */
        UCHAR  color;   /* number of colors (power of 2)                */
        USHORT col;     /* number of text columns                       */
        USHORT row;     /* number of text rows                          */
        USHORT hres;    /* horizontal resolution                        */
        USHORT vres;    /* vertical resolution                          */
        UCHAR  fmt_ID;  /* attribute format                             */
        UCHAR  attrib;  /* number of attributes                         */
        ULONG  buf_addr;
        ULONG  buf_length;
        ULONG  full_length;
        ULONG  partial_length;
        PCH    ext_data_addr;
        } VIOMODEINFO;
typedef VIOMODEINFO FAR *PVIOMODEINFO;

#define VGMT_OTHER          0x01
#define VGMT_GRAPHICS       0x02
#define VGMT_DISABLEBURST   0x04


/***   VioGetMode - Get display mode                                    */

USHORT APIENTRY VioGetMode(
        PVIOMODEINFO  pvioModeInfo,  /* structure defined above (returned)   */
        HVIO          hvio);         /* vio handle                           */


/***   VioSetMode - Set display mode                                    */

USHORT APIENTRY VioSetMode(
        PVIOMODEINFO  pvioModeInfo,  /* structure defined just above    */
        HVIO          hvio);         /* video handle                    */

/* structure for VioGetPhysBuf() */

typedef struct _VIOPHYSBUF {
        PBYTE    pBuf;          /* Buffer start address                 */
        ULONG    cb;            /* buffer length                        */
        SEL      asel[1];       /* selector list                        */
        } VIOPHYSBUF;
typedef VIOPHYSBUF far *PVIOPHYSBUF;


/***   VioGetPhysBuf - Get physical display buffer
 *
 *     Gets addressability to the physical display buffer.
 *
 */

USHORT APIENTRY VioGetPhysBuf(
        PVIOPHYSBUF pvioPhysBuf,  /* Data structure defined above       */
        USHORT      usReserved);  /* reserved (must be 0)               */


/***   VioReadCelStr - Read char/attr string
 *
 *     Reads a string of character-attribute pairs (or cells) from the screen
 *     starting at the specified location.
 *
 */

USHORT APIENTRY VioReadCellStr(
        PCH       pchCellStr,   /* Cell string buffer                   */
        PUSHORT   pcb,          /* length of cell string buffer         */
        USHORT    usRow,        /* starting row location                */
        USHORT    usColumn,     /* starting column location             */
        HVIO      hvio );       /* video handle                         */


/***   VioReadCharStr - Read character string
 *
 *     Reads a character string from the display starting at the specified
 *     location.
 *
 */

USHORT APIENTRY VioReadCharStr(
        PCH       pchCellStr,   /* character buffer                     */
        PUSHORT   pcb,          /* length of buffer                     */
        USHORT    usRow,        /* starting row location                */
        USHORT    usColumn,     /* starting column location             */
        HVIO      hvio );       /* video handle                         */


/***   VioWrtCellStr - Write char/attr string
 *
 *     Writes a string of character-attribute pairs (cells) to the display.
 *
 */

USHORT APIENTRY VioWrtCellStr(
        PCH      pchCellStr,    /* string to be written                 */
        USHORT   cb,            /* length of string                     */
        USHORT   usRow,         /* starting row position for output     */
        USHORT   usColumn,      /* starting column position for output  */
        HVIO     hvio );        /* video handle                         */


/***   VioWrtCharStr - Write character string to display                */

USHORT APIENTRY VioWrtCharStr(
        PCH      pchStr,        /* string to be written                 */
        USHORT   cb,            /* length of string                     */
        USHORT   usRow,         /* starting row position for output     */
        USHORT   usColumn,      /* starting column position for output  */
        HVIO     hvio );        /* video handle                         */


/***   VioScrollDn - Scroll screen down
 *
 *     Scrolls the entire display buffer (or area specified within the display
 *     buffer) down.
 *
 */

USHORT APIENTRY VioScrollDn(
        USHORT  usTopRow,   /* Top row of the area to scroll                  */
        USHORT  usLeftCol,  /* left column of the area to scroll              */
        USHORT  usBotRow,   /* bottom row of the area to scroll               */
        USHORT  usRightCol, /* right column of the area to scroll             */
        USHORT  cbLines,    /* number of lines to be inserted at top of screen*/
        PBYTE   pCell,      /* fill character on inserted lines               */
        HVIO    hvio );     /* video handle                                   */



/***   VioScrollUp - Scroll screen up                                   */

USHORT APIENTRY VioScrollUp(
        USHORT  usTopRow,       /* Top row of the area to scroll              */
        USHORT  usLeftCol,      /* left column of the area to scroll          */
        USHORT  usBotRow,       /* bottom row of the area to scroll           */
        USHORT  usRightCol,     /* right column of the area to scroll         */
        USHORT  cbLines, /* number of lines to be inserted at bottom of screen*/
        PBYTE   pCell,          /* fill character on inserted lines           */
        HVIO    hvio );         /* video handle                               */


/***   VioScrollLf - Scroll screen left                                       */

USHORT APIENTRY VioScrollLf(
        USHORT  usTopRow,       /* Top row of the area to scroll              */
        USHORT  usLeftCol,      /* left column of the area to scroll          */
        USHORT  usBotRow,       /* bottom row of the area to scroll           */
        USHORT  usRightCol,     /* right column of the area to scroll         */
        USHORT  cbCol,  /* number of columns to be inserted at right of screen*/
        PBYTE   pCell,          /* fill character on inserted lines           */
        HVIO    hvio );         /* video handle                               */


/***   VioScrollRt - Scroll screen right                                      */

USHORT APIENTRY VioScrollRt(
        USHORT  usTopRow,         /* Top row of the area to scroll            */
        USHORT  usLeftCol,        /* left column of the area to scroll        */
        USHORT  usBotRow,         /* bottom row of the area to scroll         */
        USHORT  usRightCol,       /* right column of the area to scroll       */
        USHORT  cbCol,  /* number of columns to be inserted at left of screen */
        PBYTE   pCell,            /* fill character on inserted lines         */
        HVIO    hvio );           /* video handle                             */


/***   VioWrtNAttr - Write n attributes
 *
 *     Writes an attribute to the display a specified number of times.
 *
 */

USHORT APIENTRY VioWrtNAttr(
        PBYTE     pAttr,        /* Attribute to be written              */
        USHORT    cb,           /* repeat count                         */
        USHORT    usRow,        /* starting row position for output     */
        USHORT    usColumn,     /* starting column postion for output   */
        HVIO      hvio );       /* video handle                         */


/***   VioWrtNCell - Write n char/attr
 *
 *     Writes a cell (or character-attribute pair) to the display a specified
 *     number of times.
 *
 */

USHORT APIENTRY VioWrtNCell(
        PBYTE   pCell,          /* cell to be written                   */
        USHORT  cb,             /* repeat count                         */
        USHORT  usRow,          /* starting row position for output     */
        USHORT  usColumn,       /* starting column postion for output   */
        HVIO    hvio );         /* video handle                         */


/***   VioWrtNChar - Write a character to the display a specified number of
 *                   times
 */

USHORT APIENTRY VioWrtNChar(
        PCH     pchChar,        /* character to be written              */
        USHORT  cb,             /* repeat count                         */
        USHORT  usRow,          /* starting row position for output     */
        USHORT  usColumn,       /* starting column postion for output   */
        HVIO    hvio );         /* video handle                         */


/***   VioWrtTTY - Write TTY string
 *
 *     Writes a character string to the display starting at the current cursor
 *     position. At the completion of the write, the cursor is positioned at the
 *     first position beyond the end of the string
 *
 */

USHORT APIENTRY VioWrtTTY(
        PCH     pch,            /* String to be written                 */
        USHORT  cb,             /* length of string                     */
        HVIO    hvio );         /* video handle                         */


/***   VioWrtCharStrAtt - Write character string with repeated attribute to the
 *                        display.
 */

USHORT APIENTRY VioWrtCharStrAtt(
        PCH       pch,          /* string to be written                 */
        USHORT    cb,           /* length of string                     */
        USHORT    usRow,        /* starting row position for output     */
        USHORT    usColumn,     /* starting column position for output  */
        PBYTE     pAttr,        /* attribute to be replicated           */
        HVIO      hvio  );      /* video handle                         */


/***   VioShowBuf - updates the physical display buffer with the logical video
 *                  buffer.
 */

USHORT APIENTRY VioShowBuf(
        USHORT  offLVB,   /* offset into the logical video buffer           */
        USHORT  cb,       /* length of the area to be updated to the screen */
        HVIO    hvio );   /* video handle                                   */


#define ANSI_ON     1
#define ANSI_OFF    0


/***   VioSetAnsi - Activates or deactivates ansi support               */

USHORT APIENTRY VioSetAnsi(
        USHORT   fAnsi,         /* 0=deactivate ansi, 1=activate ansi   */
        HVIO     hvio );        /* video handle                         */


/***   VioGetAnsi - Get the ansi On/Off status                          */

USHORT APIENTRY VioGetAnsi(
        PUSHORT  pfAnsi,        /* 0=ansi inactive, 1=ansi active       */
        HVIO     hvio );        /* vio handle                           */


/***   VioPrtSc - Copies the screen to the printer                      */

USHORT APIENTRY VioPrtSc(
        HVIO hvio);             /* vio handle                           */


/***   VioPrtScToggle - Toggle print screen
 *
 *     Called by the session manager when the operator presses Ctrl_PrtSc.
 *
 */

USHORT APIENTRY VioPrtScToggle(
        HVIO hvio);             /* vio handle                           */

#define VSRWI_SAVEANDREDRAW  0
#define VSRWI_REDRAW         1

#define VSRWN_SAVE           0
#define VSRWN_REDRAW         1

#define UNDOI_GETOWNER          0
#define UNDOI_RELEASEOWNER      1

#define UNDOK_ERRORCODE         0
#define UNDOK_TERMINATE         1


/***   VioSavRedrawWait - Screen save redraw wait
 *
 *     Notifies a graphics mode application when it must save or redraw its
 *     screen image. The return from this function call provides the
 *     notification. The thread that issues the call performs the save or redraw
 *     and then re-issues VioSavRedrawWait to wait until its screen image must
 *     be saved or redrawn again.
 *
 */

USHORT APIENTRY VioSavRedrawWait(
        USHORT   usRedrawInd,  /* 0=Save and redraw, 1=redraw only            */
        PUSHORT  pNotifyType,  /* 0=save screen image, 1=restore screen image */
        USHORT   usReserved);  /* video handle (must be zero )                */


/***   VioSavRedrawUndo - Screen save redraw undo
 *
 *     Allows one thread within a process to cancel a VioSavRedrawWait issued by
 *     another thread within the same process.
 *
 */

USHORT APIENTRY VioSavRedrawUndo(
        USHORT   usOwnerInd,    /* 0=reserve ownership, 1=give up ownership */
        USHORT   usKillInd,     /* 0=return error code, 1=terminate thread  */
        USHORT   usReserved );  /* video handle (must be zero)              */

#define VMWR_POPUP  0
#define VMWN_POPUP  0


/***   VioModeWait - Restore mode wait
 *
 *     Allows a graphics mode application to be notified when it must restore
 *     its video mode, state, and modified display adapter registers. The return
 *     from this function call provides the notification.
 *
 */

USHORT APIENTRY VioModeWait(
        USHORT   usReqType,     /* request type                         */
        PUSHORT  pNotifyType,   /* notify type (returned)               */
        USHORT   usReserved );  /* reserved (must be 0)                 */


/***   VioModeUndo - Restore mode undo
 *
 *     Allows one thread within a process to cancel a VioModeWait issued by
 *     another thread within the same process.
 *
 */

USHORT APIENTRY VioModeUndo(
        USHORT   usOwnerInd,    /* 0=reserve ownership, 1=give up ownership */
        USHORT   usKillInd,     /* 0=return error code, 1=terminate thread  */
        USHORT   usReserved );  /* video handle                             */

#define LOCKIO_NOWAIT   0
#define LOCKIO_WAIT     1

#define LOCK_SUCCESS    0
#define LOCK_FAIL       1


/***   VioScrLock - Lock screen - requests ownership of (locks) the physical
 *                  display buffer
 */

USHORT APIENTRY VioScrLock(
        USHORT   fWait,         /* 0=return if screen unavailable, 1=wait */
        PUCHAR   pfNotLocked,   /* lock status (returned)                 */
        HVIO     hvio   );      /* video handle                           */


/***   VioScrUnLock - Unlock screen - releases ownership (unlocks) of the
 *                    physical display buffer.
 */

USHORT APIENTRY VioScrUnLock(
        HVIO     hvio );        /* video handle                         */

#define VP_NOWAIT       0x0000
#define VP_WAIT         0x0001
#define VP_OPAQUE       0x0000
#define VP_TRANSPARENT  0x0002

/*** VioPopUp - Allocate a pop-up display screen
 *
 * This call is issued by an application process when it requires a temporary
 * screen to display a momentary message to the user.
 *
 */

USHORT APIENTRY VioPopUp (
        PUSHORT  pfWait,        /* Option flags                         */
        HVIO     hvio );        /* Vio handle                           */


/***   VioEndPopUp - Deallocate pop-up display screen
 *
 *     Issued by the application when it no longer requires the temporary screen
 *     obtained through a previous VioPopUp call.
 *
 */

 USHORT APIENTRY VioEndPopUp(
        HVIO hvio );            /* vio device handle                    */

/* structure for VioGetConfig() */

typedef struct _VIOCONFIGINFO {
        USHORT  cb     ;  /* length of this data structure              */
        USHORT  adapter;  /* display adapter type                       */
        USHORT  display;  /* display/monitor type                       */
        ULONG   cbMemory; /* amount of memory on the adapter in bytes   */
        USHORT  Configuration;
        USHORT  VDHVersion;
        USHORT  Flags;
        ULONG   HWBufferSize;
        ULONG   FullSaveSize;
        ULONG   PartSaveSize;
        USHORT  EMAdaptersOFF;
        USHORT  EMDisplaysOFF;
        } VIOCONFIGINFO;
typedef VIOCONFIGINFO far *PVIOCONFIGINFO;


/***   VioGetConfig - get video display configuration                   */

USHORT APIENTRY VioGetConfig(
        USHORT         usConfigId,  /* Reserved (must be 0)             */
        PVIOCONFIGINFO pvioin,      /* structure defined above          */
        HVIO           hvio );      /* vio handle                       */

/* structure for VioGet/SetFont() */
typedef struct _VIOFONTINFO {   /* viofi */
        USHORT  cb;     /* length of this structure                       */
        USHORT  type;   /* request type                                   */
        USHORT  cxCell; /* pel columns in character cell                  */
        USHORT  cyCell; /* pel rows in character cell                     */
        PVOID   pbData; /* requested font table (returned)                */
        USHORT  cbData; /* length of caller supplied data area (in bytes) */
        } VIOFONTINFO;
typedef VIOFONTINFO far *PVIOFONTINFO;

#define VGFI_GETCURFONT     0
#define VGFI_GETROMFONT     1


/***   VioGetFont - Returns either the font table of the size specified, or the
 *                  font currently in use.
 */

USHORT APIENTRY VioGetFont(
        PVIOFONTINFO  pviofi,   /* data structure defined above         */
        HVIO          hvio );   /* vio handle                           */


/***   VioSetFont - Set font
 *
 *     Downloads a display font. The font being set must be compatible with the
 *     current mode.
 *
 */

USHORT APIENTRY VioSetFont(
        PVIOFONTINFO  pviofi,   /* data structure defined just above    */
        HVIO          hvio  );  /* video handle                         */


/***   VioGetCp - Get code page
 *
 *     Allows a process to query the code page currently used to display text
 *     data.
 *
 */

USHORT APIENTRY VioGetCp(
        USHORT   usReserved,    /* reserved (zero's)                    */
        PUSHORT  pIdCodePage,   /* code page ID                         */
        HVIO     hvio  );       /* video handle                         */


/***   VioSetCp - Set code page
 *
 *     Allows a process to set the code page used to display text data on the
 *     screen.
 *
 */

USHORT APIENTRY VioSetCp(
        USHORT   usReserved,    /* reserved (zero's)                    */
        USHORT   idCodePage,    /* code page id                         */
        HVIO     hvio );        /* video handle                         */

typedef struct _VIOPALSTATE {
        USHORT  cb;             /* length of this structure in bytes    */
        USHORT  type;           /* request type=0 get palette registers */
        USHORT  iFirst;         /* first palette register to return     */
        USHORT  acolor[1];      /* color value pallete register         */
        }VIOPALSTATE;
typedef VIOPALSTATE far *PVIOPALSTATE;

typedef struct _VIOOVERSCAN {
        USHORT  cb;     /* length of this structure                     */
        USHORT  type;   /* request type=1 get overscan (border) color   */
        USHORT  color;  /* color value                                  */
        }VIOOVERSCAN;
typedef VIOOVERSCAN far *PVIOOVERSCAN;

typedef struct _VIOINTENSITY {
        USHORT  cb;     /* length of this structure                     */
        USHORT  type;   /* request type=2 get blink/background intensity
                                                switch                  */
        USHORT  fs;     /* value of blink/background switch             */
        }VIOINTENSITY;
typedef VIOINTENSITY far *PVIOINTENSITY;


typedef struct _VIOCOLORREG {  /* viocreg */
        USHORT  cb;
        USHORT  type;
        USHORT  firstcolorreg;
        USHORT  numcolorregs;
        PCH     colorregaddr;
        }VIOCOLORREG;
typedef VIOCOLORREG far *PVIOCOLORREG;

typedef struct _VIOSETULINELOC {  /* viouline */
        USHORT  cb;
        USHORT  type;
        USHORT  scanline;
        }VIOSETULINELOC;
typedef VIOSETULINELOC far *PVIOSETULINELOC;

typedef struct _VIOSETTARGET {  /* viosett */
        USHORT  cb;
        USHORT  type;
        USHORT  defaultalgorithm;
        }VIOSETTARGET;
typedef VIOSETTARGET far *PVIOSETTARGET;


/***   VioGetState - Get video state
 *
 *     Returns the current settings of the palette registers, overscan (border)
 *     color or blink/background intensity switch.
 *
 */


USHORT APIENTRY VioGetState(
        PVOID    pState,        /* one of the 3 structures defined above */
        HVIO     hvio );        /* vio handle                            */


/***   VioSetState - Set video state
 *
 *     Performs one of the following functions, sets paletted registers, sets
 *     the overscan (border) color or set the blink/background intensity switch.
 *
 */


USHORT APIENTRY VioSetState(
        PVOID    pState,        /* one of the 3 structures defined above*/
        HVIO     hvio );        /* video handle                         */

#endif /* INCL_VIO */

#ifdef INCL_MOU

typedef SHANDLE         HMOU;
typedef HMOU    far *   PHMOU;


#define MR_MOUGETNUMBUTTONS 0x00000001L
#define MR_MOUGETNUMMICKEYS 0x00000002L
#define MR_MOUGETDEVSTATUS  0x00000004L
#define MR_MOUGETNUMQUEEL   0x00000008L
#define MR_MOUREADEVENTQUE  0x00000010L
#define MR_MOUGETSCALEFACT  0x00000020L
#define MR_MOUGETEVENTMASK  0x00000040L
#define MR_MOUSETSCALEFACT  0x00000080L
#define MR_MOUSETEVENTMASK  0x00000100L
#define MR_MOUOPEN          0x00000800L
#define MR_MOUCLOSE         0x00001000L
#define MR_MOUGETPTRSHAPE   0x00002000L
#define MR_MOUSETPTRSHAPE   0x00004000L
#define MR_MOUDRAWPTR       0x00008000L
#define MR_MOUREMOVEPTR     0x00010000L
#define MR_MOUGETPTRPOS     0x00020000L
#define MR_MOUSETPTRPOS     0x00040000L
#define MR_MOUINITREAL      0x00080000L
#define MR_MOUSETDEVSTATUS  0x00100000L

/***   MouRegister - Register a mouse subsystem within a session.       */

USHORT APIENTRY MouRegister(
        PSZ   pszModName,          /* Dynamic link module name             */
        PSZ   pszEntryName,        /* dynamic link entry point             */
        ULONG flFuns ); /* bit mask (each bit represents a mouse function) */

/***   MouDeRegister - Deregister a mouse subsystem                     */

USHORT APIENTRY MouDeRegister ( void );


/***   MouFlushQue - flush the mouse event queue for this session
 *
 *     Directs the mouse driver to flush (empty) the mouse event queue for the
 *     session
 *
 */

USHORT APIENTRY MouFlushQue (
        HMOU hmou );            /* Mouse device handle */


#define MHK_BUTTON1         0x0001
#define MHK_BUTTON2         0x0002
#define MHK_BUTTON3         0x0004

/* structure for MouGet/SetPtrPos() */
typedef struct _PTRLOC {
        USHORT row;     /* pointer row coordinate screen position       */
        USHORT col;     /* pointer column coordinate screen position    */
        } PTRLOC;
typedef PTRLOC far *PPTRLOC;


/***   MouGetPtrPos - Query mouse pointer position
 *
 *     Queries the mouse driver to determine the current row and column
 *     coordinate position of the mouse pointer shape.
 *
 */

USHORT APIENTRY MouGetPtrPos(
        PPTRLOC  pmouLoc,       /* pointer to structure indicated above */
        HMOU     hmou );        /* mouse device handle                  */


/***   MouSetPtrPos - Set mouse pointer position
 *
 *     Directs the mouse driver to set a new current row and column coordinate
 *     position for the mouse pointer shape.
 *
 */

USHORT APIENTRY MouSetPtrPos(
        PPTRLOC  pmouLoc,       /* pointer to structure indicated above */
        HMOU     hmou );        /* mouse device handle                  */

/* structure for MouGet/SetPtrShape() */
typedef struct _PTRSHAPE {
        USHORT cb;              /* total length necessary to build image      */
        USHORT col;             /* # of columns in mouse shape                */
        USHORT row;             /* number of rows in mouse shape              */
        USHORT colHot;          /* column coordinate of pointer image hotspot */
        USHORT rowHot;          /* row coordinate of pointer image hotspot    */
        } PTRSHAPE;
typedef PTRSHAPE far *PPTRSHAPE;


/***   MouSetPtrShape - Set mouse pointer shape
 *
 *     Allows a process to set the pointer shape and size to be used as the
 *     mouse device driver pointer image for all applications in a session.
 *
 */

USHORT APIENTRY MouSetPtrShape(
        PBYTE     pBuf,         /* bit image of the pointer shape       */
        PPTRSHAPE pmoupsInfo,   /* pointer to structure defined above   */
        HMOU      hmou );       /* mouse device handle                  */


/***   MouGetPtrShape - Get pointer shape
 *
 *     Allows a process to get (copy) the pointer shape for the session.
 *
 */

USHORT APIENTRY MouGetPtrShape(
        PBYTE     pBuf,         /* pointer bit image (returned)         */
        PPTRSHAPE pmoupsInfo,   /* pointer to structure defined above   */
        HMOU      hmou );       /* mouse device handle                  */


/***   MouGetDevStatus - Get mouse device status
 *
 *     Returns status flags for the mouse device driver currently installed.
 *
 */

USHORT APIENTRY MouGetDevStatus(
        PUSHORT  pfsDevStatus,  /* current status flags                 */
        HMOU     hmou );        /* mouse device handle                  */


/***   MouGetNumButtons - Get number of mouse buttons
 *
 *     Returns the number of buttons supported on the mouse driver currently
 *     installed.
 *
 */

USHORT APIENTRY MouGetNumButtons(
        PUSHORT  pcButtons,     /* number of mouse buttons              */
        HMOU     hmou );        /* mouse device handle                  */


/***   MouGetNumMickeys - Get number of mouse mickeys
 *
 *     Returns the number of mickeys per centimeter for the mouse driver
 *     currently installed.
 *
 */

USHORT APIENTRY MouGetNumMickeys(
        PUSHORT  pcMickeys,     /* number of mickeys per centimeter     */
        HMOU     hmou );        /* mouse device handle                  */

/* structure for MouReadEventQue() */
typedef struct _MOUEVENTINFO {
        USHORT fs;      /* State of mouse at the time the event was reported */
        ULONG  time;    /* time since boot in milliseconds                   */
        USHORT row;     /* absolute/relative row position                    */
        USHORT col;     /* absolute/relative column position                 */
        }MOUEVENTINFO;
typedef MOUEVENTINFO far *PMOUEVENTINFO;


/***   MouReadEventQue - read mouse event queue
 *
 *     Reads an event from the mouse device FIFO event queue, and places it in
 *     a structure provided by the application.
 *
 */

USHORT APIENTRY MouReadEventQue(
        PMOUEVENTINFO pmouevEvent,  /* pointer to structure defined above   */
        PUSHORT       pfWait,       /* 0=no wait for data, 1= wait for data */
        HMOU          hmou );       /* mouse device handle                  */

/* structure for MouGetNumQueEl() */
typedef struct _MOUQUEINFO {
        USHORT cEvents;    /* current number of event queue elements    */
        USHORT cmaxEvents; /* MaxNumQueElements value                   */
        } MOUQUEINFO;
typedef MOUQUEINFO far *PMOUQUEINFO;


/***   MouGetNumQueEl - Get Event queue status
 *
 *     Returns the current status for the mouse device driver event queue.
 *
 */

USHORT APIENTRY MouGetNumQueEl(
        PMOUQUEINFO  qmouqi,    /* pointer to structure defined above   */
        HMOU         hmou );    /* mouse device handle                  */


/***   MouGetEventMask - Get the current value of the mouse event queue mask*/

USHORT APIENTRY MouGetEventMask(
        PUSHORT  pfsEvents,     /* current mouse event mask (returned)  */
        HMOU     hmou );        /* mouse device handle                  */


/***   MouSetEventMask - Assign a new event mask to the current mouse device
 *                       driver.
 */

USHORT APIENTRY MouSetEventMask(
        PUSHORT  pfsEvents,     /* mouse event mask                     */
        HMOU     hmou );        /* mouse device handle                  */

/* structure for MouGet/SetScaleFact() */
typedef struct _SCALEFACT {
        USHORT rowScale; /* row scaling factor                          */
        USHORT colScale; /* column coordinate scaling factor            */
        } SCALEFACT;
typedef SCALEFACT far *PSCALEFACT;


/***   MouGetScaleFact - Get mouse scaling factors.                     */

USHORT APIENTRY MouGetScaleFact(
        PSCALEFACT  pmouscFactors, /* pointer to structure indicated above */
        HMOU        hmou );        /* mouse device handle                  */


/***   MouSetScaleFact - Set mouse scaling factor.                      */

USHORT APIENTRY MouSetScaleFact(
        PSCALEFACT  pmouscFactors, /* pointer to structure indicated above */
        HMOU        hmou );        /* mouse device handle                  */


/***   MouOpen - Open the mouse device for the current session.         */

USHORT APIENTRY MouOpen(
        PSZ      pszDvrname,   /* pointer to name of mouse draw device driver */
        PHMOU    phmou );      /* mouse device handle                         */


/***   MouClose - Close the mouse device for the current session.*/

USHORT APIENTRY MouClose(
        HMOU hmou );            /* mouse device handle                  */


/* structure for MouRemovePtr() */
typedef struct _NOPTRRECT {
        USHORT row;             /* upper left row coodinates            */
        USHORT col;             /* upper left column coodinates         */
        USHORT cRow;            /* Lower right row coordinates          */
        USHORT cCol;            /* Lower right column coordinates       */
        } NOPTRRECT;
typedef NOPTRRECT far *PNOPTRRECT;


/***   MouRemovePtr - Remove mouse pointer
 *
 *     Allows a process to notify the mouse device driver that the area defined
 *     by the passed parameters is for the exclusive use of the application.
 *     This area is defined as the 'collision' area and is not available to the
 *     mouse device driver when drawing pointer images.
 *
 */

USHORT APIENTRY MouRemovePtr(
        PNOPTRRECT pmourtRect,  /* Address of pointer data block        */
        HMOU       hmou );      /* mouse device handle                  */


/***   MouDrawPtr - Mouse draw pointer
 *
 *     Allows a process to notify the mouse device driver that an area
 *     previously restricted to the pointer image is now available to the mouse
 *     device driver.
 *
 */

USHORT APIENTRY MouDrawPtr(
        HMOU hmou );            /* mouse device handle                  */

#define MOU_NODRAW      0x0001
#define MOU_DRAW        0x0000
#define MOU_MICKEYS     0x0002
#define MOU_PELS        0x0000


/***   MouSetDevStatus - Set mouse device status
 *
 *     Sets the mouse device driver status flags for the mouse device driver
 *     currently installed. The status flags are a 2 byte set of bit flags.
 *
 */

USHORT APIENTRY MouSetDevStatus(
        PUSHORT  pfsDevStatus,  /* mouse device status flags            */
        HMOU     hmou );        /* mouse device handle                  */


/***   MouInitReal - Initialize the DOS mode mouse device driver        */

USHORT APIENTRY MouInitReal(
        PSZ );                  /* pointer to name of mouse draw driver */

/*** MouSynch - Get synchronous access
 *
 *   Provides synchronous access for a mouse subsystem to the mouse device
 *   driver.
 *
 */

USHORT APIENTRY MouSynch(
        USHORT pszDvrName );    /* Indicate wait/no wait              */

#endif /* INCL_MOU */
