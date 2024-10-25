/***    subcalls.h
 *
 *      (C) Copyright IBM Corporation 1987-1990.  All rights reserved.
 *
 */
struct CursorData {
        unsigned cur_start;             /* Cursor start line */
        unsigned cur_end;               /* Cursor end line */
        unsigned cur_width;             /* Cursor width */
        unsigned cur_attribute;         /* Cursor attribute */
        };
struct KbdStatus {
        unsigned length;                /* length in words of data structure */
        unsigned bit_mask;              /* bit mask */
        unsigned turn_around_char;      /* turnaround character */
        unsigned interim_char_flags;    /* interim character flags */
        unsigned shift_state;           /* shift state */
        };
struct KbdTRANS {
        unsigned char char_code;        /* ASCII character code */
        unsigned char scan_code;        /* scan code */
        unsigned char status;           /* indicates state of char */
        unsigned char nls_shift;        /* reserved */
        unsigned shift_state;           /* state of the shift keys */
        unsigned long time;             /* timestamp of keystroke */
        unsigned kbdDDflags;            /* flags for monitor packet */
        unsigned xlt_flags;             /* Xlate flags */
        unsigned xlt_shift_state;       /* Xlate shift state */
        unsigned xlt_rsrv_0;            /* reserved = 0 */
        };
struct KeyData {
        unsigned char char_code;        /* ASCII character code */
        unsigned char scan_code;        /* scan code */
        unsigned char status;           /* indicates state of the character */
        unsigned char nls_shift;        /* reserved */
        unsigned shift_state;           /* state of the shift keys */
        unsigned long time;             /* time stamp of the keystroke */
        };
struct ModeData {
        unsigned length;                /* Length of structure */
        unsigned char type;             /* Text or graphics */
        unsigned char color;            /* Color or monochrome */
        unsigned col;                   /* Column resolution */
        unsigned row;                   /* Row resolution */
        unsigned hres;                  /* horizontal resolution */
        unsigned vres;                  /* vertical resolution */
        unsigned char fmt_ID;           /* Format ID */
        unsigned char attrib;           /* Attribute count */
        unsigned long buf_addr;         /* 32-bit Buffer Physical Address */
        unsigned long buf_length;       /* Buffer Length */
        unsigned long full_length;      /* Full Buffer Length */
        unsigned long partial_length;   /* Partial Buffer Length */
        char far *ext_data_addr;        /* Address of Extended Data Area */
        };
struct PVBData {
        unsigned pvb_size;              /* size of the structure */
        unsigned long pvb_ptr;          /* returns pointer to the pvb buffer */
        unsigned pvb_length;            /* length of PVB */
        unsigned pvb_rows;              /* buffer dimension (rows) */
        unsigned pvb_cols;              /* buffer dimension (cols) */
        unsigned char pvb_type;         /* color or mono */
        };
struct PhysBufData {
        unsigned long buf_start;        /* Physical address of buffer */
        unsigned long buf_length;       /* Size of buffer (in bytes) */
        unsigned      selectors[2];     /* 1 or more selectors (assume 2) */
        };
struct ConfigData {
        unsigned length;                /* Length of the structure in bytes */
        unsigned adapter_type;          /* specifies the video adapter type */
        unsigned display_type;          /* specifies the video display type */
        unsigned long memory_size;      /* number of bytes in display memory */
        unsigned Configuration;         /* Configuration number */
        unsigned VDHVersion;            /* VDH version number */
        unsigned Flags;                 /* Flags */
        unsigned long HWBufferSize;     /* Environment Buffer size */
        unsigned long FullSaveSize;     /* Full save size */
        unsigned long PartSaveSize;     /* Partial save size */
        unsigned EMAdaptersOFF;         /* Offset to emulated adapters */
        unsigned EMDisplaysOFF;         /* Offset to emulated displays */
        };
struct VIOFONT {
        unsigned length;                /* Length of the struct (14) */
        unsigned req_type;              /* 0=current font, 1=ROM font */
        unsigned pel_cols;              /* character cell width */
        unsigned pel_rows;              /* character cell height */
        unsigned long font_data;        /* far ptr to font data area */
        unsigned font_len;              /* num. bytes of font data */
        };
struct VIOSTATE {
        unsigned length;                /* structure length (max 38) */
        unsigned req_type;              /* 0 = set palette regs   */
                                        /* 1 = set overscan color */
        unsigned double_defined;        /* req_type = 0 :            */
                                        /*  first palette reg to set */
                                        /* req_type = 1 :            */
                                        /*  border (overscan) color  */
        unsigned palette0;              /* color value */
        unsigned palette1;              /* color value */
        unsigned palette2;              /* color value */
        unsigned palette3;              /* color value */
        unsigned palette4;              /* color value */
        unsigned palette5;              /* color value */
        unsigned palette6;              /* color value */
        unsigned palette7;              /* color value */
        unsigned palette8;              /* color value */
        unsigned palette9;              /* color value */
        unsigned palette10;             /* color value */
        unsigned palette11;             /* color value */
        unsigned palette12;             /* color value */
        unsigned palette13;             /* color value */
        unsigned palette14;             /* color value */
        unsigned palette15;             /* color value */
        };
struct EventInfo {
        unsigned Mask;
        unsigned long Time;
        unsigned Row;
        unsigned Col;
        };
struct NoPointer {
        unsigned Row;
        unsigned Col;
        unsigned Height;
        unsigned Width;
        };
struct PtrImage {
        unsigned TotLength;
        unsigned Col;
        unsigned Row;
        unsigned ColOffset;
        unsigned RowOffset;
        };
struct PtrLoc {
        unsigned RowPos;
        unsigned ColPos;
        };
struct QueInfo {
        unsigned Events;
        unsigned QSize;
        };
struct ScaleFact {
        unsigned RowScale;
        unsigned ColScale;
        };
struct KbdStringInLength {
        unsigned int  Length;
        unsigned int  LengthB;
        };
struct KbdHWID {
        unsigned length;
        unsigned kbd_id;
        unsigned reserved1;
        unsigned reserved2;
        };
extern unsigned far pascal KBDREGISTER (
        char far *,                     /* Module name      */
        char far *,                     /* Entry point name */
        unsigned long);                 /* Function mask    */
extern unsigned far pascal KBDDEREGISTER (
        void );                         /* No Parameters */
extern unsigned far pascal KBDCHARIN (
        struct KeyData far *,           /* Buffer for character code */
        unsigned,                       /* I/O wait - 0=wait for a */
                                        /* character, 1=no wait */
        unsigned );                     /* keyboard handle */
extern unsigned far pascal KBDFLUSHBUFFER (
        unsigned );                     /* keyboard handle */
extern unsigned far pascal KBDGETSTATUS (
        struct KbdStatus far *,         /* data structure */
        unsigned );                     /* Keyboard device handle */
extern unsigned far pascal KBDPEEK (
        struct KeyData far *,           /* buffer for data */
        unsigned );                     /* keyboard handle */
extern unsigned far pascal KBDSETFGND (
        void );                         /* No Parameters */
extern unsigned far pascal KBDSETSTATUS (
        struct KbdStatus far *,         /* data structure */
        unsigned );                     /* device handle */
extern unsigned far pascal KBDSTRINGIN (
        char far *,
        struct KbdStringInLength far *,
        unsigned,
        unsigned );
extern unsigned far pascal KBDOPEN (
        unsigned far * );               /* addr. of returned handle */
extern unsigned far pascal KBDCLOSE (
        unsigned );                     /* keyboard handle */
extern unsigned far pascal KBDGETFOCUS (
        unsigned,                       /* wait/nowait indicator */
        unsigned );                     /* keyboard handle */
extern unsigned far pascal KBDFREEFOCUS (
        unsigned );                     /* keyboard handle */
extern unsigned far pascal KBDGETCP (
        unsigned long,                  /* reserved */
        unsigned far *,                 /* addr. of returned ID */
        unsigned );                     /* keyboard handle */
extern unsigned far pascal KBDSETCP (
        unsigned,                       /* reserved */
        unsigned,                       /* translate table ID */
        unsigned );                     /* keyboard handle */
extern unsigned far pascal KBDXLATE (
        struct KbdTRANS far *,          /* translation record */
        unsigned );                     /* keyboard handle */
extern unsigned far pascal KBDSETCUSTXT (
        unsigned far *,                 /* translation table */
        unsigned );                     /* keyboard handle */
extern unsigned far pascal KBDSYNCH (
        unsigned );                     /* IOwait word 0 or 1              */
                                        /* 0 = requestor will wait for the */
                                        /* access to the router            */
                                        /* 1 = requestor will not wait for */
                                        /* access to the router            */
extern unsigned far pascal KBDGETHWID (
        struct KbdHWID far *,           /* Hardware record (returned) */
        unsigned );                     /* keyboard handle */
extern unsigned far pascal VIOREGISTER (
        char far *,                     /* Module name */
        char far *,                     /* Entry Point name */
        unsigned long,                  /* Function mask 1 */
        unsigned long );                /* Function mask 2 */
extern unsigned far pascal VIODEREGISTER (
        void );                         /* No Parameters */
extern unsigned far pascal VIOGLOBALREG (
        char far *,                     /* Module name */
        char far *,                     /* Entry Point name */
        unsigned long,                  /* Function mask 1 */
        unsigned long,                  /* Function mask 2 */
        long );                         /* Reserved (must be 0) */
extern unsigned far pascal VIOGETBUF (
        unsigned long far *,            /* Will point to logical video buffer */
        unsigned far *,                 /* Length of Buffer */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOGETCURPOS (
        unsigned far *,                 /* Current row position */
        unsigned far *,                 /* Current column position */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOGETCURTYPE (
        struct CursorData far *,        /* Cursor characteristics */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOGETMODE (
        struct ModeData far *,          /* Length of Buffer */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOGETPHYSBUF (
        struct PhysBufData far *,       /* VIO Physical Buffer Info */
        unsigned );                     /* Reserved (must be 0) */
extern unsigned far pascal VIOREADCELLSTR (
        char far *,                     /* Character Buffer */
        unsigned far *,                 /* Length of cell string buffer */
        unsigned,                       /* Starting location (row) */
        unsigned,                       /* Starting location (col) */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOREADCHARSTR (
        char far *,                     /* Character Buffer */
        unsigned far *,                 /* Length of cell string buffer */
        unsigned,                       /* Starting location (row) */
        unsigned,                       /* Starting location (col) */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOSCROLLDN (
        unsigned,                       /* Top row of section to scroll */
        unsigned,                       /* Left column of section to scroll */
        unsigned,                       /* Bottom row of section to scroll */
        unsigned,                       /* Right column of section to scroll */
        unsigned,                       /* Number of blank lines at bottom */
        char far *,                     /* pointer to blank Char,Attr */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOSCROLLUP (
        unsigned,                       /* Top row of section to scroll */
        unsigned,                       /* Left column of section to scroll */
        unsigned,                       /* Bottom row of section to scroll */
        unsigned,                       /* Right column of section to scroll */
        unsigned,                       /* Number of blank lines at bottom */
        char far *,                     /* pointer to blank Char,Attr */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOSCROLLLF (
        unsigned,                       /* Top row of section to scroll */
        unsigned,                       /* Left column of section to scroll */
        unsigned,                       /* Bottom row of section to scroll */
        unsigned,                       /* Right column of section to scroll */
        unsigned,                       /* Number of blank columsn at right */
        char far *,                     /* pointer to blank Char,Attr */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOSCROLLRT (
        unsigned,                       /* Top row of section to scroll */
        unsigned,                       /* Left column of section to scroll */
        unsigned,                       /* Bottom row of section to scroll */
        unsigned,                       /* Right column of section to scroll */
        unsigned,                       /* Number of blank columsn at left */
        char far *,                     /* pointer to blank Char,Attr */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOSETCURPOS (
        unsigned,                       /* Row return data */
        unsigned,                       /* Column return data */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOSETCURTYPE (
        struct CursorData far *,        /* Cursor characteristics */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOSETMODE (
        struct ModeData far *,          /* Mode characteristics */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOSHOWBUF (
        unsigned,                       /* Offset into buffer */
        unsigned,                       /* Length of area to be updated */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOWRTCELLSTR (
        char far *,                     /* String to be written */
        unsigned,                       /* Length of string */
        unsigned,                       /* Starting position for output (row) */
        unsigned,                       /* Starting position for output (col) */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOWRTCHARSTR (
        char far *,                     /* String to be written */
        unsigned,                       /* Length of string */
        unsigned,                       /* Starting position for output (row) */
        unsigned,                       /* Starting position for output (col) */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOWRTCHARSTRATT (
        char far *,                     /* String to be written */
        unsigned,                       /* Length of string */
        unsigned,                       /* Starting position for output (row) */
        unsigned,                       /* Starting position for output (col) */
        char far *,                     /* Attribute to be replicated */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOWRTNATTR (
        char far *,                     /* Attribute to be written */
        unsigned,                       /* Length of write */
        unsigned,                       /* Starting position for output (row) */
        unsigned,                       /* Starting position for output (col) */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOWRTNCELL (
        char far *,                     /* Cell to be written */
        unsigned,                       /* Length of write */
        unsigned,                       /* Starting position for output (row) */
        unsigned,                       /* Starting position for output (col) */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOWRTNCHAR (
        char far *,                     /* Character to be written */
        unsigned,                       /* Length of write */
        unsigned,                       /* Starting position for output (row) */
        unsigned,                       /* Starting position for output (col) */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOWRTTTY (
        char far *,                     /* String to be written */
        unsigned,                       /* Length of string */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOSETANSI (
        unsigned,                       /* ON (=1) or OFF (=0) indicator */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOGETANSI (
        unsigned far *,                 /* ANSI state (returned) */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOPRTSC (
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOPRTSCTOGGLE (
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOSAVREDRAWWAIT (
        unsigned,                       /* Save/Redraw Indicator */
        unsigned far *,                 /* Notify type (returned) */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOSAVREDRAWUNDO (
        unsigned,                       /* Ownership Indicator */
        unsigned,                       /* Terminate Indicator */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOMODEWAIT (
        unsigned,                       /* Request type */
        unsigned far *,                 /* Notify type (returned) */
        unsigned );                     /* Reserved (must be 0) */
extern unsigned far pascal VIOMODEUNDO (
        unsigned,                       /* Ownership indicator */
        unsigned,                       /* Terminate indicator */
        unsigned );                     /* Reserved (must be 0) */
extern unsigned far pascal VIOSCRLOCK (
        unsigned,                       /* Wait Flag */
        unsigned char far *,            /* Status of lock (returned) */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOSCRUNLOCK (
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOPOPUP (
        unsigned far *,                 /* Wait/Nowait Bit flags */
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOENDPOPUP (
        unsigned );                     /* Vio Handle */
extern unsigned far pascal VIOGETCONFIG (
        unsigned,                       /* Reserved - must be 0 */
        struct ConfigData far *,        /* Pointer to data buffer */
        unsigned );                     /* VIO handle */
extern unsigned far pascal VIOGETFONT (
        struct VIOFONT far *,           /* request block */
        unsigned );                     /* VIO handle */
extern unsigned far pascal VIOGETCP (
        unsigned,                       /* Reserved - must be 0 */
        unsigned far *,                 /* Ptr to returnd codepageID */
        unsigned );                     /* VIO handle */
extern unsigned far pascal VIOSETCP (
        unsigned,                       /* Reserved - must be 0 */
        unsigned,                       /* codepage ID */
        unsigned );                     /* VIO handle */
extern unsigned far pascal VIOSETFONT (
        struct VIOFONT far *,           /* request block */
        unsigned );                     /* VIO handle */
extern unsigned far pascal VIOGETSTATE (
        struct VIOSTATE far *,          /* request block */
        unsigned );                     /* VIO handle */
extern unsigned far pascal VIOSETSTATE (
        struct VIOSTATE far *,          /* request block */
        unsigned );                     /* VIO handle */
extern unsigned far pascal MOUREGISTER (
        char far *,                     /* Module name */
        char far *,                     /* Entry Point name */
        unsigned long );                /* Function mask */
extern unsigned far pascal MOUDEREGISTER (
        void );                         /* No Parameters */
extern unsigned far pascal MOUFLUSHQUE (
        unsigned );                     /* Mouse device handle */
extern unsigned far pascal MOUGETHOTKEY (
        unsigned far *,                 /* mask of which key is the hot key */
        unsigned );                     /* Mouse device handle */
extern unsigned far pascal MOUSETHOTKEY (
        unsigned far *,                 /* Mouse Button Mask */
        unsigned );                     /* Mouse Device Handle */
extern unsigned far pascal MOUGETPTRPOS (
        struct PtrLoc far *,            /* Pointer Location Record (returned) */
        unsigned );                     /* Mouse device handle */
extern unsigned far pascal MOUSETPTRPOS (
        struct PtrLoc far *,            /* Pointer Location Record */
        unsigned );                     /* Mouse device handle */
extern unsigned far pascal MOUGETPTRSHAPE (
        unsigned char far *,            /* Pointer Shape Buffer (returned) */
        struct PtrImage far *,          /* Pointer Definition Record */
        unsigned );                     /* Mouse device handle */
extern unsigned far pascal MOUSETPTRSHAPE (
        unsigned char far *,            /* Pointer Shape Buffer */
        struct PtrImage far *,          /* Pointer Definition Record */
        unsigned );                     /* Mouse device handle */
extern unsigned far pascal MOUGETDEVSTATUS (
        unsigned far *,                 /* Current status flags (returned) */
        unsigned );                     /* Mouse Device Handle */
extern unsigned far pascal MOUGETNUMBUTTONS (
        unsigned far *,                 /* Number of mouse buttons (returned) */
        unsigned );                     /* Mouse Device Handle */
extern unsigned far pascal MOUGETNUMMICKEYS (
        unsigned far *,                 /* Number of Mickeys/cm (returned) */
        unsigned );                     /* Mouse Device Handle */
extern unsigned far pascal MOUREADEVENTQUE (
        struct EventInfo far *,         /* Event Queue Entry (returned) */
        unsigned far *,                 /* Type of read operation */
        unsigned );                     /* Mouse Device Handle */
extern unsigned far pascal MOUGETNUMQUEEL (
        struct QueInfo far *,           /* Queue Information (returned) */
        unsigned );                     /* Mouse Device Handle */
extern unsigned far pascal MOUGETEVENTMASK (
        unsigned far *,                 /* Event Mask (returned) */
        unsigned );                     /* Mouse Device Handle */
extern unsigned far pascal MOUSETEVENTMASK (
        unsigned far *,                 /* Event Mask */
        unsigned );                     /* Mouse Device Handle */
extern unsigned far pascal MOUGETSCALEFACT (
        struct ScaleFact far *,         /* Scaling Factors (returned) */
        unsigned );                     /* Mouse Device Handle */
extern unsigned far pascal MOUSETSCALEFACT (
        struct ScaleFact far *,         /* Scaling Factors */
        unsigned );                     /* Mouse Device Handle */
extern unsigned far pascal MOUOPEN (
        char far *,                     /* Pointer draw device name */
        unsigned far * );               /* Mouse Device Handle (returned) */
extern unsigned far pascal MOUCLOSE (
        unsigned );                     /* Mouse Device Handle */
extern unsigned far pascal MOUREMOVEPTR (
        struct NoPointer far *,         /* Pointer Area */
        unsigned );                     /* Mouse Device Handle */
extern unsigned far pascal MOUDRAWPTR (
        unsigned );                     /* Mouse Device Handle */
extern unsigned far pascal MOUSETDEVSTATUS (
        unsigned far *,                 /* status flags */
        unsigned );                     /* Mouse Device Handle */
extern unsigned far pascal MOUINITREAL (
        char far * );                   /* Pointer draw driver name */
extern unsigned far pascal MOUSYNCH (
        unsigned );                     /* I/O Wait - indicate wait/nowait */
