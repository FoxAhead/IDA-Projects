;лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
;лл                                                                        лл
;лл  VFX.INC                                                               лл
;лл                                                                        лл
;лл  Header file for VFX functions                                         лл
;лл                                                                        лл
;лл  80386 ASM source compatible with Microsoft Assembler v6.0 or later    лл
;лл                                                                        лл
;лл  Version 0.10 of  6-Jan-93: Initial version                            лл
;лл          1.00 of 19-Jun-93: Current working version                    лл
;лл          1.10 of  3-Dec-93: Added common clipping macro                лл
;лл                                                                        лл
;лл  Project: 386FX Sound & Light(TM)                                      лл
;лл  Authors: Ken Arnold, John Miles, John Lemberger                       лл
;лл                                                                        лл
;лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
;лл                                                                        лл
;лл  Copyright (C) 1992-1994 Non-Linear Arts, Inc.                         лл
;лл                                                                        лл
;лл  Non-Linear Arts, Inc.                                                 лл
;лл  3415 Greystone #200                                                   лл
;лл  Austin, TX 78731                                                      лл
;лл                                                                        лл
;лл  (512) 346-9595 / FAX (512) 346-9596 / BBS (512) 454-9990              лл
;лл                                                                        лл
;лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

TRUE        equ -1
FALSE       equ 0

TRANSPARENT equ 255             ;Default transparent color for many primitives

;--------------------------------
;
; Window and pane structure definitions
;
;--------------------------------

PBYTE       TYPEDEF PTR BYTE

WINDOW      STRUCT
  buffer    PBYTE   ?
  wnd_x1    DWORD   ?
  wnd_y1    DWORD   ?

  stencil   PBYTE   ?
  shadow    PBYTE   ?
WINDOW      ENDS

PWIN        TYPEDEF PTR WINDOW

;--------------------------------

PANE        STRUCT
  win       PWIN    ?
  x0        DWORD   ?
  y0        DWORD   ?
  x1        DWORD   ?
  y1        DWORD   ?
PANE        ENDS

PPANE       TYPEDEF PTR PANE

;--------------------------------

POINT       STRUCT
  x         DWORD ?
  y         DWORD ?
POINT       ENDS

PPOINT      TYPEDEF PTR POINT

;--------------------------------

FONT        STRUCT
  version          DWORD ?
  char_count       DWORD ?
  char_height      DWORD ?
  font_background  DWORD ?
FONT        ENDS

PFONT      TYPEDEF PTR FONT

;--------------------------------

SHAPETABLE  STRUCT
  version          DWORD ?
  shape_count      DWORD ?
SHAPETABLE  ENDS

PSHAPETABLE TYPEDEF PTR SHAPETABLE

;--------------------------------

SHAPEHEADER STRUCT
  bounds           DWORD ?
  origin           DWORD ?
  xmin             DWORD ?
  ymin             DWORD ?
  xmax             DWORD ?
  ymax             DWORD ?
SHAPEHEADER ENDS

PSHAPEHEADER TYPEDEF PTR SHAPEHEADER

;--------------------------------

PCX         STRUCT
  manufacturer     BYTE  ?
  version          BYTE  ?
  encoding         BYTE  ?
  bits_per_pixel   BYTE  ?
  xmin             WORD  ?
  ymin             WORD  ?
  xmax             WORD  ?
  ymax             WORD  ?
  hres             WORD  ?
  vres             WORD  ?
  palette          BYTE 48 DUP (?)
  reserved         BYTE  ?
  color_planes     BYTE  ?
  BYTEs_per_line   WORD  ?
  palette_type     WORD  ?
  filler           BYTE 58 DUP (?)
PCX         ENDS

PPCX       TYPEDEF PTR PCX

;--------------------------------

GIFDATA    STRUCT
  nextcode         DWORD ?
  nextlimit        DWORD ?
  xloc             DWORD ?
  yloc             DWORD ?
  bufct            DWORD ?
  rem              DWORD ?
  remct            DWORD ?
  reqct            DWORD ?
  rowcnt           DWORD ?
  imagewide        DWORD ?
  imagedepth       DWORD ?
  interlaced       BYTE  ?
  pass             BYTE  ?
GIFDATA    ENDS

PGIFDATA      TYPEDEF PTR GIFDATA

GIF_STACK       equ SIZEOF GIFDATA              ;Offsets into GIF data area
GIF_FIRST       equ SIZEOF GIFDATA +  4096 
GIF_LAST        equ SIZEOF GIFDATA +  8192 
GIF_LINK        equ SIZEOF GIFDATA + 12288 

;--------------------------------

GIF        STRUCT
  gif8             DWORD ?
  seven_a          WORD  ?
  screen_width     WORD  ?
  screen_depth     WORD  ?
  global_flag      BYTE  ?
  background_color BYTE  ?
  zero             BYTE  ?
GIF        ENDS

PGIF      TYPEDEF PTR GIF

;--------------------------------

LGIF       STRUCT
  comma            BYTE  ?
  image_left       WORD  ?
  image_top        WORD  ?
  image_wide       WORD  ?
  image_depth      WORD  ?
  local_flag       BYTE  ?
LGIF       ENDS

PLGIF      TYPEDEF PTR LGIF

;--------------------------------
;
;Vertex structure used by all polygon primitives
;

SCRNVERTEX      STRUC
vx              dd ?    ;Vertex destination X
vy              dd ?    ;Vertex destination Y
vc              dd ?    ;Vertex color

u               dd ?    ;Source texture X
v               dd ?    ;Source texture Y
w               dd ?    ;Homogeneous perspective factor (perspective mapping)
SCRNVERTEX      ENDS

PSCRNVERTEX     TYPEDEF PTR SCRNVERTEX

;--------------------------------
;
; VFX function prototypes
;

VFX_pane_wipe \
            PROTO   NEAR C, \
                    panep:PPANE, color:DWORD

VFX_pane_copy \
            PROTO   NEAR C, \
                    source:PPANE, sx:DWORD, sy:DWORD, \
                    target:PPANE, tx:DWORD, ty:DWORD, fill:DWORD

VFX_pane_scroll \
            PROTO   NEAR C, \
                    panep:PPANE, dx_:DWORD, dy_:DWORD, mode:DWORD, parm:DWORD

VFX_line_draw \
            PROTO   NEAR C, \
                    panep:PPANE, x0:DWORD, y0:DWORD, x1:DWORD, y1:DWORD, \
                    mode:DWORD, parm:DWORD

VFX_shape_draw \
            PROTO   NEAR C, \
                    panep:PTR PANE, shape_table:PTR SHAPETABLE,
                    shape_number:DWORD, hotX:DWORD, hotY:DWORD

VFX_shape_scan \
            PROTO   NEAR C, \
                    panep:PPANE, transparentColor:DWORD, \
                    hotX:DWORD, hotY:DWORD, buffer:PTR

VFX_pixel_write \
            PROTO   NEAR C, \
                    panep:PPANE, x:DWORD, y:DWORD, color:DWORD

VFX_pixel_read \
            PROTO   NEAR C, \
                    panep:PPANE, x:DWORD, y:DWORD

VFX_shape_resolution \
            PROTO   NEAR C, \
                    shptable:DWORD, snum:DWORD

VFX_shape_minxy \
            PROTO   NEAR C, \
                    shptable:DWORD, snum:DWORD

VFX_point_transform \
            PROTO   NEAR C, \
                P_in:PPOINT, P_out:PPOINT, Origin:PPOINT, \
                Rot:DWORD, X_scale:DWORD, Y_scale:DWORD

;--------------------------------
;
; Prototypes for internal (private) functions
;


DrawShapeUnclipped \
            PROTO   NEAR C, \
                    panep:PPANE, shape:PTR, hotx:DWORD, hoty:DWORD, CP_W:DWORD

XlatShapeUnclipped \
            PROTO   NEAR C, \
                    panep:PPANE, shape:PTR, hotx:DWORD, hoty:DWORD, CP_W:DWORD

ScanLine \
            PROTO   NEAR C, \
                    count:DWORD, skipval:DWORD, CP_L:DWORD

FlushPacket \
            PROTO   NEAR C, \
                    packetType:DWORD, keep:DWORD, CP_L:DWORD

;--------------------------------
;
; Miscellaneous equates
;

; 1/2 in 0:32 fixed point binary (used in 'line_draw).

ONE_HALF    EQU     80000000H

; constant for none-color (used in 'pane_copy and 'pane_scroll)

NO_COLOR    EQU     -1

; packet types (used in 'shape_scan's RLL encoder)

INIT_       equ     0
STRING_     equ     1
RUN_        equ     2
SKIP_       equ     3
END_        equ     4
NONE_       equ     5

; clip flags (used in 'shape_draw)

LEFTOF      EQU     1000B
RIGHTOF     EQU     0100B
ABOVE       EQU     0010B
BELOW       EQU     0001B

;
;Flags used by VFX_map_polygon()
;(Don't change these without also changing vector table logic in
;function!)
;

MP_XLAT     equ 1              ;Enable lookaside table (w/transparency)
MP_XP       equ 2              ;Enable transparency only

;
;Flags used by VFX_shape_transform()
;

ST_XLAT     equ 1              ;Use shape_lookaside() table
ST_REUSE    equ 2              ;Use buffer contents from prior call

;
;Flags used by VFX_shape_visible_rectangle()
;

VR_X_MIRROR   equ  1
VR_Y_MIRROR   equ  2
VR_XY_MIRROR  equ  3

;--------------------------------
;
; General purpose macros for VFXA.ASM
;
;--------------------------------

; mem to reg to mem move

MOVE        MACRO   dest,via,src
            mov     via,src
            mov     dest,via
            ENDM

;--------------------------------
; minimum (signed)

MIN         MACRO   dest,src
            LOCAL   around

            cmp     dest,src
            jl      around
            mov     dest,src
around:
            ENDM

;--------------------------------
; maximum (signed)

MAX         MACRO   dest,src
            LOCAL   around

            cmp     dest,src
            jg      around
            mov     dest,src
around:
            ENDM

;--------------------------------
; quick BYTE moves

STOSB_      MACRO
            mov     [edi],al
            inc     edi
            ENDM
            
LODSB_      MACRO
            mov     al,[esi]
            inc     esi
            ENDM

MOVSB_      MACRO
            LODSB_
            STOSB_
            ENDM

;--------------------------------
; quick WORD moves

STOSW_      MACRO
            mov     [edi],ax
            add     edi,2
            ENDM
            
LODSW_      MACRO
            mov     ax,[esi]
            add     esi,2
            ENDM

MOVSW_      MACRO
            LODSW_
            STOSW_
            ENDM

;--------------------------------
; quick DWORD moves

STOSD_      MACRO
            mov     [edi],eax
            add     edi,4
            ENDM
            
LODSD_      MACRO
            mov     eax,[esi]
            add     esi,4
            ENDM

MOVSD_      MACRO
            LODSD_
            STOSD_
            ENDM

;----------------------------------------------------------------------------
;
; String Macros
;

;--------------------------------
; aliases for repeated instructions (cosmetic)

RSTOSB      MACRO
            rep stosb
            ENDM

RMOVSB      MACRO
            rep movsb
            ENDM

RSTOSW      MACRO
            rep stosw
            ENDM

RMOVSW      MACRO
            rep movsw
            ENDM

RSTOSD      MACRO
            rep stosd
            ENDM

RMOVSD      MACRO
            rep movsd
            ENDM

;--------------------------------
; 32-bit string macros

RSTOSB32    MACRO   temp

            IFNB    <temp>

            mov     temp,ecx
            and     ecx,11B
            RSTOSB

            mov     ah,al
            rol     eax,8
            mov     al,ah
            rol     eax,8
            mov     al,ah

            mov     ecx,temp
            shr     ecx,2
            RSTOSD

            ELSE

            push    ecx
            and     ecx,11B
            RSTOSB

            mov     ah,al
            rol     eax,8
            mov     al,ah
            rol     eax,8
            mov     al,ah

            pop     ecx
            shr     ecx,2
            RSTOSD

            ENDIF

            ENDM


RMOVSB32    MACRO   temp

            IFNB    <temp>

            mov     temp,ecx
            and     ecx,11B
            RMOVSB
            mov     ecx,temp
            shr     ecx,2
            RMOVSD

            ELSE

            push    ecx
            and     ecx,11B
            RMOVSB
            pop     ecx
            shr     ecx,2
            RMOVSD

            ENDIF

            ENDM

RXLAT32     MACRO
            LOCAL __xlat_4,__xlat_1,__exit

            xor eax,eax

            or ecx,ecx
            jz __exit

            cmp ecx,4
            jl __xlat_1

__xlat_4:   mov al,[esi]
            mov al,lookaside[eax]
            mov [edi],al

            mov al,[esi+1]
            mov al,lookaside[eax]
            mov [edi+1],al

            mov al,[esi+2]
            mov al,lookaside[eax]
            mov [edi+2],al

            mov al,[esi+3]
            mov al,lookaside[eax]
            mov [edi+3],al

            add esi,4
            add edi,4

            sub ecx,4
            jz __exit

            cmp ecx,4
            jge __xlat_4

__xlat_1:   mov al,[esi]
            mov al,lookaside[eax]
            mov [edi],al

            inc esi
            inc edi

            dec ecx
            jnz __xlat_1

__exit:
            ENDM

;
;Set pane coordinates; clip pane to window
;
; Input: Pointer to pane structure
;
;Output: Pane width-1, height-1 for clipping (VP_R, VP_B)
;        Pointer to (0,0) pixel relative to pane (buff_addr)
;        Width of window scanline (line_size)
;

SET_DEST_PANE MACRO

            ASSUME esi:PPANE
            ASSUME ebx:PWIN

            mov esi,[DestPane]      ;get pane pointer
            mov ebx,[esi].win       ;windowp = panep->win

            mov ecx,[ebx].wnd_x1    ;set ECX = wnd_x1-wnd_x0+1
            inc ecx
            mov line_size,ecx       ;store line width in bytes = ECX

            mov eax,[esi].x1        ;VP_R = min(pane width, Xsize)
            mov ecx,[ebx].wnd_x1
            MIN ecx,eax
            mov eax,[esi].x0
            mov edi,0
            MAX edi,eax
            sub ecx,edi
            jl __exit               ;if VP_R < 0, exit
            mov VP_R,ecx

            mov eax,[esi].y1        ;VP_B = min(pane height, Ysize)
            mov ecx,[ebx].wnd_y1
            MIN ecx,eax
            mov edx,[esi].y0
            mov eax,0
            MAX eax,edx
            sub ecx,eax
            jl __exit               ;if VP_B < 0, exit
            mov VP_B,ecx

            mul line_size           ;adjust window buffer pointer to
            add eax,edi             ;point to upper-left corner of pane
            add eax,[ebx].buffer
            mov buff_addr,eax       ;&(0,0) = (width*Y) + top X + buffer

            ENDM


;
;Macro to compile partially unrolled scanline loops
;
;Pass label name for top of loop, macro name for loop body,
;# of unrolled blocks, # of pixels written per iteration,
;register/location containing # of iterations-1
;

PARTIAL_UNROLL MACRO LName,MName,Extent,Pixels,Itcnt

&LName&:    cmp Itcnt,Extent-1
            jl &LName&_last
&LName&_unroll:
INDEX       = 0
            REPT Extent
            &MName&
INDEX       = INDEX + Pixels
            ENDM
            add edi,Extent*Pixels
            sub Itcnt,Extent
            js &LName&_done
            cmp Itcnt,Extent-1
            jge &LName&_unroll
&LName&_last:
INDEX       = 0
            REPT Extent-1
            &MName&
            IF INDEX NE ((Extent-2)*Pixels)
            dec Itcnt
            js &LName&_done
            ENDIF
INDEX       = INDEX + Pixels
            ENDM
&LName&_done:

            ENDM

            ;
            ;Fixed-point multiply yields EAX = whole:fract result
            ;of EAX * Multiplier
            ;
            ;(Does not round; should be used only to project to screen)
            ;

FPMUL       MACRO Multiplier

            imul Multiplier
            shrd eax,edx,16

            ENDM

            ;
            ;Fixed-point divide yields EAX = whole:fract result
            ;of FP EDX / integer Divisor
            ;
            ;Does not round; should be used only to project to screen
            ;
            ;Warning: destroys Divisor
            ;
            
FPDIV       MACRO Divisor

            xor eax,eax
            shrd eax,edx,16
            shl Divisor,16
            sar edx,16
            idiv Divisor

            ENDM

            ;
            ;Does not round; should be used only to project to screen
            ;
            ;Warning: destroys Divisor
            ;
            
FPDIV       MACRO Divisor

            xor eax,eax
            shrd eax,edx,16
            shl Divisor,16
            sar edx,16
            idiv Divisor

            ENDM


;
;         Clip pane to window
;
; Input:  Pointer to pane structure
;         Optional letters to replace CP
;
; Output: CP_L     Clipped Pane's leftmost pixel, given in window coordinates
;         CP_T                 top
;         CP_R                 right
;         CP_B                 bottom
;
;         CP_A     Base address of underlying window
;         CP_W     Width of underlying window
;
;         CP_CX    equals pane.x0 
;                  Window x coord. = Pane x coord. + (CP_CX = pane.x0)
;         CP_CY    equals pane.y0
;                  Window y coord. = Pane y coord. + (CP_CY = pane.y0)
;
; Uses:   eax, ebx, ecx, edx, esi
;


CLIP_PANE_TO_WINDOW     MACRO     panep:REQ, vname:=<CP>

                LOCAL     ReturnBadWindow
                LOCAL     ReturnBadPane
                LOCAL     exit

                ; get panep (esi)
                ; windowp (ebx) = panep->win

                ASSUME  esi:PPANE
                ASSUME  ebx:PWIN

                mov     esi,panep
                mov     ebx,[esi].win

                ; &vname&_W = windowp->wnd_x1 + 1
                ; if <= 0, return bad window
    
                mov     eax,[ebx].wnd_x1
                inc     eax
                mov     &vname&_W,eax
                jle     ReturnBadWindow
    
                ; ecx = Ysize = windowp->wnd_y1 + 1
                ; if <= 0, return bad window

                mov     eax,[ebx].wnd_y1
                inc     eax
                mov     ecx,eax
                jle     ReturnBadWindow

                ; clip pane to window:
                ;   pane_x0 = max (pane->x0, 0)
                ;   pane_y0 = max (pane->y0, 0)
                ;   pane_x1 = min (pane->x1, &vname&_W - 1)
                ;   pane_y1 = min (pane->x1, (Ysize=ecx) - 1)

                mov     eax,[esi].x0
                mov     &vname&_CX,eax
                MAX     eax,0
                mov     &vname&_L,eax
    
                mov     eax,[esi].y0
                mov     &vname&_CY,eax
                MAX     eax,0
                mov     &vname&_T,eax
    
                mov     eax,[esi].x1
                mov     edx,&vname&_W
                dec     edx
                MIN     eax,edx
                mov     &vname&_R,eax
    
                mov     eax,[esi].y1
                mov     edx,ecx
                dec     edx
                MIN     eax,edx
                mov     &vname&_B,eax

                ; exit if pane is malformed or completely off window:
                ;   if &vname&_B < &vname&_T, return bad pane
                ;   if &vname&_R < &vname&_L, return bad pane

                mov     eax,&vname&_R
                cmp     eax,&vname&_L
                jl      ReturnBadPane
    
                mov     eax,&vname&_B
                cmp     eax,&vname&_T
                jl      ReturnBadPane

                mov     eax,[ebx].buffer
                mov     &vname&_A,eax

                ASSUME  esi:nothing
                ASSUME  ebx:nothing

                jmp     exit

ReturnBadWindow:
                mov     eax,-1
                ret

ReturnBadPane:
                mov     eax,-2
                ret
exit:

                ENDM

;
;         Get screen address of point
;
; Input:  x,y pair in Window coordinates
;
; Output: eax      Address of x,y on screen
;
; Uses:   eax, edx
;

GET_WINDOW_ADDRESS MACRO x:REQ, y:REQ, vname:=<CP>

                mov     eax,y
                imul    &vname&_W
                add     eax,&vname&_A
                add     eax,x

                ENDM

;
;         Convert from pane to window coordinates
;
; Input:  x,y pair or x,y,x,y quad in Pane coordinates
;
; Output: x,y pair or x,y,x,y quad in Window coordinates
;
; Uses:   eax
;

CONVERT_REG_PAIR_PANE_TO_WINDOW MACRO x:REQ, y:REQ, vname:=<CP>

                add     x,&vname&_CX
                add     y,&vname&_CY

                ENDM

CONVERT_PAIR_PANE_TO_WINDOW MACRO x:REQ, y:REQ, vname:=<CP>

                mov     eax,&vname&_CX
                add     x,eax

                mov     eax,&vname&_CY
                add     y,eax

                ENDM

CONVERT_QUAD_PANE_TO_WINDOW MACRO x0:REQ, y0:REQ, x1:REQ, y1:REQ, vname:=<CP>

                mov     eax,&vname&_CX
                add     x0,eax
                add     x1,eax

                mov     eax,&vname&_CY
                add     y0,eax
                add     y1,eax

                ENDM

;
;         Convert from window to pane coordinates
;
; Input:  x,y pair or x,y,x,y quad in Window coordinates
;
; Output: x,y pair or x,y,x,y quad in Pane coordinates
;
; Uses:   eax
;

CONVERT_REG_PAIR_WINDOW_TO_PANE MACRO x:REQ, y:REQ, vname:=<CP>

                sub     x,&vname&_CX
                sub     y,&vname&_CY

                ENDM

CONVERT_PAIR_WINDOW_TO_PANE MACRO x:REQ, y:REQ, vname:=<CP>

                mov     eax,&vname&_CX
                sub     x,eax

                mov     eax,&vname&_CY
                sub     y,eax

                ENDM

CONVERT_QUAD_WINDOW_TO_PANE MACRO x0:REQ, y0:REQ, x1:REQ, y1:REQ, vname:=<CP>

                mov     eax,&vname&_CX
                sub     x0,eax
                sub     x1,eax

                mov     eax,&vname&_CY
                sub     y0,eax
                sub     y1,eax

                ENDM

;
;         Get pane size
;
; Input:  p        Pointer to pane
;         width    Destination variable for width
;         height   Destination variable for height
;
; Output: width    
;         height
;
; Uses:   eax, esi
;

GET_PANE_SIZE   MACRO p:REQ, width:REQ, height:REQ

                mov esi,p
                mov eax,[esi].PANE.x1
                sub eax,[esi].PANE.x0
                inc eax
                mov width,eax

                mov eax,[esi].PANE.y1
                sub eax,[esi].PANE.y0
                inc eax
                mov height,eax

                ENDM



