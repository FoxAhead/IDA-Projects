;*****************************************************************************
;*                                                                           *
;*  WINVFX8.ASM                                                              *
;*                                                                           *
;*  VFX API assembly functions for 8-bit color modes (1 byte/pixel)          *
;*                                                                           *
;*  Version 1.00 of 20-Jul-96: Initial, derived from VFXA.ASM 1.10/W3W       *
;*                             and VFX3D.ASM 1.10/W3W                        *
;*          1.01 of 13-Feb-97: VFX_shape_scan() creates single-entry         *
;*                             table suitable for use with other shape       *
;*                             primitives                                    *
;*                             All VFX_RGB structures converted from         *
;*                             6-6-6 to 8-8-8 format                         *
;*                             GIF LZW hash table now internal               *
;*                             PCX_draw() now requires PCX file size         *
;*                             Added VFX_shape_area_translate()              *
;*          1.02 of 18-Sep-98: Fixed 1xN/Nx1 shapes in area_translate()      *
;*                             Fixed step calcs in LD_EXECUTE handlers       *
;*          1.03 of  3-Dec-98: string_draw() handles empty strings properly  *
;*                                                                           *
;*  Project: 386FX Sound & Light(TM)                                         *
;*  Authors: Ken Arnold, John Lemberger, John Miles                          *
;*                                                                           *
;*  C prototypes in WINVFX.H                                                 *
;*                                                                           *
;*  80386 ASM source compatible with Microsoft Assembler v6.0 or later       *
;*                                                                           *
;*****************************************************************************
;*                                                                           *
;*  Copyright (C) 1992-1996 Miles Design, Inc.                               *
;*                                                                           *
;*  Miles Design, Incorporated                                               *
;*  8301 Elander Drive                                                       *
;*  Austin, TX 78750                                                         *
;*                                                                           *
;*  (512) 345-2642 / FAX (512) 338-9630 / 70322.2457@compuserve.com          *
;*                                                                           *
;*****************************************************************************

                OPTION SCOPED           ;Enable local labels

                .386                    ;Enable 386 instructions
                .MODEL FLAT,STDCALL     ;32-bit Windows model

                INCLUDE winvfx.inc

PBYTE           TYPEDEF PTR BYTE
PWIN            TYPEDEF PTR VFX_WINDOW
PTABLE          TYPEDEF PTR VFX_SHAPETABLE
PPANE           TYPEDEF PTR PANE
PPOINT          TYPEDEF PTR VFX_POINT
PFONT           TYPEDEF PTR VFX_FONT
PSCRNVERTEX     TYPEDEF PTR SCRNVERTEX

;--------------------------------

SHAPEHEADER     STRUCT
bounds          DWORD ?
origin          DWORD ?
xmin            DWORD ?
ymin            DWORD ?
xmax            DWORD ?
ymax            DWORD ?
SHAPEHEADER     ENDS

PSHAPEHEADER    TYPEDEF PTR SHAPEHEADER

;--------------------------------

PCX             STRUCT
manufacturer    BYTE  ?
version         BYTE  ?
encoding        BYTE  ?
bits_per_pixel  BYTE  ?
xmin            WORD  ?
ymin            WORD  ?
xmax            WORD  ?
ymax            WORD  ?
hres            WORD  ?
vres            WORD  ?
palette         BYTE 48 DUP (?)
reserved        BYTE  ?
color_planes    BYTE  ?
bytes_per_line  WORD  ?
palette_type    WORD  ?
filler          BYTE 58 DUP (?)
PCX             ENDS

PPCX            TYPEDEF PTR PCX

;--------------------------------

GIFDATA         STRUCT
nextcode        DWORD ?
nextlimit       DWORD ?
xloc            DWORD ?
yloc            DWORD ?
bufct           DWORD ?
rem             DWORD ?
remct           DWORD ?
reqct           DWORD ?
rowcnt          DWORD ?
imagewide       DWORD ?
imagedepth      DWORD ?
interlaced      BYTE  ?
pass            BYTE  ?
GIFDATA         ENDS

PGIFDATA        TYPEDEF PTR GIFDATA

GIF_STACK       equ SIZEOF GIFDATA              ;Offsets into GIF data area
GIF_FIRST       equ SIZEOF GIFDATA +  4096 
GIF_LAST        equ SIZEOF GIFDATA +  8192 
GIF_LINK        equ SIZEOF GIFDATA + 12288 

;--------------------------------

GIF             STRUCT
gif8             DWORD ?
seven_a          WORD  ?
screen_width     WORD  ?
screen_depth     WORD  ?
global_flag      BYTE  ?
background_color BYTE  ?
zero             BYTE  ?
GIF             ENDS

PGIF            TYPEDEF PTR GIF

;--------------------------------

LGIF            STRUCT
comma           BYTE  ?
image_left      WORD  ?
image_top       WORD  ?
image_wide      WORD  ?
image_depth     WORD  ?
local_flag      BYTE  ?
LGIF            ENDS

PLGIF           TYPEDEF PTR LGIF

;
;Prototypes for internal (private) functions
;

DrawShapeUnclipped \
                PROTO   STDCALL, \
                panep:PPANE, shape:PTR, hotx:DWORD, hoty:DWORD, CP_W:DWORD

XlatShapeUnclipped \
                PROTO   STDCALL, \
                panep:PPANE, shape:PTR, hotx:DWORD, hoty:DWORD, CP_W:DWORD

ScanLine \
                PROTO   STDCALL, \
                count:DWORD, skipval:DWORD, CP_L:DWORD

FlushPacket \
                PROTO   STDCALL, \
                packetType:DWORD, keep:DWORD, CP_L:DWORD

;--------------------------------
;
; Miscellaneous equates
;

; 1/2 in 0:32 fixed point binary (used in 'line_draw).

ONE_HALF        EQU     80000000H

; constant for none-color (used in 'pane_copy and 'pane_scroll)

NO_COLOR        EQU     -1

; packet types (used in 'shape_scan's RLL encoder)

INIT_           equ     0
STRING_         equ     1
RUN_            equ     2
SKIP_           equ     3
END_            equ     4
NONE_           equ     5

; clip flags (used in 'shape_draw)

LEFTOF          EQU     1000B
RIGHTOF         EQU     0100B
ABOVE           EQU     0010B
BELOW           EQU     0001B

;--------------------------------
;
; General purpose macros for VFXA.ASM
;
;--------------------------------

; mem to reg to mem move

MOVE            MACRO   dest,via,src
                mov     via,src
                mov     dest,via
                ENDM

;--------------------------------
; minimum (signed)

MIN             MACRO   dest,src
                LOCAL   around

                cmp     dest,src
                jl      around
                mov     dest,src
around:
                ENDM

;--------------------------------
; maximum (signed)

MAX             MACRO   dest,src
                LOCAL   around

                cmp     dest,src
                jg      around
                mov     dest,src
around:
                ENDM

;--------------------------------
; quick BYTE moves

STOSB_          MACRO
                mov     [edi],al
                inc     edi
                ENDM
            
LODSB_          MACRO
                mov     al,[esi]
                inc     esi
                ENDM

MOVSB_          MACRO
                LODSB_
                STOSB_
                ENDM

;--------------------------------
; quick WORD moves

STOSW_          MACRO
                mov     [edi],ax
                add     edi,2
                ENDM
                
LODSW_          MACRO
                mov     ax,[esi]
                add     esi,2
                ENDM

MOVSW_          MACRO
                LODSW_
                STOSW_
                ENDM

;--------------------------------
; quick DWORD moves

STOSD_          MACRO
                mov     [edi],eax
                add     edi,4
                ENDM
                
LODSD_          MACRO
                mov     eax,[esi]
                add     esi,4
                ENDM

MOVSD_          MACRO
                LODSD_
                STOSD_
                ENDM

;----------------------------------------------------------------------------
;
; String Macros
;

;--------------------------------
; aliases for repeated instructions (cosmetic)

RSTOSB          MACRO
                rep stosb
                ENDM
            
RMOVSB          MACRO
                rep movsb
                ENDM
            
RSTOSW          MACRO
                rep stosw
                ENDM
            
RMOVSW          MACRO
                rep movsw
                ENDM

RSTOSD          MACRO
                rep stosd
                ENDM

RMOVSD          MACRO
                rep movsd
                ENDM

;--------------------------------
; 32-bit string macros

RSTOSB32        MACRO   temp
                
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
              
RMOVSB32        MACRO   temp

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

RXLAT32         MACRO
                LOCAL __xlat_4,__xlat_1,__exit

                xor eax,eax
                
                or ecx,ecx
                jz __exit
                
                cmp ecx,4
                jl __xlat_1
                
__xlat_4:       mov al,[esi]
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
                
__xlat_1:       mov al,[esi]
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

SET_DEST_PANE   MACRO

                ASSUME esi:PPANE
                ASSUME ebx:PWIN
                
                mov esi,[DestPane]      ;get pane pointer
                mov ebx,[esi].window    ;windowp = panep->win
                
                mov ecx,[ebx].x_max     ;set ECX = x1-x0+1
                inc ecx
                mov line_size,ecx       ;store line width in bytes = ECX
                
                mov eax,[esi].x1        ;VP_R = min(pane width, Xsize)
                mov ecx,[ebx].x_max
                MIN ecx,eax
                mov eax,[esi].x0
                mov edi,0
                MAX edi,eax
                sub ecx,edi
                jl __exit               ;if VP_R < 0, exit
                mov VP_R,ecx
                
                mov eax,[esi].y1        ;VP_B = min(pane height, Ysize)
                mov ecx,[ebx].y_max
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

PARTIAL_UNROLL  MACRO LName,MName,Extent,Pixels,Itcnt

&LName&:        cmp Itcnt,Extent-1
                jl &LName&_last
&LName&_unroll:
INDEX           = 0
                REPT Extent
                &MName&
INDEX           = INDEX + Pixels
                ENDM
                add edi,Extent*Pixels
                sub Itcnt,Extent
                js &LName&_done
                cmp Itcnt,Extent-1
                jge &LName&_unroll
&LName&_last:
INDEX           = 0
                REPT Extent-1
                &MName&
                IF INDEX NE ((Extent-2)*Pixels)
                dec Itcnt
                js &LName&_done
                ENDIF
INDEX           = INDEX + Pixels
                ENDM
&LName&_done:
                ENDM

;
;Fixed-point multiply yields EAX = whole:fract result
;of EAX * Multiplier
;
;(Does not round; should be used only to project to screen)
;

FPMUL           MACRO Multiplier

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
            
FPDIV           MACRO Divisor

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
            
FPDIV           MACRO Divisor

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
;         CP_BW    Width of underlying window (bytes)
;         CP_W     Width of underlying window (pixels)
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
                mov     ebx,[esi].window

                ; &vname&_W = windowp->x1 + 1
                ; if <= 0, return bad window
    
                mov     eax,[ebx].x_max
                inc     eax
                mov     &vname&_W,eax
                jle     ReturnBadWindow

                imul [ebx].pixel_pitch
                mov &vname&_BW,eax
    
                ; ecx = Ysize = windowp->y1 + 1
                ; if <= 0, return bad window

                mov     eax,[ebx].y_max
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

                mov eax,[ebx].pixel_pitch
                mov pixel_pitch,eax

                mov eax,[ebx].bytes_per_pixel
                mov bytes_per_pixel,eax

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
                imul    &vname&_BW
                add     eax,&vname&_A
                mov     edx,x
                imul    edx,pixel_pitch
                add     eax,edx

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

                ;
                ;Translate 15-bit RGB to palette color
                ;

GET_COLOR       MACRO location
                LOCAL __use

                pusha

                mov eax,location
                test eax,40000000h
                jz __use

                mov ebx,eax
                mov ecx,eax
                shr ebx,5
                shr ecx,10
                and eax,1fh
                and ebx,1fh
                and ecx,1fh
                shl eax,3
                shl ebx,3
                shl ecx,3

                invoke VFX_triplet_value,ecx,ebx,eax
                
__use:          and eax,0ffh
                mov location,eax

                popa

                ENDM

                ;
                ;API functions
                ;

                PUBLIC VFX_pixel_write
                PUBLIC VFX_pixel_read

                PUBLIC VFX_line_draw

                PUBLIC VFX_rectangle_hash

                PUBLIC VFX_shape_scan

                PUBLIC VFX_shape_draw
                PUBLIC VFX_shape_visible_rectangle

                PUBLIC VFX_shape_lookaside
                PUBLIC VFX_shape_translate_draw

                PUBLIC VFX_shape_transform
                PUBLIC VFX_shape_area_translate

                PUBLIC VFX_shape_remap_colors

                PUBLIC VFX_pane_wipe
                PUBLIC VFX_pane_copy
                PUBLIC VFX_pane_scroll

                PUBLIC VFX_ellipse_draw
                PUBLIC VFX_ellipse_fill

                PUBLIC VFX_point_transform
                PUBLIC VFX_Cos_Sin
                PUBLIC VFX_fixed_mul

                PUBLIC VFX_font_height
                PUBLIC VFX_character_width
                PUBLIC VFX_character_draw
                PUBLIC VFX_string_draw

                PUBLIC VFX_ILBM_draw
                PUBLIC VFX_ILBM_palette
                PUBLIC VFX_ILBM_resolution

                PUBLIC VFX_PCX_draw
                PUBLIC VFX_PCX_palette
                PUBLIC VFX_PCX_resolution

                PUBLIC VFX_GIF_draw
                PUBLIC VFX_GIF_palette
                PUBLIC VFX_GIF_resolution

                PUBLIC VFX_shape_bounds
                PUBLIC VFX_shape_origin
                PUBLIC VFX_shape_resolution
                PUBLIC VFX_shape_minxy
                PUBLIC VFX_shape_palette
                PUBLIC VFX_shape_colors
                PUBLIC VFX_shape_set_colors
                PUBLIC VFX_shape_count
                PUBLIC VFX_shape_list
                PUBLIC VFX_shape_palette_list

                PUBLIC VFX_color_scan

                PUBLIC VFX_flat_polygon
                PUBLIC VFX_Gouraud_polygon
                PUBLIC VFX_dithered_Gouraud_polygon
                PUBLIC VFX_map_lookaside
                PUBLIC VFX_map_polygon
                PUBLIC VFX_translate_polygon
                PUBLIC VFX_illuminate_polygon

                ;
                ;Equates to enable/disable assembly of function bodies
                ;
                ;Unused functions may be set to FALSE to save code space --
                ;also must remove PUBLIC declarations for unused functions
                ;

                do_VFX_pixel_write              equ TRUE
                do_VFX_pixel_read               equ TRUE
                do_VFX_line_draw                equ TRUE
                do_VFX_rectangle_hash           equ TRUE
                do_VFX_shape_scan               equ TRUE
                do_VFX_shape_draw               equ TRUE
                do_VFX_shape_visible_rectangle  equ TRUE
                do_VFX_shape_lookaside          equ TRUE
                do_VFX_shape_translate_draw     equ TRUE
                do_VFX_shape_transform          equ TRUE
                do_VFX_shape_area_translate     equ TRUE
                do_VFX_shape_remap_colors       equ TRUE
                do_VFX_pane_wipe                equ TRUE
                do_VFX_pane_copy                equ TRUE
                do_VFX_pane_scroll              equ TRUE
                do_VFX_ellipse_draw             equ TRUE
                do_VFX_ellipse_fill             equ TRUE
                do_VFX_point_transform          equ TRUE
                do_VFX_Cos_Sin                  equ TRUE
                do_VFX_fixed_mul                equ TRUE
                do_VFX_font_height              equ TRUE
                do_VFX_character_width          equ TRUE
                do_VFX_character_draw           equ TRUE
                do_VFX_string_draw              equ TRUE
                do_VFX_ILBM_draw                equ TRUE
                do_VFX_ILBM_palette             equ TRUE
                do_VFX_ILBM_resolution          equ TRUE
                do_VFX_PCX_draw                 equ TRUE
                do_VFX_PCX_palette              equ TRUE
                do_VFX_PCX_resolution           equ TRUE
                do_VFX_GIF_draw                 equ TRUE
                do_VFX_GIF_palette              equ TRUE
                do_VFX_GIF_resolution           equ TRUE
                do_VFX_shape_bounds             equ TRUE
                do_VFX_shape_origin             equ TRUE
                do_VFX_shape_resolution         equ TRUE
                do_VFX_shape_minxy              equ TRUE
                do_VFX_shape_palette            equ TRUE
                do_VFX_shape_colors             equ TRUE
                do_VFX_shape_set_colors         equ TRUE
                do_VFX_shape_count              equ TRUE
                do_VFX_shape_list               equ TRUE
                do_VFX_shape_palette_list       equ TRUE
                do_VFX_color_scan               equ TRUE

                ;
                ;Equates to enable assembly of various polygon primitives
                ;Unused routines may be disabled to conserve space
                ;

F_POLY          equ TRUE                ;VFX_flat_polygon()
G_POLY          equ TRUE                ;VFX_Gouraud_polygon()
DG_POLY         equ TRUE                ;VFX_dithered_Gouraud_polygon()
M_POLY          equ TRUE                ;VFX_map_polygon()
X_POLY          equ TRUE                ;VFX_translate_polygon()
I_POLY          equ TRUE                ;VFX_illuminate_polygon()

                .DATA

;
; Clipping equates and variables
;

LEFTOF          equ     1000B
RIGHTOF         equ     0100B
ABOVE           equ     0010B
BELOW           equ     0001B

;
;VFX_pane_scroll equates
;

NOFILL          equ     -1

;
;Loop-unrolling extent for VFX_line_draw()
;

LD_COPIES       equ     4

;
;VFX_shape_scan equates and variables
;

INIT_           equ     0
STRING_         equ     1
RUN_            equ     2
SKIP_           equ     3
END_            equ     4
NONE_           equ     5

SHP_building    dd      ?  ;true if building shape, false if calc'ing buffer size
SHP_skipCount   dd      ?  ;keeps track of skipped pixels

SHP_LinePtr     dd      ?  ;marks start of current line
SHP_ScanPtr     dd      ?  ;scans current line
SHP_ShapePtr    dd      ?  ;writes shape data
SHP_FlushPtr    dd      ?  ;lags SHP_ShapePtr, used to flush completed packets

SHP_CP_L        dd      ?  ;coordinates of input pane after window clipping
SHP_CP_T        dd      ?
SHP_CP_R        dd      ?
SHP_CP_B        dd      ?

SHP_minX        dd      ?  ;coordinates of shape rectangle
SHP_minY        dd      ?
SHP_maxX        dd      ?
SHP_maxY        dd      ?

;
; VFX_draw_LBM|PCX|GIF & VFX_window_fade & VFX_pixel_fade buffers 
;

src_ytable      LABEL DWORD                     ;Needs 1 DWORD for every line
  temp_bufferA   dd 320 dup (0)                  
BM_line_buffer  LABEL BYTE                      ;1024 bytes
 color_buffer    LABEL BYTE                     ;768 bytes
  temp_buffer0   db 256 dup (0)                  
  temp_buffer1   db 256 dup (0)                  
  temp_buffer2   db 256 dup (0)                  
 color_list      LABEL BYTE                     ;256 bytes
  temp_buffer3   db 256 dup (0)                  
 color_delta     LABEL BYTE                     ;768 bytes
  temp_buffer4   db 256 dup (0)                  
  temp_buffer5   db 256 dup (0)                  
  temp_buffer6   db 256 dup (0)                  

dest_ytable     LABEL DWORD                     ;Needs 1 DWORD for every line
  temp_buffer7   dd 384 dup (0)                  
LBM_line_buffer LABEL BYTE                      ;1024 bytes
 color_sb        LABEL BYTE                     ;768 bytes
 color_vector    LABEL BYTE                     ;768 bytes
  temp_buffer10  db 256 dup (0)                  
  temp_buffer11  db 256 dup (0)                  
  temp_buffer12  db 256 dup (0)                  
 color_error     LABEL BYTE                     ;768 bytes
  temp_buffer13  db 256 dup (0)                  
  temp_buffer14  db 256 dup (0)                  
  temp_buffer15  db 256 dup (0)                  

GIF_cmask       db 0,1,3,7,0fh,1fh,3fh,7fh,0ffh
GIF_inctable    db 8,8,4,2,0
GIF_starttable  db 0,4,2,1,0
GIF_pane        dd ?                            ;Pane address 

GIF_scratch     db GIF_SCRATCH_SIZE dup (?)

                ALIGN 4
lookaside       db 256 dup (?)                  ;Color xlat table for shapes

                ;
                ;These can't be locals due to EBP preemption
                ;

loop_entry      dd ?                            
dither_1        dd ?
dither_2        dd ?
skip_first      dd ?
line_end        dd ?
ebp_save        dd ?

                ;
                ;Used by VFX_shape_transform / VFX_shape_area_translate
                ;

VERTEX2D        STRUC
vx              dd ?    ;Vertex destination X
vy              dd ?    ;Vertex destination Y
vc              dd ?    ;Vertex color

u               dd ?    ;Source texture X
v               dd ?    ;Source texture Y
VERTEX2D        ENDS

PVERTEX2D       TYPEDEF PTR VERTEX2D

vert0           VERTEX2D <>
vert1           VERTEX2D <>
vert2           VERTEX2D <>
vert3           VERTEX2D <>

                ;
                ;Index offset table used by affine-mapping primitives
                ;

UV_step         dd 4 dup (?)

                .CODE   

;----------------------------------------------------------------------------
;
; int cdecl VFX_pixel_write (PANE *panep, int x, int y, UBYTE color)
;
;     This function writes a single pixel.
;
; The panep parameter specifies the pane containing the pixel to be written.
; The x and y parameters specify the pixel coordinates.
; The color parameter specifies the color to write to the pixel.
;                                          
; Return values:
;
;    0..255:
;       Pixel value prior to write.
;
;   -1: Bad window.
;       The height or width of the pane's window is less than one.
;
;   -2: Bad pane.
;       The height or width of the pane is less than one.
;
;   -3: Off pane.
;       The specified pixel is off the pane.
;                                          
;----------------------------------------------------------------------------

                IF do_VFX_pixel_write

VFX_pixel_write PROC STDCALL USES ebx esi edi es,\
                panep:PPANE,x:S32,y:S32,color:U32

                LOCAL    CP_L   ;Leftmost pixel in Window coord.
                LOCAL    CP_T   ;Top
                LOCAL    CP_R   ;Right
                LOCAL    CP_B   ;Bottom
              
                LOCAL    CP_A   ;Base address of Clipped Pane
                LOCAL    CP_BW  ;Width of underlying window (bytes)
                LOCAL    CP_W   ;Width of underlying window (pixels)
                
                LOCAL    CP_CX  ;Window x coord. = Pane x coord. + CP_CX
                LOCAL    CP_CY  ;Window y coord. = Pane x coord. + CP_CY

                LOCAL    pixel_pitch
                LOCAL    bytes_per_pixel

                cld
                push ds
                pop es

                GET_COLOR color

                CLIP_PANE_TO_WINDOW     panep

        ; transform x & y to window coord's

                mov     ecx,x
                mov     ebx,y

                CONVERT_REG_PAIR_PANE_TO_WINDOW ecx, ebx

        ; clip pixel to pane
    
                cmp     ecx,CP_L
                jl      ReturnOffPane
                cmp     ecx,CP_R
                jg      ReturnOffPane
                cmp     ebx,CP_T
                jl      ReturnOffPane
                cmp     ebx,CP_B
                jg      ReturnOffPane
    
        ; adr (ebx) = window->buffer + CP_W * y + x

                GET_WINDOW_ADDRESS ecx, ebx
                mov     ebx,eax

        ; prior_value = [adr]

                xor     eax,eax
                mov     al,[ebx]

        ; write the pixel

                mov     dl,BYTE PTR color
                mov     [ebx],dl

        ; return prior_value

                ret

        ; error returns

ReturnOffPane:
                mov     eax,-3
                ret

VFX_pixel_write \
                ENDP

                ENDIF


;----------------------------------------------------------------------------
;
; int cdecl VFX_pixel_read (PANE *panep, int x, int y)
;
;     This function reads a single pixel.
;
; The panep parameter specifies the pane containing the pixel to be written.
; The x and y parameters specify the pixel coordinates.
;                                          
; Return values:
;
;    0..255:
;       Pixel value.
;
;   -1: Bad window.
;       The height or width of the pane's window is less than one.
;
;   -2: Bad pane.
;       The height or width of the pane is less than one.
;
;   -3: Off pane.
;       The specified pixel is off the pane.
;                                          
;----------------------------------------------------------------------------

                IF do_VFX_pixel_read

VFX_pixel_read PROC STDCALL USES ebx esi edi es,\
                panep:PPANE,x:S32,y:S32
    
                LOCAL    CP_L   ;Leftmost pixel in Window coord.
                LOCAL    CP_T   ;Top
                LOCAL    CP_R   ;Right
                LOCAL    CP_B   ;Bottom
              
                LOCAL    CP_A   ;Base address of Clipped Pane
                LOCAL    CP_BW  ;Width of underlying window (bytes)
                LOCAL    CP_W   ;Width of underlying window (pixels)
                
                LOCAL    CP_CX  ;Window x coord. = Pane x coord. + CP_CX
                LOCAL    CP_CY  ;Window y coord. = Pane x coord. + CP_CY

                LOCAL    pixel_pitch
                LOCAL    bytes_per_pixel

                cld
                push ds
                pop es

                CLIP_PANE_TO_WINDOW     panep

        ; transform x & y to window coord's

                mov     ecx,x
                mov     ebx,y

                CONVERT_REG_PAIR_PANE_TO_WINDOW ecx, ebx
   
        ; clip pixel to pane
    
                cmp     ecx,CP_L
                jl      ReturnOffPane
                cmp     ecx,CP_R
                jg      ReturnOffPane
                cmp     ebx,CP_T
                jl      ReturnOffPane
                cmp     ebx,CP_B
                jg      ReturnOffPane

        ; adr (ebx) = window->buffer + CP_W * y + x

                GET_WINDOW_ADDRESS ecx, ebx
                mov     ebx,eax

        ; read and return the pixel
    
                xor     eax,eax
                mov     al,[ebx]
                ret

; error returns

ReturnOffPane:
                mov     eax,-3
                ret

VFX_pixel_read \
                ENDP

                ENDIF

;----------------------------------------------------------------------------
;
; int cdecl VFX_line_draw (PANE *panep, int x0, int y0, int x1, int y1,
;                                                   int mode, int parm);
;
; This function clips and draws a line to a pane.
;
; The panep parameter specifies the pane.
;
; The x0 and y0 parameters specify the initial endpoint of the line.
; The x1 and y1 parameters specify the final endpoint of the line.
;
; The mode parameter specifies the operation to perform on each point
; in the line.
;
; If mode is...   parm specifies...
;
;   DRAW            a color
;   TRANSLATE       the address of a color translation table
;   EXECUTE         the address of a caller-provided function
;
; If mode is DRAW (0), the line is drawn in a solid color specified by 
; parm. 
;
; If mode is TRANSLATE (1), the line is drawn with color translation. 
; Each pixel along the path of the line is replaced with the correspond-
; ing entry in the color translation table specified by parm.
;
; If mode is EXECUTE (2), the line is drawn with the aid of a callback 
; function specifed by parm.  For each point on the line, VFX_line_draw() 
; executes the callback function, passing it the coordinates of the point.
;
; The callback function must use cdecl parameter passing, and its para-
; meter list must be (int x, int y).  The function's return type is not
; important; VFX_line_draw() ignores the return value (if any).  
;
; VFX_line_draw() clips the line to the pane.  The locus of the clipped 
; line is the same for all modes and is guaranteed to be identical to the 
; intersection of the loci of the unclipped line and the pane.  Moreover, 
; plotting always proceeds from (x0,y0) to (x1,y1) regardless of the 
; relative orientation of the two points.
;
; The locus of the clipped line consists of all points in the pane whose 
; minor-axis distance* from the ideal line is less than or equal to 1/2,
; with the following exception.  In places where the ideal line passes 
; exactly halfway between two pixels which share the same major-axis co-
; ordinate, only one of the two points is plotted.  The selection method 
; is unspecified, but is consistent throughout the line.
;
; * The minor-axis distance from a point P to a line L is the absolute 
;   difference between the minor-axis coordinates of P and Q where Q is
;   the point on L having the same major-axis coordinate as P.  (Here,
;   major-axis and minor axis are determined by L.  The major axis is
;   the axis in which the endpoints of L differ the most.  Likewise the
;   minor-axis is the one in which the endpoints differ the least).
;
; VFX_line_draw is reentrant, so callback functions can use it.
;
;
; Examples:
;
;    #define HELIOTROPE 147
;    UBYTE color_negative[256];
;    void cdecl DrawDiamond (int x, int y);
;
;    VFX_line_draw (pane, Px, Py, Qx, Qy, DRAW, HELIOTROPE);
;       draws a line from (Px,Py) to (Qx,Qy) using the color HELIOTROPE.
;
;    VFX_line_draw (pane, Px, Py, Qx, Qy, TRANSLATE, (int) color_negative);
;       draws a line from (Px,Py) to (Qx,Qy) replacing each pixel with its
;       color negative (as specified by the table color_negative).
;
;    VFX_line_draw (pane, Px, Py, Qx, Qy, EXECUTE, (int) DrawDiamond);
;       draws a line of diamonds from (Px,Py) to (Qx,Qy) using the
;       caller-provided function DrawDiamond().
;
; Return values:
;
;   -2: pane was malformed or completely outside its window
;   -1: window was malformed
;    0: all of the line was inside the pane and was drawn without clipping
;    1: some of the line was inside the pane and was drawn after clipping
;    2: the line was completely outside the pane and was not drawn
;
;----------------------------------------------------------------------------

                IF do_VFX_line_draw

VFX_line_draw PROC STDCALL USES ebx esi edi es,\
                panep:PPANE, x0:S32, y0:S32, x1:S32, y1:S32, mode:S32, parm:U32
                        
                LOCAL _dx, absdx, sgndx
                LOCAL _dy, absdy, sgndy
                LOCAL sgndxdy, slope
                LOCAL x0_, y0_, x1_, y1_
                LOCAL clip_flags
                LOCAL adr:PBYTE
    
                LOCAL    CP_L   ;Leftmost pixel in Window coord.
                LOCAL    CP_T   ;Top
                LOCAL    CP_R   ;Right
                LOCAL    CP_B   ;Bottom
              
                LOCAL    CP_A   ;Base address of Clipped Pane
                LOCAL    CP_BW  ;Width of underlying window (bytes)
                LOCAL    CP_W   ;Width of underlying window (pixels)
                
                LOCAL    CP_CX  ;Window x coord. = Pane x coord. + CP_CX
                LOCAL    CP_CY  ;Window y coord. = Pane x coord. + CP_CY

                LOCAL    pixel_pitch
                LOCAL    bytes_per_pixel

                cld
                push ds
                pop es

                CLIP_PANE_TO_WINDOW     panep

                ASSUME  esi:PPANE

        ; transform endpoints from pane to window coords:

                CONVERT_QUAD_PANE_TO_WINDOW x0,y0,x1,y1

        ; calculate dx, absdx, and sgndx
    
                mov     eax,x1
                sub     eax,x0
                mov     _dx,eax
    
                cdq
                mov     sgndx,edx
    
                xor     eax,edx
                sub     eax,edx
                mov     absdx,eax

        ; calculate dy, absdy, and sgndy
    
                mov     eax,y1
                sub     eax,y0
                mov     _dy,eax
    
                cdq
                mov     sgndy,edx
    
                xor     eax,edx
                sub     eax,edx
                mov     absdy,eax

        ; make working copies of endpoint coordinates

                MOVE    x0_,eax,x0
                MOVE    x1_,eax,x1
                MOVE    y0_,eax,y0
                MOVE    y1_,eax,y1
    
        ; handle special cases -- vertical, horizontal
    
                cmp     _dx,0
                je      Vertical
    
                cmp     _dy,0
                je      Horizontal
    
        ; calculate sgndxdy
    
                mov     eax,sgndx
                xor     eax,sgndy
                mov     sgndxdy,eax

        ; calculate slope
    
                mov     edx,absdx
                mov     ebx,absdy
                mov     eax,0FFFFFFFFH
    
                cmp     edx,ebx
                je      slope2
                jl      slope1
    
                xchg    edx,ebx
slope1:
                xor     eax,eax
                div     ebx

slope2:
                mov     slope,eax

        ; clip line to pane

                mov     clip_flags,0

clip_loop:
                xor     edx,edx

        ; calculate clip0 (dl)
    
                mov     eax,x0_
                sub     eax,CP_L
                shl     eax,1
                adc     dl,dl
    
                mov     eax,CP_R
                sub     eax,x0_
                shl     eax,1
                adc     dl,dl
    
                mov     eax,y0_
                sub     eax,CP_T
                shl     eax,1
                adc     dl,dl
    
                mov     eax,CP_B
                sub     eax,y0_
                shl     eax,1
                adc     dl,dl

        ; calculate clip1 (dh)

                mov     eax,x1_
                sub     eax,CP_L
                shl     eax,1
                adc     dh,dh
    
                mov     eax,CP_R
                sub     eax,x1_
                shl     eax,1
                adc     dh,dh
    
                mov     eax,y1_
                sub     eax,CP_T
                shl     eax,1
                adc     dh,dh
    
                mov     eax,CP_B
                sub     eax,y1_
                shl     eax,1
                adc     dh,dh

        ; remember clip flags for final return value

                or      clip_flags,edx

        ; accept if line is completely in the pane

                or      edx,edx
                jz      Accept

        ; reject if line is completely above, below, left of, or right of the pane

                test    dl,dh
                jnz     ReturnReject


        ; dispatch to appropriate clipper
    
                mov     ebx,absdx
                cmp     ebx,absdy
                jl      ClipYmajor

ClipXmajor:

        ; clip (x0,y0)

                test    dl,1000B
                jnz     Xmaj_x0_lo
                test    dl,0100B
                jnz     Xmaj_x0_hi
                test    dl,0010B
                jnz     Xmaj_y0_lo
                test    dl,0001B
                jnz     Xmaj_y0_hi

        ; clip (x1,y1)

                test    dh,1000B
                jnz     Xmaj_x1_lo
                test    dh,0100B
                jnz     Xmaj_x1_hi
                test    dh,0010B
                jnz     Xmaj_y1_lo
                test    dh,0001B
                jnz     Xmaj_y1_hi
    
                jmp     clip_loop

ClipYmajor:

        ; clip (x0,y0)

                test    dl,1000B
                jnz     Ymaj_x0_lo
                test    dl,0100B
                jnz     Ymaj_x0_hi
                test    dl,0010B
                jnz     Ymaj_y0_lo
                test    dl,0001B
                jnz     Ymaj_y0_hi

        ; clip (x1,y1)

                test    dh,1000B
                jnz     Ymaj_x1_lo
                test    dh,0100B
                jnz     Ymaj_x1_hi
                test    dh,0010B
                jnz     Ymaj_y1_lo
                test    dh,0001B
                jnz     Ymaj_y1_hi
    
                jmp     clip_loop

Xmaj_x0_lo:

        ; x0_ = CP_L;
        ; y0_ = y0 + sgndxdy * floor ((x0_-x0)*slope)+1/2);
    
                MOVE    x0_,eax,CP_L
                sub     eax,x0
    
                mul     slope
                add     eax,ONE_HALF
                adc     edx,0
                mov     eax,edx
    
                mov     edx,sgndxdy
    
                xor     eax,edx
                sub     eax,edx
    
                add     eax,y0
                mov     y0_,eax
    
                jmp     clip_loop

Ymaj_x0_lo:

        ; x0_ = CP_L;
        ; y0_ = y0 + sgndxdy * ceil ((x0_-x0-1/2)/slope);
    
                MOVE    x0_,eax,CP_L
                sub     eax,x0
    
                mov     edx,eax
                dec     edx
                mov     eax,ONE_HALF
                div     slope
    
                cmp     edx,1
                sbb     eax,-1
    
                mov     edx,sgndxdy
    
                xor     eax,edx
                sub     eax,edx
    
                add     eax,y0
                mov     y0_,eax
    
                jmp     clip_loop
    
Xmaj_x0_hi:

        ; x0_ = CP_R;
        ; y0_ = y0 - sgndxdy * floor ((x0-CP_R)*slope)+1/2);

                MOVE    x0_,eax,CP_R
                sub     eax,x0
                neg     eax
    
                mul     slope
                add     eax,ONE_HALF
                adc     edx,0
                mov     eax,edx
    
                mov     edx,sgndxdy
                not     edx
    
                xor     eax,edx
                sub     eax,edx
    
                add     eax,y0
                mov     y0_,eax
    
                jmp     clip_loop
    
Ymaj_x0_hi:

        ; x0_ = CP_R;
        ; y0_ = y0 - sgndxdy * ceil ((x0-x0_-1/2)/slope);

                MOVE    x0_,eax,CP_R
                sub     eax,x0
                neg     eax
    
                mov     edx,eax
                dec     edx
                mov     eax,ONE_HALF
                div     slope
    
                cmp     edx,1
                sbb     eax,-1
    
                mov     edx,sgndxdy
                not     edx
    
                xor     eax,edx
                sub     eax,edx
    
                add     eax,y0
                mov     y0_,eax
    
                jmp     clip_loop

Ymaj_y0_lo:

        ; y0_ = CP_T;
        ; x0_ = x0 + sgndxdy * floor ((y0_-y0)*slope)+1/2);

                MOVE    y0_,eax,CP_T
                sub     eax,y0
    
                mul     slope
                add     eax,ONE_HALF
                adc     edx,0
                mov     eax,edx
    
                mov     edx,sgndxdy
    
                xor     eax,edx
                sub     eax,edx
    
                add     eax,x0
                mov     x0_,eax
    
                jmp     clip_loop
    
Xmaj_y0_lo:

        ; y0_ = CP_T;
        ; x0_ = x0 + sgndxdy * ceil ((y0_-y0-1/2)/slope);
    
                MOVE    y0_,eax,CP_T
                sub     eax,y0
    
                mov     edx,eax
                dec     edx
                mov     eax,ONE_HALF
                div     slope
    
                cmp     edx,1
                sbb     eax,-1
    
                mov     edx,sgndxdy
    
                xor     eax,edx
                sub     eax,edx
    
                add     eax,x0
                mov     x0_,eax
    
                jmp     clip_loop

Ymaj_y0_hi:

        ; y0_ = CP_B;
        ; x0_ = x0 - sgndxdy * floor ((y0-y0_)*slope+1/2);

                MOVE    y0_,eax,CP_B
                sub     eax,y0
                neg     eax
    
                mul     slope
                add     eax,ONE_HALF
                adc     edx,0
                mov     eax,edx
    
                mov     edx,sgndxdy
                not     edx
    
                xor     eax,edx
                sub     eax,edx
    
                add     eax,x0
                mov     x0_,eax
    
                jmp     clip_loop

Xmaj_y0_hi:

        ; y0_ = CP_B;
        ; x0_ = x0 - sgndxdy * ceil ((y0-y0_-1/2)/slope);
    
                MOVE    y0_,eax,CP_B
                sub     eax,y0
                neg     eax
    
                mov     edx,eax
                dec     edx
                mov     eax,ONE_HALF
                div     slope
    
                cmp     edx,1
                sbb     eax,-1
    
                mov     edx,sgndxdy
                not     edx
    
                xor     eax,edx
                sub     eax,edx
    
                add     eax,x0
                mov     x0_,eax
    
                jmp     clip_loop

Xmaj_x1_lo:

        ; x1_ = CP_L;
        ; y1_ = y0 - sgndxdy * floor ((x0-x1_)*slope+1/2);

                MOVE    x1_,eax,CP_L
                sub     eax,x0
                neg     eax
    
                mul     slope
                add     eax,ONE_HALF
                adc     edx,0
                mov     eax,edx
    
                mov     edx,sgndxdy
                not     edx
    
                xor     eax,edx
                sub     eax,edx
    
                add     eax,y0
                mov     y1_,eax
    
                jmp     clip_loop

Ymaj_x1_lo:

        ; x1_ = CP_L;
        ; y1_ = y0 - sgndxdy * (ceil ((x0-x1_+1/2)/slope) - 1);

                MOVE    x1_,eax,CP_L
                sub     eax,x0
                neg     eax
    
                mov     edx,eax
                mov     eax,ONE_HALF
                div     slope
    
                cmp     edx,1
                sbb     eax,0
    
                mov     edx,sgndxdy
                not     edx
    
                xor     eax,edx
                sub     eax,edx
    
                add     eax,y0
                mov     y1_,eax
    
                jmp     clip_loop

Xmaj_x1_hi:

        ; x1_ = CP_R;
        ; y1_ = y0 + sgndxdy * floor ((x1_-x0)*slope+1/2);
    
                MOVE    x1_,eax,CP_R
                sub     eax,x0
    
                mul     slope
                add     eax,ONE_HALF
                adc     edx,0
                mov     eax,edx
    
                mov     edx,sgndxdy
    
                xor     eax,edx
                sub     eax,edx
    
                add     eax,y0
                mov     y1_,eax
    
                jmp     clip_loop

Ymaj_x1_hi:

        ; x1_ = CP_R;
        ; y1_ = y0 + sgndxdy * (ceil ((x1_-x0+1/2)/slope) - 1);

                MOVE    x1_,eax,CP_R
                sub     eax,x0
    
                mov     edx,eax
                mov     eax,ONE_HALF
                div     slope
    
                cmp     edx,1
                sbb     eax,0
    
                mov     edx,sgndxdy
    
                xor     eax,edx
                sub     eax,edx
    
                add     eax,y0
                mov     y1_,eax
    
                jmp     clip_loop

Ymaj_y1_lo:

        ; y1_ = CP_T;
        ; x1_ = x0 - sgndxdy * floor ((y0-y1_)*slope+1/2);

                MOVE    y1_,eax,CP_T
                sub     eax,y0
                neg     eax
    
                mul     slope
                add     eax,ONE_HALF
                adc     edx,0
                mov     eax,edx
    
                mov     edx,sgndxdy
                not     edx
    
                xor     eax,edx
                sub     eax,edx
    
                add     eax,x0
                mov     x1_,eax
    
                jmp     clip_loop

Xmaj_y1_lo:

        ; y1_ = CP_T;
        ; x1_ = x0 - sgndxdy * (ceil ((y0-y1_+1/2)/slope) - 1);
    
                MOVE    y1_,eax,CP_T
                sub     eax,y0
                neg     eax
    
                mov     edx,eax
                mov     eax,ONE_HALF
                div     slope
    
                cmp     edx,1
                sbb     eax,0
    
                mov     edx,sgndxdy
                not     edx
    
                xor     eax,edx
                sub     eax,edx
    
                add     eax,x0
                mov     x1_,eax
    
                jmp     clip_loop
    
Ymaj_y1_hi:

        ; y1_ = CP_B;
        ; x1_ = x0 + sgndxdy * floor ((y1_-y0)*slope+1/2);

                MOVE    y1_,eax,CP_B
                sub     eax,y0
    
                mul     slope
                add     eax,ONE_HALF
                adc     edx,0
                mov     eax,edx
    
                mov     edx,sgndxdy
    
                xor     eax,edx
                sub     eax,edx
    
                add     eax,x0
                mov     x1_,eax
    
                jmp     clip_loop

Xmaj_y1_hi:

        ; y1_ = CP_B;
        ; x1_ = x0 + sgndxdy * (ceil ((y1_-y0+1/2)/slope) - 1);

                MOVE    y1_,eax,CP_B
                sub     eax,y0
    
                mov     edx,eax
                mov     eax,ONE_HALF
                div     slope
    
                cmp     edx,1
                sbb     eax,0
    
                mov     edx,sgndxdy
    
                xor     eax,edx
                sub     eax,edx
    
                add     eax,x0
                mov     x1_,eax
    
                jmp     clip_loop

;----------------------------------------------------------------------------
;
; Macros for inner loops of DRAW forms (Y major, X major, and Straight)
;
;----------------------------------------------------------------------------

YM_DRAW     MACRO   adc_sbb

            mov     [edi],al            ; [adr] = pixel

            add     edx,ebx             ; accum += slope
            adc_sbb edi,esi             ; adr += ystep (+ xstep)
            dec     ecx                 ; count--

            ENDM

;----------------------------------------------------------------------------
XM_DRAW     MACRO   inc_dec

            mov     [edi],al            ; [adr] = pixel

            inc_dec edi                 ; adr += xstep
            add     edx,ebx             ; accum += slope
            jnc     @F                  ; if accum overflowed,
            add     edi,esi             ;   adr += ystep
@@:
            dec     ecx                 ; count--

            ENDM

;----------------------------------------------------------------------------
ST_DRAW     MACRO

            mov     [edi],al            ; [adr] = pixel

            add     edi,esi             ; adr += xystep
            dec     ecx                 ; count--

            ENDM

;----------------------------------------------------------------------------
;
; Macros for inner loops of XLAT forms (Y major, X major, and Straight)
;

;----------------------------------------------------------------------------
YM_XLAT     MACRO   adc_sbb

            mov     al,[edi]            ; pixel = [adr]
            xlat                        ; pixel = parm[pixel]
            mov     [edi],al            ; [adr] = pixel

            add     edx,ebp             ; accum += slope
            adc_sbb edi,esi             ; adr += ystep (+ xstep)
            dec     ecx                 ; count--

            ENDM

;----------------------------------------------------------------------------
XM_XLAT     MACRO   inc_dec

            mov     al,[edi]            ; pixel = [adr]
            xlat                        ; pixel = parm[pixel]
            mov     [edi],al            ; [adr] = pixel

            inc_dec edi                 ; adr += xstep
            add     edx,ebp             ; accum += slope
            jnc     @F                  ; if accum overflowed,
            add     edi,esi             ;   adr += ystep
@@:
            dec     ecx                 ; count--

            ENDM

;----------------------------------------------------------------------------
SW_XLAT     MACRO

            mov     al,[edi]            ; pixel = [adr]
            xlat                        ; pixel = parm[pixel]
            mov     [edi],al            ; [adr] = pixel

            add     edi,esi             ; adr += xystep
            dec     ecx                 ; count--

            ENDM

;----------------------------------------------------------------------------

Accept:

        ; calculate adr (edi),
        ; address of first pixel = window_buffer + CP_W*y0 + x0

            GET_WINDOW_ADDRESS  x0_, y0_
            mov     edi,eax

        ; calculate ystep (esi) = CP_W * sgn (dy)

            mov     esi,CP_W
            xor     esi,sgndy
            sub     esi,sgndy

        ; get slope

            mov     ebx,slope

        ; branch to Diagonal, Xmajor or Ymajor depending on absdx & absdy

            mov     eax,absdx
            cmp     eax,absdy
            je      Diagonal
            jg      Xmajor

;----------------------------------------------------------------------------
Ymajor:     

        ; calculate count (ecx) = abs (y1_ - y0_) + 1

            mov     eax,y1_
            sub     eax,y0_
            cdq
            xor     eax,edx
            sub     eax,edx
            inc     eax
            mov     ecx,eax

        ; calculate accum (edx) = abs (y0_ - y0) * slope + 1/2

            mov     eax,y0_
            sub     eax,y0
            cdq
            xor     eax,edx
            sub     eax,edx

            mul     ebx
            add     eax,ONE_HALF
            mov     edx,eax

        ; branch to YmajorNegdx or fall through to YmajorPosdx depending on sgndx

            cmp     sgndx,-1
            je      YmajorNegdx

;----------------------------------------------------------------------------
YmajorPosdx:
            cmp     mode,1
            je      YmPdxXlat
            jg      YmPdxProc

;----------------------------------------------------------------------------
YmPdxDraw:
            GET_COLOR parm
            mov eax,parm

YmPdxDrawLoop:
            REPEAT  LD_COPIES-1         ; repeat this code copies-1 times
            YM_DRAW <adc>               ;   process a pixel
            jz      YmPdxDrawDone
            ENDM

            YM_DRAW <adc>               ; process another pixel
            jnz     YmPdxDrawLoop       ; while (count)

YmPdxDrawDone:
            jmp     ReturnClipFlags     ; done

;----------------------------------------------------------------------------
YmPdxXlat:
            mov     eax,parm            ; get translation table pointer
            push    ebp                 ; preserve ebp
            mov     ebp,ebx             ; use ebp for slope to free up ebx
            mov     ebx,eax             ; table ptr must be in ebx for xlat

YmPdxXlatLoop:
            REPEAT  LD_COPIES-1         ; repeat this code copies-1 times
            YM_XLAT <adc>               ;   process a pixel
            jz      YmPdxXlatDone
            ENDM

            YM_XLAT <adc>               ; process a pixel
            jnz     YmPdxXlatLoop       ; while (count)

YmPdxXlatDone:
            pop     ebp                 ; restore ebp
            jmp     ReturnClipFlags     ; done

;----------------------------------------------------------------------------
YmPdxProc:
            mov     esi,panep           ; get pane pointer

            mov     edi,x0_             ; x (edi) = x0_ in pane coordinates
            sub     edi,[esi].x0

            mov     eax,y0_             ; y (esi) = y0_ in pane coordinates
            sub     eax,[esi].y0
            mov     esi,eax

            mov     eax,sgndy           ; ybump (eax) = (sgndy=-1) ? -1 : +1
            add     eax,eax
            inc     eax

YmPdxProcLoop:
            pushad                      ; callback (x, y)
            call    parm
            popad

            add     edx,ebx             ; accum += slope
            jnc     @F                  ; if overflow, x++
            inc     edi
@@:
            add     esi,eax             ; y += ybump

            dec     ecx                 ; count--
            jnz     YmPdxProcLoop       ; while (count)

            jmp     ReturnClipFlags     ; done

;----------------------------------------------------------------------------
YmajorNegdx:
            neg     esi                 ; neg_ystep (esi) = -ystep

            cmp     mode,1
            je      YmNdxXlat
            jg      YmNdxProc

;----------------------------------------------------------------------------
YmNdxDraw:
            GET_COLOR parm
            mov     eax,parm            ; get line color

YmNdxDrawLoop:
            REPEAT  LD_COPIES-1         ; repeat this code copies-1 times
            YM_DRAW <sbb>               ;   process a pixel
            jz      YmNdxDrawDone
            ENDM

            YM_DRAW <sbb>               ; process a pixel
            jnz     YmNdxDrawLoop       ; while (count)

YmNdxDrawDone:
            jmp     ReturnClipFlags     ; done

;----------------------------------------------------------------------------
YmNdxXlat:
            mov     eax,parm            ; get translation table pointer
            push    ebp                 ; preserve ebp
            mov     ebp,ebx             ; use ebp for slope to free up ebx
            mov     ebx,eax             ; table ptr must be in ebx for xlat

YmNdxXlatLoop:
            REPEAT  LD_COPIES-1         ; repeat this code copies-1 times
            YM_XLAT <sbb>               ;   process a pixel
            jz      YmNdxXlatDone
            ENDM

            YM_XLAT <sbb>               ; process a pixel
            jnz     YmNdxXlatLoop       ; while (count)

YmNdxXlatDone:
            pop     ebp                 ; restore ebp
            jmp     ReturnClipFlags     ; done

;----------------------------------------------------------------------------
YmNdxProc:
            mov     esi,panep           ; get pane pointer

            mov     edi,x0_             ; x (edi) = x0_ in pane coordinates
            sub     edi,[esi].x0

            mov     eax,y0_             ; y (esi) = y0_ in pane coordinates
            sub     eax,[esi].y0
            mov     esi,eax

            mov     eax,sgndy           ; ybump (eax) = (sgndy=-1) ? -1 : +1
            add     eax,eax
            inc     eax

YmNdxProcLoop:
            pushad                      ; callback (x, y)
            call    parm
            popad

            add     edx,ebx             ; accum += slope
            jnc     @F                  ; if overflow, x--
            dec     edi
@@:
            add     esi,eax             ; y += ybump

            dec     ecx                 ; count--
            jnz     YmNdxProcLoop       ; while (count)

            jmp     ReturnClipFlags     ; done

;----------------------------------------------------------------------------
Xmajor:

        ; calculate count (ecx) = abs (x1_ - x0_) + 1

            mov     eax,x1_
            sub     eax,x0_
            cdq
            xor     eax,edx
            sub     eax,edx
            inc     eax
            mov     ecx,eax

        ; calculate accum (edx) = abs (x0_ - x0) * slope + 1/2

            mov     eax,x0_
            sub     eax,x0
            cdq
            xor     eax,edx
            sub     eax,edx

            mul     ebx
            add     eax,ONE_HALF
            mov     edx,eax

        ; branch to XmajorNegdx or fall through to XmajorPosdx depending on sgndx

            cmp     sgndx,-1
            je      XmajorNegdx

;----------------------------------------------------------------------------
XmajorPosdx:
            cmp     mode,1
            je      XmPdxXlat
            jg      XmPdxProc

;----------------------------------------------------------------------------
XmPdxDraw:
            GET_COLOR parm
            mov     eax,parm            ; get line color
            
XmPdxDrawLoop:
            REPEAT  LD_COPIES-1         ; repeat this code copies-1 times
            XM_DRAW <inc>               ;    process a pixel
            jz      XmPdxDrawDone
            ENDM

            XM_DRAW <inc>               ; process another pixel
            jnz     XmPdxDrawLoop       ; while (count)

XmPdxDrawDone:
            jmp     ReturnClipFlags     ; done

;----------------------------------------------------------------------------
XmPdxXlat:
            mov     eax,parm            ; get translation table pointer
            push    ebp                 ; preserve ebp
            mov     ebp,ebx             ; use ebp for slope to free up ebx
            mov     ebx,eax             ; table ptr must be in ebx for xlat

XmPdxXlatLoop:
            REPEAT  LD_COPIES-1         ; repeat this code copies-1 times
            XM_XLAT <inc>               ;    process a pixel
            jz      XmPdxXlatDone
            ENDM

            XM_XLAT <inc>               ; process another pixel
            jnz     XmPdxXlatLoop       ; while (count)

XmPdxXlatDone:
            pop     ebp                 ; restore ebp
            jmp     ReturnClipFlags     ; done

;----------------------------------------------------------------------------
XmPdxProc:
            mov     esi,panep           ; get pane pointer

            mov     edi,x0_             ; x (edi) = x0_ in pane coordinates
            sub     edi,[esi].x0

            mov     eax,y0_             ; y (esi) = y0_ in pane coordinates
            sub     eax,[esi].y0
            mov     esi,eax

            mov     eax,sgndy           ; xbump (eax) = (sgndy=-1) ? -1 : +1
            add     eax,eax
            inc     eax

XmPdxProcLoop:
            pushad                      ; callback (x, y)
            call    parm
            popad

            add     edx,ebx             ; accum += slope
            jnc     @F                  ; if overflow, y++
            add     esi,eax
@@:         
            inc edi

            dec     ecx                 ; count--
            jnz     XmPdxProcLoop       ; while (count)

            jmp     ReturnClipFlags     ; done

;----------------------------------------------------------------------------
XmajorNegdx:
            cmp     mode,1
            je      XmNdxXlat
            jg      XmNdxProc

;----------------------------------------------------------------------------
XmNdxDraw:
            GET_COLOR parm
            mov     eax,parm            ; get line color
            
XmNdxDrawLoop:
            REPEAT  LD_COPIES-1         ; repeat this code copies-1 times
            XM_DRAW <dec>               ;   process a pixel
            jz      XmNdxDrawDone
            ENDM

            XM_DRAW <dec>               ; process another pixel
            jnz     XmNdxDrawLoop       ; while (count)

XmNdxDrawDone:
            jmp     ReturnClipFlags     ; done

;----------------------------------------------------------------------------
XmNdxXlat:
            mov     eax,parm            ; get translation table pointer
            push    ebp                 ; preserve ebp
            mov     ebp,ebx             ; use ebp for slope to free up ebx
            mov     ebx,eax             ; table ptr must be in ebx for xlat

XmNdxXlatLoop:
            REPEAT  LD_COPIES-1         ; repeat this code copies-1 times
            XM_XLAT <dec>               ;   process a pixel
            jz      XmNdxXlatDone
            ENDM

            XM_XLAT <dec>               ; process another pixel
            jnz     XmNdxXlatLoop       ; while (count)

XmNdxXlatDone:
            pop     ebp                 ; restore ebp
            jmp     ReturnClipFlags     ; done

;----------------------------------------------------------------------------
XmNdxProc:
            mov     esi,panep           ; get pane pointer

            mov     edi,x0_             ; x (edi) = x0_ in pane coordinates
            sub     edi,[esi].x0

            mov     eax,y0_             ; y (esi) = y0_ in pane coordinates
            sub     eax,[esi].y0
            mov     esi,eax

            mov     eax,sgndy           ; xbump (eax) = (sgndy=-1) ? -1 : +1
            add     eax,eax
            inc     eax

XmNdxProcLoop:
            pushad                      ; callback (x, y)
            call    parm
            popad

            add     edx,ebx             ; accum += slope
            jnc     @F                  ; if overflow, y--
            add     esi,eax
@@:         
            dec     edi

            dec     ecx                 ; count--
            jnz     XmNdxProcLoop       ; while (count)

            jmp     ReturnClipFlags     ; done

;----------------------------------------------------------------------------
Vertical:

        ; reject if line is left or right of pane

            mov     eax,x0
            cmp     eax,CP_L
            jl      ReturnReject
            cmp     eax,CP_R
            jg      ReturnReject

        ; reject if line is above plane

            mov     eax,y0
            MAX     eax,y1
            cmp     eax,CP_T
            jl      ReturnReject

        ; reject if line is below plane

            mov     eax,y0
            MIN     eax,y1
            cmp     eax,CP_B
            jg      ReturnReject

        ; clip y0, clip y1

            mov     eax,y0
            MAX     eax,CP_T;
            MIN     eax,CP_B;
            mov     y0_,eax

            mov     eax,y1
            MAX     eax,CP_T;
            MIN     eax,CP_B;
            mov     y1_,eax

            MOVE    x0_,eax,x0

        ; calculate ystep (esi)

            mov     esi,CP_W
            xor     esi,sgndy
            sub     esi,sgndy

        ; calculate count (ecx) =  abs(y1-y0) + 1

            mov     eax,y1_
            sub     eax,y0_
            cdq
            xor     eax,edx
            sub     eax,edx
            mov     ecx,eax
            inc     ecx

            jmp     Straight

;----------------------------------------------------------------------------
Horizontal:

        ; reject if line is above or below pane

            mov     eax,y0
            cmp     eax,CP_T
            jl      ReturnReject
            cmp     eax,CP_B
            jg      ReturnReject

        ; reject if line is left of pane

            mov     eax,x0
            MAX     eax,x1
            cmp     eax,CP_L
            jl      ReturnReject

        ; reject if line is right of pane

            mov     eax,x0
            MIN     eax,x1
            cmp     eax,CP_R
            jg      ReturnReject

        ; clip x0, clip x1

            mov     eax,x0
            MAX     eax,CP_L;
            MIN     eax,CP_R;
            mov     x0_,eax

            mov     eax,x1
            MAX     eax,CP_L;
            MIN     eax,CP_R;
            mov     x1_,eax

            MOVE    y0_,eax,y0

        ; calculate xstep (esi)

            mov     esi,sgndx
            inc     esi
            or      esi,sgndx

        ; calculate count (ecx) =  abs(x1-x0) + 1

            mov     eax,x1_
            sub     eax,x0_
            cdq
            xor     eax,edx
            sub     eax,edx
            mov     ecx,eax
            inc     ecx

            jmp     Straight

;----------------------------------------------------------------------------
Diagonal:

        ; calculate xystep (esi)

            mov     esi,CP_W
            xor     esi,sgndy
            sub     esi,sgndy

            mov     eax,sgndx
            inc     eax
            or      eax,sgndx
            add     esi,eax

        ; calculate count (ecx) =  abs(x1-x0) + 1

            mov     eax,x1_
            sub     eax,x0_
            cdq
            xor     eax,edx
            sub     eax,edx
            mov     ecx,eax
            inc     ecx

;----------------------------------------------------------------------------
Straight:

        ; calculate adr (edi), address of first pixel = window_buffer + CP_W*y0 + x0

            GET_WINDOW_ADDRESS  x0_, y0_
            mov     edi,eax

        ; draw the line with a color, a translation table, or a callback function

            cmp     mode,1
            je      StraightXlat
            jg      StraightProc

;----------------------------------------------------------------------------
StraightDraw:
            GET_COLOR parm
            mov     eax,parm            ; get line color

StraightLoop:
            REPEAT  LD_COPIES-1         ; repeat code copies-1 times
            ST_DRAW                     ;   process a pixel
            jz      StraightDone
            ENDM

            ST_DRAW                     ; process another pixel
            jnz     StraightLoop        ; while (count)

StraightDone:
            jmp     ReturnClipFlags     ; done

;----------------------------------------------------------------------------
StraightXlat:
            mov     ebx,parm            ; get pointer to translation table

StraightXlatLoop:
            REPEAT  LD_COPIES-1         ; repeat code copies-1 times
            SW_XLAT                     ;   process a pixel
            jz      StraightXlatDone
            ENDM

            SW_XLAT                     ; process another pixel
            jnz     StraightXlatLoop    ; while (count)

StraightXlatDone:
            jmp     ReturnClipFlags     ; done

;----------------------------------------------------------------------------

StraightProc:
            mov     esi,panep           ; get pane pointer

            mov     edi,x0_             ; x (edi) = x0_ in pane coordinates
            sub     edi,[esi].x0

            mov     eax,y0_             ; y (esi) = y0_ in pane coordinates
            sub     eax,[esi].y0
            mov     esi,eax

            xor     eax,eax             ; ybump (eax) = sgn (_dy)
            test    _dy,-1
            setnz   al
            or      eax,sgndy

            xor     ebx,ebx             ; xbump (ebx) = sgn (_dx)
            test    _dx,-1
            setnz   bl
            or      ebx,sgndx

StraightProcLoop:
            pushad                      ; callback (x, y)
            call    parm
            popad

            add     esi,eax             ; y += ybump
            add     edi,ebx             ; x += xbump

            dec     ecx                 ; count--
            jnz     StraightProcLoop    ; while (count)

            jmp     ReturnClipFlags     ; done

        ; return error code:
        ;
        ; -2: pane was malformed (or completely off its window)
        ; -1: window was malformed
        ;  0: line was accepted
        ;  1: line was clipped
        ;  2: line was rejected

ReturnClipFlags:
            xor     eax,eax
            cmp     clip_flags,1
            setae   al
            ret

ReturnReject:       
            mov     eax,2
            ret

            ASSUME  esi:nothing
            ASSUME  ebx:nothing

VFX_line_draw \
            ENDP

            ENDIF

;----------------------------------------------------------------------------
;
; int cdecl VFX_rectangle_hash (PANE *panep, int x0, int y0, int x1, int y1,
;                               UBYTE color)
;
;     This function writes a color to every other pixel in a specified rectangle.
;
; The panep parameter specifies the pane containing the pixel to be written.
; The x and y parameters specify the upper left and lower right rectangle
; coordinates.
; The color parameter specifies the color to write to the pixel.
;                                          
; Return values:
;
;    0..255:
;       Pixel value prior to write.
;
;   -1: Bad window.
;       The height or width of the pane's window is less than one.
;
;   -2: Bad pane.
;       The height or width of the pane is less than one.
;
;   -3: Off pane.
;       The specified pixel is off the pane.
;
;   -4: Bad Rectangle.
;       The height or width of the rectangle is less than one.
;                                          
;----------------------------------------------------------------------------

                IF do_VFX_rectangle_hash

VFX_rectangle_hash PROC STDCALL USES ebx esi edi es,\
                panep:PPANE,x0:S32,y0:S32,x1:S32,y1:S32,color

                LOCAL    CP_L   ;Leftmost pixel in Window coord.
                LOCAL    CP_T   ;Top
                LOCAL    CP_R   ;Right
                LOCAL    CP_B   ;Bottom
              
                LOCAL    CP_A   ;Base address of Clipped Pane
                LOCAL    CP_BW  ;Width of underlying window (bytes)
                LOCAL    CP_W   ;Width of underlying window (pixels)
                
                LOCAL    CP_CX  ;Window x coord. = Pane x coord. + CP_CX
                LOCAL    CP_CY  ;Window y coord. = Pane x coord. + CP_CY

                LOCAL    pixel_pitch
                LOCAL    bytes_per_pixel

                cld
                push ds
                pop es

                GET_COLOR color

                CLIP_PANE_TO_WINDOW     panep

                ; transform x & y to window coord's

                CONVERT_QUAD_PANE_TO_WINDOW x0,y0,x1,y1

                ; clip rectangle to pane
                ;   x0 = max (x0, x0w)
                ;   y0 = max (y0, y0w)
                ;   x1 = min (x1, x1w)
                ;   y1 = min (x1, y1w)

                mov     eax,CP_L
                MAX     x0,eax
    
                mov     eax,CP_T
                MAX     y0,eax
    
                mov     eax,CP_R
                MIN     x1,eax
    
                mov     eax,CP_B
                MIN     y1,eax

        ; exit if rect is malformed or completely off window:
        ;   if x1 < x0, return bad rect
        ;   if y1 < y0, return bad rect

        ; ecx = line width
                mov     ecx,x1
                sub     ecx,x0
                jl      ReturnBadRect
                inc     ecx
    
                GET_WINDOW_ADDRESS x0, y0
                mov     edi,eax

        ; edx = line count
                mov     edx,y1
                sub     edx,y0
                jl      ReturnBadRect

        ; eax = color
                mov     eax,[color]
                and     eax,7fffffffh    ;mask off "remap" (RGB_TRIPLET) bit

        ; esi = line start
                mov     esi,edi

        ; ebx = line width
                mov     ebx,ecx

                jmp     __odd_or_even

__write_line:
                add     esi,CP_W
                mov     edi,esi
                mov     ecx,ebx

__odd_or_even:
                push    edx
                and     edx,1
                jz      __even

                pop     edx
                inc     edi
                dec     ecx
                jmp     __write_pixel

__even:
                pop     edx

__write_pixel:
                mov     BYTE PTR [edi],al
                add     edi,2
                sub     ecx,2
                jg      __write_pixel

                dec     edx
                jns     __write_line


                xor     eax,eax
                ret

        ; error returns

ReturnOffPane:
                mov     eax,-3
                ret

ReturnBadRect:
                mov     eax,-4
                ret

VFX_rectangle_hash \
                ENDP

                ENDIF

;----------------------------------------------------------------------------
;
; int cdecl VFX_shape_draw (PANE *panep, void *shape_table,
;                           long shape_number,int hotX, int hotY)
;
; This function clips and draws a shape to a pane.
; 
; The panep parameter specifies the pane.
;
; The shape parameter specifies the shape, which must be in VFX Shape format.
;
; The hotX and hotY parameters specify the location where the shape is to be
; drawn.  The shape's hot spot will end up at the specified location.
;
; For more information, see the "VFX Shape Format Description".
;
; Return values:
;
;    0: OK
;   -1: Bad window
;   -2: Bad pane
;   -3: Shape off pane
;   -4: Null shape
;
;----------------------------------------------------------------------------

            IF do_VFX_shape_draw

VFX_shape_draw PROC STDCALL USES ebx esi edi es,\
            panep:PTR PANE, shape_table:PTR VFX_SHAPETABLE, \
            shape_number:S32, hotX:S32, hotY:S32

            LOCAL windowp:PWIN
            LOCAL ShapePtr:PTR
            LOCAL minX, minY, maxX, maxY
            LOCAL clip_flags
            LOCAL lineY
            LOCAL LinePtr:PBYTE, adr0:PBYTE, adr1:PBYTE
            LOCAL shape:PTR

            LOCAL    CP_L   ;Leftmost pixel in Window coord.
            LOCAL    CP_T   ;Top
            LOCAL    CP_R   ;Right
            LOCAL    CP_B   ;Bottom
          
            LOCAL    CP_A   ;Base address of Clipped Pane
            LOCAL    CP_BW  ;Width of underlying window (bytes)
            LOCAL    CP_W   ;Width of underlying window (pixels)
          
            LOCAL    CP_CX  ;Window x coord. = Pane x coord. + CP_CX
            LOCAL    CP_CY  ;Window y coord. = Pane x coord. + CP_CY

            LOCAL    pixel_pitch
            LOCAL    bytes_per_pixel

            ASSUME  esi:PPANE
            ASSUME  ebx:PWIN

            cld
            push ds
            pop es

            CLIP_PANE_TO_WINDOW panep

        ; convert hotspot from pane coordinates to window coordinates

            CONVERT_PAIR_PANE_TO_WINDOW hotX, hotY

        ; ShapePtr (esi) = shape

            ASSUME  esi:nothing
            mov     esi,[shape_number]  ; get selected shape offset address
            shl     esi,3               ;   mult by size of 2 longs
            add     esi,SIZEOF VFX_SHAPETABLE;  skip over shape table header       
            add     esi,[shape_table]   ;   add base address
            mov     esi,[esi]           ; get selected shape offset
            add     esi,[shape_table]   ; setup ptr to selected shape
            mov     shape,esi           ; save shape ptr

        ; determine boundaries of shape in screen coordinates as follows:
        ;    minX = *ShapePtr++ + hotX
        ;    minY = *ShapePtr++ + hotY
        ;    maxX = *ShapePtr++ + hotX
        ;    maxY = *ShapePtr++ + hotY

            mov     eax,[esi].SHAPEHEADER.xmin
            add     eax,hotX
            mov     minX,eax

            mov     eax,[esi].SHAPEHEADER.ymin
            add     eax,hotY
            mov     minY,eax

            mov     eax,[esi].SHAPEHEADER.xmax
            add     eax,hotX
            mov     maxX,eax

            mov     eax,[esi].SHAPEHEADER.ymax
            add     eax,hotY
            mov     maxY,eax

            add     esi,SIZEOF SHAPEHEADER

        ; if (maxX < minX) or (maxY < minY), shape is null, return

            mov     eax,maxX
            cmp     eax,minX
            jl      ReturnNullShape

            mov     eax,maxY
            cmp     eax,minY
            jl      ReturnNullShape

        ; calculate clip flags for shape boundary

            xor     edx,edx

            mov     eax,minX
            sub     eax,CP_L
            shl     eax,1
            adc     dl,dl

            mov     eax,CP_R
            sub     eax,minX
            shl     eax,1
            adc     dl,dl

            mov     eax,minY
            sub     eax,CP_T
            shl     eax,1
            adc     dl,dl

            mov     eax,CP_B
            sub     eax,minY
            shl     eax,1
            adc     dl,dl

            mov     eax,maxX
            sub     eax,CP_L
            shl     eax,1
            adc     dh,dh

            mov     eax,CP_R
            sub     eax,maxX
            shl     eax,1
            adc     dh,dh

            mov     eax,maxY
            sub     eax,CP_T
            shl     eax,1
            adc     dh,dh

            mov     eax,CP_B
            sub     eax,maxY
            shl     eax,1
            adc     dh,dh

            mov     clip_flags,edx

        ; if shape is completely off-pane, reject it

            test    dl,dh
            jnz     ReturnReject

        ; if pane is partially off-pane, clip it and draw it

            or      dl,dh
            jnz     ClipShape

        ; otherwise, just draw it

        ; convert hotspot coordinates from window coordinates back to pane coordinates

            ASSUME  esi:PPANE
            mov     esi,panep

            mov     eax,[esi].x0
            sub     hotX,eax

            mov     eax,[esi].y0
            sub     hotY,eax

            ASSUME  esi:nothing

        ; call DrawShapeUnclipped() with to draw the shape, then exit

            INVOKE  DrawShapeUnclipped, panep, shape, hotX, hotY, CP_W
            jmp     Exit

ClipShape:

        ; LinePtr (edi) = windowp->buffer + CP_W * minY + minX

            GET_WINDOW_ADDRESS minX, minY
            mov     edi,eax

            ASSUME  ebx:nothing

        ; lineY = minY

            mov     ecx,minY
            mov     lineY,ecx

        ; This section of code clips the top of the shape (if necessary)
        ; by skipping past the first n lines of the shape and advancing
        ; the line pointer by n lines.


        ; while (lineY < CP_T) ...

            jmp     skipLine

skipStringPacket:

        ; process string data

            movzx   eax,al
            add     esi,eax

            dec     esi

        ; process run/skip data

skipRunPacket:
skipSkipPacket:
            inc     esi

getToken:

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      skipRunPacket
            jnz     skipStringPacket
            jc      skipSkipPacket

        ; (an end packet has just been found)

        ; advance the line pointer to the next line and increment lineY

            add     edi,CP_W
            inc     ecx
skipLine:

        ; endwhile (lineY < CP_T)

            cmp     ecx,CP_T
            jl      getToken

        ; bring LinePtr and lineY up to date with their registers

            mov     LinePtr,edi
            mov     lineY,ecx

        ; calculate adr0 = LinePtr - minX + CP_L

            mov     eax,edi             
            sub     eax,minX
            add     eax,CP_L
            mov     adr0,eax

        ; calculate adr1 = LinePtr - minX + CP_R

            mov     eax,edi             
            sub     eax,minX
            add     eax,CP_R
            mov     adr1,eax

        ; enter the main draw loop

            jmp     drawLine



        ; Main draw loop.

drawLoop:

        ; clip the bottom of the shape (if necessary) by exiting early

            mov     eax,lineY
            cmp     eax,CP_B
            jg      Exit

        ; adr = LinePtr

            mov     edi,LinePtr

        ; examine clip flags and dispatch to the appropriate code section

            test    clip_flags,LEFTOF
            jnz     Case2
            test    clip_flags,RIGHTOF*100H
            jnz     Case3

Case1:

        ; This section is entered when no (more) clipping is needed
        ; from the current position to the end of the line.

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket1
            jnz     StringPacket1
            jnc     EndPacket1

SkipPacket1:

        ; process skip packet

            LODSB_
            movzx   ecx,al
            add     edi,ecx

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket1
            jnz     StringPacket1
            jc      SkipPacket1
            jnc     EndPacket1

RunPacket1:

        ; process run packet

            movzx   ecx,al
RunPacket1_:        
            LODSB_
            RSTOSB32

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket1
            jnc     EndPacket1
            jz      SkipPacket1

StringPacket1:

        ; process string packet

            movzx   ecx,al
StringPacket1_:     
            RMOVSB32

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket1
            jnz     StringPacket1
            jc      SkipPacket1

EndPacket1:

        ; process end packet (exit the loop)

            jmp     EndSwitch

Case2:

        ; This section is entered when left clipping is needed.

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket2
            jnz     StringPacket2
            jnc     EndPacket2

SkipPacket2:

        ; process string packet

            LODSB_
            movzx   ecx,al
            add     edi,ecx

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket2
            jnz     StringPacket2
            jc      SkipPacket2
            jnc     EndPacket2

RunPacket2:

        ; process run packet

            movzx   ecx,al

            mov     eax,adr0
            sub     eax,edi
            cmp     eax,ecx
            jge     RunStillLeftOfPane

            or      eax,eax
            js      RunCrossedLeftEdge

            add     edi,eax
            sub     ecx,eax

RunCrossedLeftEdge:
            test    clip_flags,RIGHTOF*100H
            jz      RunPacket1_
            jnz     RunPacket3_

RunStillLeftOfPane:
            add     edi,ecx
            inc     esi

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket2
            jnc     EndPacket2
            jz      SkipPacket2

StringPacket2:

        ; process string packet

            movzx   ecx,al

            mov     eax,adr0
            sub     eax,edi
            cmp     eax,ecx
            jge     StringStillLeftOfPane

            or      eax,eax
            js      StringCrossedLeftEdge

            add     edi,eax
            sub     ecx,eax
            add     esi,eax

StringCrossedLeftEdge:
            test    clip_flags,RIGHTOF*100H
            jz      StringPacket1_
            jnz     StringPacket3_

StringStillLeftOfPane:
            add     edi,ecx
            add     esi,ecx

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket2
            jnz     StringPacket2
            jc      SkipPacket2

EndPacket2:

        ; process end packet (exit loop)

            jmp     EndSwitch

Case3:

        ; This section is entered if the current position is inside
        ; the clip area and right clipping is forthcoming.

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_                      ; read token
            shr     al,1
            ja      RunPacket3
            jnz     StringPacket3
            jnc     EndPacket3

SkipPacket3:

        ; process skip packet

            LODSB_
            movzx   ecx,al
            add     edi,ecx

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket3
            jnz     StringPacket3
            jc      SkipPacket3
            jnc     EndPacket3

RunPacket3:

        ; process run packet

            movzx   ecx,al
RunPacket3_:
            cmp     edi,adr1
            jg      RunPacket4_

            mov     eax,edi
            add     eax,ecx
            dec     eax
            sub     eax,adr1

            cdq
            not     edx
            and     edx,eax

            sub     ecx,edx
            LODSB_
            RSTOSB32

            add     edi,edx

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket3
            jnc     EndPacket3
            jz      SkipPacket3

StringPacket3:

        ; process string packet

            movzx   ecx,al
StringPacket3_:
            cmp     edi,adr1
            jg      StringPacket4_

            mov     eax,edi
            add     eax,ecx
            dec     eax
            sub     eax,adr1

            cdq
            not     edx
            and     edx,eax

            sub     ecx,edx
            RMOVSB32

            add     edi,edx
            add     esi,edx

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket3
            jnz     StringPacket3
            jc      SkipPacket3

EndPacket3:

        ; process end packet (exit loop)

            jmp     EndSwitch

Case4:

        ; This section is entered after right the right clip boundary
        ; has been passed.  clipping has occurred
        ; The rest of the line is clipped.
        
        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_                      ; read token
            shr     al,1
            ja      RunPacket4
            jnz     StringPacket4
            jnc     EndPacket4

SkipPacket4:

        ; process skip packet

            LODSB_
            movzx   ecx,al
            add     edi,ecx

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket4
            jnz     StringPacket4
            jc      SkipPacket4
            jnc     EndPacket4

RunPacket4:

        ; process run packet

            movzx   ecx,al
RunPacket4_:
            add     edi,ecx
            inc     esi

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket4
            jnc     EndPacket4
            jz      SkipPacket4

StringPacket4:

        ; process string packet

            movzx   ecx,al
StringPacket4_:
            add     edi,ecx
            add     esi,ecx

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket4
            jnz     StringPacket4
            jc      SkipPacket4

EndPacket4:

        ; process run packet (fall out of loop)

EndSwitch:

        ; Execution comes her after the pointer reaches the end of the current line.

        ; advance LinePtr, adr0, and adr1 to the next line and increment lineY

            mov     eax,CP_W
            add     LinePtr,eax
            add     adr0,eax
            add     adr1,eax
            
            inc     lineY
drawLine:

        ; loop back for next line

            mov     eax,lineY
            cmp     eax,maxY
            jle     drawLoop

        ; return success

Exit:
            xor     eax,eax
            ret

        ; error returns

ReturnReject:
            mov     eax,-3
            ret

ReturnNullShape:
            mov     eax,-4
            ret

VFX_shape_draw \
            ENDP

;-----------------------------------------------------------------------------
;
; void cdecl DrawShapeUnclipped (PANE *panep, void *shape, int hotX, int hotY)
;
; This function draws a shape to a pane without clipping.
; 
; The panep parameter specifies the pane.
;
; The shape parameter specifies the shape, which must be in VFX Shape Format.
;
; The hotX and hotY parameters specify the location where the shape is to be
; drawn.  The shape's hot spot will end up at the specified location.
;
; For more information, see the "VFX Shape Format Description".
;
;-----------------------------------------------------------------------------

DrawShapeUnclipped PROC STDCALL USES ebx esi edi es,\
            panep:PTR PANE, shape:PTR, hotX, hotY, CP_W

            cld
            push ds
            pop es

        ; get pane pointer

            ASSUME  esi:PPANE
            mov     esi,panep

        ; window (ebx) = panep->window

            ASSUME  ebx:PWIN
            mov     ebx,[esi].window

        ; convert hot spot to window coordinates

            mov     eax,[esi].x0
            add     hotX,eax
            mov     eax,[esi].y0
            add     hotY,eax

            ASSUME  esi:nothing

        ; CP_W = window->x1+1; if <= 0, exit

            mov     eax,[ebx].x_max
            inc     eax
;            imul    eax,pixel_pitch
            mov     CP_W,eax
            jle     Exit

        ; ShapePtr (esi) = shape

            mov     esi,shape

        ; adr (edi) = buffer + CP_W * (minY + hotY) + (minX + hotX)

            mov     edi,[ebx].buffer
            ASSUME  ebx:nothing

            mov     eax,[esi].SHAPEHEADER.xmin  ; read minX from header
            add     eax,hotX
            add     edi,eax

            mov     eax,[esi].SHAPEHEADER.ymin  ; read minY from header
            mov     ebx,eax
            add     eax,hotY

            mul     CP_W
            add     edi,eax

        ; LinePtr (edx) = adr (edi)

            mov     edx,edi

        ; pass up maxX (not needed)

            mov     eax,[esi].SHAPEHEADER.xmax  ; read maxX from header

        ; linecount (ebx) = maxY + 1 - minY; if linecount <= 0, exit

            mov     eax,[esi].SHAPEHEADER.ymax  ; read maxY from header
            inc     eax
            sub     eax,ebx
            mov     ebx,eax
            jle     Exit

            add     esi,SIZEOF SHAPEHEADER

lineLoop:

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket
            jnz     StringPacket
            jnc     EndPacket

SkipPacket:

        ; process skip packet

            LODSB_
            movzx   ecx,al

            add     edi,ecx

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket
            jnz     StringPacket
            jc      SkipPacket
            jnc     EndPacket

RunPacket:

        ; process run packet

            movzx   ecx,al
            LODSB_
            RSTOSB32

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket
            jnc     EndPacket
            jz      SkipPacket

StringPacket:

        ; process string packet

            movzx   ecx,al
            RMOVSB32

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket
            jnz     StringPacket
            jc      SkipPacket

EndPacket:

        ; prcoess end packet (do nothing)

        ; advance LinePtr (edx) pointer to begining of next line
        ; set adr = LinePtr
        
            add     edx,CP_W
            mov     edi,edx

        ; loop back for next line

            dec     ebx
            jnz     lineLoop

Exit:       
            xor     eax,eax
            ret

DrawShapeUnclipped \
            ENDP

            ENDIF

;----------------------------------------------------------------------------
;
; void cdecl VFX_shape_lookaside (unsigned char *table)
;
; Establishes a color translation lookaside table for use by future calls
; to VFX_shape_translate_draw().
; 
; table points to a 256-byte table specifying remap values for each of
; the 256 possible palette indices.  The table is copied to static local 
; memory, and need not remain valid after the call.
;
;----------------------------------------------------------------------------

                IF do_VFX_shape_lookaside

VFX_shape_lookaside PROC STDCALL USES ebx esi edi es,\
                table:PTR U8

                cld

                push ds                 
                pop es

                mov esi,[table]          ;DS:ESI -> user lookaside table
                mov edi,OFFSET lookaside ;ES:EDI -> local lookaside table

                mov ecx,256/4           ;copy to local memory area with
                rep movsd               ;known offset; allows fast lookup

                ret

VFX_shape_lookaside ENDP

                ENDIF

;----------------------------------------------------------------------------
;
; int cdecl VFX_shape_translate_draw (PANE *panep, void *shape_table,
;                           long shape_number,int hotX, int hotY)
;
; This function clips and draws a shape to a pane.  It is identical to 
; VFX_shape_draw(), except that each pixel written is translated through a
; 256-byte table which was specified by a prior call to VFX_shape_lookaside().
; 
; The panep parameter specifies the pane.
;
; The shape parameter specifies the shape, which must be in VFX Shape format.
;
; The hotX and hotY parameters specify the location where the shape is to be
; drawn.  The shape's hot spot will end up at the specified location.
;
; For more information, see the "VFX Shape Format Description".
;
; Return values:
;
;    0: OK
;   -1: Bad window
;   -2: Bad pane
;   -3: Shape off pane
;   -4: Null shape
;
;----------------------------------------------------------------------------

            IF do_VFX_shape_translate_draw

VFX_shape_translate_draw PROC STDCALL USES ebx esi edi es,\
            panep:PTR PANE, shape_table:PTR VFX_SHAPETABLE, \
            shape_number:S32, hotX:S32, hotY:S32

            LOCAL windowp:PWIN
            LOCAL ShapePtr:PTR
            LOCAL minX, minY, maxX, maxY
            LOCAL clip_flags
            LOCAL lineY
            LOCAL LinePtr:PBYTE, adr0:PBYTE, adr1:PBYTE
            LOCAL shape:PTR

            LOCAL    CP_L   ;Leftmost pixel in Window coord.
            LOCAL    CP_T   ;Top
            LOCAL    CP_R   ;Right
            LOCAL    CP_B   ;Bottom
            
            LOCAL    CP_A   ;Base address of Clipped Pane
            LOCAL    CP_BW  ;Width of underlying window (bytes)
            LOCAL    CP_W   ;Width of underlying window (pixels)
            
            LOCAL    CP_CX  ;Window x coord. = Pane x coord. + CP_CX
            LOCAL    CP_CY  ;Window y coord. = Pane x coord. + CP_CY

            LOCAL    pixel_pitch
            LOCAL    bytes_per_pixel

            ASSUME  esi:PPANE
            ASSUME  ebx:PWIN

            cld
            push ds
            pop es

            CLIP_PANE_TO_WINDOW panep

        ; convert hotspot from pane coordinates to window coordinates
            
            CONVERT_PAIR_PANE_TO_WINDOW hotX, hotY

        ; ShapePtr (esi) = shape

            ASSUME  esi:nothing
            mov     esi,[shape_number]  ; get selected shape offset address
            shl     esi,3               ;   mult by size of 2 longs
            add     esi,SIZEOF VFX_SHAPETABLE;  skip over shape table header       
            add     esi,[shape_table]   ;   add base address
            mov     esi,[esi]           ; get selected shape offset
            add     esi,[shape_table]   ; setup ptr to selected shape
            mov     shape,esi           ; save shape ptr

        ; determine boundaries of shape in screen coordinates as follows:
        ;    minX = *ShapePtr++ + hotX
        ;    minY = *ShapePtr++ + hotY
        ;    maxX = *ShapePtr++ + hotX
        ;    maxY = *ShapePtr++ + hotY

            mov     eax,[esi].SHAPEHEADER.xmin
            add     eax,hotX
            mov     minX,eax

            mov     eax,[esi].SHAPEHEADER.ymin
            add     eax,hotY
            mov     minY,eax

            mov     eax,[esi].SHAPEHEADER.xmax
            add     eax,hotX
            mov     maxX,eax

            mov     eax,[esi].SHAPEHEADER.ymax
            add     eax,hotY
            mov     maxY,eax

            add     esi,SIZEOF SHAPEHEADER

        ; if (maxX < minX) or (maxY < minY), shape is null, return

            mov     eax,maxX
            cmp     eax,minX
            jl      ReturnNullShape

            mov     eax,maxY
            cmp     eax,minY
            jl      ReturnNullShape

        ; calculate clip flags for shape boundary

            xor     edx,edx

            mov     eax,minX
            sub     eax,CP_L
            shl     eax,1
            adc     dl,dl

            mov     eax,CP_R
            sub     eax,minX
            shl     eax,1
            adc     dl,dl

            mov     eax,minY
            sub     eax,CP_T
            shl     eax,1
            adc     dl,dl

            mov     eax,CP_B
            sub     eax,minY
            shl     eax,1
            adc     dl,dl

            mov     eax,maxX
            sub     eax,CP_L
            shl     eax,1
            adc     dh,dh

            mov     eax,CP_R
            sub     eax,maxX
            shl     eax,1
            adc     dh,dh

            mov     eax,maxY
            sub     eax,CP_T
            shl     eax,1
            adc     dh,dh

            mov     eax,CP_B
            sub     eax,maxY
            shl     eax,1
            adc     dh,dh

            mov     clip_flags,edx

        ; if shape is completely off-pane, reject it

            test    dl,dh
            jnz     ReturnReject

        ; if pane is partially off-pane, clip it and draw it

            or      dl,dh
            jnz     ClipShape

        ; otherwise, just draw it

        ; convert hotspot coordinates from window coordinates back to
        ; pane coordinates

            ASSUME  esi:PPANE
            mov     esi,panep

            mov     eax,[esi].x0
            sub     hotX,eax

            mov     eax,[esi].y0
            sub     hotY,eax

            ASSUME  esi:nothing

        ; call XlatShapeUnclipped() with to draw the shape, then exit

            INVOKE  XlatShapeUnclipped, panep, shape, hotX, hotY, CP_W
            jmp     Exit

ClipShape:

        ; LinePtr (edi) = windowp->buffer + CP_W * minY + minX

            GET_WINDOW_ADDRESS minX, minY
            mov     edi,eax

            ASSUME  ebx:nothing

        ; lineY = minY

            mov     ecx,minY
            mov     lineY,ecx

        ; This section of code clips the top of the shape (if necessary)
        ; by skipping past the first n lines of the shape and advancing
        ; the line pointer by n lines.


        ; while (lineY < CP_T) ...

            jmp     skipLine

skipStringPacket:

        ; process string data

            movzx   eax,al
            add     esi,eax

            dec     esi

        ; process run/skip data

skipRunPacket:
skipSkipPacket:
            inc     esi

getToken:

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      skipRunPacket
            jnz     skipStringPacket
            jc      skipSkipPacket

        ; (an end packet has just been found)

        ; advance the line pointer to the next line and increment lineY

            add     edi,CP_W
            inc     ecx
skipLine:

        ; endwhile (lineY < CP_T)

            cmp     ecx,CP_T
            jl      getToken

        ; bring LinePtr and lineY up to date with their registers

            mov     LinePtr,edi
            mov     lineY,ecx

        ; calculate adr0 = LinePtr - minX + CP_L

            mov     eax,edi             
            sub     eax,minX
            add     eax,CP_L
            mov     adr0,eax

        ; calculate adr1 = LinePtr - minX + CP_R

            mov     eax,edi             
            sub     eax,minX
            add     eax,CP_R
            mov     adr1,eax

        ; enter the main draw loop

            jmp     drawLine



        ; Main draw loop.

drawLoop:

        ; clip the bottom of the shape (if necessary) by exiting early

            mov     eax,lineY
            cmp     eax,CP_B
            jg      Exit

        ; adr = LinePtr

            mov     edi,LinePtr

        ; examine clip flags and dispatch to the appropriate code section

            test    clip_flags,LEFTOF
            jnz     Case2
            test    clip_flags,RIGHTOF*100H
            jnz     Case3

Case1:

        ; This section is entered when no (more) clipping is needed from
        ; the current position to the end of the line.
        
        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket1
            jnz     StringPacket1
            jnc     EndPacket1

SkipPacket1:

        ; process skip packet

            LODSB_
            movzx   ecx,al
            add     edi,ecx

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket1
            jnz     StringPacket1
            jc      SkipPacket1
            jnc     EndPacket1

RunPacket1:

        ; process run packet

            movzx   ecx,al
RunPacket1_:        
            xor eax,eax
            LODSB_

            mov al,lookaside[eax]

            RSTOSB32

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket1
            jnc     EndPacket1
            jz      SkipPacket1

StringPacket1:

        ; process string packet

            movzx   ecx,al
StringPacket1_:     
            RXLAT32

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket1
            jnz     StringPacket1
            jc      SkipPacket1

EndPacket1:

        ; process end packet (exit the loop)

            jmp     EndSwitch

Case2:

        ; This section is entered when left clipping is needed.

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket2
            jnz     StringPacket2
            jnc     EndPacket2

SkipPacket2:

        ; process string packet

            LODSB_
            movzx   ecx,al
            add     edi,ecx

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket2
            jnz     StringPacket2
            jc      SkipPacket2
            jnc     EndPacket2

RunPacket2:

        ; process run packet

            movzx   ecx,al

            mov     eax,adr0
            sub     eax,edi
            cmp     eax,ecx
            jge     RunStillLeftOfPane

            or      eax,eax
            js      RunCrossedLeftEdge

            add     edi,eax
            sub     ecx,eax

RunCrossedLeftEdge:
            test    clip_flags,RIGHTOF*100H
            jz      RunPacket1_
            jnz     RunPacket3_

RunStillLeftOfPane:
            add     edi,ecx
            inc     esi
        
        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket2
            jnc     EndPacket2
            jz      SkipPacket2

StringPacket2:

        ; process string packet

            movzx   ecx,al

            mov     eax,adr0
            sub     eax,edi
            cmp     eax,ecx
            jge     StringStillLeftOfPane

            or      eax,eax
            js      StringCrossedLeftEdge

            add     edi,eax
            sub     ecx,eax
            add     esi,eax

StringCrossedLeftEdge:
            test    clip_flags,RIGHTOF*100H
            jz      StringPacket1_
            jnz     StringPacket3_

StringStillLeftOfPane:
            add     edi,ecx
            add     esi,ecx

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket2
            jnz     StringPacket2
            jc      SkipPacket2

EndPacket2:

        ; process end packet (exit loop)

            jmp     EndSwitch

Case3:

        ; This section is entered if the current position is inside the clip area 
        ; and right clipping is forthcoming.

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_                      ; read token
            shr     al,1
            ja      RunPacket3
            jnz     StringPacket3
            jnc     EndPacket3

SkipPacket3:

        ; process skip packet

            LODSB_
            movzx   ecx,al
            add     edi,ecx
        
        ; get token, adjust count, and branch to appropriate packet handler
        
            LODSB_
            shr     al,1
            ja      RunPacket3
            jnz     StringPacket3
            jc      SkipPacket3
            jnc     EndPacket3

RunPacket3:

        ; process run packet

            movzx   ecx,al
RunPacket3_:
            cmp     edi,adr1
            jg      RunPacket4_

            mov     eax,edi
            add     eax,ecx
            dec     eax
            sub     eax,adr1

            cdq
            not     edx
            and     edx,eax

            sub     ecx,edx

            xor eax,eax
            LODSB_

            mov al,lookaside[eax]

            RSTOSB32

            add     edi,edx

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket3
            jnc     EndPacket3
            jz      SkipPacket3

StringPacket3:

        ; process string packet

            movzx   ecx,al
StringPacket3_:
            cmp     edi,adr1
            jg      StringPacket4_

            mov     eax,edi
            add     eax,ecx
            dec     eax
            sub     eax,adr1

            cdq
            not     edx
            and     edx,eax

            sub     ecx,edx
            RXLAT32

            add     edi,edx
            add     esi,edx

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket3
            jnz     StringPacket3
            jc      SkipPacket3

EndPacket3:

        ; process end packet (exit loop)

            jmp     EndSwitch

Case4:

        ; This section is entered after right the right clip boundary has
        ; been passed.  clipping has occurred
        ; The rest of the line is clipped.

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_                      ; read token
            shr     al,1
            ja      RunPacket4
            jnz     StringPacket4
            jnc     EndPacket4

SkipPacket4:

        ; process skip packet

            LODSB_
            movzx   ecx,al
            add     edi,ecx

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket4
            jnz     StringPacket4
            jc      SkipPacket4
            jnc     EndPacket4

RunPacket4:

        ; process run packet

            movzx   ecx,al
RunPacket4_:
            add     edi,ecx
            inc     esi

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket4
            jnc     EndPacket4
            jz      SkipPacket4

StringPacket4:

        ; process string packet

            movzx   ecx,al
StringPacket4_:
            add     edi,ecx
            add     esi,ecx

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket4
            jnz     StringPacket4
            jc      SkipPacket4

EndPacket4:

        ; process run packet (fall out of loop)

EndSwitch:

        ; Execution comes her after the pointer reaches the
        ; end of the current line.

        ; advance LinePtr, adr0, and adr1 to the next line and increment lineY

            mov     eax,CP_W
            add     LinePtr,eax
            add     adr0,eax
            add     adr1,eax
            
            inc     lineY
drawLine:

        ; loop back for next line

            mov     eax,lineY
            cmp     eax,maxY
            jle     drawLoop

        ; return success

Exit:
            xor     eax,eax
            ret

        ; error returns

ReturnReject:
            mov     eax,-3
            ret

ReturnNullShape:
            mov     eax,-4
            ret

VFX_shape_translate_draw \
            ENDP

;-----------------------------------------------------------------------------
;
; void cdecl XlatShapeUnclipped (PANE *panep, void *shape, int hotX, int hotY)
;
; This function draws a shape to a pane without clipping.
; Each pixel written is translated through a 256-byte table which was 
; specified by a prior call to VFX_shape_lookaside().
; 
; The panep parameter specifies the pane.
;
; The shape parameter specifies the shape, which must be in VFX Shape Format.
;
; The hotX and hotY parameters specify the location where the shape is to be
; drawn.  The shape's hot spot will end up at the specified location.
;
; For more information, see the "VFX Shape Format Description".
;
;-----------------------------------------------------------------------------

XlatShapeUnclipped PROC STDCALL USES ebx esi edi es,\
            panep:PTR PANE, shape:PTR, hotX, hotY, CP_W

            cld
            push ds
            pop es

        ; get pane pointer

            ASSUME  esi:PPANE
            mov     esi,panep

        ; window (ebx) = panep->window

            ASSUME  ebx:PWIN
            mov     ebx,[esi].window

        ; convert hot spot to window coordinates

            mov     eax,[esi].x0
            add     hotX,eax
            mov     eax,[esi].y0
            add     hotY,eax

            ASSUME  esi:nothing

        ; CP_W = window->x1+1; if <= 0, exit

            mov     eax,[ebx].x_max
            inc     eax
;            imul    eax,pixel_pitch
            mov     CP_W,eax
            jle     Exit

        ; ShapePtr (esi) = shape

            mov     esi,shape

        ; adr (edi) = buffer + CP_W * (minY + hotY) + (minX + hotX)

            mov     edi,[ebx].buffer
            ASSUME  ebx:nothing

            mov     eax,[esi].SHAPEHEADER.xmin  ; read minX from header
            add     eax,hotX
            add     edi,eax

            mov     eax,[esi].SHAPEHEADER.ymin  ; read minY from header
            mov     ebx,eax
            add     eax,hotY

            mul     CP_W
            add     edi,eax

        ; LinePtr (edx) = adr (edi)

            mov     edx,edi

        ; pass up maxX (not needed)

            mov     eax,[esi].SHAPEHEADER.xmax  ; read maxX from header

        ; linecount (ebx) = maxY + 1 - minY; if linecount <= 0, exit

            mov     eax,[esi].SHAPEHEADER.ymax  ; read maxY from header
            inc     eax
            sub     eax,ebx
            mov     ebx,eax
            jle     Exit

            add     esi,SIZEOF SHAPEHEADER

lineLoop:

        ; get token, adjust count, and branch to
        ; appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket
            jnz     StringPacket
            jnc     EndPacket

SkipPacket:

        ; process skip packet

            LODSB_
            movzx   ecx,al
            add     edi,ecx

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket
            jnz     StringPacket
            jc      SkipPacket
            jnc     EndPacket

RunPacket:

        ; process run packet

            movzx   ecx,al

            xor eax,eax
            LODSB_

            mov al,lookaside[eax]

            RSTOSB32

        ; get token, adjust count, and branch to
        ; appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket
            jnc     EndPacket
            jz      SkipPacket

StringPacket:

        ; process string packet

            movzx   ecx,al
            RXLAT32

        ; get token, adjust count, and branch to
        ; appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket
            jnz     StringPacket
            jc      SkipPacket

EndPacket:

        ; prcoess end packet (do nothing)

        ; advance LinePtr (edx) pointer to begining of next line
        ; set adr = LinePtr

            add     edx,CP_W
            mov     edi,edx

        ; loop back for next line

            dec     ebx
            jnz     lineLoop

Exit:       
            xor     eax,eax
            ret

XlatShapeUnclipped \
            ENDP

            ENDIF

;----------------------------------------------------------------------------
;
; void cdecl VFX_shape_transform (PANE *pane,
;   void *shape_table, LONG shape_number, LONG hotX, LONG hotY,
;   void *buffer, LONG rot, LONG x_scale, LONG y_scale, LONG flags)
;
; This function draws a shape to an intermediate buffer with optional color
; translation, and then copies the intermediate buffer to the specified pane
; with optional 2D scaling, mirroring, and rotation.
; 
; The pane parameter specifies the destination pane for the transformed shape.
;
; The shape_ parameters specify the shape, which must be in the
; standard VFX shape format.
;
; The hotX and hotY parameters specify the location where the shape is to be
; drawn.  The shape's hot spot will appear at the specified location.
;
; The buffer parameter points to a user-supplied memory buffer of sufficient
; size to contain the shape to be transformed (i.e. shape_width * shape_height
; bytes for 256-color shapes).
;
; rot gives the angular rotation for the shape in increments of 1/10 degree.
;
; x_scale and y_scale give the 16.16 fixed-point scaling values for the 
; rendered shape in its X and Y dimensions, respectively.  Negative scale
; values for an axis cause the shape to be flipped along that axis.
;
; flags has 2 valid bitfields:
;
;  ST_XLAT .... Renders the shape to the intermediate buffer through the 
;               color lookaside table last registered with the 
;               VFX_shape_lookaside() function.
;
;  ST_REUSE ... Causes the initial rendering pass to be skipped, resulting
;               in greater performance in cases where the source shape data
;               and buffer remain valid from one call to the next.
;
; Note that if the shape has any transparent areas at all, they will be
; rendered internally as color 255.  Color 255 will always be
; treated as transparent during the inverse transformation pass.
;
;----------------------------------------------------------------------------

                IF do_VFX_shape_transform

VFX_shape_transform PROC STDCALL USES ebx esi edi es,\
                DestPane:PTR PANE, shape_table:PTR VFX_SHAPETABLE, \
                shape_number:S32, hotX:S32, hotY:S32, \
                buffer:PTR, rot:S32, x_scale:S32, y_scale:S32, \
                flags
                
                LOCAL bufwnd:VFX_WINDOW
                LOCAL buf:PANE
                LOCAL pt_in:VFX_POINT
                LOCAL pt_out:VFX_POINT
                LOCAL pt_origin:VFX_POINT

                LOCAL sw,sh,comp_x,comp_y
                LOCAL txt_width
                LOCAL txt_bitmap
                LOCAL line_base
                LOCAL vlist_beg
                LOCAL vlist_end
                LOCAL v_top
                LOCAL lcur
                LOCAL rcur
                LOCAL lnxt
                LOCAL rnxt
                LOCAL lcnt
                LOCAL rcnt
                LOCAL line_cnt
                LOCAL line_y
                LOCAL lx
                LOCAL rx
                LOCAL lu
                LOCAL ru
                LOCAL lv
                LOCAL rv
                LOCAL ldx
                LOCAL rdx
                LOCAL ldu
                LOCAL rdu
                LOCAL ldv
                LOCAL rdv
                LOCAL plx
                LOCAL prx
                LOCAL du
                LOCAL dv
                LOCAL flu
                LOCAL    pixel_pitch
                LOCAL    bytes_per_pixel

                LOCAL    CP_L   ;Leftmost pixel in Window coord.
                LOCAL    CP_T   ;Top
                LOCAL    CP_R   ;Right
                LOCAL    CP_B   ;Bottom
              
                LOCAL    CP_A   ;Base address of Clipped Pane
                LOCAL    CP_BW  ;Width of underlying window (bytes)
                LOCAL    CP_W   ;Width of underlying window (pixels)
                
                LOCAL    CP_CX  ;Window x coord. = Pane x coord. + CP_CX
                LOCAL    CP_CY  ;Window y coord. = Pane x coord. + CP_CY

                cld
                push ds
                pop es
              
                cmp x_scale,010000h
                jnz __do_transform
                cmp y_scale,010000h
                jnz __do_transform
                cmp rot,0                   ;draw shape directly if no scaling
                je __unity_case             ;or rotation requested

__do_transform: invoke VFX_shape_resolution,shape_table,shape_number
                
                mov ecx,eax
                shr eax,16
                dec eax
                mov sw,eax                  ;get overall shape width
                
                and ecx,0ffffh
                dec ecx
                mov sh,ecx                  ;get overall shape height
                
                ASSUME ebx:PWIN             ;assign pane/window for 1st pass
                ASSUME esi:PPANE
                
                lea ebx,bufwnd
                lea esi,buf
                
                mov [esi].window,ebx
                
                mov edx,buffer
                mov [ebx].buffer,edx
                
                mov [esi].x0,0
                mov vert0.u,0
                mov vert3.u,0
                
                mov [esi].y0,0
                mov vert0.v,0
                mov vert1.v,0
                
                mov [ebx].x_max,eax
                mov [esi].x1,eax
                mov vert1.u,eax
                mov vert2.u,eax
                
                mov [ebx].y_max,ecx
                mov [esi].y1,ecx
                mov vert2.v,ecx
                mov vert3.v,ecx
                
                invoke VFX_shape_minxy,shape_table,shape_number
                
                mov ebx,eax
                cwde
                neg eax
                mov pt_origin.y,eax          ;get hotspot offset from upper-left
                
                sar ebx,16
                neg ebx
                mov pt_origin.x,ebx
                
                test flags,ST_REUSE
                jnz __pass_2
                
                invoke VFX_pane_wipe,ADDR buf,PAL_TRANSPARENT

                test flags,ST_XLAT
                jz __draw_norm

                invoke VFX_shape_translate_draw,ADDR buf,shape_table,\
                       shape_number,pt_origin.x,pt_origin.y
                jmp __pass_2

__draw_norm:    invoke VFX_shape_draw,ADDR buf,shape_table,shape_number,\
                       pt_origin.x,pt_origin.y
                
__pass_2:       
                CLIP_PANE_TO_WINDOW     DestPane

                mov eax,hotX
                sub eax,pt_origin.x
                mov comp_x,eax
                
                mov eax,hotY
                sub eax,pt_origin.y
                mov comp_y,eax
                
                mov pt_in.x,0
                mov pt_in.y,0
                invoke VFX_point_transform,ADDR pt_in,ADDR pt_out,ADDR pt_origin,\
                       rot,x_scale,y_scale
                mov eax,pt_out.x
                add eax,comp_x
                mov vert0.vx,eax
                mov eax,pt_out.y
                add eax,comp_y
                mov vert0.vy,eax

                mov eax,sw
                mov pt_in.x,eax
                mov pt_in.y,0
                invoke VFX_point_transform,ADDR pt_in,ADDR pt_out,ADDR pt_origin,\
                       rot,x_scale,y_scale
                mov eax,pt_out.x
                add eax,comp_x
                mov vert1.vx,eax
                mov eax,pt_out.y
                add eax,comp_y
                mov vert1.vy,eax

                CONVERT_QUAD_PANE_TO_WINDOW vert0.vx,vert0.vy, vert1.vx,vert1.vy

                mov eax,sw
                mov ebx,sh
                mov pt_in.x,eax
                mov pt_in.y,ebx
                invoke VFX_point_transform,ADDR pt_in,ADDR pt_out,ADDR pt_origin,\
                       rot,x_scale,y_scale
                mov eax,pt_out.x
                add eax,comp_x
                mov vert2.vx,eax
                mov eax,pt_out.y
                add eax,comp_y
                mov vert2.vy,eax
                
                mov eax,sh
                mov pt_in.x,0
                mov pt_in.y,eax
                invoke VFX_point_transform,ADDR pt_in,ADDR pt_out,ADDR pt_origin,\
                       rot,x_scale,y_scale
                mov eax,pt_out.x
                add eax,comp_x
                mov vert3.vx,eax
                mov eax,pt_out.y
                add eax,comp_y
                mov vert3.vy,eax

                CONVERT_QUAD_PANE_TO_WINDOW vert2.vx,vert2.vy, vert3.vx,vert3.vy

                ASSUME ebx:PWIN

                lea ebx,bufwnd
                mov eax,[ebx].buffer    ;copy buffer pointer
                mov txt_bitmap,eax
                mov ecx,[ebx].x_max     ; = windowp->x1+1
                inc ecx                 ;   - windowp->x0
                mov txt_width,ecx       ;store line size

                ASSUME ebx:PVERTEX2D
                ASSUME esi:PVERTEX2D
                ASSUME edi:PVERTEX2D

                push ds
                pop es

                mov ebx,OFFSET vert0    ;EBX -> list of VERTEX strcts
                mov eax,ebx
                add eax,80              ;4 vertices * 20 bytes/VERTEX
                mov vlist_beg,ebx      
                mov vlist_end,eax       ;BX + VCnt*SIZE VERTEX -> end of list

        ;
        ;Find top and bottom vertices; perform Sutherland-Cohen
        ;clipping on output quadrangle
        ;

                mov esi,32767           ;ESI = top vertex Y
                mov edi,-32768          ;EDI = bottom vertex Y

                mov ecx,1111b           ;ECX = S-C "and" result for polygon

__vertex_sort:  mov edx,0               ;EDX = S-C flags for this vertex

                mov eax,[ebx].vx
                sub eax,CP_L
                shld edx,eax,1

                mov eax,CP_R
                sub eax,[ebx].vx
                shld edx,eax,1

                mov eax,[ebx].vy
                sub eax,CP_T
                shld edx,eax,1

                mov eax,CP_B
                sub eax,[ebx].vy
                shld edx,eax,1

                mov eax,[ebx].vy

                cmp eax,esi             ;keep track of top and bottom vertices
                jg __not_top
                mov esi,eax
                mov v_top,ebx

__not_top:      cmp eax,edi
                jl __not_btm
                mov edi,eax

__not_btm:      and ecx,edx
                
                add ebx,SIZE VERTEX2D
                cmp ebx,vlist_end
                jne __vertex_sort

                or ecx,ecx              ;all vertices to one side of window?
                jnz __exit              ;yes, polygon fully clipped

                mov eax,v_top           ;else init right, left vertices = top
                mov lnxt,eax
                mov rnxt,eax

                mov line_y,esi          ;init scanline Y = top vertex Y

                cmp edi,esi             ;is polygon flat?
                je __exit               ;yes, don't draw it

        ;
        ;Calculate initial edge positions & stepping vals for
        ;left and right edges
        ;

__init_left:    mov ebx,lnxt
                mov lcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                sub esi,SIZE VERTEX2D
                cmp esi,vlist_beg
                jge __init_lnxt
                mov esi,vlist_end
                sub esi,SIZE VERTEX2D
__init_lnxt:    mov lnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].vy        ;ECX = edge bottom Y
                mov edx,[ebx].vy        ;EDX = edge top Y

                cmp edx,CP_T            ;skip edge if above viewport
                jge __set_l_pcnt
                cmp ecx,CP_T
                jle __init_left         ;(bottom vertex shared w/next edge)

__set_l_pcnt:   sub ecx,edx             ;is edge flat?
                jz __init_left          ;yes, advance one edge left

                mov lcnt,ecx            ;set left edge pixel count

                mov edx,[esi].vx        ;get size of edge in X
                sub edx,[ebx].vx
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldx,eax             ;set left DX
                
                mov ecx,lcnt

                mov edx,[esi].u         ;get size of edge in U
                sub edx,[ebx].u
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldu,eax             ;set left DU

                mov ecx,lcnt

                mov edx,[esi].v         ;get size of edge in V
                sub edx,[ebx].v
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldv,eax             ;set left DV

                mov edx,[ebx].vx        ;convert X, U, and V to fixed-point
                shl edx,16              ;pre-round by adding +0.5 to all
                add edx,8000h           
                mov lx,edx

                mov edx,[ebx].u
                shl edx,16
                add edx,8000h
                mov lu,edx

                mov edx,[ebx].v
                shl edx,16
                add edx,8000h
                mov lv,edx

__init_right:   mov ebx,rnxt
                mov rcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                add esi,SIZE VERTEX2D
                cmp esi,vlist_end
                jl __init_rnxt
                mov esi,vlist_beg
__init_rnxt:    mov rnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].vy        ;ECX = edge bottom Y
                mov edx,[ebx].vy        ;EDX = edge top Y

                cmp edx,CP_T            ;skip edge if above viewport
                jge __set_r_pcnt
                cmp ecx,CP_T
                jle __init_right        ;(bottom vertex shared w/next edge)

__set_r_pcnt:   sub ecx,edx             ;is edge flat?
                jz __init_right         ;yes, advance one edge right

                mov rcnt,ecx            ;set right edge pixel count

                mov edx,[esi].vx        ;get size of edge in X
                sub edx,[ebx].vx
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdx,eax             ;set right DX
                
                mov ecx,rcnt

                mov edx,[esi].u         ;get size of edge in U
                sub edx,[ebx].u
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdu,eax             ;set right DU

                mov ecx,rcnt

                mov edx,[esi].v         ;get size of edge in U
                sub edx,[ebx].v
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdv,eax             ;set right DV

                mov edx,[ebx].vx        ;convert X,U, and V to fixed-point
                shl edx,16              ;pre-round by adding +0.5 to all
                add edx,8000h
                mov rx,edx

                mov edx,[ebx].u
                shl edx,16
                add edx,8000h
                mov ru,edx

                mov edx,[ebx].v
                shl edx,16
                add edx,8000h
                mov rv,edx

        ;
        ;Set scanline count; clip against bottom of window
        ;

                mov eax,CP_B
                sub eax,line_y

                sub edi,CP_B
                jg __clip_bottom

                add eax,edi
__clip_bottom:  mov line_cnt,eax

        ;
        ;Clip against top of window
        ;

                mov eax,CP_T
                sub eax,line_y
                jle __set_Y_base

                sub line_cnt,eax

                mov ecx,CP_T
                mov line_y,ecx
                mov ebx,lcur
                sub ecx,[ebx].vy
                sub lcnt,ecx

                shl ecx,16              ;ECX = # of pixels to clip from left

                mov eax,ldx             ;lx = lx + ECX * ldx
                FPMUL ecx
                add lx,eax

                mov eax,ldu             ;lu = lu + ECX * ldu
                FPMUL ecx
                add lu,eax

                mov eax,ldv             ;lv = lv + ECX * ldv
                FPMUL ecx
                add lv,eax

                mov ecx,CP_T
                mov ebx,rcur
                sub ecx,[ebx].vy
                sub rcnt,ecx

                shl ecx,16              ;ECX = # of pixels to clip from right

                mov eax,rdx             ;rx = rx + ECX * rdx
                FPMUL ecx
                add rx,eax

                mov eax,rdu             ;ru = ru + ECX * rdu
                FPMUL ecx
                add ru,eax

                mov eax,rdv             ;rv = rv + ECX * rdv
                FPMUL ecx
                add rv,eax

        ;
        ;Set window base address and loop variables
        ;

__set_Y_base:   GET_WINDOW_ADDRESS 0,line_y
                mov line_base,eax

                mov eax,lx
                mov ebx,rx
                mov ecx,lu
                mov edx,ru
                mov esi,lv
                mov edi,rv

        ;
        ;Trace edges & plot scanlines ...
        ;

__do_line:      push eax                ;save LX
                push ebx                ;save RX
                push ecx                ;save LU
                push edx                ;save RU
                push esi                ;save LV
                push edi                ;save RV

                cmp ebx,eax             ;sort X, U, and V left-to-right
                jg __XUV_sorted

                xchg eax,ebx
                xchg ecx,edx
                xchg esi,edi

__XUV_sorted:   sar eax,16              ;(preserve sign)
                cmp eax,CP_R
                jg __next_line

                sar ebx,16              ;(preserve sign)
                cmp ebx,CP_L
                jl __next_line

                mov plx,eax
                mov prx,ebx

                mov flu,ecx             ;save left source X (U)
                
                sub ebx,eax             ;EBX = # of pixels in scanline - 1
                jz __index_bitmap       ;(single-pixel line)

                push ebx

                sub edx,ecx             ;EDX = ru-lu
                FPDIV ebx
                mov du,eax              
                shld edx,eax,16

                pop ebx

                and eax,0ffffh
                and edx,0ffffh

                mov ecx,1               ;assume DU positive
                test edx,8000h
                jz __set_U_step
                or edx,0ffff0000h
                neg ecx
                cmp eax,1               ;if DU negative, truncate step to
                sbb edx,-1              ;next higher integer
__set_U_step:   add ecx,edx

                push ecx
                push edx

                sub edi,esi             ;EDI = rv-lv
                mov edx,edi
                FPDIV ebx
                mov dv,eax
                shld edx,eax,16

                and eax,0ffffh
                and edx,0ffffh

                mov ecx,txt_width       ;assume DV positive
                test edx,8000h
                jz __set_V_step
                neg ecx                  
                cmp eax,1               ;if DV negative, truncate step to
                sbb edx,-1              ;next higher integer
__set_V_step:   mov eax,txt_width
                imul dx                 ;EAX = DV base, ECX = DV step-DV base
                cwde

                pop edx                 ;EDX = DU base
                pop ebx                 ;EBX = DU step

                add edx,eax               
                mov UV_step[0*4],edx    ;00 = DU+base,DV+base
                add edx,ecx
                mov UV_step[1*4],edx    ;01 = DU+base,DV+base+step
                add ebx,eax
                mov UV_step[2*4],ebx    ;10 = DU+base+step,DV+base
                add ebx,ecx
                mov UV_step[3*4],ebx    ;11 = DU+base+step,DV+base+step

                mov ecx,CP_L
                sub ecx,plx             ;ECX = # of left-clipped pixels
                jg __clip_left

__left_clipped: mov eax,prx
                sub eax,CP_R            ;EAX = # of right-clipped pixels
                jg __clip_right

__index_bitmap: mov ecx,esi

                shr esi,16              ;set ESI -> texture pixel at (lu,lv)
                mov eax,esi
                mul txt_width           ;index initial texture scanline
                add eax,txt_bitmap
                mov esi,flu
                shr esi,16
                add esi,eax             ;add left edge U (source X)

                mov eax,plx
                mov edi,line_base        
                add edi,eax             ;set EDI -> beginning of dest scanline
                mov ebx,prx
                sub ebx,eax             ;set EBX = # of dest pixels - 1

                push ebp

                mov edx,flu

                mov eax,du              ;adjust U and DU for additive carry   
                or eax,eax              ;generation
                jns __DU_positive
                neg eax
                not edx                 ;(negate and subtract 1)
__DU_positive:  shl eax,16
                shl edx,16

                mov ebp,dv              ;adjust V and DV for additive carry
                or ebp,ebp              ;generation
                jns __DV_positive
                neg ebp
                not ecx                 ;(negate and subtract 1)
__DV_positive:  shl ebp,16
                shl ecx,16

                push ebx                ;set [esp] = pixel count-1
                xor ebx,ebx             ;initialize EBX = 0

        ;
        ;Inverse transform scanline with transparency
        ;

SCAN_OUT        MACRO       
                mov bl,BYTE PTR [esi]
                cmp bl,PAL_TRANSPARENT
                je @F
                mov BYTE PTR [edi+INDEX],bl
@@:             
                xor ebx,ebx             ;clear advance table index
                add edx,eax             ;U += DU                  
                adc ebx,ebx             ;shift carry into index   
                add ecx,ebp             ;V += DV                  
                adc ebx,ebx             ;shift carry into index   
                add esi,UV_step[ebx*4]  ;advance in both U and V
                ENDM

                PARTIAL_UNROLL scan_write,SCAN_OUT,6,1,DWORD PTR [esp]

__end_line:     add esp,4               ;remove iteration counter from stack
                pop ebp                 ;restore stack frame

__next_line:    mov edi,CP_W
                add line_base,edi

                pop edi
                pop esi
                pop edx
                pop ecx
                pop ebx
                pop eax

        ;
        ;Exit if no more scanlines
        ;

                dec line_cnt
                js __exit
                jz __last

        ;
        ;Calculate new X, U, and V vals for both edges, stepping
        ;across vertices when necessary to find next scanline
        ;

                dec lcnt
                jz __step_left

                add eax,ldx
                add ecx,ldu
                add esi,ldv

__left_stepped: dec rcnt
                jz __step_right

                add ebx,rdx
                add edx,rdu
                add edi,rdv

                jmp __do_line

__exit:         ret

        ;
        ;Do last line without switching edges
        ;

__last:         add eax,ldx
                add ecx,ldu
                add esi,ldv

                add ebx,rdx
                add edx,rdu
                add edi,rdv

                jmp __do_line

        ;
        ;Clip CX pixels from left edge of scanline
        ;

__clip_left:    add plx,ecx             ;add pixel count to left endpoint X

                shl ecx,16              ;convert to FP

                mov eax,du
                FPMUL ecx               ;adjust U
                add flu,eax

                mov eax,dv
                FPMUL ecx               ;adjust V
                add esi,eax
                
                jmp __left_clipped

        ;
        ;Clip AX pixels from right edge of scanline
        ;

__clip_right:   sub prx,eax             ;subtract AX from line width
                jmp __index_bitmap

        ;
        ;Step across left edge vertex
        ;

__step_left:    push ebx
                push edx

                mov ebx,lnxt
                mov lcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                sub esi,SIZE VERTEX2D
                cmp esi,vlist_beg
                jge __step_lnxt
                mov esi,vlist_end
                sub esi,SIZE VERTEX2D
__step_lnxt:    mov lnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].vy        ;ECX = edge bottom Y
                mov edx,[ebx].vy        ;EDX = edge top Y

                sub ecx,edx             ;if edge flat, force delta=1
                cmp ecx,1               ;(possible only at bottom scan line)
                adc ecx,0

                mov lcnt,ecx            ;set left edge pixel count

                mov edx,[esi].vx        ;get size of edge in X
                sub edx,[ebx].vx
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldx,eax             ;set left DX

                mov ecx,lcnt

                mov edx,[esi].u         ;get size of edge in U
                sub edx,[ebx].u
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldu,eax             ;set left DU

                mov ecx,lcnt

                mov edx,[esi].v         ;get size of edge in V
                sub edx,[ebx].v
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldv,eax             ;set left DV

                mov eax,[ebx].vx        
                shl eax,16              ;convert X to fixed-point val
                add eax,8000h           ;pre-round by adding +0.5

                mov ecx,[ebx].u
                shl ecx,16              ;convert U to fixed-point val
                add ecx,8000h           ;pre-round by adding +0.5

                mov esi,[ebx].v
                shl esi,16              ;convert V to fixed-point val
                add esi,8000h           ;pre-round by adding +0.5

                pop edx
                pop ebx
                jmp __left_stepped

        ;
        ;Step across right edge vertex
        ;

__step_right:   push eax
                push ecx
                
                mov ebx,rnxt
                mov rcur,ebx            ;EBX -> vertex at top of edge

                mov edi,ebx
                add edi,SIZE VERTEX2D
                cmp edi,vlist_end
                jl __step_rnxt
                mov edi,vlist_beg
__step_rnxt:    mov rnxt,edi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[edi].vy        ;ECX = edge bottom Y
                mov edx,[ebx].vy        ;EDX = edge top Y

                sub ecx,edx             ;if edge flat, force delta=1
                cmp ecx,1               ;(possible only at bottom scan line)
                adc ecx,0

                mov rcnt,ecx            ;set right edge pixel count

                mov edx,[edi].vx        ;get size of edge in X
                sub edx,[ebx].vx
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdx,eax             ;set right DX

                mov ecx,rcnt

                mov edx,[edi].u         ;get size of edge in U
                sub edx,[ebx].u
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdu,eax             ;set right DU

                mov ecx,rcnt

                mov edx,[edi].v         ;get size of edge in V
                sub edx,[ebx].v
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdv,eax             ;set right DV

                mov edx,[ebx].u
                shl edx,16              ;convert U to fixed-point val
                add edx,8000h           ;pre-round by adding +0.5

                mov edi,[ebx].v
                shl edi,16              ;convert V to fixed-point val
                add edi,8000h           ;pre-round by adding +0.5

                mov ebx,[ebx].vx        
                shl ebx,16              ;convert X to fixed-point val
                add ebx,8000h           ;pre-round by adding +0.5

                pop ecx
                pop eax
                jmp __do_line

__unity_case:   test flags,ST_XLAT      ;draw without scaling or rotation
                jz __unity_norm

                invoke VFX_shape_translate_draw,DestPane,shape_table,\
                       shape_number,hotX,hotY
                jmp __exit

__unity_norm:   invoke VFX_shape_draw,DestPane,shape_table,shape_number,\
                       hotX,hotY
                ret

                ASSUME esi:PPANE
                ASSUME ebx:PWIN
                ASSUME edi:NOTHING

VFX_shape_transform ENDP

                ENDIF

;----------------------------------------------------------------------------
;
; void cdecl VFX_shape_area_translate (PANE *pane,
;   void *shape_table, LONG shape_number, LONG hotX, LONG hotY,
;   void *buffer, LONG rot, LONG x_scale, LONG y_scale, LONG flags,
;   void *lookaside)
;
; This function operates exactly as does VFX_shape_transform(), but 
; instead of drawing the transformed shape, performs a destination color
; translation via *lookaside at each non-transparent pixel in the transformed
; shape.  The actual color information in the shape image buffer is ignored.
; Consequently, the ST_XLAT flag has no effect on the behavior of this 
; function.
;
; Note that if the shape has any transparent areas at all, they will be
; rendered internally as color 65534 (0xfffe).  This color will always be
; treated as transparent during the inverse transformation pass.
;
;----------------------------------------------------------------------------

                IF do_VFX_shape_area_translate

VFX_shape_area_translate PROC STDCALL USES ebx esi edi es,\
                DestPane:PTR PANE, shape_table:PTR VFX_SHAPETABLE, \
                shape_number:S32, hotX:S32, hotY:S32, \
                buffer:PTR, rot:S32, x_scale:S32, y_scale:S32, \
                flags, xlat_LUT:PTR
                
                LOCAL bufwnd:VFX_WINDOW
                LOCAL buf:PANE
                LOCAL pt_in:VFX_POINT
                LOCAL pt_out:VFX_POINT
                LOCAL pt_origin:VFX_POINT

                LOCAL sw,sh,comp_x,comp_y
                LOCAL txt_width
                LOCAL txt_bitmap
                LOCAL line_base
                LOCAL vlist_beg
                LOCAL vlist_end
                LOCAL v_top
                LOCAL lcur
                LOCAL rcur
                LOCAL lnxt
                LOCAL rnxt
                LOCAL lcnt
                LOCAL rcnt
                LOCAL line_cnt
                LOCAL line_y
                LOCAL lx
                LOCAL rx
                LOCAL lu
                LOCAL ru
                LOCAL lv
                LOCAL rv
                LOCAL ldx
                LOCAL rdx
                LOCAL ldu
                LOCAL rdu
                LOCAL ldv
                LOCAL rdv
                LOCAL plx
                LOCAL prx
                LOCAL du
                LOCAL dv
                LOCAL flu
                LOCAL    pixel_pitch
                LOCAL    bytes_per_pixel

                LOCAL    CP_L   ;Leftmost pixel in Window coord.
                LOCAL    CP_T   ;Top
                LOCAL    CP_R   ;Right
                LOCAL    CP_B   ;Bottom
              
                LOCAL    CP_A   ;Base address of Clipped Pane
                LOCAL    CP_BW  ;Width of underlying window (bytes)
                LOCAL    CP_W   ;Width of underlying window (pixels)
                
                LOCAL    CP_CX  ;Window x coord. = Pane x coord. + CP_CX
                LOCAL    CP_CY  ;Window y coord. = Pane x coord. + CP_CY

                cld
                push ds
                pop es
              
                invoke VFX_shape_resolution,shape_table,shape_number
                
                mov ecx,eax                 ;get overall shape width
                shr eax,16
                dec eax
                jnz __set_w
                mov eax,2                   ;(1-pixel shape treated as 3 wide)
__set_w:        mov sw,eax                  
                
                and ecx,0ffffh              ;get overall shape height
                dec ecx
                jnz __set_h
                mov ecx,2                   ;(1-line shape treated as 3 high)
__set_h:        mov sh,ecx                  
                
                ASSUME ebx:PWIN             ;assign pane/window for 1st pass
                ASSUME esi:PPANE
                
                lea ebx,bufwnd
                lea esi,buf
                
                mov [esi].window,ebx
                
                mov edx,buffer
                mov [ebx].buffer,edx
                
                mov [esi].x0,0
                mov vert0.u,0
                mov vert3.u,0
                
                mov [esi].y0,0
                mov vert0.v,0
                mov vert1.v,0
                
                mov [ebx].x_max,eax
                mov [esi].x1,eax
                mov vert1.u,eax
                mov vert2.u,eax
                
                mov [ebx].y_max,ecx
                mov [esi].y1,ecx
                mov vert2.v,ecx
                mov vert3.v,ecx
                
                invoke VFX_shape_minxy,shape_table,shape_number
                
                mov ebx,eax
                cwde
                neg eax
                mov pt_origin.y,eax          ;get hotspot offset from upper-left
                
                sar ebx,16
                neg ebx
                mov pt_origin.x,ebx
                
                test flags,ST_REUSE
                jnz __pass_2
                
                invoke VFX_pane_wipe,ADDR buf,PAL_TRANSPARENT

                invoke VFX_shape_draw,ADDR buf,shape_table,shape_number,\
                       pt_origin.x,pt_origin.y
                
__pass_2:       
                CLIP_PANE_TO_WINDOW DestPane

                mov eax,hotX
                sub eax,pt_origin.x
                mov comp_x,eax
                
                mov eax,hotY
                sub eax,pt_origin.y
                mov comp_y,eax
                
                mov pt_in.x,0
                mov pt_in.y,0
                invoke VFX_point_transform,ADDR pt_in,ADDR pt_out,ADDR pt_origin,\
                       rot,x_scale,y_scale
                mov eax,pt_out.x
                add eax,comp_x
                mov vert0.vx,eax
                mov eax,pt_out.y
                add eax,comp_y
                mov vert0.vy,eax

                mov eax,sw
                mov pt_in.x,eax
                mov pt_in.y,0
                invoke VFX_point_transform,ADDR pt_in,ADDR pt_out,ADDR pt_origin,\
                       rot,x_scale,y_scale
                mov eax,pt_out.x
                add eax,comp_x
                mov vert1.vx,eax
                mov eax,pt_out.y
                add eax,comp_y
                mov vert1.vy,eax

                CONVERT_QUAD_PANE_TO_WINDOW vert0.vx,vert0.vy, vert1.vx,vert1.vy

                mov eax,sw
                mov ebx,sh
                mov pt_in.x,eax
                mov pt_in.y,ebx
                invoke VFX_point_transform,ADDR pt_in,ADDR pt_out,ADDR pt_origin,\
                       rot,x_scale,y_scale
                mov eax,pt_out.x
                add eax,comp_x
                mov vert2.vx,eax
                mov eax,pt_out.y
                add eax,comp_y
                mov vert2.vy,eax
                
                mov eax,sh
                mov pt_in.x,0
                mov pt_in.y,eax
                invoke VFX_point_transform,ADDR pt_in,ADDR pt_out,ADDR pt_origin,\
                       rot,x_scale,y_scale
                mov eax,pt_out.x
                add eax,comp_x
                mov vert3.vx,eax
                mov eax,pt_out.y
                add eax,comp_y
                mov vert3.vy,eax

                CONVERT_QUAD_PANE_TO_WINDOW vert2.vx,vert2.vy, vert3.vx,vert3.vy

                ASSUME ebx:PWIN

                lea ebx,bufwnd
                mov eax,[ebx].buffer    ;copy buffer pointer
                mov txt_bitmap,eax
                mov ecx,[ebx].x_max    ; = windowp->x_max+1
                inc ecx                 ;   - windowp->wnd_x0
                mov txt_width,ecx       ;store line size

                ASSUME ebx:PVERTEX2D
                ASSUME esi:PVERTEX2D
                ASSUME edi:PVERTEX2D

                push ds
                pop es

                mov ebx,OFFSET vert0    ;EBX -> list of VERTEX strcts
                mov eax,ebx
                add eax,(SIZE VERTEX2D) * 4
;was                add eax,80              ;4 vertices * 20 bytes/VERTEX
                mov vlist_beg,ebx      
                mov vlist_end,eax       ;BX + VCnt*SIZE VERTEX -> end of list

        ;
        ;Find top and bottom vertices; perform Sutherland-Cohen
        ;clipping on output quadrangle
        ;

                mov esi,32767           ;ESI = top vertex Y
                mov edi,-32768          ;EDI = bottom vertex Y

                mov ecx,1111b           ;ECX = S-C "and" result for polygon

__vertex_sort:  mov edx,0               ;EDX = S-C flags for this vertex

                mov eax,[ebx].vx
                sub eax,CP_L
                shld edx,eax,1

                mov eax,CP_R
                sub eax,[ebx].vx
                shld edx,eax,1

                mov eax,[ebx].vy
                sub eax,CP_T
                shld edx,eax,1

                mov eax,CP_B
        	sub eax,[ebx].vy
        	shld edx,eax,1

                mov eax,[ebx].vy

                cmp eax,esi             ;keep track of top and bottom vertices
                jg __not_top
                mov esi,eax
                mov v_top,ebx

__not_top:      cmp eax,edi
                jl __not_btm
                mov edi,eax

__not_btm:      and ecx,edx
                
                add ebx,SIZE VERTEX2D
                cmp ebx,vlist_end
                jne __vertex_sort

                or ecx,ecx              ;all vertices to one side of window?
                jnz __exit              ;yes, polygon fully clipped

                mov eax,v_top           ;else init right, left vertices = top
                mov lnxt,eax
                mov rnxt,eax

                mov line_y,esi          ;init scanline Y = top vertex Y

                cmp edi,esi             ;is polygon flat?
                je __exit               ;yes, don't draw it

        ;
        ;Calculate initial edge positions & stepping vals for
        ;left and right edges
        ;

__init_left:    mov ebx,lnxt
                mov lcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                sub esi,SIZE VERTEX2D
                cmp esi,vlist_beg
                jge __init_lnxt
                mov esi,vlist_end
                sub esi,SIZE VERTEX2D
__init_lnxt:    mov lnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].vy        ;ECX = edge bottom Y
                mov edx,[ebx].vy        ;EDX = edge top Y

                cmp edx,CP_T            ;skip edge if above viewport
                jge __set_l_pcnt
                cmp ecx,CP_T
                jle __init_left         ;(bottom vertex shared w/next edge)

__set_l_pcnt:   sub ecx,edx             ;is edge flat?
                jz __init_left          ;yes, advance one edge left

                mov lcnt,ecx            ;set left edge pixel count

                mov edx,[esi].vx        ;get size of edge in X
                sub edx,[ebx].vx
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldx,eax             ;set left DX
                
                mov ecx,lcnt

                mov edx,[esi].u         ;get size of edge in U
                sub edx,[ebx].u
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldu,eax             ;set left DU

                mov ecx,lcnt

                mov edx,[esi].v         ;get size of edge in V
                sub edx,[ebx].v
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldv,eax             ;set left DV

                mov edx,[ebx].vx        ;convert X, U, and V to fixed-point
                shl edx,16              ;pre-round by adding +0.5 to all
                add edx,8000h           
                mov lx,edx

                mov edx,[ebx].u
                shl edx,16
                add edx,8000h
                mov lu,edx

                mov edx,[ebx].v
                shl edx,16
                add edx,8000h
                mov lv,edx

__init_right:   mov ebx,rnxt
                mov rcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                add esi,SIZE VERTEX2D
                cmp esi,vlist_end
                jl __init_rnxt
                mov esi,vlist_beg
__init_rnxt:    mov rnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].vy        ;ECX = edge bottom Y
                mov edx,[ebx].vy        ;EDX = edge top Y

                cmp edx,CP_T            ;skip edge if above viewport
                jge __set_r_pcnt
                cmp ecx,CP_T
                jle __init_right        ;(bottom vertex shared w/next edge)

__set_r_pcnt:   sub ecx,edx             ;is edge flat?
                jz __init_right         ;yes, advance one edge right

                mov rcnt,ecx            ;set right edge pixel count

                mov edx,[esi].vx        ;get size of edge in X
                sub edx,[ebx].vx
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdx,eax             ;set right DX
                
                mov ecx,rcnt

                mov edx,[esi].u         ;get size of edge in U
                sub edx,[ebx].u
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdu,eax             ;set right DU

                mov ecx,rcnt

                mov edx,[esi].v         ;get size of edge in U
                sub edx,[ebx].v
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdv,eax             ;set right DV

                mov edx,[ebx].vx        ;convert X,U, and V to fixed-point
                shl edx,16              ;pre-round by adding +0.5 to all
                add edx,8000h
                mov rx,edx

                mov edx,[ebx].u
                shl edx,16
                add edx,8000h
                mov ru,edx

                mov edx,[ebx].v
                shl edx,16
                add edx,8000h
                mov rv,edx

        ;
        ;Set scanline count; clip against bottom of window
        ;

                mov eax,CP_B
                sub eax,line_y

                sub edi,CP_B
                jg __clip_bottom

                add eax,edi
__clip_bottom:  mov line_cnt,eax

        ;
        ;Clip against top of window
        ;

                mov eax,CP_T
                sub eax,line_y
                jle __set_Y_base

                sub line_cnt,eax

                mov ecx,CP_T
                mov line_y,ecx
                mov ebx,lcur
                sub ecx,[ebx].vy
                sub lcnt,ecx

                shl ecx,16              ;ECX = # of pixels to clip from left

                mov eax,ldx             ;lx = lx + ECX * ldx
                FPMUL ecx
                add lx,eax

                mov eax,ldu             ;lu = lu + ECX * ldu
                FPMUL ecx
                add lu,eax

                mov eax,ldv             ;lv = lv + ECX * ldv
                FPMUL ecx
                add lv,eax

                mov ecx,CP_T
                mov ebx,rcur
                sub ecx,[ebx].vy
                sub rcnt,ecx

                shl ecx,16              ;ECX = # of pixels to clip from right

                mov eax,rdx             ;rx = rx + ECX * rdx
                FPMUL ecx
                add rx,eax

                mov eax,rdu             ;ru = ru + ECX * rdu
                FPMUL ecx
                add ru,eax

                mov eax,rdv             ;rv = rv + ECX * rdv
                FPMUL ecx
                add rv,eax

        ;
        ;Set window base address and loop variables
        ;

__set_Y_base:   GET_WINDOW_ADDRESS 0,line_y
                mov line_base,eax

                mov eax,lx
                mov ebx,rx
                mov ecx,lu
                mov edx,ru
                mov esi,lv
                mov edi,rv

        ;
        ;Trace edges & plot scanlines ...
        ;

__do_line:      push eax                ;save LX
                push ebx                ;save RX
                push ecx                ;save LU
                push edx                ;save RU
                push esi                ;save LV
                push edi                ;save RV

                cmp ebx,eax             ;sort X, U, and V left-to-right
                jg __XUV_sorted

                xchg eax,ebx
                xchg ecx,edx
                xchg esi,edi

__XUV_sorted:   sar eax,16              ;(preserve sign)
                cmp eax,CP_R
                jg __next_line

                sar ebx,16              ;(preserve sign)
                cmp ebx,CP_L
                jl __next_line

                mov plx,eax
                mov prx,ebx

                mov flu,ecx             ;save left source X (U)
                
                sub ebx,eax             ;EBX = # of pixels in scanline - 1
                jz __index_bitmap       ;(single-pixel line)

                push ebx

                sub edx,ecx             ;EDX = ru-lu
                FPDIV ebx
                mov du,eax              
                shld edx,eax,16

                pop ebx

                and eax,0ffffh
                and edx,0ffffh

                mov ecx,1               ;assume DU positive
                test edx,8000h
                jz __set_U_step
                or edx,0ffff0000h
                neg ecx
                cmp eax,1               ;if DU negative, truncate step to
                sbb edx,-1              ;next higher integer
__set_U_step:   add ecx,edx

                push ecx
                push edx

                sub edi,esi             ;EDI = rv-lv
                mov edx,edi
                FPDIV ebx
                mov dv,eax
                shld edx,eax,16

                and eax,0ffffh
                and edx,0ffffh

                mov ecx,txt_width       ;assume DV positive
                test edx,8000h
                jz __set_V_step
                neg ecx                  
                cmp eax,1               ;if DV negative, truncate step to
                sbb edx,-1              ;next higher integer
__set_V_step:   mov eax,txt_width
                imul dx                 ;EAX = DV base, ECX = DV step-DV base
                cwde

                pop edx                 ;EDX = DU base
                pop ebx                 ;EBX = DU step

                add edx,eax               
                mov UV_step[0*4],edx   ;00 = DU+base,DV+base
                add edx,ecx
                mov UV_step[1*4],edx   ;01 = DU+base,DV+base+step
                add ebx,eax
                mov UV_step[2*4],ebx   ;10 = DU+base+step,DV+base
                add ebx,ecx
                mov UV_step[3*4],ebx   ;11 = DU+base+step,DV+base+step

                mov ecx,CP_L
                sub ecx,plx             ;ECX = # of left-clipped pixels
                jg __clip_left

__left_clipped: mov eax,prx
                sub eax,CP_R            ;EAX = # of right-clipped pixels
                jg __clip_right

__index_bitmap: mov ecx,esi

                shr esi,16              ;set ESI -> texture pixel at (lu,lv)
                mov eax,esi
                mul txt_width           ;index initial texture scanline
                add eax,txt_bitmap
                mov esi,flu
                shr esi,16
                add esi,eax             ;add left edge U (source X)

                mov eax,plx
                mov edi,line_base        
                add edi,eax             ;set EDI -> beginning of dest scanline
                mov ebx,prx
                sub ebx,eax             ;set EBX = # of dest pixels - 1

                push ebp

                mov edx,flu

                mov eax,du              ;adjust U and DU for additive carry   
                or eax,eax              ;generation
                jns __DU_positive
                neg eax
                not edx                 ;(negate and subtract 1)
__DU_positive:  shl eax,16
                shl edx,16

                push eax                ;free up EAX and set to xlat_LUT
                mov eax,xlat_LUT

                mov ebp,dv              ;adjust V and DV for additive carry
                or ebp,ebp              ;generation
                jns __DV_positive
                neg ebp
                not ecx                 ;(negate and subtract 1)
__DV_positive:  shl ebp,16
                shl ecx,16

                push ebx                ;set [esp] = pixel count-1
                xor ebx,ebx             ;initialize EBX = 0

        ;
        ;Inverse transform scanline with transparency
        ;

SCAN_OUT        MACRO       
                mov bl,BYTE PTR [esi]
                cmp bl,PAL_TRANSPARENT
                je @F

                mov bl,BYTE PTR [edi+INDEX]
                mov bl,BYTE PTR [eax][ebx]
                mov BYTE PTR [edi+INDEX],bl
@@:             
                xor ebx,ebx               ;clear advance table index
                add edx,DWORD PTR [esp+4] ;U += DU                  
                adc ebx,ebx               ;shift carry into index   
                add ecx,ebp               ;V += DV                  
                adc ebx,ebx               ;shift carry into index   
                add esi,UV_step[ebx*4]   ;advance in both U and V
                ENDM

                PARTIAL_UNROLL scan_write,SCAN_OUT,6,1,DWORD PTR [esp]

__end_line:     add esp,8               ;remove iteration counter from stack
                pop ebp                 ;restore stack frame

__next_line:    mov edi,CP_W
                add line_base,edi

                pop edi
                pop esi
                pop edx
                pop ecx
                pop ebx
                pop eax

        ;
        ;Exit if no more scanlines
        ;

                dec line_cnt
                js __exit
                jz __last

        ;
        ;Calculate new X, U, and V vals for both edges, stepping
        ;across vertices when necessary to find next scanline
        ;

                dec lcnt
                jz __step_left

                add eax,ldx
                add ecx,ldu
                add esi,ldv

__left_stepped: dec rcnt
                jz __step_right

                add ebx,rdx
                add edx,rdu
                add edi,rdv

                jmp __do_line

__exit:         ret

        ;
        ;Do last line without switching edges
        ;

__last:         add eax,ldx
                add ecx,ldu
                add esi,ldv

                add ebx,rdx
                add edx,rdu
                add edi,rdv

                jmp __do_line

        ;
        ;Clip CX pixels from left edge of scanline
        ;

__clip_left:    add plx,ecx             ;add pixel count to left endpoint X

                shl ecx,16              ;convert to FP

                mov eax,du
                FPMUL ecx               ;adjust U
                add flu,eax

                mov eax,dv
                FPMUL ecx               ;adjust V
                add esi,eax
                
                jmp __left_clipped

        ;
        ;Clip AX pixels from right edge of scanline
        ;

__clip_right:   sub prx,eax             ;subtract AX from line width
                jmp __index_bitmap

        ;
        ;Step across left edge vertex
        ;

__step_left:    push ebx
                push edx

                mov ebx,lnxt
                mov lcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                sub esi,SIZE VERTEX2D
                cmp esi,vlist_beg
                jge __step_lnxt
                mov esi,vlist_end
                sub esi,SIZE VERTEX2D
__step_lnxt:    mov lnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].vy        ;ECX = edge bottom Y
                mov edx,[ebx].vy        ;EDX = edge top Y

                sub ecx,edx             ;if edge flat, force delta=1
                cmp ecx,1               ;(possible only at bottom scan line)
                adc ecx,0

                mov lcnt,ecx            ;set left edge pixel count

                mov edx,[esi].vx        ;get size of edge in X
                sub edx,[ebx].vx
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldx,eax             ;set left DX

                mov ecx,lcnt

                mov edx,[esi].u         ;get size of edge in U
                sub edx,[ebx].u
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldu,eax             ;set left DU

                mov ecx,lcnt

                mov edx,[esi].v         ;get size of edge in V
                sub edx,[ebx].v
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldv,eax             ;set left DV

                mov eax,[ebx].vx        
                shl eax,16              ;convert X to fixed-point val
                add eax,8000h           ;pre-round by adding +0.5

                mov ecx,[ebx].u
                shl ecx,16              ;convert U to fixed-point val
                add ecx,8000h           ;pre-round by adding +0.5

                mov esi,[ebx].v
                shl esi,16              ;convert V to fixed-point val
                add esi,8000h           ;pre-round by adding +0.5

                pop edx
                pop ebx
                jmp __left_stepped

        ;
        ;Step across right edge vertex
        ;

__step_right:   push eax
                push ecx
                
                mov ebx,rnxt
                mov rcur,ebx            ;EBX -> vertex at top of edge

                mov edi,ebx
                add edi,SIZE VERTEX2D
                cmp edi,vlist_end
                jl __step_rnxt
                mov edi,vlist_beg
__step_rnxt:    mov rnxt,edi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[edi].vy        ;ECX = edge bottom Y
                mov edx,[ebx].vy        ;EDX = edge top Y

                sub ecx,edx             ;if edge flat, force delta=1
                cmp ecx,1               ;(possible only at bottom scan line)
                adc ecx,0

                mov rcnt,ecx            ;set right edge pixel count

                mov edx,[edi].vx        ;get size of edge in X
                sub edx,[ebx].vx
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdx,eax             ;set right DX

                mov ecx,rcnt

                mov edx,[edi].u         ;get size of edge in U
                sub edx,[ebx].u
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdu,eax             ;set right DU

                mov ecx,rcnt

                mov edx,[edi].v         ;get size of edge in V
                sub edx,[ebx].v
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdv,eax             ;set right DV

                mov edx,[ebx].u
                shl edx,16              ;convert U to fixed-point val
                add edx,8000h           ;pre-round by adding +0.5

                mov edi,[ebx].v
                shl edi,16              ;convert V to fixed-point val
                add edi,8000h           ;pre-round by adding +0.5

                mov ebx,[ebx].vx        
                shl ebx,16              ;convert X to fixed-point val
                add ebx,8000h           ;pre-round by adding +0.5

                pop ecx
                pop eax
                jmp __do_line

                ASSUME esi:PPANE
                ASSUME ebx:PWIN
                ASSUME edi:NOTHING

VFX_shape_area_translate ENDP

                ENDIF

;-----------------------------------------------------------------------------
;
; void cdecl VFX_shape_visible_rectangle(void *shape_table,
;                           long shape_number, int hotX, int hotY,
;                           long mirror, long *rectangle)
;
; This function traces a shape and returns a smallest rectangle which
; will hold the visible portion of the shape.
; 
; The shape parameter specifies the shape, which must be in VFX Shape Format.
;
; The hotX and hotY parameters specify the location where the shape is to be
; drawn.  The shape's hot spot will end up at the specified location.
;
; The mirror parameter holds flags to mirror the shape in X, Y or both.
;
; The rectangle parameter must point to an array of at least 4 DWORDS which
; will receive the rectangle coordinates.
;
; For more information, see the "VFX Shape Format Description".
;
;-----------------------------------------------------------------------------

                IF do_VFX_shape_visible_rectangle

VFX_shape_visible_rectangle     \
            PROC STDCALL USES ebx esi edi es,\
            shape_table:PTR VFX_SHAPETABLE, shape_number:S32, hotX:S32, hotY:S32, \
            mirror:S32, rectangle:PTR VFX_RECT

            LOCAL shape:PTR
            LOCAL x0,y0,x1,y1
            LOCAL vx0,vy0,vx1,vy1

            cld
            push ds
            pop es

        ; setup visible rectangle coordinates for NULL rectangle

            mov     vx0,0
            mov     vy0,0
            mov     vx1,0
            mov     vy1,0

        ; get shape pointer

            ASSUME  esi:nothing
            mov     esi,[shape_number]  ; get selected shape offset address
            shl     esi,3               ;   mult by size of 2 longs
            add     esi,SIZEOF VFX_SHAPETABLE;  skip over shape table header       
            add     esi,[shape_table]   ;   add base address
            mov     esi,[esi]           ; get selected shape offset
            add     esi,[shape_table]   ; setup ptr to selected shape
            mov     shape,esi           ; save shape ptr

        ; ShapePtr (esi) = shape

            mov     esi,shape

            mov     eax,[esi].SHAPEHEADER.xmin  ; read minX from header
            add     eax,hotX
            mov     x0,eax              ; x0 = min possibly visible x

            mov     eax,[esi].SHAPEHEADER.ymin  ; read minY from header
            mov     ebx,eax
            add     eax,hotY
            mov     y0,eax              ; y0 = min possibly visible y

        ; pass up maxX (not needed)

            mov     eax,[esi].SHAPEHEADER.xmax  ; read maxX from header
            add     eax,hotX
            mov     x1,eax              ; x1 = max possibly visible x

            mov     eax,[esi].SHAPEHEADER.ymax  ; read maxY from header
            mov     ecx,eax
            add     ecx,hotY
            mov     y1,ecx              ; y1 = max possibly visible y

        ; linecount (ebx) = maxY + 1 - minY; if linecount <= 0, exit

            inc     eax
            sub     eax,ebx
            mov     ebx,eax
            jle     Exit

            add     esi,SIZEOF SHAPEHEADER

        ; setup visible rectangle coordinates for adjustment loop

            mov     vx0,7fffffffh       ;largest positive number
            mov     vy0,7fffffffh

            mov     vx1,80000000h       ;largest negative number
            mov     vy1,80000000h

        ; edx = y

            mov     edx,y0

lineLoop:

        ; edi = x

            mov     edi,x0

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket
            jnz     StringPacket
            jnc     EndPacket

SkipPacket:

        ; process skip packet

            LODSB_
            movzx   ecx,al

            add     edi,ecx

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket
            jnz     StringPacket
            jc      SkipPacket
            jnc     EndPacket

RunPacket:

        ; process run packet

            movzx   ecx,al
            LODSB_

        ; update visible rectangle if necessary

            MIN     vx0, edi

            add     edi,ecx

            MAX     vx1, edi

            MIN     vy0, edx
            MAX     vy1, edx

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket
            jnc     EndPacket
            jz      SkipPacket

StringPacket:

        ; process string packet

            movzx   ecx,al
            add     esi,ecx

        ; update visible rectangle if necessary

            MIN     vx0, edi

            add     edi,ecx

            MAX     vx1, edi

            MIN     vy0, edx
            MAX     vy1, edx

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket
            jnz     StringPacket
            jc      SkipPacket

EndPacket:

        ; prcoess end packet (do nothing)

        ; advance (edx) Y 

            inc     edx

        ; loop back for next line

            dec     ebx
            jnz     lineLoop

Exit:       
        ; adjust for mirroring

            mov     eax,[mirror]
            and     eax,VR_X_MIRROR
            jz      __check_y_mirror
                
            mov     eax,hotX
            add     eax,hotX
            mov     ebx,eax

            sub     eax,vx0
            sub     ebx,vx1

            mov     vx1,eax
            mov     vx0,ebx

__check_y_mirror:
            mov     eax,[mirror]
            and     eax,VR_Y_MIRROR
            jz      __save_coords

            mov     eax,hotY
            add     eax,hotY
            mov     ebx,eax

            sub     eax,vy0
            sub     ebx,vy1

            mov     vy1,eax
            mov     vy0,ebx

__save_coords:

        ; save visible rectangle coordinates in rectangle array

            mov     edi,[rectangle]

            mov     eax,vx0
            stosd

            mov     eax,vy0
            stosd

            mov     eax,vx1
            stosd

            mov     eax,vy1
            stosd

            xor     eax,eax
            ret

VFX_shape_visible_rectangle     \
            ENDP

            ENDIF


;--------------------------------------------------------------------------
;
; int VFX_shape_scan (PANE *panep, BYTE transparentColor,
;                     int  hotX, int hotY, VFX_SHAPETABLE *buffer)
;
; This function converts a raster image into a standard VFX shape, stored
; as the sole entry in a VFX shape table
;
; The panep parameter specifies the region containing the shape.
;
; The transparentColor parameter specifies the transparent color,
; i.e: the background color.
;
; The hotX and hotY parameters specify the location of the "hot spot"
;
; The buffer parameter specifies the user-provided shape buffer into
; which the shape table will be stored; or, if the parameter is NULL, it
; indicates that VFX_shape_scan() should calculate the required size 
; of the buffer, rather than converting the image to a shape table.
;                
; For more information, see the "VFX Shape Format Description".
;
; Return values:
;                                          
;--------------------------------------------------------------------------

                IF do_VFX_shape_scan

VFX_shape_scan PROC STDCALL USES ebx esi edi es,\
               panep:PPANE, transparentColor, hotX:S32, hotY:S32, \
               buffer:PTR VFX_SHAPETABLE

            LOCAL Ysize, paneWidth, paneHeight
            LOCAL lineY, count, shapeWidth

            LOCAL    CP_L   ;Leftmost pixel in Window coord.
            LOCAL    CP_T   ;Top
            LOCAL    CP_R   ;Right
            LOCAL    CP_B   ;Bottom
            
            LOCAL    CP_A   ;Base address of Clipped Pane
            LOCAL    CP_BW  ;Width of underlying window (bytes)
            LOCAL    CP_W   ;Width of underlying window (pixels)
            
            LOCAL    CP_CX  ;Window x coord. = Pane x coord. + CP_CX
            LOCAL    CP_CY  ;Window y coord. = Pane x coord. + CP_CY

            LOCAL    pixel_pitch
            LOCAL    bytes_per_pixel

            cld
            push ds
            pop es

            CLIP_PANE_TO_WINDOW panep

            ASSUME  esi:PPANE
            ASSUME  ebx:PWIN

        ; get panep (esi)
        ; windowp (ebx) = panep->win

            mov     esi,panep
            mov     ebx,[esi].window

        ; initialize SHP_ShapePtr (edi) address of shape buffer
        ; SHP_building = !(buffer == NULL)

            MOVE    SHP_building,edi,buffer
            or      edi,edi
            jz      pastStores

        ;
        ; JCM: Write header for VFX shape table with single entry (shape being
        ; grabbed)
        ;

            mov al,'1'          ;table version = 1.10
            STOSB_
            mov al,'.'
            STOSB_
            mov al,'1'
            STOSB_
            mov al,'0'
            STOSB_

            mov eax,1           ;1 shape in table
            STOSD_

            mov eax,16          ;16 bytes to shape definition
            STOSD_      

            mov eax,0           ;NULL color table (must be added seperately)
            STOSD_      

        ; write shape header for a null shape:
        ; (bounds) (origin) (0, 0), (-1, -1)

            mov     eax,[esi].x1
            sub     eax,[esi].x0
            shl     eax,16

            mov     ax,WORD PTR [esi].y1
            sub     ax,WORD PTR [esi].y0

            STOSD_                      ;SHAPEHEADER.bounds

            mov     eax,[hotX]
            shl     eax,16
            mov     ax,WORD PTR [hotY]

            STOSD_                      ;SHAPEHEADER.origin

            xor     eax,eax
            STOSD_                      ;SHAPEHEADER.xmin
            STOSD_                      ;SHAPEHEADER.ymin

            dec     eax
            STOSD_                      ;SHAPEHEADER.xmax
            STOSD_                      ;SHAPEHEADER.ymax

pastStores:

            ASSUME  esi:nothing

        ; convert hot spot from pane coordinates to window coordinates

            CONVERT_PAIR_PANE_TO_WINDOW hotX, hotY

        ; calculate width and height of clipped pane
        ; if width or height is less than one, return bad pane error

            mov     eax,CP_R
            inc     eax
            sub     eax,CP_L
            mov     paneWidth,eax

            mov     eax,CP_R
            inc     eax
            sub     eax,CP_L
            mov     paneHeight,eax
        ;
        ; Pass 1 -- determine SHP_minX, SHP_minY, SHP_maxX, SHP_maxY
        ;

        ; initialize SHP_minX and SHP_minY to MAXINT, SHP_maxX and SHP_maxY to MININT
        
            mov     eax,7FFFFFFFH
            mov     SHP_minX,eax
            mov     SHP_minY,eax

            neg     eax
            mov     SHP_maxX,eax
            mov     SHP_maxY,eax

        ; initialize SHP_LinePtr to the address of upper left-hand pixel of the scan pane

            GET_WINDOW_ADDRESS  CP_L, CP_T
            mov     SHP_LinePtr,eax
            mov     esi,eax

        ; for (lineY =  CP_T; lineY <= CP_B; lineY++)

            MOVE    lineY,eax,CP_T
            jmp     nextLine

lineLoop:

        ; prepare to scan the line from left to right: 
        ;   SHP_ScanPtr (edi) = SHP_LinePtr
        ;   count (ecx) = paneWidth
            
            MOVE    SHP_ScanPtr,edi,SHP_LinePtr
            MOVE    count,ecx,paneWidth

        ; scan line for image (non-background) pixels (left to right)

            mov     al,BYTE PTR transparentColor
            repe scasb

        ; if the line did not contain any image pixels, skip to bumpSHP_LinePtr

            je      bumpSHP_LinePtr

        ; the line contained image pixels, so update SHP_minY and SHP_maxY

            mov     eax,SHP_minY
            MIN     eax,lineY
            mov     SHP_minY,eax

            mov     eax,SHP_maxY
            MAX     eax,lineY
            mov     SHP_maxY,eax

        ; eax (left edge) = CP_R - count

            mov     eax,CP_R
            sub     eax,ecx
        
        ; if the left edge is left of SHP_minX, update SHP_minX

            MIN     eax,SHP_minX
            mov     SHP_minX,eax

        ; prepare to scan the line from right to left:
        ;   SHP_ScanPtr (edi) = SHP_LinePtr + paneWidth - 1
        ;   count (ecx) = paneWidth

            mov     eax,SHP_LinePtr
            add     eax,paneWidth
            dec     eax
            MOVE    SHP_ScanPtr,edi,eax
            MOVE    count,ecx,paneWidth

        ; find the last image pixel on the line by scanning from right to left

            mov     al,BYTE PTR transparentColor
            std
            repe scasb
            cld

        ; if the line was all blank (how?), skip to bumpSHP_LinePtr

            je      bumpSHP_LinePtr

        ; eax (right edge) = CP_L + count

            mov     eax,CP_L
            add     eax,ecx

        ; if the right edge is right of SHP_maxX, update SHP_maxX

            MAX     eax,SHP_maxX
            mov     SHP_maxX,eax

bumpSHP_LinePtr:

        ; advance SHP_LinePtr to the next line

            mov     eax,CP_W
            add     SHP_LinePtr,eax

        ; end for (lineY...)

            inc     lineY
nextLine:
            mov     eax,lineY
            cmp     eax,CP_B
            jle     lineLoop
            
        ;
        ; Pass 2 -- encode shape
        ;

        ; initialize shape pointer (edi) and write shape header to shape buffer

            mov     edi,buffer
            add     edi,16                      ;JCM: add size of table header
            cmp     edi,16                      ;was buffer NULL?
            je      skip_stores                 ;yes, don't write

            mov     eax,SHP_minX
            sub     eax,hotX
            mov     [edi].SHAPEHEADER.xmin,eax

            mov     eax,SHP_minY
            sub     eax,hotY
            mov     [edi].SHAPEHEADER.ymin,eax

            mov     eax,SHP_maxX
            sub     eax,hotX
            mov     [edi].SHAPEHEADER.xmax,eax

            mov     eax,SHP_maxY
            sub     eax,hotY
            mov     [edi].SHAPEHEADER.ymax,eax

skip_stores:

        ; update SHP_ShapePtr

            add     edi,SIZEOF SHAPEHEADER
            mov     SHP_ShapePtr,edi

        ; calculate shape width

            mov     eax,SHP_maxX
            inc     eax
            sub     eax,SHP_minX
            mov     shapeWidth,eax

        ; initialize line pointer to upper left-hand corner of image rectangle

            GET_WINDOW_ADDRESS SHP_minX, SHP_minY
            mov     esi,eax
            mov     SHP_LinePtr,esi

            ASSUME  ebx:nothing

        ; for (lineY = SHP_minY; lineY <= SHP_maxY; lineY++)

            MOVE    lineY,eax,SHP_minY
            jmp     nextLine2

lineLoop2:

        ; ScanLine (shapeWidth, transparentColor)

            INVOKE  ScanLine, shapeWidth, transparentColor, CP_L

        ; SHP_LinePtr += CP_W

            mov     eax,CP_W
            add     SHP_LinePtr,eax

        ; end for (lineY...) loop

            inc     lineY
nextLine2:
            mov     eax,lineY
            cmp     eax,SHP_maxY
            jle     lineLoop2

Exit:       

        ; return shape size

            mov     eax,SHP_ShapePtr
            sub     eax,buffer
            ret

VFX_shape_scan \
            ENDP

                ENDIF

;-----------------------------------------------------------------------------
;
; void cdecl VFX_shape_remap_colors (void *shape_table, ULONG shape_number)
;
; This function permanently remaps the colors in a shape using a lookaside
; table stored by VFX_shape_lookaside()
; 
; The shape parameter specifies the shape, which must be in VFX Shape Format.
;
; For more information, see the "VFX Shape Format Description".
;
;-----------------------------------------------------------------------------

                IF do_VFX_shape_remap_colors

VFX_shape_remap_colors PROC STDCALL USES ebx esi edi es,\
            shape_table:PTR VFX_SHAPETABLE, shape_number

            cld
            push ds
            pop es

        ; ShapePtr (esi) = shape

            ASSUME  esi:nothing
            mov     esi,[shape_number]  ; get selected shape offset address
            shl     esi,3               ;   mult by size of 2 longs
            add     esi,SIZEOF VFX_SHAPETABLE;  skip over shape table header       
            add     esi,[shape_table]   ;   add base address
            mov     esi,[esi]           ; get selected shape offset
            add     esi,[shape_table]   ; setup ptr to selected shape

        ; linecount (ebx) = maxY + 1 - minY; if linecount <= 0, exit

            ASSUME  ebx:nothing

            mov     ebx,[esi].SHAPEHEADER.ymin  ; read minY from header
            mov     eax,[esi].SHAPEHEADER.ymax  ; read maxY from header
            inc     eax
            sub     eax,ebx
            mov     ebx,eax
            jle     Exit

            add     esi,SIZEOF SHAPEHEADER

lineLoop:

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket
            jnz     StringPacket
            jnc     EndPacket

SkipPacket:

        ; process skip packet

            LODSB_
            movzx   ecx,al

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket
            jnz     StringPacket
            jc      SkipPacket
            jnc     EndPacket

RunPacket:

        ; process run packet

            movzx   ecx,al

            mov     eax,0
            mov     al,[esi]
            mov     al,lookaside[eax]
            mov     [esi],al
            inc     esi

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket
            jnc     EndPacket
            jz      SkipPacket

StringPacket:

        ; process string packet

            movzx   ecx,al
            mov     eax,0

StringPacketLoop:
            mov     al,[esi]
            mov     al,lookaside[eax]
            mov     [esi],al
            inc     esi

            loop    StringPacketLoop

        ; get token, adjust count, and branch to appropriate packet handler

            LODSB_
            shr     al,1
            ja      RunPacket
            jnz     StringPacket
            jc      SkipPacket

EndPacket:

        ; prcoess end packet (do nothing)

        ; loop back for next line

            dec     ebx
            jnz     lineLoop

Exit:       
            xor     eax,eax
            ret

VFX_shape_remap_colors \
            ENDP

            ENDIF



;----------------------------------------------------------------------------
;
; static void ScanLine (int count, BYTE background)
;
; This function, which is a part of VFX_shape_scan(), scans a line and 
; encodes it in VFX standard shape format.
;
; The state machine described by this table is used to encode the line.
;
;     Current   Current        Next      Action              
;     State     Pixel          State     Taken               
;     -------   ----------     -----     ------------------------
;
;     Start     None           End       Initialize FlushPacket()
;     Start     Background     Skip      Initialize FlushPacket()
;     Start     Previous       String1   Initialize FlushPacket()
;     Start     Other          String1   Initialize FlushPacket()
;
;     String1   None           End       Flush String Packet
;     String1   Background     Skip      Flush String Packet - 1
;     String1   Previous       Run
;     String1   Other          String2
;
;     String2   None           End       Flush String Packet
;     String2   Background     Skip      Flush String Packet - 1
;     String2   Previous       String3
;     String2   Other          String2
;
;     String3   None           End       Flush String Packet
;     String3   Background     Skip      Flush String Packet - 1
;     String3   Previous       Run       Flush String Packet - 3
;     String3   Other          String2                       
;
;     Run       None           End       Flush Run Packet
;     Run       Background     Skip      Flush Run Packet - 1
;     Run       Previous       Run                           
;     Run       Other          String1   Flush Run Packet - 1
;
;     Skip      None           End       Flush Skip Packet
;     Skip     *Background     Skip                          
;     Skip     *Previous       Skip                          
;     Skip      Other          String1   Flush Skip Packet - 1
;
;     End       None           Stop      Flush End Packet
;     End       Background     Stop      Flush End Packet
;     End       Previous       Stop      Flush End Packet
;     End       Other          Stop      Flush End Packet
;
; * In the Skip state, the previous pixel is a background pixel.
;
;----------------------------------------------------------------------------

ScanLine    PROC STDCALL USES ebx esi edi es, count, background, CP_L
            LOCAL packetType

Start:
            cld
            push ds
            pop es

            MOVE    SHP_ScanPtr,esi,SHP_LinePtr ; SHP_ScanPtr (esi) = SHP_LinePtr

            INVOKE  FlushPacket, INIT_, 0, CP_L

            mov     packetType,NONE_    ; packetType = NONE

            mov     ecx,count           ; if (!count) goto End_and_Stop
            or      ecx,ecx
            jz      End_and_Stop

            LODSB_                      ; pixel = *SHP_ScanPtr++
            dec     ecx                 ; count--
            mov     ah,al               ; previous = pixel

            cmp     ah,BYTE PTR background       
            jz      Skip                ; if (pixel == background) goto Skip

String1:
            mov     packetType,STRING_  ; packetType = STRING

            or      ecx,ecx
            jz      End_and_Stop        ; if (!count) goto End_and_Stop

            LODSB_                      ; pixel = *SHP_ScanPtr+
            dec     ecx                 ; count--;
            xor     al,ah               ; same = (previous == pixel)
            xor     ah,al               ; previous = pixel

            or      al,al               ; if (same) goto Run
            jz      Run

            cmp     ah,BYTE PTR background       
            jnz     String2             ; if (pixel != background) goto String2

            mov     SHP_ScanPtr,esi
            INVOKE  FlushPacket, STRING_, 1, CP_L

            jmp     Skip                ; goto Skip

String2:
            or      ecx,ecx
            jz      End_and_Stop        ; if (!count) goto End_and_Stop

            LODSB_                      ; pixel = *SHP_ScanPtr+ 
            dec     ecx                 ; count--;
            xor     al,ah               ; same = (previous == pixel)
            xor     ah,al               ; previous = pixel

            cmp     ah,BYTE PTR background       
            jnz     @F                  ; if (pixel != background) goto @@

            mov     SHP_ScanPtr,esi
            INVOKE  FlushPacket, STRING_, 1, CP_L

            jmp     Skip                ; goto Skip

@@:         or      al,al               ; if (!same) goto String2
            jnz     String2

String3:
            or      ecx,ecx
            jz      End_and_Stop        ; if (!count) goto End_and_Stop

            LODSB_                      ; pixel = *SHP_ScanPtr+ 
            dec     ecx                 ; count--;
            xor     al,ah               ; same = (previous == pixel)
            xor     ah,al               ; previous = pixel

            cmp     ah,BYTE PTR background       
            jnz     @F                  ; if (pixel != background) goto @@

            mov     SHP_ScanPtr,esi
            INVOKE  FlushPacket, STRING_, 1, CP_L

            jmp     Skip                ; goto Skip
@@:
            or      al,al               ; if (!same) goto String2
            jnz     String2

            mov     SHP_ScanPtr,esi
            INVOKE  FlushPacket, STRING_, 3, CP_L

Run:
            mov     packetType,RUN_     ; packetType = RUN
            or      ecx,ecx
            jz      End_and_Stop        ; if (!count) goto End_and_Stop

            LODSB_                      ; pixel = *SHP_ScanPtr+ 
            dec     ecx                 ; count--;
            xor     al,ah               ; same = (previous == pixel)
            jz      Run                 ; if (same) goto Run

            xor     ah,al               ; previous = pixel

            mov     SHP_ScanPtr,esi
            INVOKE  FlushPacket, RUN_, 1, CP_L

            cmp     ah,BYTE PTR background       
            jnz     String1             ; if (pixel != background) goto String1

Skip:
            mov     packetType,SKIP_    ; packetType = SKIP
            or      ecx,ecx
            jz      End_and_Stop        ; if (!count) goto End_and_Stop

            LODSB_                      ; pixel = *SHP_ScanPtr+  
            dec     ecx                 ; count--;
            xor     al,ah               ; same = (previous == pixel)
            jz      Skip                ; if (same) goto Skip

            xor     ah,al               ; previous = pixel

            mov     SHP_ScanPtr,esi
            INVOKE  FlushPacket, SKIP_, 1, CP_L

            jmp     String1             ; goto String1

End_and_Stop:
            mov     SHP_ScanPtr,esi
            INVOKE  FlushPacket, packetType, 0, CP_L

            INVOKE  FlushPacket, END_, 0, CP_L

            ret                         ; return

ScanLine    ENDP

;----------------------------------------------------------------------------
;
; static void FlushPacket (int packetType, int keep)
;
; This function, which is a part of ScanLine(), flushes the current packet
; leaving 'keep' bytes in the queue.
;
; esi (SHP_ScanPtr) is preserved, and is used for SHP_FlushPtr during this routine.
; edi (SHP_ShapePtr) is updated.
; eax (which contains previous) is preserved.
; ecx (which contains count) is preserved.
; edx is used and not restored.
;
;----------------------------------------------------------------------------

FlushPacket PROC STDCALL USES ebx esi edi es, packetType, keep, CP_L

            cld
            push ds
            pop es

            push    eax                 ; preserve previous pixel
            push    ecx                 ; preserve count

            mov     esi,SHP_FlushPtr        ; get SHP_FlushPtr
            mov     edi,SHP_ShapePtr        ; get SHP_ShapePtr

            mov     eax,packetType      ; dispatch to packet flusher

            cmp     eax,RUN_
            jz      FlushRun

            cmp     eax,STRING_
            jz      FlushString

            cmp     eax,SKIP_
            jz      FlushSkip

            cmp     eax,END_
            jz      FlushEnd

            cmp     eax,INIT_
            jnz     Exit

        ;
        ; Initialization call
        ;

Start:
            xor     eax,eax             ; initialize SHP_skipCount to 0 and exit
            mov     SHP_skipCount,eax

            MOVE    SHP_FlushPtr,esi,SHP_ScanPtr   ; initialize SHP_FlushPtr = SHP_ScanPtr
            jmp     Exit

        ;
        ; Flush a Run packet
        ;

FlushRun:
            mov     ebx,SHP_skipCount       ; if (SHP_skipCount (ebx) == 0),
            or      ebx,ebx             ;     branch around skipToRun
            jz      FlushRun2

skipToRun:
            mov     ecx,ebx             ; n (ecx) = min (SHP_skipCount (ebx), 255)
            MIN     ecx,255

            sub     ebx,ecx             ; SHP_skipCount -= n

            .if     SHP_building            ; store n-byte Skip packet

            mov     al,1
            STOSB_
            mov     al,cl
            STOSB_

            .else

            add     edi,2

            .endif

            add     esi,ecx             ; SHP_FlushPtr += n

            or      ebx,ebx             ; if (SHP_skipCount != 0) go back for more
            jnz     skipToRun

            mov     SHP_skipCount,ebx   ; update SHP_skipCount variable

FlushRun2:
            mov     ebx,SHP_ScanPtr     ; length (ebx) = 
            sub     ebx,esi             ;     SHP_ScanPtr - SHP_FlushPtr - keep
            sub     ebx,keep

            mov     eax,CP_L            ; x (eax) =
            add     eax,esi             ;     SHP_CP_L + SHP_FlushPtr - SHP_LinePtr
            sub     eax,SHP_LinePtr

            cmp     eax,SHP_minX        ; if (x < SHP_minX) SHP_minX = x
            jge     @F
            mov     SHP_minX,eax
@@:
            add     eax,ebx             ; x += length - 1
            dec     eax

            cmp     eax,SHP_maxX        ; if (x > SHP_maxX) SHP_maxX = x
            jle     FlushRunLoop
            mov     SHP_maxX,eax

            jmp     FlushRunNext

FlushRunLoop:
            mov     ecx,ebx             ; n (ecx) = min (length, 127)
            MIN     ecx,127

            .if     SHP_building        ; store n-byte Run packet

            mov     al,cl
            add     al,al
            STOSB_
            mov     al,[esi]
            STOSB_

            .else

            add     edi,2

            .endif

            add     esi,ecx             ; SHP_FlushPtr += n
            sub     ebx,ecx             ; length -= n

FlushRunNext:
            or      ebx,ebx             ; endwhile
            jnz     FlushRunLoop

            jmp     Exit                ; endcase

        ;
        ; Flush a String packet
        ;

FlushString:
            mov     ebx,SHP_skipCount       ; if (SHP_skipCount (ebx) == 0),
            or      ebx,ebx             ;     branch around skipToString
            jz      FlushString2

skipToString:
            mov     ecx,ebx             ; n (ecx) = min (SHP_skipCount (ebx), 255)
            MIN     ecx,255

            sub     ebx,ecx             ; SHP_skipCount -= n

            .if     SHP_building            ; store n-byte Skip packet

            mov     al,1
            STOSB_
            mov     al,cl
            STOSB_

            .else

            add     edi,2

            .endif

            add     esi,ecx             ; SHP_FlushPtr += n

            or      ebx,ebx             ; if (SHP_skipCount != 0) go back for more
            jnz     skipToString

            mov     SHP_skipCount,ebx   ; update SHP_skipCount variable

FlushString2:
            mov     ebx,SHP_ScanPtr     ; length (ebx) = 
            sub     ebx,esi             ;     SHP_ScanPtr - SHP_FlushPtr - keep
            sub     ebx,keep

            mov     eax,CP_L            ; x (eax) =
            add     eax,esi             ;     CP_L + SHP_FlushPtr - SHP_LinePtr
            sub     eax,SHP_LinePtr

            cmp     eax,SHP_minX            ; if (x < SHP_minX) SHP_minX = x
            jge     @F
            mov     SHP_minX,eax
@@:
            add     eax,ebx             ; x += length - 1
            dec     eax

            cmp     eax,SHP_maxX            ; if (x > SHP_maxX) SHP_maxX = x
            jle     FlushStringLoop
            mov     SHP_maxX,eax

            jmp     FlushStringNext          ; while (length)

FlushStringLoop:
            mov     ecx,ebx             ; n (ecx) = min (length, 127)
            MIN     ecx,127

            mov     edx,ecx             ; temporary copy of n

            mov     al,cl               ; *SHP_ShapePtr++ = 2*n+1
            add     al,al
            inc     al

            .if     SHP_building            ; write an n-byte String packet

            STOSB_
            RMOVSB

            .else

            inc     edi
            add     esi,ecx
            add     edi,ecx

            .endif

            sub     ebx,edx             ; length -= n
FlushStringNext:
            or      ebx,ebx             ; endwhile
            jnz     FlushStringLoop

            jmp     Exit                ; endcase

        ;
        ; Flush a Skip packet
        ;

FlushSkip:
            mov     ebx,SHP_ScanPtr         ; SHP_skipCount =
            sub     ebx,esi             ;     SHP_ScanPtr - SHP_FlushPtr - keep
            sub     ebx,keep
            mov     SHP_skipCount,ebx
            
            jmp     Exit                ; endcase

;----------------------------------------------------------------------------
;
; Flush end packet
;

FlushEnd:
            xor     eax,eax             ; add end packet
            .if     SHP_building
            mov     [edi],al
            .endif
            inc     edi

;----------------------------------------------------------------------------

Exit:
            mov     SHP_ShapePtr,edi    ; put SHP_ShapePtr
            mov     SHP_FlushPtr,esi    ; put SHP_FlushPtr

            pop     ecx                 ; restore count
            pop     eax                 ; restore previous pixel

            ret

FlushPacket ENDP

;----------------------------------------------------------------------------
;
; int cdecl VFX_pane_wipe (PANE *panep, int color)
;
; This function wipes the specified pane with the specified color.
;
; The panep parameter specifies the pane to be filled.
; The color parameter specifies the color to fill the pane with.
;
; Return values:    
;
;    0 OK
;   -1 Bad window: 
;         The height or width of the window is less than one.
;   -2 Bad pane: 
;         The height or width of the pane is less than one,
;         or the pane is completely off window (which is legal)
;
;----------------------------------------------------------------------------

                IF do_VFX_pane_wipe

VFX_pane_wipe PROC STDCALL USES ebx esi edi es,\
            panep:PPANE, color:U32

            LOCAL    CP_L   ;Leftmost pixel in Window coord.
            LOCAL    CP_T   ;Top
            LOCAL    CP_R   ;Right
            LOCAL    CP_B   ;Bottom
            
            LOCAL    CP_A   ;Base address of Clipped Pane
            LOCAL    CP_BW  ;Width of underlying window (bytes)
            LOCAL    CP_W   ;Width of underlying window (pixels)
            
            LOCAL    CP_CX  ;Window x coord. = Pane x coord. + CP_CX
            LOCAL    CP_CY  ;Window y coord. = Pane x coord. + CP_CY

            LOCAL    pixel_pitch
            LOCAL    bytes_per_pixel

            cld
            push ds
            pop es

            GET_COLOR color

            CLIP_PANE_TO_WINDOW panep        

        ; adr (edi) = windowp->buffer + CP_W * CP_T + CP_L

            GET_WINDOW_ADDRESS CP_L, CP_T
            mov     edi,eax

        ; tell assembler that ebx and esi are no longer pointers

        ; paneWidth (ebx) = CP_R+1 - CP_L

            mov     ebx,CP_R
            inc     ebx
            sub     ebx,CP_L

        ; lineGap (esi) = CP_W - paneWidth

            mov     esi,CP_W
            sub     esi,ebx

        ; get fill color

            mov     al,BYTE PTR color

        ; copy fill color to all bytes of eax (for stosd)

            mov     ah,al
            shl     eax,16
            mov     al,BYTE PTR color
            mov     ah,al

        ; main loop:
        ;
        ;    for (lineY (edx) = CP_T; lineY <= CP_B; lineY++)
        ;    {
        ;       for (i = 0; i < paneWidth; i++)
        ;       {
        ;          *adr++ = color;
        ;       }
        ;       adr += lineGap;
        ;    }

            mov     edx,CP_T
            jmp     nextY
loopY:      
            mov     ecx,ebx
            and     ecx,11B
            RSTOSB
            mov     ecx,ebx
            shr     ecx,2
            RSTOSD

            add     edi,esi
            inc     edx
nextY:      
            cmp     edx,CP_B
            jle     loopY

        ; normal exit and error exits

Exit:
            xor     eax,eax
            ret

VFX_pane_wipe \
            ENDP

                ENDIF


;----------------------------------------------------------------------------
;
; int VFX_pane_copy (PANE *source, int Sx, Sy, *target, int Tx, Ty, int fill)
;
; This function copies pixels from one pane to another pane.
;
; The source parameter specifies the pane from which pixels are to be copied.  
; The target parameter specifies the pane to   which pixels are to be copied.
; The Sx and Sy parameters specify a reference point in the source pane.
; The Tx and Ty parameters specify a reference point in the target pane.
; The fill parameter can be used to substitute a solid color for the pixels
; from the source pane.  The parameters are discussed in detail below.
;
; The source and target panes may be associated with the same window or with 
; different windows.  VFX_pane_copy() clips each pane to its window before
; begining the copy operation.
;
; The reference points (Sx,Sy) and (Tx,Ty) establish the desired positional 
; correspondence between the source and target panes.  The pixel at (Sx,Sy) 
; in the source pane corresponds to the pixel at (Tx,Ty) in the target pane. 
; Likewise, the pixel at (Sx+i,Sy+j) in the source pane corresponds to the
; pixel at (Tx+i,Ty+j) in the target pane for all integer values i and j.
; Note that the reference points may themselves lie outside their panes.
;
; Pixels in the source pane which have no corresponding pixels in the target
; pane are ignored.  Pixels in the target pane which have no corresponding
; pixels in the source pane are left unchanged.
;
; If the fill parameter is set to a color number (0 to 255), VFX_pane_copy() 
; performs a pane fill instead of a pane copy.  The target pixels which
; would ordinarily recieve data from the source pane will instead be filled
; with the color specified by the fill parameter.  VFX_pane_scroll() uses
; this feature to fill the vacated portions of the pane after scrolling.
;
; If the fill parameter is not a color number, an ordinary pane copy is
; performed.  By convention, the value NO_COLOR (-1) is used.
;
; Note that VFX_pane_copy() will not overwrite source data with target data 
; until the source data has been read.  (This is a potential problem when 
; panes overlap within a single window).  VFX_pane_copy() avoids the problem 
; by choosing an appropriate copy order, e.g: bottom-to-top, right-to-left.
;
; Return values:
;
;    0 OK
;   -1 Bad window: 
;        The height or width of one of the panes' windows is less than one.
;   -2 Bad pane:
;        The height or width of one of the panes is less than one, or one
;        of the panes lies completely off its window (which is legal).
;   -3 Disjoint panes:
;        No pixels in source pane have corresponding pixels in target pane.
;
;----------------------------------------------------------------------------

                IF do_VFX_pane_copy

VFX_pane_copy PROC STDCALL  USES ebx esi edi es,\
              source:PPANE, Sx:S32, Sy:S32, target:PPANE, Tx:S32, Ty:S32, fill:S32

            LOCAL p_x0, p_y0, p_x1, p_y1
            LOCAL q_x0, q_y0, q_x1, q_y1
            LOCAL delta_x, delta_y
            LOCAL source_x0, source_y0, source_x1, source_y1, sourceYstep
            LOCAL target_x0, target_y0, target_x1, target_y1, targetYstep
            LOCAL copyYsize, copyXsize
            LOCAL adjust

            LOCAL SCP_L, SCP_T, SCP_R, SCP_B, SCP_W, SCP_BW, SCP_A, SCP_CX, SCP_CY

            LOCAL    CP_L   ;Leftmost pixel in Window coord.
            LOCAL    CP_T   ;Top
            LOCAL    CP_R   ;Right
            LOCAL    CP_B   ;Bottom
            
            LOCAL    CP_A   ;Base address of Clipped Pane
            LOCAL    CP_BW  ;Width of underlying window (bytes)
            LOCAL    CP_W   ;Width of underlying window (pixels)
            
            LOCAL    CP_CX  ;Window x coord. = Pane x coord. + CP_CX
            LOCAL    CP_CY  ;Window y coord. = Pane x coord. + CP_CY

            LOCAL    pixel_pitch
            LOCAL    bytes_per_pixel

            cld
            push ds
            pop es

            CLIP_PANE_TO_WINDOW source, SCP

            mov     eax,SCP_L
            mov     source_x0,eax
            mov     eax,SCP_T
            mov     source_y0,eax
            mov     eax,SCP_R
            mov     source_x1,eax
            mov     eax,SCP_B
            mov     source_y1,eax

            CONVERT_QUAD_WINDOW_TO_PANE source_x0, source_y0, \
                                        source_x1, source_y1, SCP


            CLIP_PANE_TO_WINDOW target, CP

            mov     eax,CP_L
            mov     target_x0,eax
            mov     eax,CP_T
            mov     target_y0,eax
            mov     eax,CP_R
            mov     target_x1,eax
            mov     eax,CP_B
            mov     target_y1,eax

            CONVERT_QUAD_WINDOW_TO_PANE target_x0, target_y0, \
                                        target_x1, target_y1, CP


        ; calculate delta_x and delta_y

            mov     eax,Sx
            sub     eax,Tx
            mov     delta_x,eax

            mov     eax,Sy
            sub     eax,Ty
            mov     delta_y,eax

        ; clip source pane to target pane:
        ;   p_x0 = max (source_x0, target_x0 + delta_x)
        ;   p_y0 = max (source_y0, target_y0 + delta_y)
        ;   p_x1 = min (source_x1, target_x1 + delta_x)
        ;   p_y1 = min (source_y1, target_y1 + delta_y)

            mov     eax,source_x0
            mov     edx,target_x0
            add     edx,delta_x
            MAX     eax,edx
            mov     p_x0,eax

            mov     eax,source_y0
            mov     edx,target_y0
            add     edx,delta_y
            MAX     eax,edx
            mov     p_y0,eax

            mov     eax,source_x1
            mov     edx,target_x1
            add     edx,delta_x
            MIN     eax,edx
            mov     p_x1,eax

            mov     eax,source_y1
            mov     edx,target_y1
            add     edx,delta_y
            MIN     eax,edx
            mov     p_y1,eax

        ; if panes are disjoint, return

            mov     eax,p_x1
            cmp     eax,p_x0
            jl      ReturnDisjointPanes

            mov     eax,p_y1
            cmp     eax,p_y0
            jl      ReturnDisjointPanes

        ; clip target pane to source pane:
        ;   q_x0 = max (target_x0, source_x0 - delta_x)
        ;   q_y0 = max (target_y0, source_y0 - delta_y)
        ;   q_x1 = min (target_x1, source_x1 - delta_x)
        ;   q_y1 = min (target_y1, source_y1 - delta_y)

            mov     eax,target_x0
            mov     edx,source_x0
            sub     edx,delta_x
            MAX     eax,edx
            mov     q_x0,eax

            mov     eax,target_y0
            mov     edx,source_y0
            sub     edx,delta_y
            MAX     eax,edx
            mov     q_y0,eax

            mov     eax,target_x1
            mov     edx,source_x1
            sub     edx,delta_x
            MIN     eax,edx
            mov     q_x1,eax

            mov     eax,target_y1
            mov     edx,source_y1
            sub     edx,delta_y
            MIN     eax,edx
            mov     q_y1,eax

        ; copyXsize = p_x1+1 - p_x0
        ; copyYsize = p_y1+1 - p_y0

            mov     eax,p_x1
            inc     eax
            sub     eax,p_x0
            mov     copyXsize,eax

            mov     eax,p_y1
            inc     eax
            sub     eax,p_y0
            mov     copyYsize,eax

        ; p (esi) = sourceWindow->buffer
        ; q (edi) = targetWindow->buffer

            GET_WINDOW_ADDRESS SCP_CX, SCP_CY, SCP
            mov     esi,eax

            GET_WINDOW_ADDRESS CP_CX, CP_CY, CP
            mov     edi,eax

        ; if (p_y0 > q_y0)
        ; {
        ;    p += SCP_W * p_y0;
        ;    q += CP_W * q_y0;
        ;
        ;    sourceYstep = +SCP_W;
        ;    targetYstep = +CP_W;
        ; }
        ; else
        ; {
        ;    p += SCP_W * p_y1;
        ;    q += CP_W * q_y1;
        ;
        ;    sourceYstep = -SCP_W;
        ;    targetYstep = -CP_W;
        ; }

            mov     eax,p_y0
            mov     ebx,q_y0
            cmp     eax,ebx
            jle     bottom_to_top

top_to_bottom:
            mul     SCP_W
            add     esi,eax

            mov     eax,ebx
            mul     CP_W
            add     edi,eax

            MOVE    sourceYstep,eax,SCP_W
            MOVE    targetYstep,eax,CP_W

            jmp     @F

bottom_to_top:
            mov     eax,p_y1
            mul     SCP_W
            add     esi,eax

            mov     eax,q_y1
            mul     CP_W
            add     edi,eax

            mov     eax,SCP_W
            neg     eax
            mov     sourceYstep,eax

            mov     eax,CP_W
            neg     eax
            mov     targetYstep,eax
@@:

        ; if (p_x0 > q_x0)
        ; {
        ;    p += p_x0;
        ;    q += q_x0;
        ;
        ;    sourceYstep -= copyXsize;
        ;    targetYstep -= copyXsize;
        ;
        ;    step = +1;
        ;    adjust = 0;
        ; }
        ; else
        ; {
        ;    p += p_x1;
        ;    q += q_x1;
        ;
        ;    sourceYstep += copyXsize;
        ;    targetYstep += copyXsize;
        ;  
        ;    step = -1;
        ;    adjust = 3;
        ; }
        ;
        ; Note: The variable 'adjust' is used to adjust the source and
        ; destination pointers for backword 32-bit string operations.

            mov     ecx,copyXsize

            mov     eax,p_x0
            mov     ebx,q_x0
            cmp     eax,ebx
            jle     right_to_left

left_to_right:
            add     esi,eax
            add     edi,ebx

            sub     sourceYstep,ecx
            sub     targetYstep,ecx

            cld
            mov     adjust,0
            jmp     @F

right_to_left:
            add     esi,p_x1
            add     edi,q_x1

            add     sourceYstep,ecx
            add     targetYstep,ecx

            std
            mov     adjust,3
@@:

        ; If the fill parameter is in the range [0..255], perform a fill
        ; operation. Otherwise, perform a copy operation.

            mov     eax,fill
            test    eax,0FFFFFF00H
            jz      fillIt

        ; copy the clipped source pane to the clipped target pane

copyIt:
            mov     edx,copyYsize
            mov     eax,sourceYstep
            mov     ebx,targetYstep
copyLoop:
            mov     ecx,copyXsize
            and     ecx,11B
            RMOVSB

            mov     ecx,copyXsize
            shr     ecx,2

            sub     esi,adjust
            sub     edi,adjust
            RMOVSD
            add     esi,adjust
            add     edi,adjust

            add     esi,eax
            add     edi,ebx

            dec     edx
            jnz     copyLoop

            cld
            jmp     Exit

        ; fill the clipped target pane with the fill color

fillIt:

        ; replicate color into all four bytes of eax

            mov     dl,al
            mov     ah,al
            shl     eax,16
            mov     al,dl
            mov     ah,al

            mov     edx,copyYsize
            mov     ebx,targetYstep
fillLoop:
            mov     ecx,copyXsize
            and     ecx,11B
            RSTOSB

            mov     ecx,copyXsize
            shr     ecx,2

            sub     edi,adjust
            RSTOSD
            add     edi,adjust

            add     edi,ebx

            dec     edx
            jnz     fillLoop

            cld

Exit:
            xor     eax,eax
            ret

ReturnDisjointPanes:
            mov     eax,-3
            ret

            ASSUME  esi:nothing
            ASSUME  edi:nothing
            ASSUME  ebx:nothing

VFX_pane_copy \
            ENDP

                ENDIF


;----------------------------------------------------------------------------
;
; int cdecl VFX_pane_scroll (PANE *panep, int dx_, int dy_,
;                           int mode, int parm)
;
; This function scrolls the contents of a pane.
;
; The panep parameter specifies the pane to be modified.
; The dx_ parameter specifies the horizontal scroll distance in pixels.
; The dy_ parameter specifies the vertical   scroll distance in pixels.
; The mode parameter specifies the scroll mode (NORMAL or WRAP).
; The parm parameter specifies the fill color (if mode is NORMAL), or
; the address of a caller-provided temporary buffer (if mode is WRAP).
;
; Positive values of dx_ (dy_) indicate rightward (downward) movement.
; Negative values of dx_ (dy_) indicate leftward (upward) movement.
; In other words, the point (dx_,dy_) specifies the scroll destination
; of the pane's origin (upper left-hand pixel).
;
; If mode is NORMAL (0), pixels which are vacated by the scroll operation
; are filled with the color specified by parm.
;
; If mode is WRAP (1), pixels which are scrolled off one side of the pane
; are wrapped around to the other side of the pane.  Both vertical and
; horizontal wrapping can occur simultaneously.  When mode is WRAP, the
; caller must provide a temporary work buffer and set parm to its address.  
; If parm is NULL, VFX_pane_scroll does not perform the specified scroll 
; operation but instead returns the minimum buffer size required to
; perform the operation.
;
; VFX_pane_scroll() uses VFX_pane_copy() to move and fill pixels.
; 
; Examples:
;
;    #define NOWRAP 0
;    #define WRAP   1
;
;    VFX_pane_scroll (&paneA, 0, -16, NOWRAP, BACKGROUND_COLOR)
;       scrolls paneA 16 pixels upward, filling the vacated area at the 
;       bottom with the color BACKGROUND_COLOR.
;
;    VFX_pane_scroll (&paneB, 5, 0, NOWRAP, CHARTREUSE)
;       scrolls paneB 5 pixels to the right, filling the vacated area at
;       the left with the color CHARTREUSE.
;
;    VFX_pane_scroll (&paneC, -10, 20, WRAP, (int) ScrollBuf)
;       scrolls paneC 10 pixels to the left and 20 pixels downward, wrapping
;       instead of filling and using ScrollBuf for temporary storage.
;
;    size = VFX_pane_scroll (&paneD, 29, 76, WRAP, NULL)
;       calculates and returns the buffer size which will be required to 
;       perform the specified scroll operation.
;
; Notes about dx_ and dy_:
;
;    If the scroll mode is NORMAL and the horizontal (vertical) scroll 
;    distance exceeds the pane width (height), the whole pane will be 
;    filled with the color specified by parm.  This applies to both 
;    positive and negative distances.
;    
;    If mode is WRAP, modulo arithmetic is applied to the scroll distances
;    so that a continuous wrap affect is implemented.  For example, if the
;    pane width (CP_W) is 20, these values of dx_ are treated equally:
;
;        ... -57, -37, -17, 3, 23, 43, 63, ...
; 
; Notes about the temporary buffer:
;    
;    A temporary buffer is only needed when scroll mode is WRAP (1).
;    
;    The required buffer size depends on dx_ and dy_ as well as Xsize
;    and Ysize.  (Xsize and Ysize are the width and height of the pane, 
;    respectively.)
;
;    The worst-case buffer size is Xsize*Ysize.  The best-case
;    buffer size is 0, which occurs when no movement is required
;    (i.e: (dx_ mod Xsize) = (dy_ mod Ysize) = 0).
;
; Return values (n):
;
;    0: OK.  Scroll operation was successful.
;
;   >0: Required buffer of size n.
;       Returned when mode is WRAP, parm is NULL, and buffering is needed.
;    
;   -1: Bad window.
;       The height or width of the pane's window is less than one.
;
;   -2: Bad pane.
;       The height or width of the pane is less than one.
;
;----------------------------------------------------------------------------

                IF do_VFX_pane_scroll

VFX_pane_scroll PROC STDCALL USES ebx esi edi es,\
                panep:PPANE, dx_:S32, dy_:S32, mode:S32, parm:S32

                LOCAL temp_window:VFX_WINDOW
                LOCAL temp_pane:PANE, temp_panep:PPANE
                LOCAL Xsize, Ysize, _Xsize, _Ysize
                LOCAL buffer_size
                LOCAL color

                cld
                push ds
                pop es

; get pane pointer

            ASSUME  esi:PPANE
            mov     esi,panep

; calculate pane x and y sizes as follows:
;
;    Xsize = panep->x1+1 - panep->x0;
;    if (Xsize <= 0)
;       return bad pane;
;
;    Ysize = panep->y1+1 - panep->y0;
;    if (Ysize <= 0)
;       return bad pane;
;
;    _Xsize = -Xsize;
;    _Ysize = -Ysize;

            mov     eax,[esi].x1
            inc     eax
            sub     eax,[esi].x0
            mov     Xsize,eax
            jle     ReturnBadPane

            mov     edx,[esi].y1
            inc     edx
            sub     edx,[esi].y0
            mov     Ysize,edx
            jle     ReturnBadPane

            neg     eax
            mov     _Xsize,eax

            neg     edx
            mov     _Ysize,edx

; test the mode parameter and branch accordingly

            cmp     mode,1
            je      wrap

no_wrap:

; if ((abs(dx_) >= Xsize) || (abs(dy_) >= Ysize)) 
;    fill pane with color and return

            mov     eax,dx_
            cdq
            xor     eax,edx
            sub     eax,edx
            cmp     eax,Xsize
            jge     fill_all

            mov     eax,dy_
            cdq
            xor     eax,edx
            sub     eax,edx
            cmp     eax,Ysize
            jge     fill_all

; temp_panep = panep
; color = parm

            MOVE    temp_panep,eax,panep
            MOVE    color,eax,parm
            and     color,7fffffffh     ;mask off "remap" (RGB_TRIPLET) bit

            jmp     common

fill_all:
            mov     eax,parm
            and     eax,7fffffffh       ;mask off "remap" (RGB_TRIPLET) bit
            INVOKE  VFX_pane_wipe, panep, al
            ret

wrap:

; if a buffer has not been provided, return the required buffer size

            cmp     parm,0
            jz      ReturnBufferSize

; impose a window and pane structure onto the temporary buffer as follows:
;
; temp_panep = &temp_pane;
;
; temp_window.buffer = parm;
; temp_pane.window = &temp_window;
;
; temp_pane.x0 = temp_window.wndx_0 = 0;
; temp_pane.y0 = temp_window.wndy_0 = 0;
; temp_pane.x1 = temp_window.wndx_1 = Xsize - 1;
; temp_pane.y1 = temp_window.wndy_1 = Ysize - 1;

            lea     eax,temp_pane
            mov     temp_panep,eax

            MOVE    temp_window.buffer,eax,parm
            lea     eax,temp_window
            mov     temp_pane.window,eax

            xor     eax,eax
            mov     temp_pane.x0,eax

            mov     temp_pane.y0,eax

            mov     eax,Xsize
            dec     eax
            mov     temp_window.x_max,eax
            mov     temp_pane.x1,eax

            mov     eax,Ysize
            dec     eax
            mov     temp_window.y_max,eax
            mov     temp_pane.y1,eax

            mov     temp_window.pixel_pitch,1
            mov     temp_window.bytes_per_pixel,1

; copy pane to temporary pane as follows:
;
;    VFX_pane_copy (panep, 0, 0, temp_panep, 0, 0, NO_COLOR);

            INVOKE  VFX_pane_copy, panep, 0, 0, temp_panep, 0, 0, NO_COLOR

; we're wrapping, so make sure dx_ & dy_ are in range as follows:
;
;    dx %= Xsize;
;    dy %= Ysize;

            mov     eax,dx_
            cdq
            idiv    Xsize
            mov     dx_,edx

            mov     eax,dy_
            cdq
            idiv    Ysize
            mov     dy_,edx

; color = NO_COLOR

            mov     color,NO_COLOR

common:

; if dx_ and dy_ are both zero, no action is needed, so return

            mov     eax,dx_
            or      eax,dy_
            jz      ReturnOK

; perform the scroll as follows:
;
;    VFX_pane_copy (temp_panep,     0,     0, panep, dx_, dy_, NO_COLOR);
;
;    VFX_pane_copy (temp_panep, Xsize, Ysize, panep, dx_, dy_, color);
;    VFX_pane_copy (temp_panep, Xsize,     0, panep, dx_, dy_, color);
;    VFX_pane_copy (temp_panep, Xsize,-Ysize, panep, dx_, dy_, color);
;
;    VFX_pane_copy (temp_panep,     0, Ysize, panep, dx_, dy_, color);
;
;    VFX_pane_copy (temp_panep,     0,-Ysize, panep, dx_, dy_, color);
;
;    VFX_pane_copy (temp_panep,-Xsize, Ysize, panep, dx_, dy_, color);
;    VFX_pane_copy (temp_panep,-Xsize,     0, panep, dx_, dy_, color);
;    VFX_pane_copy (temp_panep,-Xsize,-Ysize, panep, dx_, dy_, color);
            
            mov     esi,temp_panep
            ASSUME  edi:PPANE
            mov     edi,panep

            INVOKE  VFX_pane_copy, esi,     0,     0, edi, dx_, dy_, NO_COLOR

            INVOKE  VFX_pane_copy, esi, Xsize, Ysize, edi, dx_, dy_, color
            INVOKE  VFX_pane_copy, esi, Xsize,     0, edi, dx_, dy_, color
            INVOKE  VFX_pane_copy, esi, Xsize,_Ysize, edi, dx_, dy_, color

            INVOKE  VFX_pane_copy, esi,     0, Ysize, edi, dx_, dy_, color

            INVOKE  VFX_pane_copy, esi,     0,_Ysize, edi, dx_, dy_, color

            INVOKE  VFX_pane_copy, esi,_Xsize, Ysize, edi, dx_, dy_, color
            INVOKE  VFX_pane_copy, esi,_Xsize,     0, edi, dx_, dy_, color
            INVOKE  VFX_pane_copy, esi,_Xsize,_Ysize, edi, dx_, dy_, color

ReturnOK:
            xor     eax,eax
            ret

; return required buffer size

ReturnBufferSize:
            mov     eax,Xsize
            mul     Ysize

            ret

ReturnBadPane:
            mov     eax,-2
            ret

            ASSUME  esi:nothing
            ASSUME  edi:nothing

VFX_pane_scroll \
            ENDP

                ENDIF


;----------------------------------------------------------------------------
;
; void VFX_ellipse_draw(PANE *pane, LONG xc, LONG yc,
;                        LONG width, LONG height, LONG color);
;
; Draws an ellipse in the specified pane with the specified color.
;
; Algorithm from Wilton, "Programmer's Guide to PC & PS/2 
; Video Systems"
;
;----------------------------------------------------------------------------

                ;
                ; BASCALC: EDI -> address of point (x,y) in window
                ;
                ; Entry:        
                ;               edi = x coordinate
                ;               edx = y coordinate
                ;
                ; Uses:         eax, edx, edi
                ;
                ; Returns:      edi = target address
                ;
     
BASCALC         MACRO

                GET_WINDOW_ADDRESS edi,edx

                mov edi,eax
                
                ENDM


                ;
                ;CLIP: Branch to branch_out if point (pt_x,pt_y) lies outside
                ;primary window
                ;

CLIP            MACRO branch_out

                cmp edi,CP_L
                jl branch_out

                cmp edi,CP_R
                jg branch_out

                cmp edx,CP_T
                jl branch_out

                cmp edx,CP_B
                jg branch_out

                ENDM


ELLIPSE_PIXELS  MACRO
                LOCAL P1,P2,P3,P4

                push ebx
                mov ecx,[Color]

                mov edi,x_bottom
                add edi,x_top
                mov edx,y_bottom
                add edx,y_top
                CLIP P1
                BASCALC
                mov BYTE PTR [edi],cl

P1:             mov edi,x_bottom
                add edi,x_top
                mov edx,y_bottom
                sub edx,y_top
                CLIP P2
                BASCALC
                mov BYTE PTR [edi],cl

P2:             mov edi,x_bottom
                sub edi,x_top
                mov edx,y_bottom
                add edx,y_top
                CLIP P3
                BASCALC
                mov BYTE PTR [edi],cl

P3:             mov edi,x_bottom
                sub edi,x_top
                mov edx,y_bottom
                sub edx,y_top
                CLIP P4
                BASCALC
                mov BYTE PTR [edi],cl

P4:             pop ebx

                ENDM



                IF do_VFX_ellipse_draw

VFX_ellipse_draw PROC STDCALL USES ebx esi edi es, \
                Target:PPANE,XC:S32,YC:S32,AxisA:S32,AxisB:S32,Color:U32

                LOCAL x_bottom, y_bottom, x_top, y_top
                LOCAL Asquared, TwoAsquared, Bsquared, TwoBsquared
                LOCAL var_dx, var_dy
                LOCAL x_vector
                LOCAL line_left,line_right

                LOCAL    CP_L   ;Leftmost pixel in Window coord.
                LOCAL    CP_T   ;Top
                LOCAL    CP_R   ;Right
                LOCAL    CP_B   ;Bottom
              
                LOCAL    CP_A   ;Base address of Clipped Pane
                LOCAL    CP_BW  ;Width of underlying window (bytes)
                LOCAL    CP_W   ;Width of underlying window (pixels)
                
                LOCAL    CP_CX  ;Window x coord. = Pane x coord. + CP_CX
                LOCAL    CP_CY  ;Window y coord. = Pane x coord. + CP_CY

                LOCAL    pixel_pitch
                LOCAL    bytes_per_pixel

                cld
                push ds
                pop es

                GET_COLOR Color

                cmp [AxisA],0
                je __degen_case
                cmp [AxisB],0
                jne __valid

__degen_case:   
                mov eax,[YC]
                add eax,[AxisB]
                mov ebx,[XC]
                add ebx,[AxisA]
                mov ecx,[YC]
                sub ecx,[AxisB]
                mov edx,[XC]
                sub edx,[AxisA]
                invoke VFX_line_draw,[Target],edx,ecx,ebx,eax,0,[Color]
                jmp __ellipse_out

__valid:        

                CLIP_PANE_TO_WINDOW Target

                mov eax,[Color]
                mov ah,al
                mov [Color],eax
                mov WORD PTR [Color+2],ax

                CONVERT_PAIR_PANE_TO_WINDOW XC,YC

                mov eax,[XC]
                mov x_bottom,eax
                mov eax,[YC]
                mov y_bottom,eax

                mov x_top,0
                mov eax,[AxisB]
                mov y_top,eax
                mul eax                         ;compute B squares
                mov Bsquared,eax
                shl eax,1
                mov TwoBsquared,eax

                mov eax,[AxisA]                 ;compute A squares
                mul eax
                mov Asquared,eax
                shl eax,1
                mov TwoAsquared,eax

                mov var_dx,0

                mov eax,TwoAsquared             ;dy = TwoAsquared * b
                mul [AxisB]
                mov var_dy,eax

                mov eax,Asquared                
                shr eax,2                       
                add eax,Bsquared                ;eax = Asquared/4 + Bsquared
                mov x_vector,eax                ;x_vector= a^2/4 + b^2
                mov eax,Asquared
                mul [AxisB]
                sub x_vector,eax                ;x_vector=a^2/4+b^2-a^2*b 

                mov ebx,[AxisB]

__until_pos:
                mov eax,var_dx                  
                sub eax,var_dy
                jns __dx_ge_dy                  ;jmp if dx >= dy

__plot_neg:     ELLIPSE_PIXELS

                cmp x_vector,0                  
                js __d_neg                      ;jmp if d < 0

                dec y_top
                dec ebx

                mov eax,var_dy
                sub eax,TwoAsquared
                mov var_dy,eax                  ;dy -= 2*a^2

                sub x_vector,eax                ;x_vector -= dy

__d_neg:        inc x_top               

                mov eax,var_dx                  
                add eax,TwoBsquared
                mov var_dx,eax                  ;dx += 2*b^2

                add eax,Bsquared                
                add x_vector,eax                ;x_vector += dx + b^2

                jmp __until_pos

__dx_ge_dy:     
                mov eax,Asquared
                sub eax,Bsquared                ;eax=a^2-b^2
                mov edx,eax                     ;edx=a^2-b^2
                sar eax,1                       ;eax=(a^2-b^2)/2
                add eax,edx                     ;eax=3*(a^2-b^2)/2 
                sub eax,var_dx                  ;eax=3*(a^2-b^2)/2 - dx 
                sub eax,var_dy                  ;eax=3*(a^2-b^2)/2 - (dx+dy)
                sar eax,1                       ; /2

                add x_vector,eax

__until_neg:    ELLIPSE_PIXELS

                cmp x_vector,0
                jns __d_pos

                inc x_top

                mov eax,var_dx
                add eax,TwoBsquared
                mov var_dx,eax                  ;dx += 2*b^2
                add x_vector,eax                ;x_vector += dx

__d_pos:        dec y_top

                mov eax,var_dy                  
                sub eax,TwoAsquared
                mov var_dy,eax                  ;dy -= 2*a^2
                sub eax,Asquared                ;eax = dy - a^2
                sub x_vector,eax                ;x_vector += (-dy + a^2)

                dec ebx

                js __end_ellipse
                jmp __until_neg

__end_ellipse:  
__ellipse_out:
                ret

VFX_ellipse_draw ENDP

                ENDIF

;----------------------------------------------------------------------------
;
; void VFX_ellipse_fill(PANE *pane, LONG xc, LONG yc,
;                        LONG width, LONG height, LONG color);
;
; Draws and fills an ellipse in the specified pane with the specified color.
;
; Algorithm from Wilton, "Programmer's Guide to PC & PS/2 
; Video Systems"
;
;----------------------------------------------------------------------------

                ;
                ;EDI = left X
                ;EDX = Y
                ;

HLIN            MACRO

                BASCALC 

                mov ecx,line_right
                sub ecx,line_left
                inc ecx

                mov eax,[Color]
                mov edx,ecx
                and edx,3
                shr ecx,2
                rep stosd
                mov ecx,edx
                rep stosb

                ENDM

ELLIPSE_LINES   MACRO
                LOCAL TR1,TR2,LN1,LN2

                mov edi,x_bottom
                add edi,x_top
                cmp edi,CP_L
                jl LN2                  ;;right end to left of window

                cmp edi,CP_R
                jl TR1

                mov edi,CP_R

TR1:            mov line_right,edi
                mov edi,x_bottom
                sub edi,x_top
                cmp edi,CP_R
                jg LN2                  ;;left end to right of window

                cmp edi,CP_L
                jg TR2

                mov edi,CP_L

TR2:            mov line_left,edi
                mov edx,y_bottom
                add edx,y_top
                cmp edx,CP_T     
                jl LN2                  ;;bottom line above window

                cmp edx,CP_B
                jg LN1

                HLIN

LN1:            mov edi,line_left
                mov edx,y_bottom
                sub edx,y_top
                cmp edx,CP_T     
                jl LN2

                cmp edx,CP_B
                jg LN2                  ;;top line below window

                HLIN
LN2:    
                ENDM


                IF do_VFX_ellipse_fill

VFX_ellipse_fill PROC STDCALL USES ebx esi edi es, \
                Target:PPANE,XC:S32,YC:S32,AxisA:S32,AxisB:S32,Color:U32

                LOCAL x_bottom, y_bottom, x_top, y_top
                LOCAL Asquared, TwoAsquared, Bsquared, TwoBsquared
                LOCAL var_dx, var_dy
                LOCAL x_vector
                LOCAL line_left,line_right

                LOCAL    CP_L   ;Leftmost pixel in Window coord.
                LOCAL    CP_T   ;Top
                LOCAL    CP_R   ;Right
                LOCAL    CP_B   ;Bottom
              
                LOCAL    CP_A   ;Base address of Clipped Pane
                LOCAL    CP_BW  ;Width of underlying window (bytes)
                LOCAL    CP_W   ;Width of underlying window (pixels)
                
                LOCAL    CP_CX  ;Window x coord. = Pane x coord. + CP_CX
                LOCAL    CP_CY  ;Window y coord. = Pane x coord. + CP_CY

                LOCAL    pixel_pitch
                LOCAL    bytes_per_pixel

                cld
                push ds
                pop es

                GET_COLOR Color

                cmp [AxisA],0
                je __degen_case
                cmp [AxisB],0
                jne __valid

__degen_case:   
                mov eax,[YC]
                add eax,[AxisB]
                mov ebx,[XC]
                add ebx,[AxisA]
                mov ecx,[YC]
                sub ecx,[AxisB]
                mov edx,[XC]
                sub edx,[AxisA]
                invoke VFX_line_draw,[Target],edx,ecx,ebx,eax,0,[Color]
                jmp __ellipse_out

__valid:
                CLIP_PANE_TO_WINDOW Target
                
                mov eax,[Color]
                mov ah,al
                mov [Color],eax
                mov WORD PTR [Color+2],ax

                CONVERT_PAIR_PANE_TO_WINDOW XC,YC

                mov eax,[XC]
                mov x_bottom,eax
                mov eax,[YC]
                mov y_bottom,eax

                mov x_top,0
                mov eax,[AxisB]
                mov y_top,eax
                mul eax                         ;compute B squares
                mov Bsquared,eax
                shl eax,1
                mov TwoBsquared,eax

                mov eax,[AxisA]                 ;compute A squares
                mul eax
                mov Asquared,eax
                shl eax,1
                mov TwoAsquared,eax

                mov var_dx,0

                mov eax,TwoAsquared             ;dy = TwoAsquared * b
                mul [AxisB]
                mov var_dy,eax

                mov eax,Asquared                
                shr eax,2                       
                add eax,Bsquared                ;eax = Asquared/4 + Bsquared
                mov x_vector,eax                ;x_vector= a^2/4 + b^2
                mov eax,Asquared
                mul [AxisB]
                sub x_vector,eax                ;x_vector=a^2/4+b^2-a^2*b 

                mov ebx,[AxisB]

__until_pos:    mov eax,var_dx
                sub eax,var_dy
                js __plot_neg
                jmp __dx_ge_dy

__plot_neg:     ELLIPSE_LINES

                cmp x_vector,0
                js __d_neg
                dec y_top
                dec ebx
                mov eax,var_dy
                sub eax,TwoAsquared
                mov var_dy,eax
                sub x_vector,eax

__d_neg:        inc x_top
                mov eax,var_dx
                add eax,TwoBsquared
                mov var_dx,eax
                add eax,Bsquared
                add x_vector,eax
                jmp __until_pos

__dx_ge_dy:
                mov eax,Asquared
                sub eax,Bsquared                ;eax=a^2-b^2
                mov edx,eax                     ;edx=a^2-b^2
                sar eax,1                       ;eax=(a^2-b^2)/2
                add eax,edx                     ;eax=3*(a^2-b^2)/2 
                sub eax,var_dx                  ;eax=3*(a^2-b^2)/2 - dx 
                sub eax,var_dy                  ;eax=3*(a^2-b^2)/2 - (dx+dy)
                sar eax,1                       ; /2
                add x_vector,eax

__until_neg:    ELLIPSE_LINES

                cmp x_vector,0
                jns __d_pos
                inc x_top
                mov eax,var_dx
                add eax,TwoBsquared
                mov var_dx,eax
                add x_vector,eax

__d_pos:        dec y_top
                mov eax,var_dy
                sub eax,TwoAsquared
                mov var_dy,eax
                sub eax,Asquared
                sub x_vector,eax

                dec ebx
                js __end_ellipse
                jmp __until_neg

__end_ellipse:
__ellipse_out:
                ret
VFX_ellipse_fill ENDP

                ENDIF

;----------------------------------------------------------------------------
;
; void VFX_Cos_Sin(LONG Angle, FIXEDPOINT *Cos, FIXEDPOINT *Sin);
;
; Returns the sine and cosine of an angle.
;
;       16.16 fixed-point cosines of angles from
;       pi/2, in steps of 1/10 degree.
;
; Source: Abrash, "X-Sharp" engine from DDJ
;
;----------------------------------------------------------------------------

CosTable        LABEL DWORD

 dd 010000h,010000h,010000h,0ffffh,0fffeh,0fffeh,0fffch,0fffbh,0fffah,0fff8h
 dd 0fff6h,0fff4h,0fff2h,0ffefh,0ffech,0ffeah,0ffe6h,0ffe3h,0ffe0h,0ffdch
 dd 0ffd8h,0ffd4h,0ffd0h,0ffcbh,0ffc7h,0ffc2h,0ffbdh,0ffb7h,0ffb2h,0ffach
 dd 0ffa6h,0ffa0h,0ff9ah,0ff93h,0ff8dh,0ff86h,0ff7fh,0ff77h,0ff70h,0ff68h
 dd 0ff60h,0ff58h,0ff50h,0ff48h,0ff3fh,0ff36h,0ff2dh,0ff24h,0ff1ah,0ff10h
 dd 0ff07h,0fefdh,0fef2h,0fee8h,0feddh,0fed2h,0fec7h,0febch,0feb1h,0fea5h
 dd 0fe99h,0fe8dh,0fe81h,0fe74h,0fe68h,0fe5bh,0fe4eh,0fe40h,0fe33h,0fe25h
 dd 0fe18h,0fe09h,0fdfbh,0fdedh,0fddeh,0fdcfh,0fdc0h,0fdb1h,0fda2h,0fd92h
 dd 0fd82h,0fd72h,0fd62h,0fd52h,0fd41h,0fd30h,0fd1fh,0fd0eh,0fcfdh,0fcebh
 dd 0fcd9h,0fcc7h,0fcb5h,0fca3h,0fc90h,0fc7dh,0fc6ah,0fc57h,0fc44h,0fc30h
 dd 0fc1ch,0fc08h,0fbf4h,0fbe0h,0fbcbh,0fbb7h,0fba2h,0fb8dh,0fb77h,0fb62h
 dd 0fb4ch,0fb36h,0fb20h,0fb0ah,0faf3h,0fadch,0fac5h,0faaeh,0fa97h,0fa80h
 dd 0fa68h,0fa50h,0fa38h,0fa20h,0fa07h,0f9efh,0f9d6h,0f9bdh,0f9a3h,0f98ah
 dd 0f970h,0f956h,0f93ch,0f922h,0f908h,0f8edh,0f8d2h,0f8b7h,0f89ch,0f881h
 dd 0f865h,0f84ah,0f82eh,0f811h,0f7f5h,0f7d9h,0f7bch,0f79fh,0f782h,0f764h
 dd 0f747h,0f729h,0f70bh,0f6edh,0f6cfh,0f6b0h,0f692h,0f673h,0f654h,0f635h
 dd 0f615h,0f5f6h,0f5d6h,0f5b6h,0f596h,0f575h,0f555h,0f534h,0f513h,0f4f2h
 dd 0f4d0h,0f4afh,0f48dh,0f46bh,0f449h,0f427h,0f404h,0f3e2h,0f3bfh,0f39ch
 dd 0f378h,0f355h,0f331h,0f30eh,0f2eah,0f2c5h,0f2a1h,0f27ch,0f258h,0f233h
 dd 0f20eh,0f1e8h,0f1c3h,0f19dh,0f177h,0f151h,0f12bh,0f104h,0f0deh,0f0b7h
 dd 0f090h,0f068h,0f041h,0f019h,0eff2h,0efcah,0efa2h,0ef79h,0ef51h,0ef28h
 dd 0eeffh,0eed6h,0eeadh,0ee83h,0ee5ah,0ee30h,0ee06h,0eddch,0edb1h,0ed87h
 dd 0ed5ch,0ed31h,0ed06h,0ecdbh,0ecafh,0ec83h,0ec58h,0ec2bh,0ebffh,0ebd3h
 dd 0eba6h,0eb79h,0eb4ch,0eb1fh,0eaf2h,0eac4h,0ea97h,0ea69h,0ea3bh,0ea0dh
 dd 0e9deh,0e9b0h,0e981h,0e952h,0e923h,0e8f3h,0e8c4h,0e894h,0e864h,0e834h
 dd 0e804h,0e7d3h,0e7a3h,0e772h,0e741h,0e710h,0e6deh,0e6adh,0e67bh,0e649h
 dd 0e617h,0e5e5h,0e5b3h,0e580h,0e54dh,0e51ah,0e4e7h,0e4b4h,0e481h,0e44dh
 dd 0e419h,0e3e5h,0e3b1h,0e37ch,0e348h,0e313h,0e2deh,0e2a9h,0e274h,0e23eh
 dd 0e209h,0e1d3h,0e19dh,0e167h,0e131h,0e0fah,0e0c3h,0e08dh,0e056h,0e01eh
 dd 0dfe7h,0dfb0h,0df78h,0df40h,0df08h,0ded0h,0de97h,0de5fh,0de26h,0ddedh
 dd 0ddb4h,0dd7bh,0dd41h,0dd07h,0dcceh,0dc94h,0dc5ah,0dc1fh,0dbe5h,0dbaah
 dd 0db6fh,0db34h,0daf9h,0dabeh,0da82h,0da47h,0da0bh,0d9cfh,0d993h,0d956h
 dd 0d91ah,0d8ddh,0d8a0h,0d863h,0d826h,0d7e9h,0d7abh,0d76dh,0d72fh,0d6f1h
 dd 0d6b3h,0d675h,0d636h,0d5f7h,0d5b9h,0d57ah,0d53ah,0d4fbh,0d4bbh,0d47ch
 dd 0d43ch,0d3fch,0d3bch,0d37bh,0d33bh,0d2fah,0d2b9h,0d278h,0d237h,0d1f5h
 dd 0d1b4h,0d172h,0d130h,0d0eeh,0d0ach,0d06ah,0d027h,0cfe5h,0cfa2h,0cf5fh
 dd 0cf1ch,0ced8h,0ce95h,0ce51h,0ce0eh,0cdcah,0cd85h,0cd41h,0ccfdh,0ccb8h
 dd 0cc73h,0cc2eh,0cbe9h,0cba4h,0cb5fh,0cb19h,0cad3h,0ca8eh,0ca48h,0ca01h
 dd 0c9bbh,0c975h,0c92eh,0c8e7h,0c8a0h,0c859h,0c812h,0c7cah,0c783h,0c73bh
 dd 0c6f3h,0c6abh,0c663h,0c61ah,0c5d2h,0c589h,0c540h,0c4f7h,0c4aeh,0c465h
 dd 0c41bh,0c3d2h,0c388h,0c33eh,0c2f4h,0c2aah,0c260h,0c215h,0c1cah,0c180h
 dd 0c135h,0c0eah,0c09eh,0c053h,0c007h,0bfbch,0bf70h,0bf24h,0bed8h,0be8bh
 dd 0be3fh,0bdf2h,0bda5h,0bd58h,0bd0bh,0bcbeh,0bc71h,0bc23h,0bbd6h,0bb88h
 dd 0bb3ah,0baech,0ba9eh,0ba4fh,0ba01h,0b9b2h,0b963h,0b914h,0b8c5h,0b876h
 dd 0b827h,0b7d7h,0b787h,0b738h,0b6e8h,0b698h,0b647h,0b5f7h,0b5a6h,0b556h
 dd 0b505h,0b4b4h,0b463h,0b412h,0b3c0h,0b36fh,0b31dh,0b2cbh,0b279h,0b227h
 dd 0b1d5h,0b183h,0b130h,0b0deh,0b08bh,0b038h,0afe5h,0af92h,0af3eh,0aeebh
 dd 0ae97h,0ae44h,0adf0h,0ad9ch,0ad48h,0acf3h,0ac9fh,0ac4bh,0abf6h,0aba1h
 dd 0ab4ch,0aaf7h,0aaa2h,0aa4dh,0a9f7h,0a9a1h,0a94ch,0a8f6h,0a8a0h,0a84ah
 dd 0a7f3h,0a79dh,0a747h,0a6f0h,0a699h,0a642h,0a5ebh,0a594h,0a53dh,0a4e5h
 dd 0a48eh,0a436h,0a3deh,0a386h,0a32eh,0a2d6h,0a27eh,0a225h,0a1cdh,0a174h
 dd 0a11bh,0a0c2h,0a069h,0a010h,09fb7h,09f5dh,09f04h,09eaah,09e50h,09df6h
 dd 09d9ch,09d42h,09ce7h,09c8dh,09c32h,09bd8h,09b7dh,09b22h,09ac7h,09a6ch
 dd 09a11h,099b5h,0995ah,098feh,098a2h,09846h,097eah,0978eh,09732h,096d6h
 dd 09679h,0961ch,095c0h,09563h,09506h,094a9h,0944ch,093eeh,09391h,09334h
 dd 092d6h,09278h,0921ah,091bch,0915eh,09100h,090a2h,09043h,08fe5h,08f86h
 dd 08f27h,08ec8h,08e69h,08e0ah,08dabh,08d4ch,08cech,08c8dh,08c2dh,08bcdh
 dd 08b6dh,08b0dh,08aadh,08a4dh,089edh,0898ch,0892ch,088cbh,0886bh,0880ah
 dd 087a9h,08748h,086e7h,08685h,08624h,085c2h,08561h,084ffh,0849dh,0843ch
 dd 083dah,08377h,08315h,082b3h,08251h,081eeh,0818bh,08129h,080c6h,08063h
 dd 08000h,07f9dh,07f3ah,07ed6h,07e73h,07e0fh,07dach,07d48h,07ce4h,07c80h
 dd 07c1ch,07bb8h,07b54h,07af0h,07a8ch,07a27h,079c3h,0795eh,078f9h,07894h
 dd 0782fh,077cah,07765h,07700h,0769bh,07635h,075d0h,0756ah,07504h,0749fh
 dd 07439h,073d3h,0736dh,07307h,072a0h,0723ah,071d4h,0716dh,07107h,070a0h
 dd 07039h,06fd2h,06f6bh,06f04h,06e9dh,06e36h,06dcfh,06d67h,06d00h,06c98h
 dd 06c31h,06bc9h,06b61h,06af9h,06a91h,06a29h,069c1h,06959h,068f1h,06888h
 dd 06820h,067b7h,0674fh,066e6h,0667dh,06614h,065abh,06542h,064d9h,06470h
 dd 06407h,0639eh,06334h,062cbh,06261h,061f8h,0618eh,06124h,060bah,06050h
 dd 05fe6h,05f7ch,05f12h,05ea8h,05e3dh,05dd3h,05d69h,05cfeh,05c93h,05c29h
 dd 05bbeh,05b53h,05ae8h,05a7dh,05a12h,059a7h,0593ch,058d1h,05865h,057fah
 dd 0578fh,05723h,056b8h,0564ch,055e0h,05574h,05509h,0549dh,05431h,053c5h
 dd 05358h,052ech,05280h,05214h,051a7h,0513bh,050ceh,05062h,04ff5h,04f88h
 dd 04f1ch,04eafh,04e42h,04dd5h,04d68h,04cfbh,04c8eh,04c21h,04bb4h,04b46h
 dd 04ad9h,04a6bh,049feh,04990h,04923h,048b5h,04848h,047dah,0476ch,046feh
 dd 04690h,04622h,045b4h,04546h,044d8h,0446ah,043fbh,0438dh,0431fh,042b0h
 dd 04242h,041d3h,04165h,040f6h,04088h,04019h,03faah,03f3bh,03ecch,03e5eh
 dd 03defh,03d80h,03d11h,03ca1h,03c32h,03bc3h,03b54h,03ae5h,03a75h,03a06h
 dd 03996h,03927h,038b7h,03848h,037d8h,03769h,036f9h,03689h,03619h,035aah
 dd 0353ah,034cah,0345ah,033eah,0337ah,0330ah,0329ah,0322ah,031b9h,03149h
 dd 030d9h,03069h,02ff8h,02f88h,02f17h,02ea7h,02e37h,02dc6h,02d55h,02ce5h
 dd 02c74h,02c04h,02b93h,02b22h,02ab1h,02a41h,029d0h,0295fh,028eeh,0287dh
 dd 0280ch,0279bh,0272ah,026b9h,02648h,025d7h,02566h,024f5h,02483h,02412h
 dd 023a1h,02330h,022beh,0224dh,021dch,0216ah,020f9h,02087h,02016h,01fa4h
 dd 01f33h,01ec1h,01e50h,01ddeh,01d6dh,01cfbh,01c89h,01c18h,01ba6h,01b34h
 dd 01ac2h,01a51h,019dfh,0196dh,018fbh,01889h,01817h,017a6h,01734h,016c2h
 dd 01650h,015deh,0156ch,014fah,01488h,01416h,013a4h,01332h,012c0h,0124eh
 dd 011dch,01169h,010f7h,01085h,01013h,0fa1h,0f2fh,0ebdh,0e4ah,0dd8h
 dd 0d66h,0cf4h,0c81h,0c0fh,0b9dh,0b2bh,0ab8h,0a46h,09d4h,0961h
 dd 08efh,087dh,080bh,0798h,0726h,06b4h,0641h,05cfh,055ch,04eah
 dd 0478h,0405h,0393h,0321h,02aeh,023ch,01cah,0157h,0e5h,072h
 dd 00h

                IF do_VFX_Cos_Sin

VFX_Cos_Sin     PROC STDCALL USES ebx esi edi es,\
                Angle:F16, Cos_ptr:PTR F16, Sin_ptr:PTR F16

                mov     ebx,Angle
                and     ebx,ebx         ;make sure angle's between 0 and 2*pi
                jns     CheckInRange
MakePos:                                ;less than 0, so make it positive
                add     ebx,360*10
                js      MakePos
                jmp     CheckInRange

MakeInRange:                            ;make sure angle is no more than 2*pi
                sub     ebx,360*10
CheckInRange:
                cmp     ebx,360*10
                jg      MakeInRange
                
                cmp     ebx,180*10              ;figure out which quadrant
                ja      BottomHalf              ;quadrant 2 or 3
                cmp     ebx,90*10               ;quadrant 0 or 1
                ja      Quadrant1
                                                ;quadrant 0
                shl     ebx,2
                mov     eax,CosTable[ebx]       ;look up sine
                neg     ebx                     ;sin(Angle) = cos(90-Angle)
                mov     edx,CosTable[ebx+90*10*4]       ;look up cosine
                jmp     CSDone

Quadrant1:
                neg     ebx
                add     ebx,180*10              ;convert to angle between 0 and 90
                shl     ebx,2
                mov     eax,CosTable[ebx]       ;look up cosine
                neg     eax                     ;negative in this quadrant
                neg     ebx                     ;sin(Angle) = cos(90-Angle)
                mov     edx,CosTable[ebx+90*10*4] ;look up cosine
                jmp     CSDone
                
BottomHalf:                                     ;quadrant 2 or 3
                neg     ebx
                add     ebx,360*10              ;convert to between 0 and 180
                cmp     ebx,90*10               ;quadrant 2 or 3
                ja      Quadrant2
                                                ;quadrant 3
                shl     ebx,2
                mov     eax,CosTable[ebx]       ;look up cosine
                neg     ebx                     ;sin(Angle) = cos(90-Angle)
                mov     edx,CosTable[90*10*4+ebx] ;look up sine
                neg     edx                     ;negative in this quadrant
                jmp     CSDone
                
Quadrant2:
                neg     ebx
                add     ebx,180*10              ;convert to between 0 and 90
                shl     ebx,2
                mov     eax,CosTable[ebx]       ;look up cosine
                neg     eax                     ;negative in this quadrant
                neg     ebx                     ;sin(Angle) = cos(90-Angle)
                mov     edx,CosTable[90*10*4+ebx] ;look up sine
                neg     edx                     ;negative in this quadrant
CSDone:
                ASSUME  ebx:NOTHING

                mov     ebx,Cos_ptr
                mov     [ebx],eax
                mov     ebx,Sin_ptr
                mov     [ebx],edx
                
                ret

VFX_Cos_Sin     ENDP

                ENDIF

;----------------------------------------------------------------------------
; 
;       FIXEDPOINT VFX_fixed_mul(FIXEDPOINT M1, FIXEDPOINT M2, FP *result);
;
;       Multiplies two fixed-point values together.
;
;----------------------------------------------------------------------------

EDX_FIXED_MUL   MACRO M1

                imul    M1
                add     eax,8000h       ;round by adding 2^(-17)
                adc     edx,0           ;whole part of result is in DX

                ENDM


FIXED_MUL       MACRO M1, M2

                mov eax,M1

                EDX_FIXED_MUL M2

                mov     ax,dx
                ror     eax,16          ;(E)AX = whole & E(AX) = fraction

                ENDM

                IF do_VFX_fixed_mul

VFX_fixed_mul   PROC STDCALL USES ebx esi edi es,\
                M1:F16,M2:F16,result:PTR F16

                FIXED_MUL M1, M2

                mov     edi,result
                mov     DWORD PTR [edi],eax

                ret

VFX_fixed_mul   ENDP

                ENDIF

;----------------------------------------------------------------------------
;
; void VFX_point_transform(POINT *in, POINT *out, POINT *origin, LONG rot,
;                          FIXEDPOINT x_scale, FIXEDPOINT y_scale)
;
; Scales the point (in) in both x and y by the x_scale and y_scale parameters,
; then rotates it by the specified angle (rot/10 degrees) around the
; point (origin).  The result is written to the structure (out).
;
;----------------------------------------------------------------------------

                IF do_VFX_point_transform

VFX_point_transform PROC STDCALL USES ebx esi edi es, \
                P_in:PPOINT, P_out:PPOINT, Origin:PPOINT, \
                Rot:F16, X_scale:F16, Y_scale:F16
                LOCAL cos, sin
                LOCAL dxcos, dysin
                LOCAL dxsin, dycos
                LOCAL dxs, dys

                cld
                push ds
                pop es

                ASSUME  esi:PPOINT
                ASSUME  edi:PPOINT

                invoke VFX_Cos_Sin, Rot, ADDR cos, ADDR sin  

                mov esi,[P_in]
                mov edi,[Origin]

                mov eax,[esi].x                 ;compute dx
                sub eax,[edi].x
                sal eax,16                      ;long to fixed

                EDX_FIXED_MUL X_scale          
                mov ebx,edx

                FIXED_MUL ebx, cos
                mov dxcos,eax
                FIXED_MUL ebx, sin
                mov dxsin,eax

                mov eax,[esi].y                 ;compute dy
                sub eax,[edi].y
                sal eax,16                      ;long to fixed

                EDX_FIXED_MUL Y_scale          
                mov ecx,edx

                FIXED_MUL ecx, cos
                mov dycos,eax
                FIXED_MUL ecx, sin
                mov dysin,eax

                mov esi,[P_out]

                mov edx,dxcos                   ;compute out.x
                sub edx,dysin
                add edx,[edi].x
                mov [esi].x,edx

                mov edx,dycos                   ;compute out.y
                add edx,dxsin
                add edx,[edi].y
                mov [esi].y,edx

                ret

VFX_point_transform ENDP

                ENDIF

;----------------------------------------------------------------------------
;
; LONG VFX_font_height(void *font)
;
; Returns the height (in pixels) of the specified font.
;
;----------------------------------------------------------------------------

                IF do_VFX_font_height

VFX_font_height PROC STDCALL USES ebx esi edi es, \
                Font_ptr:PFONT

                ASSUME esi:PFONT

                mov esi,[Font_ptr]
                mov eax,[esi].char_height

                ret

VFX_font_height ENDP

                ENDIF

;----------------------------------------------------------------------------
;
; LONG VFX_character_width(void *font, LONG character)
;
; Returns the width (in pixels) of the specified character in font.
;
;----------------------------------------------------------------------------

                IF do_VFX_character_width

VFX_character_width  PROC STDCALL USES ebx esi edi es, \
                Font_ptr:PFONT, Character:S32

                mov eax,[Character]             ;get index #
                shl eax,2                       ;mult by 4 (sizeof(long))
                add eax,[Font_ptr]              ;add base address
                add eax,16                      ;skip header to offsets

                mov esi,[eax]                   ;get character offset
                add esi,[Font_ptr]              ;add base address

                mov eax,DWORD PTR [esi]         ;get char width in eax

                ret

VFX_character_width  ENDP

                ENDIF

;----------------------------------------------------------------------------
;
; long VFX_character_draw(PANE *pane, LONG x, LONG y, void *font,
;                         LONG character, BYTE *color_translate)
;
; Draws a character from a font to x,y in the specified pane with clipping.
; If color_translate is NULL, the character's pixels are copied with no
; color translation or transparency.  If color_translate points to a table, 
; pixels with a color value of 255 are skipped, resulting in transparency.
;
;----------------------------------------------------------------------------

                IF do_VFX_character_draw

VFX_character_draw PROC STDCALL USES ebx esi edi es, \
                Target:PPANE, X:S32, Y:S32, Font_ptr:PFONT, Character:S32, Translate:PTR

                LOCAL src_char_width, dst_char_width, window_byte_width
                LOCAL char_height

                LOCAL    CP_L   ;Leftmost pixel in Window coord.
                LOCAL    CP_T   ;Top
                LOCAL    CP_R   ;Right
                LOCAL    CP_B   ;Bottom
              
                LOCAL    CP_A   ;Base address of Clipped Pane
                LOCAL    CP_BW  ;Width of underlying window (bytes)
                LOCAL    CP_W   ;Width of underlying window (pixels)
                
                LOCAL    CP_CX  ;Window x coord. = Pane x coord. + CP_CX
                LOCAL    CP_CY  ;Window y coord. = Pane x coord. + CP_CY

                LOCAL    pixel_pitch
                LOCAL    bytes_per_pixel

                cld
                push ds
                pop es

                CLIP_PANE_TO_WINDOW Target

                CONVERT_PAIR_PANE_TO_WINDOW X,Y

                mov esi,[Font_ptr]
                mov edx,[esi].VFX_FONT.char_height

                mov eax,[Character]             ;get index #
                shl eax,2                       ;mult by 4 (sizeof(long))
                add eax,[Font_ptr]              ;add base address
                add eax,16                      ;skip header to offsets

                mov esi,[eax]                   ;get character offset
                add esi,[Font_ptr]              ;add base address

                mov dst_char_width,0
                mov ecx,[esi]                   ;get char width in eax
                mov src_char_width,ecx
                cmp ecx,0
                je __return

                add esi,4                       ;point to bitmap

                mov edi,[Target]

                mov eax,CP_R                    ;Clip right
                inc eax
                sub eax,ecx                     
                sub eax,X                       ;eax=x1-x-char_width
                jns __clip_left                 ;jump if char will fit

                add ecx,eax                     ;adjust char_width
                jle __return                    ;if width<=0 skip draw

__clip_left:
                mov eax,X                       ;Clip Left
                sub eax,CP_L
                ;cmp eax,0
                jns __clip_bottom               ;jump if char will fit

                add ecx,eax                     ;adjust char_width
                jle __return                    ;if width<=0 skip draw

                sub esi,eax                     ;add new bitmap x offset
                sub X,eax                       ;set to edge of pane

__clip_bottom:
                mov eax,CP_B                    ;Clip Bottom
                inc eax
                sub eax,edx
                sub eax,Y                       ;eax=y1-y-char_height
                jns __clip_top                  ;jump if char will fit

                add edx,eax                     ;adjust char_height
                jle __return                    ;if height<=0 skip draw

__clip_top:
                mov eax,Y                       ;Clip Top
                sub eax,CP_T
                ;cmp eax,0
                jns __setup_copy                ;jump if char will fit

                add edx,eax                     ;adjust char_height
                jle __return                    ;if height<=0 skip draw

                sub Y,eax                       ;set to edge of pane
                imul eax,src_char_width
                sub esi,eax                     ;add new bitmap y offset

__setup_copy:   
                mov char_height,edx

                GET_WINDOW_ADDRESS X,Y
                mov edi,eax

                mov dst_char_width,ecx
                sub src_char_width,ecx

                mov ebx,ecx
                imul ebx,pixel_pitch            ;get # of bytes wide

                mov eax,CP_BW
                sub eax,ebx                     ;set up EDI addend
                mov window_byte_width,eax

                cmp Translate,0
                jnz __use_translate

__copy_line:                                    ;do 16-bit writes for overhead        

                shr ecx,1                       ;3
                rep movsw                       ;8+4*ecx/2
                adc ecx,0                       ;2
                rep movsb                       ;8

                mov ecx,dst_char_width          ;setup for next line
                add esi,src_char_width
                add edi,window_byte_width       ;skip to next dest line
                dec char_height
                jnz __copy_line                 ;jump if more lines

                mov eax,src_char_width
                add eax,dst_char_width          ;return char width to caller

                ret

__use_translate:
                jecxz __return                  ;skip if char_width=0
                mov ebx,[Translate]
                mov edx,0                       ;leave upper 24 bits zero!

__translate_line:
                cmp bytes_per_pixel,2
                je __translate_2bpp

__translate_1bpp:
                mov dl,BYTE PTR [esi]           ;copy bitmap line
                mov al,BYTE PTR [edx][ebx]
                cmp al,0ffh
                je __skip_1bpp
                mov BYTE PTR [edi],al
__skip_1bpp:
                inc esi
                inc edi
                loop __translate_1bpp
                jmp __next_translate

__translate_2bpp:
                mov dl,BYTE PTR [esi]           ;copy bitmap line
                mov ax,WORD PTR [edx*2][ebx]
                cmp ax,-2                       ;-2=15/16bpp transparent key
                je __skip_2bpp
                mov WORD PTR [edi],ax
__skip_2bpp:
                inc esi
                add edi,pixel_pitch
                loop __translate_2bpp

__next_translate:    
                mov ecx,dst_char_width          ;setup for next line
                add esi,src_char_width
                add edi,window_byte_width       ;skip to next dest line
                dec char_height
                jnz __translate_line            ;jump if more lines

__return:
                mov eax,src_char_width
                add eax,dst_char_width          ;return char width to caller

                ret

VFX_character_draw ENDP

                ENDIF

;----------------------------------------------------------------------------
;
; void VFX_string_draw(PANE *pane, LONG x, LONG y, void *font, CHAR *string,
;                      BYTE *color_translate)
;
;
; Warning: Does not wrap!
;
;----------------------------------------------------------------------------

                IF do_VFX_string_draw

VFX_string_draw PROC STDCALL USES ebx esi edi es, \
                Target:PPANE, X:S32, Y:S32, Font_ptr:PFONT, String:PTR S8, Translate:PTR

                cld
                push ds
                pop es

                mov esi,[String]
                mov edi,[X]

__draw_char:
                movzx eax,BYTE PTR [esi]
                cmp eax,0
                je __bail
                invoke VFX_character_draw, \
                       [Target],edi,[Y],[Font_ptr],eax,[Translate]

                add edi,eax                     ;add char width to X
                inc esi
                jmp __draw_char

__bail:         ret

VFX_string_draw ENDP

                ENDIF

;----------------------------------------------------------------------------
;
; void VFX_line_to_pane(PANE *pane, y, UBYTE *line_buffer, LONG length)
;
; Copies the pixels in line_buffer to the specified pane at row y
;
;----------------------------------------------------------------------------

VFX_line_to_pane PROC STDCALL USES ebx esi edi es, \
                Target:PPANE, Y, Line_buffer, Line_length

                LOCAL X

                LOCAL    CP_L   ;Leftmost pixel in Window coord.
                LOCAL    CP_T   ;Top
                LOCAL    CP_R   ;Right
                LOCAL    CP_B   ;Bottom
              
                LOCAL    CP_A   ;Base address of Clipped Pane
                LOCAL    CP_BW  ;Width of underlying window (bytes)
                LOCAL    CP_W   ;Width of underlying window (pixels)
                
                LOCAL    CP_CX  ;Window x coord. = Pane x coord. + CP_CX
                LOCAL    CP_CY  ;Window y coord. = Pane x coord. + CP_CY

                LOCAL    pixel_pitch
                LOCAL    bytes_per_pixel

                cld
                push ds
                pop es

                CLIP_PANE_TO_WINDOW Target

                mov X,0
                CONVERT_PAIR_PANE_TO_WINDOW X,Y

                mov esi,[Line_buffer]

                ASSUME edi:NOTHING
                mov edi,[Target]

                mov ecx,[Line_length]

                mov eax,CP_R                    ;Clip right
                sub eax,X
                inc eax
                sub eax,ecx                     ;eax=x1-length
                jns __clip_left                 ;jump if line will fit

                add ecx,eax                     ;adjust line length
                jle __return                    ;if length<=0 skip draw

__clip_left:
                mov eax,X                       ;Clip Left
                sub eax,CP_L
                jns __clip_bottom               ;jump if line will fit

                add ecx,eax                     ;adjust line length
                jle __return                    ;if width<=0 skip draw

                sub esi,eax                     ;add new bitmap x offset
                sub X,eax                       ;set to edge of pane

__clip_bottom:
                mov eax,CP_B                    ;Clip Bottom
                sub eax,Y                       ;eax=y1-y
                js __return                     ;if y>y1 skip draw

__clip_top:
                mov eax,Y                       ;Clip Top
                sub eax,CP_T
                js __return                     ;if y<y0 skip draw

                GET_WINDOW_ADDRESS X,Y
                mov edi,eax

                mov edx,ecx                     ;copy line to pane
                and ecx,3
                rep movsb
                mov ecx,edx
                shr ecx,2
                rep movsd

__return:
                ret

VFX_line_to_pane ENDP

;----------------------------------------------------------------------------
;
; find_ILBM_property(CHAR *property_title, UBYTE *ILBM_buffer)
;
; Returns the offset address of the specified property in the ILBM_buffer.
;
;----------------------------------------------------------------------------

BMHD_prop       db 'BMHD'
CMAP_prop       db 'CMAP'
BODY_prop       db 'BODY'

find_ILBM_property   PROC STDCALL USES ebx esi edi es,\
                PropTitle,Pointer

                cld
                push ds
                pop es

                mov esi,[Pointer]

                add esi,12               ;skip FORM ILBM/PBM header

__find_text:    cmp BYTE PTR [esi],0     ;circumvent DPaint IIE bug
                jne __check
                inc esi
                jmp __find_text

__check:        mov ecx,2
                mov edi,[PropTitle]
                mov eax,esi
                repe cmpsw               ;compare with property header
                je __found               ;strings match, exit
                mov esi,eax
                add esi,6
                lodsw                    ;else get property length
                xchg al,ah
                and eax,0ffffh
                add esi,eax              ;point to the next property
                jmp __find_text          ;...and go check it

__found:        add eax,8
                ret

find_ILBM_property   ENDP

;----------------------------------------------------------------------------
;
; long VFX_ILBM_draw(PANE *pane,UBYTE *ILBM_buffer)
;
; Draws ILBM formatted image to the specified pane.
;
;----------------------------------------------------------------------------

                IF do_VFX_ILBM_draw

VFX_ILBM_draw   PROC STDCALL USES ebx esi edi es, \
                Target:PPANE, ILBM_buffer:PTR

                LOCAL PBM_flag
                LOCAL bmap_height, bmap_width, bmap_ptr, bmap_count
                LOCAL byte_count, byte_count_temp
                LOCAL height_1, width_1, y1_1
                LOCAL compress_type, byte_width, line_width
                LOCAL xcolor
                LOCAL wndbuf

                cld
                push ds
                pop es

                ASSUME edi:PPANE
                mov edi,[Target]

                mov eax,[edi].x1
                sub eax,[edi].x0
                inc eax
                mov width_1,eax

                mov eax,[edi].y1
                sub eax,[edi].y0
                inc eax
                mov height_1,eax

                mov edi,[edi].window
                ASSUME edi:NOTHING
                mov edi,[edi]
                mov wndbuf,edi

                mov y1_1,0

                mov edi,[ILBM_buffer]
                mov eax,[edi+8]         ;DPaint IIE doesn't use ILBM format
                xor eax,'MBLI'          ;for mode 13H images, so skip bitmap
                mov PBM_flag,eax        ;reconstruction if no 'ILBM' present

                invoke find_ILBM_property, OFFSET BMHD_prop, [ILBM_buffer]
                mov esi,eax
                lods WORD PTR [esi]
                xchg al,ah              
                and eax,0ffffh
                mov bmap_width,eax
                lods WORD PTR [esi]
                xchg al,ah              
                and eax,0ffffh
                cmp eax,height_1        ;set height to smaller of bitmap or
                jl __set_height         ;window height

                mov eax,height_1

__set_height:   mov bmap_height,eax
                add esi,5
                lods BYTE PTR [esi]   
                cmp al,1                ;mask plane (DPaint "template") used?
                je __image_done         ;yes, abort

                mov eax,0
                lods BYTE PTR [esi]
                mov compress_type,eax

                add esi,2
                mov eax,0
                lods BYTE PTR [esi]
                mov xcolor,eax          ;get DPaint "background color"
                
                mov eax,bmap_width
                mov ebx,eax
                shr eax,3
                and ebx,111b            ;round up to even byte width:
                cmp ebx,1               ;C == !BX
                sbb eax,-1              ;AX += !C 
                mov ebx,eax
                and eax,1
                add ebx,eax
                mov byte_width,ebx

                mov eax,bmap_width
                and eax,1
                add eax,bmap_width
                mov line_width,eax
                
                mov eax,bmap_width      ;set width to smaller of bitmap or
                cmp eax,width_1         ;window width
                jl __set_width

                mov eax,width_1

__set_width:    
                mov bmap_width,eax

                invoke find_ILBM_property, OFFSET BODY_prop, [ILBM_buffer]
                mov bmap_ptr,eax

__do_line:      mov esi,bmap_ptr        ;get start-of-line
                cmp compress_type,1
                jne __not_packed        ;no compression used

                mov edi,OFFSET LBM_line_buffer 
                mov edx,line_width      ;else unpack RL-encoded line to buffer
                add edx,edi             ;edx = end of line
__get_token:    cmp edi,edx
                jae __unpack_done

                lodsb
                movzx ecx,al
                cmp ecx,128              
                jz __get_token          ;-128: nop
                ja __rep_run            ;[-1..-127]: rep next byte -n+1 times

                inc ecx                 ;[0..127]: next n+1 bytes verbatim

                push ecx
                and ecx,3
                rep movsb
                pop ecx
                shr ecx,2
                rep movsd

                jmp __get_token

__rep_run:      lodsb
                mov ah,al
                mov ebx,eax
                shl eax,16
                mov ax,bx

                neg cl
                inc cl

                push ecx
                and ecx,3
                rep stosb
                pop ecx
                shr ecx,2
                rep stosd

                jmp __get_token

__unpack_done:  mov bmap_ptr,esi        
                mov esi,OFFSET LBM_line_buffer
                jmp __draw_line

__not_packed:   mov eax,esi
                add eax,line_width
                mov bmap_ptr,eax

__draw_line:    cmp PBM_flag,0
                jne __draw_PBM

                ASSUME edi:NOTHING
                mov edi,OFFSET BM_line_buffer

                mov eax,byte_width              ;unpack interleaved bit planes
                mov byte_count,eax              ;from ILBM file
                mov byte_count_temp,eax
                mov eax,bmap_width              ;("Old" DPaint format)
                mov bmap_count,eax      

__draw_ILBM:    mov edx,80h
__for_plane:    mov ebx,0
                mov eax,100h
__for_value:    movzx ecx,BYTE PTR [ebx][esi]
                and ecx,edx
                jz __next_value

                or al,ah

__next_value:   add ebx,byte_count_temp
                shl ah,1
                jnz __for_value

                stosb
                dec bmap_count
                jz __end_ILBM

                shr dl,1
                jnz __for_plane

                inc esi
                dec byte_count
                jnz __draw_ILBM

__end_ILBM:     
                invoke VFX_line_to_pane, \
                [Target],y1_1,OFFSET BM_line_buffer,bmap_width        

                jmp __next_line
             
__draw_PBM:     
                invoke VFX_line_to_pane, \
                [Target],y1_1,esi,bmap_width        
        

__next_line:    inc y1_1
                dec bmap_height
                jnz __do_line

__image_done:                        
                mov eax,xcolor
                ret

VFX_ILBM_draw   ENDP

                ENDIF

;----------------------------------------------------------------------------
;
; void VFX_ILBM_palette(UBYTE *ILBM_buffer, RGB *palette);
;
; Returns palette information from ILBM file in RGB array at palette.
;
;----------------------------------------------------------------------------

                IF do_VFX_ILBM_palette

VFX_ILBM_palette PROC STDCALL USES ebx esi edi es, \
                FORM_ILBM:PTR,Dest:PTR VFX_RGB

                cld
                push ds
                pop es

                invoke find_ILBM_property,OFFSET CMAP_prop,[FORM_ILBM]
                mov esi,eax
                mov edi,[Dest]

                mov ecx,768
                rep movsb

                ret
VFX_ILBM_palette ENDP

                ENDIF

;----------------------------------------------------------------------------
;
; long VFX_ILBM_resolution(UBYTE *ILBM_buffer);
;
; Returns x,y resolution (image size) in pixels.  (E)AX=x E(AX)=y.
;
;----------------------------------------------------------------------------

                IF do_VFX_ILBM_resolution

VFX_ILBM_resolution PROC STDCALL USES ebx esi edi es, \
                ILBM_buffer:PTR

                cld
                push ds
                pop es

                invoke find_ILBM_property, OFFSET BMHD_prop, [ILBM_buffer]
                mov esi,eax
                lods WORD PTR [esi]
                xchg al,ah              
                shl eax,16              ;put x resolution in (E)AX

                lods WORD PTR [esi]
                xchg al,ah              

                ret
VFX_ILBM_resolution ENDP

                ENDIF

;----------------------------------------------------------------------------
;
; void VFX_PCX_draw(PANE *pane,UBYTE *PCX_buffer)
;
; Draws ILBM formatted image to the specified pane.
;
;----------------------------------------------------------------------------

                IF do_VFX_PCX_draw

VFX_PCX_draw    PROC STDCALL USES ebx esi edi es, \
                Target:PPANE, PCX_file_size:S32, PCX_buffer:PTR

                LOCAL bytes_per_line,height
                LOCAL xcolor

                cld
                push ds
                pop es

                mov xcolor,0

                ASSUME edi:PPANE                
                mov edi,[Target]                ;setup dest pane ptr
                mov edi,[edi].window
                ASSUME edi:NOTHING
                mov edi,[edi]

                ASSUME esi:PPCX                 ;get number of lines
                mov esi,[PCX_buffer]
                movzx ebx,WORD PTR [esi].ymax
                sub bx,WORD PTR [esi].ymin
                mov height,ebx
                mov ebx,0                       ;ebx = y

                movzx eax,WORD PTR [esi].bytes_per_line
                mov bytes_per_line,eax

                ASSUME esi:NOTHING
                add esi,128                     ;skip past header

__next_line:
                mov edi,OFFSET BM_line_buffer
                mov edx,edi
__do_line:      
                add edx,bytes_per_line          ;setup eol check
__do_byte:
                lodsb                           ;get a key byte
                mov ah,al
                and ah,0c0h
                xor ah,0c0h
                jnz __store_it

                and eax,3fh                     ;and off the high bits
                mov ecx,eax                     ;setup run counter
                lodsb                           ;get the run byte in al
                rep stosb                       ;run the byte
                jmp __check_eol
__store_it:
                stosb
__check_eol:
                cmp edi,edx                     
                jl __do_byte                    ;jump if not to eol

                invoke VFX_line_to_pane, \
                [Target],ebx,OFFSET BM_line_buffer,bytes_per_line

                inc ebx                         ;inc y
                cmp ebx,height
                jle __next_line

__image_done:                        
                mov eax,xcolor
                ret

VFX_PCX_draw    ENDP

                ENDIF


;----------------------------------------------------------------------------
;
; void VFX_PCX_palette(UBYTE *PCX_buffer, LONG PCX_file_size,
;                          RGB *palette);
;
; Returns palette information from PCX file in RGB array at palette.
;
;----------------------------------------------------------------------------

                IF do_VFX_PCX_palette

VFX_PCX_palette PROC STDCALL USES ebx esi edi es, \
                PCX_buffer:PTR, PCX_file_size:S32, Palette:PTR VFX_RGB

                cld
                push ds
                pop es

                mov esi,[PCX_buffer]
                add esi,[PCX_file_size]
                sub esi,768                     ;backup to palette start

                mov edi,[Palette]               ;setup destination ptr

                mov ecx,768
                rep movsb

                ret
VFX_PCX_palette ENDP

                ENDIF

;----------------------------------------------------------------------------
;
; long VFX_PCX_resolution(UBYTE *PCX_buffer);
;
; Returns x,y resolution (image size) in pixels.  (E)AX=x E(AX)=y.
;
;----------------------------------------------------------------------------

                IF do_VFX_PCX_resolution

VFX_PCX_resolution PROC STDCALL USES ebx esi edi es, \
                PCX_buffer:PTR

                ASSUME esi:PPCX

                mov esi,[PCX_buffer]

                mov ax,[esi].xmax
                sub ax,[esi].xmin
                inc ax
                shl eax,16

                mov ax,[esi].ymax
                sub ax,[esi].ymin
                inc ax

                ret
VFX_PCX_resolution ENDP

                ENDIF

;----------------------------------------------------------------------------
;
; GIF_init_codetable - Initializes the GIF code table
;
; Entry:        ECX = code
;
;----------------------------------------------------------------------------

GIF_init_codetable PROC

                mov ebx,0                       ;start with a zero code
                mov eax,ecx
                add eax,2                       ;nextcode = clearcode + 2
                mov [edi].GIFDATA.nextcode,eax

                mov eax,ecx                     ;nextlimit = clearcode * 2
                shl eax,1
                mov [edi].GIFDATA.nextlimit,eax

__init_table1:
                cmp ebx,ecx                     
                jge __init_table2               ;while code < clearcode

                mov BYTE PTR [edi+GIF_FIRST+ebx],bl
                mov BYTE PTR [edi+GIF_LAST+ebx],bl
                mov WORD PTR [edi+GIF_LINK+ebx*2],0ffffh
                inc ebx
                jmp __init_table1

__init_table2:
                cmp ebx,4096                    
                jge __init_table3               ;while code < 4096

                mov WORD PTR [edi+GIF_LINK+ebx*2],0fffeh
                inc ebx
                jmp __init_table2

__init_table3:
                ret

GIF_init_codetable ENDP

;----------------------------------------------------------------------------
;
; GIF_getb - Gets the buffer length
;
;----------------------------------------------------------------------------

GIF_getb        PROC

                cmp [edi].GIFDATA.bufct,0
                jne __getb2

                lodsb                           ;get a byte from GIF_buffer
                and eax,0ffh
                mov [edi].GIFDATA.bufct,eax

__getb2:
                lodsb                           ;get a byte from GIF_buffer
                and eax,0ffh

                dec [edi].GIFDATA.bufct         ;got the byte
                ret

GIF_getb        ENDP

;----------------------------------------------------------------------------
;
; GIF_getbcode - Gets a Bcode from source buffer
;
; Entry:        EDX = [edi].GIFDATA.reqct
;
; Returns:      EAX = code
;
;----------------------------------------------------------------------------

GIF_getbcode    PROC

                cmp [edi].GIFDATA.remct,0
                jne __getbcode1

                call GIF_getb
                mov [edi].GIFDATA.rem,eax
                mov [edi].GIFDATA.remct,8

__getbcode1:
                mov eax,edx
                cmp [edi].GIFDATA.remct,eax
                jnl __getbcode2

                call GIF_getb
                mov ecx,[edi].GIFDATA.remct
                shl eax,cl
                or [edi].GIFDATA.rem,eax

                add [edi].GIFDATA.remct,8

__getbcode2:
                mov ebx,edx
                movzx eax,BYTE PTR [GIF_cmask+ebx]
                mov ebx,[edi].GIFDATA.rem
                and ebx,eax
                push ebx

                sub [edi].GIFDATA.remct,edx

                mov ecx,edx
                shr [edi].GIFDATA.rem,cl

                pop eax
                ret

GIF_getbcode    ENDP

;----------------------------------------------------------------------------
;
; GIF_insertcode - Inserts a code into the table
;
; Entry:        EBX = code
;               ECX = oldcode
;
;----------------------------------------------------------------------------

GIF_insertcode  PROC

                push ebx
                mov ebx,[edi].GIFDATA.nextcode
                mov WORD PTR [edi+GIF_LINK+ebx*2],cx
                pop ebx

                push ebx
                mov al,BYTE PTR [edi+GIF_FIRST+ebx]
                mov ebx,[edi].GIFDATA.nextcode
                mov BYTE PTR [edi+GIF_LAST+ebx],al

                mov ebx,ecx
                mov al,BYTE PTR [edi+GIF_FIRST+ebx]
                mov ebx,[edi].GIFDATA.nextcode
                mov BYTE PTR [edi+GIF_FIRST+ebx],al
                pop ebx

                inc [edi].GIFDATA.nextcode
                mov eax,[edi].GIFDATA.nextcode
                cmp eax,[edi].GIFDATA.nextlimit
                jne __insertcode2

                cmp [edi].GIFDATA.reqct,12
                jnl __insertcode2

                inc [edi].GIFDATA.reqct
                shl [edi].GIFDATA.nextlimit,1

__insertcode2:
                ret
                
GIF_insertcode  ENDP

;----------------------------------------------------------------------------
;
; GIF_dopixel - Writes one pixel to the line_buffer
;
; Entry:        AL = pixel value
;
;----------------------------------------------------------------------------

GIF_dopixel     PROC

                mov ebx,[edi].GIFDATA.xloc
                mov [BM_line_buffer+ebx],al
                inc [edi].GIFDATA.xloc

                dec [edi].GIFDATA.rowcnt
                cmp [edi].GIFDATA.rowcnt,0
                jne __dopixel3

                invoke VFX_line_to_pane, \
                GIF_pane,[edi].GIFDATA.yloc,OFFSET BM_line_buffer,[edi].GIFDATA.imagewide

                mov [edi].GIFDATA.xloc,0
                mov eax,[edi].GIFDATA.imagewide
                mov [edi].GIFDATA.rowcnt,eax

                cmp [edi].GIFDATA.interlaced,0
                je __dopixel2

                movzx ebx,[edi].GIFDATA.pass
                movzx eax,[GIF_inctable+ebx]
                add [edi].GIFDATA.yloc,eax

                mov eax,[edi].GIFDATA.yloc
                cmp eax,[edi].GIFDATA.imagedepth
                jl __dopixel1

                inc [edi].GIFDATA.pass
                movzx ebx,[edi].GIFDATA.pass
                movzx eax,[GIF_starttable + ebx]
                mov [edi].GIFDATA.yloc,eax

__dopixel1:     jmp __dopixel3

__dopixel2:
                inc [edi].GIFDATA.yloc
                mov eax,[edi].GIFDATA.yloc
                cmp eax,[edi].GIFDATA.imagedepth
                jl __dopixel3

                mov [edi].GIFDATA.yloc,0

__dopixel3:
                ret

GIF_dopixel     ENDP

;----------------------------------------------------------------------------
;
; long VFX_GIF_draw(PANE *pane,UBYTE *GIF_buffer
;
; Draws ILBM formatted image to the specified pane.
;
;----------------------------------------------------------------------------

                IF do_VFX_GIF_draw

VFX_GIF_draw    PROC STDCALL USES ebx esi edi es, \
                Target:PPANE, GIF_buffer:PTR

                LOCAL clearcode,eoi
                LOCAL code,oldcode
                LOCAL done
                LOCAL xcolor

                cld
                push ds
                pop es

                mov edi,[Target]                ;setup dest pane ptr
                mov GIF_pane,edi

                lea edi,GIF_scratch             ;setup scratch pad ptr
                mov eax,0
                mov ecx,SIZEOF GIFDATA

                mov edx,ecx                     ;zero temp mem buffer
                and ecx,3
                rep stosb
                mov ecx,edx
                shr ecx,2
                rep stosd

                lea edi,GIF_scratch             ;reset scratch pad ptr

                ASSUME esi:PGIF
                mov esi,[GIF_buffer]

                movzx eax,[esi].background_color
                mov xcolor,eax

                mov al,[esi].global_flag
                mov cl,al
                and cl,7
                inc cl
                mov ebx,1
                shl ebx,cl                      ;ebx = # of colors

                add esi,SIZEOF GIF              ;point past top of header

                test al,80h
                jz __over_global_colors

                imul ebx,3                      ;ebx = size of color array
                add esi,ebx

__over_global_colors:
                ASSUME esi:PLGIF

                movzx eax,[esi].image_wide
                mov [edi].GIFDATA.imagewide,eax
                movzx eax,[esi].image_depth
                mov [edi].GIFDATA.imagedepth,eax

                movzx eax,[esi].local_flag
                mov [edi].GIFDATA.interlaced,al
                and [edi].GIFDATA.interlaced,40h
                add esi,SIZEOF LGIF             ;point past top of header
                test al,80h                     ;is there a local color map?
                jz __no_local_colors

                mov cl,al
                and cl,7
                inc cl
                mov ebx,1
                shl ebx,cl                      ;ebx = # of colors
                imul ebx,3                      ;ebx = size of color array

                add esi,ebx                     ;point past local colors

__no_local_colors:
                mov [edi].GIFDATA.bufct,0
                lodsb                           ;get codestart

                movzx ecx,al
                mov edx,8                       ;pixel size in bits

                push ecx
                push edx

                mov eax,1
                shl eax,cl
                mov clearcode,eax               ;clearcode = 1 << codestart

                inc eax
                mov eoi,eax                     ;eoi = clearcode + 1 

                inc ecx
                mov [edi].GIFDATA.reqct,ecx     ;reqct = codestart + 1

                mov ecx,clearcode
                call GIF_init_codetable         ;init table with clearcode

                mov oldcode,0ffffh
                mov done,0
                mov [edi].GIFDATA.pass,0
                mov eax,[edi].GIFDATA.imagewide
                mov [edi].GIFDATA.rowcnt,eax

                mov [edi].GIFDATA.xloc,0
                mov [edi].GIFDATA.yloc,0

                pop edx
                pop ecx

__extimg1:
                push ecx
                push edx
                mov edx,[edi].GIFDATA.reqct

__getcode:
                cmp edx,8
                jg __getcode1

                push edx
                call GIF_getbcode
                pop edx
                jmp __getcode2

__getcode1:
                push edx
                mov edx,8
                call GIF_getbcode
                pop edx
                push eax

                push edx
                sub edx,8
                call GIF_getbcode
                pop edx
                shl eax,8
                pop ebx
                or eax,ebx
__getcode2:     

                mov code,eax
                pop edx
                pop ecx

                cmp eax,clearcode
                jne __extimg2

                push ecx
                push edx
                mov ecx,clearcode
                call GIF_init_codetable
                pop edx
                pop ecx

                mov eax,ecx
                inc eax
                mov [edi].GIFDATA.reqct,eax

                mov oldcode,0ffffh
                jmp __extimg7

__extimg2:
                cmp eax,eoi
                jne __extimg3

                
__flushin1:     
                cmp [edi].GIFDATA.bufct,0
                je __flushin2

                lodsb
                dec [edi].GIFDATA.bufct
                jmp __flushin1

__flushin2:     
                lodsb
                and eax,0ffh
                mov [edi].GIFDATA.bufct,eax
                cmp [edi].GIFDATA.bufct,0
                jne __flushin1
                

                mov done,0ffffh
                jmp __extimg7

__extimg3:      
                mov ebx,code
                cmp WORD PTR [edi+GIF_LINK+ebx*2],0fffeh
                je __extimg5

                cmp oldcode,0ffffh
                je __extimg4

                push ecx
                push edx

                mov ecx,oldcode
                call GIF_insertcode
                pop edx
                pop ecx
__extimg4:
                jmp __extimg6

__extimg5:
                push ecx
                push edx
                mov ebx,oldcode
                mov ecx,oldcode
                call GIF_insertcode
                pop edx
                pop ecx

__extimg6:
                push ecx
                push edx
                mov ebx,code

__putx:
                push esi
                mov ecx,0
                mov esi,edi
                add esi,GIF_STACK

__putx1:
                mov al,BYTE PTR [edi+GIF_LAST+ebx]
                mov BYTE PTR [esi],al
                inc esi

                inc ecx
                movzx ebx,WORD PTR [edi+GIF_LINK+ebx*2]
                cmp ebx,0ffffh  
                jne __putx1

                cmp edx,1
                jne __putx3

__putx2:
                dec esi
                mov al,BYTE PTR [esi]
                and eax,1
                push ecx
                call GIF_dopixel
                pop ecx
                mov al,BYTE PTR [esi]
                and eax,0ffh
                shr eax,1
                push ecx
                call GIF_dopixel
                pop ecx
                loop __putx2

                jmp __putx4

__putx3:
                dec esi
                mov al,BYTE PTR [esi]
                and eax,0ffh
                push ecx
                call GIF_dopixel
                pop ecx
                loop __putx3

__putx4:        
                pop esi

                pop edx
                pop ecx

                mov eax,code
                mov oldcode,eax

__extimg7:
                cmp done,0
                jne __extimg8
                jmp __extimg1

__extimg8:
                mov eax,xcolor                  ;return background color
                ret

VFX_GIF_draw    ENDP

                ENDIF


;----------------------------------------------------------------------------
;
; void VFX_GIF_palette(UBYTE *GIF_buffer, RGB *palette);
;
; Returns palette information from GIF file in RGB array at palette.
;
;----------------------------------------------------------------------------

                IF do_VFX_GIF_palette

VFX_GIF_palette PROC STDCALL USES ebx esi edi es, \
                GIF_buffer:PTR, Palette:PTR VFX_RGB

                cld
                push ds
                pop es

                ASSUME esi:PGIF

                mov esi,[GIF_buffer]

                mov al,[esi].global_flag
                add esi,SIZEOF GIF              ;point past top of header
                test al,80h                     ;is there a global color map?
                jz __no_global_colors

                mov cl,al
                and cl,7
                inc cl
                mov ebx,1
                shl ebx,cl                      ;ebx = # of colors
                imul ebx,3                      ;ebx = size of color array

                mov edi,[Palette]               ;setup destination ptr
                mov ecx,ebx                     ;setup counter
                rep movsb

__no_global_colors:
                ASSUME esi:PLGIF

                mov al,[esi].local_flag
                test al,80h                     ;is there a local color map?
                jz __no_local_colors

                mov cl,al
                and cl,7
                inc cl
                mov ebx,1
                shl ebx,cl                      ;ebx = # of colors
                imul ebx,3                      ;ebx = size of color array

                add esi,SIZEOF LGIF             ;point past top of header
                mov edi,[Palette]               ;overwrite global palette
                mov ecx,ebx                     ;setup counter
                rep movsb

__no_local_colors:
                ret

VFX_GIF_palette ENDP

                ENDIF

;----------------------------------------------------------------------------
;
; long VFX_GIF_resolution(UBYTE *GIF_buffer);
;
; Returns x,y resolution (image size) in pixels.  (E)AX=x E(AX)=y.
;
;----------------------------------------------------------------------------

                IF do_VFX_GIF_resolution

VFX_GIF_resolution PROC STDCALL USES ebx esi edi es, \
                GIF_buffer:PTR

                ASSUME esi:PGIF

                mov esi,[GIF_buffer]

                mov al,[esi].global_flag
                mov cl,al
                and cl,7
                inc cl
                mov ebx,1
                shl ebx,cl                      ;ebx = # of colors

                add esi,SIZEOF GIF              ;point past top of header

                test al,80h
                jz __over_colors

                imul ebx,3                      ;ebx = size of color array
                add esi,ebx

__over_colors:
                ASSUME esi:PLGIF
                mov ax,[esi].image_wide
                shl eax,16

                mov ax,[esi].image_depth

                ret

VFX_GIF_resolution ENDP

                ENDIF

;----------------------------------------------------------------------------
;
; long VFX_shape_bounds(void *shape_table, LONG shape_number);
;
; Returns width,height of the shape (including transparent areas) in pixels.  (E)AX=x E(AX)=y.
; (E)AX=x E(AX)=y.
;
;----------------------------------------------------------------------------

                IF do_VFX_shape_bounds

VFX_shape_bounds PROC STDCALL USES ebx esi edi es, \
                SHP_buffer:PTABLE, Shape_number:S32

                ASSUME esi:NOTHING

                mov esi,[SHP_buffer]
                add esi,8                       ;skip to offsets
                
                mov eax,Shape_number            ;point to shape offset ptr 
                shl eax,3                       ;mul eax by sizeof 2 longs
                add esi,eax                     

                mov esi,[esi]                   ;get shape offset ptr
                add esi,[SHP_buffer]            ;add base address

__over_colors:
                mov eax,[esi].SHAPEHEADER.bounds

                ret

VFX_shape_bounds ENDP

                ENDIF

;----------------------------------------------------------------------------
;
; long VFX_shape_origin(void *shape_table, LONG shape_number);
;
; Returns hotspot of the shape (in pixels) relative to the upper left bounds).
; (E)AX=x E(AX)=y.
;
;----------------------------------------------------------------------------

                IF do_VFX_shape_origin

VFX_shape_origin PROC STDCALL USES ebx esi edi es, \
                SHP_buffer:PTABLE, Shape_number:S32

                ASSUME esi:NOTHING

                mov esi,[SHP_buffer]
                add esi,8                       ;skip to offsets
                
                mov eax,Shape_number            ;point to shape offset ptr 
                shl eax,3                       ;mul eax by sizeof 2 longs
                add esi,eax                     

                mov esi,[esi]                   ;get shape offset ptr
                add esi,[SHP_buffer]            ;add base address

__over_colors:
                mov eax,[esi].SHAPEHEADER.origin

                ret

VFX_shape_origin ENDP

                ENDIF


;----------------------------------------------------------------------------
;
; long VFX_shape_resolution(void *shape_table, LONG shape_number);
;
; Returns x,y resolution (image size) in pixels.  (E)AX=x E(AX)=y.
;
;----------------------------------------------------------------------------

                IF do_VFX_shape_resolution

VFX_shape_resolution PROC STDCALL USES ebx esi edi es, \
                SHP_buffer:PTABLE, Shape_number:S32

                ASSUME esi:NOTHING

                mov esi,[SHP_buffer]
                add esi,8                       ;skip to offsets
                
                mov eax,Shape_number            ;point to shape offset ptr 
                shl eax,3                       ;mul eax by sizeof 2 longs
                add esi,eax                     

                mov esi,[esi]                   ;get shape offset ptr
                add esi,[SHP_buffer]            ;add base address

__over_colors:
                mov eax,[esi].SHAPEHEADER.xmax  ;eax = xmax - xmin
                sub eax,[esi].SHAPEHEADER.xmin
                inc eax                         ;      + 1

                mov ebx,[esi].SHAPEHEADER.ymax  ;ebx = ymax - ymin
                sub ebx,[esi].SHAPEHEADER.ymin
                inc ebx                         ;      + 1

                shl eax,16
                mov ax,bx

                ret

VFX_shape_resolution ENDP

                ENDIF

;----------------------------------------------------------------------------
;
; long VFX_shape_minxy(void *shape_table, LONG shape_number);
;
; Returns min x,min y in pixels.  (E)AX=x E(AX)=y.
;
;----------------------------------------------------------------------------

                IF do_VFX_shape_minxy

VFX_shape_minxy PROC STDCALL USES ebx esi edi es, \
                SHP_buffer:PTABLE, Shape_number:S32

                ASSUME esi:NOTHING

                mov esi,[SHP_buffer]
                add esi,8                       ;skip to offsets
                
                mov eax,Shape_number            ;point to shape offset ptr 
                shl eax,3                       ;mul eax by sizeof 2 longs
                add esi,eax                     

                mov esi,[esi]                   ;get shape offset ptr
                add esi,[SHP_buffer]            ;add base address

                mov eax,[esi].SHAPEHEADER.xmin  ;eax = xmin
                shl eax,16

                mov ax,WORD PTR [esi].SHAPEHEADER.ymin  ;ebx = ymin

                ret

VFX_shape_minxy ENDP

                ENDIF

;----------------------------------------------------------------------------
;
; void VFX_shape_palette(void *shape_table, LONG shape_number, RGB *Palette);
;
; Returns shape palette information in Palette.
;
;----------------------------------------------------------------------------

                IF do_VFX_shape_palette

VFX_shape_palette PROC STDCALL USES ebx esi edi es, \
                SHP_buffer:PTABLE, Shape_number:S32, Palette:PTR VFX_RGB

                cld
                push ds
                pop es

                ASSUME esi:NOTHING

                mov esi,[SHP_buffer]
                add esi,8                       ;skip to offsets
                
                mov eax,Shape_number            ;point to shape offset ptr 
                shl eax,3                       ;mul eax by sizeof 2 longs
                add esi,eax                     
                add esi,4                       ;skip shape offset

                mov esi,[esi]                   ;get palette offset ptr
                cmp esi,0
                jz __return                     ;no palette for shape

                add esi,[SHP_buffer]            ;add base address
                lodsd
                mov ecx,eax                     ;ecx = color_count

                mov edi,[Palette]

__read_color:
                lodsb                           ;get color#

                and eax,0ffh
                mov ebx,eax
                shl ebx,1                       ;mul color# by 3
                add ebx,eax

                lodsb
                shl al,2                        ;shift from VGA to normalized
                mov BYTE PTR [edi][ebx],al      ;8-8-8 format
                lodsb
                shl al,2
                mov BYTE PTR [edi][ebx+1],al
                lodsb
                shl al,2
                mov BYTE PTR [edi][ebx+2],al

                dec ecx
                jnz __read_color

__return:
                ret

VFX_shape_palette ENDP

                ENDIF

;----------------------------------------------------------------------------
;
; long VFX_shape_colors(void *shape_table, LONG shape_number, ULONG *colors);
;
; Returns number of colors used in the specified shape.
;
; If *colors is a valid ptr (!NULL) the palette information will
; be stored there.
;
;----------------------------------------------------------------------------

                IF do_VFX_shape_colors

VFX_shape_colors PROC STDCALL USES ebx esi edi es, \
                SHP_buffer:PTABLE, Shape_number:S32, Colors:PTR VFX_CRGB

                ASSUME esi:NOTHING

                cld
                push ds
                pop es

                mov esi,[SHP_buffer]
                add esi,8                       ;skip to offsets
                
                mov eax,Shape_number            ;point to shape offset ptr 
                shl eax,3                       ;mul eax by sizeof 2 longs
                add esi,eax                     
                add esi,4                       ;skip shape offset

                mov esi,[esi]                   ;get colors offset ptr
                cmp esi,0
                jnz __colors_exist

                mov eax,0                       ;return 0 colors
                jmp __return

__colors_exist:
                add esi,[SHP_buffer]            ;add base address
                lodsd                           ;eax = color_count
                mov ebx,eax

                mov edi,[Colors]
                or edi,edi              
                jz __return                     ;skip copy if NULL ptr

                mov ecx,ebx                     ;ecx = color_count
                mov eax,0
__get_color:
                movsd
                loop __get_color

                mov eax,ebx                     ;return color_count
__return:
                ret

VFX_shape_colors ENDP

                ENDIF


;----------------------------------------------------------------------------
;
; long VFX_shape_set_colors(void *shape_table, LONG shape_number,
;                           VFX_CRGB *colors);
;
; Returns number of colors used in the specified shape.
;
; If *colors is a valid ptr (!NULL) the palette information stored there will
; be used to replace the colors for the shape.
;
;----------------------------------------------------------------------------

                IF do_VFX_shape_set_colors

VFX_shape_set_colors PROC STDCALL USES ebx esi edi es, \
                SHP_buffer:PTABLE, Shape_number:S32, Colors:PTR VFX_CRGB

                ASSUME esi:NOTHING
                ASSUME edi:NOTHING

                cld
                push ds
                pop es

                mov esi,[SHP_buffer]
                add esi,8                       ;skip to offsets
                
                mov eax,Shape_number            ;point to shape offset ptr 
                shl eax,3                       ;mul eax by sizeof 2 longs
                add esi,eax                     
                add esi,4                       ;skip shape offset

                mov esi,[esi]                   ;get colors offset ptr
                cmp esi,0
                jnz __colors_exist

                mov eax,0                       ;return 0 colors
                jmp __return

__colors_exist:
                add esi,[SHP_buffer]            ;add base address
                lodsd                           ;eax = color_count
                mov ebx,eax

                mov edi,esi
                mov esi,[Colors]
                or esi,esi              
                jz __return                     ;skip copy if NULL ptr

                mov ecx,ebx                     ;ecx = color_count
                mov eax,0
__get_color:
                movsd
                loop __get_color

                mov eax,ebx                     ;return color_count
__return:
                ret

VFX_shape_set_colors ENDP

                ENDIF


;----------------------------------------------------------------------------
;
; long VFX_shape_count(void *shape_table);
;
; Returns number of shape references in the specified shape table. Each
; shape may have one or more references.
;
;----------------------------------------------------------------------------

                IF do_VFX_shape_count

VFX_shape_count PROC STDCALL USES ebx esi edi es,\
                SHP_buffer:PTABLE

                ASSUME esi:NOTHING

                mov esi,[SHP_buffer]
                mov eax,[esi+4]

                ret

VFX_shape_count ENDP

                ENDIF


;----------------------------------------------------------------------------
;
; long VFX_shape_list(void *shape_table, ULONG *index_list);
;
; Returns number of unique shapes present in the specified shape table.
;
; Places the index number of each unique shape in *index_list.
;
;----------------------------------------------------------------------------

                IF do_VFX_shape_list

VFX_shape_list PROC STDCALL USES ebx esi edi es,\
                SHP_buffer:PTABLE, Index_list:PTR U32

                LOCAL   table_base

                ASSUME esi:NOTHING

                mov esi,[SHP_buffer]            ;esi -> shape file
                mov ecx,[esi+4]                 ;ecx = # shape entries
                dec ecx

                add esi,8                       ;esi -> shape offsets table
                mov table_base,esi

                mov ebx,1                       ;ebx = unique shape count        

                mov edx,[Index_list]            ;setup output list
                cmp edx,0                       ;if needed
                je __check_more_than_one

                mov DWORD PTR [edx],0           ;store first entry in list
                add edx,4

__check_more_than_one:

                cmp ecx,0
                je __exit

__outer_loop:
                add esi,8                       ;point to next entry
                mov eax,[esi]                   ;eax = shape offset

                mov edi,table_base              ;edi -> shape offsets table

__inner_loop:
                cmp eax,[edi]                   ;compare shape offsets        
                je __break_inner                

__not_same:     
                add edi,8                       ;edi -> next shape offset
                cmp edi,esi                     
                jl __inner_loop                 ;loop until edi = esi

                cmp edx,0
                je __just_count

                mov eax,esi
                sub eax,table_base              ;eax = byte offset into table
                shr eax,3                       ;eax = index
                mov [edx],eax                   ;store index in list
                add edx,4

__just_count:
                inc ebx                         ;increment unique shape count        

__break_inner:
                loop __outer_loop

__exit:
                mov eax,ebx                     ;return unique shape count

                ret

VFX_shape_list ENDP

                ENDIF


;----------------------------------------------------------------------------
;
; long VFX_shape_palette_list(void *shape_table, ULONG *index_list);
;
; Returns number of unique palettes present in the specified shape table.
;
; Places the index number of a shape with each unique palette in *index_list.
;
;----------------------------------------------------------------------------

                IF do_VFX_shape_palette_list

VFX_shape_palette_list PROC STDCALL USES ebx esi edi es,\
                SHP_buffer:PTABLE, Index_list:PTR U32

                LOCAL   table_base

                ASSUME esi:NOTHING

                mov esi,[SHP_buffer]            ;esi -> shape file
                mov ecx,[esi+4]                 ;ecs = # shape entries
                dec ecx

                add esi,12                      ;esi -> shape offsets table
                mov table_base,esi

                mov ebx,1                       ;ebx = unique shape count        

                mov edx,[Index_list]            ;setup output list
                cmp edx,0                       ;if needed
                je __check_more_than_one

                mov DWORD PTR [edx],0           ;store first entry in list
                add edx,4

__check_more_than_one:

                cmp ecx,0
                je __exit

__outer_loop:
                add esi,8                       ;start with 2nd table entry
                mov eax,[esi]                   ;eax = shape offset

                mov edi,table_base              ;edi -> shape offsets table

__inner_loop:
                cmp eax,[edi]                   ;compare shape offsets        
                je __break_inner                

__not_same:     
                add edi,8                       ;edi -> next shape offset
                cmp edi,esi                     
                jl __inner_loop                 ;loop until edi = esi

                cmp edx,0
                je __just_count

                mov eax,esi
                sub eax,table_base              ;eax = byte offset into table
                shr eax,3                       ;eax = index
                mov [edx],eax                   ;store index in list
                add edx,4

__just_count:
                inc ebx                         ;increment unique shape count        

__break_inner:
                loop __outer_loop

__exit:
                mov eax,ebx                     ;return unique shape count

                ret

VFX_shape_palette_list ENDP

                ENDIF

;----------------------------------------------------------------------------
;
; long VFX_color_scan(PANE *pane, ULONG *colors);
;
; Returns number of colors used in the specified window.
;
; If *colors is a valid ptr (!NULL) the color information will
; be stored there.
;
;----------------------------------------------------------------------------

                IF do_VFX_color_scan

VFX_color_scan  PROC STDCALL USES ebx esi edi es, \
                Panep:PPANE,Colors:PTR U32
                LOCAL color_count
                LOCAL pane_width, window_width

                ASSUME esi:NOTHING

                cld
                push ds
                pop es

                mov edi,OFFSET color_sb                ;clear color score board
                mov eax,0
                mov ecx,64 
                rep stosd

                mov esi,[Panep]
                mov ecx,[esi].PANE.x1
                sub ecx,[esi].PANE.x0           ;ecx = pane width
                mov pane_width,ecx

                mov ebx,[esi].PANE.y1
                sub ebx,[esi].PANE.y0           ;ebx = pane depth

                mov esi,[esi].PANE.window
                mov eax,[esi].VFX_WINDOW.x_max
                inc eax
                mov window_width,eax

                mov esi,[Panep]
                mov eax,[esi].PANE.y0
                imul window_width
                add eax,[esi].PANE.x0
                mov esi,[esi].PANE.window
                mov esi,[esi].VFX_WINDOW.buffer
                add esi,eax

                mov edi,[Colors]
                mov color_count,-1

__score_colors:
                mov eax,0                       ;al = color value
                movzx eax,BYTE PTR [esi][ecx]   ;get color number
                cmp color_sb[eax],0              
                jnz __already_scored            ;if color not scored

                or color_sb[eax],1              ;  score color
                inc color_count

                cmp edi,0                       ;  skip store if NULL ptr
                jz __already_scored

                stosd                           ;  store color number

__already_scored:
                dec ecx
                jns __score_colors              ;next

                mov ecx,pane_width
                add esi,window_width

                dec ebx
                jns __score_colors

                mov eax,color_count             ;return # of colors used
                inc eax                         ;convert max to count
                ret

VFX_color_scan  ENDP

                ENDIF

;----------------------------------------------------------------------------
;
;Fixed-point polygon primitives from VFX3D.ASM (affine/flat/Gouraud only)
;
;----------------------------------------------------------------------------

;*****************************************************************************
VFX_flat_polygon PROC USES ebx esi edi es,\
                DestPane:PTR PANE, VCnt:S32, VList:PSCRNVERTEX

                LOCAL VP_R            
                LOCAL VP_B            
                LOCAL buff_addr       
                LOCAL line_size       
                LOCAL txt_width       
                LOCAL txt_bitmap      
                LOCAL line_base       
                LOCAL x_clipped       
                LOCAL vlist_beg       
                LOCAL vlist_end       
                LOCAL v_top           
                LOCAL lcur            
                LOCAL rcur            
                LOCAL lnxt            
                LOCAL rnxt            
                LOCAL lcnt            
                LOCAL rcnt            
                LOCAL line_cnt        
                LOCAL y               
                LOCAL lx              
                LOCAL rx              
                LOCAL lc              
                LOCAL rc              
                LOCAL lu              
                LOCAL ru              
                LOCAL lv              
                LOCAL rv              
                LOCAL ldx             
                LOCAL rdx             
                LOCAL ldc             
                LOCAL rdc             
                LOCAL ldu             
                LOCAL rdu             
                LOCAL ldv             
                LOCAL rdv             
                LOCAL plx             
                LOCAL prx             
                LOCAL dc              
                LOCAL du              
                LOCAL dv              
                LOCAL flu             
                LOCAL color           

                IF F_POLY

                SET_DEST_PANE

                ASSUME ebx:PSCRNVERTEX
                ASSUME esi:PSCRNVERTEX

                push ds
                pop es

                mov ebx,[VList]         ;EBX -> list of VERTEX strcts

                mov eax,[VCnt]
                shl eax,3
                mov edx,eax
                shl eax,1               ;* SIZE VERTEX (8n+16n=24n)
                add eax,edx             

                add eax,ebx

                mov vlist_beg,ebx      
                mov vlist_end,eax       ;BX + VCnt*SIZE VERTEX -> end of list


                mov eax,[ebx].color     ;read polygon color from 1st vertex
                mov color,eax

                GET_COLOR color

                mov eax,color    
                shl eax,16              ;convert to fixed point

                add eax,8000h           ;rest of code compatible with DOS version...
                shr eax,16
                mov ah,al
                mov edx,eax
                shl eax,16
                or eax,edx
                mov color,eax

                ;
                ;Find top and bottom vertices; perform Sutherland-Cohen
                ;clipping on polygon
                ;

                mov x_clipped,0         ;nonzero if any scanlines clipped in X

                mov esi,32767           ;ESI = top vertex Y
                mov edi,-32768          ;EDI = bottom vertex Y

                mov ecx,1111b           ;ECX = S-C "and" result for polygon

__vertex_sort:  mov edx,0               ;EDX = S-C flags for this vertex

                mov eax,[ebx].x
                shld edx,eax,1

                mov eax,VP_R
                sub eax,[ebx].x
                shld edx,eax,1

                or x_clipped,edx

                mov eax,[ebx].y
                shld edx,eax,1

                mov eax,VP_B
                sub eax,[ebx].y
                shld edx,eax,1

                mov eax,[ebx].y

                cmp eax,esi             ;keep track of top and bottom vertices
                jg __not_top
                mov esi,eax
                mov v_top,ebx

__not_top:      cmp eax,edi
                jl __not_btm
                mov edi,eax

__not_btm:      and ecx,edx
                
                add ebx,SIZE SCRNVERTEX
                cmp ebx,vlist_end
                jne __vertex_sort

                or ecx,ecx              ;all vertices to one side of window?
                jnz __exit              ;yes, polygon fully clipped

                mov eax,v_top           ;else init right, left vertices = top
                mov lnxt,eax
                mov rnxt,eax

                mov y,esi               ;init scanline Y = top vertex Y

                cmp edi,esi             ;is polygon flat?
                je __exit               ;yes, don't draw it

                ;
                ;Calculate initial edge positions & stepping vals for
                ;left and right edges
                ;

__init_left:    mov ebx,lnxt
                mov lcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                sub esi,SIZE SCRNVERTEX
                cmp esi,vlist_beg
                jge __init_lnxt
                mov esi,vlist_end
                sub esi,SIZE SCRNVERTEX
__init_lnxt:    mov lnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].y        ;ECX = edge bottom Y
                mov edx,[ebx].y        ;EDX = edge top Y

                cmp edx,0               ;skip edge if above viewport
                jge __set_l_pcnt
                cmp ecx,0
                jle __init_left         ;(bottom vertex shared w/next edge)

__set_l_pcnt:   sub ecx,edx             ;is edge flat?
                jz __init_left          ;yes, advance one edge left
	;(pci)
	js __exit

                mov lcnt,ecx            ;set left edge pixel count

                mov edx,[esi].x        ;get size of edge in X
                sub edx,[ebx].x
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldx,eax             ;set left DX
                
                mov edx,[ebx].x        ;convert X to fixed-point val
                shl edx,16
                add edx,8000h           ;pre-round by adding +0.5
                mov lx,edx

__init_right:   mov ebx,rnxt
                mov rcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                add esi,SIZE SCRNVERTEX
                cmp esi,vlist_end
                jl __init_rnxt
                mov esi,vlist_beg
__init_rnxt:    mov rnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].y        ;ECX = edge bottom Y
                mov edx,[ebx].y        ;EDX = edge top Y

                cmp edx,0               ;skip edge if above viewport
                jge __set_r_pcnt
                cmp ecx,0
                jle __init_right        ;(bottom vertex shared w/next edge)

__set_r_pcnt:   sub ecx,edx             ;is edge flat?
                jz __init_right         ;yes, advance one edge right
	;(pci)
	js __exit

                mov rcnt,ecx            ;set right edge pixel count

                mov edx,[esi].x        ;get size of edge in X
                sub edx,[ebx].x
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdx,eax             ;set right DX
                
                mov edx,[ebx].x        ;convert X to fixed-point val
                shl edx,16
                add edx,8000h
                mov rx,edx              ;pre-round by adding +0.5

                ;
                ;Set scanline count; clip against bottom of window
                ;

                mov eax,VP_B
                sub eax,y

                sub edi,VP_B
                jg __clip_bottom

                add eax,edi
__clip_bottom:  mov line_cnt,eax

                ;
                ;Clip against top of window
                ;

                mov eax,0
                sub eax,y
                jle __set_Y_base

                sub line_cnt,eax

                mov ecx,0
                mov y,ecx
                mov ebx,lcur
                sub ecx,[ebx].y
                sub lcnt,ecx

                shl ecx,16              ;ECX = # of pixels to clip from left

                mov eax,ldx             ;lx = lx + ECX * ldx
                FPMUL ecx
                add lx,eax

                mov ecx,0
                mov ebx,rcur
                sub ecx,[ebx].y
                sub rcnt,ecx

                shl ecx,16              ;ECX = # of pixels to clip from right

                mov eax,rdx             ;rx = rx + ECX * rdx
                FPMUL ecx
                add rx,eax

                ;
                ;Set window base address and loop variables
                ;

__set_Y_base:   mov eax,y
                mul line_size
                mov edi,buff_addr
                add edi,eax             ;EDI = line_base

                mov eax,lx
                mov ebx,rx

                ;
                ;Use faster loop if unclipped
                ;

                cmp x_clipped,0
                jne __clip_line

                ;
                ;Trace edges & plot unclipped scanlines ...
                ;
                
                ALIGN 4

__unclip_line:  push eax                ;save LX
                push edi                ;save line_base

                mov edx,ebx
                cmp edx,eax
                jg __unclip_X

                xchg eax,edx

__unclip_X:     sar eax,16              ;EAX = left endpoint (preserve sign)
                sar edx,16              ;EDX = right endpoint (preserve sign)

                mov ecx,edx
                sub ecx,eax
                inc ecx                 ;ECX = # of pixels in line

                add edi,eax             ;EDI -> start of line

                mov eax,color

                mov edx,ecx
                and ecx,3
                rep stosb
                mov ecx,edx
                shr ecx,2
                rep stosd

                pop edi                 ;recover loop vars
                pop eax

                ;
                ;Step one line down in Y; exit if no more scanlines
                ;

                add edi,line_size

                dec line_cnt
                js __exit
                jz __unclip_last

                ;
                ;Calculate new X vals for both edges, stepping across
                ;vertices when necessary to find next scanline
                ;

                dec lcnt
                jz __step_left

                add eax,ldx

__unclip_r:     dec rcnt
                jz __step_right

                add ebx,rdx

                jmp __unclip_line

__exit:         ret

                ;
                ;Do last line without switching edges
                ;

__unclip_last:  add eax,ldx
                add ebx,rdx
                jmp __unclip_line

                ;
                ;Trace edges & plot clipped scanlines ...
                ;
                
                ALIGN 4

__clip_line:    push eax                ;save LX
                push edi                ;save line_base

                mov edx,ebx
                cmp edx,eax
                jg __clip_X

                xchg eax,edx

__clip_X:       sar eax,16              ;EAX = left endpoint (preserve sign)
                sar edx,16              ;EDX = right endpoint (preserve sign)

                cmp eax,VP_R
                jg __clip_next

                cmp edx,0
                jl __clip_next

                mov ecx,edx
                sub ecx,eax
                inc ecx                 ;CX = # of pixels in line

                add edi,eax             ;EDI -> start of line

                sub eax,0               ;AX = 0 - # of left-clipped pixels
                jl __clip_left

__left_clipped: sub edx,VP_R            ;DX = # of right-clipped pixels
                jg __clip_right

__clip_loop:    mov eax,color

                mov edx,ecx
                and ecx,3
                rep stosb
                mov ecx,edx
                shr ecx,2
                rep stosd

__clip_next:    pop edi                 ;recover loop vars
                pop eax

                ;
                ;Step one line down in Y; exit if no more scanlines
                ;

                add edi,line_size

                dec line_cnt
                js __exit
                jz __clip_last

                ;
                ;Calculate new X vals for both edges, stepping across
                ;vertices when necessary to find next scanline
                ;

                dec lcnt
                jz __step_left

                add eax,ldx

__clip_r:       dec rcnt
                jz __step_right

                add ebx,rdx

                jmp __clip_line

                ;
                ;Do last line without switching edges
                ;

__clip_last:    add eax,ldx
                add ebx,rdx
                jmp __clip_line

                ;
                ;Clip 0 - AX pixels from left edge of scanline
                ;

__clip_left:    sub edi,eax             ;add -EAX to left endpoint X...
                add ecx,eax             ;and subtract -EAX from line width
                jmp __left_clipped

                ;
                ;Clip DX pixels from right edge of scanline
                ;

__clip_right:   sub ecx,edx             ;subtract EDX from line width
                jmp __clip_loop

                ;
                ;Step across left edge vertex
                ;

__step_left:    push ebx

                mov ebx,lnxt
                mov lcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                sub esi,SIZE SCRNVERTEX
                cmp esi,vlist_beg
                jge __step_lnxt
                mov esi,vlist_end
                sub esi,SIZE SCRNVERTEX
__step_lnxt:    mov lnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].y        ;ECX = edge bottom Y
                mov edx,[ebx].y        ;EDX = edge top Y

                sub ecx,edx             ;if edge flat, force delta=1
	;(pci)
	js __abort
                cmp ecx,1               ;(possible only at bottom scan line)
                adc ecx,0

                mov lcnt,ecx            ;set left edge pixel count

                mov edx,[esi].x        ;get size of edge in X
                sub edx,[ebx].x
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldx,eax             ;set left DX
                
                mov eax,[ebx].x        
                shl eax,16              ;convert X to fixed-point val
                add eax,8000h           ;pre-round by adding +0.5

                pop ebx
                cmp x_clipped,0
                je __unclip_r
                jmp __clip_r

                ;
                ;Step across right edge vertex
                ;

__step_right:   push eax
                
                mov ebx,rnxt
                mov rcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                add esi,SIZE SCRNVERTEX
                cmp esi,vlist_end
                jl __step_rnxt
                mov esi,vlist_beg
__step_rnxt:    mov rnxt,esi            ;SI -> vertex at bottom (end) of edge

                mov ecx,[esi].y        ;CX = edge bottom Y
                mov edx,[ebx].y        ;DX = edge top Y

                sub ecx,edx             ;if edge flat, force delta=1
	;(pci)
	js __abort
                cmp ecx,1               ;(possible only at bottom scan line)
                adc ecx,0

                mov rcnt,ecx            ;set right edge pixel count

                mov edx,[esi].x        ;get size of edge in X
                sub edx,[ebx].x
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdx,eax             ;set right DX

                mov ebx,[ebx].x        
                shl ebx,16              ;convert X to fixed-point val
                add ebx,8000h           ;pre-round by adding +0.5

                pop eax
                cmp x_clipped,0
                je __unclip_line
                jmp __clip_line

__abort:
                pop ebx
	jmp __exit

                ELSE
                ret
                ENDIF

VFX_flat_polygon ENDP

;*****************************************************************************
VFX_Gouraud_polygon PROC USES ebx esi edi es,\
                DestPane:PTR PANE, VCnt:S32, VList:PSCRNVERTEX

                LOCAL VP_R            
                LOCAL VP_B            
                LOCAL buff_addr       
                LOCAL line_size       
                LOCAL txt_width       
                LOCAL txt_bitmap      
                LOCAL line_base       
                LOCAL x_clipped       
                LOCAL vlist_beg       
                LOCAL vlist_end       
                LOCAL v_top           
                LOCAL lcur            
                LOCAL rcur            
                LOCAL lnxt            
                LOCAL rnxt            
                LOCAL lcnt            
                LOCAL rcnt            
                LOCAL line_cnt        
                LOCAL y               
                LOCAL lx              
                LOCAL rx              
                LOCAL lc              
                LOCAL rc              
                LOCAL lu              
                LOCAL ru              
                LOCAL lv              
                LOCAL rv              
                LOCAL ldx             
                LOCAL rdx             
                LOCAL ldc             
                LOCAL rdc             
                LOCAL ldu             
                LOCAL rdu             
                LOCAL ldv             
                LOCAL rdv             
                LOCAL plx             
                LOCAL prx             
                LOCAL dc              
                LOCAL du              
                LOCAL dv              
                LOCAL flu             
                LOCAL color           

                IF G_POLY

                SET_DEST_PANE

                ASSUME ebx:PSCRNVERTEX
                ASSUME esi:PSCRNVERTEX

                push ds
                pop es

                mov ebx,[VList]         ;EBX -> list of VERTEX strcts

                mov eax,[VCnt]
                shl eax,3
                mov edx,eax
                shl eax,1               ;* SIZE VERTEX (8n+16n=24n)
                add eax,edx             

                add eax,ebx

                mov vlist_beg,ebx      
                mov vlist_end,eax       ;BX + VCnt*SIZE VERTEX -> end of list

                ;
                ;Find top and bottom vertices; perform Sutherland-Cohen
                ;clipping on polygon
                ;

                mov x_clipped,0         ;nonzero if any scanlines clipped in X

                mov esi,32767           ;ESI = top vertex Y
                mov edi,-32768          ;EDI = bottom vertex Y

                mov ecx,1111b           ;ECX = S-C "and" result for polygon

__vertex_sort:  mov edx,0               ;EDX = S-C flags for this vertex

                mov eax,[ebx].x
                shld edx,eax,1

                mov eax,VP_R
                sub eax,[ebx].x
                shld edx,eax,1

                or x_clipped,edx

                mov eax,[ebx].y
                shld edx,eax,1

                mov eax,VP_B
                sub eax,[ebx].y
                shld edx,eax,1

                mov eax,[ebx].y

                cmp eax,esi             ;keep track of top and bottom vertices
                jg __not_top
                mov esi,eax
                mov v_top,ebx

__not_top:      cmp eax,edi
                jl __not_btm
                mov edi,eax

__not_btm:      and ecx,edx
                
                add ebx,SIZE SCRNVERTEX
                cmp ebx,vlist_end
                jne __vertex_sort

                or ecx,ecx              ;all vertices to one side of window?
                jnz __exit              ;yes, polygon fully clipped

                mov eax,v_top           ;else init right, left vertices = top
                mov lnxt,eax
                mov rnxt,eax

                mov y,esi               ;init scanline Y = top vertex Y

                cmp edi,esi             ;is polygon flat?
                je __exit               ;yes, don't draw it

                ;
                ;Calculate initial edge positions & stepping vals for
                ;left and right edges
                ;

__init_left:    mov ebx,lnxt
                mov lcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                sub esi,SIZE SCRNVERTEX
                cmp esi,vlist_beg
                jge __init_lnxt
                mov esi,vlist_end
                sub esi,SIZE SCRNVERTEX
__init_lnxt:    mov lnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].y        ;ECX = edge bottom Y
                mov edx,[ebx].y        ;EDX = edge top Y

                cmp edx,0               ;skip edge if above viewport
                jge __set_l_pcnt
                cmp ecx,0
                jle __init_left         ;(bottom vertex shared w/next edge)

__set_l_pcnt:   sub ecx,edx             ;is edge flat?
                jz __init_left          ;yes, advance one edge left
	;(pci)
	js __exit
                mov lcnt,ecx            ;set left edge pixel count

                mov edx,[esi].x        ;get size of edge in X
                sub edx,[ebx].x
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldx,eax             ;set left DX
                
                mov ecx,lcnt

                mov edx,[esi].color        ;get size of edge in C
                sub edx,[ebx].color
                FPDIV ecx               ;divide by pixel count
                mov ldc,eax             ;set left DC

                mov edx,[ebx].x        ;convert X and C to fixed-point vals
                shl edx,16              ;pre-round by adding +0.5 to both
                add edx,8000h           
                mov lx,edx

                mov edx,[ebx].color
                add edx,8000h
                mov lc,edx

__init_right:   mov ebx,rnxt
                mov rcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                add esi,SIZE SCRNVERTEX
                cmp esi,vlist_end
                jl __init_rnxt
                mov esi,vlist_beg
__init_rnxt:    mov rnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].y        ;ECX = edge bottom Y
                mov edx,[ebx].y        ;EDX = edge top Y

                cmp edx,0               ;skip edge if above viewport
                jge __set_r_pcnt
                cmp ecx,0
                jle __init_right        ;(bottom vertex shared w/next edge)

__set_r_pcnt:   sub ecx,edx             ;is edge flat?
                jz __init_right         ;yes, advance one edge right
	;(pci)
	js __exit

                mov rcnt,ecx            ;set right edge pixel count

                mov edx,[esi].x        ;get size of edge in X
                sub edx,[ebx].x
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdx,eax             ;set right DX
                
                mov ecx,rcnt

                mov edx,[esi].color        ;get size of edge in C
                sub edx,[ebx].color
                FPDIV ecx               ;divide by pixel count
                mov rdc,eax             ;set right DC

                mov edx,[ebx].x        ;convert X and C to fixed-point vals
                shl edx,16              ;pre-round by adding +0.5 to both
                add edx,8000h
                mov rx,edx

                mov edx,[ebx].color
                add edx,8000h
                mov rc,edx

                ;
                ;Set scanline count; clip against bottom of window
                ;

                mov eax,VP_B
                sub eax,y

                sub edi,VP_B
                jg __clip_bottom

                add eax,edi
__clip_bottom:  mov line_cnt,eax

                ;
                ;Clip against top of window
                ;

                mov eax,0
                sub eax,y
                jle __set_Y_base

                sub line_cnt,eax

                mov ecx,0
                mov y,ecx
                mov ebx,lcur
                sub ecx,[ebx].y
                sub lcnt,ecx

                shl ecx,16              ;ECX = # of pixels to clip from left

                mov eax,ldx             ;lx = lx + ECX * ldx
                FPMUL ecx
                add lx,eax

                mov eax,ldc             ;lc = lc + ECX * ldc
                FPMUL ecx
                add lc,eax

                mov ecx,0
                mov ebx,rcur
                sub ecx,[ebx].y
                sub rcnt,ecx

                shl ecx,16              ;ECX = # of pixels to clip from right

                mov eax,rdx             ;rx = rx + ECX * rdx
                FPMUL ecx
                add rx,eax

                mov eax,rdc             ;rc = rc + ECX * rdc
                FPMUL ecx
                add rc,eax

                ;
                ;Set window base address and loop variables
                ;

__set_Y_base:   mov eax,y
                mul line_size
                mov edi,buff_addr
                add edi,eax             ;EDI = line_base

                mov eax,lx
                mov ebx,rx
                mov ecx,lc
                mov edx,rc

                ;
                ;Use faster loop if unclipped
                ;

                cmp x_clipped,0
                jne __clip_line

                ;
                ;Trace edges & plot unclipped scanlines ...
                ;
                
                ALIGN 4

__unclip_line:  push eax                ;save LX
                push ebx                ;save RX
                push ecx                ;save LC
                push edx                ;save RC
                push edi                ;save line_base

                cmp ebx,eax
                jg __unclip_XC

                xchg eax,ebx
                xchg ecx,edx

__unclip_XC:    sar eax,16              ;convert to int, preserving sign
                sar ebx,16

                add edi,eax             ;EDI -> start of line

                sub ebx,eax               
                mov esi,ebx             ;SI = # of pixels in line
                jz __unclip_loop        ;(single-pixel line)

                sub edx,ecx             ;EDX = frc-flc

                FPDIV ebx               
                shld edx,eax,16         ;DX:AX = color / x (signed) [!]

                mov ebx,esi

__unclip_loop:  add ebx,edi
                mov line_end,ebx        ;EBX -> end of line

                inc esi

                mov ebx,ecx             ;set ECX:EBX = fixed-point color
                shr ecx,16              ;(unsigned)

                shl ebx,16              ;x64K so 32-bit adds will roll over
                shl eax,16

                mov ch,cl               ;initialize first color pair
                add ebx,eax
                adc ch,dl

                test edi,1              ;pixel destination address even?
                jz __unclip_pairs       ;yes, write word-aligned dot pairs

                mov [edi],cl            ;else write odd pixel first

                dec esi                 ;decrement pixel count
                jz __unclip_next        ;exit if no more pixels

                inc edi                 ;advance output pointer

                mov cl,ch               ;advance color pair vals
                add ebx,eax
                adc ch,dl

__unclip_pairs: cmp esi,1
                je __unclip_end         ;if only one pixel left, go draw it

                push esi
                shr esi,1               ;get # of pairs to draw
                dec esi

GOURAUD         MACRO
                mov WORD PTR [edi+INDEX],cx
                mov cl,ch
                add ebx,eax
                adc cl,dl
                mov ch,cl  
                add ebx,eax
                adc ch,dl  
                ENDM

                PARTIAL_UNROLL G_unclip_write,GOURAUD,6,2,esi

                pop esi
                test esi,1
                jz __unclip_next

__unclip_end:   mov edi,line_end        ;write single pixel at end of line
                mov [edi],cl

__unclip_next:  pop edi                 ;recover loop vars
                pop edx
                pop ecx
                pop ebx
                pop eax

                ;
                ;Step one line down in Y; exit if no more scanlines
                ;

                add edi,line_size

                dec line_cnt
                js __exit
                jz __unclip_last

                ;
                ;Calculate new X and C vals for both edges, stepping across
                ;vertices when necessary to find next scanline
                ;

                dec lcnt
                jz __step_left

                add eax,ldx
                add ecx,ldc

__unclip_r:     dec rcnt
                jz __step_right

                add ebx,rdx
                add edx,rdc

                jmp __unclip_line

__exit:         ret

                ;
                ;Do last line without switching edges
                ;

__unclip_last:  add eax,ldx
                add ecx,ldc

                add ebx,rdx
                add edx,rdc

                jmp __unclip_line

                ;
                ;Trace edges & plot clipped scanlines ...
                ;

                ALIGN 4

__clip_line:    push eax                ;save LX
                push ebx                ;save RX
                push ecx                ;save LC
                push edx                ;save RC
                push edi                ;save line_base

                cmp ebx,eax
                jg __clip_XC

                xchg eax,ebx
                xchg ecx,edx

__clip_XC:      sar eax,16              ;(preserve sign)
                cmp eax,VP_R
                jg __clip_next

                sar ebx,16              ;(preserve sign)
                cmp ebx,0
                jl __clip_next

                mov plx,eax
                mov prx,ebx

                add edi,eax             ;EDI -> start of line

                sub ebx,eax               
                mov esi,ebx               
                inc esi                 ;ESI = # of pixels in line

                cmp esi,1
                jz __set_color          ;(single-pixel line)

                sub edx,ecx             ;EDX = frc-flc

                FPDIV ebx 
                mov dc,eax              ;dc = EAX = color / x (signed)

__set_color:    mov eax,0           
                sub eax,plx             ;EAX = # of left-clipped pixels
                jg __clip_left

__left_clipped: mov eax,prx
                sub eax,VP_R            ;EAX = # of right-clipped pixels
                jg __clip_right

__clip_loop:    mov ebx,ecx             ;set ECX:EBX = fixed-point color
                shr ecx,16              ;(unsigned)
                
                mov eax,edi
                add eax,esi
                dec eax                 ;EAX -> end of line
                mov line_end,eax        

                mov eax,dc              ;EAX = color change/pixel
                shld edx,eax,16         ;EDX:EAX = color / x

                shl ebx,16              ;x64K so 32-bit adds will roll over
                shl eax,16

                mov ch,cl               ;initialize first color pair
                add ebx,eax
                adc ch,dl

                test edi,1              ;pixel destination address even?
                jz __clip_pairs         ;yes, write word-aligned dot pairs

                mov [edi],cl            ;else write odd pixel first

                dec esi                 ;decrement pixel count
                jz __clip_next          ;exit if no more pixels

                inc edi                 ;advance output pointer

                mov cl,ch               ;advance color pair vals
                add ebx,eax
                adc ch,dl

__clip_pairs:   cmp esi,1                                              
                jz __clip_end           ;if only one pixel left, go draw it

                push esi
                shr esi,1               ;get # of pairs to draw
                dec esi

                PARTIAL_UNROLL G_clip_write,GOURAUD,6,2,esi

                pop esi
                test esi,1
                jz __clip_next

__clip_end:     mov edi,line_end        ;write single pixel at end of line
                mov [edi],cl

__clip_next:    pop edi                 ;recover loop vars
                pop edx
                pop ecx
                pop ebx
                pop eax

                ;
                ;Step one line down in Y; exit if no more scanlines
                ;

                add edi,line_size

                dec line_cnt
                js __exit
                jz __clip_last

                ;
                ;Calculate new X and C vals for both edges, stepping across
                ;vertices when necessary to find next scanline
                ;

                dec lcnt
                jz __step_left

                add eax,ldx
                add ecx,ldc

__clip_r:       dec rcnt
                jz __step_right

                add ebx,rdx
                add edx,rdc

                jmp __clip_line

                ;
                ;Do last line without switching edges
                ;

__clip_last:    add eax,ldx
                add ecx,ldc

                add ebx,rdx
                add edx,rdc

                jmp __clip_line

                ;
                ;Clip AX pixels from left edge of scanline
                ;

__clip_left:    add edi,eax             ;add AX to left endpoint X...
                sub esi,eax             ;and subtract AX from line width

                shl eax,16              ;convert to FP
                FPMUL dc                ;adjust color variable
                add ecx,eax
                jmp __left_clipped

                ;
                ;Clip AX pixels from right edge of scanline
                ;

__clip_right:   sub esi,eax             ;subtract AX from line width
                jmp __clip_loop

                ;
                ;Step across left edge vertex
                ;

__step_left:    push ebx
                push edx

                mov ebx,lnxt
                mov lcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                sub esi,SIZE SCRNVERTEX
                cmp esi,vlist_beg
                jge __step_lnxt
                mov esi,vlist_end
                sub esi,SIZE SCRNVERTEX
__step_lnxt:    mov lnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].y        ;ECX = edge bottom Y
                mov edx,[ebx].y        ;EDX = edge top Y

                sub ecx,edx             ;if edge flat, force delta=1
	;(pci)
	js __abort
                cmp ecx,1               ;(possible only at bottom scan line)
                adc ecx,0

                mov lcnt,ecx            ;set left edge pixel count

                mov edx,[esi].color        ;get size of edge in C
                sub edx,[ebx].color
                FPDIV ecx               ;divide by pixel count
                mov ldc,eax             ;set left DC

                mov ecx,lcnt

                mov edx,[esi].x        ;get size of edge in X
                sub edx,[ebx].x
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldx,eax             ;set left DX
                
                mov ecx,[ebx].color
                add ecx,8000h           ;pre-round by adding +0.5

                mov eax,[ebx].x        
                shl eax,16              ;convert X to fixed-point val
                add eax,8000h           ;pre-round by adding +0.5

                pop edx
                pop ebx

                cmp x_clipped,0
                je __unclip_r
                jmp __clip_r


                ;
                ;Step across right edge vertex
                ;

__step_right:   push eax
                push ecx
                
                mov ebx,rnxt
                mov rcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                add esi,SIZE SCRNVERTEX
                cmp esi,vlist_end
                jl __step_rnxt
                mov esi,vlist_beg
__step_rnxt:    mov rnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].y        ;ECX = edge bottom Y
                mov edx,[ebx].y        ;EDX = edge top Y

                sub ecx,edx             ;if edge flat, force delta=1
	;(pci)
	js __abort
                cmp ecx,1               ;(possible only at bottom scan line)
                adc ecx,0

                mov rcnt,ecx            ;set right edge pixel count

                mov edx,[esi].color        ;get size of edge in C
                sub edx,[ebx].color
                FPDIV ecx               ;divide by pixel count
                mov rdc,eax             ;set right DC

                mov ecx,rcnt

                mov edx,[esi].x        ;get size of edge in X
                sub edx,[ebx].x
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdx,eax             ;set right DX

                mov edx,[ebx].color
                add edx,8000h           ;pre-round by adding +0.5

                mov ebx,[ebx].x        
                shl ebx,16              ;convert X to fixed-point val
                add ebx,8000h           ;pre-round by adding +0.5

                pop ecx
                pop eax

                cmp x_clipped,0
                je __unclip_line
                jmp __clip_line

__abort:
                pop edx
                pop ebx
                jmp __exit

                ELSE
                ret
                ENDIF

VFX_Gouraud_polygon ENDP

;*****************************************************************************
VFX_dithered_Gouraud_polygon PROC USES ebx esi edi es,\
                DestPane:PTR PANE, DFactor:F16, VCnt:S32, VList:PSCRNVERTEX

                LOCAL VP_R            
                LOCAL VP_B            
                LOCAL buff_addr       
                LOCAL line_size       
                LOCAL txt_width       
                LOCAL txt_bitmap      
                LOCAL line_base       
                LOCAL x_clipped       
                LOCAL vlist_beg       
                LOCAL vlist_end       
                LOCAL v_top           
                LOCAL lcur            
                LOCAL rcur            
                LOCAL lnxt            
                LOCAL rnxt            
                LOCAL lcnt            
                LOCAL rcnt            
                LOCAL line_cnt        
                LOCAL y               
                LOCAL lx              
                LOCAL rx              
                LOCAL lc              
                LOCAL rc              
                LOCAL lu              
                LOCAL ru              
                LOCAL lv              
                LOCAL rv              
                LOCAL ldx             
                LOCAL rdx             
                LOCAL ldc             
                LOCAL rdc             
                LOCAL ldu             
                LOCAL rdu             
                LOCAL ldv             
                LOCAL rdv             
                LOCAL plx             
                LOCAL prx             
                LOCAL dc              
                LOCAL du              
                LOCAL dv              
                LOCAL flu             
                LOCAL color           

                IF DG_POLY

                SET_DEST_PANE

                ASSUME ebx:PSCRNVERTEX
                ASSUME esi:PSCRNVERTEX

                push ds
                pop es

                mov ebp_save,ebp        ;(EBP used later as temporary var)

                mov ebx,[VList]         ;EBX -> list of VERTEX strcts

                mov eax,[VCnt]
                shl eax,3
                mov edx,eax
                shl eax,1               ;* SIZE VERTEX (4n+16n=24n)
                add eax,edx             

                add eax,ebx

                mov vlist_beg,ebx      
                mov vlist_end,eax       ;BX + VCnt*SIZE VERTEX -> end of list

                ;
                ;Find top and bottom vertices; perform Sutherland-Cohen
                ;clipping on polygon
                ;

                mov x_clipped,0         ;nonzero if any scanlines clipped in X

                mov esi,32767           ;ESI = top vertex Y
                mov edi,-32768          ;EDI = bottom vertex Y

                mov ecx,1111b           ;ECX = S-C "and" result for polygon

__vertex_sort:  mov edx,0               ;EDX = S-C flags for this vertex

                mov eax,[ebx].x
                shld edx,eax,1

                mov eax,VP_R
                sub eax,[ebx].x
                shld edx,eax,1

                or x_clipped,edx

                mov eax,[ebx].y
                shld edx,eax,1

                mov eax,VP_B
                sub eax,[ebx].y
                shld edx,eax,1

                mov eax,[ebx].y

                cmp eax,esi             ;keep track of top and bottom vertices
                jg __not_top
                mov esi,eax
                mov v_top,ebx

__not_top:      cmp eax,edi
                jl __not_btm
                mov edi,eax

__not_btm:      and ecx,edx
                
                add ebx,SIZE SCRNVERTEX
                cmp ebx,vlist_end
                jne __vertex_sort

                or ecx,ecx              ;all vertices to one side of window?
                jnz __exit              ;yes, polygon fully clipped

                mov eax,v_top           ;else init right, left vertices = top
                mov lnxt,eax
                mov rnxt,eax

                mov y,esi               ;init scanline Y = top vertex Y

                cmp edi,esi             ;is polygon flat?
                je __exit               ;yes, don't draw it

                ;
                ;Calculate initial edge positions & stepping vals for
                ;left and right edges
                ;

__init_left:    mov ebx,lnxt
                mov lcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                sub esi,SIZE SCRNVERTEX
                cmp esi,vlist_beg
                jge __init_lnxt
                mov esi,vlist_end
                sub esi,SIZE SCRNVERTEX
__init_lnxt:    mov lnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].y        ;ECX = edge bottom Y
                mov edx,[ebx].y        ;EDX = edge top Y

                cmp edx,0               ;skip edge if above viewport
                jge __set_l_pcnt
                cmp ecx,0
                jle __init_left         ;(bottom vertex shared w/next edge)

__set_l_pcnt:   sub ecx,edx             ;is edge flat?
                jz __init_left          ;yes, advance one edge left

                mov lcnt,ecx            ;set left edge pixel count

                mov edx,[esi].x        ;get size of edge in X
                sub edx,[ebx].x
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldx,eax             ;set left DX
                
                mov ecx,lcnt

                mov edx,[esi].color        ;get size of edge in C
                sub edx,[ebx].color
                FPDIV ecx               ;divide by pixel count
                mov ldc,eax             ;set left DC

                mov edx,[ebx].x        ;convert X and C to fixed-point vals
                shl edx,16              ;pre-round by adding +0.5 to both
                add edx,8000h           
                mov lx,edx

                mov edx,[ebx].color
                add edx,8000h
                mov lc,edx

__init_right:   mov ebx,rnxt
                mov rcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                add esi,SIZE SCRNVERTEX
                cmp esi,vlist_end
                jl __init_rnxt
                mov esi,vlist_beg
__init_rnxt:    mov rnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].y        ;ECX = edge bottom Y
                mov edx,[ebx].y        ;EDX = edge top Y

                cmp edx,0               ;skip edge if above viewport
                jge __set_r_pcnt
                cmp ecx,0
                jle __init_right        ;(bottom vertex shared w/next edge)

__set_r_pcnt:   sub ecx,edx             ;is edge flat?
                jz __init_right         ;yes, advance one edge right

                mov rcnt,ecx            ;set right edge pixel count

                mov edx,[esi].x        ;get size of edge in X
                sub edx,[ebx].x
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdx,eax             ;set right DX
                
                mov ecx,rcnt

                mov edx,[esi].color        ;get size of edge in C
                sub edx,[ebx].color
                FPDIV ecx               ;divide by pixel count
                mov rdc,eax             ;set right DC

                mov edx,[ebx].x        ;convert X and C to fixed-point vals
                shl edx,16              ;pre-round by adding +0.5 to both
                add edx,8000h
                mov rx,edx

                mov edx,[ebx].color
                add edx,8000h
                mov rc,edx

                ;
                ;Set scanline count; clip against bottom of window
                ;

                mov eax,VP_B
                sub eax,y

                sub edi,VP_B
                jg __clip_bottom

                add eax,edi
__clip_bottom:  mov line_cnt,eax

                mov esi,[DFactor]       ;ESI/EDI = dither addition pattern
                mov edi,0

                ;
                ;Clip against top of window
                ;

                mov eax,0
                sub eax,y
                jle __set_Y_base

                sub line_cnt,eax

                test eax,1              ;keep dither pattern consistent when
                jz __clip_top           ;clipping from top
                xchg esi,edi

__clip_top:     mov ecx,0
                mov y,ecx
                mov ebx,lcur
                sub ecx,[ebx].y
                sub lcnt,ecx

                shl ecx,16              ;ECX = # of pixels to clip from left

                mov eax,ldx             ;lx = lx + ECX * ldx
                FPMUL ecx
                add lx,eax

                mov eax,ldc             ;lc = lc + ECX * ldc
                FPMUL ecx
                add lc,eax

                mov ecx,0
                mov ebx,rcur
                sub ecx,[ebx].y
                sub rcnt,ecx

                shl ecx,16              ;ECX = # of pixels to clip from right

                mov eax,rdx             ;rx = rx + ECX * rdx
                FPMUL ecx
                add rx,eax

                mov eax,rdc             ;rc = rc + ECX * rdc
                FPMUL ecx
                add rc,eax

                ;
                ;Set dither pattern, window base address, and loop variables
                ;

__set_Y_base:   mov dither_1,esi
                mov dither_2,edi
                
                mov eax,y
                mul line_size
                mov edi,buff_addr
                add edi,eax             ;EDI = line_base

                mov eax,lx
                mov ebx,rx
                mov ecx,lc
                mov edx,rc

                ;
                ;Use faster loop if unclipped
                ;

                cmp x_clipped,0
                jne __clip_line

                ;
                ;Trace edges & plot unclipped scanlines ...
                ;
                
                ALIGN 4

__unclip_line:  push eax                ;save LX
                push ebx                ;save RX
                push ecx                ;save LC
                push edx                ;save RC
                push edi                ;save line_base

                cmp ebx,eax
                jg __unclip_XC

                xchg eax,ebx
                xchg ecx,edx

__unclip_XC:    sar eax,16              ;convert to int, preserving sign
                sar ebx,16

                add edi,eax             ;EDI -> start of line

                sub ebx,eax               
                mov esi,ebx             ;SI = # of pixels in line
                jz __unclip_loop        ;(single-pixel line)

                sub edx,ecx             ;EDX = frc-flc

                sar ebx,1               ;divide dx by 2, rounding up if zero
                cmp ebx,1
                adc ebx,0

                FPDIV ebx               
                shld edx,eax,16         ;EDX:EAX = 2 * color / x (signed)

                mov ebx,esi

__unclip_loop:  shl eax,16              ;(x64K so 32-bit adds will roll over)
                
                add ebx,edi
                mov line_end,ebx        ;EBX -> end of line

                inc esi                 ;set ESI = # of pixels to draw

                mov ebx,ecx             ;set CL:EBX and CH:EBP = initial
                mov ebp,ecx             ;fixed-point color pair
                add ebx,dither_1
                add ebp,dither_2
                mov ecx,ebx
                shr ecx,16
                mov dh,cl
                mov ecx,ebp
                shr ecx,8
                mov cl,dh
                shl ebx,16              ;(x64K so 32-bit adds will roll over)
                shl ebp,16

                test edi,1              ;pixel destination address even?
                jz __unclip_pairs       ;yes, write word-aligned dot pairs

                mov [edi],cl            ;else write odd pixel first

                dec esi                 ;decrement pixel count
                jz __unclip_next        ;exit if no more pixels

                inc edi                 ;advance output pointer

                xchg cl,ch              ;swap and advance colors
                xchg ebx,ebp
                add ebp,eax             
                adc ch,dl

__unclip_pairs: cmp esi,1       
                je __unclip_end         ;if only one pixel left, go draw it

                push esi
                shr esi,1               ;get # of pairs to draw
                dec esi

D_GOURAUD       MACRO
                mov WORD PTR [edi+INDEX],cx
                add ebx,eax
                adc cl,dl  
                add ebp,eax
                adc ch,dl
                ENDM

                PARTIAL_UNROLL G_unclip_write,D_GOURAUD,6,2,esi

                pop esi
                test esi,1
                jz __unclip_next

__unclip_end:   mov edi,line_end        ;write single pixel at end of line
                mov [edi],cl

__unclip_next:  mov eax,dither_1        ;switch odd/even dither patterns
                mov ebx,dither_2
                mov dither_2,eax
                mov dither_1,ebx
                
                mov ebp,ebp_save        ;recover stack frame
                pop edi                 ;recover loop vars
                pop edx
                pop ecx
                pop ebx
                pop eax

                ;
                ;Step one line down in Y; exit if no more scanlines
                ;

                add edi,line_size

                dec line_cnt
                js __exit
                jz __unclip_last

                ;
                ;Calculate new X and C vals for both edges, stepping across
                ;vertices when necessary to find next scanline
                ;

                dec lcnt
                jz __step_left

                add eax,ldx
                add ecx,ldc

__unclip_r:     dec rcnt
                jz __step_right

                add ebx,rdx
                add edx,rdc

                jmp __unclip_line

__exit:         ret

                ;
                ;Do last line without switching edges
                ;

__unclip_last:  add eax,ldx
                add ecx,ldc

                add ebx,rdx
                add edx,rdc

                jmp __unclip_line

                ;
                ;Trace edges & plot clipped scanlines ...
                ;

                ALIGN 4

__clip_line:    push eax                ;save LX
                push ebx                ;save RX
                push ecx                ;save LC
                push edx                ;save RC
                push edi                ;save line_base

                cmp ebx,eax
                jg __clip_XC

                xchg eax,ebx
                xchg ecx,edx

__clip_XC:      sar eax,16              ;(preserve sign)
                cmp eax,VP_R
                jg __clip_next

                sar ebx,16              ;(preserve sign)
                cmp ebx,0
                jl __clip_next

                mov plx,eax
                mov prx,ebx

                add edi,eax             ;EDI -> start of line

                sub ebx,eax               
                mov esi,ebx               
                inc esi                 ;ESI = # of pixels in line
                cmp esi,1
                jz __set_color          ;(single-pixel line)

                sub edx,ecx             ;EDX = frc-flc

                sar ebx,1               ;divide dx by 2, rounding up if 0
                cmp ebx,1
                adc ebx,0

                FPDIV ebx 
                mov dc,eax              ;dc = EAX = 2 * color / x (signed)

__set_color:    mov eax,0           
                sub eax,plx             ;EAX = # of left-clipped pixels
                jg __clip_left

                mov skip_first,0        ;skip_first bit 0 set if odd # of
                                        ;pixels clipped from left edge
__left_clipped: mov eax,prx
                sub eax,VP_R            ;EAX = # of right-clipped pixels
                jg __clip_right

__clip_loop:    mov eax,edi
                add eax,esi
                dec eax                 ;EAX -> end of line
                mov line_end,eax        

                mov eax,dc              ;EAX = color change/pixel
                shld edx,eax,16         ;EDX:EAX = color / x
                shl eax,16              ;(x64K so 32-bit adds will roll over)

                mov ebx,ecx             ;set CL:EBX and CH:EBP = initial
                mov ebp,ecx             ;fixed-point color pair
                add ebx,dither_1
                add ebp,dither_2
                mov ecx,ebx
                shr ecx,16
                mov dh,cl
                mov ecx,ebp
                shr ecx,8
                mov cl,dh
                shl ebx,16              ;(x64K so 32-bit adds will roll over)
                shl ebp,16

                test skip_first,1       ;1st pair broken by left clipping?
                jnz __skip_first        ;yes, must skip first pixel

                test edi,1              ;pixel destination address even?
                jz __clip_pairs         ;yes, write word-aligned dot pairs

                mov [edi],cl            ;else write odd pixel first

                dec esi                 ;decrement pixel count
                jz __clip_next          ;exit if no more pixels

                inc edi                 ;advance output pointer

__skip_first:   xchg cl,ch              ;swap and advance colors
                xchg ebx,ebp
                add ebp,eax
                adc ch,dl

__clip_pairs:   cmp esi,1                                              
                jz __clip_end           ;if only one pixel left, go draw it

                push esi
                shr esi,1               ;get # of pairs to draw
                dec esi

                PARTIAL_UNROLL G_clip_write,D_GOURAUD,6,2,esi

                pop esi
                test esi,1
                jz __clip_next

__clip_end:     mov edi,line_end        ;write single pixel at end of line
                mov [edi],cl

__clip_next:    mov eax,dither_1        ;switch odd/even dither patterns
                mov ebx,dither_2
                mov dither_2,eax
                mov dither_1,ebx
                
                mov ebp,ebp_save        ;recover stack frame
                pop edi                 ;recover loop vars
                pop edx
                pop ecx
                pop ebx
                pop eax

                ;
                ;Step one line down in Y; exit if no more scanlines
                ;

                add edi,line_size

                dec line_cnt
                js __exit
                jz __clip_last

                ;
                ;Calculate new X and C vals for both edges, stepping across
                ;vertices when necessary to find next scanline
                ;

                dec lcnt
                jz __step_left

                add eax,ldx
                add ecx,ldc

__clip_r:       dec rcnt
                jz __step_right

                add ebx,rdx
                add edx,rdc

                jmp __clip_line

                ;
                ;Do last line without switching edges
                ;

__clip_last:    add eax,ldx
                add ecx,ldc

                add ebx,rdx
                add edx,rdc

                jmp __clip_line

                ;
                ;Clip AX pixels from left edge of scanline
                ;
                ;If odd # of pixels clipped, set flag to split first pair of
                ;color bytes
                ;

__clip_left:    mov skip_first,eax      ;if odd # clipped, skip first in pair

                add edi,eax             ;add AX to left endpoint X...
                sub esi,eax             ;and subtract AX from line width

                and eax,NOT 1           ;get # of pixel pairs to clip
                shl eax,15              ;(convert to FP and divide by 2)

                FPMUL dc                ;adjust color variable by clipped pair
                add ecx,eax             ;count

                jmp __left_clipped

                ;
                ;Clip AX pixels from right edge of scanline
                ;

__clip_right:   sub esi,eax             ;subtract AX from line width
                jmp __clip_loop

                ;
                ;Step across left edge vertex
                ;

__step_left:    push ebx
                push edx

                mov ebx,lnxt
                mov lcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                sub esi,SIZE SCRNVERTEX
                cmp esi,vlist_beg
                jge __step_lnxt
                mov esi,vlist_end
                sub esi,SIZE SCRNVERTEX
__step_lnxt:    mov lnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].y        ;ECX = edge bottom Y
                mov edx,[ebx].y        ;EDX = edge top Y

                sub ecx,edx             ;if edge flat, force delta=1
	;(pci)
	js __abort
                cmp ecx,1               ;(possible only at bottom scan line)
                adc ecx,0

                mov lcnt,ecx            ;set left edge pixel count

                mov edx,[esi].color        ;get size of edge in C
                sub edx,[ebx].color
                FPDIV ecx               ;divide by pixel count
                mov ldc,eax             ;set left DC

                mov ecx,lcnt

                mov edx,[esi].x        ;get size of edge in X
                sub edx,[ebx].x
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldx,eax             ;set left DX
                
                mov ecx,[ebx].color
                add ecx,8000h           ;pre-round by adding +0.5

                mov eax,[ebx].x        
                shl eax,16              ;convert X to fixed-point val
                add eax,8000h           ;pre-round by adding +0.5

                pop edx
                pop ebx

                cmp x_clipped,0
                je __unclip_r
                jmp __clip_r

                ;
                ;Step across right edge vertex
                ;

__step_right:   push eax
                push ecx
                
                mov ebx,rnxt
                mov rcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                add esi,SIZE SCRNVERTEX
                cmp esi,vlist_end
                jl __step_rnxt
                mov esi,vlist_beg
__step_rnxt:    mov rnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].y        ;ECX = edge bottom Y
                mov edx,[ebx].y        ;EDX = edge top Y

                sub ecx,edx             ;if edge flat, force delta=1
	;(pci)
	js __abort
                cmp ecx,1               ;(possible only at bottom scan line)
                adc ecx,0

                mov rcnt,ecx            ;set right edge pixel count

                mov edx,[esi].color        ;get size of edge in C
                sub edx,[ebx].color
                FPDIV ecx               ;divide by pixel count
                mov rdc,eax             ;set right DC

                mov ecx,rcnt

                mov edx,[esi].x        ;get size of edge in X
                sub edx,[ebx].x
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdx,eax             ;set right DX

                mov edx,[ebx].color
                add edx,8000h           ;pre-round by adding +0.5

                mov ebx,[ebx].x        
                shl ebx,16              ;convert X to fixed-point val
                add ebx,8000h           ;pre-round by adding +0.5

                pop ecx
                pop eax

                cmp x_clipped,0
                je __unclip_line
                jmp __clip_line

__abort:
                pop edx
                pop ebx
		jmp __exit

                ELSE
                ret
                ENDIF

VFX_dithered_Gouraud_polygon ENDP

;*****************************************************************************
VFX_translate_polygon PROC USES ebx esi edi es,\
                DestPane:PTR PANE, VCnt:S32, VList:PSCRNVERTEX, XTable:PTR

                LOCAL VP_R            
                LOCAL VP_B            
                LOCAL buff_addr       
                LOCAL line_size       
                LOCAL txt_width       
                LOCAL txt_bitmap      
                LOCAL line_base       
                LOCAL x_clipped       
                LOCAL vlist_beg       
                LOCAL vlist_end       
                LOCAL v_top           
                LOCAL lcur            
                LOCAL rcur            
                LOCAL lnxt            
                LOCAL rnxt            
                LOCAL lcnt            
                LOCAL rcnt            
                LOCAL line_cnt        
                LOCAL y               
                LOCAL lx              
                LOCAL rx              
                LOCAL lc              
                LOCAL rc              
                LOCAL lu              
                LOCAL ru              
                LOCAL lv              
                LOCAL rv              
                LOCAL ldx             
                LOCAL rdx             
                LOCAL ldc             
                LOCAL rdc             
                LOCAL ldu             
                LOCAL rdu             
                LOCAL ldv             
                LOCAL rdv             
                LOCAL plx             
                LOCAL prx             
                LOCAL dc              
                LOCAL du              
                LOCAL dv              
                LOCAL flu             
                LOCAL color           

                IF X_POLY

                SET_DEST_PANE

                ASSUME ebx:PSCRNVERTEX
                ASSUME esi:PSCRNVERTEX

                push ds
                pop es

                mov ebx,[VList]         ;EBX -> list of VERTEX strcts

                mov eax,[VCnt]
                shl eax,3
                mov edx,eax
                shl eax,1               ;* SIZE VERTEX (8n+16n=24n)
                add eax,edx             

                add eax,ebx

                mov vlist_beg,ebx      
                mov vlist_end,eax       ;BX + VCnt*SIZE VERTEX -> end of list

                ;
                ;Find top and bottom vertices; perform Sutherland-Cohen
                ;clipping on polygon
                ;

                mov esi,32767           ;ESI = top vertex Y
                mov edi,-32768          ;EDI = bottom vertex Y

                mov ecx,1111b           ;ECX = S-C "and" result for polygon

__vertex_sort:  mov edx,0               ;EDX = S-C flags for this vertex

                mov eax,[ebx].x
                shld edx,eax,1

                mov eax,VP_R
                sub eax,[ebx].x
                shld edx,eax,1

                mov eax,[ebx].y
                shld edx,eax,1

                mov eax,VP_B
	sub eax,[ebx].y
	shld edx,eax,1

                mov eax,[ebx].y

                cmp eax,esi             ;keep track of top and bottom vertices
                jg __not_top
                mov esi,eax
                mov v_top,ebx

__not_top:      cmp eax,edi
                jl __not_btm
                mov edi,eax

__not_btm:      and ecx,edx
                
                add ebx,SIZE SCRNVERTEX
                cmp ebx,vlist_end
                jne __vertex_sort

                or ecx,ecx              ;all vertices to one side of window?
                jnz __exit              ;yes, polygon fully clipped

                mov eax,v_top           ;else init right, left vertices = top
                mov lnxt,eax
                mov rnxt,eax

                mov y,esi               ;init scanline Y = top vertex Y

                cmp edi,esi             ;is polygon flat?
                je __exit               ;yes, don't draw it

                ;
                ;Calculate initial edge positions & stepping vals for
                ;left and right edges
                ;

__init_left:    mov ebx,lnxt
                mov lcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                sub esi,SIZE SCRNVERTEX
                cmp esi,vlist_beg
                jge __init_lnxt
                mov esi,vlist_end
                sub esi,SIZE SCRNVERTEX
__init_lnxt:    mov lnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].y        ;ECX = edge bottom Y
                mov edx,[ebx].y        ;EDX = edge top Y

                cmp edx,0               ;skip edge if above viewport
                jge __set_l_pcnt
                cmp ecx,0
                jle __init_left         ;(bottom vertex shared w/next edge)

__set_l_pcnt:   sub ecx,edx             ;is edge flat?
                jz __init_left          ;yes, advance one edge left
	;(pci)
	js __exit

                mov lcnt,ecx            ;set left edge pixel count

                mov edx,[esi].x        ;get size of edge in X
                sub edx,[ebx].x
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldx,eax             ;set left DX
                
                mov edx,[ebx].x        ;convert X to fixed-point
                shl edx,16              ;pre-round by adding +0.5
                add edx,8000h           
                mov lx,edx

__init_right:   mov ebx,rnxt
                mov rcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                add esi,SIZE SCRNVERTEX
                cmp esi,vlist_end
                jl __init_rnxt
                mov esi,vlist_beg
__init_rnxt:    mov rnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].y        ;ECX = edge bottom Y
                mov edx,[ebx].y        ;EDX = edge top Y

                cmp edx,0               ;skip edge if above viewport
                jge __set_r_pcnt
                cmp ecx,0
                jle __init_right        ;(bottom vertex shared w/next edge)

__set_r_pcnt:   sub ecx,edx             ;is edge flat?
                jz __init_right         ;yes, advance one edge right
	;(pci)
	js __exit

                mov rcnt,ecx            ;set right edge pixel count

                mov edx,[esi].x        ;get size of edge in X
                sub edx,[ebx].x
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdx,eax             ;set right DX
                
                mov edx,[ebx].x        ;convert X to fixed-point
                shl edx,16              ;pre-round by adding +0.5
                add edx,8000h
                mov rx,edx

                ;
                ;Set scanline count; clip against bottom of window
                ;

                mov eax,VP_B
                sub eax,y

                sub edi,VP_B
                jg __clip_bottom

                add eax,edi
__clip_bottom:  mov line_cnt,eax

                ;
                ;Clip against top of window
                ;

                mov eax,0
                sub eax,y
                jle __set_Y_base

                sub line_cnt,eax

                mov ecx,0
                mov y,ecx
                mov ebx,lcur
                sub ecx,[ebx].y
                sub lcnt,ecx

                shl ecx,16              ;ECX = # of pixels to clip from left

                mov eax,ldx             ;lx = lx + ECX * ldx
                FPMUL ecx
                add lx,eax

                mov ecx,0
                mov ebx,rcur
                sub ecx,[ebx].y
                sub rcnt,ecx

                shl ecx,16              ;ECX = # of pixels to clip from right

                mov eax,rdx             ;rx = rx + ECX * rdx
                FPMUL ecx
                add rx,eax

                ;
                ;Set window base address and loop variables
                ;

__set_Y_base:   mov eax,y
                mul line_size
                add eax,buff_addr
                mov line_base,eax

                mov eax,lx
                mov ebx,rx

                ;
                ;Trace edges & plot scanlines ...
                ;

__do_line:      push eax                ;save LX
                push ebx                ;save RX

                cmp ebx,eax             ;sort X left-to-right
                jg __X_sorted

                xchg eax,ebx

__X_sorted:     sar eax,16              ;(preserve sign)
                cmp eax,VP_R
                jg __next_line

                sar ebx,16              ;(preserve sign)
                cmp ebx,0
                jl __next_line

                mov plx,eax
                mov prx,ebx

                sub ebx,eax             ;EBX = # of pixels in scanline - 1
                jz __r_clipped          ;(single-pixel line)

                mov ecx,0
                sub ecx,plx             ;ECX = # of left-clipped pixels
                jg __clip_left

__l_clipped:    mov eax,prx
                sub eax,VP_R            ;EAX = # of right-clipped pixels
                jg __clip_right

__r_clipped:    mov eax,plx
                mov edi,line_base        
                add edi,eax             ;set EDI -> beginning of dest scanline
                mov ebx,prx
                sub ebx,eax             ;set EBX = # of dest pixels - 1

                mov eax,edi
                add eax,ebx
                mov line_end,eax        ;EAX -> end of line

                xor eax,eax             ;EAX = 0
                mov esi,[XTable]        ;ESI = pointer to lookaside table

                inc ebx
                test edi,1              ;pixel destination address even?
                jz __chk_pairs          ;yes, write word-aligned dot pairs
                mov al,BYTE PTR [edi]   ;else write odd pixel first
                mov dl,BYTE PTR [esi][eax]
                mov BYTE PTR [edi],dl
                dec ebx                 ;decrement pixel count
                jz __next_line          ;exit if no more pixels
                inc edi                 ;advance output pointer

__chk_pairs:    cmp ebx,1
                je __write_end          ;if only one pixel left, go draw it

                push ebx
                shr ebx,1
                dec ebx

                ;
                ;Translate pixels in scanline through lookaside table
                ;

TRANSLATE_PAIR  MACRO
                mov cx,WORD PTR [edi+INDEX]
                mov al,cl
                mov dl,BYTE PTR [esi][eax]
                mov al,ch
                mov dh,BYTE PTR [esi][eax]
                mov WORD PTR [edi+INDEX],dx
                ENDM

                PARTIAL_UNROLL TS,TRANSLATE_PAIR,6,2,ebx

                pop ebx
                test ebx,1
                jz __next_line

__write_end:    mov edi,line_end        ;write single pixel at end of line
                mov al,BYTE PTR [edi]
                mov dl,BYTE PTR [esi][eax]
                mov BYTE PTR [edi],dl

__next_line:    mov edi,line_size
                add line_base,edi

                pop ebx
                pop eax

                ;
                ;Exit if no more scanlines
                ;

                dec line_cnt
                js __exit
                jz __last

                ;
                ;Calculate new X, U, and V vals for both edges, stepping
                ;across vertices when necessary to find next scanline
                ;

                dec lcnt
                jz __step_left

                add eax,ldx

__left_stepped: dec rcnt
                jz __step_right

                add ebx,rdx

                jmp __do_line

__exit:         ret

                ;
                ;Do last line without switching edges
                ;

__last:         add eax,ldx
                add ebx,rdx

                jmp __do_line

                ;
                ;Clip CX pixels from left edge of scanline
                ;

__clip_left:    add plx,ecx             ;add pixel count to left endpoint X
                jmp __l_clipped

                ;
                ;Clip AX pixels from right edge of scanline
                ;

__clip_right:   sub prx,eax             ;subtract AX from line width
                jmp __r_clipped

                ;
                ;Step across left edge vertex
                ;

__step_left:    push ebx

                mov ebx,lnxt
                mov lcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                sub esi,SIZE SCRNVERTEX
                cmp esi,vlist_beg
                jge __step_lnxt
                mov esi,vlist_end
                sub esi,SIZE SCRNVERTEX
__step_lnxt:    mov lnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].y        ;ECX = edge bottom Y
                mov edx,[ebx].y        ;EDX = edge top Y

                sub ecx,edx             ;if edge flat, force delta=1
	;(pci)
	js __abort
                cmp ecx,1               ;(possible only at bottom scan line)
                adc ecx,0

                mov lcnt,ecx            ;set left edge pixel count

                mov edx,[esi].x        ;get size of edge in X
                sub edx,[ebx].x
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldx,eax             ;set left DX

                mov eax,[ebx].x        
                shl eax,16              ;convert X to fixed-point val
                add eax,8000h           ;pre-round by adding +0.5

                pop ebx
                jmp __left_stepped

                ;
                ;Step across right edge vertex
                ;

__step_right:   push eax
                
                mov ebx,rnxt
                mov rcur,ebx            ;EBX -> vertex at top of edge

                mov edi,ebx
                add edi,SIZE SCRNVERTEX
                cmp edi,vlist_end
                jl __step_rnxt
                mov edi,vlist_beg
__step_rnxt:    mov rnxt,edi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[edi].SCRNVERTEX.y  ;ECX = edge bottom Y
                mov edx,[ebx].y             ;EDX = edge top Y

                sub ecx,edx             ;if edge flat, force delta=1
	;(pci)
	js __abort
                cmp ecx,1               ;(possible only at bottom scan line)
                adc ecx,0

                mov rcnt,ecx            ;set right edge pixel count

                mov edx,[edi].SCRNVERTEX.x        ;get size of edge in X
                sub edx,[ebx].x
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdx,eax             ;set right DX

                mov ebx,[ebx].x        
                shl ebx,16              ;convert X to fixed-point val
                add ebx,8000h           ;pre-round by adding +0.5

                pop eax
                jmp __do_line

__abort:
		pop ebx
		jmp __exit

                ELSE
                ret
                ENDIF

VFX_translate_polygon ENDP

;*****************************************************************************
VFX_illuminate_polygon PROC USES ebx esi edi es,\
                DestPane:PTR PANE,DFactor:F16,VCnt:S32,VList:PSCRNVERTEX

                LOCAL VP_R            
                LOCAL VP_B            
                LOCAL buff_addr       
                LOCAL line_size       
                LOCAL txt_width       
                LOCAL txt_bitmap      
                LOCAL line_base       
                LOCAL x_clipped       
                LOCAL vlist_beg       
                LOCAL vlist_end       
                LOCAL v_top           
                LOCAL lcur            
                LOCAL rcur            
                LOCAL lnxt            
                LOCAL rnxt            
                LOCAL lcnt            
                LOCAL rcnt            
                LOCAL line_cnt        
                LOCAL y               
                LOCAL lx              
                LOCAL rx              
                LOCAL lc              
                LOCAL rc              
                LOCAL lu              
                LOCAL ru              
                LOCAL lv              
                LOCAL rv              
                LOCAL ldx             
                LOCAL rdx             
                LOCAL ldc             
                LOCAL rdc             
                LOCAL ldu             
                LOCAL rdu             
                LOCAL ldv             
                LOCAL rdv             
                LOCAL plx             
                LOCAL prx             
                LOCAL dc              
                LOCAL du              
                LOCAL dv              
                LOCAL flu             
                LOCAL color           

                IF I_POLY

                SET_DEST_PANE

                ASSUME ebx:PSCRNVERTEX
                ASSUME esi:PSCRNVERTEX

                push ds
                pop es

                mov ebp_save,ebp        ;(EBP used later as temporary var)

                mov ebx,[VList]         ;EBX -> list of VERTEX strcts

                mov eax,[VCnt]
                shl eax,3
                mov edx,eax
                shl eax,1               ;* SIZE VERTEX (8n+16n=24n)
                add eax,edx             

                add eax,ebx

                mov vlist_beg,ebx      
                mov vlist_end,eax       ;BX + VCnt*SIZE VERTEX -> end of list

                ;
                ;Find top and bottom vertices; perform Sutherland-Cohen
                ;clipping on polygon
                ;

                mov x_clipped,0         ;nonzero if any scanlines clipped in X

                mov esi,32767           ;ESI = top vertex Y
                mov edi,-32768          ;EDI = bottom vertex Y

                mov ecx,1111b           ;ECX = S-C "and" result for polygon

__vertex_sort:  mov edx,0               ;EDX = S-C flags for this vertex

                mov eax,[ebx].x
                shld edx,eax,1

                mov eax,VP_R
                sub eax,[ebx].x
                shld edx,eax,1

                or x_clipped,edx

                mov eax,[ebx].y
                shld edx,eax,1

                mov eax,VP_B
                sub eax,[ebx].y
                shld edx,eax,1

                mov eax,[ebx].y

                cmp eax,esi             ;keep track of top and bottom vertices
                jg __not_top
                mov esi,eax
                mov v_top,ebx

__not_top:      cmp eax,edi
                jl __not_btm
                mov edi,eax

__not_btm:      and ecx,edx
                
                add ebx,SIZE SCRNVERTEX
                cmp ebx,vlist_end
                jne __vertex_sort

                or ecx,ecx              ;all vertices to one side of window?
                jnz __exit              ;yes, polygon fully clipped

                mov eax,v_top           ;else init right, left vertices = top
                mov lnxt,eax
                mov rnxt,eax

                mov y,esi               ;init scanline Y = top vertex Y

                cmp edi,esi             ;is polygon flat?
                je __exit               ;yes, don't draw it

                ;
                ;Calculate initial edge positions & stepping vals for
                ;left and right edges
                ;

__init_left:    mov ebx,lnxt
                mov lcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                sub esi,SIZE SCRNVERTEX
                cmp esi,vlist_beg
                jge __init_lnxt
                mov esi,vlist_end
                sub esi,SIZE SCRNVERTEX
__init_lnxt:    mov lnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].y        ;ECX = edge bottom Y
                mov edx,[ebx].y        ;EDX = edge top Y

                cmp edx,0               ;skip edge if above viewport
                jge __set_l_pcnt
                cmp ecx,0
                jle __init_left         ;(bottom vertex shared w/next edge)

__set_l_pcnt:   sub ecx,edx             ;is edge flat?
                jz __init_left          ;yes, advance one edge left
	;(pci)
	js __exit

                mov lcnt,ecx            ;set left edge pixel count

                mov edx,[esi].x        ;get size of edge in X
                sub edx,[ebx].x
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldx,eax             ;set left DX
                
                mov ecx,lcnt

                mov edx,[esi].color        ;get size of edge in C
                sub edx,[ebx].color
                FPDIV ecx               ;divide by pixel count
                mov ldc,eax             ;set left DC

                mov edx,[ebx].x        ;convert X and C to fixed-point vals
                shl edx,16              ;pre-round by adding +0.5 to both
                add edx,8000h           
                mov lx,edx

                mov edx,[ebx].color
                add edx,8000h
                mov lc,edx

__init_right:   mov ebx,rnxt
                mov rcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                add esi,SIZE SCRNVERTEX
                cmp esi,vlist_end
                jl __init_rnxt
                mov esi,vlist_beg
__init_rnxt:    mov rnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].y        ;ECX = edge bottom Y
                mov edx,[ebx].y        ;EDX = edge top Y

                cmp edx,0               ;skip edge if above viewport
                jge __set_r_pcnt
                cmp ecx,0
                jle __init_right        ;(bottom vertex shared w/next edge)

__set_r_pcnt:   sub ecx,edx             ;is edge flat?
                jz __init_right         ;yes, advance one edge right
	;(pci)
	js __exit

                mov rcnt,ecx            ;set right edge pixel count

                mov edx,[esi].x        ;get size of edge in X
                sub edx,[ebx].x
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdx,eax             ;set right DX
                
                mov ecx,rcnt

                mov edx,[esi].color        ;get size of edge in C
                sub edx,[ebx].color
                FPDIV ecx               ;divide by pixel count
                mov rdc,eax             ;set right DC

                mov edx,[ebx].x        ;convert X and C to fixed-point vals
                shl edx,16              ;pre-round by adding +0.5 to both
                add edx,8000h
                mov rx,edx

                mov edx,[ebx].color
                add edx,8000h
                mov rc,edx

                ;
                ;Set scanline count; clip against bottom of window
                ;

                mov eax,VP_B
                sub eax,y

                sub edi,VP_B
                jg __clip_bottom

                add eax,edi
__clip_bottom:  mov line_cnt,eax

                mov esi,[DFactor]       ;ESI/EDI = dither addition pattern
                mov edi,0

                ;
                ;Clip against top of window
                ;

                mov eax,0
                sub eax,y
                jle __set_Y_base

                sub line_cnt,eax

                test eax,1              ;keep dither pattern consistent when
                jz __clip_top           ;clipping from top
                xchg esi,edi

__clip_top:     mov ecx,0
                mov y,ecx
                mov ebx,lcur
                sub ecx,[ebx].y
                sub lcnt,ecx

                shl ecx,16              ;ECX = # of pixels to clip from left

                mov eax,ldx             ;lx = lx + ECX * ldx
                FPMUL ecx
                add lx,eax

                mov eax,ldc             ;lc = lc + ECX * ldc
                FPMUL ecx
                add lc,eax

                mov ecx,0
                mov ebx,rcur
                sub ecx,[ebx].y
                sub rcnt,ecx

                shl ecx,16              ;ECX = # of pixels to clip from right

                mov eax,rdx             ;rx = rx + ECX * rdx
                FPMUL ecx
                add rx,eax

                mov eax,rdc             ;rc = rc + ECX * rdc
                FPMUL ecx
                add rc,eax

                ;
                ;Set dither pattern, window base address, and loop variables
                ;

__set_Y_base:   mov dither_1,esi
                mov dither_2,edi
                
                mov eax,y
                mul line_size
                mov edi,buff_addr
                add edi,eax             ;EDI = line_base

                mov eax,lx
                mov ebx,rx
                mov ecx,lc
                mov edx,rc

                ;
                ;Use faster loop if unclipped
                ;

                cmp x_clipped,0
                jne __clip_line

                ;
                ;Trace edges & plot unclipped scanlines ...
                ;
                
                ALIGN 4

__unclip_line:  push eax                ;save LX
                push ebx                ;save RX
                push ecx                ;save LC
                push edx                ;save RC
                push edi                ;save line_base

                cmp ebx,eax
                jg __unclip_XC

                xchg eax,ebx
                xchg ecx,edx

__unclip_XC:    sar eax,16              ;convert to int, preserving sign
                sar ebx,16

                add edi,eax             ;EDI -> start of line

                sub ebx,eax               
                mov esi,ebx             ;SI = # of pixels in line
                jz __unclip_loop        ;(single-pixel line)

                sub edx,ecx             ;EDX = frc-flc

                sar ebx,1               ;divide dx by 2, rounding up if zero
                cmp ebx,1
                adc ebx,0

                FPDIV ebx               
                shld edx,eax,16         ;EDX:EAX = 2 * color / x (signed)

                mov ebx,esi

__unclip_loop:  shl eax,16              ;(x64K so 32-bit adds will roll over)
                
                add ebx,edi
                mov line_end,ebx        ;EBX -> end of line

                inc esi                 ;set ESI = # of pixels to draw

                mov ebx,ecx             ;set CL:EBX and CH:EBP = initial
                mov ebp,ecx             ;fixed-point color pair
                add ebx,dither_1
                add ebp,dither_2
                mov ecx,ebx
                shr ecx,16
                mov dh,cl
                mov ecx,ebp
                shr ecx,8
                mov cl,dh
                shl ebx,16              ;(x64K so 32-bit adds will roll over)
                shl ebp,16

                test edi,1              ;pixel destination address even?
                jz __unclip_pairs       ;yes, write word-aligned dot pairs

                add [edi],cl            ;else write odd pixel first

                dec esi                 ;decrement pixel count
                jz __unclip_next        ;exit if no more pixels

                inc edi                 ;advance output pointer

                xchg cl,ch              ;swap and advance colors
                xchg ebx,ebp
                add ebp,eax             
                adc ch,dl

__unclip_pairs: cmp esi,1       
                je __unclip_end         ;if only one pixel left, go draw it

                push esi
                shr esi,1               ;get # of pairs to draw
                dec esi

D_GOURAUD_LIGHT MACRO
                add [edi+INDEX],cx
                add ebx,eax
                adc cl,dl  
                add ebp,eax
                adc ch,dl
                ENDM

                PARTIAL_UNROLL GL_unclip_write,D_GOURAUD_LIGHT,6,2,esi

                pop esi
                test esi,1
                jz __unclip_next

__unclip_end:   mov edi,line_end        ;write single pixel at end of line
                add [edi],cl

__unclip_next:  mov eax,dither_1        ;switch odd/even dither patterns
                mov ebx,dither_2
                mov dither_2,eax
                mov dither_1,ebx
                
                mov ebp,ebp_save        ;recover stack frame
                pop edi                 ;recover loop vars
                pop edx
                pop ecx
                pop ebx
                pop eax

                ;
                ;Step one line down in Y; exit if no more scanlines
                ;

                add edi,line_size

                dec line_cnt
                js __exit
                jz __unclip_last

                ;
                ;Calculate new X and C vals for both edges, stepping across
                ;vertices when necessary to find next scanline
                ;

                dec lcnt
                jz __step_left

                add eax,ldx
                add ecx,ldc

__unclip_r:     dec rcnt
                jz __step_right

                add ebx,rdx
                add edx,rdc

                jmp __unclip_line

__exit:         ret

                ;
                ;Do last line without switching edges
                ;

__unclip_last:  add eax,ldx
                add ecx,ldc

                add ebx,rdx
                add edx,rdc

                jmp __unclip_line

                ;
                ;Trace edges & plot clipped scanlines ...
                ;

                ALIGN 4

__clip_line:    push eax                ;save LX
                push ebx                ;save RX
                push ecx                ;save LC
                push edx                ;save RC
                push edi                ;save line_base

                cmp ebx,eax
                jg __clip_XC

                xchg eax,ebx
                xchg ecx,edx

__clip_XC:      sar eax,16              ;(preserve sign)
                cmp eax,VP_R
                jg __clip_next

                sar ebx,16              ;(preserve sign)
                cmp ebx,0
                jl __clip_next

                mov plx,eax
                mov prx,ebx

                add edi,eax             ;EDI -> start of line

                sub ebx,eax               
                mov esi,ebx               
                inc esi                 ;ESI = # of pixels in line
                cmp esi,1
                jz __set_color          ;(single-pixel line)

                sub edx,ecx             ;EDX = frc-flc

                sar ebx,1               ;divide dx by 2, rounding up if 0
                cmp ebx,1
                adc ebx,0

                FPDIV ebx 
                mov dc,eax              ;dc = EAX = 2 * color / x (signed)

__set_color:    mov eax,0           
                sub eax,plx             ;EAX = # of left-clipped pixels
                jg __clip_left

                mov skip_first,0        ;skip_first bit 0 set if odd # of
                                        ;pixels clipped from left edge
__left_clipped: mov eax,prx
                sub eax,VP_R            ;EAX = # of right-clipped pixels
                jg __clip_right

__clip_loop:    mov eax,edi
                add eax,esi
                dec eax                 ;EAX -> end of line
                mov line_end,eax        

                mov eax,dc              ;EAX = color change/pixel
                shld edx,eax,16         ;EDX:EAX = color / x
                shl eax,16              ;(x64K so 32-bit adds will roll over)

                mov ebx,ecx             ;set CL:EBX and CH:EBP = initial
                mov ebp,ecx             ;fixed-point color pair
                add ebx,dither_1
                add ebp,dither_2
                mov ecx,ebx
                shr ecx,16
                mov dh,cl
                mov ecx,ebp
                shr ecx,8
                mov cl,dh
                shl ebx,16              ;(x64K so 32-bit adds will roll over)
                shl ebp,16

                test skip_first,1       ;1st pair broken by left clipping?
                jnz __skip_first        ;yes, must skip first pixel

                test edi,1              ;pixel destination address even?
                jz __clip_pairs         ;yes, write word-aligned dot pairs

                add [edi],cl            ;else write odd pixel first

                dec esi                 ;decrement pixel count
                jz __clip_next          ;exit if no more pixels

                inc edi                 ;advance output pointer

__skip_first:   xchg cl,ch              ;swap and advance colors
                xchg ebx,ebp
                add ebp,eax
                adc ch,dl

__clip_pairs:   cmp esi,1                                              
                jz __clip_end           ;if only one pixel left, go draw it

                push esi
                shr esi,1               ;get # of pairs to draw
                dec esi

                PARTIAL_UNROLL GL_clip_write,D_GOURAUD_LIGHT,6,2,esi

                pop esi
                test esi,1
                jz __clip_next

__clip_end:     mov edi,line_end        ;write single pixel at end of line
                add [edi],cl

__clip_next:    mov eax,dither_1        ;switch odd/even dither patterns
                mov ebx,dither_2
                mov dither_2,eax
                mov dither_1,ebx
                
                mov ebp,ebp_save        ;recover stack frame
                pop edi                 ;recover loop vars
                pop edx
                pop ecx
                pop ebx
                pop eax

                ;
                ;Step one line down in Y; exit if no more scanlines
                ;

                add edi,line_size

                dec line_cnt
                js __exit
                jz __clip_last

                ;
                ;Calculate new X and C vals for both edges, stepping across
                ;vertices when necessary to find next scanline
                ;

                dec lcnt
                jz __step_left

                add eax,ldx
                add ecx,ldc

__clip_r:       dec rcnt
                jz __step_right

                add ebx,rdx
                add edx,rdc

                jmp __clip_line

                ;
                ;Do last line without switching edges
                ;

__clip_last:    add eax,ldx
                add ecx,ldc

                add ebx,rdx
                add edx,rdc

                jmp __clip_line

                ;
                ;Clip AX pixels from left edge of scanline
                ;
                ;If odd # of pixels clipped, set flag to split first pair of
                ;color bytes
                ;

__clip_left:    mov skip_first,eax      ;if odd # clipped, skip first in pair

                add edi,eax             ;add AX to left endpoint X...
                sub esi,eax             ;and subtract AX from line width

                and eax,NOT 1           ;get # of pixel pairs to clip
                shl eax,15              ;(convert to FP and divide by 2)

                FPMUL dc                ;adjust color variable by clipped pair
                add ecx,eax             ;count

                jmp __left_clipped

                ;
                ;Clip AX pixels from right edge of scanline
                ;

__clip_right:   sub esi,eax             ;subtract AX from line width
                jmp __clip_loop

                ;
                ;Step across left edge vertex
                ;

__step_left:    push ebx
                push edx

                mov ebx,lnxt
                mov lcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                sub esi,SIZE SCRNVERTEX
                cmp esi,vlist_beg
                jge __step_lnxt
                mov esi,vlist_end
                sub esi,SIZE SCRNVERTEX
__step_lnxt:    mov lnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].y        ;ECX = edge bottom Y
                mov edx,[ebx].y        ;EDX = edge top Y

                sub ecx,edx             ;if edge flat, force delta=1
	;(pci)
	js __abort
                cmp ecx,1               ;(possible only at bottom scan line)
                adc ecx,0

                mov lcnt,ecx            ;set left edge pixel count

                mov edx,[esi].color        ;get size of edge in C
                sub edx,[ebx].color
                FPDIV ecx               ;divide by pixel count
                mov ldc,eax             ;set left DC

                mov ecx,lcnt

                mov edx,[esi].x        ;get size of edge in X
                sub edx,[ebx].x
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldx,eax             ;set left DX
                
                mov ecx,[ebx].color
                add ecx,8000h           ;pre-round by adding +0.5

                mov eax,[ebx].x        
                shl eax,16              ;convert X to fixed-point val
                add eax,8000h           ;pre-round by adding +0.5

                pop edx
                pop ebx

                cmp x_clipped,0
                je __unclip_r
                jmp __clip_r

                ;
                ;Step across right edge vertex
                ;

__step_right:   push eax
                push ecx
                
                mov ebx,rnxt
                mov rcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                add esi,SIZE SCRNVERTEX
                cmp esi,vlist_end
                jl __step_rnxt
                mov esi,vlist_beg
__step_rnxt:    mov rnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].y        ;ECX = edge bottom Y
                mov edx,[ebx].y        ;EDX = edge top Y

                sub ecx,edx             ;if edge flat, force delta=1
	;(pci)
	js __abort
                cmp ecx,1               ;(possible only at bottom scan line)
                adc ecx,0

                mov rcnt,ecx            ;set right edge pixel count

                mov edx,[esi].color        ;get size of edge in C
                sub edx,[ebx].color
                FPDIV ecx               ;divide by pixel count
                mov rdc,eax             ;set right DC

                mov ecx,rcnt

                mov edx,[esi].x        ;get size of edge in X
                sub edx,[ebx].x
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdx,eax             ;set right DX

                mov edx,[ebx].color
                add edx,8000h           ;pre-round by adding +0.5

                mov ebx,[ebx].x        
                shl ebx,16              ;convert X to fixed-point val
                add ebx,8000h           ;pre-round by adding +0.5

                pop ecx
                pop eax

                cmp x_clipped,0
                je __unclip_line
                jmp __clip_line

__abort:
                pop edx
                pop ebx
		jmp __exit
		
                ELSE
                ret
                ENDIF

VFX_illuminate_polygon ENDP

;*****************************************************************************
VFX_map_lookaside PROC STDCALL USES ebx esi edi es,\
                table:PTR U8

                IF M_POLY

                cld

                push ds                 
                pop es

                mov esi,[table]         ;DS:ESI -> user lookaside table
                lea edi,lookaside       ;ES:EDI -> local lookaside table

                mov ecx,256/4           ;copy to local memory area with
                rep movsd               ;known offset; allows fast lookup

                ENDIF

                ret

VFX_map_lookaside ENDP

;*****************************************************************************
VFX_map_polygon PROC USES ebx esi edi es,\
                DestPane:PTR PANE, VCnt:S32, VList:PSCRNVERTEX, TxtWnd:PTR VFX_WINDOW,Flags

                LOCAL VP_R            
                LOCAL VP_B            
                LOCAL buff_addr       
                LOCAL line_size       
                LOCAL txt_width       
                LOCAL txt_bitmap      
                LOCAL line_base       
                LOCAL x_clipped       
                LOCAL vlist_beg       
                LOCAL vlist_end       
                LOCAL v_top           
                LOCAL lcur            
                LOCAL rcur            
                LOCAL lnxt            
                LOCAL rnxt            
                LOCAL lcnt            
                LOCAL rcnt            
                LOCAL line_cnt        
                LOCAL y               
                LOCAL lx              
                LOCAL rx              
                LOCAL lc              
                LOCAL rc              
                LOCAL lu              
                LOCAL ru              
                LOCAL lv              
                LOCAL rv              
                LOCAL ldx             
                LOCAL rdx             
                LOCAL ldc             
                LOCAL rdc             
                LOCAL ldu             
                LOCAL rdu             
                LOCAL ldv             
                LOCAL rdv             
                LOCAL plx             
                LOCAL prx             
                LOCAL dc              
                LOCAL du              
                LOCAL dv              
                LOCAL flu             
                LOCAL color           

                IF M_POLY

                SET_DEST_PANE

                mov ebx,[TxtWnd]
                mov eax,[ebx].buffer    ;copy buffer pointer
                mov txt_bitmap,eax
                mov ecx,[ebx].x_max     ;xsize  = windowp->x_max+1
                inc ecx                 ;             - windowp->wnd_x0
                mov txt_width,ecx       ;store line size

                ASSUME ebx:PSCRNVERTEX
                ASSUME esi:PSCRNVERTEX
                ASSUME edi:PSCRNVERTEX

                push ds
                pop es

                mov ebx,[VList]         ;EBX -> list of VERTEX strcts

                mov eax,[VCnt]
                shl eax,3
                mov edx,eax
                shl eax,1               ;* SIZE VERTEX (8n+16n=24n)
                add eax,edx             

                add eax,ebx

                mov vlist_beg,ebx      
                mov vlist_end,eax       ;BX + VCnt*SIZE VERTEX -> end of list

                ;
                ;Find top and bottom vertices; perform Sutherland-Cohen
                ;clipping on polygon
                ;

                mov esi,32767           ;ESI = top vertex Y
                mov edi,-32768          ;EDI = bottom vertex Y

                mov ecx,1111b           ;ECX = S-C "and" result for polygon

__vertex_sort:  mov edx,0               ;EDX = S-C flags for this vertex

                mov eax,[ebx].x
                shld edx,eax,1

                mov eax,VP_R
                sub eax,[ebx].x
                shld edx,eax,1

                mov eax,[ebx].y
                shld edx,eax,1

                mov eax,VP_B
	sub eax,[ebx].y
	shld edx,eax,1

                mov eax,[ebx].y

                cmp eax,esi             ;keep track of top and bottom vertices
                jg __not_top
                mov esi,eax
                mov v_top,ebx

__not_top:      cmp eax,edi
                jl __not_btm
                mov edi,eax

__not_btm:      and ecx,edx
                
                add ebx,SIZE SCRNVERTEX
                cmp ebx,vlist_end
                jne __vertex_sort

                or ecx,ecx              ;all vertices to one side of window?
                jnz __exit              ;yes, polygon fully clipped

                mov eax,v_top           ;else init right, left vertices = top
                mov lnxt,eax
                mov rnxt,eax

                mov y,esi               ;init scanline Y = top vertex Y

                cmp edi,esi             ;is polygon flat?
                je __exit               ;yes, don't draw it

                ;
                ;Calculate initial edge positions & stepping vals for
                ;left and right edges
                ;

__init_left:    mov ebx,lnxt
                mov lcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                sub esi,SIZE SCRNVERTEX
                cmp esi,vlist_beg
                jge __init_lnxt
                mov esi,vlist_end
                sub esi,SIZE SCRNVERTEX
__init_lnxt:    mov lnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].y        ;ECX = edge bottom Y
                mov edx,[ebx].y        ;EDX = edge top Y

                cmp edx,0               ;skip edge if above viewport
                jge __set_l_pcnt
                cmp ecx,0
                jle __init_left         ;(bottom vertex shared w/next edge)

__set_l_pcnt:   sub ecx,edx             ;is edge flat?
                jz __init_left          ;yes, advance one edge left
	;(pci)
	js __exit

                mov lcnt,ecx            ;set left edge pixel count

                mov edx,[esi].x        ;get size of edge in X
                sub edx,[ebx].x
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldx,eax             ;set left DX
                
                mov ecx,lcnt

                mov edx,[esi].u         ;get size of edge in U
                sub edx,[ebx].u
                FPDIV ecx               ;divide by pixel count
                mov ldu,eax             ;set left DU

                mov ecx,lcnt

                mov edx,[esi].v         ;get size of edge in V
                sub edx,[ebx].v
                FPDIV ecx               ;divide by pixel count
                mov ldv,eax             ;set left DV

                mov edx,[ebx].x        ;convert X, U, and V to fixed-point
                shl edx,16              ;pre-round by adding +0.5 to all
                add edx,8000h           
                mov lx,edx

                mov edx,[ebx].u
                add edx,8000h
                mov lu,edx

                mov edx,[ebx].v
                add edx,8000h
                mov lv,edx

__init_right:   mov ebx,rnxt
                mov rcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                add esi,SIZE SCRNVERTEX
                cmp esi,vlist_end
                jl __init_rnxt
                mov esi,vlist_beg
__init_rnxt:    mov rnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].y        ;ECX = edge bottom Y
                mov edx,[ebx].y        ;EDX = edge top Y

                cmp edx,0               ;skip edge if above viewport
                jge __set_r_pcnt
                cmp ecx,0
                jle __init_right        ;(bottom vertex shared w/next edge)

__set_r_pcnt:   sub ecx,edx             ;is edge flat?
                jz __init_right         ;yes, advance one edge right
	;(pci)
	js __exit

                mov rcnt,ecx            ;set right edge pixel count

                mov edx,[esi].x        ;get size of edge in X
                sub edx,[ebx].x
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdx,eax             ;set right DX
                
                mov ecx,rcnt

                mov edx,[esi].u         ;get size of edge in U
                sub edx,[ebx].u
                FPDIV ecx               ;divide by pixel count
                mov rdu,eax             ;set right DU

                mov ecx,rcnt

                mov edx,[esi].v         ;get size of edge in U
                sub edx,[ebx].v
                FPDIV ecx               ;divide by pixel count
                mov rdv,eax             ;set right DV

                mov edx,[ebx].x        ;convert X,U, and V to fixed-point
                shl edx,16              ;pre-round by adding +0.5 to all
                add edx,8000h
                mov rx,edx

                mov edx,[ebx].u
                add edx,8000h
                mov ru,edx

                mov edx,[ebx].v
                add edx,8000h
                mov rv,edx

                ;
                ;Set scanline count; clip against bottom of window
                ;

                mov eax,VP_B
                sub eax,y

                sub edi,VP_B
                jg __clip_bottom

                add eax,edi
__clip_bottom:  mov line_cnt,eax

                ;
                ;Clip against top of window
                ;

                mov eax,0
                sub eax,y
                jle __set_Y_base

                sub line_cnt,eax

                mov ecx,0
                mov y,ecx
                mov ebx,lcur
                sub ecx,[ebx].y
                sub lcnt,ecx

                shl ecx,16              ;ECX = # of pixels to clip from left

                mov eax,ldx             ;lx = lx + ECX * ldx
                FPMUL ecx
                add lx,eax

                mov eax,ldu             ;lu = lu + ECX * ldu
                FPMUL ecx
                add lu,eax

                mov eax,ldv             ;lv = lv + ECX * ldv
                FPMUL ecx
                add lv,eax

                mov ecx,0
                mov ebx,rcur
                sub ecx,[ebx].y
                sub rcnt,ecx

                shl ecx,16              ;ECX = # of pixels to clip from right

                mov eax,rdx             ;rx = rx + ECX * rdx
                FPMUL ecx
                add rx,eax

                mov eax,rdu             ;ru = ru + ECX * rdu
                FPMUL ecx
                add ru,eax

                mov eax,rdv             ;rv = rv + ECX * rdv
                FPMUL ecx
                add rv,eax

                ;
                ;Set window base address and loop variables
                ;

__set_Y_base:   mov eax,y
                mul line_size
                add eax,buff_addr
                mov line_base,eax

                mov eax,[Flags]          ;select optimum output loop based on 
                mov eax,__map_logic[eax*4] ;user-requested options
                mov loop_entry,eax

                mov eax,lx
                mov ebx,rx
                mov ecx,lu
                mov edx,ru
                mov esi,lv
                mov edi,rv

                ;
                ;Trace edges & plot scanlines ...
                ;

__do_line:      push eax                ;save LX
                push ebx                ;save RX
                push ecx                ;save LU
                push edx                ;save RU
                push esi                ;save LV
                push edi                ;save RV

                cmp ebx,eax             ;sort X, U, and V left-to-right
                jg __XUV_sorted

                xchg eax,ebx
                xchg ecx,edx
                xchg esi,edi

__XUV_sorted:   sar eax,16              ;(preserve sign)
                cmp eax,VP_R
                jg __next_line

                sar ebx,16              ;(preserve sign)
                cmp ebx,0
                jl __next_line

                mov plx,eax
                mov prx,ebx

                mov flu,ecx             ;save left source X (U)
                
                sub ebx,eax             ;EBX = # of pixels in scanline - 1
                jz __index_bitmap       ;(single-pixel line)

                push ebx

                sub edx,ecx             ;EDX = ru-lu
                FPDIV ebx
                mov du,eax              
                shld edx,eax,16

                pop ebx

                and eax,0ffffh
                and edx,0ffffh

                mov ecx,1               ;assume DU positive
                test edx,8000h
                jz __set_U_step
                or edx,0ffff0000h
                neg ecx
                cmp eax,1               ;if DU negative, truncate step to
                sbb edx,-1              ;next higher integer
__set_U_step:   add ecx,edx

                push ecx
                push edx

                sub edi,esi             ;EDI = rv-lv
                mov edx,edi
                FPDIV ebx
                mov dv,eax
                shld edx,eax,16

                and eax,0ffffh
                and edx,0ffffh

                mov ecx,txt_width       ;assume DV positive
                test edx,8000h
                jz __set_V_step
                neg ecx                  
                cmp eax,1               ;if DV negative, truncate step to
                sbb edx,-1              ;next higher integer
__set_V_step:   mov eax,txt_width
                imul dx                 ;EAX = DV base, ECX = DV step-DV base
                cwde

                pop edx                 ;EDX = DU base
                pop ebx                 ;EBX = DU step

                add edx,eax               
                mov UV_step[0*4],edx    ;00 = DU+base,DV+base
                add edx,ecx
                mov UV_step[1*4],edx    ;01 = DU+base,DV+base+step
                add ebx,eax
                mov UV_step[2*4],ebx    ;10 = DU+base+step,DV+base
                add ebx,ecx
                mov UV_step[3*4],ebx    ;11 = DU+base+step,DV+base+step

                mov ecx,0
                sub ecx,plx             ;ECX = # of left-clipped pixels
                jg __clip_left

__left_clipped: mov eax,prx
                sub eax,VP_R            ;EAX = # of right-clipped pixels
                jg __clip_right

__index_bitmap: mov ecx,esi

                shr esi,16              ;set ESI -> texture pixel at (lu,lv)
                mov eax,esi
                mul txt_width           ;index initial texture scanline
                add eax,txt_bitmap
                mov esi,flu
                shr esi,16
                add esi,eax             ;add left edge U (source X)

                mov eax,plx
                mov edi,line_base        
                add edi,eax             ;set EDI -> beginning of dest scanline
                mov ebx,prx
                sub ebx,eax             ;set EBX = # of dest pixels - 1

                push ebp

                mov edx,flu

                mov eax,du              ;adjust U and DU for additive carry   
                or eax,eax              ;generation
                jns __DU_positive
                neg eax
                not edx                 ;(negate and subtract 1)
__DU_positive:  shl eax,16
                shl edx,16

                mov ebp,dv              ;adjust V and DV for additive carry
                or ebp,ebp              ;generation
                jns __DV_positive
                neg ebp
                not ecx                 ;(negate and subtract 1)
__DV_positive:  shl ebp,16
                shl ecx,16

                push ebx                ;set [esp] = pixel count-1
                xor ebx,ebx             ;initialize EBX = 0
                jmp [loop_entry]        ;branch to desired output loop

                ;
                ;Common code to advance source pixel location
                ;

SOURCE_ADVANCE  MACRO
                xor ebx,ebx             ;clear advance table index
                add edx,eax             ;U += DU                  
                adc ebx,ebx             ;shift carry into index   
                add ecx,ebp             ;V += DV                  
                adc ebx,ebx             ;shift carry into index   
                add esi,UV_step[ebx*4]  ;advance in both U and V
                ENDM

                ;
                ;Translated scanline output with transparency
                ;

TXTMAP_TX       MACRO       
                mov bl,BYTE PTR [esi]
                mov bl,lookaside[ebx]
                cmp bl,PAL_TRANSPARENT
                je @F
                mov BYTE PTR [edi+INDEX],bl
@@:             
                SOURCE_ADVANCE
                ENDM
                                 
                ;
                ;Translated scanline output, no transparency
                ;

TXTMAP_X        MACRO       
                mov bl,BYTE PTR [esi]
                mov bl,lookaside[ebx]
                mov BYTE PTR [edi+INDEX],bl

                SOURCE_ADVANCE
                ENDM

                ;
                ;Untranslated scanline output with transparency
                ;

TXTMAP_T        MACRO       
                mov bl,BYTE PTR [esi]
                cmp bl,PAL_TRANSPARENT
                je @F
                mov BYTE PTR [edi+INDEX],bl
@@:             
                SOURCE_ADVANCE
                ENDM

                ;
                ;Untranslated scanline output, no transparency
                ;

TXTMAP          MACRO
                mov bl,BYTE PTR [esi]
                mov BYTE PTR [edi+INDEX],bl

                SOURCE_ADVANCE
                ENDM

                ;
                ;Vectors into texture-mapping variations
                ;

__map_logic     dd OFFSET M_write       ;flags = 0
                dd OFFSET MX_write      ;flags = MP_XLAT
                dd OFFSET MT_write      ;flags = MP_XP
                dd OFFSET MTX_write     ;flags = MP_XLAT | MP_XP

                PARTIAL_UNROLL MTX_write,TXTMAP_TX,6,1,DWORD PTR [esp]
                jmp __end_line

                PARTIAL_UNROLL MX_write,TXTMAP_X,6,1,DWORD PTR [esp]
                jmp __end_line

                PARTIAL_UNROLL MT_write,TXTMAP_T,6,1,DWORD PTR [esp]
                jmp __end_line

                PARTIAL_UNROLL M_write,TXTMAP,6,1,DWORD PTR [esp]

__end_line:     add esp,4               ;remove iteration counter from stack
                pop ebp                 ;restore stack frame

__next_line:    mov edi,line_size
                add line_base,edi

                pop edi
                pop esi
                pop edx
                pop ecx
                pop ebx
                pop eax

                ;
                ;Exit if no more scanlines
                ;

                dec line_cnt
                js __exit
                jz __last

                ;
                ;Calculate new X, U, and V vals for both edges, stepping
                ;across vertices when necessary to find next scanline
                ;

                dec lcnt
                jz __step_left

                add eax,ldx
                add ecx,ldu
                add esi,ldv

__left_stepped: dec rcnt
                jz __step_right

                add ebx,rdx
                add edx,rdu
                add edi,rdv

                jmp __do_line

__exit:         ret

                ;
                ;Do last line without switching edges
                ;

__last:         add eax,ldx
                add ecx,ldu
                add esi,ldv

                add ebx,rdx
                add edx,rdu
                add edi,rdv

                jmp __do_line

                ;
                ;Clip CX pixels from left edge of scanline
                ;

__clip_left:    add plx,ecx             ;add pixel count to left endpoint X

                shl ecx,16              ;convert to FP

                mov eax,du
                FPMUL ecx               ;adjust U
                add flu,eax

                mov eax,dv
                FPMUL ecx               ;adjust V
                add esi,eax
                
                jmp __left_clipped

                ;
                ;Clip AX pixels from right edge of scanline
                ;

__clip_right:   sub prx,eax             ;subtract AX from line width
                jmp __index_bitmap

                ;
                ;Step across left edge vertex
                ;

__step_left:    push ebx
                push edx

                mov ebx,lnxt
                mov lcur,ebx            ;EBX -> vertex at top of edge

                mov esi,ebx
                sub esi,SIZE SCRNVERTEX
                cmp esi,vlist_beg
                jge __step_lnxt
                mov esi,vlist_end
                sub esi,SIZE SCRNVERTEX
__step_lnxt:    mov lnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[esi].y        ;ECX = edge bottom Y
                mov edx,[ebx].y        ;EDX = edge top Y

                sub ecx,edx             ;if edge flat, force delta=1
	;(pci)
	js __abort
                cmp ecx,1               ;(possible only at bottom scan line)
                adc ecx,0

                mov lcnt,ecx            ;set left edge pixel count

                mov edx,[esi].x        ;get size of edge in X
                sub edx,[ebx].x
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldx,eax             ;set left DX

                mov ecx,lcnt

                mov edx,[esi].u         ;get size of edge in U
                sub edx,[ebx].u
                FPDIV ecx               ;divide by pixel count
                mov ldu,eax             ;set left DU

                mov ecx,lcnt

                mov edx,[esi].v         ;get size of edge in V
                sub edx,[ebx].v
                FPDIV ecx               ;divide by pixel count
                mov ldv,eax             ;set left DV

                mov eax,[ebx].x        
                shl eax,16              ;convert X to fixed-point val
                add eax,8000h           ;pre-round by adding +0.5

                mov ecx,[ebx].u
                add ecx,8000h           ;pre-round by adding +0.5

                mov esi,[ebx].v
                add esi,8000h           ;pre-round by adding +0.5

                pop edx
                pop ebx
                jmp __left_stepped

                ;
                ;Step across right edge vertex
                ;

__step_right:   push eax
                push ecx
                
                mov ebx,rnxt
                mov rcur,ebx            ;EBX -> vertex at top of edge

                mov edi,ebx
                add edi,SIZE SCRNVERTEX
                cmp edi,vlist_end
                jl __step_rnxt
                mov edi,vlist_beg
__step_rnxt:    mov rnxt,edi            ;ESI -> vertex at bottom (end) of edge

                mov ecx,[edi].y        ;ECX = edge bottom Y
                mov edx,[ebx].y        ;EDX = edge top Y

                sub ecx,edx             ;if edge flat, force delta=1
	;(pci)
	js __abort
                cmp ecx,1               ;(possible only at bottom scan line)
                adc ecx,0

                mov rcnt,ecx            ;set right edge pixel count

                mov edx,[edi].x        ;get size of edge in X
                sub edx,[ebx].x
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdx,eax             ;set right DX

                mov ecx,rcnt

                mov edx,[edi].u         ;get size of edge in U
                sub edx,[ebx].u
                FPDIV ecx               ;divide by pixel count
                mov rdu,eax             ;set right DU

                mov ecx,rcnt

                mov edx,[edi].v         ;get size of edge in V
                sub edx,[ebx].v
                FPDIV ecx               ;divide by pixel count
                mov rdv,eax             ;set right DV

                mov edx,[ebx].u
                add edx,8000h           ;pre-round by adding +0.5

                mov edi,[ebx].v
                add edi,8000h           ;pre-round by adding +0.5

                mov ebx,[ebx].x        
                shl ebx,16              ;convert X to fixed-point val
                add ebx,8000h           ;pre-round by adding +0.5

                pop ecx
                pop eax
                jmp __do_line

__abort:
                pop edx
                pop ebx
                jmp __exit

                ELSE
                ret
                ENDIF

VFX_map_polygon ENDP

                END
