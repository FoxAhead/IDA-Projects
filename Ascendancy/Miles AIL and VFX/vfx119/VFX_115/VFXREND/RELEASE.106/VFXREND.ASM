;лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
;лл                                                                        лл
;лл  VFXREND.ASM                                                           лл
;лл                                                                        лл
;лл  VFX general-purpose polygon rendering primitives                      лл
;лл                                                                        лл
;лл  Version 1.00 of  5-Nov-93: Original (derived from VFX3D V1.02)        лл
;лл          1.01 of 20-Nov-93: Fixed and commented TEXTURE_SETUP macro    лл
;лл                             Moved BUILD options to RENDOPTS.INC        лл
;лл                             Switched SMP_FINE, SMP_COARSE mask values  лл
;лл          1.02 of 23-Nov-93: Absolute value testing in SCAN_CONVERT     лл
;лл          1.03 of 24-Nov-93: New delta calculations, optimizations      лл
;лл          1.04 of 13-Dec-93: Screen coords changed to integers          лл
;лл                             EBX register now holds dv_fract            лл
;лл                             Replaced string instructions               лл
;лл                             Vector table moved to code segment         лл
;лл          1.05 of 16-Dec-93: ROUND_UV option added                      лл
;лл          1.06 of 16-Jan-94: Indirect Gouraud shading added             лл
;лл                             Clipping code merged                       лл
;лл                                                                        лл
;лл  Project: 386FX Sound & Light(TM)                                      лл
;лл  Authors: John Miles, John Lemberger                                   лл
;лл                                                                        лл
;лл  C prototypes in VFXREND.H                                             лл
;лл                                                                        лл
;лл  80386 ASM source compatible with Microsoft Assembler v6.0 or later    лл
;лл                                                                        лл
;лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
;лл                                                                        лл
;лл  Copyright (C) 1991-1993 Miles Design, Inc.                            лл
;лл  Copyright (C) 1993-1994 Non-Linear Arts, Inc.                         лл
;лл                                                                        лл
;лл  Non-Linear Arts, Inc.                                                 лл
;лл  3415 Greystone Drive                                                  лл
;лл  Suite 200                                                             лл
;лл  Austin, TX 78731                                                      лл
;лл                                                                        лл
;лл  Support: (512) 346-9595 / FAX (512) 346-9596 / BBS (512) 454-9990     лл
;лл                                                                        лл
;лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

                IFDEF MASM
                OPTION SCOPED           ;Enable local labels
                ELSE
                LOCALS __       
                ENDIF

                .386P                   ;Enable 386 instructions

                IFDEF FLAT_MODEL
                .MODEL FLAT,C           ;32-bit OS/2 model
                ELSE
                .MODEL SMALL,C          ;Small 16-bit model
                ENDIF

                INCLUDE VFX.INC

                ;
                ;Configuration
                ;

XCOLOR          equ 255                 ;Transparent color for texture mapping

ROUND_UV        equ 1                   ;1 to add 0.5 to (u,v) coords for
                                        ;underflow protection; should be set
                                        ;to 0 if noninteger (u,v) input coords
                                        ;cause page faults

BUILD_CLIP      equ 1                   ;1 to assemble clipping code

MAX_SCRNVERTEX  equ 256                 ;Max # of points in clipped polygon

                ;
                ;Flags
                ;

MAP_ILLUM       = 0000h       ;Translate existing pixels only (flat/Gouraud)
MAP_SOLID       = 0200h       ;Draw solid polygon only (flat/Gouraud)
MAP_AFFINE      = 0400h       ;Draw affine texture map 
MAP_PERSPECT    = 0600h       ;Draw perspective texture map

SHD_NONE        = 0000h       ;No shading
SHD_FLAT        = 0080h       ;Output translated via 256-byte flat shading
SHD_GOURAUD     = 0040h       ;Outout translated via Gouraud lookaside shading
SHD_I_GOURAUD   = 00c0h       ;Output written as indirect Gouraud fill
SHD_R_GOURAUD   = 0100h       ;Output written as palette-range Gouraud fill

SMP_FINE        = 0000h       ;Normal (1:1) texture sampling
SMP_COARSE      = 0020h       ;Subsample texture by 2:1

TIL_NONE        = 0000h       ;No tiling
TIL_LOG         = 0010h       ;Tiling in binary-power increments only (2^n)
TIL_LIN         = 0008h       ;Tiling in linear (arbitrary) increments

XP_NONE         = 0000h       ;No transparency processing
XP_SKIP         = 0001h       ;Skip transparent pixels
XP_FLAT         = 0002h       ;Draw transparent pixels as solid color
XP_XLUCENT      = 0003h       ;Draw transparent pixels as lookaside[screen]
XP_I_GOURAUD    = 0004h       ;Draw transparent pixels with Gouraud fill
XP_R_GOURAUD    = 0007h       ;Draw transparent pixels with indirect fill

PARM_SPACE      equ 800h      ;2 ^ width of operation bitmask

                ;
                ;Misc. equates
                ;

MAP_MASK        = 600h
SHD_MASK        = 1c0h
SMP_MASK        = 20h
TIL_MASK        = 18h
XP_MASK         = 7h
                                
MAP             equ <(OP AND MAP_MASK)>
SHD             equ <(OP AND SHD_MASK)>
SMP             equ <(OP AND SMP_MASK)>
TIL             equ <(OP AND TIL_MASK)>
XP              equ <(OP AND  XP_MASK)>

CLIP_RIGHT_BIT  equ 08H
CLIP_LEFT_BIT   equ 04H
CLIP_TOP_BIT    equ 02H
CLIP_BOTTOM_BIT equ 01H

                .DATA

                ;
                ;Global data -- should be DWORD aligned for speed
                ;

dfactor_1       dd 8000h
dfactor_2       dd 0

dither_1        dd ?
dither_2        dd ?

line_size       dd ?
line_end        dd ?
buff_addr       dd ?
vlist_beg       dd ?
vlist_end       dd ?
lnxt            dd ?
rnxt            dd ?
lcnt            dd ?
rcnt            dd ?
line_cnt        dd ?
y               dd ?
lx              dd ?
rx              dd ?
lc              dd ?
rc              dd ?
lu              dd ?
ru              dd ?
lv              dd ?
rv              dd ?
lw              dd ?
rw              dd ?
ldx             dd ?
rdx             dd ?
ldc             dd ?
rdc             dd ?
ldu             dd ?
rdu             dd ?
ldv             dd ?
rdv             dd ?
ldw             dd ?
rdw             dd ?
plx             dd ?
prx             dd ?
dc              dd ?
du              dd ?
dv              dd ?
color           dd ?
xp_color        dd ?

pixel_cnt       dd ?
pdw             dd ?
flu             dd ?
fru             dd ?
flv             dd ?
frv             dd ?
flw             dd ?
frw             dd ?
ut              dd ?
vt              dd ?
du_fract        dd ?
du_whole        dd ?
dv_fract        dd ?
dv_whole        dd ?
du_fract_x2     dd ?
du_whole_x2     dd ?
dv_fract_x2     dd ?
dv_whole_x2     dd ?
dc_fract        dd ?
dc_whole        dd ?
loops           dd ?
iterations      dd ?

U_tile          dd ?
V_tile          dd ?

p_texture       dd ?
p_cueing        dd ?
p_translucency  dd ?

                IF BUILD_CLIP
work_pts        dd MAX_SCRNVERTEX * ((SIZE SCRNVERTEX) / 4) dup (?)
UV_clip         dd ?
W_clip          dd ?
C_clip          dd ?
                ENDIF

                .CODE

                PUBLIC VFX_polygon_render
                PUBLIC VFX_set_Gouraud_dither_level

                IF BUILD_CLIP
                PUBLIC VFX_polygon_clip_XY_and_render
                PUBLIC F16_div_to_F30
                PUBLIC F30_reciprocal
                PUBLIC mul_F30
                ENDIF

                ;
                ;Polygon vertex descriptor
                ;

POLYVERTEX      STRUC
vx              dd ?    ;Vertex destination X            (int)
vy              dd ?    ;Vertex destination Y            (int)
vc              dd ?    ;Vertex color                    (16:16)
u               dd ?    ;Source texture X                (16:16)
v               dd ?    ;Source texture Y                (16:16)
w               dd ?    ;Homogeneous perspective divisor (2:30)
POLYVERTEX      ENDS

PPOLYVERTEX     TYPEDEF PTR POLYVERTEX

                ;
                ;Texture map descriptor
                ;

VFXTXT          STRUC
v_addrs         dd ?    ;Pointer to list of baseline V-addresses
txt_width       dd ?    ;X tiling limit
txt_height      dd ?    ;Y tiling limit
VFXTXT          ENDS

PVFXTXT         TYPEDEF PTR VFXTXT

                ;
                ;Fixed-point divide yields EAX = 16:16 result
                ;of 16:16 EDX / 16:16 Divisor
                ;
                ;Does not round; should be used only to project to screen
                ;
            
FIXDIV          MACRO Divisor

                xor eax,eax
                shrd eax,edx,16
                sar edx,16
                idiv Divisor

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
                ;Fixed-point divide yields EAX = +/- 1:fract result
                ;of FP EDX / integer Divisor
                ;
                ;Does not round; should be used only to project to screen
                ;
                
FPDIVONE        MACRO Divisor

                xor eax,eax
                shrd eax,edx,2
                sar edx,2
                idiv Divisor            ;EAX = whole:fraction (16.16)

                ENDM

                ;
                ;Generate partially-unrolled loop
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
                ;Write ECX copies of AL (replicated into EAX) to DS:DI
                ;
                ;Destroys EDX
                ;

REP_STOS        MACRO
                LOCAL __write_rem,__write_whole,_WW,__exit

                cmp ecx,4
                jl __write_rem

                REPT 3
                test edi,3
                jz __write_whole
                mov [edi],al
                inc edi
                dec ecx
                ENDM

__write_whole:  push ecx
                shr ecx,2

__write_4:      cmp ecx,4
                jl __string_rem
                mov [edi],eax
                mov [edi+4],eax
                mov [edi+8],eax
                mov [edi+12],eax
                add edi,16
                sub ecx,4
                jmp __write_4
__string_rem:   REPT 3
                dec ecx
                js __write_rest
                mov [edi],eax
                add edi,4
                ENDM

__write_rest:   pop ecx

                and ecx,3
__write_rem:
                INDEX = 0
                REPT 3
                dec ecx
                jl __exit
                mov [edi+INDEX],al
                INDEX = INDEX + 1
                ENDM
__exit:
                ENDM

;лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
;лл                                                                        лл
;лл Scanline output modules                                                лл
;лл                                                                        лл
;лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

                ;
                ;Setup code for palette-range Gouraud fill
                ;

R_GOURAUD_SETUP MACRO

                mov eax,dfactor_1
                mov dither_1,eax

                mov eax,dfactor_2
                mov dither_2,eax

                ENDM

                ;
                ;Solid Gouraud-filled polygon
                ;

R_GOURAUD_SOLID MACRO

                mov eax,lx
                mov ebx,rx
                mov ecx,lc
                mov edx,rc

                cmp ebx,eax
                jg __Gouraud_XC

                xchg eax,ebx
                xchg ecx,edx

__Gouraud_XC:   sar eax,16              ;convert to int, preserving sign
                sar ebx,16

                mov edi,buff_addr
                add edi,eax             ;EDI -> start of line

                sub ebx,eax               
                mov esi,ebx             ;SI = # of pixels in line
                jz __Gouraud_loop       ;(single-pixel line)

                sub edx,ecx             ;EDX = frc-flc

                sar ebx,1               ;divide dx by 2, rounding up if zero
                cmp ebx,1
                adc ebx,0

                FPDIV ebx               
                shld edx,eax,16         ;EDX:EAX = 2 * color / x (signed)

                mov ebx,esi

__Gouraud_loop: shl eax,16              ;(x64K so 32-bit adds will roll over)
                
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
                jz __Gouraud_pair       ;yes, write word-aligned dot pairs

                mov [edi],cl            ;else write odd pixel first

                dec esi                 ;decrement pixel count
                jz __Gouraud_next       ;exit if no more pixels

                inc edi                 ;advance output pointer

                xchg cl,ch              ;swap and advance colors
                xchg ebx,ebp
                add ebp,eax             
                adc ch,dl

__Gouraud_pair: cmp esi,1       
                je __Gouraud_end        ;if only one pixel left, go draw it

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

                PARTIAL_UNROLL __Gouraud_write,D_GOURAUD,6,2,esi

                pop esi
                test esi,1
                jz __Gouraud_next

__Gouraud_end:  mov edi,line_end        ;write single pixel at end of line
                mov [edi],cl

__Gouraud_next: mov eax,dither_1        ;switch odd/even dither patterns
                mov ebx,dither_2
                mov dither_2,eax
                mov dither_1,ebx
                
                ENDM

                ;
                ;Setup code for indirect Gouraud fill
                ;

I_GOURAUD_SETUP MACRO

                mov eax,dfactor_1
                mov dither_1,eax

                mov eax,dfactor_2
                mov dither_2,eax

                mov eax,p_translucency

                cmp DWORD PTR es:__ig_00+2,eax
                je __end_set_ig

                mov DWORD PTR es:__ig_00+2,eax
                mov DWORD PTR es:__ig_01+2,eax
                mov DWORD PTR es:__ig_02+2,eax
                mov DWORD PTR es:__ig_03+2,eax
                mov DWORD PTR es:__ig_10+2,eax        
                mov DWORD PTR es:__ig_11+2,eax
                mov DWORD PTR es:__ig_12+2,eax

                mov DWORD PTR es:__jg_00+2,eax
                mov DWORD PTR es:__jg_01+2,eax
                mov DWORD PTR es:__jg_02+2,eax
                mov DWORD PTR es:__jg_03+2,eax
                mov DWORD PTR es:__jg_10+2,eax        
                mov DWORD PTR es:__jg_11+2,eax
                mov DWORD PTR es:__jg_12+2,eax

__end_set_ig:
                ENDM

                ;
                ;Solid indirect-Gouraud-filled polygon
                ;

I_GOURAUD_SOLID MACRO

                mov eax,lx
                mov ebx,rx
                mov ecx,lc
                mov edx,rc

                cmp ebx,eax
                jg __I_G_XC

                xchg eax,ebx
                xchg ecx,edx

__I_G_XC:       sar eax,16              ;convert to int, preserving sign
                sar ebx,16

                mov edi,buff_addr
                add edi,eax             ;EDI -> start of line

                sub ebx,eax               
                mov esi,ebx             ;ESI = # of pixels in line
                jz __I_G_loop           ;(single-pixel line)

                sub edx,ecx             ;EDX = frc-flc

                sar ebx,1               ;divide dx by 2, rounding up if zero
                cmp ebx,1
                adc ebx,0

                FPDIV ebx               
                shld edx,eax,16         ;EDX:EAX = 2 * color / x (signed)

                mov ebx,esi

__I_G_loop:     shl eax,16              ;(x64K so 32-bit adds will roll over)
                mov dc_fract,eax
                mov dc_whole,edx
                
                add ebx,edi
                mov line_end,ebx        ;EBX -> end of line

                inc esi                 ;set ESI = # of pixels to draw

                mov ebx,ecx             ;set CL:EBX and DL:EBP = initial
                mov ebp,ecx             ;fixed-point color pair
                add ebx,dither_1
                add ebp,dither_2
                mov ecx,ebx
                shr ecx,16
                mov edx,ebp
                shr edx,16
                shl ebx,16              ;(x64K so 32-bit adds will roll over)
                shl ebp,16

                and ecx,0ffh            ;zero high 24-bits of index values
                and edx,0ffh            

                test edi,1              ;pixel destination address even?
                jz __I_G_pair           ;yes, write word-aligned dot pairs

                mov eax,p_translucency
                mov al,[eax][ecx]
                mov [edi],al            ;else write odd pixel first

                dec esi                 ;decrement pixel count
                jz __I_G_next           ;exit if no more pixels

                inc edi                 ;advance output pointer

                xchg cl,dl              ;swap and advance colors
                xchg ebx,ebp
                add ebp,dc_fract
                adc dl,BYTE PTR dc_whole

__I_G_pair:     cmp esi,1       
                je __I_G_end            ;if only one pixel left, go draw it

                push esi
                shr esi,1               ;get # of pairs to draw
                dec esi
                mov pixel_cnt,esi       ;set ESI = color delta fraction
                mov esi,dc_fract

                cmp pixel_cnt,4-1
                jl __ig_10

__ig_00:        mov al,BYTE PTR [32768][ecx]
__jg_00:        mov ah,BYTE PTR [32768][edx]
                mov WORD PTR [edi],ax
                add ebx,esi
                adc cl,BYTE PTR dc_whole
                add ebp,esi
                adc dl,BYTE PTR dc_whole
__ig_01:        mov al,BYTE PTR [32768][ecx]
__jg_01:        mov ah,BYTE PTR [32768][edx]
                mov WORD PTR [edi+2],ax
                add ebx,esi
                adc cl,BYTE PTR dc_whole
                add ebp,esi
                adc dl,BYTE PTR dc_whole
__ig_02:        mov al,BYTE PTR [32768][ecx]
__jg_02:        mov ah,BYTE PTR [32768][edx]
                mov WORD PTR [edi+4],ax
                add ebx,esi
                adc cl,BYTE PTR dc_whole
                add ebp,esi
                adc dl,BYTE PTR dc_whole
__ig_03:        mov al,BYTE PTR [32768][ecx]
__jg_03:        mov ah,BYTE PTR [32768][edx]
                mov WORD PTR [edi+6],ax

                add edi,4*2
                sub pixel_cnt,4
                js __I_G_done

                add ebx,esi
                adc cl,BYTE PTR dc_whole
                add ebp,esi
                adc dl,BYTE PTR dc_whole

                cmp pixel_cnt,4-1
                jge __ig_00

__ig_10:        mov al,BYTE PTR [32768][ecx]
__jg_10:        mov ah,BYTE PTR [32768][edx]
                mov WORD PTR [edi],ax
                dec pixel_cnt
                js __I_G_done
                add ebx,esi
                adc cl,BYTE PTR dc_whole
                add ebp,esi
                adc dl,BYTE PTR dc_whole
__ig_11:        mov al,BYTE PTR [32768][ecx]
__jg_11:        mov ah,BYTE PTR [32768][edx]
                mov WORD PTR [edi+2],ax
                dec pixel_cnt
                js __I_G_done
                add ebx,esi
                adc cl,BYTE PTR dc_whole
                add ebp,esi
                adc dl,BYTE PTR dc_whole
__ig_12:        mov al,BYTE PTR [32768][ecx]
__jg_12:        mov ah,BYTE PTR [32768][edx]
                mov WORD PTR [edi+4],ax

__I_G_done:     pop esi
                test esi,1
                jz __I_G_next

                add ebx,dc_fract        ;write single pixel at end of line
                adc cl,BYTE PTR dc_whole

__I_G_end:      mov edi,line_end        
                mov eax,p_translucency
                mov al,[eax][ecx]
                mov [edi],al

__I_G_next:     mov eax,dither_1        ;switch odd/even dither patterns
                mov ebx,dither_2
                mov dither_2,eax
                mov dither_1,ebx
                
                ENDM

                ;
                ;Gouraud-illuminated solid polygon fill
                ;
                ;For each pixel in/under polygon:
                ;
                ;       screen = p_cueing [v[n].c] [color]
                ;

M_GOURAUD_SOLID MACRO

                mov eax,lx
                mov ebx,rx
                mov ecx,lc
                mov edx,rc

                cmp ebx,eax
                jg __M_G_cue_XC

                xchg eax,ebx
                xchg ecx,edx

__M_G_cue_XC:   sar eax,16              ;convert to int, preserving sign
                sar ebx,16

                mov edi,buff_addr
                add edi,eax             ;EDI -> start of line

                sub ebx,eax               
                mov esi,ebx             ;SI = # of pixels in line
                jz __M_G_cue_loop       ;(single-pixel line)

                sub edx,ecx             ;EDX = frc-flc

                sar ebx,1               ;divide dx by 2, rounding up if zero
                cmp ebx,1
                adc ebx,0

                FPDIV ebx               
                shld edx,eax,16         ;EDX:EAX = 2 * color / x (signed)

                mov ebx,esi

__M_G_cue_loop: shl eax,16              ;(x64K so 32-bit adds will roll over)
                
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

                cmp esi,1       
                je __M_G_cue_end        ;if only one pixel left, go draw it

                push esi
                shr esi,1               ;get # of pairs to draw
                dec esi

                ;
                ;Dithered Gouraud solid polygon illumination
                ;

M_GOURAUD       MACRO

                mov edx,color
                mov dh,cl
                add edx,p_cueing
                mov al,[edx]

                mov edx,color
                mov dh,ch
                add edx,p_cueing
                mov ah,[edx]

                mov [edi+INDEX],ax

                add ebx,dc_fract
                adc cl,BYTE PTR dc_whole
                add ebp,dc_fract
                adc ch,BYTE PTR dc_whole

                ENDM

                mov dc_fract,eax
                mov dc_whole,edx

                PARTIAL_UNROLL __GM_unclip_write,M_GOURAUD,6,2,esi

                pop esi
                test esi,1
                jz __M_G_cue_next

__M_G_cue_end:  mov edi,line_end        ;write single pixel at end of line
                mov edx,color
                mov dh,cl
                add edx,p_cueing
                mov al,[edx]
                mov [edi],al

__M_G_cue_next: mov eax,dither_1        ;switch odd/even dither patterns
                mov ebx,dither_2
                mov dither_2,eax
                mov dither_1,ebx
                
                ENDM

                ;
                ;Gouraud-shaded light cueing
                ;
                ;For each pixel in/under polygon:
                ;
                ;       screen = p_cueing [v[n].c] [screen]
                ;

GOURAUD_CUE     MACRO

                mov eax,lx
                mov ebx,rx
                mov ecx,lc
                mov edx,rc

                cmp ebx,eax
                jg __G_cue_XC

                xchg eax,ebx
                xchg ecx,edx

__G_cue_XC:     sar eax,16              ;convert to int, preserving sign
                sar ebx,16

                mov edi,buff_addr
                add edi,eax             ;EDI -> start of line

                sub ebx,eax               
                mov esi,ebx             ;SI = # of pixels in line
                jz __G_cue_loop         ;(single-pixel line)

                sub edx,ecx             ;EDX = frc-flc

                sar ebx,1               ;divide dx by 2, rounding up if zero
                cmp ebx,1
                adc ebx,0

                FPDIV ebx               
                shld edx,eax,16         ;EDX:EAX = 2 * color / x (signed)

                mov ebx,esi

__G_cue_loop:   shl eax,16              ;(x64K so 32-bit adds will roll over)
                
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

                cmp esi,1       
                je __G_cue_end          ;if only one pixel left, go draw it

                push esi
                shr esi,1               ;get # of pairs to draw
                dec esi

                ;
                ;Dithered Gouraud cueing
                ;

D_GOURAUD_CUE   MACRO

                xor edx,edx
                mov dl,[edi+INDEX]
                mov dh,cl
                add edx,p_cueing
                mov al,[edx]

                xor edx,edx
                mov dl,[edi+INDEX+1]
                mov dh,ch
                add edx,p_cueing
                mov ah,[edx]

                mov [edi+INDEX],ax

                add ebx,dc_fract
                adc cl,BYTE PTR dc_whole
                add ebp,dc_fract
                adc ch,BYTE PTR dc_whole

                ENDM

                mov dc_fract,eax
                mov dc_whole,edx

                PARTIAL_UNROLL __GL_unclip_write,D_GOURAUD_CUE,6,2,esi

                pop esi
                test esi,1
                jz __G_cue_next

__G_cue_end:    mov edi,line_end        ;write single pixel at end of line
                xor edx,edx
                mov dl,[edi]
                mov dh,cl
                add edx,p_cueing
                mov al,[edx]
                mov [edi],al

__G_cue_next:   mov eax,dither_1        ;switch odd/even dither patterns
                mov ebx,dither_2
                mov dither_2,eax
                mov dither_1,ebx
                
                ENDM

                ;
                ;Solid flat-shaded polygon setup
                ;

FLAT_SOLID_SETUP MACRO                  ;Replicate polygon color

                IFDEF MASM
                ASSUME ebx:PPOLYVERTEX
                ENDIF

                mov eax,color
                shr eax,16
                mov ah,al
                mov edx,eax
                shl eax,16
                or eax,edx
                mov color,eax

                ENDM

                ;
                ;Solid flat-shaded polygon
                ;

FLAT_SOLID      MACRO
                LOCAL __exit,__L_solid_X

                mov eax,lx
                mov edx,rx

                cmp edx,eax
                jg __L_solid_X

                xchg eax,edx

__L_solid_X:    sar eax,16              ;EAX = left endpoint (preserve sign)
                sar edx,16              ;EDX = right endpoint (preserve sign)

                mov ecx,edx
                sub ecx,eax
                inc ecx                 ;ECX = # of pixels in line

                mov edi,buff_addr
                add edi,eax             ;EDI -> start of line

                mov eax,color

                REP_STOS

                ENDM

                ;
                ;Flat (Lambert) translation
                ;

FLAT_CUE        MACRO
                LOCAL __L_cue_X,__chk_pairs,__TS,__write_end,__next_line

                mov eax,lx
                mov ebx,rx

                cmp ebx,eax             ;sort X left-to-right
                jg __L_cue_X

                xchg eax,ebx

__L_cue_X:      sar eax,16              ;(preserve sign)
                sar ebx,16              ;(preserve sign)

                sub ebx,eax             ;EBX = # of pixels in line - 1

                mov edi,buff_addr
                add edi,eax             ;EDI -> start of line

                mov eax,ebx
                add eax,edi
                mov line_end,eax        ;EAX -> end of line

                xor eax,eax             ;EAX = 0
                mov esi,p_cueing        ;ESI = pointer to lookaside table

                inc ebx                 ;EBX = # of pixels in line

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

                PARTIAL_UNROLL __TS,TRANSLATE_PAIR,6,2,ebx

                pop ebx
                test ebx,1
                jz __next_line

__write_end:    mov edi,line_end        ;write single pixel at end of line
                mov al,BYTE PTR [edi]
                mov dl,BYTE PTR [esi][eax]
                mov BYTE PTR [edi],dl

__next_line:
                ENDM

                ;
                ;Texture mapping setup
                ;

TEXTURE_SETUP   MACRO

                IFDEF MASM
                ASSUME ebx:PVFXTXT
                ENDIF

                mov ebx,p_texture

                ;
                ;Set V-baseline table address operands
                ;

                mov eax,[ebx].v_addrs

                cmp DWORD PTR es:__V_addr_00+3,eax
                je __end_set_V

                mov DWORD PTR es:__V_addr_00+3,eax        
                mov DWORD PTR es:__V_addr_01+3,eax
                mov DWORD PTR es:__V_addr_02+3,eax
                mov DWORD PTR es:__V_addr_03+3,eax

                IF SMP EQ SMP_FINE
                mov DWORD PTR es:__V_addr_04+3,eax
                mov DWORD PTR es:__V_addr_05+3,eax
                mov DWORD PTR es:__V_addr_06+3,eax
                mov DWORD PTR es:__V_addr_07+3,eax
                ENDIF

                mov DWORD PTR es:__V_addr_08+3,eax

                mov DWORD PTR es:__V_addr_11+3,eax
                mov DWORD PTR es:__V_addr_12+3,eax
                mov DWORD PTR es:__V_addr_13+3,eax
                mov DWORD PTR es:__V_addr_14+3,eax
                mov DWORD PTR es:__V_addr_15+3,eax
                mov DWORD PTR es:__V_addr_16+3,eax
__end_set_V:

                ;
                ;Set tile limits, if used
                ;

                IF TIL EQ TIL_LIN

                mov eax,[ebx].txt_width
                mov U_tile,eax
                mov eax,[ebx].txt_height
                mov V_tile,eax

                ELSEIF TIL EQ TIL_LOG

                mov eax,[ebx].txt_width
                dec eax
                mov U_tile,eax
                mov eax,[ebx].txt_height
                dec eax
                mov V_tile,eax

                ENDIF

                ;
                ;Set flat color, if used
                ;

                IF XP EQ XP_FLAT

                IFDEF MASM
                ASSUME ebx:PPOLYVERTEX
                ENDIF

                mov ebx,vlist_beg
                mov eax,[ebx].vc        
                shr eax,16
                mov BYTE PTR xp_color,al

                ELSEIF XP EQ XP_XLUCENT

                ;
                ;Set translucent table address operands, if used
                ;

                mov eax,p_translucency

                cmp DWORD PTR es:__xl_00+2,eax
                je __end_set_xl

                mov DWORD PTR es:__xl_00+2,eax        
                mov DWORD PTR es:__xl_01+2,eax
                mov DWORD PTR es:__xl_02+2,eax
                mov DWORD PTR es:__xl_03+2,eax

                IF SMP EQ SMP_FINE
                mov DWORD PTR es:__xl_04+2,eax
                mov DWORD PTR es:__xl_05+2,eax
                mov DWORD PTR es:__xl_06+2,eax
                mov DWORD PTR es:__xl_07+2,eax
                ENDIF

                mov DWORD PTR es:__xl_08+2,eax

                mov DWORD PTR es:__xl_11+2,eax
                mov DWORD PTR es:__xl_12+2,eax
                mov DWORD PTR es:__xl_13+2,eax
                mov DWORD PTR es:__xl_14+2,eax
                mov DWORD PTR es:__xl_15+2,eax
                mov DWORD PTR es:__xl_16+2,eax
__end_set_xl:                
                ENDIF

                ;
                ;Set flat lookaside table address operands, if used
                ;

                IF SHD EQ SHD_FLAT

                mov eax,p_cueing

                cmp DWORD PTR es:__fs_00+2,eax
                je __end_set_fs

                mov DWORD PTR es:__fs_00+2,eax        
                mov DWORD PTR es:__fs_01+2,eax
                mov DWORD PTR es:__fs_02+2,eax
                mov DWORD PTR es:__fs_03+2,eax

                IF SMP EQ SMP_FINE
                mov DWORD PTR es:__fs_04+2,eax
                mov DWORD PTR es:__fs_05+2,eax
                mov DWORD PTR es:__fs_06+2,eax
                mov DWORD PTR es:__fs_07+2,eax
                ENDIF

                mov DWORD PTR es:__fs_08+2,eax

                mov DWORD PTR es:__fs_11+2,eax
                mov DWORD PTR es:__fs_12+2,eax
                mov DWORD PTR es:__fs_13+2,eax
                mov DWORD PTR es:__fs_14+2,eax
                mov DWORD PTR es:__fs_15+2,eax
                mov DWORD PTR es:__fs_16+2,eax
__end_set_fs:
                ENDIF

                ENDM

                ;
                ;Get address of pixel to fetch from texture map, given 
                ;EDX==U and ECX==V
                ;
                ;Returns [EBX] if tiling used, else [EAX][EDX]
                ;

TEXTURE_INDEX   MACRO Num

                IF TIL EQ TIL_LOG

                mov eax,ecx
                mov ebx,edx

                and eax,V_tile
                and ebx,U_tile
__V_addr_&Num&: add ebx,[-1][eax*4]

                ELSEIF TIL EQ TIL_LIN

                mov eax,ecx
                mov ebx,edx

__V_test_&Num&: cmp eax,V_tile
                jae __V_limit_&Num&
__U_test_&Num&: cmp ebx,U_tile
                jae __U_limit_&Num&
__V_addr_&Num&: add ebx,[-1][eax*4]

                ELSE

__V_addr_&Num&: mov eax,[-1][ecx*4]

                ENDIF

                ENDM

                ;
                ;Handle pixel transparency and flat (Lambert) shading
                ;
                ;AL = pixel value; __skip = local label after pixel write
                ;
                ;Destroys EBX if flat shading or translucency enabled
                ;

TEXTURE_XP      MACRO Lbl,Dest,Num
                LOCAL __draw

                IF SHD EQ SHD_FLAT

                xor ebx,ebx
                mov bl,al
__fs_&Num&:     mov al,[-32768][ebx]

                ENDIF

                IF (XP EQ XP_SKIP) OR (XP EQ XP_R_GOURAUD) OR (XP EQ XP_I_GOURAUD)

                cmp al,XCOLOR
                je Lbl

                ELSEIF XP EQ XP_FLAT

                cmp al,XCOLOR
                jne __draw
                mov al,BYTE PTR xp_color

                ELSEIF XP EQ XP_XLUCENT

                cmp al,XCOLOR
                jne __draw

                IF SHD NE SHD_FLAT
                xor ebx,ebx                     ;already 0 if flat shading on
                ENDIF

                IF SMP EQ SMP_FINE
                mov bl,[edi+Dest]
                ELSE
                mov bl,[edi+(Dest SHL 1)]
                ENDIF

__xl_&Num&:     mov al,[-32768][ebx]

                ENDIF
__draw:
                ENDM

                ;
                ;Copy pixel from source texture map to output buffer
                ;

TEXTURE_COPY    MACRO Dest,Num
                LOCAL __skip,__skip_2

                IF SMP EQ SMP_FINE

                ;
                ;Normal sampling
                ;

                IF (TIL EQ 0) AND (SHD NE SHD_FLAT) AND (XP NE XP_XLUCENT)
                add ebp,ebx
                ELSE
                add ebp,dv_fract        ;V += DV fraction
                ENDIF

                IF TIL EQ 0
                mov al,[eax][edx]
                ELSE
                mov al,[ebx]
                ENDIF

                adc ecx,dv_whole        ;V += DV whole   

                TEXTURE_XP __skip,Dest,Num

                mov [edi+Dest],al

__skip:         add esi,du_fract        ;U += DU fraction
                adc edx,du_whole        ;U += DU whole   

                ELSE

                ;
                ;Subsampling
                ;

                IF (TIL EQ 0) AND (SHD NE SHD_FLAT) AND (XP NE XP_XLUCENT)
                add ebp,ebx
                ELSE
                add ebp,dv_fract_x2     ;V += DV fraction
                ENDIF

                IF TIL EQ 0
                mov al,[eax][edx]
                ELSE
                mov al,[ebx]
                ENDIF

                adc ecx,dv_whole_x2     ;V += DV whole   

                TEXTURE_XP __skip_2,Dest,Num

                mov ah,al
                mov [edi+(Dest SHL 1)],ax

__skip_2:       add esi,du_fract_x2     ;U += DU fraction
                adc edx,du_whole_x2     ;U += DU whole   

                ENDIF

                ENDM

                ;
                ;Affine texture mapping
                ;

AFFINE_MAP      MACRO

                mov eax,lx
                mov ebx,rx
                mov ecx,lu
                mov edx,ru
                mov esi,lv
                mov edi,rv

                cmp ebx,eax             ;sort X, U, and V left-to-right
                jg __XUV_sorted

                xchg eax,ebx            ;exchange LX, RX
                xchg ecx,edx            ;exchange LU, RU
                xchg esi,edi            ;exchange LV, RV

__XUV_sorted:   sar eax,16              ;(preserve sign)  
                sar ebx,16              ;(preserve sign)

                push ecx                ;push init U
                push esi                ;push init V

                push eax                ;push init X

                sub ebx,eax             ;EBX = # of pixels in scanline - 1
                inc ebx                 ;set EBX = # of pixels in scanline
                mov iterations,ebx

                sub edx,ecx             ;EDX = ru-lu
                FPDIV ebx
                mov ecx,eax             ;ECX = du = (ru-lu) / (rx-lx)

                sub edi,esi             ;EDI = rv-lv
                mov edx,edi
                FIXDIV ebx              ;EAX = dv = (rv-lv) / (rx-lx)

                mov ebx,eax

                pop edi                 ;restore init X
                add edi,buff_addr       ;set EDI -> beginning of dest scanline

                mov eax,ecx             ;convert DU to 32:32 (ECX->EAX:ECX)
                mov edx,ebx             ;convert DV to 32:32 (EBX->EDX:EBX)
                sar eax,16              
                sar edx,16              
                shl ecx,16
                shl ebx,16
                mov du_fract,ecx
                mov du_whole,eax
                mov dv_fract,ebx
                mov dv_whole,edx

                IF SMP EQ SMP_COARSE

                shl ecx,1
                rcl eax,1
                shl ebx,1
                rcl edx,1
                mov du_fract_x2,ecx
                mov du_whole_x2,eax
                mov dv_fract_x2,ebx
                mov dv_whole_x2,edx

                ENDIF

                pop ebp                 ;restore init V
                pop esi                 ;restore init U

                IF ROUND_UV
                add ebp,8000h           ;round to center of pixel
                add esi,8000h           ;round to center of pixel
                ENDIF

                mov edx,esi             ;convert U to 32:32 (ESI->EDX:ESI)
                mov ecx,ebp             ;convert V to 32:32 (EBP->ECX:EBP)
                shr edx,16
                shr ecx,16
                shl esi,16
                shl ebp,16

                TEXTURE_INDEX 00

                cmp iterations,8
                jl __do_remainder

                ;
                ;EAX = texture base address for initial V value
                ;
                ;EDI = scanline address for first pixel
                ;
                ;EDX:ESI = 64-bit U
                ;ECX:EBP = 64-bit V
                ;
                ;     EBX:du_fract = 64-bit DU/DX
                ;dv_whole:dv_fract = 64-bit DV/DX
                ;
                ;Upper 16 bits of EDX and ECX = 0
                ;

__unroll_loop:  TEXTURE_COPY  00,00

                TEXTURE_INDEX 01
                TEXTURE_COPY  01,01

                TEXTURE_INDEX 02
                TEXTURE_COPY  02,02

                TEXTURE_INDEX 03
                TEXTURE_COPY  03,03

                IF SMP EQ SMP_FINE

                TEXTURE_INDEX 04
                TEXTURE_COPY  04,04

                TEXTURE_INDEX 05
                TEXTURE_COPY  05,05

                TEXTURE_INDEX 06
                TEXTURE_COPY  06,06

                TEXTURE_INDEX 07
                TEXTURE_COPY  07,07

                ENDIF

                TEXTURE_INDEX 08

                add edi,8               ;add 8 pixels to output
                sub iterations,8
                jz __next_line
                cmp iterations,8
                jge __unroll_loop

__do_remainder:         
                TEMP = OP               ;turn subsampling off for remainder
                OP = OP AND (NOT SMP_COARSE)     

                TEXTURE_COPY  00,08

                dec iterations
                jz __next_line

                TEXTURE_INDEX 11
                TEXTURE_COPY  01,11

                dec iterations
                jz __next_line

                TEXTURE_INDEX 12
                TEXTURE_COPY  02,12

                dec iterations
                jz __next_line

                TEXTURE_INDEX 13
                TEXTURE_COPY  03,13

                dec iterations
                jz __next_line

                TEXTURE_INDEX 14
                TEXTURE_COPY  04,14

                dec iterations
                jz __next_line

                TEXTURE_INDEX 15
                TEXTURE_COPY  05,15

                dec iterations
                jz __next_line

                TEXTURE_INDEX 16
                TEXTURE_COPY  06,16

                OP = TEMP

                jmp __next_line

                IF TIL EQ TIL_LIN

__V_limit_00:   sub eax,V_tile
                jmp __V_test_00
__U_limit_00:   sub ebx,U_tile
                jmp __U_test_00

__V_limit_01:   sub eax,V_tile
                jmp __V_test_01
__U_limit_01:   sub ebx,U_tile
                jmp __U_test_01

__V_limit_02:   sub eax,V_tile
                jmp __V_test_02
__U_limit_02:   sub ebx,U_tile
                jmp __U_test_02

__V_limit_03:   sub eax,V_tile
                jmp __V_test_03
__U_limit_03:   sub ebx,U_tile
                jmp __U_test_03

                IF SMP EQ SMP_FINE

__V_limit_04:   sub eax,V_tile
                jmp __V_test_04
__U_limit_04:   sub ebx,U_tile
                jmp __U_test_04

__V_limit_05:   sub eax,V_tile
                jmp __V_test_05
__U_limit_05:   sub ebx,U_tile
                jmp __U_test_05

__V_limit_06:   sub eax,V_tile
                jmp __V_test_06
__U_limit_06:   sub ebx,U_tile
                jmp __U_test_06

__V_limit_07:   sub eax,V_tile
                jmp __V_test_07
__U_limit_07:   sub ebx,U_tile
                jmp __U_test_07

                ENDIF

__V_limit_08:   sub eax,V_tile
                jmp __V_test_08
__U_limit_08:   sub ebx,U_tile
                jmp __U_test_08

__V_limit_11:   sub eax,V_tile
                jmp __V_test_11
__U_limit_11:   sub ebx,U_tile
                jmp __U_test_11

__V_limit_12:   sub eax,V_tile
                jmp __V_test_12
__U_limit_12:   sub ebx,U_tile
                jmp __U_test_12

__V_limit_13:   sub eax,V_tile
                jmp __V_test_13
__U_limit_13:   sub ebx,U_tile
                jmp __U_test_13

__V_limit_14:   sub eax,V_tile
                jmp __V_test_14
__U_limit_14:   sub ebx,U_tile
                jmp __U_test_14

__V_limit_15:   sub eax,V_tile
                jmp __V_test_15
__U_limit_15:   sub ebx,U_tile
                jmp __U_test_15

__V_limit_16:   sub eax,V_tile
                jmp __V_test_16
__U_limit_16:   sub ebx,U_tile
                jmp __U_test_16

                ENDIF

__next_line:
                ENDM

                ;
                ;Perspective texture mapping
                ;

PERSPECTIVE_MAP MACRO

                mov eax,lx
                mov ebx,rx
                mov ecx,lu
                mov edx,ru
                mov esi,lw              
                mov edi,rw

                cmp ebx,eax             ;sort X, U, V, and W left-to-right
                jg __XUV_sorted

                xchg eax,ebx            ;exchange LX, RX
                xchg ecx,edx            ;exchange LU, RU

                mov flw,edi             ;exchange LW, RW
                mov frw,esi             

                mov edi,lv              ;exchange LV, RV
                mov esi,rv

                jmp __XUV_sorted_2

__XUV_sorted:   mov flw,esi             ;load LW
                mov frw,edi             ;load RW        

                mov edi,rv              ;load LV
                mov esi,lv              ;load RV

__XUV_sorted_2: sar eax,16              ;(preserve sign)  
                sar ebx,16              ;(preserve sign)

                mov plx,eax
                mov prx,ebx

                mov flu,ecx             ;save left source X (U)
                mov fru,edx             ;save right source X (U)

                mov flv,esi             ;save left source Y (V)
                mov frv,edi             ;save right source Y (V)

                sub ebx,eax             ;EBX = # of pixels in scanline - 1
                inc ebx                 ;set EBX = # of pixels in scanline
                mov pixel_cnt,ebx

                sub edx,ecx             ;EDX = ru-lu
                FPDIV ebx
                sal eax,4
                mov du,eax              ;du = (ru-lu) / (rx-lx) << sv

                sub edi,esi             ;EDI = rv-lv
                mov edx,edi
                FIXDIV ebx
                sal eax,4
                mov dv,eax              ;dv = (rv-lv) / (rx-lx) << sv

                mov edx,frw
                sub edx,flw             ;EDX = rw-lw
                FIXDIV ebx
                sal eax,4
                mov pdw,eax             ;dw = (rw-lw) / (rx-lx) << sv

                mov edx,flu             ;ut = fixed_div_one(lu, lw)        
                FPDIVONE flw
                IF ROUND_UV
                add eax,8000h           ;round to center of pixel
                ENDIF
                mov ut,eax              

                mov edx,flv             ;vt = fixed_div_one(lv, lw)
                FPDIVONE flw
                IF ROUND_UV
                add eax,8000h           ;round to center of pixel
                ENDIF
                mov vt,eax              

                mov eax,plx
                mov edi,buff_addr
                add edi,eax             ;set EDI -> beginning of dest scanline

                mov ebx,pixel_cnt       ;loops = (prx - plx) >> sv
                shr ebx,4
                mov loops,ebx

                jz __last_segment       ;segment < subdivision width, do short

__whole_seg:    mov eax,flu             ;u += du
                add eax,du
                mov flu,eax

                mov eax,flv             ;u += dv
                add eax,dv
                mov flv,eax

                mov eax,flw             ;w += dw
                add eax,pdw
                mov flw,eax

                mov ebx,16
                mov iterations,ebx

                mov edx,flv             ;v1 = fixed_div_one(v, w)
                FPDIVONE flw
                IF ROUND_UV
                add eax,8000h           ;round to center of pixel
                ENDIF
                sub eax,vt              ;dv = (v1-vt) >> sv
                sar eax,4
                mov esi,eax

                mov edx,flu             ;u1 = fixed_div_one(u, w)
                FPDIVONE flw
                IF ROUND_UV
                add eax,8000h           ;round to center of pixel
                ENDIF
                sub eax,ut              ;du = (u1-ut) >> sv
                sar eax,4

                mov ebx,esi             ;set dv
                mov ecx,eax             ;set du

                ;
                ;ECX = segment DU 16:16
                ;EBX = segment DV 16:16
                ;
                ;[UT] = segment start U 16:16
                ;[VT] = segment start V 16:16
                ;
                ;EDI = scanline address for first pixel
                ;[iterations] = # of pixels to write
                ;

__do_loop:      mov edx,ecx              ;convert DU to 32:32 (ECX->EDX:ECX)
                mov eax,ebx              ;convert DV to 32:32 (EBX->EAX:EBX)
                sar edx,16
                sar eax,16
                shl ecx,16
                shl ebx,16
                mov du_fract,ecx
                mov du_whole,edx
                mov dv_fract,ebx
                mov dv_whole,eax

                IF SMP EQ SMP_COARSE

                shl ecx,1
                rcl edx,1
                shl ebx,1
                rcl eax,1
                mov du_fract_x2,ecx
                mov du_whole_x2,edx
                mov dv_fract_x2,ebx
                mov dv_whole_x2,eax

                ENDIF

                mov esi,ut              
                mov ebp,vt              

                mov edx,esi             ;convert U to 32:32 (ESI->EDX:ESI)
                mov ecx,ebp             ;convert V to 32:32 (EBP->ECX:EBP)
                shr edx,16
                shr ecx,16
                shl esi,16
                shl ebp,16

                TEXTURE_INDEX 00

                cmp iterations,8
                jl __do_remainder

                ;
                ;EAX = texture base address for initial V value
                ;
                ;EDI = scanline address for first pixel
                ;
                ;EDX:ESI = 64-bit U
                ;ECX:EBP = 64-bit V
                ;
                ;     EBX:du_fract = 64-bit DU/DX
                ;dv_whole:dv_fract = 64-bit DV/DX
                ;
                ;Upper 16 bits of EDX and ECX = 0
                ;

__unroll_loop:  TEXTURE_COPY  00,00

                TEXTURE_INDEX 01
                TEXTURE_COPY  01,01

                TEXTURE_INDEX 02
                TEXTURE_COPY  02,02

                TEXTURE_INDEX 03
                TEXTURE_COPY  03,03

                IF SMP EQ SMP_FINE

                TEXTURE_INDEX 04
                TEXTURE_COPY  04,04

                TEXTURE_INDEX 05
                TEXTURE_COPY  05,05

                TEXTURE_INDEX 06
                TEXTURE_COPY  06,06

                TEXTURE_INDEX 07
                TEXTURE_COPY  07,07

                ENDIF

                TEXTURE_INDEX 08

                add edi,8               ;add 8 pixels to output
                sub iterations,8
                jz __end_unroll
                cmp iterations,8
                jge __unroll_loop

__do_remainder: 
                TEMP = OP               ;turn subsampling off for remainder
                OP = OP AND (NOT SMP_COARSE)     

                TEXTURE_COPY  00,08

                dec iterations
                jz __end_unroll

                TEXTURE_INDEX 11
                TEXTURE_COPY  01,11

                dec iterations
                jz __end_unroll

                TEXTURE_INDEX 12
                TEXTURE_COPY  02,12

                dec iterations
                jz __end_unroll

                TEXTURE_INDEX 13
                TEXTURE_COPY  03,13

                dec iterations
                jz __end_unroll

                TEXTURE_INDEX 14
                TEXTURE_COPY  04,14

                dec iterations
                jz __end_unroll

                TEXTURE_INDEX 15
                TEXTURE_COPY  05,15

                dec iterations
                jz __end_unroll

                TEXTURE_INDEX 16
                TEXTURE_COPY  06,16

                OP = TEMP

__end_unroll:   shrd esi,edx,16         ;end of affine run, update U and V
                shrd ebp,ecx,16

                mov ut,esi
                mov vt,ebp

                mov eax,loops
                dec eax
                js __next_line
                mov loops,eax
                jnz __whole_seg

__last_segment: mov ebx,pixel_cnt       ;pixel count = px & ((1 << sv) - 1);
                and ebx,15
                jz __next_line          ;skip if no pixels left

                mov iterations,ebx

                mov edx,fru             ;u1 = fixed_div_one(ru, rw)
                FPDIVONE frw
                IF ROUND_UV
                add eax,8000h           ;round to center of pixel
                ENDIF
                sub eax,ut              ;du = (u1-ut) / xc
                mov edx,eax
                FPDIV ebx
                mov ecx,eax             ;set DU

                mov edx,frv             ;v1 = fixed_div_one(rv, rw)
                FPDIVONE frw
                IF ROUND_UV
                add eax,8000h           ;round to center of pixel
                ENDIF
                sub eax,vt              ;dv = (v1-vt) / xc
                mov edx,eax
                FIXDIV ebx
                mov ebx,eax             ;set DV

                jmp __do_loop           ;do last segment

                IF TIL EQ TIL_LIN

__V_limit_00:   sub eax,V_tile
                jmp __V_test_00
__U_limit_00:   sub ebx,U_tile
                jmp __U_test_00

__V_limit_01:   sub eax,V_tile
                jmp __V_test_01
__U_limit_01:   sub ebx,U_tile
                jmp __U_test_01

__V_limit_02:   sub eax,V_tile
                jmp __V_test_02
__U_limit_02:   sub ebx,U_tile
                jmp __U_test_02

__V_limit_03:   sub eax,V_tile
                jmp __V_test_03
__U_limit_03:   sub ebx,U_tile
                jmp __U_test_03

                IF SMP EQ SMP_FINE

__V_limit_04:   sub eax,V_tile
                jmp __V_test_04
__U_limit_04:   sub ebx,U_tile
                jmp __U_test_04

__V_limit_05:   sub eax,V_tile
                jmp __V_test_05
__U_limit_05:   sub ebx,U_tile
                jmp __U_test_05

__V_limit_06:   sub eax,V_tile
                jmp __V_test_06
__U_limit_06:   sub ebx,U_tile
                jmp __U_test_06

__V_limit_07:   sub eax,V_tile
                jmp __V_test_07
__U_limit_07:   sub ebx,U_tile
                jmp __U_test_07

                ENDIF

__V_limit_08:   sub eax,V_tile
                jmp __V_test_08
__U_limit_08:   sub ebx,U_tile
                jmp __U_test_08

__V_limit_11:   sub eax,V_tile
                jmp __V_test_11
__U_limit_11:   sub ebx,U_tile
                jmp __U_test_11

__V_limit_12:   sub eax,V_tile
                jmp __V_test_12
__U_limit_12:   sub ebx,U_tile
                jmp __U_test_12

__V_limit_13:   sub eax,V_tile
                jmp __V_test_13
__U_limit_13:   sub ebx,U_tile
                jmp __U_test_13

__V_limit_14:   sub eax,V_tile
                jmp __V_test_14
__U_limit_14:   sub ebx,U_tile
                jmp __U_test_14

__V_limit_15:   sub eax,V_tile
                jmp __V_test_15
__U_limit_15:   sub ebx,U_tile
                jmp __U_test_15

__V_limit_16:   sub eax,V_tile
                jmp __V_test_16
__U_limit_16:   sub ebx,U_tile
                jmp __U_test_16

                ENDIF

__next_line:
                ENDM

;лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
;лл                                                                        лл
;лл Polygon scan conversion                                                лл
;лл                                                                        лл
;лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

                ;
                ;Perform d/dy calculations for left scanline edges
                ;
                ;Expects ECX = edge size in Y
                ;

LEFT_DELTAS     MACRO

                mov lcnt,ecx            ;set left edge pixel count
                shl ecx,16

                mov edi,[ebx].vx
                mov edx,[esi].vx        ;get size of edge in X
                sub edx,edi
                shl edx,16
                FIXDIV ecx              ;divide by pixel count
                mov ldx,eax             ;set left DX
                shl edi,16
                add edi,8000h
                mov lx,edi
                
                IF USE_C

                mov edi,[ebx].vc
                mov edx,[esi].vc        ;get size of edge in C
                sub edx,edi
                FIXDIV ecx              ;divide by pixel count
                mov ldc,eax             ;set left DC
                mov lc,edi              
                ENDIF

                IF USE_U

                mov edi,[ebx].u
                mov edx,[esi].u         ;get size of edge in U
                sub edx,edi
                FIXDIV ecx              ;divide by pixel count
                mov ldu,eax             ;set left DU
                mov lu,edi              
                ENDIF

                IF USE_V

                mov edi,[ebx].v
                mov edx,[esi].v         ;get size of edge in V
                sub edx,edi
                FIXDIV ecx              ;divide by pixel count
                mov ldv,eax             ;set left DV
                mov lv,edi              
                ENDIF

                IF USE_W

                mov edi,[ebx].w
                mov edx,[esi].w         ;get size of edge in W
                sub edx,edi
                FIXDIV ecx              ;divide by pixel count
                mov ldw,eax             ;set left DW
                mov lw,edi              
                ENDIF

                ENDM

                ;
                ;Perform d/dy calculations for right scanline edges
                ;
                ;Expects ECX = edge size in Y
                ;

RIGHT_DELTAS    MACRO

                mov rcnt,ecx            ;set right edge pixel count
                shl ecx,16

                mov edi,[ebx].vx
                mov edx,[esi].vx        ;get size of edge in X
                sub edx,edi
                shl edx,16
                FIXDIV ecx              ;divide by pixel count
                mov rdx,eax             ;set right DX
                shl edi,16
                add edi,8000h
                mov rx,edi

                IF USE_C

                mov edi,[ebx].vc
                mov edx,[esi].vc        ;get size of edge in C
                sub edx,edi
                FIXDIV ecx              ;divide by pixel count
                mov rdc,eax             ;set right DC
                mov rc,edi
                ENDIF

                IF USE_U

                mov edi,[ebx].u
                mov edx,[esi].u         ;get size of edge in U
                sub edx,edi
                FIXDIV ecx              ;divide by pixel count
                mov rdu,eax             ;set right DU
                mov ru,edi
                ENDIF

                IF USE_V

                mov edi,[ebx].v
                mov edx,[esi].v         ;get size of edge in V
                sub edx,edi
                FIXDIV ecx              ;divide by pixel count
                mov rdv,eax             ;set right DV
                mov rv,edi
                ENDIF

                IF USE_W

                mov edi,[ebx].w
                mov edx,[esi].w         ;get size of edge in W
                sub edx,edi
                FIXDIV ecx              ;divide by pixel count
                mov rdw,eax             ;set right DW
                mov rw,edi
                ENDIF

                ENDM

                ;
                ;Step left edge variables
                ;

LEFT_TRACE      MACRO

                mov eax,ldx
                add lx,eax

                IF USE_C

                mov eax,ldc
                add lc,eax
                ENDIF

                IF USE_U

                mov eax,ldu
                add lu,eax
                ENDIF

                IF USE_V

                mov eax,ldv
                add lv,eax
                ENDIF

                IF USE_W

                mov eax,ldw
                add lw,eax
                ENDIF

                ENDM

                ;
                ;Step right edge variables
                ;

RIGHT_TRACE     MACRO

                mov eax,rdx
                add rx,eax

                IF USE_C

                mov eax,rdc
                add rc,eax
                ENDIF

                IF USE_U

                mov eax,rdu
                add ru,eax
                ENDIF

                IF USE_V

                mov eax,rdv
                add rv,eax
                ENDIF

                IF USE_W

                mov eax,rdw
                add rw,eax
                ENDIF

                ENDM

                ;
                ;Macro used to construct scan converters
                ;
                ;USE_C to interpolate C
                ;USE_U to interpolate U
                ;USE_V to interpolate V
                ;USE_W to interpolate W
                ;
                ;Needs: line_size = # of bytes/output scanline
                ;       buff_addr = output buffer
                ;       vlist_beg = pointer to start of vertex list
                ;       vlist_end = pointer to end of vertex list
                ;       VList     = list of polygon vertices
                ;       VCnt      = # of polygon vertices
                ;

SCAN_CONVERT    MACRO
                LOCAL __vertex_sort,__not_top,__not_btm
                LOCAL __init_left,__init_lnxt
                LOCAL __init_right,__init_rnxt
                LOCAL __do_scanline,__right_edge,__last_line
                LOCAL __step_left,__step_lnxt,__l_slopes,__l_flat
                LOCAL __step_right,__step_rnxt,__r_slopes,__r_flat
                LOCAL __exit

                push ebp                ;save stack frame pointer

                ;
                ;Perform optional scanline loop setup
                ;

                SETUP_1
                SETUP_2
                SETUP_3

                ;
                ;Find top and bottom vertices
                ;

                IFDEF MASM
                ASSUME ebx:PPOLYVERTEX
                ASSUME esi:PPOLYVERTEX
                ENDIF

                mov ebx,vlist_beg

                mov esi,07fffffffh      ;ESI = top vertex Y
                mov edi,080000000h      ;EDI = bottom vertex Y

__vertex_sort:  mov eax,[ebx].vy

                cmp eax,esi             ;keep track of top and bottom vertices
                jg __not_top
                mov esi,eax
                mov ecx,ebx

__not_top:      cmp eax,edi
                jl __not_btm
                mov edi,eax

__not_btm:      add ebx,SIZE POLYVERTEX
                cmp ebx,vlist_end
                jne __vertex_sort

                mov lnxt,ecx            ;init right, left vertices = top
                mov rnxt,ecx

                mov y,esi               ;init scanline Y = top vertex Y

                sub edi,esi             ;is polygon flat?
                je __exit               ;yes, don't draw it

                mov line_cnt,edi        ;else store integer scanline height-1

                ;
                ;Calculate initial edge positions & stepping vals for
                ;left edge
                ;

__init_left:    mov ebx,lnxt            ;EBX -> vertex at top of edge

                mov esi,ebx
                sub esi,SIZE POLYVERTEX
                cmp esi,vlist_beg
                jge __init_lnxt
                mov esi,vlist_end
                sub esi,SIZE POLYVERTEX
__init_lnxt:    mov lnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov eax,[ebx].vy        ;EAX = edge top Y
                mov ecx,[esi].vy        ;ECX = edge bottom Y

                sub ecx,eax             ;is edge flat?
                jz __init_left          ;yes, advance one edge left

                LEFT_DELTAS             ;calculate slopes

                ;
                ;Calculate initial edge positions & stepping vals for
                ;right edge
                ;

__init_right:   mov ebx,rnxt            ;EBX -> vertex at top of edge

                mov esi,ebx
                add esi,SIZE POLYVERTEX
                cmp esi,vlist_end
                jl __init_rnxt
                mov esi,vlist_beg
__init_rnxt:    mov rnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov eax,[ebx].vy        ;EAX = edge top Y
                mov ecx,[esi].vy        ;ECX = edge bottom Y

                sub ecx,eax             ;is edge flat?
                jz __init_right         ;yes, advance one edge left

                RIGHT_DELTAS            ;calculate slopes

                ;
                ;Set window base address and loop variables
                ;

                mov eax,y               ;truncate Y to integer
                mul line_size
                add buff_addr,eax

                ;
                ;Trace edges & plot scanlines
                ;
                
__do_scanline:  PASS_1                  ;First rendering pass
                PASS_2                  ;Second rendering pass (optional)
                PASS_3                  ;Third rendering pass (optional)

                ;
                ;Step one line down in Y; exit if no more scanlines
                ;

                mov eax,line_size
                add buff_addr,eax

                dec line_cnt
                js __exit
                jz __last_line

                ;
                ;Calculate new variables for both edges, stepping across
                ;vertices when necessary to find next scanline
                ;

                dec lcnt
                jz __step_left

                LEFT_TRACE

__right_edge:   dec rcnt
                jz __step_right

                RIGHT_TRACE

                jmp __do_scanline

                ;
                ;Do last line without switching edges
                ;

__last_line:    LEFT_TRACE

                RIGHT_TRACE

                jmp __do_scanline

                ;
                ;Step across left edge vertex
                ;

__step_left:    mov ebx,lnxt            ;EBX -> vertex at top of edge

                mov esi,ebx
                sub esi,SIZE POLYVERTEX
                cmp esi,vlist_beg
                jge __step_lnxt
                mov esi,vlist_end
                sub esi,SIZE POLYVERTEX
__step_lnxt:    mov lnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov eax,[ebx].vy        ;EAX = edge top Y
                mov ecx,[esi].vy        ;ECX = edge bottom Y

                sub ecx,eax             ;is edge flat?
                cmp ecx,1               ;(possible only at bottom scan line)
                adc ecx,0

                LEFT_DELTAS             ;calculate slopes
                jmp __right_edge

                ;
                ;Step across right edge vertex
                ;

__step_right:   mov ebx,rnxt            ;EBX -> vertex at top of edge

                mov esi,ebx
                add esi,SIZE POLYVERTEX
                cmp esi,vlist_end
                jl __step_rnxt
                mov esi,vlist_beg
__step_rnxt:    mov rnxt,esi            ;ESI -> vertex at bottom (end) of edge

                mov eax,[ebx].vy        ;EAX = edge top Y
                mov ecx,[esi].vy        ;ECX = edge bottom Y

                sub ecx,eax             ;is edge flat?
                cmp ecx,1               ;(possible only at bottom scan line)
                adc ecx,0

                RIGHT_DELTAS            ;calculate slopes
                jmp __do_scanline

                ;
                ;Restore stack frame and exit
                ;

__exit:         pop ebp

                ENDM

;лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
;лл                                                                        лл
;лл Primitive construction macros                                          лл
;лл                                                                        лл
;лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

MAKE_POLY       MACRO Flg
poly_&Flg&      PROC

                ;
                ;Clear flags and macros
                ;

                USE_U   = 0
                USE_V   = 0
                USE_C   = 0
                USE_W   = 0

                SETUP_1 equ <>
                SETUP_2 equ <>
                SETUP_3 equ <>
                PASS_1  equ <>
                PASS_2  equ <>
                PASS_3  equ <>

                ;
                ;Assemble perspective texture mapping
                ;

                IF (MAP EQ MAP_PERSPECT)
                
                SETUP_2 equ <TEXTURE_SETUP>
                PASS_2  equ <PERSPECTIVE_MAP>

                USE_U = 1
                USE_V = 1
                USE_W = 1

                ENDIF

                ;
                ;Assemble affine texture mapping
                ;

                IF (MAP EQ MAP_AFFINE)
                
                SETUP_2 equ <TEXTURE_SETUP>
                PASS_2  equ <AFFINE_MAP>

                USE_U = 1
                USE_V = 1

                ENDIF

                ;
                ;Assemble solid Gouraud shading as background pass
                ;
                ;(for transparent areas of texture maps; other XP_
                ;options handled from within texture mapping loops)
                ;

                IF (XP EQ XP_R_GOURAUD)

                SETUP_1 equ <R_GOURAUD_SETUP>
                PASS_1  equ <R_GOURAUD_SOLID>

                USE_C = 1

                ELSEIF (XP EQ XP_I_GOURAUD)

                SETUP_1 equ <I_GOURAUD_SETUP>
                PASS_1  equ <I_GOURAUD_SOLID>

                USE_C = 1

                ENDIF

                ;
                ;Assemble solid Gouraud or Lambert polygon fills 
                ;as foreground pass (unmapped)
                ;

                IF (MAP EQ MAP_SOLID)

                IF SHD EQ SHD_GOURAUD

                USE_C = 1

                SETUP_1 equ <R_GOURAUD_SETUP>
                PASS_1  equ <M_GOURAUD_SOLID>

                ELSEIF SHD EQ SHD_I_GOURAUD

                USE_C = 1

                SETUP_1 equ <I_GOURAUD_SETUP>
                PASS_1  equ <I_GOURAUD_SOLID>

                ELSEIF SHD EQ SHD_R_GOURAUD

                USE_C = 1

                SETUP_1 equ <R_GOURAUD_SETUP>
                PASS_1  equ <R_GOURAUD_SOLID>

                ELSEIF SHD EQ SHD_FLAT

                SETUP_1 equ <FLAT_SOLID_SETUP>
                PASS_1  equ <FLAT_SOLID>

                ENDIF
                ENDIF

                ;
                ;Assemble Gouraud cueing for texture mapping and illumination
                ;

                IF (SHD EQ SHD_GOURAUD)
                IF (MAP EQ MAP_AFFINE) OR (MAP EQ MAP_PERSPECT) OR (MAP EQ MAP_ILLUM)

                USE_C = 1

                SETUP_3 equ <R_GOURAUD_SETUP>
                PASS_3  equ <GOURAUD_CUE>

                ENDIF
                ENDIF

                ;
                ;Assemble Lambert cueing
                ;(for illumination only -- texture cueing handled from
                ;within texture-mapping loops)
                ;

                IF (SHD EQ SHD_FLAT)
                IF (MAP EQ MAP_ILLUM)

                PASS_3 equ <FLAT_CUE>

                ENDIF
                ENDIF

                ;
                ;Finally, generate the actual primitive
                ;

                SCAN_CONVERT

                ret
poly_&Flg&      ENDP

                ;
                ;Save current assembly location, then insert vector to 
                ;primitive at appropriate place in jump table
                ;

                ASM = $

                ORG (OP) * 4
                dd poly_&Flg&

                ORG ASM

                ENDM

BUILD           MACRO Flg
                OP = Flg
                MAKE_POLY %OP
                ENDM

;лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
;лл                                                                        лл
;лл Primitive vectors generated at beginning of code segment               лл
;лл                                                                        лл
;лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

poly_vectors    LABEL DWORD

;лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
;лл                                                                        лл
;лл Actual primitive code begins here                                      лл
;лл                                                                        лл
;лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл

                org PARM_SPACE * 4

                INCLUDE rendopts.inc

;*****************************************************************************
VFX_set_Gouraud_dither_level PROC USES ebx esi edi es,\
                Dither1:DWORD,Dither2:DWORD

                mov eax,[Dither1]
                mov dfactor_1,eax

                mov eax,[Dither2]
                mov dfactor_2,eax
                ret

VFX_set_Gouraud_dither_level ENDP

;*****************************************************************************
VFX_polygon_render PROC USES ebx esi edi es,\
                Paneptr:PPANE,VList:PTR,VCnt,\
                Operation,\
                VColor,\
                PTexture:PTR,PCueing:PTR,PTranslucency:PTR

                IFDEF FLAT_MODEL        ;if in flat model, make sure ES=DS
                push ds                 ;(for background calls, etc.)
                pop es
                ENDIF

                mov edi,[Paneptr]

                mov edi,[edi].PANE.win

                mov eax,[edi].WINDOW.wnd_x1
                inc eax
                mov line_size,eax

                mov eax,[edi].WINDOW.buffer
                mov buff_addr,eax 

                mov ebx,[VList]         ;EBX -> list of VERTEX structs

                mov eax,[VCnt]
                shl eax,3
                mov edx,eax
                shl eax,1               ;* SIZE VERTEX (8n+16n=24n)
                add eax,edx             

                add eax,ebx

                mov vlist_beg,ebx      
                mov vlist_end,eax       ;EBX + VCnt*SIZE VERTEX -> end of list

                ;
                ;Copy parameters to shared area
                ;

                mov eax,[PTexture]
                mov p_texture,eax
                mov eax,[PCueing]
                mov p_cueing,eax
                mov eax,[PTranslucency]
                mov p_translucency,eax
                mov eax,[VColor]
                mov color,eax

                ;
                ;Select rendering primitive based on input flags
                ;

                mov ebx,[Operation]
                mov eax,poly_vectors[ebx*4]

                cmp eax,0
                je __end

                call eax

__end:          ret

VFX_polygon_render ENDP

                ;
                ;Clipping-related code begins
                ;

                IF BUILD_CLIP

;*****************************************************************************
;----------------------------------------------------------------------------
; 
;       F16_DIV_TO_F30  EDX=Dividend, EAX=Divisor
;
;       Divides two F16 values, returning an F30 result
;
;----------------------------------------------------------------------------

MF16_DIV_TO_F30 MACRO

                LOCAL __FDP1        
                LOCAL __FDP2        
                LOCAL __FDP3        

                push ebx
                push ecx

                push eax                ;push Divisor

                sub ecx,ecx             ;assume positive result
                mov eax,edx             ;mov eax,[Dividend]     
                and eax,eax             ;positive dividend?
                jns __FDP1              ;yes
                inc ecx                 ;mark it's a negative dividend
                neg eax                 ;make the dividend positive
__FDP1:         
                mov edx,eax             ;put dividend in EDX
                sar edx,2              
                shl eax,30             
                pop ebx                 ;mov ebx,[Divisor]      
                and ebx,ebx             ;positive divisor?
                jns __FDP2              ;yes
                dec ecx                 ;mark it's a negative divisor
                neg ebx                 ;make divisor positive
__FDP2:         div ebx                 ;divide
                shr ebx,1               ;divisor/2, minus 1 if the divisor is
                adc ebx,0               ; even
                dec ebx                
                cmp ebx,edx             ;set Carry if the remainder is at least
                adc eax,0               ; half as large as the divisor, then
                                        ; use that to round up if necessary
                and ecx,ecx             ;should the result be made negative?
                jz  __FDP3              ;no
                neg eax                 ;yes, negate it
__FDP3:
                pop ecx        
                pop ebx
        
                ENDM


;----------------------------------------------------------------------------
; 
;       MUL_F30 M2
;
;       Multiplies F16||F30 value in eax by F30 value M2.
;       Returns F16||F30 value.
;
;----------------------------------------------------------------------------

MMUL_F30        MACRO M2

                imul M2
                add eax,20000000h       ;round by adding 2/16 (* 4 = 1/2)
                adc edx,0               ;result is in EDX

                shld edx,eax,2          ;get LSB in EDX from top of EAX (* 4)
                mov eax,edx             ;return 16.16 result in EAX

                ENDM


;----------------------------------------------------------------------------
; 
;       CLIP_UV
;
;       Clips u and v coordinates
;
;----------------------------------------------------------------------------

CLIP_UV         MACRO
                LOCAL __exit        

                ; if (flags & F_USE_UV)

                cmp UV_clip,0
                je __exit

                ; out->u = (s->u + F16_mul_F30((f->u - s->u),mu))

                mov eax,[esi].u
                sub eax,[ebx].u

                MMUL_F30 mu

                mov edx,[ebx].u
                add edx,eax

                mov [edi].u,edx

                ; out->v = (s->v + F16_mul_F30((f->v - s->v),mu));

                mov eax,[esi].v
                sub eax,[ebx].v

                MMUL_F30 mu

                mov edx,[ebx].v
                add edx,eax

                mov [edi].v,edx
__exit:
                ENDM

;----------------------------------------------------------------------------
; 
;       CLIP_W
;
;       Clips w coordinate
;
;----------------------------------------------------------------------------

CLIP_W          MACRO
                LOCAL __exit        

                ; if (flags & F_USE_W)

                cmp W_clip,0
                je __exit

                ; out->w = s->w + F30_mul(f->w - s->w, mu);

                mov eax,[esi].w
                sub eax,[ebx].w

                MMUL_F30 mu

                mov edx,[ebx].w
                add edx,eax
                          
                mov [edi].w,edx
__exit:
                ENDM

;----------------------------------------------------------------------------
; 
;       CLIP_C
;
;       Clips c coordinate
;
;----------------------------------------------------------------------------

CLIP_C          MACRO
                LOCAL __exit

                cmp C_clip,0
                je __exit

                ; out->c = s->c + F30_mul(f->c - s->c, mu)

                mov eax,[esi].vc
                sub eax,[ebx].vc

                MMUL_F30 mu

                mov edx,[ebx].vc
                add edx,eax
                          
                mov [edi].vc,edx
__exit:
                ENDM

;----------------------------------------------------------------------------
;
;static void clip_x_line(F16 p, SCRNVERTEX *s, SCRNVERTEX *f, SCRNVERTEX *out,
;   ULONG flags)
;
;----------------------------------------------------------------------------

CLIP_X_LINE     MACRO   Clipval:REQ

                ; mu = F16_div_to_F30((p - s->x), (f->x - s->x));
                
                sub eax,edx             ;(f->x - s->x)        

                neg edx                 ;(p - s->x)
                add edx,Clipval

                MF16_DIV_TO_F30         ;eax = edx / eax

                mov mu, eax

                ; out->x = (LONG) p;

                mov eax,Clipval
                mov [edi].vx,eax

                ; out->y = (LONG) (s->y + F16_mul_F30((f->y - s->y),mu));

                mov eax,[esi].vy
                sub eax,[ebx].vy

                MMUL_F30 mu

                mov edx,[ebx].vy
                add edx,eax

                mov [edi].vy,edx

                CLIP_UV

                CLIP_W

                CLIP_C

                add edi,SIZEOF SCRNVERTEX

                ENDM            

;----------------------------------------------------------------------------
;
;static void clip_y_line(F16 p, SCRNVERTEX *s, SCRNVERTEX *f, SCRNVERTEX *out,
;   ULONG flags)
;
;----------------------------------------------------------------------------

CLIP_Y_LINE     MACRO   Clipval:REQ

                LOCAL   __use_w
                LOCAL   __use_c
                LOCAL   __return

                ; mu = F16_div_to_F30((p - s->y), (f->y - s->y));
                
                sub eax,edx             ;(f->y - s->y)        

                neg edx                 ;(p - s->y)
                add edx,Clipval

                MF16_DIV_TO_F30         ;eax = edx / eax

                mov mu, eax

                ; out->y = (LONG) p;

                mov eax,Clipval
                mov [edi].vy,eax

                ; out->x = (LONG) (s->x + F16_mul_F30((f->x - s->x),mu));

                mov eax,[esi].vx
                sub eax,[ebx].vx

                MMUL_F30 mu

                mov edx,[ebx].vx
                add edx,eax

                mov [edi].vx,edx

                CLIP_UV

                CLIP_W

                CLIP_C

                add edi,SIZEOF SCRNVERTEX

                ENDM            



SETUP_FIRST_SECOND_WORK MACRO Source:REQ, Entries:REQ, Dest:REQ

                ; second = work_pts;

                mov ebx,Source

                ; first = work-1;

                mov eax,Entries
                dec eax
                mov esi,eax

                ; multiply by 24 (sizeof(SCRNVERTEX))

                shl eax,4
                shl esi,3
                add esi,eax

                add esi,ebx     ; add base address of list

                ; work     = points;

                mov edi,Dest

                mov out_points,0
        
                ENDM


SETUP_NEXT_POINTERS     MACRO

                LOCAL __even        
                LOCAL __exit        

                inc planes_clipped
                mov eax,planes_clipped
                and eax,1
                jz __even

                SETUP_FIRST_SECOND_WORK OFFSET work_pts, VCnt, [VList]
                jmp __exit

__even:
                SETUP_FIRST_SECOND_WORK [VList], VCnt, OFFSET work_pts

__exit:

                ENDM


COPY_SCRVERTEX  MACRO

                push eax

                SOFF = 0
                REPT SIZEOF SCRNVERTEX / 4

                   mov eax,DWORD PTR [esi+SOFF]
                   mov DWORD PTR [edi+SOFF],eax

                SOFF=SOFF+4
                ENDM

                add edi,SIZEOF SCRNVERTEX

                pop eax

                inc out_points

                ENDM

                .CODE


;*****************************************************************************
;----------------------------------------------------------------------------
; 
;       F30 F16_div_to_F30(F16 Dividend, F16 Divisor);
;
;       Divides two F16 values, returning an F30 result
;
;----------------------------------------------------------------------------

                ALIGN 4
F16_div_to_F30  PROC C USES ebx,Dividend,Divisor

                sub ecx,ecx             ;assume positive result
                mov eax,[Dividend]     
                and eax,eax             ;positive dividend?
                jns __FDP1              ;yes
                inc ecx                 ;mark it's a negative dividend
                neg eax                 ;make the dividend positive
__FDP1:         
                mov edx,eax             ;put dividend in EDX
                sar edx,2              
                shl eax,30             
                mov ebx,[Divisor]      
                and ebx,ebx             ;positive divisor?
                jns __FDP2              ;yes
                dec ecx                 ;mark it's a negative divisor
                neg ebx                 ;make divisor positive
__FDP2:         div ebx                 ;divide
                shr ebx,1               ;divisor/2, minus 1 if the divisor is
                adc ebx,0               ; even
                dec ebx                
                cmp ebx,edx             ;set Carry if the remainder is at least
                adc eax,0               ; half as large as the divisor, then
                                        ; use that to round up if necessary
                and ecx,ecx             ;should the result be made negative?
                jz  __FDP3              ;no
                neg eax                 ;yes, negate it
__FDP3:
                ret
F16_div_to_F30  ENDP

;*****************************************************************************
;----------------------------------------------------------------------------
; 
;       F30 F30_reciprocal(F16 Divisor);
;
;       Divides 1 by an F16 value, returning the F30 result
;
;----------------------------------------------------------------------------

                ALIGN 4
F30_reciprocal  PROC C USES ebx,Divisor

                sub ecx,ecx             ;assume positive result
                mov edx,4000h           ;put dividend in EDX
                xor eax,eax             ;clear EAX for extended decimal places
                mov ebx,[Divisor]     
                and ebx,ebx             ;positive divisor?
                jns __FDP2              ;yes
                dec ecx                 ;mark it's a negative divisor
                neg ebx                 ;make divisor positive
__FDP2:         div ebx                 ;divide
                shr ebx,1               ;divisor/2, minus 1 if the divisor is
                adc ebx,0               ; even
                dec ebx               
                cmp ebx,edx             ;set Carry if the remainder is at least
                adc eax,0               ; half as large as the divisor, then
                                        ; use that to round up if necessary
                and ecx,ecx             ;should the result be made negative?
                jz  __FDP3              ;no
                neg eax                 ;yes, negate it
__FDP3:
                ret
F30_reciprocal  ENDP

;*****************************************************************************
;----------------------------------------------------------------------------
; 
;       F30 mul_F30(F?? M1, F30 M2);
;
;       Multiplies a F?? value by a F30 value together, returning an F??.
;
;----------------------------------------------------------------------------

                ALIGN 4
mul_F30         PROC C M1,M2

                mov eax,M1
                imul M2               
                add eax,20000000h       ;round by adding
                adc edx,0               ;result is in EDX

                shld edx,eax,2          ;get LSB in EDX from top of EAX
                mov eax,edx             ;return 2.30 result in EAX

                ret

mul_F30         ENDP

;*****************************************************************************
                ALIGN 4
VFX_polygon_clip_XY_and_render PROC C USES es esi edi ebx, \
                Paneptr:PPANE,VList:PTR,VCnt,\
                Operation,\
                VColor,\
                PTexture:PTR,PCueing:PTR,PTranslucency:PTR

                LOCAL rightclip, topclip, leftclip, bottomclip

                LOCAL mu
                LOCAL out_points
                LOCAL clip_needed
                LOCAL planes_clipped

                push ds
                pop es
                cld

                mov clip_needed,0        

                mov esi,[VList]
                ASSUME esi:PSCRNVERTEX

                mov edi,[Paneptr]
                ASSUME edi:NOTHING

                ;
                ;Set up clipping boundaries
                ;

                mov eax,[edi].PANE.x1           ;right        
                mov ebx,[edi].PANE.x0           ;left
                mov ecx,[edi].PANE.y1           ;top (top & bottom reversed)
                mov edx,[edi].PANE.y0           ;bottom

                mov rightclip,eax
                mov leftclip,ebx
                mov topclip,ecx
                mov bottomclip,edx      

                mov edi,[edi].PANE.win
                mov eax,[edi].WINDOW.wnd_x1
                inc eax
                mov line_size,eax

                mov eax,[edi].WINDOW.buffer
                mov buff_addr,eax 

                ;
                ;Loop thru points to determine clips needed
                ;

                mov ecx,VCnt

__check_if_clip_needed:

                mov edx,0

                mov eax,rightclip               ;Right
                mov ebx,[esi].vx        
                sub eax,ebx               
                shld edx,eax,1

                mov eax,leftclip                ;Left
                sub ebx,eax             
                shld edx,ebx,1
                
                mov eax,topclip                 ;Top
                mov ebx,[esi].vy
                sub eax,ebx
                shld edx,eax,1

                mov eax,bottomclip              ;Bottom
                sub ebx,eax
                shld edx,ebx,1

                or clip_needed,edx
                add esi,SIZEOF SCRNVERTEX

                loop __check_if_clip_needed

                ;
                ;Set up point lists
                ;

                ASSUME esi:PSCRNVERTEX
                ASSUME ebx:PSCRNVERTEX
                ASSUME edi:PSCRNVERTEX

                SETUP_FIRST_SECOND_WORK [VList], [VCnt], OFFSET work_pts

                ;
                ;Jump to renderer if no clipping needed
                ;

                cmp clip_needed,0               ;if no clip needed
                jz __finished                   ;jmp to render

                ;
                ;Init clipping vars; assign operation codes for 
                ;variable clipping
                ;

                mov out_points,0
                mov planes_clipped,0

                ;
                ;Set UV clipping flag
                ;

                mov eax,[Operation]
                and eax,(MAP_AFFINE OR MAP_PERSPECT) AND NOT MAP_SOLID
                mov UV_clip,eax

                ;
                ;Set W clipping flag
                ;

                mov ecx,0

                mov eax,[Operation]
                and eax,MAP_MASK
                cmp eax,MAP_PERSPECT
                jne __set_W

                mov ecx,1
__set_W:        mov W_clip,ecx
                
                ;
                ;Set C clipping flag
                ;

                mov ecx,1

                mov eax,[Operation]
                and eax,SHD_MASK
                cmp eax,SHD_GOURAUD
                je __set_C
                cmp eax,SHD_I_GOURAUD
                je __set_C
                cmp eax,SHD_R_GOURAUD
                je __set_C

                mov eax,[Operation]
                and eax,XP_MASK
                cmp eax,XP_I_GOURAUD
                je __set_C
                cmp eax,XP_R_GOURAUD
                je __set_C

                mov ecx,0
__set_C:        mov C_clip,ecx

                ;
                ;Clip right
                ;

                mov eax,clip_needed
                and eax,CLIP_RIGHT_BIT
                jz __clip_bottom

                ;
                ;Loop thru points and clip
                ;

                mov ecx, VCnt
__loop_right:
                mov eax,[esi].vx                ;eax = first->x
                mov edx,[ebx].vx                ;edx = second->x

                cmp eax,rightclip               ;if (first->x <= xclip)
                jg __check_right

                COPY_SCRVERTEX

                cmp edx,rightclip               ;if ( second->x > xclip )
                jg __clip_x_right
                jmp __next_right

__check_right:
                cmp edx,rightclip               ;if ( second->x <= xclip )   
                jg __next_right


__clip_x_right:
                CLIP_X_LINE rightclip           ;edx, eax, edi, [Operation]

                inc out_points

__next_right:
                mov esi,ebx;                    ; first = second;
                add ebx,SIZEOF SCRNVERTEX

                dec ecx
                jnz __loop_right

                inc planes_clipped

                mov eax,out_points
                mov VCnt,eax

                cmp eax,0
                jz __finished                   ;No points left in polygon

                SETUP_FIRST_SECOND_WORK OFFSET work_pts, VCnt, [VList]

                ;
                ;Clip bottom
                ;

__clip_bottom:
                mov eax,clip_needed
                and eax,CLIP_BOTTOM_BIT
                jz __clip_left

                ;
                ;Loop thru points and clip
                ;

                mov ecx, VCnt
__loop_bottom:
                mov eax,[esi].vy                ;eax = first->y
                mov edx,[ebx].vy                ;ebx = second->y

                cmp eax,bottomclip              ;if (first->y >= -yclip)
                jl __check_bottom

                COPY_SCRVERTEX

                cmp edx,bottomclip              ;if ( second->y < -yclip )
                jl __clip_y_bottom
                jmp __next_bottom

__check_bottom:
                cmp edx,bottomclip              ;if ( second->x >= -yclip )   
                jl __next_bottom

__clip_y_bottom:
                CLIP_Y_LINE bottomclip          ;edx, eax, edi, [Operation]

                inc out_points

__next_bottom:
                mov esi,ebx;                    ;first = second;        
                add ebx,SIZEOF SCRNVERTEX

                dec ecx
                jnz __loop_bottom

                mov eax,out_points
                mov VCnt,eax
                cmp eax,0
                jz __finished                   ;No points left in polygon

                SETUP_NEXT_POINTERS

                ;
                ;Clip left
                ;

__clip_left:
                mov eax,clip_needed
                and eax,CLIP_LEFT_BIT
                jz __clip_top

                ;
                ;Loop thru points and clip
                ;

                mov ecx, VCnt
__loop_left:
                mov eax,[esi].vx                ;eax = first->x
                mov edx,[ebx].vx                ;ebx = second->x

                cmp eax,leftclip                ;if (first->x >= -xclip)
                jl __check_left

                COPY_SCRVERTEX

                cmp edx,leftclip                ;if ( second->x < -xclip )
                jl __clip_x_left
                jmp __next_left

__check_left:
                cmp edx,leftclip                ;if ( second->x >= xclip )   
                jl __next_left

__clip_x_left:
                CLIP_X_LINE leftclip            ;edx, eax, edi, [Operation]

                inc out_points

__next_left:
                mov esi,ebx;                    ;first = second
                add ebx,SIZEOF SCRNVERTEX

                dec ecx
                jnz __loop_left

                mov eax,out_points
                mov VCnt,eax
                cmp eax,0
                jz __finished                   ;No points left in polygon

                SETUP_NEXT_POINTERS

                ;
                ;Clip top
                ;

__clip_top:
                mov eax,clip_needed
                and eax,CLIP_TOP_BIT
                jz __finished

                ;
                ;Loop thru points and clip
                ;

                mov ecx, VCnt
__loop_top:
                mov eax,[esi].vy                ;eax = first->y
                mov edx,[ebx].vy                ;ebx = second->y

                cmp eax,topclip                 ;if (first->y <= yclip)
                jg __check_top

                COPY_SCRVERTEX

                cmp edx,topclip                 ;if ( second->y > yclip )
                jg __clip_y_top
                jmp __next_top

__check_top:
                cmp edx,topclip                 ;if ( second->x <= yclip )   
                jg __next_top

__clip_y_top:
                CLIP_Y_LINE topclip             ;edx, eax, edi, [Operation]

                inc out_points

__next_top:
                mov esi,ebx;                    ;first = second;
                add ebx,SIZEOF SCRNVERTEX

                dec ecx
                jnz __loop_top

                mov eax,out_points
                mov VCnt,eax
                cmp eax,0
                jz __finished                   ;No points left in polygon

                SETUP_NEXT_POINTERS

__finished:
                ;EBX -> list of VERTEX structs

                mov eax,[VCnt]
                cmp eax,3
                jl __end                ;less than 3 points

                shl eax,3
                mov edx,eax
                shl eax,1               ;* SIZE VERTEX (8n+16n=24n)
                add eax,edx             

                add eax,ebx

                mov vlist_beg,ebx      
                mov vlist_end,eax       ;EBX + VCnt*SIZE VERTEX -> end of list

                ;
                ;Copy parameters to shared area
                ;

                mov eax,[PTexture]
                mov p_texture,eax
                mov eax,[PCueing]
                mov p_cueing,eax
                mov eax,[PTranslucency]
                mov p_translucency,eax
                mov eax,[VColor]
                mov color,eax

                ;
                ;Select rendering primitive based on input flags
                ;

                mov ebx,[Operation]
                mov eax,poly_vectors[ebx*4]

                cmp eax,0
                je __end

                call eax

__end:          ret

VFX_polygon_clip_XY_and_render ENDP

                ENDIF

                END


