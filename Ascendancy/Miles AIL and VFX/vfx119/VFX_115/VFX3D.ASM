;лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
;лл                                                                        лл
;лл  VFX3D.ASM                                                             лл
;лл                                                                        лл
;лл  VFX polygon primitives for 3D rendering                               лл
;лл                                                                        лл
;лл  Version 1.00 of  5-Jul-92: Original                                   лл
;лл          1.01 of 14-May-93: Vertex coordinates made pane-relative for  лл
;лл                              consistency with other VFX functions      лл
;лл                             Fixed-point Gouraud dithering added to     лл
;лл                              VFX_dithered_Gouraud_polygon()            лл
;лл                             VFX_precision_Gouraud_polygon() renamed;   лл
;лл                              old VFX_Gouraud_polygon() dropped         лл
;лл                             Scanline loops partially unrolled for      лл
;лл                              optimum 486/Pentium cachability           лл
;лл                             VFX_translate_polygon() added              лл
;лл                             VFX_illuminate_polygon() added             лл
;лл          1.02 of 22-Jul-93: New SCRNVERTEX structure incorporated      лл
;лл                             All source parameters now fixed-point      лл
;лл          1.10 of  3-Dec-93: New WINDOW structure implemented           лл
;лл                                                                        лл
;лл  Project: 386FX Sound & Light(TM)                                      лл
;лл   Author: John Miles                                                   лл
;лл                                                                        лл
;лл  C prototypes in VFX.H                                                 лл
;лл                                                                        лл
;лл  80386 ASM source compatible with Microsoft Assembler v6.0 or later    лл
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

                OPTION SCOPED           ;Enable local labels

                .386                    ;Enable 386 instructions
                .MODEL FLAT,C           ;32-bit OS/2 model

                INCLUDE vfx.inc

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

                PUBLIC VFX_flat_polygon
                PUBLIC VFX_Gouraud_polygon
                PUBLIC VFX_dithered_Gouraud_polygon
                PUBLIC VFX_map_lookaside
                PUBLIC VFX_map_polygon
                PUBLIC VFX_translate_polygon
                PUBLIC VFX_illuminate_polygon

                .DATA   
                                        ;global data to ensure DWORD alignment
VP_R            dd ?
VP_B            dd ?
buff_addr       dd ?
line_size       dd ?

txt_width       dd ?
txt_bitmap      dd ?

line_base       dd ?
line_end        dd ?
x_clipped       dd ?
vlist_beg       dd ?
vlist_end       dd ?
v_top           dd ?
lcur            dd ?
rcur            dd ?
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
ldx             dd ?
rdx             dd ?
ldc             dd ?
rdc             dd ?
ldu             dd ?
rdu             dd ?
ldv             dd ?
rdv             dd ?
plx             dd ?
prx             dd ?
dc              dd ?
du              dd ?
dv              dd ?
flu             dd ?
color           dd ?
loop_entry      dd ?
dither_1        dd ?
dither_2        dd ?
ebp_save        dd ?
skip_first      dd ?

                ;
                ;Index offset table used by mapping primitives
                ;

UV_step         dd 4 dup (?)

                ;
                ;Color translate ("haze") table used by mapping primitives
                ;

lookaside       db 256 dup (?)

                .CODE

;*****************************************************************************
VFX_flat_polygon PROC USES ebx esi edi es,\
                DestPane:PTR,VCnt,VList:PTR

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

                mov eax,[ebx].vc        ;read polygon color from 1st vertex
                add eax,8000h
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

                mov eax,[ebx].vx
                shld edx,eax,1

                mov eax,VP_R
                sub eax,[ebx].vx
                shld edx,eax,1

                or x_clipped,edx

                mov eax,[ebx].vy
                shld edx,eax,1

                mov eax,VP_B
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

                mov ecx,[esi].vy        ;ECX = edge bottom Y
                mov edx,[ebx].vy        ;EDX = edge top Y

                cmp edx,0               ;skip edge if above viewport
                jge __set_l_pcnt
                cmp ecx,0
                jle __init_left         ;(bottom vertex shared w/next edge)

__set_l_pcnt:   sub ecx,edx             ;is edge flat?
                jz __init_left          ;yes, advance one edge left

                mov lcnt,ecx            ;set left edge pixel count

                mov edx,[esi].vx        ;get size of edge in X
                sub edx,[ebx].vx
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldx,eax             ;set left DX
                
                mov edx,[ebx].vx        ;convert X to fixed-point val
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

                mov ecx,[esi].vy        ;ECX = edge bottom Y
                mov edx,[ebx].vy        ;EDX = edge top Y

                cmp edx,0               ;skip edge if above viewport
                jge __set_r_pcnt
                cmp ecx,0
                jle __init_right        ;(bottom vertex shared w/next edge)

__set_r_pcnt:   sub ecx,edx             ;is edge flat?
                jz __init_right         ;yes, advance one edge right

                mov rcnt,ecx            ;set right edge pixel count

                mov edx,[esi].vx        ;get size of edge in X
                sub edx,[ebx].vx
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdx,eax             ;set right DX
                
                mov edx,[ebx].vx        ;convert X to fixed-point val
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
                sub ecx,[ebx].vy
                sub lcnt,ecx

                shl ecx,16              ;ECX = # of pixels to clip from left

                mov eax,ldx             ;lx = lx + ECX * ldx
                FPMUL ecx
                add lx,eax

                mov ecx,0
                mov ebx,rcur
                sub ecx,[ebx].vy
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
                
                mov eax,[ebx].vx        
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

                mov ecx,[esi].vy        ;CX = edge bottom Y
                mov edx,[ebx].vy        ;DX = edge top Y

                sub ecx,edx             ;if edge flat, force delta=1
                cmp ecx,1               ;(possible only at bottom scan line)
                adc ecx,0

                mov rcnt,ecx            ;set right edge pixel count

                mov edx,[esi].vx        ;get size of edge in X
                sub edx,[ebx].vx
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdx,eax             ;set right DX

                mov ebx,[ebx].vx        
                shl ebx,16              ;convert X to fixed-point val
                add ebx,8000h           ;pre-round by adding +0.5

                pop eax
                cmp x_clipped,0
                je __unclip_line
                jmp __clip_line

                ELSE
                ret
                ENDIF

VFX_flat_polygon ENDP

;*****************************************************************************
VFX_Gouraud_polygon PROC USES ebx esi edi es,\
                DestPane:PTR,VCnt,VList:PTR

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

                mov eax,[ebx].vx
                shld edx,eax,1

                mov eax,VP_R
                sub eax,[ebx].vx
                shld edx,eax,1

                or x_clipped,edx

                mov eax,[ebx].vy
                shld edx,eax,1

                mov eax,VP_B
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

                mov ecx,[esi].vy        ;ECX = edge bottom Y
                mov edx,[ebx].vy        ;EDX = edge top Y

                cmp edx,0               ;skip edge if above viewport
                jge __set_l_pcnt
                cmp ecx,0
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

                mov edx,[esi].vc        ;get size of edge in C
                sub edx,[ebx].vc
                FPDIV ecx               ;divide by pixel count
                mov ldc,eax             ;set left DC

                mov edx,[ebx].vx        ;convert X and C to fixed-point vals
                shl edx,16              ;pre-round by adding +0.5 to both
                add edx,8000h           
                mov lx,edx

                mov edx,[ebx].vc
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

                mov ecx,[esi].vy        ;ECX = edge bottom Y
                mov edx,[ebx].vy        ;EDX = edge top Y

                cmp edx,0               ;skip edge if above viewport
                jge __set_r_pcnt
                cmp ecx,0
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

                mov edx,[esi].vc        ;get size of edge in C
                sub edx,[ebx].vc
                FPDIV ecx               ;divide by pixel count
                mov rdc,eax             ;set right DC

                mov edx,[ebx].vx        ;convert X and C to fixed-point vals
                shl edx,16              ;pre-round by adding +0.5 to both
                add edx,8000h
                mov rx,edx

                mov edx,[ebx].vc
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
                sub ecx,[ebx].vy
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
                sub ecx,[ebx].vy
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

                mov ecx,[esi].vy        ;ECX = edge bottom Y
                mov edx,[ebx].vy        ;EDX = edge top Y

                sub ecx,edx             ;if edge flat, force delta=1
                cmp ecx,1               ;(possible only at bottom scan line)
                adc ecx,0

                mov lcnt,ecx            ;set left edge pixel count

                mov edx,[esi].vc        ;get size of edge in C
                sub edx,[ebx].vc
                FPDIV ecx               ;divide by pixel count
                mov ldc,eax             ;set left DC

                mov ecx,lcnt

                mov edx,[esi].vx        ;get size of edge in X
                sub edx,[ebx].vx
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldx,eax             ;set left DX
                
                mov ecx,[ebx].vc
                add ecx,8000h           ;pre-round by adding +0.5

                mov eax,[ebx].vx        
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

                mov ecx,[esi].vy        ;ECX = edge bottom Y
                mov edx,[ebx].vy        ;EDX = edge top Y

                sub ecx,edx             ;if edge flat, force delta=1
                cmp ecx,1               ;(possible only at bottom scan line)
                adc ecx,0

                mov rcnt,ecx            ;set right edge pixel count

                mov edx,[esi].vc        ;get size of edge in C
                sub edx,[ebx].vc
                FPDIV ecx               ;divide by pixel count
                mov rdc,eax             ;set right DC

                mov ecx,rcnt

                mov edx,[esi].vx        ;get size of edge in X
                sub edx,[ebx].vx
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdx,eax             ;set right DX

                mov edx,[ebx].vc
                add edx,8000h           ;pre-round by adding +0.5

                mov ebx,[ebx].vx        
                shl ebx,16              ;convert X to fixed-point val
                add ebx,8000h           ;pre-round by adding +0.5

                pop ecx
                pop eax

                cmp x_clipped,0
                je __unclip_line
                jmp __clip_line

                ELSE
                ret
                ENDIF

VFX_Gouraud_polygon ENDP

;*****************************************************************************
VFX_dithered_Gouraud_polygon PROC USES ebx esi edi es,\
                DestPane:PTR,DFactor,VCnt,VList:PTR

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

                mov eax,[ebx].vx
                shld edx,eax,1

                mov eax,VP_R
                sub eax,[ebx].vx
                shld edx,eax,1

                or x_clipped,edx

                mov eax,[ebx].vy
                shld edx,eax,1

                mov eax,VP_B
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

                mov ecx,[esi].vy        ;ECX = edge bottom Y
                mov edx,[ebx].vy        ;EDX = edge top Y

                cmp edx,0               ;skip edge if above viewport
                jge __set_l_pcnt
                cmp ecx,0
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

                mov edx,[esi].vc        ;get size of edge in C
                sub edx,[ebx].vc
                FPDIV ecx               ;divide by pixel count
                mov ldc,eax             ;set left DC

                mov edx,[ebx].vx        ;convert X and C to fixed-point vals
                shl edx,16              ;pre-round by adding +0.5 to both
                add edx,8000h           
                mov lx,edx

                mov edx,[ebx].vc
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

                mov ecx,[esi].vy        ;ECX = edge bottom Y
                mov edx,[ebx].vy        ;EDX = edge top Y

                cmp edx,0               ;skip edge if above viewport
                jge __set_r_pcnt
                cmp ecx,0
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

                mov edx,[esi].vc        ;get size of edge in C
                sub edx,[ebx].vc
                FPDIV ecx               ;divide by pixel count
                mov rdc,eax             ;set right DC

                mov edx,[ebx].vx        ;convert X and C to fixed-point vals
                shl edx,16              ;pre-round by adding +0.5 to both
                add edx,8000h
                mov rx,edx

                mov edx,[ebx].vc
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
                sub ecx,[ebx].vy
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
                sub ecx,[ebx].vy
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

                mov ecx,[esi].vy        ;ECX = edge bottom Y
                mov edx,[ebx].vy        ;EDX = edge top Y

                sub ecx,edx             ;if edge flat, force delta=1
                cmp ecx,1               ;(possible only at bottom scan line)
                adc ecx,0

                mov lcnt,ecx            ;set left edge pixel count

                mov edx,[esi].vc        ;get size of edge in C
                sub edx,[ebx].vc
                FPDIV ecx               ;divide by pixel count
                mov ldc,eax             ;set left DC

                mov ecx,lcnt

                mov edx,[esi].vx        ;get size of edge in X
                sub edx,[ebx].vx
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldx,eax             ;set left DX
                
                mov ecx,[ebx].vc
                add ecx,8000h           ;pre-round by adding +0.5

                mov eax,[ebx].vx        
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

                mov ecx,[esi].vy        ;ECX = edge bottom Y
                mov edx,[ebx].vy        ;EDX = edge top Y

                sub ecx,edx             ;if edge flat, force delta=1
                cmp ecx,1               ;(possible only at bottom scan line)
                adc ecx,0

                mov rcnt,ecx            ;set right edge pixel count

                mov edx,[esi].vc        ;get size of edge in C
                sub edx,[ebx].vc
                FPDIV ecx               ;divide by pixel count
                mov rdc,eax             ;set right DC

                mov ecx,rcnt

                mov edx,[esi].vx        ;get size of edge in X
                sub edx,[ebx].vx
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdx,eax             ;set right DX

                mov edx,[ebx].vc
                add edx,8000h           ;pre-round by adding +0.5

                mov ebx,[ebx].vx        
                shl ebx,16              ;convert X to fixed-point val
                add ebx,8000h           ;pre-round by adding +0.5

                pop ecx
                pop eax

                cmp x_clipped,0
                je __unclip_line
                jmp __clip_line

                ELSE
                ret
                ENDIF

VFX_dithered_Gouraud_polygon ENDP

;*****************************************************************************
VFX_translate_polygon PROC USES ebx esi edi es,\
                DestPane:PTR,VCnt,VList:PTR,XTable:PTR

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

                mov eax,[ebx].vx
                shld edx,eax,1

                mov eax,VP_R
                sub eax,[ebx].vx
                shld edx,eax,1

                mov eax,[ebx].vy
                shld edx,eax,1

                mov eax,VP_B
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

                mov ecx,[esi].vy        ;ECX = edge bottom Y
                mov edx,[ebx].vy        ;EDX = edge top Y

                cmp edx,0               ;skip edge if above viewport
                jge __set_l_pcnt
                cmp ecx,0
                jle __init_left         ;(bottom vertex shared w/next edge)

__set_l_pcnt:   sub ecx,edx             ;is edge flat?
                jz __init_left          ;yes, advance one edge left

                mov lcnt,ecx            ;set left edge pixel count

                mov edx,[esi].vx        ;get size of edge in X
                sub edx,[ebx].vx
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldx,eax             ;set left DX
                
                mov edx,[ebx].vx        ;convert X to fixed-point
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

                mov ecx,[esi].vy        ;ECX = edge bottom Y
                mov edx,[ebx].vy        ;EDX = edge top Y

                cmp edx,0               ;skip edge if above viewport
                jge __set_r_pcnt
                cmp ecx,0
                jle __init_right        ;(bottom vertex shared w/next edge)

__set_r_pcnt:   sub ecx,edx             ;is edge flat?
                jz __init_right         ;yes, advance one edge right

                mov rcnt,ecx            ;set right edge pixel count

                mov edx,[esi].vx        ;get size of edge in X
                sub edx,[ebx].vx
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdx,eax             ;set right DX
                
                mov edx,[ebx].vx        ;convert X to fixed-point
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
                sub ecx,[ebx].vy
                sub lcnt,ecx

                shl ecx,16              ;ECX = # of pixels to clip from left

                mov eax,ldx             ;lx = lx + ECX * ldx
                FPMUL ecx
                add lx,eax

                mov ecx,0
                mov ebx,rcur
                sub ecx,[ebx].vy
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

                mov eax,[ebx].vx        
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

                mov ebx,[ebx].vx        
                shl ebx,16              ;convert X to fixed-point val
                add ebx,8000h           ;pre-round by adding +0.5

                pop eax
                jmp __do_line

                ELSE
                ret
                ENDIF

VFX_translate_polygon ENDP

;*****************************************************************************
VFX_illuminate_polygon PROC USES ebx esi edi es,\
                DestPane:PTR,DFactor,VCnt,VList:PTR

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

                mov eax,[ebx].vx
                shld edx,eax,1

                mov eax,VP_R
                sub eax,[ebx].vx
                shld edx,eax,1

                or x_clipped,edx

                mov eax,[ebx].vy
                shld edx,eax,1

                mov eax,VP_B
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

                mov ecx,[esi].vy        ;ECX = edge bottom Y
                mov edx,[ebx].vy        ;EDX = edge top Y

                cmp edx,0               ;skip edge if above viewport
                jge __set_l_pcnt
                cmp ecx,0
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

                mov edx,[esi].vc        ;get size of edge in C
                sub edx,[ebx].vc
                FPDIV ecx               ;divide by pixel count
                mov ldc,eax             ;set left DC

                mov edx,[ebx].vx        ;convert X and C to fixed-point vals
                shl edx,16              ;pre-round by adding +0.5 to both
                add edx,8000h           
                mov lx,edx

                mov edx,[ebx].vc
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

                mov ecx,[esi].vy        ;ECX = edge bottom Y
                mov edx,[ebx].vy        ;EDX = edge top Y

                cmp edx,0               ;skip edge if above viewport
                jge __set_r_pcnt
                cmp ecx,0
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

                mov edx,[esi].vc        ;get size of edge in C
                sub edx,[ebx].vc
                FPDIV ecx               ;divide by pixel count
                mov rdc,eax             ;set right DC

                mov edx,[ebx].vx        ;convert X and C to fixed-point vals
                shl edx,16              ;pre-round by adding +0.5 to both
                add edx,8000h
                mov rx,edx

                mov edx,[ebx].vc
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
                sub ecx,[ebx].vy
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
                sub ecx,[ebx].vy
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

                mov ecx,[esi].vy        ;ECX = edge bottom Y
                mov edx,[ebx].vy        ;EDX = edge top Y

                sub ecx,edx             ;if edge flat, force delta=1
                cmp ecx,1               ;(possible only at bottom scan line)
                adc ecx,0

                mov lcnt,ecx            ;set left edge pixel count

                mov edx,[esi].vc        ;get size of edge in C
                sub edx,[ebx].vc
                FPDIV ecx               ;divide by pixel count
                mov ldc,eax             ;set left DC

                mov ecx,lcnt

                mov edx,[esi].vx        ;get size of edge in X
                sub edx,[ebx].vx
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov ldx,eax             ;set left DX
                
                mov ecx,[ebx].vc
                add ecx,8000h           ;pre-round by adding +0.5

                mov eax,[ebx].vx        
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

                mov ecx,[esi].vy        ;ECX = edge bottom Y
                mov edx,[ebx].vy        ;EDX = edge top Y

                sub ecx,edx             ;if edge flat, force delta=1
                cmp ecx,1               ;(possible only at bottom scan line)
                adc ecx,0

                mov rcnt,ecx            ;set right edge pixel count

                mov edx,[esi].vc        ;get size of edge in C
                sub edx,[ebx].vc
                FPDIV ecx               ;divide by pixel count
                mov rdc,eax             ;set right DC

                mov ecx,rcnt

                mov edx,[esi].vx        ;get size of edge in X
                sub edx,[ebx].vx
                shl edx,16              ;convert to fixed-point
                FPDIV ecx               ;divide by pixel count
                mov rdx,eax             ;set right DX

                mov edx,[ebx].vc
                add edx,8000h           ;pre-round by adding +0.5

                mov ebx,[ebx].vx        
                shl ebx,16              ;convert X to fixed-point val
                add ebx,8000h           ;pre-round by adding +0.5

                pop ecx
                pop eax

                cmp x_clipped,0
                je __unclip_line
                jmp __clip_line

                ELSE
                ret
                ENDIF

VFX_illuminate_polygon ENDP

;*****************************************************************************
VFX_map_lookaside PROC C USES ebx esi edi es,\
                table:PTR

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
                DestPane:PTR,VCnt,VList:PTR,TxtWnd:PTR,Flags

                IF M_POLY

                SET_DEST_PANE

                mov ebx,[TxtWnd]
                mov eax,[ebx].buffer    ;copy buffer pointer
                mov txt_bitmap,eax
                mov ecx,[ebx].wnd_x1    ;xsize  = windowp->wnd_x1+1
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

                mov eax,[ebx].vx
                shld edx,eax,1

                mov eax,VP_R
                sub eax,[ebx].vx
                shld edx,eax,1

                mov eax,[ebx].vy
                shld edx,eax,1

                mov eax,VP_B
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

                mov ecx,[esi].vy        ;ECX = edge bottom Y
                mov edx,[ebx].vy        ;EDX = edge top Y

                cmp edx,0               ;skip edge if above viewport
                jge __set_l_pcnt
                cmp ecx,0
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
                FPDIV ecx               ;divide by pixel count
                mov ldu,eax             ;set left DU

                mov ecx,lcnt

                mov edx,[esi].v         ;get size of edge in V
                sub edx,[ebx].v
                FPDIV ecx               ;divide by pixel count
                mov ldv,eax             ;set left DV

                mov edx,[ebx].vx        ;convert X, U, and V to fixed-point
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

                mov ecx,[esi].vy        ;ECX = edge bottom Y
                mov edx,[ebx].vy        ;EDX = edge top Y

                cmp edx,0               ;skip edge if above viewport
                jge __set_r_pcnt
                cmp ecx,0
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
                FPDIV ecx               ;divide by pixel count
                mov rdu,eax             ;set right DU

                mov ecx,rcnt

                mov edx,[esi].v         ;get size of edge in U
                sub edx,[ebx].v
                FPDIV ecx               ;divide by pixel count
                mov rdv,eax             ;set right DV

                mov edx,[ebx].vx        ;convert X,U, and V to fixed-point
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

                mov ecx,0
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
                cmp bl,TRANSPARENT
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
                cmp bl,TRANSPARENT
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
                FPDIV ecx               ;divide by pixel count
                mov ldu,eax             ;set left DU

                mov ecx,lcnt

                mov edx,[esi].v         ;get size of edge in V
                sub edx,[ebx].v
                FPDIV ecx               ;divide by pixel count
                mov ldv,eax             ;set left DV

                mov eax,[ebx].vx        
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

                mov ebx,[ebx].vx        
                shl ebx,16              ;convert X to fixed-point val
                add ebx,8000h           ;pre-round by adding +0.5

                pop ecx
                pop eax
                jmp __do_line

                ELSE
                ret
                ENDIF

VFX_map_polygon ENDP
                END
