;лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
;лл                                                                        лл
;лл  MCGA.ASM                                                              лл
;лл                                                                        лл
;лл  VFX driver DLL for standard MCGA/VGA 320x200x256 mode                 лл
;лл                                                                        лл
;лл  Version 1.00 of 16-Oct-92: Initial version                            лл
;лл          1.01 of 28-Jul-93: VFX_bank_reset() added                     лл
;лл          1.10 of 17-Nov-93: Phar Lap support added                     лл
;лл          1.11 of 23-Jan-94: New WINDOW structure                       лл
;лл                             VFX_DAC_write() uses ES                    лл
;лл                             VFX_line_address() added                   лл
;лл          1.15 of 15-Mar-94: Added stencil and shadow buffer support    лл
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

                OPTION SCOPED   ;Enable local labels

                .386            ;Enable 386 instructions
                .MODEL FLAT,C   ;32-bit OS/2 model

                INCLUDE vfx.mac

SCRN_ADDR       equ 0a0000h                     ;Flat-model screen address

SCRN_W          equ 320                         ;Screen width = 320 pixels
SCRN_H          equ 200                         ;Screen height = 200 pixels

                ;
                ;BASCALC: Calculates linear address for line (X0,Y - X1,Y)
                ;
                ;Expects:  EDI = X0
                ;          ECX = X1
                ;          EBX = Y
                ;
                ;Returns:  EDI = address of point X0,Y
                ;          ECX = # of bytes in line
                ;
                ;Destroys: EAX,EDX
                ;

BASCALC         MACRO
                LOCAL __do_line,__exit

                sub ecx,edi
                inc ecx                  ;ECX = # of bytes to write

                add edi,SCRN_ADDR
                add edi,Y_base[ebx*4]

                ENDM

                ;
                ;SHADOW_MOVSB: If src_shadow NULL, do standard REP MOVSB 
                ;operation -- otherwise, write only changed bytes to
                ;destination memory
                ;
                ;Expects: DS:ESI,ES:EDI = src,dest ptrs
                ;                   ECX = # of bytes to move
                ;
                ;Destroys: EAX,EDX,EBX
                ;

SHADOW_MOVSB    MACRO
                LOCAL __write_4,__string_rem,__write_rest,__write_rem
                LOCAL __unshadowed,__done

                mov ebx,src_shadow
                and ebx,ebx
                je __unshadowed

                cmp ecx,2
                jl __write_rem

                push ecx
                shr ecx,1
                cmp ecx,4
                jl __string_rem
__write_4:
                REPT 4
                mov ax,WORD PTR [esi]
                cmp ax,WORD PTR [ebx][esi]
                je @F
                mov WORD PTR [edi],ax
                mov WORD PTR [ebx][esi],ax
@@:             add edi,2
                add esi,2
                ENDM

                sub ecx,4
                cmp ecx,4
                jge __write_4

__string_rem:   REPT 3
                dec ecx
                js __write_rest
                mov ax,WORD PTR [esi]
                cmp ax,WORD PTR [ebx][esi]
                je @F
                mov WORD PTR [edi],ax
                mov WORD PTR [ebx][esi],ax
@@:             add edi,2
                add esi,2
                ENDM

__write_rest:   pop ecx
                and ecx,1

__write_rem:    dec ecx
                jl __done
                mov al,BYTE PTR [esi]
                cmp al,BYTE PTR [ebx][esi]
                je __done
                mov BYTE PTR [edi],al
                mov BYTE PTR [ebx][esi],al
                jmp __done
                
__unshadowed:   REP_MOVSB   
__done:
                ENDM

                ;
                ;WRITE_LINE: EDI = X0
                ;            ECX = X1
                ;            EBX = Y
                ;            EAX = color byte (replicated)
                ;         
                ;            Destroys all registers

WRITE_LINE      MACRO
                LOCAL __exit

                BASCALC
                REP_STOSB                ;write entire line & exit

                ENDM

                ;
                ;COPY_LINE:  ESI -> source buffer
                ;            EDI = X0
                ;            ECX = X1
                ;            EBX = Y
                ;
                ;            Destroys all registers
                ;

COPY_LINE       MACRO
                LOCAL __split_line,__exit

                BASCALC
                SHADOW_MOVSB             ;write entire line & exit

                ENDM

                ;
                ;SCALE_LINE: ESI -> source buffer
                ;            EDX = # of source bytes
                ;            EDI = destination X0
                ;            ECX = destination X1
                ;            EBX = Y
                ;
                ;            Destroys all registers
                ;

SCALE_LINE      MACRO
                LOCAL __set_addr,__scale_loop

                ASSUME esi:NOTHING

                BASCALC

                mov ebx,ecx
                shl ebx,16              ;EBX = # of dest pixels (FP)

                shl edx,16
                mov eax,edx
                shr edx,16              
                shl eax,16              ;EDX:EAX = # of src pixels * 64K (FP)

                idiv ebx                ;EAX = quotient * 64K

                mov ebx,eax
                shr ebx,16              ;EBX = whole src/dest
                                        ;AX = fractional src/dest
                mov WORD PTR fraction,ax         

                mov dx,0

__scale_loop:   mov al,[esi]            ;fetch byte from source data
                IFDEF PHARLAP
                mov es:[edi],al         ;store at destination pointer
                ELSE
                mov BYTE PTR [edi],al   ;store at destination pointer
                ENDIF
                inc edi
         
                add dx,WORD PTR fraction
                adc esi,ebx

                dec ecx
                jnz __scale_loop
       
                ENDM


                ;
                ;READ_LINE:  ESI -> destination buffer
                ;            EDI = X0
                ;            ECX = X1
                ;            EBX = Y
                ;
                ;            Destroys all registers
                ;

READ_LINE       MACRO
                LOCAL __split_line,__exit

                BASCALC

                xchg esi,edi             ;setup for movsx

                IFDEF PHARLAP
                push ds
                push es
                pop ds
                pop es
                ENDIF

                REP_MOVSB                ;write entire line & exit

                IFDEF PHARLAP
                push ds
                push es
                pop ds
                pop es
                ENDIF

                xchg edi,esi

                ENDM

                ;
                ;READ_SCALE_LINE: ESI -> src buffer
                ;                 EDI -> dest buffer
                ;                 EDX = # of src bytes
                ;                 ECX = # of dest bytes
                ;
                ;                 Returns EDI -> next byte in dest
                ;                 Destroys all other registers
                ;


READ_SCALE_LINE MACRO
                LOCAL __scale_loop

                ASSUME esi:NOTHING

                mov ebx,ecx             ;ebx= # dest pixels
                shl ebx,16              ;EBX = # of dest pixels (FP)

                shl edx,16              
                mov eax,edx
                shr edx,16              
                shl eax,16              ;EDX:EAX = # of src pixels * 64K (FP)

                idiv ebx                ;EAX = quotient * 64K

                mov ebx,eax
                shr ebx,16              ;EBX = whole src/dest
                                        ;AX = fractional src/dest
                mov WORD PTR fraction,ax         

                mov dx,0

__scale_loop:   
                IFDEF PHARLAP
                mov al,es:[esi]         ;fetch byte from source data
                ELSE
                mov al,[esi]            ;fetch byte from source data
                ENDIF
                mov [edi],al            ;store at destination pointer
                inc edi
         
                add dx,WORD PTR fraction
                adc esi,ebx

                dec ecx
                jnz __scale_loop

                ENDM

                ;
                ;WND_REFRESH: ESI -> left edge of top line in source buffer
                ;       src_width =  # of bytes/source pane line
                ;       wnd_width =  # of bytes/window line
                ;
                ;Uses src_, dest_ vars in VFX_window_refresh()
                ;

WND_REFRESH     MACRO

                mov eax,dest_right
                sub eax,dest_left

                mov edx,dest_bottom
                sub edx,dest_top

                mov ebx,src_right
                sub ebx,src_left

                mov ecx,src_bottom
                sub ecx,src_top

                mov TY_steps,edx
                mov SY_steps,ecx

                cmp eax,ebx
                jne __XY_scale

                cmp edx,ecx
                je __block_copy

                ;
                ;Copy contents of window scaled in (Y) only
                ;

__Y_scale:      mov wndbuf,esi
                mov Y_value,0
                
                mov ecx,TY_steps
                inc ecx
                shl ecx,16              ;EBX = # of dest steps (FP)

                mov edx,SY_steps
                inc edx
                shl edx,16
                mov eax,edx
                shr edx,16              
                shl eax,16              ;EDX:EAX = # of src steps * 64K (FP)

                idiv ecx                ;EAX = quotient * 64K

                mov Y_fraction,ax       ;fractional src/dest

                mov ebx,eax
                shr ebx,16              
                mov Y_step,ebx          ;whole src/dest

                mov Y_accum,0

                mov ebx,dest_top

__Y_line:       mov eax,Y_value
                mul wnd_width
                mov esi,eax
                add esi,wndbuf

                mov edi,dest_left
                mov ecx,dest_right

                push ebx
                COPY_LINE
                pop ebx

__Y_next_line:  mov ax,Y_fraction
                add Y_accum,ax
                mov eax,Y_step
                adc Y_value,eax

                inc ebx
                cmp ebx,dest_bottom
                jle __Y_line

                jmp __return

                ;
                ;Copy contents of window scaled in (X) or (X and Y)
                ;

__XY_scale:     mov wndbuf,esi
                mov Y_value,0
                
                mov ecx,TY_steps
                inc ecx
                shl ecx,16              ;ECX = # of dest steps (FP)

                mov edx,SY_steps
                inc edx
                shl edx,16
                mov eax,edx
                shr edx,16              
                shl eax,16              ;EDX:EAX = # of src steps * 64K (FP)

                idiv ecx                ;EAX = quotient * 64K

                mov Y_fraction,ax       ;fractional src/dest

                mov ebx,eax
                shr ebx,16              
                mov Y_step,ebx          ;whole src/dest

                mov Y_accum,0

                mov ebx,dest_top
                
                mov eax,dest_right        
                sub eax,dest_left
                inc eax
                test eax,11b            ;multiple of 4 pixels to write?
                jnz __XY_line           ;no
                add eax,eax             ;2:1 scaling (e.g. 640:320)?
                cmp eax,src_width
                je __half_line          ;yes

__XY_line:      mov eax,Y_value
                mul wnd_width
                mov esi,eax
                add esi,wndbuf

                mov edi,dest_left
                mov ecx,dest_right
                mov edx,src_width

                push ebx
                SCALE_LINE
                pop ebx

                mov ax,Y_fraction
                add Y_accum,ax
                mov eax,Y_step
                adc Y_value,eax

                inc ebx
                cmp ebx,dest_bottom
                jle __XY_line

                jmp __return

                ;
                ;Do optimized 2:1 scaling in X if possible
                ;

__half_line:    push ebx
                
                mov eax,Y_value
                mul wnd_width
                mov esi,eax
                add esi,wndbuf

                mov edi,dest_left
                mov ecx,dest_right

                BASCALC

__scale_half:   mov eax,[esi+4]
                mov ebx,0
                mov bl,al
                shr eax,8
                mov bh,ah
                shl ebx,16
                mov eax,[esi]
                mov bl,al
                shr eax,8
                mov bh,ah

                IFDEF PHARLAP
                mov DWORD PTR es:[edi],ebx
                ELSE
                mov DWORD PTR [edi],ebx
                ENDIF

                add esi,8
                add edi,4
                sub ecx,4
                jg __scale_half

                mov ax,Y_fraction
                add Y_accum,ax
                mov eax,Y_step
                adc Y_value,eax

                pop ebx
                inc ebx
                cmp ebx,dest_bottom
                jle __half_line

                jmp __return

                ;
                ;Copy contents of window as unscaled block
                ;

__block_copy:   cmp src_stencil,0
                jne __st_copy
                
                mov ebx,dest_top

__block_line:   push ebx
                push esi
                mov edi,dest_left
                mov ecx,dest_right

                COPY_LINE

                pop esi
                pop ebx
                add esi,wnd_width

                inc ebx
                cmp ebx,dest_bottom
                jle __block_line
                jmp __return

                ;
                ;Perform unscaled block copy with stencil
                ;

__st_copy:      mov eax,dest_left
                sub eax,src_left
                mov src_to_dest,eax

                mov ebx,dest_top

                mov eax,src_top
                shl eax,2
                add eax,src_stencil

__for_line:     push esi
                mov dest_line_Y,ebx
                mov stencil_dir,eax

                mov src_left_addr,esi

                mov eax,dest_right
                sub eax,dest_left
                inc eax
                mov line_len,eax

                mov eax,0               ;EAX = packet left
                mov edx,stencil_dir     ;index first packet in stencil line
                mov edx,[edx]
                add edx,src_stencil
                dec edx
__st_clip_l:    inc edx                 ;fetch RLL packet from stencil
                mov ecx,0
                mov cl,BYTE PTR [edx]           
                and ecx,7fh             ;ECX = pixel count for current packet
                add eax,ecx             ;EAX = leftmost pixel in next packet
                cmp eax,src_left
                jle __st_clip_l

                mov ecx,src_left
                mov packet_left,ecx
                sub eax,ecx
                mov packet_len,eax

__st_clip_r:    mov eax,line_len
                sub eax,packet_len
                jge __set_len
                add packet_len,eax
                mov eax,0
__set_len:      mov line_len,eax

                cmp BYTE PTR [edx],80h
                jb __next_packet

                push edx
                mov edi,packet_left
                add edi,src_to_dest
                mov ecx,edi
                add ecx,packet_len
                dec ecx
                mov esi,src_left_addr
                mov ebx,dest_line_Y
                COPY_LINE
                pop edx

__next_packet:  cmp line_len,0
                je __next_line
                
                mov eax,packet_len
                add packet_left,eax
                add src_left_addr,eax

                inc edx
                mov eax,0
                mov al,BYTE PTR [edx]
                and eax,7fh
                mov packet_len,eax
                jmp __st_clip_r

__next_line:    pop esi
                mov ebx,dest_line_Y
                mov eax,stencil_dir

                add esi,wnd_width
                inc ebx
                add eax,SIZE DWORD

                cmp ebx,dest_bottom
                jle __for_line

                ENDM

                ;
                ;Data structure declarations
                ;

RGB             STRUC
R               db ?
G               db ?
B               db ?
RGB             ENDS

WINDOW          STRUCT
buffer          dd ?
x1              dd ?
y1              dd ?
stencil         dd ?
shadow          dd ?
WINDOW          ENDS

PWIN            TYPEDEF PTR WINDOW

PANE            STRUCT
win             dd ?
px0             dd ?
py0             dd ?
px1             dd ?
py1             dd ?
PANE            ENDS

PPANE           TYPEDEF PTR PANE

                ;
                ;Vector table at beginning of code segment
                ;Functions are C-callable via the following pointers
                ;

                .CODE

vector_table    dd OFFSET VFX_describe_driver           ;0
                dd OFFSET VFX_init_driver               ;1
                dd OFFSET VFX_shutdown_driver           ;2
                dd OFFSET VFX_area_wipe                 ;3
                dd OFFSET VFX_wait_vblank               ;4
                dd OFFSET VFX_wait_vblank_leading       ;5
                dd OFFSET VFX_window_refresh            ;6 (reentrant)
                dd OFFSET VFX_window_read               ;7 (reentrant)
                dd OFFSET VFX_DAC_read                  ;8
                dd OFFSET VFX_DAC_write                 ;9
                dd OFFSET VFX_bank_reset                ;10
                dd OFFSET VFX_pane_refresh              ;11 (reentrant)
                dd OFFSET VFX_line_address              ;12

num_vectors     equ ($-vector_table)/4

                dd 256-num_vectors dup (0)

                dd '1.00'

                db '386FX(TM) (C) 1992,1993 Miles Design, Inc.',01ah

                ;
                ;Internal static data
                ;

                ALIGN 2

Y_base          dd SCRN_H dup (?)               ;Y-row baseline addresses

                ;
                ;Flag definitions
                ;

VFX_RAMHEAP     equ 1                           ;1 if heap in system RAM
VFX_VIDHEAP     equ 2                           ;1 if heap in video RAM

                ;
                ;Driver description table
                ;

DRVR_DESC       LABEL WORD
                dd SCRN_W                       ;screen_width
                dd SCRN_H                       ;screen_height
                dd 1                            ;pixel_size
                dd 256                          ;ncolors
                dd 1                            ;npages
                dd VFX_RAMHEAP                  ;flags
                dd 0                            ;reserved

;*****************************************************************************
VFX_describe_driver PROC C USES ebx esi edi es

                lea eax,DRVR_DESC

                ret
VFX_describe_driver ENDP

;*****************************************************************************
VFX_wait_vblank PROC C USES ebx esi edi es

                ADDRESS_CRTC
                add dx,0ah                 

__while_not_V:  in al,dx                        ;wait while not in VBL
                test al,8        
                jz __while_not_V   

                ret
VFX_wait_vblank ENDP

;*****************************************************************************
VFX_wait_vblank_leading PROC C USES ebx esi edi es

                ADDRESS_CRTC
                add dx,0ah                 

__while_V:      in al,dx                        ;already in VBL interval?
                test al,8  
                jnz __while_V                   ;yes, wait for end

__while_not_V:  in al,dx                        ;else wait for beginning of 
                test al,8                       ;next VBL interval
                jz __while_not_V   

                ret
VFX_wait_vblank_leading ENDP

;*****************************************************************************
VFX_init_driver PROC C USES ebx esi edi es

                mov esi,0                       ;set up MCGA screen table
                mov eax,0
__MCGA_addr:    mov Y_base[esi*4],eax
                add eax,SCRN_W
                inc esi
                cmp esi,SCRN_H
                jne __MCGA_addr

__set_mode:     invoke VFX_wait_vblank_leading

                mov eax,13h                     ;set mode 13h (320x200x256)
                int 10h
                
                ret

VFX_init_driver ENDP

;*****************************************************************************
VFX_shutdown_driver PROC C USES ebx esi edi es

                mov eax,3                       ;set color text mode
                int 10h

                ret
VFX_shutdown_driver ENDP

;*****************************************************************************
VFX_area_wipe   PROC C USES ebx esi edi es\
                X0,Y0,X1,Y1,Color
                LOCAL color_rep

                cld

                IFDEF DPMI
                push ds
                pop es
                ELSEIFDEF PHARLAP
                mov ax,34h                      ;load ES with selector to
                mov es,ax                       ;lower 1MB 
                ENDIF

                mov eax,[Color]
                mov ah,al
                mov bx,ax
                shl eax,16
                mov ax,bx
                mov color_rep,eax

                mov ebx,[Y0]

__do_line:      push ebx
                mov edi,[X0]
                mov ecx,[X1]
                mov eax,color_rep

                WRITE_LINE

                pop ebx
                inc ebx
                cmp ebx,[Y1]
                jle __do_line

                ret
VFX_area_wipe   ENDP

;*****************************************************************************
VFX_window_refresh PROC C USES ebx esi edi es \
                SrcWnd:PTR,TargX0,TargY0,TargX1,TargY1
                LOCAL src_left,src_right,src_top,src_bottom
                LOCAL src_stencil,stencil_dir,src_to_dest,src_shadow
                LOCAL src_left_addr,dest_line_Y,packet_left,packet_len,line_len
                LOCAL dest_left,dest_right,dest_top,dest_bottom
                LOCAL TY_steps
                LOCAL SY_steps
                LOCAL src_width,wnd_width
                LOCAL Y_value,Y_step,Y_fraction:WORD,Y_accum:WORD
                LOCAL fraction
                LOCAL wndbuf
                
                ASSUME esi:PWIN

                cld

                IFDEF DPMI
                push ds
                pop es
                ELSEIFDEF PHARLAP
                mov ax,34h                      ;load ES with selector to
                mov es,ax                       ;lower 1MB 
                ENDIF

                mov esi,[SrcWnd]

                mov eax,[esi].stencil
                mov src_stencil,eax

                mov eax,[esi].shadow            ;if no shadow buffer, set
                cmp eax,0                       ;src_shadow to NULL 
                je __set_shadow
                sub eax,[esi].buffer            ;else pre-subtract buffer for
__set_shadow:   mov src_shadow,eax              ;faster indexing

                mov src_left,0

                mov eax,[esi].x1
                mov src_right,eax

                mov src_top,0

                mov eax,[esi].y1
                mov src_bottom,eax

                mov eax,src_right
                sub eax,src_left
                inc eax
                mov src_width,eax
                mov wnd_width,eax

                mov eax,[TargX0]
                cmp eax,SCRN_W-1
                jg __return                     ;dest to right of window
                cmp eax,0
                jg __dest_clip_l
                mov eax,0
__dest_clip_l:  mov dest_left,eax

                mov eax,[TargX1]
                cmp eax,0
                jl __return                     ;dest to left of window
                cmp eax,SCRN_W-1
                jl __dest_clip_r
                mov eax,SCRN_W-1
__dest_clip_r:  mov dest_right,eax

                mov eax,[TargY0]
                cmp eax,SCRN_H-1
                jg __return                     ;dest below window
                cmp eax,0
                jg __dest_clip_t
                mov eax,0
__dest_clip_t:  mov dest_top,eax

                mov eax,[TargY1]
                cmp eax,0
                jl __return                     ;dest above window
                cmp eax,SCRN_H-1
                jl __dest_clip_b
                mov eax,SCRN_H-1
__dest_clip_b:  mov dest_bottom,eax

                mov esi,[esi].buffer

                WND_REFRESH
__return:
                ret

VFX_window_refresh ENDP

;*****************************************************************************
VFX_pane_refresh PROC C USES ebx esi edi es \
                SrcPane:PTR,TargX0,TargY0,TargX1,TargY1
                LOCAL src_left,src_right,src_top,src_bottom
                LOCAL src_stencil,stencil_dir,src_to_dest,src_shadow
                LOCAL src_left_addr,dest_line_Y,packet_left,packet_len,line_len
                LOCAL dest_left,dest_right,dest_top,dest_bottom
                LOCAL TY_steps
                LOCAL SY_steps
                LOCAL src_width,wnd_width
                LOCAL Y_value,Y_step,Y_fraction:WORD,Y_accum:WORD
                LOCAL fraction
                LOCAL wndbuf
                
                ASSUME esi:PWIN
                ASSUME edi:PPANE

                cld

                IFDEF DPMI
                push ds
                pop es
                ELSEIFDEF PHARLAP
                mov ax,34h                      ;load ES with selector to
                mov es,ax                       ;lower 1MB 
                ENDIF

                mov edi,[SrcPane]
                mov esi,[edi].win

                mov eax,[esi].stencil
                mov src_stencil,eax

                mov eax,[esi].shadow            ;if no shadow buffer, set
                cmp eax,0                       ;src_shadow to NULL 
                je __set_shadow
                sub eax,[esi].buffer            ;else pre-subtract buffer for
__set_shadow:   mov src_shadow,eax              ;faster indexing

                mov eax,[esi].x1
                inc eax
                mov wnd_width,eax

                mov eax,[edi].px0
                cmp eax,[esi].x1
                jg __return                     ;pane to right of window
                cmp eax,0
                jg __pane_clip_l
                mov eax,0
__pane_clip_l:  mov src_left,eax

                mov eax,[edi].px1
                cmp eax,0
                jl __return                     ;pane to left of window
                cmp eax,[esi].x1
                jl __pane_clip_r
                mov eax,[esi].x1
__pane_clip_r:  mov src_right,eax

                mov eax,[edi].py0
                cmp eax,[esi].y1
                jg __return                     ;pane below window
                cmp eax,0
                jg __pane_clip_t
                mov eax,0
__pane_clip_t:  mov src_top,eax

                mov eax,src_right
                sub eax,src_left
                inc eax
                mov src_width,eax

                mov eax,[edi].py1
                cmp eax,0
                jl __return                     ;pane above window
                cmp eax,[esi].y1
                jl __pane_clip_b                
                mov eax,[esi].y1
__pane_clip_b:  mov src_bottom,eax

                mov eax,[TargX0]
                cmp eax,SCRN_W-1
                jg __return                     ;dest to right of window
                cmp eax,0
                jg __dest_clip_l
                mov eax,0
__dest_clip_l:  mov dest_left,eax

                mov eax,[TargX1]
                cmp eax,0
                jl __return                     ;dest to left of window
                cmp eax,SCRN_W-1
                jl __dest_clip_r
                mov eax,SCRN_W-1
__dest_clip_r:  mov dest_right,eax

                mov eax,[TargY0]
                cmp eax,SCRN_H-1
                jg __return                     ;dest below window
                cmp eax,0
                jg __dest_clip_t
                mov eax,0
__dest_clip_t:  mov dest_top,eax

                mov eax,[TargY1]
                cmp eax,0
                jl __return                     ;dest above window
                cmp eax,SCRN_H-1
                jl __dest_clip_b
                mov eax,SCRN_H-1
__dest_clip_b:  mov dest_bottom,eax

                ;
                ;Set ESI = starting address in source window
                ;

                mov eax,src_top

                mul wnd_width

                add eax,src_left

                add eax,[esi].buffer

                mov esi,eax

                ;
                ;Copy subarea of window
                ;

                WND_REFRESH
__return:
                ret

                ASSUME edi:NOTHING

VFX_pane_refresh ENDP

;*****************************************************************************
VFX_window_read PROC C USES ebx esi edi es\
                DstWnd:PTR,SrcX0,SrcY0,SrcX1,SrcY1
                LOCAL DX_steps,DY_steps
                LOCAL SX_steps,SY_steps
                LOCAL dest_width
                LOCAL Y_value,Y_step,Y_fraction:WORD,Y_accum:WORD
                LOCAL Y_count
                LOCAL wndbuf
                LOCAL fraction
                
                ASSUME esi:PWIN

                cld

                IFDEF DPMI
                push ds
                pop es
                ELSEIFDEF PHARLAP
                mov ax,34h                      ;load ES with selector to
                mov es,ax                       ;lower 1MB 
                ENDIF

                mov esi,[DstWnd]

                mov ebx,[esi].x1
                mov DX_steps,ebx

                mov ecx,[esi].y1
                mov DY_steps,ecx

                mov eax,[SrcX1]
                sub eax,[SrcX0]
                mov SX_steps,eax

                mov edx,[SrcY1]
                sub edx,[SrcY0]
                mov SY_steps,edx

                inc ebx
                mov dest_width,ebx
                dec ebx

                mov esi,[esi].buffer

                cmp eax,ebx             ;Compare Source & Dest width
                jne __XY_scale

                cmp edx,ecx             ;Compare Source & Dest height
                je __block_copy

                ;
                ;Copy contents of window scaled in (Y) only
                ;

__Y_scale:      mov wndbuf,esi
                mov Y_value,0
                
                mov ecx,DY_steps
                inc ecx
                shl ecx,16              ;EBX = # of dest steps (FP)

                mov edx,SY_steps
                inc edx
                shl edx,16
                mov eax,edx
                shr edx,16              
                shl eax,16              ;EDX:EAX = # of src steps * 64K (FP)

                idiv ecx                ;EAX = quotient * 64K

                mov Y_fraction,ax       ;fractional src/dest

                mov ebx,eax
                shr ebx,16              
                mov Y_step,ebx          ;whole src/dest

                mov Y_accum,0
                mov Y_count,0

__Y_line:
                mov ebx,Y_value         ;load source Y value
                mov edi,[SrcX0]         ;setup for a full line
                mov ecx,[SrcX1]

                READ_LINE

__Y_next_line:  mov ax,Y_fraction       ;compute new source Y value
                add Y_accum,ax
                mov eax,Y_step
                adc Y_value,eax

                inc Y_count
                mov eax,DY_steps
                cmp Y_count,eax
                jle __Y_line

                jmp __return

                ;
                ;Copy contents of window scaled in (X) or (X and Y)
                ;

__XY_scale:     mov wndbuf,esi
                mov Y_value,0
                
                mov ecx,DY_steps
                inc ecx
                shl ecx,16              ;ECX = # of dest steps (FP)

                mov edx,SY_steps
                inc edx
                shl edx,16
                mov eax,edx
                shr edx,16              
                shl eax,16              ;EDX:EAX = # of src steps * 64K (FP)

                idiv ecx                ;EAX = quotient * 64K

                mov Y_fraction,ax       ;fractional src/dest

                mov ebx,eax
                shr ebx,16              
                mov Y_step,ebx          ;whole src/dest

                mov Y_accum,0
                mov Y_count,0

__XY_line:      mov edi,[SrcX0]
                mov ecx,[SrcX1]
                mov ebx,Y_value

                BASCALC
                xchg esi,edi            ;ESI->scrn data, EDI->dest, ECX = cnt

                mov edx,ecx             ;EDX = # of bytes to read
                mov ecx,dest_width      ;ECX = # of bytes to write

                READ_SCALE_LINE

                mov esi,edi             ;update dest pointer

__XY_next_line: mov ax,Y_fraction
                add Y_accum,ax
                mov eax,Y_step
                adc Y_value,eax

                inc Y_count
                mov eax,DY_steps
                cmp Y_count,eax
                jle __XY_line

                jmp __return

                ;
                ;Copy contents of window as unscaled block
                ;

__block_copy:   mov ebx,[SrcY0]

__block_line:   push ebx
                push esi
                mov edi,[SrcX0]
                mov ecx,[SrcX1]

                READ_LINE

                pop esi
                pop ebx
                add esi,dest_width

                inc ebx
                cmp ebx,[SrcY1]
                jle __block_line

__return:       ret

VFX_window_read ENDP


;*****************************************************************************
VFX_DAC_read    PROC C USES ebx esi edi es\
                color_number,triplet:PTR

                pushfd
                cli

                cld
                push ds
                pop es

                mov dx,3c7h                     ;DAC Read Addr Register
                mov eax,[color_number]
                out dx,al
                jmp $+2

                mov dx,3c9h                     ;DAC Data Register
                mov edi,[triplet]
                ins BYTE PTR [edi],dx           ;Read r
                jmp $+2
                ins BYTE PTR [edi+1],dx         ;Read g
                jmp $+2
                ins BYTE PTR [edi+2],dx         ;Read b

                POP_F

                ret
VFX_DAC_read    ENDP

;*****************************************************************************
VFX_DAC_write   PROC C USES ebx esi edi es\
                color_number,triplet:PTR

                pushfd
                cli

                cld
                push ds
                pop es

                mov dx,3c8h                     ;Setup DAC Write Addr Reg
                mov eax,[color_number]
                out dx,al
                jmp $+2

                mov dx,3c9h                     ;DAC Data Register
                mov esi,[triplet]       
                outs dx,BYTE PTR [esi]          ;Write r
                jmp $+2
                outs dx,BYTE PTR [esi+1]        ;Write g
                jmp $+2
                outs dx,BYTE PTR [esi+2]        ;Write b

                POP_F

                ret
VFX_DAC_write   ENDP

;*****************************************************************************
VFX_bank_reset  PROC C USES ebx esi edi es

                ret
VFX_bank_reset  ENDP

;*****************************************************************************
VFX_line_address  PROC C USES ebx esi edi es\
                x_point,y_line,line_addr:PTR,nbytes:PTR

                mov edi,[x_point]
                mov ecx,SCRN_W-1

                mov ebx,[y_line]

                BASCALC

                mov esi,[line_addr]
                cmp esi,0
                je __skip_addr

                mov [esi],edi
                
__skip_addr:    mov esi,[nbytes]
                cmp esi,0
                je __skip_nbytes

                mov [esi],ecx

__skip_nbytes:  ret

VFX_line_address  ENDP
;*****************************************************************************

                END
