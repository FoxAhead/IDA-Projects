;лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
;лл                                                                        лл
;лл  VESA400.ASM                                                           лл
;лл                                                                        лл
;лл  VFX driver DLL for video adapters supporting VESA 640x400x256 mode    лл
;лл                                                                        лл
;лл  Version 1.00 of 17-Sep-92: Initial version                            лл
;лл          1.10 of 17-Nov-93: Phar Lap support added                     лл
;лл                                                                        лл
;лл  Project: 386FX Sound & Light(TM)                                      лл
;лл  Authors: John Miles & John Lemberger                                  лл
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

                OPTION SCOPED	;Enable local labels

        	.386		;Enable 386 instructions
                .MODEL FLAT,C	;32-bit OS/2 model

                INCLUDE vfx.mac

SCRN_ADDR       equ 0a0000h                     ;Flat-model screen address

                IFDEF VESA768
SCRN_W          equ 1024                        ;Screen width = 640 pixels
                ELSE
SCRN_W          equ 640                         ;Screen width = 640 pixels
                ENDIF
                
                IFDEF VESA400
VMODE_NUM       equ 100h                        ;Vesa mode 100h 640x400x256
SCRN_H          equ 400                         ;Screen height = 400 pixels
                ELSEIFDEF VESA480
VMODE_NUM       equ 101h                        ;Vesa mode 101h 640x480x256
SCRN_H          equ 480                         ;Screen height = 400 pixels
                ELSEIFDEF VESA768
VMODE_NUM       equ 105h                        ;Vesa mode 101h 1024x768x256
SCRN_H          equ 768                         ;Screen height = 768 pixels
                ENDIF

USE_BANK_INC    equ 1

;*****************************************************************************
                ;
                ;SET_BANK: Sets EVGA bank
                ;
                ;Expects:  AL = 000000PS
                ;
                ;Destroys: AX,DX
                ;

SET_READ_BANK   MACRO
                LOCAL __skip

                cmp ax,read_shadow
                je __skip
                mov read_shadow,ax
                mov write_shadow,ax     ;(also changes write)

                pushfd                  ;VESA drivers may not be re-entrant,
                cli                     ;so shut off IRQs

                push esi
                push edi
                push ecx
                push ebx

                movzx edx,ax            ;Load bank #
                push edx

                mov ebx,0               ;Select SVGA Memory Window 0
                mov eax,4f05h           ;BIOS CPU Video Memory Wnd Ctrl
                int 10h

                pop edx

                mov ebx,1               ;Select SVGA Memory Window 1
                mov eax,4f05h           ;BIOS CPU Video Memory Wnd Ctrl
                int 10h

                pop ebx
                pop ecx
                pop edi
                pop esi

                POP_F
__skip:
                ENDM

SET_WRITE_BANK  MACRO
                LOCAL __skip

                cmp ax,write_shadow
                je __skip
                mov write_shadow,ax
                mov read_shadow,-1      ;(invalidates read)

                pushfd                  ;VESA drivers may not be re-entrant,
                cli                     ;so shut off IRQs

                push esi
                push edi
                push ecx
                push ebx

                mov ebx,0               ;Select SVGA Memory Window 0
                movzx edx,ax            ;Load bank #
                mov eax,4f05h           ;BIOS CPU Video Memory Wnd Ctrl
                int 10h

                pop ebx
                pop ecx
                pop edi
                pop esi

                POP_F
__skip:
                ENDM

;*****************************************************************************

                INCLUDE vfxdrv.inc

;*****************************************************************************
VFX_init_driver PROC C USES ebx esi edi es

                cld
                push ds
                pop es

                mov read_shadow,-1              ;invalidate shadow registers
                mov write_shadow,-1
                mov entry_count,0               ;zero entry count

                IFDEF PHARLAP

                mov ebx,16
                mov eax,25c0h
                int 21h

                mov selector,34h

                mov save_es,ax
                mov selector_es,ax
                mov di,0

                ELSEIFDEF DPMI

                mov eax,100h                    ;allocate real mode memory
                mov ebx,16                      ;get 256 bytes for MODE_INFO
                int 31h

                mov selector,edx                ;save the selector

                mov int_ES,ax                   ;setup real ptr to MODE_INFO
                mov int_DI,0

                ENDIF

                ;
                ;Get mode info for VESA 640x4?0 256 color mode
                ;

                IFDEF PHARLAP

                mov interrupt_num,10h
                mov register_eax,4f01h
                mov ecx,VMODE_NUM

                mov eax,2511h
                mov edx,OFFSET X32_real_int
                int 21h

                push es
                mov es,selector
                movzx edi,selector_es
                shl edi,4

                ELSEIFDEF DPMI

                mov eax,4f01h                   ;BIOS return SVGA Info
                mov int_AX,ax

                mov eax,VMODE_NUM               ;VESA 640x(400||480)x256 mode
                mov int_CX,ax

                mov int_DS,0
                pushf
                pop ax
                mov int_flags,ax

                mov eax,0300h                   ;DPMI function
                mov ebx,0010h                   ;Int 10h
                mov ecx,0
                lea edi,DPMI_real_int
                int 31h                         ;DPMI Interrupt

                push es                         ;load es with MODE_INFO selct
                mov eax,selector
                mov es,ax
                mov edi,0                       ;edi = MODE_INFO offset

                ENDIF

                mov eax,64                      ;Divide 64 by granularity
                xor edx,edx                     ;to get bank inc value
                div es:[edi].MODE_INFO.WinGranularity   
                mov bank_inc,ax                 

                mov esi,0
                mov edx,0
                mov eax,0
__VGAChip_addr: mov Y_base[esi*2],ax            ;set up addressing tables
                mov Y_bank[esi*2],dx
                inc esi
                cmp esi,SCRN_H
                je __VGAChip_init
                add ax,es:[edi].MODE_INFO.BytesPerScanLine
                jnc __VGAChip_addr
                add dx,bank_inc
                jmp __VGAChip_addr

__VGAChip_init: pop es

                IFDEF PHARLAP

                mov cx,save_es
                mov eax,25c1h
                int 21h

                ELSEIFDEF DPMI

                mov eax,101h                    ;free MODE_INFO block
                mov edx,selector
                int 31h

                ENDIF

                invoke VFX_wait_vblank_leading

                mov eax,4f02h                   ;select SVGA Mode Set
                mov ebx,VMODE_NUM               ;VESA 640x(400||480)x256 mode
                int 10h                         

                mov ax,0
                SET_WRITE_BANK

                mov ax,0
                SET_READ_BANK
__exit:
                ret

VFX_init_driver ENDP

;*****************************************************************************
MODE_INFO       STRUC
ModeAttributes  dw ?                            ;VESA Mode Info            
WinAAttributes  db ?
WinBAttributes  db ?
WinGranularity  dw ?
WinSize         dw ?
WinASegment     dw ?
WinBSegment     dw ?
WinFunctPtr     dd ?
BytesPerScanLine dw ?
extra_buffer     db 255 dup (?)       
MODE_INFO       ENDS


;------------------------------------------------------------------
                IFDEF DPMI
DPMI_real_int   LABEL BYTE            ;DPMI real-mode interrupt structure

int_DI          dw ?                  ;*** MUST REMAIN CONTIGUOUS ***
                dw 0            
int_SI          dw ?
                dw 0
int_BP          dw ?
                dw 0
                dd 0
int_BX          dw ?
                dw 0
int_DX          dw ?
                dw 0
int_CX          dw ?
                dw 0
int_AX          dw ?
                dw 0
int_flags       dw ?
int_ES          dw ?
int_DS          dw ?
                dw 0
                dw 0
                dw 0
                dw 0
                dw 0
                dw 0

                ELSEIFDEF INT21
X32_real_int    LABEL BYTE            ;Flashtek X32 real-mode int structure

interrupt_num   dw ?                  ;*** MUST REMAIN CONTIGUOUS ***
selector_ds     dw ?
selector_es     dw ?
selector_fs     dw ?
selector_gs     dw ?
register_eax    dd ?
register_edx    dd ?

                ENDIF

bank_inc        dw ?

save_es         dw ?
selector        dd ?

;*****************************************************************************
VFX_shutdown_driver PROC C USES ebx esi edi es

                mov eax,3                        ;set text mode
                int 10h

                ret

VFX_shutdown_driver ENDP

;*****************************************************************************


	END
