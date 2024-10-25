;лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
;лл                                                                        лл
;лл  AHEAD.ASM                                                             лл
;лл                                                                        лл
;лл  VFX driver DLL for Ahead V5000A & V5000B SVGA chip                    лл
;лл                                                                        лл
;лл  Version 1.00 of 12-Jan-93: Initial version                            лл
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

                OPTION SCOPED   ;Enable local labels

                .386            ;Enable 386 instructions
                .MODEL FLAT,C   ;32-bit OS/2 model

                INCLUDE vfx.mac

SCRN_ADDR       equ 0a0000h                     ;Flat-model screen address

SCRN_W          equ 640                         ;Screen width in pixels
SCRN_H          equ 400                         ;Screen height in pixels

BANK_INC        equ 1                           ;Increment value for Bank Swt

;*****************************************************************************
                ;
                ;SET_BANK: Sets EVGA bank
                ;
                ;Expects:  AL = 000000PS
                ;
                ;Destroys: AX,DX
                ;

                IFDEF V5000A

SET_BANK        MACRO
                LOCAL   __skip_neg                

                mov ah,al               ;save bank number

                mov dx,03cch            ;read page bit
                in al,dx
                and al,11011111b        ;clear bit 5 (page bit)
                shr ah,1
                jc __skip_neg           ;bit 5 = NOT (LSB of bank#)
                or al,00100000b         ;set bit 5 (page bit)

__skip_neg:
                mov dx,03c2h            ;write new page bit
                out dx,al

                mov dx,03ceh
                mov al,0dh
                out dx,al

                inc dx
                in al,dx
                and al,11111000b        ;clear bank bits
                or al,ah                ;copy new bank bits
                out dx,al               ;write to port

                ENDM

                ELSEIFDEF V5000B

SET_BANK        MACRO

                mov dx,03ceh            ;select IO address port
                mov ah,al
                mov al,0dh
                out dx,ax       

                ENDM

                ENDIF

SET_READ_BANK   MACRO
                LOCAL __skip

                cmp ax,read_shadow
                je __skip
                mov read_shadow,ax
                mov write_shadow,ax     ;read==write
                SET_BANK
__skip:
                ENDM

SET_WRITE_BANK  MACRO
                LOCAL __skip

                cmp ax,write_shadow
                je __skip
                mov write_shadow,ax
                mov read_shadow,ax      ;read==write
                SET_BANK 
__skip:
                ENDM

;*****************************************************************************

                INCLUDE vfxdrv.inc

;*****************************************************************************
VFX_init_driver PROC C USES ebx esi edi es

                cld
                IFDEF DPMI
                push ds
                pop es
                ELSEIFDEF PHARLAP
                mov ax,34h                      ;load ES with selector to
                mov es,ax                       ;lower 1MB 
                ENDIF

                mov read_shadow,-1              ;invalidate shadow registers
                mov write_shadow,-1
                mov entry_count,0               ;zero entry count

                mov esi,0
                mov dx,0
                mov ax,0
__VGAChip_addr: mov Y_base[esi*2],ax            ;set up addressing tables
                mov Y_bank[esi*2],dx
                inc esi
                cmp esi,SCRN_H
                je __VGAChip_init
                add ax,SCRN_W
                jnc __VGAChip_addr
                add dx,BANK_INC
                jmp __VGAChip_addr

__VGAChip_init: mov edi,0                       ;(nonzero to preserve screen)

                invoke VFX_wait_vblank_leading

                mov eax,60h                     ;640x400x256 AHEAD mode
                cmp edi,0                       
                jne __set_MCGA
                or ebx,80h
__set_MCGA:     int 10h                         

                mov dx,03ceh                    ;unlock AHEAD extended regs
                mov ax,200fh
                out dx,ax

                cmp edi,0                       ;clearing screen?
                jne __set_regs

                mov dx,3c4h                     ;yes, disable CRT to 
                mov al,0                        ;avoid flicker
                out dx,al
                inc dx
                in al,dx
                and al,11111100b
                out dx,al

                mov dx,3c4h
                mov al,1                        
                out dx,al
                inc dx
                in al,dx
                or al,00100000b
                out dx,al
  
                mov dx,3c4h      
                mov al,0                    
                out dx,al
                inc dx
                in al,dx
                or al,00000011b
                out dx,al

__set_regs:     
                pushfd
                cli                             ;turn off all interrupts

                cmp edi,0                       ;clearing screen memory?
                jne __VGAChip_set_b             ;no, done

                mov ebx,4                       ;clear 5 banks (256K) of
                mov eax,0
__clear_bank:   mov edi,SCRN_ADDR               ;VGAChip screen memory

                SET_WRITE_BANK

                mov eax,0
                mov ecx,4000h
                rep stosd
                mov ax,write_shadow
                add ax,BANK_INC
                dec ebx
                jnz __clear_bank

                invoke VFX_wait_vblank_leading

                mov dx,3c4h                     ;re-enable CRT display
                mov al,0                        
                out dx,al
                inc dx
                in al,dx
                and al,11111100b
                out dx,al

                mov dx,3c4h
                mov al,1                        
                out dx,al
                inc dx
                in al,dx
                and al,11011111b
                out dx,al

                mov dx,3c4h      
                mov al,0                    
                out dx,al
                inc dx
                in al,dx
                or al,00000011b
                out dx,al

__VGAChip_set_b:
                POP_F

                mov ax,0                 ;page=0 seg=0
                SET_WRITE_BANK

                mov ax,0
                SET_READ_BANK

                ret

VFX_init_driver ENDP

;*****************************************************************************
VFX_shutdown_driver PROC C USES ebx esi edi es

                mov eax,3                        ;set text mode
                int 10h

                ret

VFX_shutdown_driver ENDP

;*****************************************************************************

                END
