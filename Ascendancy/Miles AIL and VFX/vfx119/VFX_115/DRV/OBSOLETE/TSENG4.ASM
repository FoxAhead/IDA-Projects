;лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
;лл                                                                        лл
;лл  TSENG4.ASM                                                            лл
;лл                                                                        лл
;лл  VFX driver DLL for Tseng Labs ET4000-based video adapters             лл
;лл                                                                        лл
;лл  Version 1.00 of 17-Sep-92: Initial version                            лл
;лл          1.10 of 17-Nov-93: Phar Lap support added                     лл
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

                OPTION SCOPED	;Enable local labels

        	.386		;Enable 386 instructions
                .MODEL FLAT,C	;32-bit OS/2 model

                INCLUDE vfx.mac

SCRN_ADDR       equ 0a0000h                     ;Flat-model screen address

SCRN_W          equ 640                         ;Screen width = 640 pixels
SCRN_H          equ 400                         ;Screen height = 400 pixels

USE_BANK_INC    equ 1                           ;Use bank_inc instead of 1
BANK_INC        equ 11h                         ;Increment value for Bank Swt

;*****************************************************************************
                ;
                ;SET_BANK: Set 64K EVGA bank AL = BANK NUMBER
                ;Preserves all registers (except DX)
                ;

SET_BANK        MACRO

                mov dx,3cdh              ;select bank
                out dx,al

                ENDM

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
__Tseng_addr:   mov Y_base[esi*2],ax            ;set up addressing tables
                mov Y_bank[esi*2],dx
                inc esi
                cmp esi,SCRN_H
                je __Tseng_init
                add ax,SCRN_W
                jnc __Tseng_addr
                add dx,BANK_INC
                jmp __Tseng_addr

__Tseng_init:   mov edi,0                       ;(nonzero to preserve screen)

                invoke VFX_wait_vblank_leading

                mov eax,13h                     ;set 320x200 resolution first
                cmp edi,0                       ;to establish base mode
                jne __set_MCGA
                or eax,80h
__set_MCGA:     int 10h                         

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

__set_regs:     pushfd
                cli                             ;turn off all interrupts

                mov ebx,0
__update_AC:    mov dx,ds:[463h]
                add dx,6
                in al,dx                        ;reset AC flip-flop

                mov dx,3c0h                 
                mov al,bl
                out dx,al
                mov al,ATTRIB_TSENG[ebx]        ;set new attributes for 
                out dx,al                       ;640x400 mode
                mov dx,ds:[463h]
                add dx,6
                in al,dx
                mov dx,3c0h
                mov al,20h
                out dx,al
                inc ebx
                cmp ebx,21
                jne __update_AC

                mov dx,ds:[463h]        
                lea esi,CRTC_TSENG              ;ESI -> CRTC registers table
                mov al,11h                      ;deprotect registers 0-7
                mov ah,ds:[esi+11h]
                and ah,7fh
                out dx,ax

                mov ecx,18h                     ;set new CRTC controller
                mov ebx,0                       ;values for 640x400 mode
__update_CRTC:  mov al,bl                       
                mov ah,ds:[ebx+esi]         
                out dx,ax
                inc ebx                          
                loop __update_CRTC

                POP_F                           ;restore interrupt status

                cmp edi,0                       ;clearing screen memory?
                jne __Tseng_set_b               ;no, done

                mov bx,0                        ;clear 4 banks (256K) of
__clear_bank:   mov edi,SCRN_ADDR               ;Tseng ET4000 screen memory
                mov ax,bx

                SET_WRITE_BANK

                mov eax,0
                mov ecx,4000h
                rep stosd
                add bx,BANK_INC
                cmp bx,44h
                jne __clear_bank

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

__Tseng_set_b:  
                mov ax,0
                SET_WRITE_BANK

                mov ax,0
                SET_READ_BANK

                ret

VFX_init_driver ENDP

;*****************************************************************************
ATTRIB_TSENG    db 000h,001h,002h,003h          ;Tseng ET4000 AC for 640x400
                db 004h,005h,006h,007h          ;256-color mode
                db 008h,009h,00Ah,00Bh 
                db 00Ch,00Dh,00Eh,00Fh 
                db 001h,000h,00Fh,000h 
                db 000h 

CRTC_TSENG      db 05fh,04fh,050h,082h          ;Tseng ET4000 CRTC for 640x400
                db 054h,080h,0bfh,01fh          ;256-color mode
                db 000h,040h,00dh,00eh
                db 000h,000h,003h,0c0h
                db 09ch,08eh,08fh,050h
                db 060h,096h,0b9h,0abh

;*****************************************************************************
VFX_shutdown_driver PROC C USES ebx esi edi es

                mov eax,3                        ;set text mode
                int 10h

                ret

VFX_shutdown_driver ENDP

;*****************************************************************************

	END
