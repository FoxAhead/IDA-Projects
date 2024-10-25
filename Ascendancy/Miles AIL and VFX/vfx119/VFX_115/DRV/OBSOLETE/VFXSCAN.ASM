;лллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллллл
;лл                                                                        лл
;лл  VFXSCAN.ASM                                                           лл
;лл                                                                        лл
;лл  VFX DLL for auto-detection of Extended VGA chipsets                   лл
;лл                                                                        лл
;лл  Version 1.00 of 26-Sep-92: Initial version                            лл
;лл          1.10 of 17-Nov-93: Phar Lap support added                     лл
;лл                                                                        лл
;лл  Project: 386FX Sound & Light(TM)                                      лл
;лл  Authors: John Miles, John Lemberger                                   лл
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

                ;
                ;Vector table at beginning of code segment
                ;Functions are C-callable via the following pointers
                ;

                .CODE

vector_table    dd OFFSET VFX_driver_name

num_vectors     equ ($-vector_table)/4

                dd 256-num_vectors dup (0)

                dd '1.00'

                db '386FX(TM) (C) 1992,1993 Miles Design, Inc.',01ah

                ;
                ;Names of supported drivers
                ;

TSENG4_asc      db 'TSENG4.DLL',0
WD1A_asc        db 'WD1A.DLL',0 
HT205_asc       db 'HT205.DLL',0 
HT216_asc       db 'HT216.DLL',0 
TRIDENT_asc     db 'TRIDENT.DLL',0
S3_asc          db 'VESA480.DLL',0
ATI_asc         db 'ATI.DLL',0
OAK_asc         db 'OAK.DLL',0
OAK87_asc       db 'OAK87.DLL',0
CLGD542X_asc    db 'CLGD542X.DLL',0
W5186_asc       db 'VESA480.DLL',0   ;changed from W5186.DLL pending P9000 fix
AHEAD5A_asc     db 'AHEAD5A.DLL',0
AHEAD5B_asc     db 'AHEAD5B.DLL',0
CT450_asc       db 'CT450.DLL',0
CT451_asc       db 'CT451.DLL',0
;               ...
VESA400_asc     db 'VESA400.DLL',0
VESA480_asc     db 'VESA480.DLL',0
MCGA_asc        db 'MCGA.DLL',0

                ;
                ;Internal static data
                ;

                ALIGN 4

CRTC_port       dw ?                  ;CRTC port I/O address

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

selector        dd ?
save_es         dw ?

                ;
                ;Verify support for desired VESA mode
                ;

VMODE_DETECT    MACRO ModeNum
                LOCAL __exit,__fail_exit

                IFDEF PHARLAP

                mov ebx,16
                mov eax,25c0h
                int 21h

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
                ;Get info for desired mode
                ;

                IFDEF PHARLAP

                mov interrupt_num,10h
                mov register_eax,4f01h
                mov ecx,[ModeNum]

                mov eax,2511h
                mov edx,OFFSET X32_real_int
                int 21h

                push eax

                mov cx,save_es                  ;free MODE_INFO block
                mov eax,25c1h
                int 21h

                pop eax

                ELSEIFDEF DPMI

                mov eax,4f01h                   ;BIOS return SVGA Info
                mov int_AX,ax

                mov eax,[ModeNum]
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

                mov eax,101h                    ;free MODE_INFO block
                mov edx,selector
                int 31h

                mov ax,int_AX

                ENDIF

                cmp ax,4fh
                je __exit                       ;400 mode supported
__fail_exit:
                xor ax,ax                       ;Clear AX if VESA mode invalid
__exit:
                ENDM

;*****************************************************************************
WD1A_detect     PROC C USES ebx esi edi es      ;Attempt to detect WD PVGA1A/
                                                ;90C11/90C30 or compatible
                pushfd
                cli

                mov cx,0                        ;assume bad

                IFDEF PHARLAP

                mov ax,34h
                mov es,ax

                cmp WORD PTR es:[0c007dh],'GV'  ;WD BIOS if *c000:007d 'VGA='
                jne __exit
                cmp WORD PTR es:[0c007fh],'=A'
                jne __exit

                ELSEIFDEF DPMI

                cmp WORD PTR ds:[0c007dh],'GV'  ;WD BIOS if *c000:007d 'VGA='
                jne __exit
                cmp WORD PTR ds:[0c007fh],'=A'
                jne __exit

                ENDIF

                mov cx,1                        ;assume good

                mov dx,03cch                    ;get DX=CRTC address at 3B0h
                in al,dx                        ;(mono) or 3D0h (color)
                and al,1
                shl al,5
                mov dx,03b0h
                add dl,al
                mov CRTC_port,dx

                mov dx,3ceh                     ;unlock WD PRxx registers
                mov ax,50fh                     ;data=05h  index=0fh
                out dx,ax

                mov dx,3c4h
                mov ax,4806h
                out dx,ax

                mov dx,CRTC_port                ;Check for PVGA1A
                add dx,4
                mov al,2bh                      ;select index 2bh
                out dx,al

                inc dx                          
                in al,dx                        ;read data from 2bh
                mov bl,al
                mov al,0aah                     ;write an aah
                out dx,al

                in al,dx                        ;read it back
                mov bh,al
                mov al,bl
                out dx,al                       ;restore original value

                cmp bh,0aah                     ;PVGA1A?
                je __lock                       ;yes

                mov dx,3c4h                     ;Select Misc Control
                mov al,12h
                out dx,al

                inc dx                          ;Read register
                in al,dx
                mov bl,al                       ;store value
                and al,0bfh                     ;clear bit 6
                out dx,al                       ;write it

                in al,dx                        ;read it back
                and al,40h                      ;WD 90C00?
                jnz __lock                      ;yes

                mov al,bl                       ;restore original value
                or al,40h                       ;set bit 6
                out dx,al                       ;write it

                in al,dx                        ;read it back
                and al,40h                      ;WD 90C00?
                jz __lock                       ;yes

                mov al,bl                       ;restore original value
                out dx,al

                mov cx,0                        ;assume bad

                mov dx,3c4h                     ;select extended register
                mov al,10h
                out dx,al
                inc dx

                in al,dx                        ;read register
                mov bl,al                       ;store value
                and al,0fbh                     ;clear bit 3
                out dx,al                       ;write it

                in al,dx                        ;read it back
                and al,04h                      ;WD 90C10?
                jnz __restore                   ;if so, no 640x400x256 mode!

                mov al,bl                       ;restore original
                or al,04h                       ;set bit 3
                out dx,al

                in al,dx                        ;read it back
                and al,04h                      ;WD 90C10?
                jz __restore                    ;if so, no 640x400x256 mode!

                mov cx,1

__restore:      mov al,bl                       ;restore original value
                out dx,al

__lock:         mov dx,3ceh                     ;lock WD PRxx registers
                mov ax,000fh
                out dx,ax

                mov dx,3c4h
                mov ax,0006h
                out dx,ax

__exit:         movzx eax,cx

                POP_F
                ret

WD1A_detect     ENDP

;*****************************************************************************
Tseng4_detect   PROC C USES ebx esi edi es      ;Attempt to detect Tseng Labs
                                                ;ET4000 or compatible
                pushfd
                cli

                mov dx,03cch                    ;get DX=CRTC address at 3B0h
                in al,dx                        ;(mono) or 3D0h (color)
                and al,1
                shl al,5
                mov dx,03b0h
                add dl,al
                mov CRTC_port,dx

                mov cx,0                        ;assume ET4000 not found

                mov dx,CRTC_port                ;wait for vsync leading to
                add dx,10                       ;avoid snow
__vsync:	in al,dx
	test al,8
	jnz __vsync
__not_vsync:    in al,dx
                test al,8
                jz __not_vsync

                mov al,3
                mov dx,3bfh
                out dx,al

                mov dx,3cch
                in al,dx
                and al,1
                mov dx,3d8h
                jnz __detect_1
                mov dx,3b8h
__detect_1:     mov al,0a0h
                out dx,al
                
                mov dx,3dah
                in al,dx
                mov dx,3c0h
                mov al,16h
                out dx,al
                mov dx,3c1h
                in al,dx
                mov bl,al

                mov dx,3dah
                in al,dx
                mov dx,3c0h
                mov al,16h
                out dx,al
                mov al,bl
                xor al,10h
                out dx,al

                mov dx,3dah
                in al,dx
                mov dx,3c0h
                mov al,16h
                out dx,al
                mov dx,3c1h
                in al,dx
                mov bh,al

                mov dx,3dah
                in al,dx
                mov dx,3c0h
                mov al,16h
                out dx,al
                mov al,bl
                out dx,al
                
                mov dx,3dah
                in al,dx
                mov dx,3c0h
                mov al,20h
                out dx,al

                mov al,bl
                xor al,10h
                cmp al,bh
                jne __exit                      ;not Tseng chip, exit

                mov cx,1
                jmp __exit

                mov dx,CRTC_port

                mov al,33h
                out dx,al
                inc dx

                in al,dx
                mov bl,al

                xor al,0fh
                out dx,al
                in al,dx
                mov bh,al

                mov al,bl
                out dx,al

                xor bl,0fh
                cmp bl,bh
                jne __exit                      ;not ET4000, exit

                mov cx,1

__exit:         movzx eax,cx

                POP_F
                ret
                
Tseng4_detect   ENDP

;*****************************************************************************
TRIDENT_detect  PROC C USES ebx esi edi es      ;Attempt to detect Trident
                                                ;TVGA8900C CL 9000 8800
                pushfd
                cli

                mov ecx,200h                    ;Look at first 512 bytes
                mov esi,0c0000h                 ;Start of Video BIOS

                IFDEF PHARLAP
                mov ax,34h
                mov es,ax
                ELSEIFDEF DPMI
                push ds
                pop es
                ENDIF

__check_dword:
                mov eax,es:[esi]
                or eax,20202020h                ;Convert to lower case
                cmp eax,'dirt'                  ;Look for Trident copyright

                jne __next_dword

                add esi,3
                mov eax,es:[esi]                ;
                or eax,20202020h                ;Convert to lower case
                cmp eax,'tned'                  ;Look for Trident copyright

                je __check_chipset              ;It is a Trident BIOS

__next_dword:
                inc esi
                loop __check_dword

                xor eax,eax                     ;Not a Trident
                jmp __exit

__check_chipset:

                mov dx,3c4h                     
                mov al,0bh                      ;Select Hardware Ver. reg
                out dx,al

                inc dx                          ;Set New Mode format
                in  al,dx                       ;& read H/W version

                cmp al,1                        ;8800BR
                jne __not_8800BR                ;Not 8800BR 

                mov ax,1                        ;return 8800BR flag
                jmp __exit

__not_8800BR:
                mov dx,3c4h                     
                mov al,0eh                      ;Select Mode Ctrl #1 Reg
                out dx,al

                inc dx                          ;save current value
                in  al,dx
                xor ax,2                        ;complement bit 1
                mov ah,al

                and al,0fdh                     ;write a zero to bit 1
                out dx,al

                in  al,dx                       ;read it back
                
                xchg al,ah                      ;restore previous value
                out dx,al

                mov al,ah
                and ax,2                        ;If bit was inverted then
                                                ;it is a Trident
__exit:
                POP_F
                ret
                
TRIDENT_detect  ENDP

;*****************************************************************************
S3_detect       PROC C USES ebx esi edi es      ;Attempt to detect 
                                                ;S3 86C911,924,801,805,928
                pushfd
                cli

                ADDRESS_CRTC                    ;Get DX=CRTC address
                add dx,4                       

                mov al,38h                      ;Select S3 Reg Lock 1
                out dx,al

                inc dx                          ;Goto I/O port

                mov al,48h                      ;Unlock S3 Registers
                out dx,al

                dec dx                          ;Goto Index port

                mov al,30h                      ;Select Chip ID Register
                out dx,al

                inc dx                          ;Goto I/O port

                mov al,0                        ;Attempt to overwrite
                out dx,al

                in al,dx                        ;Read Chip ID Register

                xor ah,ah                       

                cmp al,81h                      ;81h = S3 86C911 Chip
                je __exit

                cmp al,82h                      ;82h = S3 86C924 Chip
                je __exit

                cmp al,90h                      ;90h = S3 86C928 Chip
                je __exit

                cmp al,0a0h                     ;a0h = S3 86C801/805 Chip
                je __exit

                xor ax,ax                       ;Clear AX if not an S3

__exit:
                POP_F
                ret
                
S3_detect       ENDP

;*****************************************************************************
ATI_detect      PROC C USES ebx esi edi es      ;Attempt to detect ATI

                pushfd
                cli

                IFDEF PHARLAP
                mov ax,34h
                mov es,ax
                ELSEIFDEF DPMI
                push ds
                pop es
                ENDIF

                mov esi,0c0031h                 ;load ptr to BIOS signature

                mov eax,es:[esi]                ;check 1st 4 bytes
                cmp eax,'2167'
                jne __fail_exit

                mov eax,es:[esi+4]              ;check 2nd 4 bytes
                cmp eax,'2559'
                jne __fail_exit

                mov al,BYTE PTR es:[esi+8]      ;check last byte
                cmp al,'0'
                jne __fail_exit

                je __exit

__fail_exit:
                xor ax,ax                       ;Clear AX if not an ATI

__exit:
                POP_F
                ret
                
ATI_detect      ENDP

;*****************************************************************************
OAK_detect      PROC C USES ebx esi edi es      ;Attempt to detect ATI

                pushfd
                cli

	mov	dx,3DEh
	mov	al,1Ah
	out	dx,al			
	nop
	in	al,dx			
	cmp	al,5Ah			;Oak 67 test
	je	__check_ram

	cmp	al,7Ah			;Oak ?? test
	je	__check_ram

	cmp	al,0BAh	   		;Oak 77 test
	jne	__check_87

__check_ram:
                mov	dx,3DEh
	mov	al,0Dh                  ;OTI Misc Register
	out	dx,al			;port 3DEh
	inc	dx
	in	al,dx			;port 3DFh
	and	al,80h                  ;clear all but DRAM cfg.
	cmp	al,0
	jne	__exit			;Jump if >256k ram
                                                ;OAK doesn't have 640x400
                mov     ax,1
                jmp     __exit

__check_87:
                and     al,11110000b
	cmp	al,10h			;Oak 87 test
                mov     eax,087h                ;
	je	__exit     	        ;Jump if equal

__fail_exit:
                xor     ax,ax                   ;Clear AX if not an OAK

__exit:
                POP_F
                ret
                
OAK_detect      ENDP

;*****************************************************************************
VESA_detect     PROC C USES ebx esi edi es      ;Attempt to detect VESA BIOS

                pushfd
                cli

                mov eax,4f03h                   ;Return current video mode
                int 10h

                cmp al,4fh                      ;If supported, VESA installed
                je __exit

__fail_exit:
                xor ax,ax                       ;Clear AX if no VESA

__exit:
                POP_F
                ret
                
VESA_detect     ENDP

;*****************************************************************************
VESA400_detect  PROC C USES ebx esi edi es      ;Attempt to detect VESA BIOS

                pushfd
                cli

                VMODE_DETECT 100h               ;640x400 256-color mode

                POP_F
                ret
                
VESA400_detect  ENDP

;*****************************************************************************
VESA480_detect  PROC C USES ebx esi edi es      ;Attempt to detect VESA BIOS

                pushfd
                cli

                VMODE_DETECT 101h               ;640x480 256-color mode

                POP_F
                ret
                
VESA480_detect  ENDP

;*****************************************************************************
CLGD542X_detect PROC C USES ebx esi edi es      ;Attempt to detect Cirrus

                pushfd
                cli

	mov dx,3c4h
	mov ax,1206h
	out dx,ax			
                inc dx
                in al,dx
                mov ah,1
                cmp al,12h
                jne __fail_exit         ;assume 5401

                mov dx,3d4h
                mov al,27h
                out dx,al
                inc dx
                in al,dx
                mov ah,3
                cmp al,8ah
                jne __exit              ;5420

                shr al,2
                mov ah,4
                cmp al,23h
                je  __exit              ;5422

                mov ah,5
                cmp al,25h
                je __exit               ;5424

                mov ah,6
                cmp al,24h
                je __exit               ;5426

__fail_exit:
                xor ax,ax               ;Clear AX if not an CLGD542X
__exit:
                mov al,ah
                POP_F
                ret

CLGD542X_detect ENDP

;*****************************************************************************
HT216_detect    PROC C USES ebx esi edi es      ;Check for Headland BIOS

                pushfd
                cli

                mov ax,6f00h
                int 10h
                cmp bx,'V7'
                jnz __fail_exit

                mov ax,6f07h
                int 10h

                mov ax,bx

                jmp __exit 

__fail_exit:
                xor ax,ax                       ;Clear AX if no HT

__exit:
                POP_F
                ret
                
HT216_detect    ENDP

;*****************************************************************************
W5186_detect    PROC C USES ebx esi edi es      ;Check for Weitek 5186

                pushfd
                cli

                mov dx,03c4h
                mov al,7
                out dx,al

                inc dx
                in al,dx
                mov ah,al
                and ah,11100000b
                cmp ah,00100000b                ;check for ID=001
                jne __fail_exit

                and al,00011111b                ;write ID=000
                out dx,al
                in al,dx
                and al,11100000b
                cmp al,00100000b                ;check for ID=001
                je __exit

__fail_exit:
                xor ax,ax                       ;Clear AX if no W5186

__exit:
                POP_F
                ret
                
W5186_detect    ENDP

;*****************************************************************************
AHEAD_detect    PROC C USES ebx esi edi es      ;Check for Ahead V5000 A or B

                pushfd
                cli

                mov dx,03ceh
                mov al,0fh
                out dx,al

                inc dx
                mov al,20h
                out dx,al

                jmp $+2
                jmp $+2
                jmp $+2

                in al,dx

                cmp al,20h                      ;check for V5000A
                je __exit

                cmp al,21h                      ;check for V5000B
                je __exit

__fail_exit:
                xor ax,ax                       ;Clear AX if not AHEAD

__exit:
                POP_F
                ret
                
AHEAD_detect    ENDP

;*****************************************************************************
CT45x_detect    PROC C USES ebx esi edi es      ;Check for CT45x

                pushfd
                cli

                mov dx,46e8h                    ;put VGA into Setup Mode
                mov al,1eh
                out dx,al

                mov dx,104h                     ;Global ID register
                in al,dx
                cmp al,0a5h                     ;Is it a Chips & Tech. 45x?
                jne __fail_exit

                mov dx,0103h                    ;enable C&T extension regs
                in al,dx
                or al,80h
                out dx,al

                mov dx,46e8h                    ;exit C&T VGA Setup Mode
                mov al,0eh
                out dx,al

                ADDRESS_CRTC                    ;select Chip Version reg.
                add dx,6
                mov al,0
                out dx,al

                inc dx                          ;read chip version &
                in al,dx                        ;clear revision info.
                and al,0f0h

                cmp al,50h                      ;check for 456
                je __exit_451
                cmp al,40h                      ;check for 450
                je __exit_450
                cmp al,30h                      ;check for 453
                je __exit_450
                cmp al,20h                      ;check for 455
                je __exit_451
                cmp al,10h                      ;check for 451 or 452
                jne __fail_exit

                ADDRESS_CRTC
                add dx,6
                mov al,03ah
                out dx,al                       ;Graphics Cursor Color Reg.
                inc dx
                in al,dx                        ;Read current value
                mov ah,al                       ;save it in ah
                mov al,0aah                     
                out dx,al                       ;modify reg.
                in al,dx                        ;read it back
                xchg al,ah                      ;retore register
                out dx,al

                cmp ah,0aah                     ;check for 452
                je __exit_450

__exit_451:     mov ax,1                        ;Return 451 cmptbl. flag
                jmp __exit

__exit_450:     mov ax,2                        ;Return 450 cmptbl. flag
                jmp __exit

__fail_exit:
                mov dx,46e8h                    ;exit VGA Setup Mode
                mov al,0eh
                out dx,al

                xor ax,ax                       ;Clear AX if not CT45x

__exit:
                POP_F
                ret
                
CT45x_detect    ENDP

;*****************************************************************************
VFX_driver_name PROC C USES ebx esi edi es

                invoke AHEAD_detect             ;perform Ahead V5000 A & B 
                cmp al,20h                      ;chipset detection
                jne __Chk_Ahead5B
                lea eax,AHEAD5A_asc
                jmp __exit
__Chk_Ahead5B:  cmp al,21h              
                lea eax,AHEAD5B_asc
                je __exit

                invoke HT216_detect             ;perform Headland detection
                cmp al,60h
                jl __Chk_HT205
                cmp al,70h
                jge __Chk_HT205
                lea eax,HT216_asc
                jmp __exit
__Chk_HT205:
                or ax,ax
                lea eax,HT205_asc
                jnz __exit

                invoke WD1A_detect              ;perform WD chipset detection
                or ax,ax
                lea eax,WD1A_asc
                jnz __exit

                invoke S3_detect                ;perform S3 chipset 
                or ax,ax                        ;detection
                lea eax,S3_asc                  ;(supported via VESA for now)
                jnz __exit

                invoke OAK_detect               ;perform OAK chipset 
                cmp al,87h                      ;chipset detection
                jne __Chk_Oak67
                lea eax,OAK87_asc
                jmp __exit
__Chk_Oak67:
                cmp al,1                        ;(is OAK but only 256k)
                je __MCGA                      
                or ax,ax        
                lea eax,OAK_asc
                jnz __exit

                invoke ATI_detect               ;perform ATI chipset 
                or ax,ax                        ;detection
                lea eax,ATI_asc
                jnz __exit

                invoke CLGD542X_detect          ;perform CLGD542X chipset 
                or ax,ax                        ;detection
                lea eax,CLGD542X_asc
                jnz __exit

                invoke W5186_detect             ;perform W5186 chipset 
                or ax,ax                        ;detection
                lea eax,W5186_asc
                jnz __exit

                invoke CT45x_detect             ;perform CT45x chipset 
                cmp ax,1
                jne __Chk_CT450
                lea eax,CT451_asc
                jmp __exit
__Chk_CT450:    cmp ax,2
                lea eax,CT450_asc
                je __exit

;               ...                             ;(for future expansion)

                ;
                ;Warning: Trident must be tested after Oak and Cirrus
                ;

                invoke TRIDENT_detect           ;perform Trident 8900C Chipset 
                cmp al,1                        ;is 8800BR no 640x400
                je __MCGA                       ;
                or ax,ax                        ;detection
                lea eax,TRIDENT_asc
                jnz __exit

                ;
                ;Warning: Tseng 4000 must be tested after Trident
                ;

                invoke Tseng4_detect            ;perform ET4000 chipset 
                or ax,ax                        ;detection
                lea eax,TSENG4_asc
                jnz __exit

                invoke VESA_detect              ;perform VESA BIOS 
                or ax,ax                        ;detection
                jz __MCGA

                invoke VESA400_detect           ;perform VESA 640x400x256 mode
                or ax,ax                        ;detection
                lea eax,VESA400_asc
                jnz __exit

                invoke VESA480_detect           ;perform VESA 640x480x256 mode
                or ax,ax                        ;detection
                lea eax,VESA480_asc
                jnz __exit
__MCGA:
                lea eax,MCGA_asc                ;if all else fails, use MCGA
__exit:                                         ;with driver auto-scaling
                ret

VFX_driver_name ENDP

	END
