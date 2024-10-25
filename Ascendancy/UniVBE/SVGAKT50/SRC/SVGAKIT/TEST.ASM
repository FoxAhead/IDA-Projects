;****************************************************************************
;*
;*                        	  The SuperVGA Kit
;*
;*                  Copyright (C) 1994 SciTech Software
;*                          All rights reserved.
;*
;* Filename:    $RCSfile: test.asm $
;* Version:     $Revision: 1.1 $
;*
;* Language:    80386 Assembler
;* Environment: IBM PC Real Mode and 16/32 bit Protected Mode.
;*
;* Description: Assembly language test routines for the SuperVGA Kit
;*				SVGATEST.EXE and PROFILE.EXE programs. These routines have
;*				been moved to this module as they are not part of the
;*				SuperVGA Kit proper as such.
;*
;* $Id: test.asm 1.1 1994/08/22 12:27:12 kjb release $
;*
;****************************************************************************

		IDEAL

INCLUDE "model.mac"             ; Memory model macros

header  test                    ; Set up memory model

CRTC    EQU 3D4h        		; Port of CRTC registers

		$EXTRN  _maxx,UINT
		$EXTRN  _maxy,UINT
		$EXTRN  _maxcolor,ULONG
		$EXTRN  _maxpage,UINT
		$EXTRN  _bytesperline,USHORT
		$EXTRN  _pagesize,ULONG
		$EXTRN  _curBank,UINT

		EXTRN	setBank:FPTR
		EXTRN	setReadBank:FPTR

begcodeseg	test

;----------------------------------------------------------------------------
; void _copyTest16(void)
;----------------------------------------------------------------------------
; Routine to copy the top half of video memory to the bottom half of
; video memory. To ensure that we a moving across a bank boundary in
; 16 color modes, we copy the data to the second video page.
;----------------------------------------------------------------------------
procstart   __copyTest16

		enter_c	0
		push    ds					; Save registers

        mov     _ax,[_maxy]
        inc     ax
        shr     ax,1                ; AX := (Yres+1) / 2
        mul     [_bytesperline]
        mov     cx,ax               ; CX := Number of bytes to move

; Set up graphics controller

        mov     dx,3CEh             ; DX := Graphics Controller address port
        mov     ax,0105h            ; AH := 1 (read mode 0, write mode 1)
                                    ; AL := 5 (Mode register number)
        out     dx,ax               ; Set up mode

		mov     di,[USHORT _pagesize] ; ES:DI := offset into destination buffer
		mov     ax,[USHORT _pagesize+2]
		add     di,cx
		adc     al,0
        call    setBank             ; Set the read/write bank number

        xor     si,si               ; DS:SI := offset into source buffer
		xor     ax,ax
        call    setReadBank         ; Set the read bank number

		mov		ax,0A000h
		mov     ds,ax               ; DS:SI -> source buffer
        mov     es,ax               ; ES:DI -> destination buffer
        cld                         ; Moves go up in memory

    rep movsb                       ; Move all data in bank FAST!

; Restore default graphics controller state

		mov     dx,3CEh             ; DX := Graphics Controller address port
		mov     ax,0005h            ; default mode register value
        out     dx,ax

		pop     ds
		leave_c
		ret

procend     __copyTest16

;----------------------------------------------------------------------------
; void _copyTest256(void)
;----------------------------------------------------------------------------
; Routine to copy the top half of video memory to the bottom half of
; video memory, to test moving data across bank boundaries using separate
; read/write banks. To simplify the coding we move the first 100 scan
; lines down to start at scanline 205. This ensure allows us to move data
; from bank 0 to bank 2 in 640x??? display modes.
;----------------------------------------------------------------------------
procstart   __copyTest256

		enter_c	0
		push    ds					; Save registers

        mov     ax,100
        mul     [_bytesperline]
        mov     cx,ax               ; CX := Number of bytes to move
		shr     cx,1                ; CX := Number of USHORTs to move

        mov     ax,205
        mul     [_bytesperline]
		mov     di,ax               ; DI := offset into destination bank
		mov		al,dl
		call    setBank             ; Set the read/write bank number

		xor     si,si               ; DS:SI := offset into source buffer
		xor     al,al
        call    setReadBank         ; Set the read bank number

		mov		ax,0A000h
		mov     ds,ax               ; DS:SI -> source buffer
        mov     es,ax               ; ES:DI -> destination buffer
        cld                         ; Moves go up in memory

    rep movsw                       ; Move all data in bank FAST!

		pop     ds
		leave_c
		ret

procend     __copyTest256

;----------------------------------------------------------------------------
; void bltImage(char *p,int numBanks,int lastBytes)
;----------------------------------------------------------------------------
; Blts and image from a memory bank to the display. This routine does
; a simple full screen Blt, and is intended to test the speed of performing
; such Blts in 32 bit protected mode for specific resolutions. This code
; will only work in 32 bit protected mode, as we need to work with _huge_
; memory blocks in a linear fashion (it will however work with the 320x200
; 256 color standard VGA mode in real mode).
;----------------------------------------------------------------------------
procstart	_bltImage

		ARG		p:DPTR, numBanks:UINT, lastBytes:UINT

		enter_c	0
		use_ds
		push	es

		mov		ax,fs
		mov		es,ax
		xor		_di,_di				; ES:_DI -> start of video memory
		_lds	_si,[p]				; DS:_SI -> memory block to Blt
		xor		dl,dl				; DL := first bank number
		mov     dh,[BYTE numBanks]  ; DH := number of full banks to fill
		or		dh,dh
		jz		@@DoPartial			; Only a single bank to handle

; Move all of the full 64k banks first

@@OuterLoop:
		mov		al,dl
		call    setBank
		mov     _cx,4000h           ; Need to set 4000h DWORDS per bank
	rep movsd
		xor		_di,_di
		inc     dl
		dec     dh
		jnz     @@OuterLoop

; Now fill the last partial bank

@@DoPartial:
		mov		al,dl
		call    setBank
		mov     _cx,[lastBytes]
		shr     _cx,2               ; _CX := number of DWORDs to set
	rep movsd

		pop		es
		unuse_ds
		leave_c
		ret

procend		_bltImage

endcodeseg	test

		END
