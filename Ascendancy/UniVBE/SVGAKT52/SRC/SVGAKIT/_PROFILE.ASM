;****************************************************************************
;*
;*			The SuperVGA Kit - UniVBE Software Development Kit
;*
;*                  Copyright (C) 1994 SciTech Software
;*                          All rights reserved.
;*
;* Filename:    $RCSfile: _profile.asm $
;* Version:     $Revision: 1.2 $
;*
;* Language:    80386 Assembler
;* Environment: IBM PC Real Mode and 16/32 bit Protected Mode.
;*
;* Description: Assembly language test routines for the SuperVGA Kit
;*				PROFILE.EXE program.
;*
;* $Id: _profile.asm 1.2 1995/09/16 10:45:13 kjb release $
;*
;****************************************************************************

		IDEAL

INCLUDE "model.mac"             ; Memory model macros

header  _profile                    ; Set up memory model

		$EXTRN  _maxx,UINT
		$EXTRN  _maxy,UINT
		$EXTRN  _maxcolor,ULONG
		$EXTRN  _maxpage,UINT
		$EXTRN  _bytesperline,USHORT
		$EXTRN  _pagesize,ULONG
		$EXTRN  _curBank,UINT
		$EXTRN	_videoMem,DPTR

		EXTRN	setBank:FPTR

begcodeseg	_profile

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

		_les	_di,[_videoMem]		; EDI -> start of video memory
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
		push	_di
	rep movsd
		pop		_di
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

		unuse_ds
		leave_c_nolocal
		ret

procend		_bltImage

;----------------------------------------------------------------------------
; void bltImageLin(char *p,uint numBytes)
;----------------------------------------------------------------------------
procstart	_bltImageLin

        ARG     p:DPTR, numBytes:UINT

		enter_c	0
		use_ds

		_les	_di,[_videoMem]		; ES:_DI -> start of video memory
		_lds	_si,[p]				; DS:_SI -> memory block to Blt
		mov		_cx,[numBytes]
		shr		_cx,2				; Convert from bytes to DWORDS
		cld
	rep	movsd						; Copy all DWORDS's fast!

		unuse_ds
        leave_c_nolocal
		ret

procend		_bltImageLin

;----------------------------------------------------------------------------
; void clearSysBuf(void *buffer,long value,uint len)
;----------------------------------------------------------------------------
procstart	_clearSysBuf

		ARG		buffer:DPTR, value:ULONG, len:UINT

		enter_c	0

		force_es_eq_ds
		_les    _di,[buffer]	; ES:_DI -> memory block
		mov		_cx,[len]
		shr		_cx,2			; Convert from bytes to DWORDS
		mov		eax,[value]		; EAX := value to store
		cld
	rep	stosd					; Store all middle DWORD's fast!

        leave_c_nolocal
		ret

procend		_clearSysBuf

;----------------------------------------------------------------------------
; void copySysBuf(void *buffer,char *image,uint len)
;----------------------------------------------------------------------------
procstart	_copySysBuf

		ARG		buffer:DPTR, image:DPTR, len:UINT

		enter_c	0
		use_ds

		force_es_eq_ds
		_les    _di,[buffer]	; ES:_DI -> destination block
		_lds	_si,[image]		; DS:_SI -> source block
		mov		_cx,[len]
		shr		_cx,2			; Convert from bytes to DWORDS
		cld
	rep	movsd					; Copy all DWORDS's fast!

		unuse_ds
        leave_c_nolocal
		ret

procend		_copySysBuf

endcodeseg	_profile

		END
