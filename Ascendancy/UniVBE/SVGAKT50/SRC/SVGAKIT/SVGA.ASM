;****************************************************************************
;*
;*                        	  The SuperVGA Kit
;*
;*                  Copyright (C) 1994 SciTech Software
;*                          All rights reserved.
;*
;* Filename:    $RCSfile: svga.asm $
;* Version:     $Revision: 1.1 $
;*
;* Language:    80386 Assembler
;* Environment: IBM PC Real Mode and 16/32 bit Protected Mode.
;*
;* Description: Assembly language support routines for the SuperVGA test
;*              library. All the code here assumes that the video memory
;*				selector has been cached in the FS selector before the
;*				code is called.
;*
;* $Id: svga.asm 1.1 1994/08/22 12:27:00 kjb release $
;*
;****************************************************************************

		IDEAL

INCLUDE "model.mac"             ; Memory model macros

header  svga                    ; Set up memory model

CRTC    EQU 3D4h        		; Port of CRTC registers

		$EXTRN  _maxx,UINT
		$EXTRN  _maxy,UINT
		$EXTRN  _maxcolor,ULONG
		$EXTRN  _maxpage,UINT
		$EXTRN  _bytesperline,USHORT
		$EXTRN  _pagesize,ULONG
		$EXTRN  _curBank,UINT
		$EXTRN  _bankSwitch,ULONG
		$EXTRN  _bankShift,UINT
		$EXTRN  _writeBank,ULONG	; Relocated write bank routine
		$EXTRN  _readBank,ULONG 	; Relocated read bank routine
		$EXTRN	_extendedflipping,BOOL

begdataseg	svga

originOffset	DW	?				; Offset of current page in buffer
bankOffset		DW	?				; Bank offset in total video memory

enddataseg	svga

begcodeseg	svga

;----------------------------------------------------------------------------
; int _setFS(unsigned sel)
;----------------------------------------------------------------------------
; Set the FS register to the specified selector value. This register is
; never changed, so we only ever need to do it once (to save time with
; expensive selector loads in protected mode).
;----------------------------------------------------------------------------
procstart	__setFS

		ARG		sel:UINT

		push	_bp
		mov		_bp,_sp
		mov		_ax,[sel]
		mov     cx,fs
		mov		fs,ax
		mov		ax,cx
		pop		_bp
		ret

procend		__setFS

;----------------------------------------------------------------------------
; PixelAddr16	Determine buffer address of pixel in SVGA 16 color modes
;----------------------------------------------------------------------------
;
; Entry:		_AX	-	y-coordinate
;				_BX	-	x-coordinate
;
; Exit:			AH	-	bit mask
;				_BX	-	byte offset in buffer
;				CL	-	number of bits to shift left
;				_SI	-	64k bank number of the address
;				FS	-	video buffer segment
;
; Registers:	none.
;
;----------------------------------------------------------------------------
PROC	PixelAddr16	near

		push	_dx					; Save DX
		mul		[_bytesperline]		; DX:AX := y * BytesPerLine
		mov		cl,bl				; CL := low-order byte of x

		shr		_bx,3				; _BX := x/8
		add		bx,ax
		adc		dl,0				; DL:_BX := y*BytesPerLine + x/8
		add		bx,[originOffset]	; _BX := byte offset in video buffer
		adc		dl,[BYTE bankOffset]; DL := bank number
		mov		_si,_dx				; _SI := bank number

		mov		ah,1				; AH := unshifted bit mask
		and		cl,7				; CL := x & 7
		xor		cl,7				; CL := # bits to shift left

		pop		_dx
		ret

ENDP	PixelAddr16

;----------------------------------------------------------------------------
; PixelAddr256	Determine buffer address of pixel in SVGA 256 color modes
;----------------------------------------------------------------------------
;
; Entry:		_AX	-	y-coordinate
;				_BX	-	x-coordinate
;
; Exit:			_BX	-	byte offset in buffer
;				_DX	-	64k bank number of the address
;				FS	-	video buffer segment
;
; Registers:	None.
;
;----------------------------------------------------------------------------
PROC	PixelAddr256	near

		mul		[_bytesperline]		; DX:AX := y * bytesperline
		add		bx,ax
		adc		dx,0				; DX:_BX := y * BytesPerLine + x
		add		bx,[originOffset]
		adc		dl,[BYTE bankOffset]; DL := bank number
		ret

ENDP	PixelAddr256

;----------------------------------------------------------------------------
; PixelAddr32k	Determine buffer address of pixel in SVGA 32k color modes
;----------------------------------------------------------------------------
;
; Entry:		_AX	-	y-coordinate
;				_BX	-	x-coordinate
;
; Exit:			_BX	-	byte offset in buffer
;				_DX	-	64k bank number of the address
;				FS	-	video buffer segment
;
; Registers:	None.
;
;----------------------------------------------------------------------------
PROC	PixelAddr32k	near

		mul		[_bytesperline]		; DX:AX := y * bytesperline
		shl		_bx,1
		add		bx,ax
		adc		dx,0				; DX:BX := y * BytesPerLine + x * 2
		add		bx,[originOffset]
		adc		dl,[BYTE bankOffset]; DL := bank number
		ret

ENDP	PixelAddr32k

;----------------------------------------------------------------------------
; PixelAddr16m	Determine buffer address of pixel in SVGA 16m color modes
;----------------------------------------------------------------------------
;
; Entry:		_AX	-	y-coordinate
;				_BX	-	x-coordinate
;
; Exit:			_BX	-	byte offset in buffer
;				_DX	-	64k bank number of the address
;				FS	-	video buffer segment
;
; Registers:	None.
;
;----------------------------------------------------------------------------
PROC	PixelAddr16m	near

		mul		[_bytesperline]		; DX:AX := y * bytesperline
		add		ax,bx
		shl		_bx,1
		add		bx,ax
		adc		dx,0				; DX:BX := y * BytesPerLine + x * 3
		add		bx,[originOffset]
		adc		dl,[BYTE bankOffset]; DL := bank number
		ret

ENDP	PixelAddr16m

;----------------------------------------------------------------------------
; PixelAddr4G	Determine buffer address of pixel in SVGA 32k color modes
;----------------------------------------------------------------------------
;
; Entry:		_AX	-	y-coordinate
;				_BX	-	x-coordinate
;
; Exit:			_BX	-	byte offset in buffer
;				_DX	-	64k bank number of the address
;				FS	-	video buffer segment
;
; Registers:	None.
;
;----------------------------------------------------------------------------
PROC	PixelAddr4G	near

		mul		[_bytesperline]		; DX:AX := y * bytesperline
		shl		_bx,2
		add		bx,ax
		adc		dx,0				; DX:BX := y * BytesPerLine + x * 2
		add		bx,[originOffset]
		adc		dl,[BYTE bankOffset]; DL := bank number
		ret

ENDP	PixelAddr4G

;----------------------------------------------------------------------------
; void clear16(long color)
;----------------------------------------------------------------------------
; Routine to clear the screen. Works even if the display contains more than
; one bank, so will work for 1024x768 and 1280x1024 video modes.
;----------------------------------------------------------------------------
procstart   __clear16

		ARG		color:ULONG

		enter_c	0
		push	es

; Setup graphics controller

        mov     dx,3CEh             ; DX := Graphics Controller I/O port

		mov     ah,[BYTE color]		; AH := Background color
        xor     al,al               ; AL := 0 (Set/Reset register number)
        out     dx,ax               ; load set/reset register

        mov     ax,0F01h            ; AH := 1111b (mask for Enable set/reset)
                                    ; AL := 1 (enable Set/reset reg number)
        out     dx,ax               ; load enable set/reset reg

		mov     _ax,[_maxy]
		inc     _ax
        mul     [_bytesperline]     ; DX:AX := number of bytes to fill
        mov     bx,ax               ; BX := bytes in last bank to fill
        mov     dh,dl               ; DH := number of full banks to fill

		mov		ax,fs
		mov		es,ax
		xor		_di,_di             ; ES:_DI -> video memory
		add     di,[originOffset]
		mov     ax,[bankOffset]     ; AX := starting bank number
        cld                         ; Moves go up in memory

        or      dh,dh               ; More than one bank to fill?
        jz      @@SingleBank        ; No, only fill a single bank

; Fill all of the full 64k banks first

@@OuterLoop:
		call    setBank
		mov     _cx,4000h            ; Need to set 4000h double USHORTs per bank
	rep stosd
		xor		_di,_di
		inc     al
        dec     dh
        jnz     @@OuterLoop

; Now fill the last partial bank

@@SingleBank:
		call    setBank
		xor		_cx,_cx
		mov     cx,bx
		shr     _cx,2                ; _CX := number of double USHORTs to set
    rep stosd

; Restore graphics controller

        mov     dx,3CEh             ; DX := Graphics Controller I/O port
        xor     ax,ax               ; AH := 0, AL := 0
        out     dx,ax               ; Restore default Set/Reset register

        inc     ax                  ; AH := 0, AL := 1
        out     dx,ax               ; Restore enable Set/Reset register

		pop		es
		leave_c
		ret

procend     __clear16

;----------------------------------------------------------------------------
; void clear256(long color)
;----------------------------------------------------------------------------
; Routine to clear the screen. Assumes pages begin on bank boundaries
; for simplicity of coding.
;----------------------------------------------------------------------------
procstart   __clear256

		ARG		color:ULONG

		enter_c 0
		push	es

		xor		eax,eax
		mov		al,[BYTE color]
		mov		ebx,eax
		shl		ebx,8
		or		eax,ebx
		mov		ebx,eax
		shl		ebx,16
		or		eax,ebx
		mov		[color],eax			; Color = 32 bit color value

        mov     _ax,[_maxy]
        inc     _ax
        mul     [_bytesperline]     ; DX:AX := number of bytes to fill
        mov     bx,ax               ; BX := bytes in last bank to fill
        mov     dh,dl               ; DH := number of full banks to fill

		mov		ax,fs
		mov		es,ax
		xor		_di,_di				; ES:_DI -> start of video memory
		add     di,[originOffset]
		mov     dl,[BYTE bankOffset]; DL := starting bank number
        cld                         ; Moves go up in memory

        or      dh,dh               ; More than one bank to fill?
        jz      @@SingleBank        ; No, only fill a single bank

; Fill all of the full 64k banks first

@@OuterLoop:
		mov     al,dl
		call    setBank
		mov		eax,[color]
		mov     _cx,4000h           ; Need to set 4000h double USHORTs per bank
	rep stosd
		xor		_di,_di
		inc     dl
        dec     dh
        jnz     @@OuterLoop

; Now fill the last partial bank

@@SingleBank:
		mov     al,dl
		call    setBank
		mov		eax,[color]
		xor     _cx,_cx
        mov     cx,bx
		shr     _cx,2               ; _CX := number of double USHORTs to set
    rep stosd

		pop		es
        leave_c
		ret

procend     __clear256

;----------------------------------------------------------------------------
; void clear32k(long color)
;----------------------------------------------------------------------------
; Routine to clear the screen. Assumes pages begin on bank boundaries
; for simplicity of coding.
;----------------------------------------------------------------------------
procstart   __clear32k

		ARG		color:ULONG

		enter_c	0
		push	es

		xor		eax,eax
		mov		ax,[WORD color]
		mov		ebx,eax
		shl		ebx,16
		or		eax,ebx
		mov		[color],eax			; Color = 32 bit color value

		mov     _ax,[_maxy]
		inc     _ax
        mul     [_bytesperline]     ; DX:AX := number of bytes to fill
        mov     bx,ax               ; BX := bytes in last bank to fill
        mov     dh,dl               ; DH := number of full banks to fill

		mov		ax,fs
		mov		es,ax
		xor		_di,_di				; ES:_DI -> start of video memory
		add     di,[originOffset]
		mov     dl,[BYTE bankOffset]; DL := starting bank number
        cld                         ; Moves go up in memory

; Fill all of the full 64k banks first

@@OuterLoop:
		mov     al,dl
		call    setBank
		mov		eax,[color]
		mov     _cx,4000h           ; Need to set 4000h double USHORTs per bank
	rep stosd
		xor		_di,_di
		inc     dl
		dec     dh
		jnz     @@OuterLoop

; Now fill the last partial bank

		mov     al,dl
		call    setBank
		mov		eax,[color]
		xor		_cx,_cx
        mov     cx,bx
		shr     _cx,2               ; _CX := number of double USHORTs to set
    rep stosd

		pop		es
		leave_c
		ret

procend     __clear32k

;----------------------------------------------------------------------------
; void clear16m(long color)
;----------------------------------------------------------------------------
; Routine to clear the screen. Assumes pages begin on bank boundaries
; for simplicity of coding.
;----------------------------------------------------------------------------
procstart   __clear16m

		ARG		color:ULONG

		enter_c	0
		push	_bp

		xor		_bx,_bx				; FS:_BX -> start of video memory
		add     bx,[originOffset]
		mov     dl,[BYTE bankOffset]; DL := starting bank number
		mov		ax,dx
		call	setBank				; Change to starting bank number

		mov		_di,[_maxx]
		inc		_di					; _DI := number of pixels to draw
		mov		_si,[_maxy]
		inc		_si					; _SI := number of lines to process
		mov		ax,[WORD color]		; AX := pixel color
		mov		dh,[BYTE color+2]	; DH := top byte of pixel color
		mov		bp,di
		shl		bp,1
		add		bp,di				; BP := bytes per physical scanline
		sub		bp,[_bytesperline]
		neg		bp					; BP := scanline adjust factor

@@NextScanLine:
		mov		_cx,_di

@@LoopSolid:
		cmp		bx,0FFFDh
		jae		@@BankSwitch		; Bank switch occurs!

		mov		[WORD fs:_bx],ax	; Set pixel value in buffer
		mov		[BYTE fs:_bx+2],dh
		add		_bx,3				; Increment to next pixel
		loop	@@LoopSolid			; Loop across line

@@AfterPlot:
		add		bx,bp
		jc		@@BankSwitch2
		dec		_si
		jnz		@@NextScanLine
		jmp		@@Exit

@@BankSwitch:
		call	DrawPixelSlow16m
		inc		dl
		loop	@@LoopSolid			; Loop across line
		jmp		@@AfterPlot

@@BankSwitch2:
		inc		dl
		push	_ax
		mov		_ax,_dx
		call	setBank
		pop		_ax
		dec		_si
		jnz		@@NextScanLine

@@Exit:
		pop		_bp
		leave_c
		ret

procend     __clear16m

;----------------------------------------------------------------------------
; void clear4G(long color)
;----------------------------------------------------------------------------
; Routine to clear the screen. Assumes pages begin on bank boundaries
; for simplicity of coding.
;----------------------------------------------------------------------------
procstart   __clear4G

		ARG		color:ULONG

		enter_c	0
		push	es

		mov     _ax,[_maxy]
		inc     _ax
        mul     [_bytesperline]     ; DX:AX := number of bytes to fill
        mov     bx,ax               ; BX := bytes in last bank to fill
        mov     dh,dl               ; DH := number of full banks to fill

		mov		ax,fs
		mov		es,ax
		xor		_di,_di				; ES:_DI -> start of video memory
		add     di,[originOffset]
		mov     dl,[BYTE bankOffset]; DL := starting bank number
        cld                         ; Moves go up in memory

; Fill all of the full 64k banks first

@@OuterLoop:
		mov     al,dl
		call    setBank
		mov     eax,[color]
		mov     _cx,4000h           ; Need to set 4000h double USHORTs per bank
	rep stosd
		xor		_di,_di
		inc     dl
		dec     dh
		jnz     @@OuterLoop

; Now fill the last partial bank

		mov     al,dl
		call    setBank
		mov    	eax,[color]
		xor		_cx,_cx
		mov     cx,bx
		shr     _cx,2               ; _CX := number of double USHORTs to set
    rep stosd

		pop		es
		leave_c
		ret

procend     __clear4G

;----------------------------------------------------------------------------
; void putPixel16(int x,int y,long color)
;----------------------------------------------------------------------------
; Routine sets the value of a pixel in native VGA graphics modes.
;
; Entry:        x       -   X coordinate of pixel to draw
;               y       -   Y coordinate of pixel to draw
;               color   -   Color of pixel to draw
;
;----------------------------------------------------------------------------
procstart   __putPixel16

		ARG     x:UINT, y:UINT, color:ULONG

		enter_c	0

; Compute the pixel's address in video buffer

		mov     _ax,[y]
		mov     _bx,[x]
		mul     [_bytesperline]     ; DX:AX := y * BytesPerLine

		mov     cl,bl               ; CL := low-order byte of x

		shr     _bx,3               ; _BX := x/8
		add     bx,ax
		adc     dx,0                ; DX:BX := y*BytesPerLine + x/8
		add     bx,[originOffset]   ; DX:BX := byte offset in video buffer
		adc     dx,[bankOffset]

		cmp     dl,[BYTE _curBank]
		je      @@NoChange

        mov     al,dl
		call    setBank

@@NoChange:
		mov     ah,1                ; AH := unshifted bit mask
        and     cl,7                ; CL := x & 7
        xor     cl,7                ; CL := # bits to shift left

; set Graphics Controller Bit Mask register

        shl     ah,cl               ; AH := bit mask in proper postion
        mov     dx,3CEh             ; GC address register port
        mov     al,8                ; AL := Bit Mask Register number
        out     dx,ax

; set Graphics Controller Mode register

        mov     ax,0205h            ; AL := Mode register number
                                    ; AH := Write mode 2 (bits 0,1)
                                    ;   Read mode 0 (bit 3)
        out     dx,ax

; set data rotate/Function Select register

        mov     ax,3                ; AL := Data Rotate/Func select reg #
        out     dx,ax

; set the pixel value

		mov     al,[fs:_bx]       	; latch one byte from each bit plane
		mov     al,[BYTE color]     ; AL := pixel value
		mov     [fs:_bx],al   		; update all bit planes

; restore default Graphics Controller registers

        mov     ax,0FF08h           ; default bit mask
        out     dx,ax

        mov     ax,0005             ; default mode register
        out     dx,ax

        mov     ax,0003             ; default function select
        out     dx,ax

		leave_c
		ret

procend     __putPixel16

;----------------------------------------------------------------------------
; void putPixel256(int x,int y,long color)
;----------------------------------------------------------------------------
; Routine sets the value of a pixel in native VGA graphics modes.
;
; Entry:        x       -   X coordinate of pixel to draw
;               y       -   Y coordinate of pixel to draw
;               color   -   Color of pixel to draw
;
;----------------------------------------------------------------------------
procstart   __putPixel256

		ARG     x:UINT, y:UINT, color:ULONG

        enter_c 0

		mov     _ax,[y]
        mul     [_bytesperline]
		mov     _bx,[x]
        add     ax,bx
        adc     dx,0                ; DX:AX := y * BytesPerLine + x
		add     ax,[originOffset]
		adc     dl,[BYTE bankOffset]; DL := bank number
        mov     bx,ax               ; BX := Offset in buffer
        cmp     dl,[BYTE _curBank]
        je      @@NoChange

        mov     al,dl
        call    setBank

@@NoChange:
		mov     al,[BYTE color]
		mov     [fs:_bx],al        ; Replace the pixel

		leave_c
		ret

procend     __putPixel256

;----------------------------------------------------------------------------
; void putPixel32k(int x,int y,long color)
;----------------------------------------------------------------------------
; Routine sets the value of a pixel in native VGA graphics modes.
;
; Entry:        x       -   X coordinate of pixel to draw
;               y       -   Y coordinate of pixel to draw
;               color   -   Color of pixel to draw
;
;----------------------------------------------------------------------------
procstart   __putPixel32k

		ARG     x:UINT, y:UINT, color:ULONG

		enter_c	0

		mov     _ax,[y]
        mul     [_bytesperline]
		mov     _bx,[x]
		shl     _bx,1
        add     ax,bx
        adc     dx,0                ; DX:AX := y * BytesPerLine + x * 2
		add     ax,[originOffset]
		adc     dl,[BYTE bankOffset]; DL := bank number
        mov     bx,ax               ; BX := Offset in buffer
        cmp     dl,[BYTE _curBank]
        je      @@NoChange

        mov     al,dl
        call    setBank

@@NoChange:
		mov     ax,[USHORT color]
		mov     [fs:_bx],ax        	; Replace the pixel

		leave_c
		ret

procend     __putPixel32k

;----------------------------------------------------------------------------
; void putPixel16m(int x,int y,long color)
;----------------------------------------------------------------------------
; Routine sets the value of a pixel in native VGA graphics modes.
;
; Entry:        x       -   X coordinate of pixel to draw
;               y       -   Y coordinate of pixel to draw
;               color   -   Color of pixel to draw
;
;----------------------------------------------------------------------------
procstart   __putPixel16m

		ARG     x:UINT, y:UINT, color:ULONG

		enter_c	0

		mov     _ax,[y]
        mul     [_bytesperline]
		mov     _bx,[x]
        add     ax,bx
        adc     dx,0
        shl     bx,1
        add     ax,bx
        adc     dx,0                ; DX:AX := y * BytesPerLine + x * 3
		add     ax,[originOffset]
		adc     dl,[BYTE bankOffset]; DL := bank number
        mov     bx,ax               ; BX := Offset in buffer
        cmp     dl,[BYTE _curBank]
        je      @@NoChange

        mov     al,dl
        call    setBank

@@NoChange:
		mov     ax,[WORD color]
		mov		dh,[BYTE color+2]
		cmp		bx,0FFFEh
		jae		@@SlowVersion		; Bank switch occurs in pixel!

		mov     [fs:_bx],ax        	; Replace the first byte
		mov		[fs:_bx+2],dh

@@Exit:	leave_c
		ret

@@SlowVersion:
		call	DrawPixelSlow16m	; Draw the pixel slowly
		jmp		@@Exit

procend     __putPixel16m

;----------------------------------------------------------------------------
; IncBXDL	Increment the BX/DL offset bank number combination
;----------------------------------------------------------------------------
;
; This routine is called in place to increment the value of DL:BX where
; DL is the current bank offset, and BX is the current frame buffer offset.
; The routine also ensures that the bank boundary is correctly crossed. It
; is slow, but only gets called for about less than 10 pixels on the entire
; display page.
;
; Entry:		BX	- Video buffer offset
;				DL	- Video bank number
;
; Exit:			BX	- New buffer offset (+1)
;				DL	- New bank bumber (carried over from BX)
;
; Registers:	None.
;
;----------------------------------------------------------------------------
PROC	IncBXDL	near

		add		bx,1
		adc		dl,0
		xchg	al,dl
		call	setBank
		xchg	al,dl
		ret

ENDP	IncBXDL

;----------------------------------------------------------------------------
; DrawPixelSlow16m	Draws a pixel split across a bank boundary correctly
;----------------------------------------------------------------------------
;
; Draws the pixel taking into account that a bank boundary occurs in the
; middle of the pixel.
;
; Entry:		DH:AX		- Color of the pixel to plot
;				FS:_BX		- Address of pixel to plot
;				_curBank	- Current bank number
;
; Exit:			DH:AX		- Color of pixel to plot
;				FS:_BX		- Address of pixel to plot + 3
;				_curBank	- Current bank number + 1
;
; Registers:	All preserved.
;
;----------------------------------------------------------------------------
PROC	DrawPixelSlow16m	near

		push	_dx

		mov		dl,[BYTE _curBank]
		mov		[fs:_bx],al			; Replace the pixel
		call    IncBXDL
		mov		[fs:_bx],ah
		call	IncBXDL
		mov		[fs:_bx],dh
		call    IncBXDL
		pop		_dx
		ret

ENDP	DrawPixelSlow16m

;----------------------------------------------------------------------------
; void putPixel4G(int x,int y,long color)
;----------------------------------------------------------------------------
; Routine sets the value of a pixel in native VGA graphics modes.
;
; Entry:        x       -   X coordinate of pixel to draw
;               y       -   Y coordinate of pixel to draw
;               color   -   Color of pixel to draw
;
;----------------------------------------------------------------------------
procstart   __putPixel4G

		ARG     x:UINT, y:UINT, color:ULONG

		enter_c	0

		mov     _ax,[y]
        mul     [_bytesperline]
		mov     _bx,[x]
		shl     _bx,1
		shl		_bx,1
        add     ax,bx
		adc     dx,0                ; DX:AX := y * BytesPerLine + x * 4
		add     ax,[originOffset]
		adc     dl,[BYTE bankOffset]; DL := bank number
        mov     bx,ax               ; BX := Offset in buffer
        cmp     dl,[BYTE _curBank]
        je      @@NoChange

        mov     al,dl
        call    setBank

@@NoChange:
		mov     eax,[color]
		mov     [fs:_BX],eax       	; Replace the pixel

		leave_c
		ret

procend     __putPixel4G

;----------------------------------------------------------------------------
; void _line16(int x1,int y1,int x2,int y2, long color)
;----------------------------------------------------------------------------
; Routine draws a line in native VGA graphics modes.
;
; Differentiates between horizontal, vertical and sloping lines. Horizontal
; and vertical lines are special cases and can be drawn extremely quickly.
; The sloping lines are drawn using the Midpoint line algorithm.
;
; Entry:		x1		- X1 coordinate of line to draw
;				y1		- Y1 coordinate of line to draw
;				x2		- X2 coordinate of line to draw
;				y2		- Y2 coordinate of line to draw
;				color	- color to draw the line in
;
;----------------------------------------------------------------------------
procstart	__line16

		ARG		x1:UINT, y1:UINT, x2:UINT, y2:UINT, color:ULONG
		LOCAL	Routine:NCPTR, VertInc:ULONG, EIncr:UINT, 			\
				NEIncr:UINT = LocalSize

		enter_c	LocalSize
		cld

; Configure the graphics controller (write mode 3)

		mov		dx,3CEh				; DX := Graphics Controller port addr

		mov		ax,0B05h			; AL := Mode register number
									; AH := Write mode 3 (bits 0,1)
									;	Read mode 1 (bit 3)
		out		dx,ax

		xor		ah,ah				; AH := replace mode
		mov		al,3				; AL := Data Rotate/Func select reg #
		out		dx,ax

		mov		ax,0007h			; AH := 0 (don't care for all maps;
									;	CPU reads always return 0FFH)
									; AL := 7 (Color Don't care reg number)
		out		dx,ax				; Set up Color Don't care reg

		mov		ax,0F01h			; AH := 1111b (bit plane mask for
									;  enable Set/Reset)
		out		dx,ax				; AL := Enable Set/Reset Register #

		mov		ax,0FF08h			; AH := 11111111b, AL := 8
		out		dx,ax				; restore bit mask register

; Load the current color

		mov		dx,3CEh				; DX := Graphics Controller port addr
		mov		ah,[BYTE color]		; Get color value into ah
		xor		al,al				; AL := Set/Reset Register number
		out		dx,ax

		mov		si,[_bytesperline]	; Increment for video buffer
		mov		[USHORT VertInc+2],0	; Zero out sign for vertical increment
		mov		_ax,[x2]
		sub		_ax,[x1]			; _AX := X2 - X1

; Force X1 < X2

		jns		@@X2Greater			; Jump if X2 > X1
		neg		_ax					; _AX := X1 - X2

		mov		_bx,[x2]			; Exchange X1 and X2
		xchg	_bx,[x1]
		mov		[x2],_bx

		mov		_bx,[y2]			; Exchange Y1 and Y2
		xchg	_bx,[y1]
		mov		[y2],_bx

; calcluate dy = ABS(Y2-Y1)

@@X2Greater:
		mov		_bx,[y2]
		sub		_bx,[y1]			; _BX := Y2 - Y1
		jns		@@Y2Greater			; Jump if slope is positive

		neg		_bx					; _BX := Y1 - Y2
		neg		si					; negative increment for buffer
		mov		[USHORT VertInc+2],0FFFFh	; ensure vert increment is negative

; select appropriate routine for slope of line

@@Y2Greater:
		mov		[USHORT VertInc],si	; save increment
		mov		[Routine],offset @@LoSlopeLine
		cmp		_bx,_ax
		jle		@@LoSlope			; Jump if dy <= dx (Slope <= 1)
		mov		[Routine],offset @@HiSlopeLine
		xchg	_bx,_ax				; exchange dy and dx

; calculate initial decision variable and increments

@@LoSlope:
		shl		_bx,1				; _BX := 2 * dy
		mov		[EIncr],_bx			; EIncr := 2 * dy
		sub		_bx,_ax				; d = 2 * dy - dx
		mov		_di,_bx				; DI := initial decision variable
		sub		_bx,_ax
		mov		[NEIncr],_bx		; NEIncr := 2 * (dy - dx)

; calculate first pixel address

		push	_ax					; preserve dx
		mov		_ax,[y1]
		mov		_bx,[x1]
		call	PixelAddr16			; AH := Bit mask
									; FS:_BX -> buffer
									; CL := # bits to shift left
									; _SI := bank number
		shl		ah,cl				; AH := bit mask in proper position
		mov		al,ah				; AL := bit Mask
		pop		_cx					; Restore dx
		inc		_cx					; _CX := # pixels to draw

		jmp		[Routine]			; jump to appropriate routine

;****************************************************************************
;
; Routine for dy <= dx (slope <= 1)
;						FS:_BX -> video buffer
;						AL = bit mask for 1st pixel
;						AH = bit mask for 1st pixel
;						_CX = # pixels to draw
;						DX = Graphics Controller data register port addr
;						_SI = bank number
;						_DI = Initial decision variable
;						EIncr	- East pixel increment
;						NEIncr	- North East pixel increment
;
; The Graphics Controller index register should be set to point to the
; Bit Mask register.
;
;****************************************************************************

@@LoSlopeLine:

@@StartLo:
		mov		al,ah				; AL := bit mask for next pixel
		cmp		si,[USHORT _curBank]
		je		@@BitMaskIn

		push	_ax					; Preserve AX
		mov		_ax,_si				; AX := new bank number
		call	setBank				; Program this bank
		pop		_ax

@@BitMaskIn:
		or		al,ah				; mask current pixel position
		ror		ah,1				; Rotate pixel value
		jc		@@BitMaskOut		; Jump if mask rotated to leftmost pixel

; bit mask not shifted out

		or		_di,_di				; test sign of d
		jns		@@InPosDi			; jump if d >= 0

		add		_di,[EIncr]			; d := d + EIncr
		loop	@@BitMaskIn

		and		[fs:_bx],al			; set remaining pixel(s)
		jmp		@@Exit

@@InPosDi:
		add		_di,[NEIncr]		; d := d + NEIncr

		and		[fs:_bx],al			; Update bit planes

		add		bx,[USHORT VertInc]	; increment y
		adc		si,[USHORT VertInc+2]	; Adjust bank number
		loop	@@StartLo
		jmp		@@Exit

; bit mask shifted out

@@BitMaskOut:
		and		[fs:_bx],al			; Update bit planes
		add		bx,1				; increment x
		adc		si,0				; Adjust bank value

		or		_di,_di				; test sign of d
		jns		@@OutPosDi			; jump if non-negative

		add		_di,[EIncr]			; d := d + EIncr
		loop	@@StartLo
		jmp		@@Exit

@@OutPosDi:
		add		_di,[NEIncr]		; d := d + NEIncr
		add		bx,[USHORT VertInc]	; vertical increment
		adc		si,[USHORT VertInc+2]	; Adjust bank number
		loop	@@StartLo
		jmp		@@Exit

;****************************************************************************
;
; Routine for dy > dx (slope > 1)
;						FS:_BX -> video buffer
;						AL = bit mask for 1st pixel
;						_CX = # pixels to draw
;						DX = Graphics Controller data register port addr
;						_SI = bank number
;						_DI = Initial decision variable
;						EIncr	- East pixel increment
;						NEIncr	- North East pixel increment
;
; The Graphics Controller index register should be set to point to the
; Bit Mask register.
;
;****************************************************************************

@@HiSlopeLine:

@@StartHi:
		cmp		si,[USHORT _curBank]
		je		@@SetHi

		push	_ax					; Preserve AX
		mov		_ax,_si				; AX := new bank number
		call	setBank				; Program this bank
		pop		_ax

@@SetHi:
		and		[fs:_bx],al			; update bit planes

		add		bx,[USHORT VertInc]	; increment y
		adc		si,[USHORT VertInc+2]	; Adjust bank number

		or		_di,_di				; test sign of d
		jns		@@HiPosDi			; jump if d >= 0

		add		_di,[EIncr]			; d := d + EIncr
		loop	@@StartHi
		jmp		@@Exit

@@HiPosDi:
		add		_di,[NEIncr]		; d := d + NEIncr

		ror		al,1				; rotate bit mask
		adc		bx,0				; Increment BX when mask rotated to
									;  leftmost pixel position
		adc		si,0				; Adjust bank number
		loop	@@StartHi

; Restore graphics controller and return to caller

@@Exit:
		mov		dx,3CEh				; DX := Graphics Controller port addr
		xor		ax,ax				; AH := 0, AL := 0
		out		dx,ax				; Restore Set/Reset Register

		inc		ax					; AH := 0, AL := 1
		out		dx,ax				; Restore Enable Set/Reset register

		mov		al,3				; AH := 0, AL := 3
		out		dx,ax				; Restore Data Rotate/Func select reg

		mov		al,5				; AH := 0, AL := 5
		out		dx,ax				; default mode register

		mov		ax,0F07h			; default color compare value
		out		dx,ax

		mov		ax,0FF08h			; AH := 11111111b, AL := 8
		out		dx,ax				; restore bit mask register

		leave_c
		ret

procend		__line16

;----------------------------------------------------------------------------
; void _line256(int x1,int y1,int x2,int y2, long color)
;----------------------------------------------------------------------------
; Routine draws a line in native VGA graphics modes.
;
; Differentiates between horizontal, vertical and sloping lines. Horizontal
; and vertical lines are special cases and can be drawn extremely quickly.
; The sloping lines are drawn using the Midpoint line algorithm.
;
; Entry:		x1		- X1 coordinate of line to draw
;				y1		- Y1 coordinate of line to draw
;				x2		- X2 coordinate of line to draw
;				y2		- Y2 coordinate of line to draw
;				color	- color to draw the line in
;
;----------------------------------------------------------------------------
procstart	__line256

		ARG		x1:UINT, y1:UINT, x2:UINT, y2:UINT, color:ULONG
		LOCAL	Routine:NCPTR, VertInc:ULONG, EIncr:UINT, 			\
				NEIncr:UINT = LocalSize

		enter_c	LocalSize

		mov		si,[_bytesperline]	; Increment for video buffer
		mov		[USHORT VertInc+2],0	; Zero out sign for vertical increment

		mov		_ax,[x2]
		sub		_ax,[x1]			; _AX := X2 - X1

; Force X1 < X2

		jns		@@X2Greater			; Jump if X2 > X1
		neg		_ax					; _AX := X1 - X2

		mov		_bx,[x2]			; Exchange X1 and X2
		xchg	_bx,[x1]
		mov		[x2],_bx

		mov		_bx,[y2]			; Exchange Y1 and Y2
		xchg	_bx,[y1]
		mov		[y2],_bx

; calcluate dy = ABS(Y2-Y1)

@@X2Greater:
		mov		_bx,[y2]
		sub		_bx,[y1]			; _BX := Y2 - Y1
		jns		@@Y2Greater			; Jump if slope is positive

		neg		_bx					; _BX := Y1 - Y2
		neg		si					; negative increment for buffer
		mov		[USHORT VertInc+2],0FFFFh	; ensure vert increment is negative

; select appropriate routine for slope of line

@@Y2Greater:
		mov		[USHORT VertInc],si	; save increment
		mov		[Routine],offset @@LoSlopeLine
		cmp		_bx,_ax
		jle		@@LoSlope			; Jump if dy <= dx (Slope <= 1)
		mov		[Routine],offset @@HiSlopeLine
		xchg	_bx,_ax				; exchange dy and dx

; calculate initial decision variable and increments

@@LoSlope:
		shl		_bx,1				; _BX := 2 * dy
		mov		[EIncr],_bx			; EIncr := 2 * dy
		sub		_bx,_ax				; d = 2 * dy - dx
		mov		_di,_bx				; _DI := initial decision variable
		sub		_bx,_ax
		mov		[NEIncr],_bx		; NEIncr := 2 * (dy - dx)

; calculate first pixel address

		push	_ax					; preserve dx
		mov		_ax,[y1]
		mov		_bx,[x1]
		call	PixelAddr256		; FS:_BX -> buffer

		pop		_cx					; Restore dx
		inc		_cx					; CX := # pixels to draw

		jmp     [Routine]           ; jump to appropriate routine

;****************************************************************************
;
; Routine for dy <= dx (slope <= 1)
;						FS:_BX -> video buffer
;						_CX = # pixels to draw
;						_DX = Bank number for first pixel
;						_DI = decision variable
;						EIncr	- East pixel increment
;						NEIncr	- North East pixel increment
;
;****************************************************************************

@@LoSlopeLine:
		mov		al,0
		call	setBank
		mov		al,[BYTE color]		; AL := pixel value to fill
		mov		dh,[BYTE _curBank]	; DH := current bank number

@@LoopLo:
		cmp		dl,dh
		je		@@SetLo

		mov		dh,al				; DH := color value
		mov		al,dl				; AL := new bank number
		call	setBank				; Program this bank
		mov		al,dh				; AL := color value
		mov		dh,dl				; DH := current bank number

@@SetLo:
		mov		[fs:_bx],al			; Set pixel value in buffer
		add		bx,1				; Increment x coordinate
		adc		dl,0				; Adjust bank number
		or		_di,_di				; Test sign of d
		jns		@@LoPosDi			; Jump if d >= 0

		add		_di,[EIncr]			; d := d + EIncr
		loop	@@LoopLo			; Loop for remaining pixels
		jmp		@@Exit				; We are all done

@@LoPosDi:
		add		_di,[NEIncr]		; d := d + NEIncr
		add		bx,[USHORT VertInc]	; increment y
		adc		dl,[BYTE VertInc+2]	; adjust page number
		loop	@@LoopLo			; Loop for remaining pixels
		jmp		@@Exit				; We are all done

;****************************************************************************
;
; Routine for dy > dx (slope > 1)
;						ES:_BX -> video buffer
;						_CX = # pixels to draw
;						_DX = Bank number for first pixel
;						_DI = decision variable
;						EIncr	- East pixel increment
;						NEIncr	- North East pixel increment
;
;****************************************************************************

@@HiSlopeLine:
		mov		al,[BYTE color]		; AL := pixel value to fill
		mov		dh,[BYTE _curBank]	; DH := current bank number

@@LoopHi:
		cmp		dh,dl
		je		@@SetHi

		mov		dh,al				; DH := color value
		mov		al,dl				; AL := new bank number
		call	setBank				; Program this bank
		mov		al,dh				; AL := color value
		mov		dh,dl				; DH := current bank number

@@SetHi:
		mov		[fs:_bx],al			; Set pixel value in buffer
		add		bx,[USHORT VertInc]	; increment y
		adc		dl,[BYTE VertInc+2]	; Adjust bank number
		or		_di,_di				; Test sign of d
		jns		@@HiPosDi			; Jump if d >= 0

		add		_di,[EIncr]			; d := d + EIncr
		loop	@@LoopHi			; Loop for remaining pixels
		jmp		@@Exit				; We are all done

@@HiPosDi:
		add		_di,[NEIncr]		; d := d + NEIncr
		add		bx,1				; Increment x
		adc		dl,0				; Adjust bank number
		loop	@@LoopHi			; Loop for remaining pixels

@@Exit:
		leave_c
		ret

procend		__line256

;----------------------------------------------------------------------------
; void _line32k(int x1,int y1,int x2,int y2, long color)
;----------------------------------------------------------------------------
; Routine draws a line in native VGA graphics modes.
;
; Differentiates between horizontal, vertical and sloping lines. Horizontal
; and vertical lines are special cases and can be drawn extremely quickly.
; The sloping lines are drawn using the Midpoint line algorithm.
;
; Entry:		x1		- X1 coordinate of line to draw
;				y1		- Y1 coordinate of line to draw
;				x2		- X2 coordinate of line to draw
;				y2		- Y2 coordinate of line to draw
;				color	- color to draw the line in
;
;----------------------------------------------------------------------------
procstart	__line32k

		ARG		x1:UINT, y1:UINT, x2:UINT, y2:UINT, color:ULONG
		LOCAL	Routine:NCPTR, VertInc:ULONG, EIncr:UINT, 			\
				NEIncr:UINT = LocalSize

		enter_c	LocalSize
		cld

		mov		si,[_bytesperline]	; Increment for video buffer
		mov		[USHORT VertInc+2],0	; Zero out sign for vertical increment

		mov		_ax,[x2]
		sub		_ax,[x1]			; _AX := X2 - X1

; Force X1 < X2

		jns		@@X2Greater			; Jump if X2 > X1
		neg		_ax					; _AX := X1 - X2

		mov		_bx,[x2]			; Exchange X1 and X2
		xchg	_bx,[x1]
		mov		[x2],_bx

		mov		_bx,[y2]			; Exchange Y1 and Y2
		xchg	_bx,[y1]
		mov		[y2],_bx

; calcluate dy = ABS(Y2-Y1)

@@X2Greater:
		mov		_bx,[y2]
		sub		_bx,[y1]			; _BX := Y2 - Y1
		jns		@@Y2Greater			; Jump if slope is positive

		neg		_bx					; _BX := Y1 - Y2
		neg		si					; negative increment for buffer
		mov		[USHORT VertInc+2],0FFFFh	; ensure vert increment is negative

; select appropriate routine for slope of line

@@Y2Greater:
		mov		[USHORT VertInc],si	; save increment
		mov		[Routine],offset @@LoSlopeLine
		cmp		_bx,_ax
		jle		@@LoSlope			; Jump if dy <= dx (Slope <= 1)
		mov		[Routine],offset @@HiSlopeLine
		xchg	_bx,_ax				; exchange dy and dx

; calculate initial decision variable and increments

@@LoSlope:
		shl		_bx,1				; _BX := 2 * dy
		mov		[EIncr],_bx			; EIncr := 2 * dy
		sub		_bx,_ax				; d = 2 * dy - dx
		mov		_di,_bx				; _DI := initial decision variable
		sub		_bx,_ax
		mov		[NEIncr],_bx		; NEIncr := 2 * (dy - dx)

; calculate first pixel address

		push	_ax					; preserve dx
		mov		_ax,[y1]
		mov		_bx,[x1]
		call	PixelAddr32k		; FS:_BX -> buffer

		pop		_cx					; Restore dx
		inc		_cx					; _CX := # pixels to draw

		jmp		[Routine]			; jump to appropriate routine

;****************************************************************************
;
; Routine for dy <= dx (slope <= 1)
;						FS:_BX -> video buffer
;						_CX = # pixels to draw
;						_DX = Bank number for first pixel
;						_DI = decision variable
;						EIncr	- East pixel increment
;						NEIncr	- North East pixel increment
;
;****************************************************************************

@@LoSlopeLine:
		mov		ax,[USHORT color]		; AX := pixel value to fill
		mov		dh,[BYTE _curBank]	; DH := current bank number

@@LoopLo:
		cmp		dl,dh
		je		@@SetLo

		push	_ax					; Save color value
		mov		al,dl				; AL := new bank number
		call	setBank				; Program this bank
		mov		dh,dl				; DH := current bank number
		pop		_ax					; Restore color value

@@SetLo:
		mov		[fs:_bx],ax			; Set pixel value in buffer
		add		bx,2				; Increment x coordinate
		adc		dl,0				; Adjust bank number
		or		_di,_di				; Test sign of d
		jns		@@LoPosDi			; Jump if d >= 0

		add		_di,[EIncr]			; d := d + EIncr
		loop	@@LoopLo			; Loop for remaining pixels
		jmp		@@Exit				; We are all done

@@LoPosDi:
		add		_di,[NEIncr]		; d := d + NEIncr
		add		bx,[USHORT VertInc]	; increment y
		adc		dl,[BYTE VertInc+2]	; adjust page number
		loop	@@LoopLo			; Loop for remaining pixels
		jmp		@@Exit				; We are all done

;****************************************************************************
;
; Routine for dy > dx (slope > 1)
;						FS:_BX -> video buffer
;						_CX = # pixels to draw
;						_DX = Bank number for first pixel
;						_DI = decision variable
;						EIncr	- East pixel increment
;						NEIncr	- North East pixel increment
;
;****************************************************************************

@@HiSlopeLine:
		mov		ax,[USHORT color]		; AL := pixel value to fill
		mov		dh,[BYTE _curBank]	; DH := current bank number

@@LoopHi:
		cmp		dh,dl
		je		@@SetHi

		push	_ax					; Save color value
		mov		al,dl				; AL := new bank number
		call	setBank				; Program this bank
		mov		dh,dl				; DH := current bank number
		pop		_ax					; Restore color value

@@SetHi:
		mov		[fs:_bx],ax			; Set pixel value in buffer
		add		bx,[USHORT VertInc]	; increment y
		adc		dl,[BYTE VertInc+2]	; Adjust bank number
		or		_di,_di				; Test sign of d
		jns		@@HiPosDi			; Jump if d >= 0

		add		_di,[EIncr]			; d := d + EIncr
		loop	@@LoopHi			; Loop for remaining pixels
		jmp		@@Exit				; We are all done

@@HiPosDi:
		add		_di,[NEIncr]		; d := d + NEIncr
		add		bx,2				; Increment x
		adc		dl,0				; Adjust bank number
		loop	@@LoopHi			; Loop for remaining pixels

@@Exit:
		leave_c
		ret

procend		__line32k

;----------------------------------------------------------------------------
; void _line16m(int x1,int y1,int x2,int y2, long color)
;----------------------------------------------------------------------------
; Routine draws a line in native VGA graphics modes.
;
; Differentiates between horizontal, vertical and sloping lines. Horizontal
; and vertical lines are special cases and can be drawn extremely quickly.
; The sloping lines are drawn using the Midpoint line algorithm.
;
; Entry:		x1		- X1 coordinate of line to draw
;				y1		- Y1 coordinate of line to draw
;				x2		- X2 coordinate of line to draw
;				y2		- Y2 coordinate of line to draw
;				color	- color to draw the line in
;
;----------------------------------------------------------------------------
procstart	__line16m

		ARG		x1:UINT, y1:UINT, x2:UINT, y2:UINT, color:ULONG
		LOCAL	Routine:NCPTR, VertInc:ULONG, EIncr:UINT, 			\
				NEIncr:UINT = LocalSize

		enter_c	LocalSize
		cld

		mov		si,[_bytesperline]	; Increment for video buffer
		mov		[USHORT VertInc+2],0	; Zero out sign for vertical increment

		mov		_ax,[x2]
		sub		_ax,[x1]			; _AX := X2 - X1

; Force X1 < X2

		jns		@@X2Greater			; Jump if X2 > X1
		neg		_ax					; _AX := X1 - X2

		mov		_bx,[x2]			; Exchange X1 and X2
		xchg	_bx,[x1]
		mov		[x2],_bx

		mov		_bx,[y2]			; Exchange Y1 and Y2
		xchg	_bx,[y1]
		mov		[y2],_bx

; calcluate dy = ABS(Y2-Y1)

@@X2Greater:
		mov		_bx,[y2]
		sub		_bx,[y1]			; _BX := Y2 - Y1
		jns		@@Y2Greater			; Jump if slope is positive

		neg		_bx					; _BX := Y1 - Y2
		neg		si					; negative increment for buffer
		mov		[USHORT VertInc+2],0FFFFh	; ensure vert increment is negative

; select appropriate routine for slope of line

@@Y2Greater:
		mov		[USHORT VertInc],si	; save increment
		mov		[Routine],offset @@LoSlopeLine
		cmp		_bx,_ax
		jle		@@LoSlope			; Jump if dy <= dx (Slope <= 1)
		mov		[Routine],offset @@HiSlopeLine
		xchg	_bx,_ax				; exchange dy and dx

; calculate initial decision variable and increments

@@LoSlope:
		shl		_bx,1				; _BX := 2 * dy
		mov		[EIncr],_bx			; EIncr := 2 * dy
		sub		_bx,_ax				; d = 2 * dy - dx
		mov		_di,_bx				; _DI := initial decision variable
		sub		_bx,_ax
		mov		[NEIncr],_bx		; NEIncr := 2 * (dy - dx)

; calculate first pixel address

		push	_ax					; preserve dx
		mov		_ax,[y1]
		mov		_bx,[x1]
		call	PixelAddr16m		; FS:_BX -> buffer

		pop		_cx					; Restore dx
		inc		_cx					; CX := # pixels to draw

		jmp		[Routine]			; jump to appropriate routine

;****************************************************************************
;
; Routine for dy <= dx (slope <= 1)
;						FS:_BX -> video buffer
;						_CX = # pixels to draw
;						_DX = Bank number for first pixel
;						_DI = decision variable
;						EIncr	- East pixel increment
;						NEIncr	- North East pixel increment
;
;****************************************************************************

@@LoSlopeLine:
		mov		ax,[USHORT color]		; AX := pixel value to fill
		mov		dh,[BYTE color+2]	; DH := top byte of pixel value

@@LoopLo:
		cmp		dl,[BYTE _curBank]
		je		@@SetPixelLo

		push	_ax					; Save color value
		mov		al,dl				; AL := new bank number
		call	setBank				; Program this bank
		pop		_ax					; Restore color value

@@SetPixelLo:
		cmp		bx,0FFFEh
		jae		@@BankSwitchLo

@@SetLo:
		mov		[fs:_bx],ax			; Set pixel value in buffer
		mov		[fs:_bx+2],dh
		add		bx,3				; Increment x coordinate
		adc		dl,0				; Adjust bank number

@@DonePixelLo:
		or		_di,_di				; Test sign of d
		jns		@@LoPosDi			; Jump if d >= 0

		add		_di,[EIncr]			; d := d + EIncr
		loop	@@LoopLo			; Loop for remaining pixels
		jmp		@@Exit				; We are all done

@@LoPosDi:
		add		_di,[NEIncr]		; d := d + NEIncr
		add		bx,[USHORT VertInc]	; increment y
		adc		dl,[BYTE VertInc+2]	; adjust page number
		loop	@@LoopLo			; Loop for remaining pixels
		jmp		@@Exit				; We are all done

@@BankSwitchLo:
		call	DrawPixelSlow16m
		inc		dl
		jmp     @@DonePixelLo

;****************************************************************************
;
; Routine for dy > dx (slope > 1)
;						FS:_BX -> video buffer
;						_CX = # pixels to draw
;						_DX = Bank number for first pixel
;						_DI = decision variable
;						EIncr	- East pixel increment
;						NEIncr	- North East pixel increment
;
;****************************************************************************

@@HiSlopeLine:
		mov		ax,[USHORT color]		; AL := pixel value to fill
		mov		dh,[BYTE color+2]	; DH := current bank number

@@LoopHi:
		cmp		dl,[BYTE _curBank]
		je		@@SetPixelHi

		push	_ax					; Save color value
		mov		al,dl				; AL := new bank number
		call	setBank				; Program this bank
		pop		_ax					; Restore color value

@@SetPixelHi:
		cmp		bx,0FFFEh
		jae		@@BankSwitchHi

@@SetHi:
		mov		[fs:_bx],ax			; Set pixel value in buffer
		mov		[fs:_bx+2],dh

@@DonePixelHi:
		add		bx,[USHORT VertInc]	; increment y
		adc		dl,[BYTE VertInc+2]	; Adjust bank number
		or		_di,_di				; Test sign of d
		jns		@@HiPosDi			; Jump if d >= 0

		add		_di,[EIncr]			; d := d + EIncr
		loop	@@LoopHi			; Loop for remaining pixels
		jmp		@@Exit				; We are all done

@@HiPosDi:
		add		_di,[NEIncr]		; d := d + NEIncr
		add		bx,3				; Increment x
		adc		dl,0				; Adjust bank number
		loop	@@LoopHi			; Loop for remaining pixels
		jmp		@@Exit

@@BankSwitchHi:
		call	DrawPixelSlow16m
		sub		bx,3
		jmp     @@DonePixelHi

@@Exit:
		leave_c
		ret

procend		__line16m

;----------------------------------------------------------------------------
; void _line4G(int x1,int y1,int x2,int y2, long color)
;----------------------------------------------------------------------------
; Routine draws a line in native VGA graphics modes.
;
; Differentiates between horizontal, vertical and sloping lines. Horizontal
; and vertical lines are special cases and can be drawn extremely quickly.
; The sloping lines are drawn using the Midpoint line algorithm.
;
; Entry:		x1		- X1 coordinate of line to draw
;				y1		- Y1 coordinate of line to draw
;				x2		- X2 coordinate of line to draw
;				y2		- Y2 coordinate of line to draw
;				color	- color to draw the line in
;
;----------------------------------------------------------------------------
procstart	__line4G

		ARG		x1:UINT, y1:UINT, x2:UINT, y2:UINT, color:ULONG
		LOCAL	Routine:NCPTR, VertInc:ULONG, EIncr:UINT, 			\
				NEIncr:UINT = LocalSize

		enter_c	LocalSize
		push	eax
		cld

		mov		si,[_bytesperline]	; Increment for video buffer
		mov		[USHORT VertInc+2],0	; Zero out sign for vertical increment

		mov		_ax,[x2]
		sub		_ax,[x1]			; _AX := X2 - X1

; Force X1 < X2

		jns		@@X2Greater			; Jump if X2 > X1
		neg		_ax					; _AX := X1 - X2

		mov		_bx,[x2]			; Exchange X1 and X2
		xchg	_bx,[x1]
		mov		[x2],_bx

		mov		_bx,[y2]			; Exchange Y1 and Y2
		xchg	_bx,[y1]
		mov		[y2],_bx

; calcluate dy = ABS(Y2-Y1)

@@X2Greater:
		mov		_bx,[y2]
		sub		_bx,[y1]			; _BX := Y2 - Y1
		jns		@@Y2Greater			; Jump if slope is positive

		neg		_bx					; _BX := Y1 - Y2
		neg		si					; negative increment for buffer
		mov		[USHORT VertInc+2],0FFFFh	; ensure vert increment is negative

; select appropriate routine for slope of line

@@Y2Greater:
		mov		[USHORT VertInc],si	; save increment
		mov		[Routine],offset @@LoSlopeLine
		cmp		_bx,_ax
		jle		@@LoSlope			; Jump if dy <= dx (Slope <= 1)
		mov		[Routine],offset @@HiSlopeLine
		xchg	_bx,_ax				; exchange dy and dx

; calculate initial decision variable and increments

@@LoSlope:
		shl		_bx,1				; _BX := 2 * dy
		mov		[EIncr],_bx			; EIncr := 2 * dy
		sub		_bx,_ax				; d = 2 * dy - dx
		mov		_di,_bx				; _DI := initial decision variable
		sub		_bx,_ax
		mov		[NEIncr],_bx		; NEIncr := 2 * (dy - dx)

; calculate first pixel address

		push	_ax					; preserve dx
		mov		_ax,[y1]
		mov		_bx,[x1]
		call	PixelAddr4G			; FS:_BX -> buffer

		pop		_cx					; Restore dx
		inc		_cx					; _CX := # pixels to draw

		jmp		[Routine]			; jump to appropriate routine

;****************************************************************************
;
; Routine for dy <= dx (slope <= 1)
;						ES:_BX -> video buffer
;						_CX = # pixels to draw
;						_DX = Bank number for first pixel
;						_DI = decision variable
;						EIncr	- East pixel increment
;						NEIncr	- North East pixel increment
;
;****************************************************************************

@@LoSlopeLine:
		mov		eax,[color]			; EAX := pixel value to fill
		mov		dh,[BYTE _curBank]	; DH := current bank number

@@LoopLo:
		cmp		dl,dh
		je		@@SetLo

		push	_ax					; Save color value
		mov		al,dl				; AL := new bank number
		call	setBank				; Program this bank
		mov		dh,dl				; DH := current bank number
		pop		_ax					; Restore color value

@@SetLo:
		mov		[fs:_bx],eax		; Set pixel value in buffer
		add		bx,4				; Increment x coordinate
		adc		dl,0				; Adjust bank number
		or		_di,_di				; Test sign of d
		jns		@@LoPosDi			; Jump if d >= 0

		add		_di,[EIncr]			; d := d + EIncr
		loop	@@LoopLo			; Loop for remaining pixels
		jmp		@@Exit				; We are all done

@@LoPosDi:
		add		_di,[NEIncr]		; d := d + NEIncr
		add		bx,[USHORT VertInc]	; increment y
		adc		dl,[BYTE VertInc+2]	; adjust page number
		loop	@@LoopLo			; Loop for remaining pixels
		jmp		@@Exit				; We are all done

;****************************************************************************
;
; Routine for dy > dx (slope > 1)
;						ES:_BX -> video buffer
;						_CX = # pixels to draw
;						_DX = Bank number for first pixel
;						_DI = decision variable
;						EIncr	- East pixel increment
;						NEIncr	- North East pixel increment
;
;****************************************************************************

@@HiSlopeLine:
		mov		eax,[color]			; EAX := pixel value to fill
		mov		dh,[BYTE _curBank]	; DH := current bank number

@@LoopHi:
		cmp		dh,dl
		je		@@SetHi

		push	_ax					; Save color value
		mov		al,dl				; AL := new bank number
		call	setBank				; Program this bank
		mov		dh,dl				; DH := current bank number
		pop		_ax					; Restore color value

@@SetHi:
		mov		[fs:_bx],eax		; Set pixel value in buffer
		add		bx,[USHORT VertInc]	; increment y
		adc		dl,[BYTE VertInc+2]	; Adjust bank number
		or		_di,_di				; Test sign of d
		jns		@@HiPosDi			; Jump if d >= 0

		add		_di,[EIncr]			; d := d + EIncr
		loop	@@LoopHi			; Loop for remaining pixels
		jmp		@@Exit				; We are all done

@@HiPosDi:
		add		_di,[NEIncr]		; d := d + NEIncr
		add		bx,4				; Increment x
		adc		dl,0				; Adjust bank number
		loop	@@LoopHi			; Loop for remaining pixels

@@Exit:
		pop		eax
		leave_c
		ret

procend		__line4G

;----------------------------------------------------------------------------
; void setActivePage(int which)
;----------------------------------------------------------------------------
; Routine to set the video page for active output.
;
; Entry:        page    - Page number of page to use
;
;----------------------------------------------------------------------------
procstart   _setActivePage

		ARG     which:UINT

		enter_c	0

; Calculate 18 bit address of page in video memory

		xor     eax,eax
		mov     _ax,[which]         ; EAX := page number
		mul     [_pagesize]         ; EDX:EAX := result
		mov     [originOffset],ax   ; Save video buffer offset
		shr     eax,16
		mov     [bankOffset],ax     ; Save video bank offset

		leave_c
		ret

procend     _setActivePage

;----------------------------------------------------------------------------
; void setVisualPage(int which)
;----------------------------------------------------------------------------
; Routine to set the visible video page.
;
; Entry:        page    - Page number of page to use
;
;----------------------------------------------------------------------------
procstart       _setVisualPage

		ARG     which:UINT

		enter_c	0

		cmp		[_maxpage],0		; No flipping if only one page
		je		@@Exit

; Calculate 18 bit address of page in video memory

		xor     eax,eax
		mov     _ax,[which]         ; EAX := page number
		mul     [_pagesize]         ; EAX := starting address in memory
		mov     edx,eax
		shr     edx,16              ; DX:AX := starting address in memory

		cmp     [_extendedflipping],0
		je      @@VGAFlip           ; We have no extended page flipping

		div     [_bytesperline]     ; AX := starting scanline,
									; DX := starting byte
		mov     cx,dx
		cmp     [USHORT _maxcolor],0Fh
        je      @@16Color
		cmp     [USHORT _maxcolor],0FFh
        je      @@SetIt
		cmp     [USHORT _maxcolor+2],0FFh
        je      @@16MColor

		shr     cx,1                ; CX := starting pixel in buffer
		jmp     @@SetIt

@@16Color:
		shl     cx,3                ; CX := starting pixel in buffer
		jmp     @@SetIt

@@16MColor:
		mov		bx,ax				; Preserve AX
		xor     dx,dx
		mov     ax,cx
		mov     cx,3
		div     cx
		mov     cx,ax               ; CX := starting pixel in buffer
		mov		ax,bx				; Restore AX

@@SetIt:
		mov     bx,ax               ; BX := starting scanline in buffer

		mov     _ax,04F07h
		mov     _dx,_bx             ; DX := starting scanline number
		xor     _bx,_bx             ; BX := 0 - set display start
		int     10h                 ; Set the display start address
		jmp     @@Exit

@@VGAFlip:
		mov     bx,ax               ; BX := bottom 16 bits of address

; Wait for display enable to be active (active low), to be sure that
; both halves of the start address will take place in one frame. We
; preload a few values here to save time after the DE has been
; detected.

		mov     cl,0Ch              ; CL := Start Address High register
		mov     ch,bh               ; CH := high byte of new address
		mov     bh,bl               ; BH := low byte of new address
		mov     bl,0Dh              ; BL := Start Address Low register
		mov     dx,03DAh            ; DX := video status port

@@WaitDEVGA:
		in      al,dx
		test    al,1
		jnz     @@WaitDEVGA         ; Wait for Display Enable

		cli
		mov     dx,03D4h            ; DX := CRTC I/O port (3D4h)
		mov     ax,bx
		out     dx,ax
		mov     ax,cx
		out     dx,ax
		sti

; Now wait for the start of the vertical sync, to ensure that the old
; page will be invisible before anything is drawn on it.

		mov     dx,03DAh            ; DX := video status port
@@WaitStartVert:
		in      al,dx               ; Wait for start of vertical retrace
		test    al,8
		jz      @@WaitStartVert

@@Exit:
		leave_c
		ret

procend     _setVisualPage

;----------------------------------------------------------------------------
; setBank   Sets the read/write bank from assembly language
;----------------------------------------------------------------------------
;
; Entry:        AL  - New read/write bank number
;
; Exit:         AL  - New read/write bank number
;
; Registers:    All preserved!
;
; Note that some VESA BIOSes and TSR's set the first window to be
; write only and the second window to be read only, so we need to set both
; windows for most common operations to the same value. The Universal
; VESA VBE sets both the read and write banks to the same value for
; Window A, and changed the read bank only for Window B, hence the second
; call is _not_ required when the Universal VESA VBE is installed. You can
; determine what the window does by looking at the WindowAAttributes in
; the SuperVGAInfo block returned by function 00h. You could use this
; information to optimise bank switching when using faster VBE's like
; the Universal VESA VBE (but I have no bothered to do that here).
;----------------------------------------------------------------------------
procstart   setBank

		push	_dx
ife flatmodel
		push	ds
		mov		dx,DGROUP			; Address our data segment
		mov		ds,dx
endif
		mov     [_curBank],_ax      ; Save current write bank number
		cmp     [_writeBank],0
		je      @@VESABank
		mov	    _dx,_ax             ; DX := bank number
		call    [_writeBank]        ; Call relocated version
ife flatmodel
		pop		ds
endif
		pop		_dx
		ret

@@VESABank:
		push    _ax
		push    _bx
		push	_cx
		mov		cl,[BYTE _bankShift]; Adjust to VESA granularity
		shl		al,cl
		push    _ax
        mov     _dx,_ax             ; DX := bank number
        xor     _bx,_bx             ; BX := select window A
		cmp		[_bankSwitch],0
        je      @@UseInt10

		call    [_bankSwitch]       ; Set write window
        pop     _dx
        inc     _bx
		call    [_bankSwitch]       ; Set read window
		jmp		@@Exit

; Use the int 10h interface if the bankSwitch routine is NULL, which will
; be the case in protected mode until VBE 2.0 (unless UniVBE 5.0 or above
; is installed).

@@UseInt10:
        mov     _ax,04F05h
        int     10h
        pop     _dx
        inc     _bx
        mov     _ax,04F05h
		int     10h

@@Exit:	pop     _cx
		pop     _bx
		pop     _ax
ife flatmodel
		pop		ds
endif
		pop		_dx
		ret

procend     setBank

;----------------------------------------------------------------------------
; setReadBank   Sets the read bank from assembly language
;----------------------------------------------------------------------------
;
; Entry:        AL  - New read bank number
;
; Exit:         AL  - New read bank number
;
; Registers:    All preserved!
;
;----------------------------------------------------------------------------
procstart   setReadBank

		push	_dx
ife flatmodel
		push	ds
		mov		dx,DGROUP			; Address our data segment
		mov		ds,dx
endif
		mov     [_curBank],-1       ; Ensure banking will be re-loaded
		cmp     [_readBank],0
		je      @@VESABank
		mov	    _dx,_ax             ; DX := bank number
		call    [_readBank]         ; Call relocated version
ife flatmodel
		pop		ds
endif
		pop		_dx
		ret

@@VESABank:
        push    _ax
        push    _bx
		push    _cx
		mov		cl,[BYTE _bankShift]; Adjust to VESA granularity
		shl		al,cl
		mov     _dx,_ax             ; DX := bank number
        mov     _bx,1               ; BX := select window B
		cmp		[_bankSwitch],0
        je      @@UseInt10

		call    [_bankSwitch]       ; Set read window
		jmp		@@Exit

; Use the int 10h interface if the bankSwitch routine is NULL, which will
; be the case in protected mode until VBE 2.0 (unless UniVBE 4.4 or above
; is installed).

@@UseInt10:
        mov     _ax,04F05h
		int     10h

@@Exit:	pop     _cx
		pop     _bx
		pop     _ax
ife flatmodel
		pop		ds
endif
		pop		_dx
        ret

procend     setReadBank

;----------------------------------------------------------------------------
; void setBank(int bank)
;----------------------------------------------------------------------------
; Sets the new read/write bank number from C
;----------------------------------------------------------------------------
procstart   _setBank

		ARG     bank:UINT

		push    _bp
		mov     _bp,_sp
        mov     _ax,[bank]
		call    setBank
		pop     _bp
        ret

procend     _setBank

;----------------------------------------------------------------------------
; void setReadBank(int bank)
;----------------------------------------------------------------------------
; Sets the new reading bank number from C
;----------------------------------------------------------------------------
procstart   _setReadBank

		ARG     bank:UINT

		push    _bp
		mov     _bp,_sp
        mov     _ax,[bank]
		call    setReadBank
		pop     _bp
        ret

procend     _setReadBank

endcodeseg	svga

		END
