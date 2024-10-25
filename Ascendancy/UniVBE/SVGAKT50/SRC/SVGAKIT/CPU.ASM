;****************************************************************************
;*
;*                            The MegaToolbox
;*
;*                  Copyright (C) 1993 SciTech Software
;*                          All rights reserved.
;*
;* Filename:    $RCSfile: cpu.asm $
;* Version:     $Revision: 1.1 $
;*
;* Language:    8086 Assembler
;* Environment: IBM PC Real Mode and 16 bit Protected Mode.
;*
;* Description: Autodetection routine to determine the type of CPU installed
;*              in the system.
;*
;* $Id: cpu.asm 1.1 1994/08/22 12:27:00 kjb release $
;*
;****************************************************************************

		IDEAL

INCLUDE "model.mac"             ; Memory model macros

header  cpu                     ; Set up memory model

;****************************************************************************
;
; Equates used by queryCPU routine.
;
;****************************************************************************

; Central Processing Unit type codes

CPU86       =   0               ; 8086/88 type processor
CPU186      =   1               ; 80186 type processor
CPU286      =   2               ; 80286 type processor
CPU286p     =   3               ; 80286 type processor in protected mode
CPU386      =   4               ; 80386 type processor
CPU386p     =   5               ; 80386 type processor in protected mode
CPU486      =   6               ; 80486 type processor
CPU486p     =   7               ; 80486 type processor in protected mode
CPU586		=	8				; Pentium type processor
CPU586p		=	9				; Pentium type processor in protected mode

; Floating Point Unit type codes

FPUNONE     =   0               ; No coprocessor present
FPU87       =   1               ; 8087 coprocessor
FPU287      =   2               ; 80287 coprocessor
FPU387      =   3               ; 80387 coprocessor
FPU487      =   4               ; 80487 coprocessor
FPU587		=	5				; Pentium coprocessor

; Save the type of CPU detected so we can determine the co-processor
; type correctly. This means that we MUST call queryCpu() BEFORE calling
; queryFpu() to obtain correct results.

begdataseg
cpu         dw  CPU86
enddataseg

begcodeseg  cpu                 ; Start of code segment

P386							; Turn on 386 instructions

;----------------------------------------------------------------------------
; cpu_type queryCpu(void)
;----------------------------------------------------------------------------
; Determine type of processor present.
;----------------------------------------------------------------------------
procstart   _queryCpu

		push	bx
		push    bp              ; We MUST save bp for initialization code...

		mov     _ax,CPU86       ; Default to 8086/8088 processor
        push    sp
        pop     bx              ; BX holds the value of SP or SP-2
        cmp     bx,sp           ; 88/86/186 pushes the value of SP-2
        je      @@Check286      ; Must be a 286/386/486 type processor
        mov     cl,32           ; 186 uses count mod 32 = 0
        shl     bx,cl           ; 86 shifts 32 bits left so ax = 0
        jz      @@Done          ; zero: shifted out all bits so 86/88
		mov     _ax,CPU186      ; nonzero: no shift, so 186
        jz      @@Done

@@Check286:                     ; First check for 386/486 in 32 bit mode
        pushf                   ; Test for 16 or 32 operand size:
        mov     bx,sp           ;  pushed 2 or 4 bytes of flags
        popf
        inc     bx
        inc     bx
        cmp     bx,sp           ; did pushf change sp by 2?
        jnz     @@Check486      ; 32 bit push, so it is a 386/486

        sub     sp,6            ; Is it a 286/386/486 in 16 bit mode?
        mov     bp,sp
        sgdt    [QWORD ptr bp]  ; 80286/386/486 specific instrucion
        add     sp,4            ; Get global descriptor table
        pop     bx
        inc     bh              ; Third word of GDT = -1 for 286
        jnz     @@Check486      ; We have a 386/486

		mov     _ax,CPU286      ; We have a 286
        jmp     @@TestPROT

@@Check486:

; Distinguish an 80386 from an 80486. Bit 18 (40000H) of EFLAGS register
; is used only in the 486. This code flips it and tests if anything happened.

		mov     edx,esp         ; Save stack pointer
		and     esp,not 3       ; Align stack pointer to prevent a fault
								;  when we set the AC flag on a 486
		pushfd                  ; Copy the EFLAGS register
		pop     eax             ;   into register eax
        mov     ecx,eax         ; Save the original EFLAGS value
		xor     eax,40000H      ; Flip the AC flag bit
		push    eax             ; Try to put the modified value back
        popfd                   ;   into the EFLAGS register
        pushfd                  ; Copy the EFLAGS register again
        pop     eax             ;   into eax
        xor     eax,ecx         ; Compare the old and new AC bits
        shr     eax,18          ; Shift and mask to get the AC comparison bit
        and     eax,1           ;   in the low order position of eax
        push    ecx
        popfd                   ; Restore EFLAGS that were saved on entry
        mov     esp,edx         ; And restore stack pointer to saved value
		mov     bx,ax           ; and move into bx

; At this point ax = 0 for a 386, or ax = 1 for a 486

		test    bx,bx
		jnz     @@Check586      ; Check for the presence of a Pentium(tm)
		mov     _ax,CPU386
		jnz     @@TestPROT      ; We have a 386

@@Check586:

; Distinguish between the i486 and Pentium by the ability to set the ID flag
; in the EFLAGS register. If the ID flag is set, then we can use the CPUID
; instruction to determine the final version of the chip. Otherwise we
; simply have an 80486.

		pushfd                  ; push original EFLAGS
		pop     eax             ; get original EFLAGS in eax
		mov     ecx,eax         ; save original EFLAGS in ecx
		or      eax,200000h     ; flip ID bit in EFLAGS
		push    eax             ; save for EFLAGS
		popfd                   ; copy to EFLAGS
		pushfd                  ; push EFLAGS
		pop     eax             ; get new EFLAGS value
		xor     eax,ecx
		mov		_ax,CPU486
		jz		@@TestProt		; We have an old i486 (flag would not set)

; Now execute the CPUID instruction to determine the vendor, family, model
; and stepping (some new 486's answer to the CPUID test also).

		mov     eax,1           ; set up for CPUID instruction
;       cpuid
db      0Fh, 0A2h               ; Opcodes for CPUID instruction
		and     eax,0F00H       ; mask everything but family
		shr     eax,8
		cmp		al,5
		mov		_ax,CPU486
		jl		@@TestProt		; We have an i486
		mov     _ax,CPU586      ; We have a Pentium(tm)

@@TestPROT:
        smsw    cx              ; protected? machine status -> cx
        ror     cx,1            ; protection bit -> carry flag
        jnc     @@Done          ; Real mode if no carry
		inc     _ax             ; Protected: return value + 1

@@Done:
		mov     [cpu],ax       	; Save CPU type in code segment variable
		pop     bp              ; Restore bp
		pop		bx
		ret                     ; We are done

procend     _queryCpu

;----------------------------------------------------------------------------
; fpu_type queryFpu(void)
;----------------------------------------------------------------------------
; Determine type of floating point coprocessor present in the system.
; The idea is to determine whether or not the floating-point control word
; can be successfully read. If it cannot, then no coprocessor exists.
; If it can the correct coprocessor is then determined depending on the
; main CPU id.
;----------------------------------------------------------------------------
procstart   _queryFpu

		LOCAL   ndp_cw:WORD, ndp_sw:WORD = LocalSize

		push	_bp
		mov		_bp,_sp
		sub		_sp,LocalSize
		push	bx

        mov     bx,FPUNONE      ; Default to no FPU present

; The next two 80x87 instructions cannot carry the WAIT prefix,
; because there may not be an 80x87 for which to wait.  The WAIT is
; therefore emulated with a MOV <E>CX,<value> LOOP $ combination.

        mov     [ndp_cw],0      ; Clear the control word in memory
        cli                     ; Interrupts must be off during test

        fninit                  ; reset NDP status word
		mov     _cx,2          	; Wait for co-pro to complete operation
		loop    $

		fnstcw  [ndp_cw]        ; Obtain the processor control word
		mov     _cx,14h        	; Wait for co-pro to complete operation
        loop    $

        sti                     ; Re-enable interrupts

; We check to see that the precison control bits of the control word
; indicate 64 bit internal precision (bits 8 & 9 set) which is the default
; set up by the fninit instruction above. We also test that the exception
; masks are properly set.

        mov     ax,[ndp_cw]     ; AX := NDP control word
        and     ax,033fh        ; Mask out the precision control bits etc.
        cmp     ax,033fh        ; is the NDP present?
        jne     @@Done          ; No, we are all done... (must be a 3)

; Determine the type of NDP from the main CPU type

        mov     bx,FPU87        ; Start with the 8087 NDP
        mov     ax,[cpu]        ; Get current cpu type
        cmp     ax,CPU286       ; >= 80286 type processor?
        jge     @@80286         ; Yes, check for 287/387/487
        jmp     @@Done          ; No, we are done

; Now that we know we have a possible co-processor and the processor is
; at least an 80286, we can check to see if coprocessor emulation software
; is installed in the system. Some emulators such as FRANKIE.387 emulate
; the co-processor so well that the above checks believe a co-pro is
; actually out there.

@@80286:
        smsw    ax              ; AX := machine status word
        test    al,4            ; Check the EM bit status
        jnz     @@Done          ; Software emulation installed on INT 7!

        mov     ax,[cpu]        ; AX := current CPU flag
        cmp     ax,CPU386       ; Do we have a 386 or above?
        jge     @@80386         ; Yes, check for it
        mov     bx,FPU287       ; We have a 80287 co-pro
        jmp     @@Done

@@80386:
        cmp     ax,CPU486       ; Do we have a 486 or above?
        jge     @@80486         ; Yes, check for it

; The i386 processor can work with either an 80287 or 80387 co processor
; so we must check for that here. The 387 says that +inf <> -inf while
; the 287 says that they are the same.

        fld1                    ; Load +1.0 onto NDP stack
        fldz                    ; Load +0.0 onto NDP stack
        fdiv                    ; do +1/0 (create +inf)
        fld1                    ; Load +1.0 onto NDP stack
        fchs                    ; Change to -1.0
        fldz                    ; Load +0.0 onto NDP stack
        fdiv                    ; do -1/0 (create -inf)
        fcompp                  ; compare and pop values from stack
        fstsw   [ndp_sw]        ; Get the status word from the co pro
        mov     ax,[ndp_sw]     ; AX := Status word
        and     ah,41h          ; Mask out C3 and C0 condition codes
        cmp     ah,40h          ; C3 = 1, C0 = 0 means ST(0) == ST(1)
        mov     bx,FPU287       ; Set up for a 287 co pro
        je      @@Done          ; Yes, we were correct

        mov     bx,FPU387       ; No, it was an 80387
        jmp     @@Done

@@80486:
		mov     bx,FPU487       ; We must have a 487 co pro.
		cmp		ax,CPU586
		jl		@@Done

		mov		bx,FPU587		; We must have a Pentium co pro.

@@Done:
		xor		_ax,_ax
		mov     ax,bx           ; Return FPU type in AX
		pop		bx
		mov		_sp,_bp
		pop		_bp
		ret                     ; We are done

procend     _queryFpu

endcodeseg  cpu

        END                     ; End of module
