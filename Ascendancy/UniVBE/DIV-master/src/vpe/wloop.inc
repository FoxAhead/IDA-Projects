
WLOOP_LEN    equ 32
WLOOP_SIZE   equ 15

WLoop MACRO

	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
	and dl, ah
	mov bl, [esi+edx]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc dl, al
       
ENDM

.DATA
WLoopOffset label dword
    dd 01E0h,01D1h,01C2h,01B3h,01A4h,0195h,0186h,0177h
    dd 0168h,0159h,014Ah,013Bh,012Ch,011Dh,010Eh,00FFh
    dd 00F0h,00E1h,00D2h,00C3h,00B4h,00A5h,0096h,0087h
    dd 0078h,0069h,005Ah,004Bh,003Ch,002Dh,001Eh,000Fh

