
OLOOP_LEN    equ 32
OLOOP_SIZE   equ 12

OLoop MACRO

	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
	mov bl, [esi]
	mov bl, [ebx]
	mov [edi], bl
	add edi, ebp
	add eax, ecx
	adc esi, edx
      
ENDM

.DATA
OLoopOffset label dword
    dd 0180h,0174h,0168h,015Ch,0150h,0144h,0138h,012Ch
    dd 0120h,0114h,0108h,00FCh,00F0h,00E4h,00D8h,00CCh
    dd 00C0h,00B4h,00A8h,009Ch,0090h,0084h,0078h,006Ch
    dd 0060h,0054h,0048h,003Ch,0030h,0024h,0018h,000Ch

