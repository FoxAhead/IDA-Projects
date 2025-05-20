_TEXT:00000000                              public strcat_
_TEXT:00000000                   strcat_    proc near
_TEXT:00000000 51                           push    ecx
_TEXT:00000001 56                           push    esi
_TEXT:00000002 57                           push    edi
_TEXT:00000003 89 C7                        mov     edi, eax
_TEXT:00000005 89 D6                        mov     esi, edx
_TEXT:00000007 06                           push    es
_TEXT:00000008 1E                           push    ds
_TEXT:00000009 07                           pop     es
_TEXT:0000000A                              assume es:DGROUP
_TEXT:0000000A 57                           push    edi
_TEXT:0000000B 2B C9                        sub     ecx, ecx
_TEXT:0000000D 49                           dec     ecx
_TEXT:0000000E B0 00                        mov     al, 0
_TEXT:00000010 F2 AE                        repne scasb
_TEXT:00000012 4F                           dec     edi
_TEXT:00000013                              
_TEXT:00000013                   loc_10023:                         ; CODE XREF: strcat_+2D↓j
_TEXT:00000013 8A 06                        mov     al, [esi]
_TEXT:00000015 88 07                        mov     [edi], al
_TEXT:00000017 3C 00                        cmp     al, 0
_TEXT:00000019 0F 84 10 00 00 00            jz      loc_1003F
_TEXT:0000001F 8A 46 01                     mov     al, [esi+1]
_TEXT:00000022 83 C6 02                     add     esi, 2
_TEXT:00000025 88 47 01                     mov     [edi+1], al
_TEXT:00000028 83 C7 02                     add     edi, 2
_TEXT:0000002B 3C 00                        cmp     al, 0
_TEXT:0000002D 75 E4                        jnz     short loc_10023
_TEXT:0000002F                              
_TEXT:0000002F                   loc_1003F:                         ; CODE XREF: strcat_+19↑j
_TEXT:0000002F 5F                           pop     edi
_TEXT:00000030 07                           pop     es
_TEXT:00000031                              assume es:nothing
_TEXT:00000031 89 F8                        mov     eax, edi
_TEXT:00000033 5F                           pop     edi
_TEXT:00000034 5E                           pop     esi
_TEXT:00000035 59                           pop     ecx
_TEXT:00000036 C3                           retn
_TEXT:00000036                   strcat_    endp