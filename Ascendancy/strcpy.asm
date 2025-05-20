_TEXT:00000000          strcpy_    proc near
_TEXT:00000000 51                  push  ecx
_TEXT:00000001 50                  push  eax // dst
_TEXT:00000002                           
_TEXT:00000002          loc_10012:                       ; CODE XREF: strcpy_+1A↓j
_TEXT:00000002 8A 0A               mov   cl, [edx] // src
_TEXT:00000004 88 08               mov   [eax], cl
_TEXT:00000006 80 F9 00            cmp   cl, 0
_TEXT:00000009 74 11               jz    short loc_1002C
_TEXT:0000000B 8A 4A 01            mov   cl, [edx+1]
_TEXT:0000000E 83 C2 02            add   edx, 2
_TEXT:00000011 88 48 01            mov   [eax+1], cl
_TEXT:00000014 83 C0 02            add   eax, 2
_TEXT:00000017 80 F9 00            cmp   cl, 0
_TEXT:0000001A 75 E6               jnz   short loc_10012
_TEXT:0000001C                           
_TEXT:0000001C          loc_1002C:                       ; CODE XREF: strcpy_+9↑j
_TEXT:0000001C 58                  pop   eax // dst
_TEXT:0000001D 59                  pop   ecx
_TEXT:0000001E C3                  retn  
_TEXT:0000001E          strcpy_    endp  