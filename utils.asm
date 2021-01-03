
EXTRN idxSysCall : DWORD

.code

ALIGN 16
getAddrTEB PROC
	mov rax, gs:[30h]
	ret
getAddrTEB ENDP

ALIGN 16
callSyscall PROC
	mov r10, rcx
	mov eax, idxSysCall	
	nop ; ON LAISSE 2 OCTETS DE LIBRE POUR ECRIRE PENDANT L'EXECUTION LES OPCODES POUR 'syscall'
	nop ; -----
	ret
callSyscall ENDP

; ! ATTENTION, SSE4 REQUIS !
ALIGN 16
calcCrc32 PROC
  mov       eax, ecx
  cmp       r8d, 4
  jb        short groupBy1
  cmp       r8d, 8
  jb        short groupBy4
groupBy8:
  crc32     rax, qword ptr[rdx]
  add       rdx, 8
  sub       r8d, 8
  je        short onEXIT
  cmp       r8d, 8
  jae       short groupBy8
  cmp       r8d, 4
  jb        short groupBy1
groupBy4:
  crc32     eax, dword ptr[rdx]
  add       rdx, 4
  sub       r8d, 4
  je        short onEXIT
groupBy1:
  crc32     eax, byte ptr[rdx]
  add       rdx, 1
  sub       r8d, 1
  jne       short groupBy1
onEXIT:
  ret       0
calcCrc32 ENDP

ALIGN 16
bnultoa PROC ; ECX = DWORD dwnum, RDX = char* szdst
  cmp     ecx, 10
  jae     short sup9
  add     cl, 48
  lea     rax, [rdx+1]
  mov     byte ptr[rdx], cl
  ret     0
sup9:
  lea     r9, [rdx + 2] ; R9 pointeur final SANS LE ZERO
  cmp     ecx, 100
  jb      short lenOK
  add     r9, 1
  cmp     ecx, 1000
  jb      short lenOK
  add     r9, 1
  cmp     ecx, 10000
  jb      short lenOK
  add     r9, 1
  cmp     ecx, 100000
  jb      short lenOK
  add     r9, 1
  cmp     ecx, 1000000
  jb      short lenOK
  add     r9, 1
  cmp     ecx, 10000000
  jb      short lenOK
  add     r9, 1
  cmp     ecx, 100000000
  jb      short lenOK
  add     r9, 1
  cmp     ecx, 1000000000
  jb      short lenOK
  add     r9, 1
lenOK:
  mov     r8, r9
toASC:
  mov     eax, -858993459
  mul     ecx
  sub     r8, 1
  shr     edx, 3
  mov     eax, ecx
  lea     ecx, [edx+edx*8]
  sub     eax, edx
  sub     eax, ecx
  add     al, 48
  test    edx, edx
  mov     [r8], al
  mov     ecx, edx
  jnz     short toASC
  mov     rax, r9
  ret     0
bnultoa ENDP

ALIGN 16
bnuqwtoa PROC ; RCX = uqw, RDX = *psz
  mov       r8, rsp
  mov       r9, rdx
L1:
  mov       rax, -3689348814741910323
  mul       rcx
  sub       r8, 1
  shr       rdx, 3
  mov       rax, rcx
  lea       rcx, [rdx+rdx*8]
  sub       rax, rdx
  sub       rax, rcx
  add       al, 48
  test      rdx, rdx
  mov       [r8], al
  mov       rcx, rdx
  jnz       short L1
  mov       rax, rsp
  lddqu     xmm0, xmmword ptr[r8]
  mov       ecx, [r8 + 16]
  sub       rax, r8
  movdqu    xmmword ptr[r9], xmm0
  mov       [r9 + 16], ecx
  add       rax, r9
  ret       0
bnuqwtoa ENDP

; char* bnqwtohexa(RCX = UINT64 qwnum, RDX = char* szdst
ALIGN 16
bnqwtohexa PROC
  test      rcx, rcx
  jne       short noZERO
  lea       rax, [rdx + 2]
  mov       byte ptr[rdx], 48
  mov       byte ptr[rdx + 1], 48
  ret       0
noZERO:
  bswap     rcx
  mov       r8d, 8
delZEROLEFT:
  test      cl, cl
  jne       short goHEXA
  sub       r8d, 1
  shr       rcx, 8
  jmp       short delZEROLEFT
goHEXA:
  mov       al, cl
  and       al, 15
  shr       cl, 4
  add       al, 48
  add       cl, 48
  cmp       al, 57
  jbe       short loINF58
  add       al, 7
loINF58:
  cmp       cl, 57
  jbe       short hiINF58
  add       cl, 7
hiINF58:
  mov       byte ptr[rdx + 1], al
  mov       byte ptr[rdx], cl
  shr       rcx, 8
  add       rdx, 2
  sub       r8d, 1
  jne       short goHEXA
  mov       rax, rdx
  ret       0
bnqwtohexa ENDP

END
