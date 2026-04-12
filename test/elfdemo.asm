; MSGDEMO.ASM
; fasm demonstration of assembling object files

; compile the program using commands like:
;   fasm msgdemo.asm msgdemo.o
;   fasm writemsg.asm writemsg.o
;   ld msgdemo.o writemsg.o -o msgdemo

format ELF

section '.text' executable

 public _start
 _start:

 extrn writemsg

        mov     esi,msg
        call    writemsg

  loop1:
        mov     esi,msg2
        call    writemsg

        jmp     loop1

        mov     eax,1
        xor     ebx,ebx
        int     0x80

section '.data' writeable

 msg db "Elves are coming!",0xA,0
 msg2 db "Whatever that means", 13, 0
