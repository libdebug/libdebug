.section .text
.globl _start, checkpoint
_start:
    nop
checkpoint:
    nop
#ifdef __x86_64__
    mov $1, %eax
    mov $1, %edi
    lea message(%rip), %rsi
    mov $4, %edx
    syscall
    cmpq $1, (%rsp)
    jbe done
    lea 16(%rsp), %rsi
    mov (%rsi), %rdi
    xor %edx, %edx
    mov $59, %eax
    syscall
    mov $111, %edi
    jmp exit
 done:
    xor %edi, %edi
 exit:
    mov $60, %eax
    syscall
#else
    mov $4, %eax
    mov $1, %ebx
    mov $message, %ecx
    mov $4, %edx
    int $0x80
    cmpl $1, (%esp)
    jbe done
    lea 8(%esp), %ecx
    mov (%ecx), %ebx
    xor %edx, %edx
    mov $11, %eax
    int $0x80
    mov $111, %ebx
    jmp exit
 done:
    xor %ebx, %ebx
 exit:
    mov $1, %eax
    int $0x80
#endif
.section .rodata
message: .ascii "ABI\n"
.section .note.GNU-stack,"",@progbits
