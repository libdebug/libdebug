#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MAPPED_ADDRESS 0x1aabbcc1000
#define MAP_SIZE 0x1000
#define handle_error(msg) \
    do { perror(msg); exit(EXIT_FAILURE); } while (0)

int main(void){
    char *p = mmap((void *)MAPPED_ADDRESS, MAP_SIZE, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, NULL, NULL);
    if (p == MAP_FAILED)
        handle_error("mmap");
    for (int i=0; i < MAP_SIZE; i++){
        p[i] = 0xff - (i%0x100);
    }

    while(1){
    __asm__("movq $0x0011223344556677, %rax \n\t"
            "movq $0x1122334455667788, %rbx \n\t"
            "movq $0x2233445566778899, %rcx \n\t"
            "movq $0x33445566778899aa, %rdx \n\t"
            "movq $0x445566778899aabb, %rdi \n\t"
            "movq $0x5566778899aabbcc, %rsi \n\t"
            "movq $0x66778899aabbccdd, %rsp \n\t"
            "movq $0x778899aabbccddee, %rbp \n\t"
            "movq $0x8899aabbccddeeff, %r8  \n\t"
            "movq $0xffeeddccbbaa9988, %r9  \n\t"
            "movq $0xeeddccbbaa998877, %r10 \n\t"
            "movq $0xddccbbaa99887766, %r11 \n\t"
            "movq $0xccbbaa9988776655, %r12 \n\t"
            "movq $0xbbaa998877665544, %r13 \n\t"
            "movq $0xaa99887766554433, %r14 \n\t"
            "movq $0x9988776655443322, %r15 \n\t"
            );
    }
}