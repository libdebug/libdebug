#include <stdio.h>
#include <stdlib.h>

#pragma GCC optimize ("O0")

void register_test()
{
    asm volatile (
        "push %%rbp\n\t"
        "mov $0x0011223344556677, %%rax\n\t"
        "mov $0x1122334455667700, %%rbx\n\t"
        "mov $0x2233445566770011, %%rcx\n\t"
        "mov $0x3344556677001122, %%rdx\n\t"
        "mov $0x4455667700112233, %%rsi\n\t"
        "mov $0x5566770011223344, %%rdi\n\t"
        "mov $0x6677001122334455, %%rbp\n\t"
        "mov $0xaabbccdd11223344, %%r8\n\t"
        "mov $0xbbccdd11223344aa, %%r9\n\t"
        "mov $0xccdd11223344aabb, %%r10\n\t"
        "mov $0xdd11223344aabbcc, %%r11\n\t"
        "mov $0x11223344aabbccdd, %%r12\n\t"
        "mov $0x223344aabbccdd11, %%r13\n\t"
        "mov $0x3344aabbccdd1122, %%r14\n\t"
        "mov $0x44aabbccdd112233, %%r15\n\t"
        "nop\n\t"
        "mov $0x11, %%al\n\t"
        "mov $0x22, %%bl\n\t"
        "mov $0x33, %%cl\n\t"
        "mov $0x44, %%dl\n\t"
        "mov $0x55, %%sil\n\t"
        "mov $0x66, %%dil\n\t"
        "mov $0x77, %%bpl\n\t"
        "mov $0x88, %%r8b\n\t"
        "mov $0x99, %%r9b\n\t"
        "mov $0xaa, %%r10b\n\t"
        "mov $0xbb, %%r11b\n\t"
        "mov $0xcc, %%r12b\n\t"
        "mov $0xdd, %%r13b\n\t"
        "mov $0xee, %%r14b\n\t"
        "mov $0xff, %%r15b\n\t"
        "nop\n\t"
        "mov $0x1122, %%ax\n\t"
        "mov $0x2233, %%bx\n\t"
        "mov $0x3344, %%cx\n\t"
        "mov $0x4455, %%dx\n\t"
        "mov $0x5566, %%si\n\t"
        "mov $0x6677, %%di\n\t"
        "mov $0x7788, %%bp\n\t"
        "mov $0x8899, %%r8w\n\t"
        "mov $0x99aa, %%r9w\n\t"
        "mov $0xaabb, %%r10w\n\t"
        "mov $0xbbcc, %%r11w\n\t"
        "mov $0xccdd, %%r12w\n\t"
        "mov $0xddee, %%r13w\n\t"
        "mov $0xeeff, %%r14w\n\t"
        "mov $0xff00, %%r15w\n\t"
        "nop\n\t"
        "mov $0x11223344, %%eax\n\t"
        "mov $0x22334455, %%ebx\n\t"
        "mov $0x33445566, %%ecx\n\t"
        "mov $0x44556677, %%edx\n\t"
        "mov $0x55667788, %%esi\n\t"
        "mov $0x66778899, %%edi\n\t"
        "mov $0x778899aa, %%ebp\n\t"
        "mov $0x8899aabb, %%r8d\n\t"
        "mov $0x99aabbcc, %%r9d\n\t"
        "mov $0xaabbccdd, %%r10d\n\t"
        "mov $0xbbccdd11, %%r11d\n\t"
        "mov $0xccdd1122, %%r12d\n\t"
        "mov $0xdd112233, %%r13d\n\t"
        "mov $0x11223344, %%r14d\n\t"
        "mov $0x22334455, %%r15d\n\t"
        "nop\n\t"
        "mov $0x11, %%ah\n\t"
        "mov $0x22, %%bh\n\t"
        "mov $0x33, %%ch\n\t"
        "mov $0x44, %%dh\n\t"
        "nop\n\t"
        "pop %%rbp\n\t"
        :
        :
        : "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8",
          "r9", "r10", "r11", "r12", "r13", "r14", "r15"
    );
}

int main()
{
    printf("Provola\n");

    register_test();

    return EXIT_SUCCESS;
}
