//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>
#include <stdlib.h>

#pragma GCC optimize ("O0")

void register_test()
{
    asm volatile (
        "push %%ebp\n\t"
        "mov $0x00112233, %%eax\n\t"
        "mov $0x11223344, %%ebx\n\t"
        "mov $0x22334455, %%ecx\n\t"
        "mov $0x33445566, %%edx\n\t"
        "mov $0x44556677, %%esi\n\t"
        "mov $0x55667788, %%edi\n\t"
        "mov $0x66778899, %%ebp\n\t"
        "nop\n\t"
        "mov $0x1122, %%ax\n\t"
        "mov $0x2233, %%bx\n\t"
        "mov $0x3344, %%cx\n\t"
        "mov $0x4455, %%dx\n\t"
        "mov $0x5566, %%si\n\t"
        "mov $0x6677, %%di\n\t"
        "mov $0x7788, %%bp\n\t"
        "nop\n\t"
        "mov $0x11, %%al\n\t"
        "mov $0x22, %%bl\n\t"
        "mov $0x33, %%cl\n\t"
        "mov $0x44, %%dl\n\t"
        "nop\n\t"
        "mov $0x12, %%ah\n\t"
        "mov $0x23, %%bh\n\t"
        "mov $0x34, %%ch\n\t"
        "mov $0x45, %%dh\n\t"
        "nop\n\t"
        "pop %%ebp\n\t"
        :
        :
        : "eax", "ebx", "ecx", "edx", "esi", "edi"
    );
}

int main()
{
    printf("Provola\n");

    register_test();

    return EXIT_SUCCESS;
}
