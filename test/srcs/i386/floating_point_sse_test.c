//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

int main()
{
    char value0[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    __asm__ __volatile__("vmovdqu %0, %%xmm0" : : "m" (value0));
    char value1[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};
    __asm__ __volatile__("vmovdqu %0, %%xmm1" : : "m" (value1));
    char value2[] = {0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11};
    __asm__ __volatile__("vmovdqu %0, %%xmm2" : : "m" (value2));
    char value3[] = {0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22};
    __asm__ __volatile__("vmovdqu %0, %%xmm3" : : "m" (value3));
    char value4[] = {0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33};
    __asm__ __volatile__("vmovdqu %0, %%xmm4" : : "m" (value4));
    char value5[] = {0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44};
    __asm__ __volatile__("vmovdqu %0, %%xmm5" : : "m" (value5));
    char value6[] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    __asm__ __volatile__("vmovdqu %0, %%xmm6" : : "m" (value6));
    char value7[] = {0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    __asm__ __volatile__("vmovdqu %0, %%xmm7" : : "m" (value7));

    __asm__ __volatile__("nop");

    char value[16];
    __asm__ __volatile__("vmovdqu %%xmm0, %0" : "=m" (value));

    unsigned long check = *(unsigned long*)value;

    if (check == 0xdeadbeef) {
        __asm__ __volatile__("nop");
    }

    return 0;
}