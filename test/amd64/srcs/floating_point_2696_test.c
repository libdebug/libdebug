//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

void rotate(char value[64])
{
    char temp = value[0];
    for (int i = 0; i < 63; i++) {
        value[i] = value[i + 1];
    }
    value[63] = temp;
}

int main()
{
    char value[64];

    for (int i = 0; i < 64; i++) {
        value[i] = i;
    }

    __asm__ __volatile__("vmovdqu8 %0, %%zmm0" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm1" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm2" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm3" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm4" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm5" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm6" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm7" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm8" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm9" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm10" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm11" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm12" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm13" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm14" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm15" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm16" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm17" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm18" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm19" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm20" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm21" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm22" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm23" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm24" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm25" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm26" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm27" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm28" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm29" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm30" : : "m" (value));
    rotate(value);
    __asm__ __volatile__("vmovdqu8 %0, %%zmm31" : : "m" (value));

    __asm__ __volatile__("nop");

    char result[64];
    __asm__ __volatile__("vmovdqu8 %%zmm0, %0" : "=m" (result));

    unsigned long check = *(unsigned long*)result;

    if (check == 0xdeadbeefdeadbeef) {
        __asm__ __volatile__("nop");
    }

    return 0;
}
