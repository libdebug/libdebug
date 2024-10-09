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

    __asm__ __volatile__("nop");

    char result[64];
    __asm__ __volatile__("vmovdqu8 %%zmm0, %0" : "=m" (result));

    unsigned long check = *(unsigned long*)result;

    if (check == 0xdeadbeef) {
        __asm__ __volatile__("nop");
    }

    return 0;
}
