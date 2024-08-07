//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

void rotate(char value[16])
{
    char temp = value[0];
    for (int i = 0; i < 15; i++) {
        value[i] = value[i + 1];
    }
    value[15] = temp;
}

int main()
{
    char value[16];

    for (int i = 0; i < 16; i++) {
        value[i] = i;
    }

    // aarch64 floating point registers
    __asm__ __volatile__("ld1 {v0.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v1.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v2.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v3.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v4.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v5.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v6.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v7.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v8.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v9.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v10.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v11.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v12.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v13.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v14.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v15.16b}, [%0]" : : "r" (value));
    rotate(value);

    for (int i = 0; i < 16; i++) {
        value[i] = 0x80 + i;
    }

    __asm__ __volatile__("ld1 {v16.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v17.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v18.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v19.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v20.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v21.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v22.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v23.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v24.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v25.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v26.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v27.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v28.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v29.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v30.16b}, [%0]" : : "r" (value));
    rotate(value);
    __asm__ __volatile__("ld1 {v31.16b}, [%0]" : : "r" (value));

    __asm__ __volatile__("nop\n\t");

    char result[16];
    __asm__ __volatile__("st1 {v0.16b}, [%0]" : : "r" (result));

    unsigned long check = *(unsigned long*)result;

    if (check == 0xdeadbeefdeadbeef) {
        __asm__ __volatile__("nop\n\t");
    }

    return 0;
}