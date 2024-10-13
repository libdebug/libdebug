//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

int main()
{
    // load into the mmx registers the values
    char value0[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
    __asm__ __volatile__("movq %0, %%mm0" : : "m" (value0));
    char value1[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    __asm__ __volatile__("movq %0, %%mm1" : : "m" (value1));
    char value2[] = {0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99};
    __asm__ __volatile__("movq %0, %%mm2" : : "m" (value2));
    char value3[] = {0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA};
    __asm__ __volatile__("movq %0, %%mm3" : : "m" (value3));
    char value4[] = {0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
    __asm__ __volatile__("movq %0, %%mm4" : : "m" (value4));
    char value5[] = {0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC};
    __asm__ __volatile__("movq %0, %%mm5" : : "m" (value5));
    char value6[] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD};
    __asm__ __volatile__("movq %0, %%mm6" : : "m" (value6));
    char value7[] = {0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    __asm__ __volatile__("movq %0, %%mm7" : : "m" (value7));

    __asm__ __volatile__("nop");

    // load the value from the mmx register into the value variable
    char value[8];
    __asm__ __volatile__("movq %%mm0, %0" : "=m" (value));

    unsigned long check = *(unsigned long*)value;

    if (check == 0xdeadbeef) {
        __asm__ __volatile__("nop");
    }

    // load into the st registers floating point values
    __asm__ __volatile__("finit");
    double value8 = 123.456;
    __asm__ __volatile__("fldl %0" : : "m" (value8));
    double value9 = 234.567;
    __asm__ __volatile__("fldl %0" : : "m" (value9));
    double value10 = 345.678;
    __asm__ __volatile__("fldl %0" : : "m" (value10));
    double value11 = 456.789;
    __asm__ __volatile__("fldl %0" : : "m" (value11));
    double value12 = 567.890;
    __asm__ __volatile__("fldl %0" : : "m" (value12));
    double value13 = 678.901;
    __asm__ __volatile__("fldl %0" : : "m" (value13));
    double value14 = 789.012;
    __asm__ __volatile__("fldl %0" : : "m" (value14));
    double value15 = 890.123;
    __asm__ __volatile__("fldl %0" : : "m" (value15));

    __asm__ __volatile__("nop");

    // load the value from the st register into the value variable
    double result;
    __asm__ __volatile__("fstpl %0" : "=m" (result));

    if ((int) result == 1337) {
        __asm__ __volatile__("nop");
    }

    return 0;
}
