//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

void thread_1_function()
{
    asm volatile (
    "movk x0, #0x1111, lsl #0\n\t"
    "movk x0, #0x2222, lsl #16\n\t"
    "movk x0, #0x3333, lsl #32\n\t"
    "movk x0, #0x4444, lsl #48\n\t"
    "nop\n\t"::: "x0");
}

void thread_2_function()
{
    asm volatile (
    "movk x0, #0x6666, lsl #0\n\t"
    "movk x0, #0x7777, lsl #16\n\t"
    "movk x0, #0x8888, lsl #32\n\t"
    "movk x0, #0x9999, lsl #48\n\t"
    "nop\n\t"::: "x0");
}

void thread_3_function()
{
    asm volatile (
    "movk x0, #0xeeee, lsl #0\n\t"
    "movk x0, #0xffff, lsl #16\n\t"
    "movk x0, #0x1111, lsl #32\n\t"
    "movk x0, #0x2222, lsl #48\n\t"
    "nop\n\t"::: "x0");
}

void do_nothing()
{
    asm volatile ("nop\n\t");
}

int main()
{
    pthread_t thread_1, thread_2, thread_3;
    pthread_create(&thread_1, NULL, (void *)thread_1_function, NULL);
    pthread_create(&thread_2, NULL, (void *)thread_2_function, NULL);
    pthread_create(&thread_3, NULL, (void *)thread_3_function, NULL);
    pthread_join(thread_1, NULL);
    pthread_join(thread_2, NULL);
    pthread_join(thread_3, NULL);

    do_nothing();

    return 0;
}
