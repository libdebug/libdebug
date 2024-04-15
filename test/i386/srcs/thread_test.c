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
    "mov $0x00112233, %%eax\n\t"
    "nop\n\t"::: "eax");
}

void thread_2_function()
{
    asm volatile (
    "mov $0xccdd1122, %%eax\n\t"
    "nop\n\t"::: "rax");
}

void thread_3_function()
{
    asm volatile (
    "mov $0x66770011, %%eax\n\t"
    "nop\n\t"::: "rax");
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
