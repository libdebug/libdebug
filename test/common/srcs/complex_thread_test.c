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
    int x = 0;
    for (int i = 0; i < 50; i++)
    {
        x += i;
    }
}

void thread_2_function()
{
    int x = 1;
    for (int i = 1; i < 50; i++)
    {
        x *= i;
    }
}

void do_nothing()
{
    asm volatile ("nop\n\t");
}

int main()
{
    pthread_t thread_1, thread_2;
    
    pthread_create(&thread_1, NULL, (void *)thread_1_function, NULL);
    pthread_join(thread_1, NULL);

    do_nothing();

    pthread_create(&thread_2, NULL, (void *)thread_2_function, NULL);
    pthread_join(thread_2, NULL);

    return 0;
}
