// 
//  This file is part of libdebug Python library (https://github.com/io-no/libdebug).
//  Copyright (c) 2024 Roberto Alessandro Bertolini.
// 
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, version 3.
// 
//  This program is distributed in the hope that it will be useful, but
//  WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
//  General Public License for more details.
// 
//  You should have received a copy of the GNU General Public License
//  along with this program. If not, see <http://www.gnu.org/licenses/>.
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
