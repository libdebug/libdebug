//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

sem_t sem_other;

void do_nothing()
{

}

void do_nothing_target()
{

}

void do_something_target()
{
    int b = 0;

    for (int i = 0; i < 10; i++) {
        b += i;
    }
}

void* target_thread_function()
{
    do_nothing_target();

    int a = 0;

    for (int i = 0; i < 1024; i++) {
        a += i;
    }

    asm __volatile__("nop");
    do_something_target();
}

void do_nothing_other()
{

}

void* other_thread_function()
{
    int a;
loop:
    a = 0;

    for (int i = 0; i < 1024; i++) {
        do_nothing_other();
        a += i;
    }

    if (sem_trywait(&sem_other)) {
        goto loop;
    }
}

int main()
{
    pthread_t target, other;

    sem_init(&sem_other, 0, 0);

    pthread_create(&target, NULL, target_thread_function, NULL);
    pthread_create(&other, NULL, other_thread_function, NULL);

    do_nothing();

    int a;
    for (int i = 0; i < 10; i++) {
        a += i;
    }

    do_nothing();

    sem_post(&sem_other);

    pthread_join(target, NULL);
    pthread_join(other, NULL);

    return 0;
}