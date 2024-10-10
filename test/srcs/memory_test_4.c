//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>

sem_t semaphores[4];
sem_t leaks_done;

void leak(char *ptr)
{

}

void before_exit()
{

}

void* thread_fun(void *arg)
{
    // cast arg to int
    int thread_index = (int) ((unsigned long) arg);

    char test[16];

    memset(test, thread_index, 16);

    char *test_ptr = malloc(16);

    memset(test_ptr, thread_index + 4, 16);

    leak(test);
    leak(test_ptr);

    sem_post(&leaks_done);

    sem_wait(&semaphores[thread_index]);
}

int main()
{
    // allocate four threads
    pthread_t threads[4];

    sem_init(&leaks_done, 0, 0);

    for (int i = 0; i < 4; i++) {
        sem_init(&semaphores[i], 0, 0);
        pthread_create(&threads[i], NULL, thread_fun, (void *) ((unsigned long) i));
    }

    for (int i = 0; i < 4; i++)
        sem_wait(&leaks_done);

    before_exit();

    for (int i = 0; i < 4; i++)
        sem_post(&semaphores[i]);

    for (int i = 0; i < 4; i++)
        pthread_join(threads[i], NULL);

    return 0;
}