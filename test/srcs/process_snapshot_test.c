//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

void thread_function()
{
    // Sleep for 1 second
    struct timespec ts;
    ts.tv_sec = 1;          // 1 second
    ts.tv_nsec = 0;         // 0 nanoseconds

    // Perform nanosleep
    nanosleep(&ts, NULL);
}

void not_interesting()
{
    int a = 0;
    a++;
}

int main()
{
    pthread_t thread_1, thread_2, thread_3;
    pthread_create(&thread_1, NULL, (void *)thread_function, NULL);
    pthread_create(&thread_2, NULL, (void *)thread_function, NULL);
    pthread_create(&thread_3, NULL, (void *)thread_function, NULL);

    not_interesting();

    pthread_join(thread_1, NULL);
    pthread_join(thread_2, NULL);
    pthread_join(thread_3, NULL);

    return 0;
}
