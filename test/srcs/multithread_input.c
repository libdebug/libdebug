//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#define NUM_THREADS 5

void *threadFunction(void *arg) {
    int thread_id = *((int *)arg);
    int input;

    printf("Thread %d: Enter a number: \n", thread_id);
    scanf("%d", &input);

    pthread_exit(NULL);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    
    pthread_t threads[NUM_THREADS];
    int thread_ids[NUM_THREADS];
    int rc;
    int i;

    // Create the threads
    for (i = 0; i < NUM_THREADS; i++) {
        thread_ids[i] = i;
        rc = pthread_create(&threads[i], NULL, threadFunction, (void *)&thread_ids[i]);

        if (rc) {
            printf("ERROR: Return code from pthread_create() is %d\n", rc);
            exit(-1);
        }
    }

    printf("All threads have been created.\n");

    // Wait for all threads to complete
    for (i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("All threads have completed.\n");

    pthread_exit(NULL);
}
