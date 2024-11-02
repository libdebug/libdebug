//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

// Global variables for synchronization
pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
int inputReceived = 0;

void* inputTask(void* arg) {
    printf("Thread 1 is running...\n");
    char input[100];
    fgets(input, sizeof(input), stdin);  
    pthread_mutex_lock(&lock);
    inputReceived = 1; 
    pthread_cond_broadcast(&cond);
    pthread_mutex_unlock(&lock);
    printf("Thread 1 finished.\n");
    return NULL;
}

void* task2(void* arg) {
    printf("Thread 2 is running...\n");
    pthread_mutex_lock(&lock);
    while (!inputReceived) {
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock);
    printf("Thread 2 finished.\n");
    return NULL;
}

void* task3(void* arg) {
    printf("Thread 3 is running...\n");
    pthread_mutex_lock(&lock);
    while (!inputReceived) {
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock);
    printf("Thread 3 finished.\n");
    return NULL;
}

void* task4(void* arg) {
    printf("Thread 4 is running...\n");
    pthread_mutex_lock(&lock);
    while (!inputReceived) {
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock);
    printf("Thread 4 finished.\n");
    return NULL;
}

void* task5(void* arg) {
    printf("Thread 5 is running...\n");
    pthread_mutex_lock(&lock);
    while (!inputReceived) {
        pthread_cond_wait(&cond, &lock);
    }
    pthread_mutex_unlock(&lock);
    printf("Thread 5 finished.\n");
    return NULL;
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    
    pthread_t threads[5];

    pthread_create(&threads[0], NULL, inputTask, NULL);
    pthread_create(&threads[1], NULL, task2, NULL);
    pthread_create(&threads[2], NULL, task3, NULL);
    pthread_create(&threads[3], NULL, task4, NULL);
    pthread_create(&threads[4], NULL, task5, NULL);

    for (int i = 0; i < 5; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("All threads have completed their tasks.\n");
    pthread_mutex_destroy(&lock);
    pthread_cond_destroy(&cond);
    return 0;
}
