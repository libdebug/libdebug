//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <pthread.h>

// Global variables for synchronization
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
pthread_cond_t cond_done = PTHREAD_COND_INITIALIZER;
int ready = 0;
int sender_done = 0;

void signal_handler_receiver(int sig) {
    printf("Received signal on receiver %d\n", sig);
}

void signal_handler_sender(int sig) {
    printf("Received signal on sender %d\n", sig);
}

void *sender(void *arg) {
    pthread_t thread = *(pthread_t *)arg;

    // Wait until the receiver is ready
    pthread_mutex_lock(&mutex);
    while (!ready) {
        pthread_cond_wait(&cond, &mutex);
    }
    pthread_mutex_unlock(&mutex);

    char input[100];

    // Send signals to the receiver
    pthread_kill(thread, SIGUSR1);
    scanf("%99s", input);
    pthread_kill(thread, SIGTERM);
    scanf("%99s", input);
    pthread_kill(thread, SIGINT);
    scanf("%99s", input);
    pthread_kill(thread, SIGQUIT);
    scanf("%99s", input);
    pthread_kill(thread, SIGPIPE);
    scanf("%99s", input);
    pthread_kill(thread, SIGUSR1);
    scanf("%99s", input);
    pthread_kill(thread, SIGTERM);
    scanf("%99s", input);
    pthread_kill(thread, SIGINT);
    scanf("%99s", input);
    pthread_kill(thread, SIGQUIT);
    scanf("%99s", input);
    pthread_kill(thread, SIGPIPE);
    scanf("%99s", input);
    pthread_kill(thread, SIGQUIT);
    scanf("%99s", input);
    pthread_kill(thread, SIGPIPE);
    scanf("%99s", input);

    // Notify receiver that sender is done
    pthread_mutex_lock(&mutex);
    sender_done = 1;
    pthread_cond_signal(&cond_done);
    pthread_mutex_unlock(&mutex);


    printf("Sender exiting normally.\n");
    return NULL;
}

void *receiver() {
    // Set up signal handlers
    signal(SIGUSR1, signal_handler_receiver);
    signal(SIGTERM, signal_handler_receiver);
    signal(SIGINT, signal_handler_receiver);
    signal(SIGQUIT, signal_handler_receiver);
    signal(SIGPIPE, signal_handler_receiver);

    // Signal that the receiver is ready
    pthread_mutex_lock(&mutex);
    ready = 1;
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&mutex);

    // Wait until sender signals it's done
    pthread_mutex_lock(&mutex);
    while (!sender_done) {
        pthread_cond_wait(&cond_done, &mutex);
    }
    pthread_mutex_unlock(&mutex);

    // Final sync before exit
    char input[100];
    scanf("%99s", input);

    printf("Receiver exiting normally.\n");
    return NULL;
}

int main() {
    pthread_t thread_1, thread_2;

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    pthread_create(&thread_1, NULL, receiver, NULL);
    pthread_create(&thread_2, NULL, sender, &thread_1);

    pthread_join(thread_1, NULL);
    pthread_join(thread_2, NULL);

    return 0;
}