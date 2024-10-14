//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>

// Function to be executed by the input/output thread
void *io_thread(void *arg) {
    char buffer[256]; // Buffer to store user input

    while (1) {
        printf("Enter some text: ");
        if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
            printf("You entered: %s", buffer);
        }
    }

    return NULL;
}

// Function to be executed by the interval print thread
void *interval_thread(void *arg) {
    int count = 0;
    while (1) {
        printf("stdout: Count %d\n", ++count);
        fprintf(stderr, "stderr: \x88\x90 Count %d\n", count);
        sleep(1); // Wait for 1 second
    }

    return NULL;
}

int main() {
    pthread_t thread1, thread2;

    // Create the first thread for input/output
    if (pthread_create(&thread1, NULL, io_thread, NULL)) {
        fprintf(stderr, "Error creating thread\n");
        return 1;
    }

    // Create the second thread for interval printing
    if (pthread_create(&thread2, NULL, interval_thread, NULL)) {
        fprintf(stderr, "Error creating thread\n");
        return 1;
    }

    // Wait for both threads to finish (they won't in this simple example)
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    return 0;
}
