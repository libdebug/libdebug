//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Gabriele Digregorio. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    int depth = 0;  // Initialize process depth

    while (depth < 5) {  // Loop until we spawn the fifth process
        pid_t pid = fork();

        if (pid == -1) {
            // If fork() returns -1, the creation of a child process failed.
            perror("fork failed");
            exit(EXIT_FAILURE);
        } else if (pid == 0) {
            // This block is executed only by the child process.
            depth++;  // Increment depth for each child
            if (depth == 5) {
                // If this is the fifth process
                char input[100];  // Buffer to store input
                printf("Enter your input: ");
                fgets(input, sizeof(input), stdin);  // Read input from the user
                printf("You entered: %s", input);
                exit(EXIT_SUCCESS);  // Child process exits
            }
        } else {
            // This block is executed only by the parent process.
            wait(NULL);  // Parent waits for the child to complete
            break;  // After waiting, break the loop and prevent further forking
        }
    }

    return EXIT_SUCCESS;
}
