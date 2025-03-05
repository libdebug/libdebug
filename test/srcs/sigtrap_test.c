//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Gabriele Digregorio. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#include <stdio.h>
#include <signal.h>
#include <unistd.h>

volatile int trap_count = 0;  // Counter for the number of SIGTRAPs caught

void handle_sigtrap(int sig) {
    printf("SIGTRAP received %d times\n", ++trap_count);
}

int main() {
    struct sigaction sa;

    // Set up the sigaction struct to handle SIGTRAP with handle_sigtrap
    sa.sa_handler = handle_sigtrap;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;  // No special flags

    // Associate the sigaction with SIGTRAP
    if (sigaction(SIGTRAP, &sa, NULL) != 0) {
        perror("Failed to set signal handler");
        return 1;
    }

    // Raise SIGTRAP exactly 5 times
    for (int i = 0; i < 5; i++) {
        raise(SIGTRAP);
    }

    return 0; // Program ends normally after five SIGTRAPs
}
