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

void signal_handler(int sig) {
    printf("Received signal %d\n", sig);
}

int main() {
    // Set up signal handlers
    signal(SIGUSR1, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);
    signal(SIGPIPE, signal_handler);

    // Send SIGUSR1 to self
    kill(getpid(), SIGUSR1);

    // Send SIGTERM to self
    raise(SIGTERM); 

    // Send SIGINT to self
    raise(SIGINT);

    // Send SIGQUIT to self
    raise(SIGQUIT);

    // Send SIGPIPE to self
    raise(SIGPIPE);

    // Now again

    // Send SIGUSR1 to self
    kill(getpid(), SIGUSR1);

    // Send SIGTERM to self
    raise(SIGTERM); 

    // Send SIGINT to self
    raise(SIGINT);

    // Send SIGQUIT to self
    raise(SIGQUIT);

    // Send SIGPIPE to self
    raise(SIGPIPE);

    // Unbalace the number of signals sent

    // Send SIGQUIT to self
    raise(SIGQUIT);

    // Send SIGPIPE to self
    raise(SIGPIPE);

    // Normal program termination after handling signals
    printf("Exiting normally.\n");
    exit(0);
}
