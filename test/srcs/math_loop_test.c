//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>
#include <unistd.h>
#include <math.h>

int main() {
    setvbuf(stdout, NULL, _IONBF, 0); 
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    double result;
    int pid;

    for (int i = 0; i < 1000; i++) {
        // Perform a complex mathematical operation
        result += sin(i) * log(i + 1) * sqrt(i + 1) + cos(i) / (i + 1);

        // Call a harmless syscall
        pid = getpid();
        result += pid;
    }

    return 0;
}