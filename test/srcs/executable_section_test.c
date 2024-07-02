//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

// Function to be executed in allocated memory
int hello_world(int a) {
    return a*a;
}

int main() {
    // Size of the function to be allocated
    size_t func_size = (char*)main - (char*)hello_world;

    // Allocate memory region using mmap
    void *pippo = mmap(NULL, func_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (pippo == MAP_FAILED) {
        perror("Failed to allocate memory");
        return EXIT_FAILURE;
    }

    // Copy the function to the allocated memory
    memcpy(pippo, hello_world, func_size);

    // Make the allocated memory region executable
    if (mprotect(pippo, func_size, PROT_READ | PROT_EXEC) == -1) {
        perror("Failed to make memory executable");
        munmap(pippo, func_size);
        return EXIT_FAILURE;
    }

    // Cast the memory to a function pointer and execute it
    void (*func)() = (void (*)())pippo;
    func(3);

    // Free the allocated memory
    munmap(pippo, func_size);

    return EXIT_SUCCESS;
}
