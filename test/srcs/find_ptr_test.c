//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Gabriele Digregorio. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#include <stdio.h>
#include <stdlib.h>

int main() {
    // Declare three stack variables.
    int stack_var1 = 10;
    int stack_var2 = 20;
    int stack_var3 = 30;

    // Allocate memory on the heap for storing three addresses.
    int **heap_array = malloc(3 * sizeof(int *));

    if (heap_array == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        return EXIT_FAILURE;
    }

    // Store the addresses of the stack variables in the heap array.
    heap_array[0] = &stack_var1;
    heap_array[1] = &stack_var2;
    heap_array[2] = &stack_var3;

    // Print the addresses of the stack variables and their locations on the heap.
    for (int i = 0; i < 3; i++) {
        printf("%p %p\n", (void *)&heap_array[i], (void *)heap_array[i]);
    }

    // Free the allocated memory.
    free(heap_array);

    return EXIT_SUCCESS;
}
