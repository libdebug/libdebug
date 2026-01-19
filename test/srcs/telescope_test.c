//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Gabriele Digregorio. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function to create N levels of pointers to a string
void create_string_pointer_chain(int levels, char **chain, const char *value) {
    chain[levels - 1] = (char *)value;
    for (int i = levels - 2; i >= 0; --i) {
        chain[i] = (char *)&chain[i + 1];
    }
}

// Function to create N levels of pointers to an integer
void create_int_pointer_chain(int levels, void **chain, long long *value) {
    chain[levels - 1] = (void *)value;
    for (int i = levels - 2; i >= 0; --i) {
        chain[i] = (void *)&chain[i + 1];
    }
}

int main() {
    const int levels_5 = 5;
    const int levels_15 = 15;
    const char *text = "Telescope test passed!";
    long long number = 4242;

    // ========== STRING TEST ==========

    // For 5 (+1) levels
    char *string_chain_5[levels_5];
    create_string_pointer_chain(levels_5, string_chain_5, text);
    printf("%p\n", string_chain_5[0]);

    // For 15 (+1) levels
    char *string_chain_15[levels_15];
    create_string_pointer_chain(levels_15, string_chain_15, text);
    printf("%p\n", (void *)string_chain_15[0]);

    // ========== INTEGER TEST ==========

    // For 5 (+1) levels
    void *int_chain_5[levels_5];
    create_int_pointer_chain(levels_5, int_chain_5, &number);
    printf("%p\n", (void *)int_chain_5[0]);

    // For 15 (+1) levels
    void *int_chain_15[levels_15];
    create_int_pointer_chain(levels_15, int_chain_15, &number);
    printf("%p\n", (void *)int_chain_15[0]);

    void *loop_chain[3];
    loop_chain[0] = &loop_chain[1];
    loop_chain[1] = &loop_chain[2];
    loop_chain[2] = &loop_chain[0]; 
    printf("%p\n", (void *)loop_chain[0]);

    // Wait for user input before exiting
    printf("Press Enter to exit...\n");
    getchar();

    return 0;
}
