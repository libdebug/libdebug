//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2023-2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void change_memory(char *address)
{
    (void) address;

    return;
}

void validate_setter(char *address)
{
    (void) address;

    printf("Good!\n");

    return;
}

void leak_address(char* address)
{
    (void) address;

    return;
}

int main()
{
    char *buffer = malloc(256);

    for (int i = 0; i < 256; i++)
        buffer[i] = (char)i;

    change_memory(buffer);

    if (!strncmp(buffer + 128, "abcd1234", 8)) {
        validate_setter(buffer + 128);
    }

    free(buffer);

    buffer = malloc(2048);
    char *useless = malloc(32); // avoid consolidate
    (void) useless;

    free(buffer);

    leak_address(buffer);

    return 0;
}
