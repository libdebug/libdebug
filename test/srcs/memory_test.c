// 
//  This file is part of libdebug Python library (https://github.com/io-no/libdebug).
//  Copyright (c) 2023 Roberto Alessandro Bertolini.
// 
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, version 3.
// 
//  This program is distributed in the hope that it will be useful, but
//  WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
//  General Public License for more details.
// 
//  You should have received a copy of the GNU General Public License
//  along with this program. If not, see <http://www.gnu.org/licenses/>.
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
