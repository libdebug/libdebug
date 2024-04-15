//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#define _GNU_SOURCE

#include <sys/mman.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
    write(1, "Hello, World!\n", 14);

    char buffer[1024] = {0};

    read(0, buffer, 1023);
    buffer[1023] = '\0';

    write(1, buffer, 1024);

    char *ptr = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (ptr == MAP_FAILED) {
        perror("mmap");
        return 1;
    }

    getcwd(ptr, 4096);

    return 0;
}
