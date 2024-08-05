//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <unistd.h>
#include <sys/mman.h>

void do_nothing(int *leak)
{

}

int main()
{
    int *buffer = mmap(NULL, sizeof(int) * 1024 * 1024, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    for (int i = 0; i < 1024 * 1024; i++) {
        buffer[i] = i;
    }

    do_nothing(buffer);

    munmap(buffer, sizeof(int) * 1024 * 1024);

    return 0;
}