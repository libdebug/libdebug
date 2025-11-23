//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

void do_nothing()
{

}

int main()
{
    // Part 1:
    char *ptr = mmap((void*)0xbadf0000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

    int* p = (int*)ptr;
    *p = 42; // Write to the mapped memory to trigger any watchpoint

    munmap(ptr, 0x1000);

    // Part 2:
    ptr = mmap((void*)0xdeadb000, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

    // 0x30 ought to be enough for our do_nothing function
    memcpy(ptr, &do_nothing, 0x30);

    void (*func)() = (void (*)())ptr;

    func(); // Call the function to trigger any breakpoint

    munmap(ptr, 0x1000);

    return 0;
}