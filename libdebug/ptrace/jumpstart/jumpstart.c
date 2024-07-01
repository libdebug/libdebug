//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h>


int main(int argc, char **argv)
{
    // argv[1] is the length of the custom environment variables
    // argv[2:2 + env_len] is the custom environment variables
    // argv[2 + env_len] should be NULL
    // argv[2 + env_len + 1:] is the new argv
    int env_len = atoi(argv[1]);

    int argv_offset = env_len > 0 ? env_len : 0;

    argv[2 + argv_offset] = NULL;

    char **new_environ = argv + 2;
    char **new_argv = argv + 2 + argv_offset + 1;

    ptrace(PTRACE_TRACEME, 0, 0, 0);

    if (env_len == -1) {
        execve(new_argv[0], new_argv, environ);
    } else {
        execve(new_argv[0], new_argv, new_environ);
    }
}
