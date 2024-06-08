//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>
#include <stdlib.h>

__attribute__((constructor))
void preload()
{
    fprintf(stdout, "Preload library loaded\n");
}

int execve(const char *pathname, char *const argv[], char *const envp[])
{
    fprintf(stdout, "execve(%s, %p, %p)\n", pathname, argv, envp);
    return 0;
}
