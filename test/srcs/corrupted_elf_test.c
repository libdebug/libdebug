//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <sys/syscall.h>

void skill_issue()
{
    puts("Antonio.");
}

void sigbus()
{
    raise(SIGBUS);
}

int main()
{
    puts("Provola!");

    int x = 0;
    scanf("%d", &x);

    skill_issue();

    sigbus();

    syscall(0x1337);

    return 0;
}
