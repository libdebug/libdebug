//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main()
{
    fprintf(stdout, "Jumpstart test\n");

    execve("/bin/ls", NULL, NULL);

    return 0;
}
