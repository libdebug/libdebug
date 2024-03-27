//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>
#include <stdlib.h>

void do_nothing()
{
    asm volatile ("nop":::);
}

int main()
{
    for (int i = 0; i < 65536; i++)
    {
        do_nothing();
    }

    return EXIT_SUCCESS;
}
