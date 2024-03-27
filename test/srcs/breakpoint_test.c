//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2023-2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>
#include <stdlib.h>

void random_function()
{
    printf("Random function\n");

    int x = 0;
    for (int i = 0; i < 10; i++)
    {
        x += i;        
    }

    printf("x = %d\n", x);
}

int main()
{
    printf("Provola\n");

    random_function();

    return EXIT_SUCCESS;
}
