//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2023-2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void f(int i)
{
    (void) i;
}

int main()
{
    for (int i = 0; i < 1e5; i++) {
        f(i);
    }

    return 0;
}