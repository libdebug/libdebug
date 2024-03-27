//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2023-2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

uint64_t register_test(uint64_t number)
{
    return number;
}

int main()
{
    uint64_t value;

    value = 0xaabbccdd11223344;

    value = register_test(value);

    printf("Basic test pie: %lx\n", value);

    return 0;
}
