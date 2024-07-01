//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#include <stdlib.h>
#include <time.h>

void a()
{
    // Use current time as seed for random generator
    srand(time(NULL));
    // Generate and manipulate random numbers
    int rv1 = rand();
    int rv2 = rand();
    int rv3 = rand();
    int rv4 = rand();
    int rv5 = rand();

    rv1 ^= rv2;
    rv1 ^= rv3;
    rv1 ^= rv4;
    rv1 ^= rv5;

    rv3 *= rv4;
    rv3 *= rv5;

    rv5 += rv1;
    rv5 += rv2;

    rv2 -= rv3;

    rv4 /= rv5;
}

void b()
{
    a();
}

void c()
{
    b();
}

// Nested function calls to test the finish command
int main()
{
    c();
    return 0;
}