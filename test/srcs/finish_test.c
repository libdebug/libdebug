// 
//  This file is part of libdebug Python library (https://github.com/io-no/libdebug).
//  Copyright (c) 2024 Francesco Panebianco.
// 
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, version 3.
// 
//  This program is distributed in the hope that it will be useful, but
//  WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
//  General Public License for more details.
// 
//  You should have received a copy of the GNU General Public License
//  along with this program. If not, see <http://www.gnu.org/licenses/>.
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