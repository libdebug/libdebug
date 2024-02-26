// 
//  This file is part of libdebug Python library (https://github.com/io-no/libdebug).
//  Copyright (c) 2023 - 2024 Roberto Alessandro Bertolini.
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
