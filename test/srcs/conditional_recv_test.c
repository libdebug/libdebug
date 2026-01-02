//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

typedef enum {
    COND_NONE = 0,
    COND_BREATHE,
    COND_SUNFLOWER,
    COND_RAINBOW,
    COND_THREE,
    COND_FOUR,
    COND_450,
} conditions_t;

conditions_t condition = COND_NONE;

void break_here()
{
    int a = 0;
    a++;
}

int main(int argc, char** argv, char** envp)
{
    setvbuf(stdout, NULL, _IOLBF, 0);
    puts("Conditional receive test program");
    
    srand((unsigned int)time(NULL));
    
    condition = (conditions_t)(abs(rand() % 6) + 1);

    switch (condition)
    {
    case COND_BREATHE:
        puts("Breathe!");
        break;
    case COND_SUNFLOWER:
        puts("Sunflower.");
        break;
    case COND_RAINBOW:
        puts("Rainbow.");
        break;
    case COND_THREE:
        puts("Three to the right.");
        break;
    case COND_FOUR:
        puts("Four to the left.");
        break;
    case COND_450:
        puts("450");
        break;
    default:
        puts("This should never happen!");
        break;
    }

    break_here();
}