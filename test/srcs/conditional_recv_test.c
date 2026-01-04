//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Francesco Panebianco. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

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
    setvbuf(stderr, NULL, _IOLBF, 0);
    puts("Conditional receive test program");

    int file_select = 0;

    if (argc > 1)
    {
        if (strcmp(argv[1], "stderr") == 0)
        {
            file_select = 1;
        }
    }

    FILE* out_file = (file_select == 0) ? stdout : stderr;
    
    srand((unsigned int)time(NULL));
    
    condition = (conditions_t)((rand() % 6) + 1);

    switch (condition)
    {
    case COND_BREATHE:
        fputs("Breathe!", out_file);
        break;
    case COND_SUNFLOWER:
        fputs("Sunflower.", out_file);
        break;
    case COND_RAINBOW:
        fputs("Rainbow.", out_file);
        break;
    case COND_THREE:
        fputs("Three to the right.", out_file);
        break;
    case COND_FOUR:
        fputs("Four to the left.", out_file);
        break;
    case COND_450:
        fputs("450", out_file);
        break;
    default:
        fputs("This should never happen!", out_file);
        break;
    }
    fflush(out_file);

    break_here();
}