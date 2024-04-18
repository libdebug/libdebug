//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2023-2024 Gabriele Digregorio, Francesco Panebianco.
// Copyright (c) 2024 Roberto Alessandro Bertolini.
// All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>

int check_antidebug()
{
    return ptrace(PTRACE_TRACEME, 0, 1, 0) == -1;
}

int main(int argc, char** argv)
{
    const char correct[] = "BRUTE\0";
    char buffer[64];
    int isCorrect = 1;

    //setvbuf(stdin, NULL, _IONBF, 0);
    //setvbuf(stdout, NULL, _IONBF, 0);

    // The first call to PTRACEME should succeed
    if (check_antidebug()) {
        printf("Debugger detected\n");
        return 1;
    }

    printf("Write up to 64 chars\n");

    fgets(buffer, 64, stdin);

    for(int i = 0; i< 64; i++) {
        if (correct[i] == '\0')
            break;

        if (buffer[i] != correct[i] || !check_antidebug()) {
            isCorrect = 0;
            break;
        }
    }

    if (isCorrect) {
        printf("Giusto!\n");
    } else {
        printf("Sbagliato!\n");
    }

    return 0;
}
