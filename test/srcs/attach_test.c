//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>

void printName(char name[]) {
    printf("Your name is: %s", name);
}

int main(){
    char name[100];

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    printf("Enter your name: ");
    fgets(name, sizeof(name), stdin);

    printName(name);
    return 0;
}