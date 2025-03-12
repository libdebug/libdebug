//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Gabriele Digregorio. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//
#include <stdio.h>

void printMessage(int number) {
    printf("Function call number: %d\n", number);
}

int main() {
    for (int i = 1; i <= 10; i++) {
        printMessage(i);
    }
    return 0;
}
