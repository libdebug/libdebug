//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2023-2024 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>

// Function prototypes
int function1();
int function2(int x);
int function3(int x);
int function4(int x);
int function5(int x);
int function6(int x);

int main() {
    int result = function1();
    printf("Result: %d\n", result);
    return 0;
}

int function1() {
    return function2(1);
}

int function2(int x) {
    return function3(x + 1);
}

int function3(int x) {
    return function4(x + 2);
}

int function4(int x) {
    return function5(x + 3);
}

int function5(int x) {
    return function6(x + 4);
}

int function6(int x) {
    return x + 5;
}
