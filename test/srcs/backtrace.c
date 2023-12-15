// 
//  This file is part of libdebug Python library (https://github.com/io-no/libdebug).
//  Copyright (c) 2023 Gabriele Digregorio.
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
