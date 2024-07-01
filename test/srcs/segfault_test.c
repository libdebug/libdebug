//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Gabriele Digregorio, Marco Meinardi. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>

int main() {
    printf("Hello, World!\n");
	char* a = (char*)0x1234;
    printf("Death is coming!\n");
	*a = 'a';
    printf("Death is here!\n");
}