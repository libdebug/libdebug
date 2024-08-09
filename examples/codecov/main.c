//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int long_from_base64_decimal_str(char *str)
{
    // Validate that the input string is not NULL
    if (str == NULL) {
        return -1;
    }

    size_t len = strlen(str);

    // Validate that the input string is not empty
    if (len == 0) {
        return -1;
    }

    // Validate that the input string is a multiple of 4
    if (len % 4 != 0) {
        return -1;
    }

    // Validate that the input string is a valid base64 string
    for (size_t i = 0; i < len; i++) {
        if (str[i] < 0x20 || str[i] > 0x7E) {
            return -1;
        }
    }

    // Convert the base64 string to its byte values
    for (size_t i = 0; i < len; i++) {
        if (str[i] >= 'A' && str[i] <= 'Z') {
            str[i] = str[i] - 'A';
        } else if (str[i] >= 'a' && str[i] <= 'z') {
            str[i] = str[i] - 'a' + 26;
        } else if (str[i] >= '0' && str[i] <= '9') {
            str[i] = str[i] - '0' + 52;
        } else if (str[i] == '+') {
            str[i] = 62;
        } else if (str[i] == '/') {
            str[i] = 63;
        } else if (str[i] == '=') {
            str[i] = 0;
        } else {
            return -1;
        }
    }

    // Allocate memory for the decoded string
    char *dec_str = (char *)malloc(len);

    // Validate that the memory allocation was successful
    if (dec_str == NULL) {
        return -1;
    }

    // Decode the base64 string
    size_t j = 0;
    for (size_t i = 0; i < len; i += 4, j += 3) {
        dec_str[j] = (str[i] << 2) | (str[i + 1] >> 4);
        dec_str[j + 1] = (str[i + 1] << 4) | (str[i + 2] >> 2);
        dec_str[j + 2] = (str[i + 2] << 6) | str[i + 3];
    }

    long result = 0;

    // Clear errno
    errno = 0;

    // Convert the decoded string to a long
    result = strtol(dec_str, NULL, 10);

    // Check for errors during the conversion
    if (errno != 0) {
        // Free the memory allocated for the decoded string
        free(dec_str);
        return -1;
    }

    // Free the memory allocated for the decoded string
    free(dec_str);

    return result;
}

int main()
{
    puts("Please enter a base64 decimal string:");

    char str[256];
    fgets(str, sizeof(str), stdin);

    // Remove the newline character from the input string
    str[strcspn(str, "\n")] = '\0';

    long result = long_from_base64_decimal_str(str);

    if (result == -1) {
        puts("Invalid input string");
    } else {
        printf("%ld\n", result);
    }
}