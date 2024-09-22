//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define SIGPROVOLA 25

const char admin_pwd[] = "admin";
const char flag[] = "flag{provola}";

void option_1()
{
    printf("The flag is: %s\n", flag);
}

void option_2()
{
    char input[128];

    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0;

    if (strcmp(input, admin_pwd) == 0)
    {
        printf("Welcome admin!\n");
        printf("The flag is: %s\n", flag);
    }
    else
    {
        printf("Wrong password!\n");
    }
}

void sigprovola_handler(int sig)
{
    printf("Wowsers! This fine piece of code developed by Io_no should have never reached this state!\n");
    printf("Stacktrace[0]: %p\n", __builtin_return_address(0));
    printf("Stacktrace[1]: %s\n", flag);
    printf("Stacktrace[2]: %p\n", __builtin_return_address(2));
}

int main()
{
    setvbuf(stdout, NULL, _IONBF, 0);

    // Register the signal handler
    signal(SIGPROVOLA, sigprovola_handler);

    int choice;

    while (1)
    {
        printf("Welcome to Io_no's personal flag management system!\n");
        printf("Choose an option:\n");
        printf("1. Print the flag\n");
        printf("2. Become admin and print the flag\n");
        printf("3. Raise a signal\n");
        printf("4. Exit\n");

        scanf("%d", &choice);
        fgetc(stdin);

        switch (choice)
        {
        case 1:
            option_1();
            break;
        case 2:
            option_2();
            break;
        case 3:
            raise(SIGPROVOLA);
            break;
        case 4:
            return 0;
        default:
            printf("Invalid choice!\n");
            break;
        }
    }
}