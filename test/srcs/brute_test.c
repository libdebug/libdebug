// 
//  This file is part of libdebug Python library (https://github.com/io-no/libdebug).
//  Copyright (c) 2023 Gabriele Digregorio, Francesco Panebianco.
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
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv)
{
    const char correct[] = "BRUTINOBRUTONE\0";
    char buffer[64];
    int isCorrect = 1;

    //setvbuf(stdin, NULL, _IONBF, 0);
    //setvbuf(stdout, NULL, _IONBF, 0);


    printf("Write up to 64 chars\n");

    fgets(buffer, 64, stdin);

    for(int i = 0; i< 64; i++)
    {
        if(correct[i] == '\0')
        {
            break;
        }

        if(buffer[i] != correct[i])
        {
            isCorrect = 0;
            break;
        }
    }

    if (isCorrect)
    {
        printf("Giusto!\n");
    }
    else
    {
        printf("Sbagliato!\n");
    }

    return 0;
}
