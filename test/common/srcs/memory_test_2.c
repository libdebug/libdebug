//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#include <unistd.h>

int state = 0;

void do_nothing()
{

}

int main()
{
    state = 1;

    sleep(1);

    state = 0xdeadbeef;
    do_nothing();

    return 0;
}
