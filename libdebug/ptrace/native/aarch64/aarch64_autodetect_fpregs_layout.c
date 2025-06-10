//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

// The purpose of this script is to do nothing, as on aarch64 the FP registers layout is fixed
// and does not require any autodetection. It is used to maintain consistency with other architectures.

#include <stdio.h>

int main()
{
    // We create a dummy json with just the option we need.
    puts("{");
    puts("    \"struct_size\": 0,");
    puts("    \"type\": 0,");
    puts("    \"has_xsave\": false");
    puts("}");
    return 0;
}