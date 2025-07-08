//
// This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
// Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for details.
//

#define HAVE_DECL_BASENAME 1
#include <demangle.h>

void test_if_libiberty_is_compiled_as_pic()
{
    char *not_important = cplus_demangle_v3("test", DMGL_PARAMS | DMGL_ANSI | DMGL_TYPES);
}
