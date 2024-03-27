#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from cffi import FFI

ffibuilder = FFI()

ffibuilder.cdef(
    """

    int disable_aslr();

"""
)

ffibuilder.set_source(
    "libdebug.cffi._personality_cffi",
    """
#include <sys/personality.h>
                      
int disable_aslr()
{
    int persona = personality(0xffffffff);
                      
    persona |= ADDR_NO_RANDOMIZE;
                      
    return personality(persona);
}
""",
    libraries=[],
)

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
