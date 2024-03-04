#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
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
