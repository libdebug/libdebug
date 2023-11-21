#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 Roberto Alessandro Bertolini.
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

def u64(value: bytes) -> int:
    """Converts the specified value to an unsigned 64-bit integer.

    Args:
        value (bytes): The value to convert.

    Returns:
        int: The converted value.
    """
    value = int.from_bytes(value, "little", signed=False)
    return value & 0xFFFFFFFFFFFFFFFF


def p64(value: int) -> bytes:
    """Converts the specified value to a 64-bit integer, represented as bytes.

    Args:
        value (int): The value to convert.

    Returns:
        bytes: The converted value.
    """
    return value.to_bytes(8, "little", signed=False)
