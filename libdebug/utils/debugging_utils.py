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

from libdebug.data.memory_map import MemoryMap


def normalize_and_validate_address(address: int, maps: list[MemoryMap]) -> int:
    """Normalizes and validates the specified address.

    Returns:
        int: The normalized address.

    Throws:
        ValueError: If the specified address does not belong to any memory map.
    """
    if address < maps[0].start:
        # The address is lower than the base address of the process. Suppose it is a relative address for a PIE binary.
        return address + maps[0].start

    for map in maps:
        if map.start <= address < map.end:
            return address
    else:
        raise ValueError(f"Address {hex(address)} does not belong to any memory map.")
