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
from libdebug.utils.elf_utils import resolve_symbol, is_pie
import logging


def normalize_and_validate_address(address: int, maps: list[MemoryMap]) -> int:
    """Normalizes and validates the specified address.

    Returns:
        int: The normalized address.

    Throws:
        ValueError: If the specified address does not belong to any memory map.
    """
    if address < maps[0].start:
        # The address is lower than the base address of the process. Suppose it is a relative address for a PIE binary.
        address += maps[0].start

    for map in maps:
        if map.start <= address < map.end:
            return address
    else:
        raise ValueError(f"Address {hex(address)} does not belong to any memory map.")


def resolve_symbol_in_maps(symbol: str, maps: list[MemoryMap]) -> int:
    """Returns the address of the specified symbol in the specified memory maps.

    Args:
        maps (list[MemoryMap]): The memory maps.
        symbol (str): The symbol whose address should be returned.

    Returns:
        int: The address of the specified symbol in the specified memory maps.

    Throws:
        ValueError: If the specified symbol does not belong to any memory map.
    """
    mapped_files = {}

    if "+" in symbol:
        symbol, offset = symbol.split("+")
        offset = int(offset, 16)
    else:
        offset = 0

    for map in maps:
        if map.backing_file and map.backing_file not in mapped_files:
            mapped_files[map.backing_file] = map.start

    for file, base_address in mapped_files.items():
        try:
            address = resolve_symbol(file, symbol)

            if is_pie(file):
                address += base_address

            return address + offset
        except OSError as e:
            logging.debug(f"Error while resolving symbol {symbol} in {file}: {e}")
        except ValueError:
            pass
    else:
        raise ValueError(
            f"Symbol {symbol} not found in any mapped file. Please specify a valid symbol."
        )
