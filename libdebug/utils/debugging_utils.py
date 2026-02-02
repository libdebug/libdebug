#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Gabriele Digregorio, Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from libdebug.data.memory_map import MemoryMap
from libdebug.data.memory_map_list import MemoryMapList
from libdebug.data.symbol_list import SymbolList
from libdebug.liblog import liblog


def normalize_and_validate_address(address: int, maps: MemoryMapList[MemoryMap]) -> int:
    """Normalizes and validates the specified address.

    Args:
        address (int): The address to normalize and validate.
        maps (MemoryMapList[MemoryMap]): The memory maps.

    Returns:
        int: The normalized address.

    Throws:
        ValueError: If the specified address does not belong to any memory map.
    """
    if not maps:
        raise ValueError("No memory maps available to resolve the address. Did you specify a valid backing file?")
    if address < maps[0].start:
        # The address is lower than the base address of the lowest map. Suppose it is a relative address for a PIE binary.
        address += maps[0].start

    for vmap in maps:
        if vmap.start <= address < vmap.end:
            return address

    raise ValueError(f"Address {hex(address)} does not belong to any memory map.")


def resolve_symbol_name_in_maps_util(
    address: int,
    external_symbols: SymbolList,
) -> str:
    """Resolves the address to a symbol name using a SymbolList."""
    if not external_symbols:
        return f"{address:#x}"

    matching_symbols = external_symbols._search_by_address(address)

    if len(matching_symbols) == 0:
        return f"{address:#x}"
    elif len(matching_symbols) > 1:
        liblog.warning(f"Multiple symbols found for address {address:#x}. Taking the first one.")

    return matching_symbols[0].name
