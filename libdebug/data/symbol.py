#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from libdebug.debugger.internal_debugger_instance_manager import get_global_internal_debugger


@dataclass
class Symbol:
    """A symbol in the target process.

    start (int): The start address of the symbol in the target process.
    end (int): The end address of the symbol in the target process.
    name (str): The name of the symbol in the target process.
    backing_file (str): The backing file of the symbol in the target process.
    """

    start: int
    end: int
    name: str
    backing_file: str

    def __hash__(self: Symbol) -> int:
        """Returns the hash of the symbol."""
        return hash((self.start, self.end, self.name, self.backing_file))

    def __repr__(self: Symbol) -> str:
        """Returns the string representation of the symbol."""
        return f"Symbol(start={self.start:#x}, end={self.end:#x}, name={self.name}, backing_file={self.backing_file})"


class SymbolDict(defaultdict):
    """A dictionary of symbols in the target process."""

    def __init__(self: SymbolDict) -> None:
        """Initializes the MemoryMapList."""
        super().__init__(set)

    def _search_by_address(self: SymbolDict, address: int) -> SymbolDict[str, set[Symbol]]:
        """Searches for a symbol by address.

        Args:
            address (int): The address of the symbol to search for.

        Returns:
            SymbolDict[str, Symbol]: The dictionary of symbols that match the specified address.
        """
        symbols = SymbolDict()
        # Find the memory map that contains the address
        if maps := get_global_internal_debugger(self).maps.filter(address):
            address -= maps[0].start
        else:
            raise ValueError(
                f"Address {address:#x} does not belong to any memory map. You must specify an absolute address."
            )

        for symbol_list in self.values():
            for symbol in symbol_list:
                if symbol.start <= address < symbol.end:
                    symbols[symbol.name].add(symbol)
        return symbols

    def _search_by_name(self: SymbolDict, name: str) -> SymbolDict[str, set[Symbol]]:
        """Searches for a symbol by name.

        Args:
            name (str): The name of the symbol to search for.

        Returns:
            SymbolDict[Symbol]: The dictionary of symbols that match the specified name.
        """
        symbols = SymbolDict()

        if symbols_set := self.get(name):
            symbols[name] = symbols_set
        else:
            # If the symbol is not found, try to find it by substring
            for symbol_name in self.keys():
                if name in symbol_name:
                    symbols[symbol_name] = self[symbol_name]

        return symbols

    def filter(self: SymbolDict, value: int | str) -> SymbolDict[str, set[Symbol]]:
        """Filters the symbols according to the specified value.

        If the value is an integer, it is treated as an address.
        If the value is a string, it is treated as a symbol name.

        Args:
            value (int | str): The address or name of the symbol to find.

        Returns:
            SymbolDict[str, set[Symbol]]: The dictionary of symbols that match the specified value.
        """
        if isinstance(value, int):
            return self._search_by_address(value)
        elif isinstance(value, str):
            return self._search_by_name(value)
        else:
            raise TypeError("The value must be an integer or a string.")

    def __add__(self: SymbolDict, other: SymbolDict) -> SymbolDict:
        """Merges two SymbolDict instances, combining Symbol sets."""
        if not isinstance(other, SymbolDict):
            raise TypeError("Cannot merge a SymbolDict with a non-SymbolDict instance.")
        result = SymbolDict()
        for key in set(self.keys()).union(other.keys()):
            result[key] = self.get(key, set()).union(other.get(key, set()))
        return result

    def __repr__(self: SymbolDict) -> str:
        """Returns the string representation of the SymbolDict without the default factory."""
        return f"SymbolDict({dict(self)})"
