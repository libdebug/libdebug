#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass


@dataclass
class Symbol:
    """A symbol in the target process.

    start (int): The start address of the symbol in the target process.
    end (int): The end address of the symbol in the target process.
    name (str): The name of the symbol in the target process.
    """

    start: int
    end: int
    name: str


class SymbolDict(defaultdict):
    """A dictionary of symbols in the target process."""

    def __init__(self: SymbolDict) -> None:
        """Initializes the MemoryMapList."""
        super().__init__(list)

    def _search_by_address(self: SymbolDict, address: int) -> SymbolDict[str, list[Symbol]]:
        """Searches for a symbol by address.

        Args:
            address (int): The address of the symbol to search for.

        Returns:
            SymbolDict[str, Symbol]: The dictionary of symbols that match the specified address.
        """
        symbols = SymbolDict()
        for symbol_list in self.values():
            for symbol in symbol_list:
                if symbol.start <= address < symbol.end:
                    symbols[symbol.name].append(symbol)
        return symbols

    def _search_by_name(self: SymbolDict, name: str) -> SymbolDict[str, list[Symbol]]:
        """Searches for a symbol by name.

        Args:
            name (str): The name of the symbol to search for.

        Returns:
            SymbolDict[Symbol]: The dictionary of symbols that match the specified name.
        """
        symbols = SymbolDict()
        symbols[name] = self[name]
        return symbols

    def find(self: SymbolDict, value: int | str) -> SymbolDict[str, list[Symbol]]:
        """Finds a symbol by address or name.

        Args:
            value (int | str): The address or name of the symbol to find.

        Returns:
            SymbolDict[str, list[Symbol]]: The dictionary of symbols that match the specified value.
        """
        if isinstance(value, int):
            return self._search_by_address(value)
        elif isinstance(value, str):
            return self._search_by_name(value)
        else:
            raise TypeError("The value must be an integer or a string.")
