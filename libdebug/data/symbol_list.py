#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024-2025 Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.data.symbol import Symbol
    from libdebug.debugger.internal_debugger import InternalDebugger
    from libdebug.snapshots.snapshot import Snapshot


class SymbolList(list):
    """A list of symbols in the target process."""

    def __init__(self: SymbolList, symbols: list[Symbol], maps_source: InternalDebugger | Snapshot) -> None:
        """Initializes the SymbolDict."""
        super().__init__(symbols)

        self._maps_source = maps_source

    def _search_by_address(self: SymbolList, address: int) -> list[Symbol]:
        """Searches for a symbol by address.

        Args:
            address (int): The address of the symbol to search for.

        Returns:
            list[Symbol]: The list of symbols that match the specified address.
        """
        # Find the backing file that contains the address
        map_middle = self._maps_source.maps.filter(address)

        if map_middle:
            backing_file_first_map = self._maps_source.maps.filter(map_middle[0].backing_file)[0]
            address -= backing_file_first_map.start
        else:
            raise ValueError(
                f"Address {address:#x} does not belong to any memory map. You must specify an absolute address.",
            )
        return [
            symbol for symbol in self
            if symbol.start <= address < symbol.end
            and symbol.reference_file == map_middle[0].backing_file
        ]

    def _search_by_name(self: SymbolList, name: str) -> list[Symbol]:
        """Searches for a symbol by name.

        Args:
            name (str): The name of the symbol to search for.

        Returns:
            list[Symbol]: The list of symbols that match the specified name.
        """
        exact_match = []
        no_exact_match = []
        # We first want to list the symbols that exactly match the name
        for symbol in self:
            if symbol.name == name:
                exact_match.append(symbol)
            elif name in symbol.name:
                no_exact_match.append(symbol)
        return exact_match + no_exact_match

    def filter(self: SymbolList, value: int | str) -> SymbolList[Symbol]:
        """Filters the symbols according to the specified value.

        If the value is an integer, it is treated as an address.
        If the value is a string, it is treated as a symbol name.

        Args:
            value (int | str): The address or name of the symbol to find.

        Returns:
            SymbolList[Symbol]: The symbols matching the specified value.
        """
        if isinstance(value, int):
            filtered_symbols = self._search_by_address(value)
        elif isinstance(value, str):
            filtered_symbols = self._search_by_name(value)
        else:
            raise TypeError("The value must be an integer or a string.")

        return SymbolList(filtered_symbols, self._maps_source)

    def __getitem__(self: SymbolList, key: str | int) -> SymbolList[Symbol] | Symbol:
        """Returns the symbol with the specified name.

        Args:
            key (str, int): The name of the symbol to return, or the index of the symbol in the list.

        Returns:
            Symbol | SymbolList[Symbol]: The symbol at the specified index, or the SymbolList of symbols with the specified name.
        """
        if not isinstance(key, str):
            return super().__getitem__(key)

        symbols = [symbol for symbol in self if symbol.name == key]
        if not symbols:
            raise KeyError(f"Symbol '{key}' not found.")
        return SymbolList(symbols, self._maps_source)

    def __hash__(self) -> int:
        """Return the hash of the symbol list."""
        return hash(id(self))

    def __eq__(self, other: object) -> bool:
        """Check if the symbol list is equal to another object."""
        return super().__eq__(other)

    def __repr__(self: SymbolList) -> str:
        """Returns the string representation of the SymbolDict without the default factory."""
        return f"SymbolList({super().__repr__()})"
