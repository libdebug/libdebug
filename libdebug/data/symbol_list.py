#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.debugger.internal_debugger_instance_manager import get_global_internal_debugger

if TYPE_CHECKING:
    from libdebug.data.symbol import Symbol
    from libdebug.snapshots.memory.memory_map_snapshot_list import MemoryMapSnapshotList


class SymbolList(list):
    """A list of symbols in the target process."""

    def __init__(self: SymbolList, symbols: list[Symbol]) -> None:
        """Initializes the SymbolDict."""
        super().__init__(symbols)

    def _search_by_address(self: SymbolList, address: int) -> list[Symbol]:
        """Searches for a symbol by address.

        Args:
            address (int): The address of the symbol to search for.

        Returns:
            list[Symbol]: The list of symbols that match the specified address.
        """
        # Find the memory map that contains the address
        if maps := get_global_internal_debugger().maps.filter(address):
            address -= maps[0].start
        else:
            raise ValueError(
                f"Address {address:#x} does not belong to any memory map. You must specify an absolute address."
            )
        return [symbol for symbol in self if symbol.start <= address < symbol.end]

    def _search_by_address_in_snapshot(
        self: SymbolList, address: int, external_maps: MemoryMapSnapshotList
    ) -> list[Symbol]:
        """Searches for a symbol by address.

        Args:
            address (int): The address of the symbol to search for.
            external_maps (MemoryMapSnapshotList): The memory maps of the snapshot.

        Returns:
            list[Symbol]: The list of symbols that match the specified address.
        """
        # Find the memory map that contains the address
        if maps := external_maps.filter(address):
            address -= maps[0].start
        else:
            raise ValueError(
                f"Address {address:#x} does not belong to any memory map. You must specify an absolute address."
            )
        return [symbol for symbol in self if symbol.start <= address < symbol.end]

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

        return SymbolList(filtered_symbols)

    def __getitem__(self: SymbolList, key: str) -> Symbol:
        """Returns the symbol with the specified name."""
        symbols = [symbol for symbol in self if symbol.name == key]
        if not symbols:
            raise KeyError(f"Symbol '{key}' not found.")
        return symbols

    def __hash__(self) -> int:
        """Return the hash of the symbol list."""
        return hash(id(self))

    def __eq__(self, other: object) -> bool:
        """Check if the symbol list is equal to another object."""
        return super().__eq__(other)

    def __repr__(self: SymbolList) -> str:
        """Returns the string representation of the SymbolDict without the default factory."""
        return f"SymbolList({super().__repr__()})"
