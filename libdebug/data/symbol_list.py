#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024-2026 Gabriele Digregorio, Francesco Panebianco, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING, overload

from libdebug.native.libdebug_debug_sym_parser import Symbol

if TYPE_CHECKING:
    from libdebug.debugger.internal_debugger import InternalDebugger
    from libdebug.native.libdebug_debug_sym_parser import SymbolBinding, SymbolType
    from libdebug.snapshots.snapshot import Snapshot


class SymbolList(list[Symbol]):
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
        demangled_match = []
        partial_match = []

        # We prioritize: exact match > demangled match > partial match
        for symbol in self:
            if symbol.name == name:
                exact_match.append(symbol)
            elif symbol.demangled_name and symbol.demangled_name == name:
                demangled_match.append(symbol)
            elif name in symbol.name or (symbol.demangled_name and name in symbol.demangled_name):
                partial_match.append(symbol)

        return exact_match + demangled_match + partial_match

    def filter(self: SymbolList, value: int | str) -> SymbolList:
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

    def filter_by_type(self: SymbolList, symbol_type: SymbolType) -> SymbolList:
        """Filter symbols by type.

        Args:
            symbol_type: The symbol type to filter by (FUNC, OBJECT, TLS, etc.).

        Returns:
            SymbolList containing only symbols of the specified type.
        """
        filtered = [s for s in self if s.symbol_type == symbol_type]
        return SymbolList(filtered, self._maps_source)

    def filter_by_binding(self: SymbolList, binding: SymbolBinding) -> SymbolList:
        """Filter symbols by binding.

        Args:
            binding: The binding to filter by (LOCAL, GLOBAL, WEAK).

        Returns:
            SymbolList containing only symbols with the specified binding.
        """
        filtered = [s for s in self if s.binding == binding]
        return SymbolList(filtered, self._maps_source)

    @property
    def functions(self: SymbolList) -> SymbolList:
        """Get all function symbols."""
        filtered = [s for s in self if s.is_function]
        return SymbolList(filtered, self._maps_source)

    @property
    def objects(self: SymbolList) -> SymbolList:
        """Get all object/data symbols."""
        filtered = [s for s in self if s.is_object]
        return SymbolList(filtered, self._maps_source)

    @property
    def tls_symbols(self: SymbolList) -> SymbolList:
        """Get all TLS (thread-local storage) symbols."""
        filtered = [s for s in self if s.is_tls]
        return SymbolList(filtered, self._maps_source)

    @property
    def globals(self: SymbolList) -> SymbolList:
        """Get all global symbols."""
        filtered = [s for s in self if s.is_global]
        return SymbolList(filtered, self._maps_source)

    @property
    def locals(self: SymbolList) -> SymbolList:
        """Get all local symbols."""
        filtered = [s for s in self if s.is_local]
        return SymbolList(filtered, self._maps_source)

    @property
    def weak(self: SymbolList) -> SymbolList:
        """Get all weak symbols."""
        filtered = [s for s in self if s.is_weak]
        return SymbolList(filtered, self._maps_source)

    @property
    def plt(self: SymbolList) -> SymbolList:
        """Get all PLT (procedure linkage table) symbols."""
        filtered = [s for s in self if s.is_plt]
        return SymbolList(filtered, self._maps_source)

    @property
    def got(self: SymbolList) -> SymbolList:
        """Get all GOT (global offset table) symbols."""
        filtered = [s for s in self if s.is_got]
        return SymbolList(filtered, self._maps_source)

    @property
    def defined(self: SymbolList) -> SymbolList:
        """Get all defined (not undefined) symbols."""
        filtered = [s for s in self if s.is_defined]
        return SymbolList(filtered, self._maps_source)

    def in_file(self: SymbolList, backing_file: str) -> SymbolList:
        """Get symbols from a specific backing file.

        Args:
            backing_file: The backing file path or a substring to match.

        Returns:
            SymbolList containing symbols from the specified file.
        """
        filtered = [s for s in self if backing_file in s.backing_file]
        return SymbolList(filtered, self._maps_source)

    def with_version(self: SymbolList, version: str) -> SymbolList:
        """Get symbols with a specific version.

        Args:
            version: The version string to match (e.g., "GLIBC_2.2.5").

        Returns:
            SymbolList containing symbols with the specified version.
        """
        filtered = [s for s in self if s.version and version in s.version]
        return SymbolList(filtered, self._maps_source)

    @overload
    def __getitem__(self: SymbolList, key: int) -> Symbol:
        ...

    @overload
    def __getitem__(self: SymbolList, key: str) -> SymbolList:
        ...

    def __getitem__(self: SymbolList, key: str | int) -> SymbolList | Symbol:
        """Returns the symbol with the specified name.

        Args:
            key (str, int): The name of the symbol to return, or the index of the symbol in the list.

        Returns:
            Symbol | SymbolList[Symbol]: The symbol at the specified index, or a list with the named symbol(s).
        """
        if not isinstance(key, str):
            return super().__getitem__(key)

        symbols = [symbol for symbol in self
                    if symbol.name == key or (symbol.demangled_name and symbol.demangled_name == key)]
        if not symbols:
            raise KeyError(f"Symbol '{key}' not found.")
        return SymbolList(symbols, self._maps_source)

    def __repr__(self: SymbolList) -> str:
        """Returns the string representation of the SymbolDict without the default factory."""
        return f"SymbolList({super().__repr__()})"
