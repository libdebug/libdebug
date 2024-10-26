#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug import liblog
from libdebug.memory.abstract_memory_view import AbstractMemoryView
from libdebug.utils.debugging_utils import normalize_and_validate_address

if TYPE_CHECKING:
    from libdebug.data.symbol import Symbol
    from libdebug.data.symbol_list import SymbolList
    from libdebug.snapshots.process_snapshot import ProcessSnapshot
    from libdebug.snapshots.thread_snapshot import ThreadSnapshot


class SnapshotMemoryView(AbstractMemoryView):
    """Memory view for a thread / process snapshot."""

    def __init__(self: SnapshotMemoryView, snapshot: ThreadSnapshot | ProcessSnapshot, symbols: SymbolList) -> None:
        """Initializes the MemoryView."""
        self._snap_ref = snapshot
        self._symbol_ref = symbols

    def read(self: SnapshotMemoryView, address: int, size: int) -> bytes:
        """Reads memory from the target process.

        Args:
            address (int): The address to read from.
            size (int): The number of bytes to read.

        Returns:
            bytes: The read bytes.
        """
        target_map = self._snap_ref.maps.filter(address)

        if len(target_map) == 0:
            raise ValueError("No mapped memory at the specified address.")

        # The memory of the target map cannot be retrieved
        if target_map._content is None:
            error = "Corresponding memory map was not snapshotted"

            if self._snap_ref.level == "base":
                error += ", snapshot level is base, no memory contents were saved."
            elif self._snap_ref.level == "writable" and "w" not in target_map.permissions:
                error += ", snapshot level is writable but the target page corresponds to non-writable memory."
            else:
                error += " (it could be a priviledged memory map e.g. [vvar])."

            raise ValueError(error)

        return target_map._content[address : address + size]

    def write(self: SnapshotMemoryView, address: int, data: bytes) -> None:
        """Writes memory to the target process.

        Args:
            address (int): The address to write to.
            data (bytes): The data to write.
        """
        raise NotImplementedError("Snapshot memory is read-only, duh.")

    def find(
        self: SnapshotMemoryView,
        value: bytes | str | int,
        file: str = "all",
        start: int | None = None,
        end: int | None = None,
    ) -> list[int]:
        """Searches for the given value in the specified memory maps of the process.

        The start and end addresses can be used to limit the search to a specific range.
        If not specified, the search will be performed on the whole memory map.

        Args:
            value (bytes | str | int): The value to search for.
            file (str): The backing file to search the value in. Defaults to "all", which means all memory.
            start (int | None): The start address of the search. Defaults to None.
            end (int | None): The end address of the search. Defaults to None.

        Returns:
            list[int]: A list of offset where the value was found.
        """

        # TODO: Check if it can be done, if so call super

    def _manage_memory_read_type(
        self: SnapshotMemoryView,
        key: int | slice | str | tuple,
        file: str = "hybrid",
    ) -> bytes:
        """Manage the read from memory, according to the typing.

        Args:
            key (int | slice | str | tuple): The key to read from memory.
            file (str, optional): The user-defined backing file to resolve the address in. Defaults to "hybrid" (libdebug will first try to solve the address as an absolute address, then as a relative address w.r.t. the "binary" map file).
        """
        if isinstance(key, int):
            address = self.resolve_address(key, file, skip_absolute_address_validation=True)
            try:
                return self.read(address, 1)
            except OSError as e:
                raise ValueError("Invalid address.") from e
        elif isinstance(key, slice):
            if isinstance(key.start, str):
                start = self.resolve_symbol(key.start, file)
            else:
                start = self.resolve_address(key.start, file, skip_absolute_address_validation=True)

            if isinstance(key.stop, str):
                stop = self.resolve_symbol(key.stop, file)
            else:
                stop = self.resolve_address(key.stop, file, skip_absolute_address_validation=True)

            if stop < start:
                raise ValueError("Invalid slice range.")

            try:
                return self.read(start, stop - start)
            except OSError as e:
                raise ValueError("Invalid address.") from e
        elif isinstance(key, str):
            address = self.resolve_symbol(key, file)

            return self.read(address, 1)
        elif isinstance(key, tuple):
            return self._manage_memory_read_tuple(key)
        else:
            raise TypeError("Invalid key type.")

    def _manage_memory_read_tuple(self: SnapshotMemoryView, key: tuple) -> bytes:
        """Manage the read from memory, when the access is through a tuple.

        Args:
            key (tuple): The key to read from memory.
        """
        if len(key) == 3:
            # It can only be a tuple of the type (address, size, file)
            address, size, file = key
            if not isinstance(file, str):
                raise TypeError("Invalid type for the backing file. Expected string.")
        elif len(key) == 2:
            left, right = key
            if isinstance(right, str):
                # The right element can only be the backing file
                return self._manage_memory_read_type(left, right)
            elif isinstance(right, int):
                # The right element must be the size
                address = left
                size = right
                file = "hybrid"
        else:
            raise TypeError("Tuple must have 2 or 3 elements.")

        if not isinstance(size, int):
            raise TypeError("Invalid type for the size. Expected int.")

        if isinstance(address, str):
            address = self.resolve_symbol(address, file)
        elif isinstance(address, int):
            address = self.resolve_address(address, file, skip_absolute_address_validation=True)
        else:
            raise TypeError("Invalid type for the address. Expected int or string.")

        try:
            return self.read(address, size)
        except OSError as e:
            raise ValueError("Invalid address.") from e

    def _manage_memory_write_type(
        self: SnapshotMemoryView,
        key: int | slice | str | tuple,
        value: bytes,
        file: str = "hybrid",
    ) -> None:
        """Manage the write to memory, according to the typing.

        Args:
            key (int | slice | str | tuple): The key to read from memory.
            value (bytes): The value to write.
            file (str, optional): The user-defined backing file to resolve the address in. Defaults to "hybrid" (libdebug will first try to solve the address as an absolute address, then as a relative address w.r.t. the "binary" map file).
        """
        if isinstance(key, int):
            address = self.resolve_address(key, file, skip_absolute_address_validation=True)
            try:
                self.write(address, value)
            except OSError as e:
                raise ValueError("Invalid address.") from e
        elif isinstance(key, slice):
            if isinstance(key.start, str):
                start = self.resolve_symbol(key.start, file)
            else:
                start = self.resolve_address(key.start, file, skip_absolute_address_validation=True)

            if key.stop is not None:
                if isinstance(key.stop, str):
                    stop = self.resolve_symbol(key.stop, file)
                else:
                    stop = self.resolve_address(
                        key.stop,
                        file,
                        skip_absolute_address_validation=True,
                    )

                if stop < start:
                    raise ValueError("Invalid slice range")

                if len(value) != stop - start:
                    liblog.warning(f"Mismatch between slice width and value size, writing {len(value)} bytes.")

            try:
                self.write(start, value)
            except OSError as e:
                raise ValueError("Invalid address.") from e

        elif isinstance(key, str):
            address = self.resolve_symbol(key, file)

            self.write(address, value)
        elif isinstance(key, tuple):
            self._manage_memory_write_tuple(key, value)
        else:
            raise TypeError("Invalid key type.")

    def _manage_memory_write_tuple(self: SnapshotMemoryView, key: tuple, value: bytes) -> None:
        """Manage the write to memory, when the access is through a tuple.

        Args:
            key (tuple): The key to read from memory.
            value (bytes): The value to write.
        """
        if len(key) == 3:
            # It can only be a tuple of the type (address, size, file)
            address, size, file = key
            if not isinstance(file, str):
                raise TypeError("Invalid type for the backing file. Expected string.")
        elif len(key) == 2:
            left, right = key
            if isinstance(right, str):
                # The right element can only be the backing file
                self._manage_memory_write_type(left, value, right)
                return
            elif isinstance(right, int):
                # The right element must be the size
                address = left
                size = right
                file = "hybrid"
        else:
            raise TypeError("Tuple must have 2 or 3 elements.")

        if not isinstance(size, int):
            raise TypeError("Invalid type for the size. Expected int.")

        if isinstance(address, str):
            address = self.resolve_symbol(address, file)
        elif isinstance(address, int):
            address = self.resolve_address(address, file, skip_absolute_address_validation=True)
        else:
            raise TypeError("Invalid type for the address. Expected int or string.")

        if len(value) != size:
            liblog.warning(f"Mismatch between specified size and actual value size, writing {len(value)} bytes.")

        try:
            self.write(address, value)
        except OSError as e:
            raise ValueError("Invalid address.") from e

    def resolve_symbol(self: SnapshotMemoryView, symbol: str, file: str) -> Symbol:
        """Resolve a symbol from the symbol list.

        Args:
            symbol (str): The symbol to resolve.
            file (str): The backing file to resolve the address in.

        Returns:
            Symbol: The resolved address.
        """
        results = self._symbol_ref.search_by_name(symbol)

        if len(results) == 0:
            raise ValueError(f"Symbol {symbol} not found in snaphot memory.")

        if len(results) > 1:
            liblog.warning(f"Multiple symbols with name {symbol} found in snapshot memory. Accessing the first one.")

        if results[0].backing_file != file:
            liblog.warning(
                f"Symbol {symbol} found in different backing file {results[0].backing_file}.",
            )

        return results[0]

    def resolve_address(
        self: SnapshotMemoryView,
        address: int,
        backing_file: str,
        skip_absolute_address_validation: bool = False,
    ) -> int:
        """Normalizes and validates the specified address.

        Args:
            address (int): The address to normalize and validate.
            backing_file (str): The backing file to resolve the address in.
            skip_absolute_address_validation (bool, optional): Whether to skip bounds checking for absolute addresses. Defaults to False.

        Returns:
            int: The normalized and validated address.

        Raises:
            ValueError: If the substring `backing_file` is present in multiple backing files.
        """
        if skip_absolute_address_validation and backing_file == "absolute":
            return address

        maps = self._snap_ref.maps

        if backing_file in ["hybrid", "absolute"]:
            if maps.filter(address):
                # If the address is absolute, we can return it directly
                return address
            elif backing_file == "absolute":
                # The address is explicitly an absolute address but we did not find it
                raise ValueError(
                    "The specified absolute address does not exist. Check the address or specify a backing file.",
                )
            else:
                # If the address was not found and the backing file is not "absolute",
                # we have to assume it is in the main map
                backing_file = self._snap_ref._process_full_path
                liblog.warning(
                    f"No backing file specified and no corresponding absolute address found for {hex(address)}. Assuming {backing_file}.",
                )

        filtered_maps = maps.filter(backing_file)

        return normalize_and_validate_address(address, filtered_maps)
