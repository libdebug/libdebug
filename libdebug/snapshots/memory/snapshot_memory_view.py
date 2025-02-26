#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.liblog import liblog
from libdebug.memory.abstract_memory_view import AbstractMemoryView
from libdebug.utils.debugging_utils import normalize_and_validate_address

if TYPE_CHECKING:
    from libdebug.data.symbol import Symbol
    from libdebug.data.symbol_list import SymbolList
    from libdebug.snapshots.memory.memory_map_snapshot_list import MemoryMapSnapshotList
    from libdebug.snapshots.process.process_snapshot import ProcessSnapshot
    from libdebug.snapshots.thread.thread_snapshot import ThreadSnapshot


class SnapshotMemoryView(AbstractMemoryView):
    """Memory view for a thread / process snapshot."""

    def __init__(self: SnapshotMemoryView, snapshot: ThreadSnapshot | ProcessSnapshot, symbols: SymbolList) -> None:
        """Initializes the MemoryView."""
        self._snap_ref = snapshot
        self._symbol_ref = symbols

    def read(self: SnapshotMemoryView, address: int, size: int) -> bytes:
        """Reads memory from the target snapshot.

        Args:
            address (int): The address to read from.
            size (int): The number of bytes to read.

        Returns:
            bytes: The read bytes.
        """
        start_map = self._snap_ref.maps.filter(address)[0]
        end_map = self._snap_ref.maps.filter(address + size - 1)[0]

        index_start = self._snap_ref.maps.index(start_map)
        index_end = self._snap_ref.maps.index(end_map)

        target_maps = self._snap_ref.maps[index_start:index_end + 1]

        if not target_maps:
            raise ValueError("No mapped memory at the specified address.")

        for target_map in target_maps:
            # The memory of the target map cannot be retrieved
            if target_map.content is None:
                error = "One or more of the memory maps involved was not snapshotted"

                if self._snap_ref.level == "base":
                    error += ", snapshot level is base, no memory contents were saved."
                elif self._snap_ref.level == "writable" and "w" not in target_map.permissions:
                    error += ", snapshot level is writable but the target page corresponds to non-writable memory."
                else:
                    error += " (it could be a priviledged memory map e.g. [vvar])."

                raise ValueError(error)

        start_offset = address - target_maps[0].start

        if len(target_maps) == 1:
            end_offset = start_offset + size
            return target_maps[0].content[start_offset:end_offset]
        else:
            data = target_maps[0].content[start_offset:]

            for target_map in target_maps[1:-1]:
                data += target_map.content

            end_offset = size - len(data)
            data += target_maps[-1].content[:end_offset]

            return data

    def write(self: SnapshotMemoryView, address: int, data: bytes) -> None:
        """Writes memory to the target snapshot.

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
        """Searches for the given value in the saved memory maps of the snapshot.

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
        if self._snap_ref.level == "base":
            raise ValueError("Memory snapshot is not available at base level.")

        return super().find(value, file, start, end)

    def resolve_symbol(self: SnapshotMemoryView, symbol: str, file: str) -> Symbol:
        """Resolve a symbol from the symbol list.

        Args:
            symbol (str): The symbol to resolve.
            file (str): The backing file to resolve the address in.

        Returns:
            Symbol: The resolved address.
        """
        offset = 0

        if "+" in symbol:
            symbol, offset = symbol.split("+")
            offset = int(offset, 16)

        results = self._symbol_ref.filter(symbol)

        # Get the first result that matches the backing file
        results = [result for result in results if file in result.backing_file]

        if len(results) == 0:
            raise ValueError(f"Symbol {symbol} not found in snaphot memory.")

        page_base = self._snap_ref.maps.filter(results[0].backing_file)[0].start

        return page_base + results[0].start + offset

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

    @property
    def maps(self: SnapshotMemoryView) -> MemoryMapSnapshotList:
        """Returns a list of memory maps in the target process.

        Returns:
            MemoryMapList: The memory maps.
        """
        return self._snap_ref.maps
