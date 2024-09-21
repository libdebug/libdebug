#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass

from libdebug.debugger.internal_debugger_instance_manager import extend_internal_debugger, provide_internal_debugger
from libdebug.liblog import liblog


@dataclass(frozen=True)
class MemoryMap:
    """A memory map of the target process.

    Attributes:
        start (int): The start address of the memory map.
        end (int): The end address of the memory map.
        permissions (str): The permissions of the memory map.
        size (int): The size of the memory map.
        offset (int): The relative offset of the memory map.
        backing_file (str): The backing file of the memory map, or the symbolic name of the memory map.
    """

    start: int = 0
    end: int = 0
    permissions: str = ""
    size: int = 0

    offset: int = 0
    """The relative offset of the memory map inside the backing file, if any."""

    backing_file: str = ""
    """The backing file of the memory map, such as 'libc.so.6', or the symbolic name of the memory map, such as '[stack]'."""

    @staticmethod
    def parse(vmap: str) -> MemoryMap:
        """Parses a memory map from a /proc/pid/maps string representation.

        Args:
            vmap (str): The string containing the memory map.

        Returns:
            MemoryMap: The parsed memory map.
        """
        try:
            address, permissions, offset, *_, backing_file = vmap.split(" ", 6)
            start = int(address.split("-")[0], 16)
            end = int(address.split("-")[1], 16)
            size = end - start
            int_offset = int(offset, 16)
            backing_file = backing_file.strip()
            if not backing_file:
                backing_file = f"anon_{start:x}"
        except ValueError as e:
            raise ValueError(
                f"Invalid memory map: {vmap}. Please specify a valid memory map.",
            ) from e

        return MemoryMap(start, end, permissions, size, int_offset, backing_file)

    def __repr__(self: MemoryMap) -> str:
        """Return the string representation of the memory map."""
        return f"MemoryMap(start={hex(self.start)}, end={hex(self.end)}, permissions={self.permissions}, size={hex(self.size)}, offset={hex(self.offset)}, backing_file={self.backing_file})"


class MemoryMapList(list):
    """A list of memory maps of the target process."""

    def __init__(self: MemoryMapList, memory_maps: list[MemoryMap]) -> None:
        """Initializes the MemoryMapList."""
        super().__init__(memory_maps)
        self._internal_debugger = provide_internal_debugger(self)

    def _search_by_address(self: MemoryMapList, address: int) -> MemoryMap:
        for vmap in self:
            if vmap.start <= address < vmap.end:
                return [vmap]
        return []

    def _search_by_backing_file(self: MemoryMapList, backing_file: str) -> list[MemoryMap]:
        if backing_file in ["binary", self._internal_debugger._process_name]:
            backing_file = self._internal_debugger._process_full_path

        filtered_maps = []
        unique_files = set()

        for vmap in self:
            if backing_file in vmap.backing_file:
                filtered_maps.append(vmap)
                unique_files.add(vmap.backing_file)

        if len(unique_files) > 1:
            liblog.warning(
                f"The substring {backing_file} is present in multiple, different backing files. The address resolution cannot be accurate. The matching backing files are: {', '.join(unique_files)}.",
            )

        return filtered_maps

    def find(self: MemoryMapList, value: int | str) -> MemoryMapList[MemoryMap]:
        """Finds the memory map containing the specified value.

        If the value is an integer, it is treated as an address.
        If the value is a string, it is treated as a backing file.

        Args:
            value (int | str): The value to search for.

        Returns:
            MemoryMapList[MemoryMap]: The memory maps containing the specified value
        """
        if isinstance(value, int):
            filtered_maps = self._search_by_address(value)
        elif isinstance(value, str):
            filtered_maps = self._search_by_backing_file(value)
        else:
            raise TypeError("The value must be an integer or a string.")

        with extend_internal_debugger(self._internal_debugger):
            return MemoryMapList(filtered_maps)

    def __hash__(self) -> int:
        """Return the hash of the memory map list."""
        return hash(id(self))

    def __eq__(self, other: object) -> bool:
        """Check if the memory map list is equal to another object."""
        return super().__eq__(other)
