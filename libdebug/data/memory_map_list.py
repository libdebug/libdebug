#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024-2025 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from libdebug.data.memory_map import MemoryMap
from libdebug.debugger.internal_debugger_instance_manager import extend_internal_debugger, provide_internal_debugger
from libdebug.liblog import liblog


class MemoryMapList(list[MemoryMap]):
    """A list of memory maps of the target process."""

    def __init__(self: MemoryMapList, memory_maps: list[MemoryMap]) -> None:
        """Initializes the MemoryMapList."""
        super().__init__(memory_maps)
        self._internal_debugger = provide_internal_debugger(self)

    def _search_by_address(self: MemoryMapList, address: int) -> list[MemoryMap]:
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

    def filter(self: MemoryMapList, value: int | str) -> MemoryMapList:
        """Filters the memory maps according to the specified value.

        If the value is an integer, it is treated as an address.
        If the value is a string, it is treated as a backing file.

        Args:
            value (int | str): The value to search for.

        Returns:
            MemoryMapList: The memory maps matching the specified value.
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

    def __repr__(self) -> str:
        """Return the string representation of the memory map list."""
        return f"MemoryMapList({super().__repr__()})"
