#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024  Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.liblog import liblog

if TYPE_CHECKING:
    from libdebug.data.memory_map import MemoryMap


class MemoryMapSnapshotList(list):
    """A list of memory map snapshot from the target process."""

    def __init__(
        self: MemoryMapSnapshotList, memory_maps: list[MemoryMap], process_name: str, full_process_path: str,
    ) -> None:
        """Initializes the MemoryMapSnapshotList."""
        super().__init__(memory_maps)
        self._process_full_path = full_process_path
        self._process_name = process_name

    def _search_by_address(self: MemoryMapSnapshotList, address: int) -> list[MemoryMap]:
        for vmap in self:
            if vmap.start <= address < vmap.end:
                return [vmap]
        return []

    def _search_by_backing_file(self: MemoryMapSnapshotList, backing_file: str) -> list[MemoryMap]:
        if backing_file in ["binary", self._process_name]:
            backing_file = self._process_full_path

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

    def filter(self: MemoryMapSnapshotList, value: int | str) -> MemoryMapSnapshotList[MemoryMap]:
        """Filters the memory maps according to the specified value.

        If the value is an integer, it is treated as an address.
        If the value is a string, it is treated as a backing file.

        Args:
            value (int | str): The value to search for.

        Returns:
            MemoryMapSnapshotList[MemoryMap]: The memory maps matching the specified value.
        """
        if isinstance(value, int):
            filtered_maps = self._search_by_address(value)
        elif isinstance(value, str):
            filtered_maps = self._search_by_backing_file(value)
        else:
            raise TypeError("The value must be an integer or a string.")

        return MemoryMapSnapshotList(filtered_maps, self._process_name, self._process_full_path)
