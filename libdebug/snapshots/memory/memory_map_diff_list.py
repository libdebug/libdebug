#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024  Gabriele Digregorio, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.liblog import liblog

if TYPE_CHECKING:
    from libdebug.snapshots.memory.memory_map_diff import MemoryMapDiff


class MemoryMapDiffList(list):
    """A list of memory map snapshot diffs from the target process."""

    def __init__(
        self: MemoryMapDiffList,
        memory_maps: list[MemoryMapDiff],
        process_name: str,
        full_process_path: str,
    ) -> None:
        """Initializes the MemoryMapSnapshotList."""
        super().__init__(memory_maps)
        self._process_full_path = full_process_path
        self._process_name = process_name

    def _search_by_address(self: MemoryMapDiffList, address: int) -> list[MemoryMapDiff]:
        """Searches for a memory map diff by address.

        Args:
            address (int): The address to search for.

        Returns:
            list[MemoryMapDiff]: The memory map diff matching the specified address.
        """
        for vmap_diff in self:
            if vmap_diff.old_map_state.start <= address < vmap_diff.new_map_state.end:
                return [vmap_diff]
        return []

    def _search_by_backing_file(self: MemoryMapDiffList, backing_file: str) -> list[MemoryMapDiff]:
        """Searches for a memory map diff by backing file.

        Args:
            backing_file (str): The backing file to search for.

        Returns:
            list[MemoryMapDiff]: The memory map diff matching the specified backing file.
        """
        if backing_file in ["binary", self._process_name]:
            backing_file = self._process_full_path

        filtered_maps = []
        unique_files = set()

        for vmap_diff in self:
            compare_with_old = vmap_diff.old_map_state is not None
            compare_with_new = vmap_diff.new_map_state is not None

            if compare_with_old and backing_file in vmap_diff.old_map_state.backing_file:
                filtered_maps.append(vmap_diff)
                unique_files.add(vmap_diff.old_map_state.backing_file)
            elif compare_with_new and backing_file in vmap_diff.new_map_state.backing_file:
                filtered_maps.append(vmap_diff)
                unique_files.add(vmap_diff.new_map_state.backing_file)

        if len(unique_files) > 1:
            liblog.warning(
                f"The substring {backing_file} is present in multiple, different backing files. The address resolution cannot be accurate. The matching backing files are: {', '.join(unique_files)}.",
            )

        return filtered_maps

    def filter(self: MemoryMapDiffList, value: int | str) -> MemoryMapDiffList[MemoryMapDiff]:
        """Filters the memory maps according to the specified value.

        If the value is an integer, it is treated as an address.
        If the value is a string, it is treated as a backing file.

        Args:
            value (int | str): The value to search for.

        Returns:
            MemoryMapDiffList[MemoryMapDiff]: The memory maps matching the specified value.
        """
        if isinstance(value, int):
            filtered_maps = self._search_by_address(value)
        elif isinstance(value, str):
            filtered_maps = self._search_by_backing_file(value)
        else:
            raise TypeError("The value must be an integer or a string.")

        return MemoryMapDiffList(filtered_maps, self._process_name, self._process_full_path)
