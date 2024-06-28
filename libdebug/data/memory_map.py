#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass


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
