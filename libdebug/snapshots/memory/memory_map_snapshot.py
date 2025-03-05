#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass

from libdebug.data.memory_map import MemoryMap


@dataclass
class MemoryMapSnapshot(MemoryMap):
    """A snapshot of the memory map of the target process.

    Attributes:
        start (int): The start address of the memory map. You can access it also with the 'base' attribute.
        end (int): The end address of the memory map.
        permissions (str): The permissions of the memory map.
        size (int): The size of the memory map.
        offset (int): The relative offset of the memory map.
        backing_file (str): The backing file of the memory map, or the symbolic name of the memory map.
        content (bytes): The content of the memory map, used for snapshotted pages.
    """

    content: bytes = None
    """The content of the memory map, used for snapshotted pages."""

    def is_same_identity(self: MemoryMap, other: MemoryMap) -> bool:
        """Check if the memory map corresponds to another memory map."""
        return self.start == other.start and self.backing_file == other.backing_file

    def __repr__(self: MemoryMapSnapshot) -> str:
        """Return the string representation of the memory map."""
        str_repr = super().__repr__()

        if self.content is not None:
            str_repr = str_repr[:-1] + ", content=...)"

        return str_repr

    def __eq__(self, value: object) -> bool:
        """Check if this MemoryMap is equal to another object.

        Args:
            value (object): The object to compare to.

        Returns:
            bool: True if the objects are equal, False otherwise.
        """
        if not isinstance(value, MemoryMap):
            return False

        is_snapshot_map = isinstance(value, MemoryMapSnapshot)

        # Check if the content is available and if it is the same
        should_compare_content = is_snapshot_map and self.content is not None and value.content is not None
        same_content = not should_compare_content or self.content == value.content

        return (
            self.start == value.start
            and self.end == value.end
            and self.permissions == value.permissions
            and self.size == value.size
            and self.offset == value.offset
            and self.backing_file == value.backing_file
            and same_content
        )
