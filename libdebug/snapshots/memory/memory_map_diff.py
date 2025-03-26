#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.snapshots.memory.memory_map_snapshot import MemoryMapSnapshot


@dataclass
class MemoryMapDiff:
    """This object represents a diff between memory contents in a memory map."""

    old_map_state: MemoryMapSnapshot
    """The old state of the memory map."""

    new_map_state: MemoryMapSnapshot
    """The new state of the memory map."""

    has_changed: bool
    """Whether the memory map has changed."""

    _cached_diffs: list[slice] = None
    """Cached diff slices."""

    @property
    def content_diff(self: MemoryMapDiff) -> list[slice]:
        """Resolve the content diffs of a memory map between two snapshots.

        Returns:
            list[slice]: The list of slices representing the relative positions of diverging content.
        """
        # If the diff has already been computed, return it
        if self._cached_diffs is not None:
            return self._cached_diffs

        if self.old_map_state is None:
            raise ValueError("Cannot resolve content diff for a new memory map.")
        if self.new_map_state is None:
            raise ValueError("Cannot resolve content diff for a removed memory map.")

        if self.old_map_state.content is None or self.new_map_state.content is None:
            raise ValueError("Memory contents not available for this memory page.")

        old_content = self.old_map_state.content
        new_content = self.new_map_state.content

        work_len = min(len(old_content), len(new_content))

        found_slices = []

        # Find all the slices
        cursor = 0
        while cursor < work_len:
            # Find the first differing byte of the sequence
            if old_content[cursor] == new_content[cursor]:
                cursor += 1
                continue

            start = cursor
            # Find the last non-zero byte of the sequence
            while cursor < work_len and old_content[cursor] != new_content[cursor]:
                cursor += 1

            end = cursor

            found_slices.append(slice(start, end))

        # Cache the diff slices
        self._cached_diffs = found_slices

        return found_slices

