#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass

from libdebug.data.memory_map import MemoryMap


@dataclass
class MemoryMapDiff:
    """This object represents a diff between memory contents in a memory map."""

    old_map_state: MemoryMap
    """The old state of the memory map."""

    new_map_state: MemoryMap
    """The new state of the memory map."""

    has_changed: bool
    """Whether the memory map has changed."""
