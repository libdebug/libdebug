#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.snapshots.memory.memory_map_diff import MemoryMapDiff
from libdebug.snapshots.registers.register_diff import RegisterDiff
from libdebug.snapshots.registers.register_diff_accessor import RegisterDiffAccessor

if TYPE_CHECKING:
    from libdebug.snapshots.registers.snapshot_registers import SnapshotRegisters
    from libdebug.snapshots.snapshot import Snapshot


class Diff:
    """This object represents a diff between two snapshots."""

    def __init__(self: Diff, snapshot1: Snapshot, snapshot2: Snapshot) -> None:
        """Initialize the Diff object with two snapshots.

        Args:
            snapshot1 (Snapshot): The first snapshot.
            snapshot2 (Snapshot): The second snapshot.
        """
        if snapshot1.snapshot_id < snapshot2.snapshot_id:
            self.snapshot1 = snapshot1
            self.snapshot2 = snapshot2
        else:
            self.snapshot1 = snapshot2
            self.snapshot2 = snapshot1

        # The level of the diff is the lowest level among the two snapshots
        if snapshot1.level == "base" or snapshot2.level == "base":
            self.level = "base"
        elif snapshot1.level == "writable" or snapshot2.level == "writable":
            self.level = "writable"
        else:
            self.level = "full"

    def _save_reg_diffs(self: Snapshot) -> None:
        self.regs = RegisterDiffAccessor()

        all_regs = dir(self.snapshot1.regs)
        all_regs = [reg for reg in all_regs if isinstance(self.snapshot1.regs.__getattribute__(reg), int | float)]

        for reg_name in all_regs:
            old_value = self.snapshot1.regs.__getattribute__(reg_name)
            new_value = self.snapshot2.regs.__getattribute__(reg_name)
            has_changed = old_value != new_value

            diff = RegisterDiff(
                old_value=old_value,
                new_value=new_value,
                has_changed=has_changed,
            )

            # Create diff object
            self.regs.__setattr__(reg_name, diff)


    def _resolve_maps_diff(self: Diff) -> None:
        # Handle memory maps
        self.maps = []
        handled_map2_indices = []

        for map1 in self.snapshot1.maps:

            # Find the corresponding map in the second snapshot
            map2 = None

            for map2_index, candidate in enumerate(self.snapshot2.maps):
                if map1.is_same_identity(candidate):
                    map2 = candidate
                    handled_map2_indices.append(map2_index)
                    break

            if map2 is None:
                diff = MemoryMapDiff(
                    old_map_state=map1,
                    new_map_state=None,
                    has_changed=True,
                )
            else:
                diff = MemoryMapDiff(
                    old_map_state=map1,
                    new_map_state=map2,
                    has_changed=(map1 != map2),
                )

            self.maps.append(diff)

        new_pages = [self.snapshot2.maps[i] for i in range(len(self.snapshot2.maps)) if i not in handled_map2_indices]

        for new_page in new_pages:
            diff = MemoryMapDiff(
                old_map_state=None,
                new_map_state=new_page,
                has_changed=True,
            )

            self.maps.append(diff)

    @property
    def registers(self: Snapshot) -> SnapshotRegisters:
        """Alias for regs."""
        return self.regs
