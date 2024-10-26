#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#
from __future__ import annotations

from libdebug.snapshots.memory.memory_map_diff import MemoryMapDiff
from libdebug.snapshots.register_diff import RegisterDiff
from libdebug.snapshots.register_diff_accessor import RegisterDiffAccessor
from libdebug.snapshots.thread_snapshot import ThreadSnapshot


class ThreadSnapshotDiff:
    """This object represents a diff between thread snapshots."""

    def __init__(self: ThreadSnapshotDiff, snapshot1: ThreadSnapshot, snapshot2: ThreadSnapshot) -> ThreadSnapshotDiff:
        """Returns a diff between given snapshots of the same thread.

        Args:
            snapshot1 (ThreadSnapshot): A thread snapshot.
            snapshot2 (ThreadSnapshot): A thread snapshot.
        """
        if not isinstance(snapshot1, ThreadSnapshot) or not isinstance(snapshot2, ThreadSnapshot):
            raise ValueError("Both arguments must be ThreadSnapshot objects.")

        if snapshot1.snapshot_id < snapshot2.snapshot_id:
            self.snapshot1 = snapshot1
            self.snapshot2 = snapshot2
        else:
            self.snapshot1 = snapshot2
            self.snapshot2 = snapshot1

        # The level of the diff is the lowest level among the two snapshots
        self.level = "full" if self.snapshot1.level == "full" and self.snapshot2.level == "full" else "base"

        # Register diffs
        self.regs = RegisterDiffAccessor()

        all_regs = dir(snapshot1.regs)
        all_regs = [reg for reg in all_regs if isinstance(snapshot1.regs.__getattribute__(reg), int | float)]

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
