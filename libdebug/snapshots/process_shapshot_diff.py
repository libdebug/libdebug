#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#
from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.snapshots.thread_snapshot_diff import ThreadSnapshotDiff

if TYPE_CHECKING:
    from libdebug.snapshots.process_snapshot import ProcessSnapshot


from libdebug.snapshots.memory_content_diff import MemoryContentDiff
from libdebug.snapshots.register_diff import RegisterDiff
from libdebug.snapshots.register_diff_accessor import RegisterDiffAccessor


class ProcessSnapshotDiff:
    """This object represents a diff between process snapshots."""

    def __init__(self: ProcessSnapshotDiff, snapshot1: ProcessSnapshot, snapshot2: ProcessSnapshot) -> None:
        """Returns a diff between given snapshots of the same process.

        Args:
            snapshot1 (ProcessSnapshot): A process snapshot.
            snapshot2 (ProcessSnapshot): A process snapshot.
        """
        if not isinstance(snapshot1, ProcessSnapshot) or not isinstance(snapshot2, ProcessSnapshot):
            raise ValueError("Both arguments must be ProcessSnapshot objects.")

        self.snapshot1 = snapshot1 if snapshot1.snapshot_id < snapshot2.snapshot_id else snapshot2
        self.snapshot2 = snapshot2 if snapshot1.snapshot_id >= snapshot2.snapshot_id else snapshot1
        self.level = "full" if self.snapshot1.level == "full" and self.snapshot2.level == "full" else "base"

        # Register diffs
        self.regs = RegisterDiffAccessor()

        for reg_name in dir(snapshot1.regs):
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
        self.maps_diff = []

        for map1 in self.snapshot1.maps:
            if map1 not in self.snapshot2.maps:
                self.maps_diff.append(map1)

        for map2 in self.snapshot2.maps:
            if map2 not in self.snapshot1.maps:
                self.maps_diff.append(map2)

        # Handle saved memory maps
        if self.level == "full":
            self.saved_maps_diff = []

            for map1 in self.snapshot1.saved_memory_maps:

                # Find the corresponding map in the second snapshot
                map2 = None

                for candidate in self.snapshot2.saved_memory_maps:
                    if map1.is_same_identity(candidate):
                        map2 = candidate
                        break

                if map2 is None:
                    continue

                diff = MemoryContentDiff(
                    old_content=map1,
                    new_content=map2,
                    has_changed=(map1 != map2),
                )

                self.saved_maps_diff.append(diff)

        # Thread diffs
        # - Born and dead threads are saved as snapshots
        # - Threads that keep existing are saved as diffs and are accessed through the usual threads property
        self.born_threads = []
        self.dead_threads = []
        self.threads = []

        for t1 in self.snapshot1.threads:
            t2 = None

            for candidate in self.snapshot2.threads:
                if t1.tid == candidate.tid:
                    t2 = candidate
                    break

            if t2 is None:
                # Append thread snapshot to dead threads
                self.dead_threads.append(t1)
            else:
                diff = ThreadSnapshotDiff(t1, t2)
                self.threads_diff.append(diff)
        
        for t2 in self.snapshot2.threads:
            t1 = None

            for candidate in self.snapshot1.threads:
                if t2.tid == candidate.tid:
                    t1 = candidate
                    break

            if t1 is None:
                self.born_threads.append(t2)
