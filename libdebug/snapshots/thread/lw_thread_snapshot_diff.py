#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#
from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.snapshots.diff import Diff
from libdebug.snapshots.thread.thread_snapshot import ThreadSnapshot
from libdebug.snapshots.thread.thread_snapshot_diff import ThreadSnapshotDiff

if TYPE_CHECKING:
    from libdebug.snapshots.memory.memory_map_diff import MemoryMapDiff
    from libdebug.snapshots.process.process_shapshot_diff import ProcessSnapshotDiff


class LightweightThreadSnapshotDiff(ThreadSnapshotDiff):
    """This object represents a diff between thread snapshots."""

    def __init__(
        self: LightweightThreadSnapshotDiff,
        snapshot1: ThreadSnapshot,
        snapshot2: ThreadSnapshot,
        process_diff: ProcessSnapshotDiff,
    ) -> ThreadSnapshotDiff:
        """Returns a diff between given snapshots of the same thread.

        Args:
            snapshot1 (ThreadSnapshot): A thread snapshot.
            snapshot2 (ThreadSnapshot): A thread snapshot.
            process_diff (ProcessSnapshotDiff): The diff of the process to which the thread belongs.
        """
        if not isinstance(snapshot1, ThreadSnapshot) or not isinstance(snapshot2, ThreadSnapshot):
            raise TypeError("Both arguments must be ThreadSnapshot objects.")

        # Generic diff initialization
        Diff.__init__(self, snapshot1, snapshot2)

        # Register diffs
        self._save_reg_diffs()

        self._proc_diff = process_diff

    @property
    def maps(self: LightweightThreadSnapshotDiff) -> list[MemoryMapDiff]:
        """Return the memory map diff."""
        return self._proc_diff.maps
