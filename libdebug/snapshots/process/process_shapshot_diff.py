#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#
from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.liblog import liblog
from libdebug.snapshots.diff import Diff
from libdebug.snapshots.thread.lw_thread_snapshot_diff import LightweightThreadSnapshotDiff

if TYPE_CHECKING:
    from libdebug.snapshots.process.process_snapshot import ProcessSnapshot


class ProcessSnapshotDiff(Diff):
    """This object represents a diff between process snapshots."""

    def __init__(self: ProcessSnapshotDiff, snapshot1: ProcessSnapshot, snapshot2: ProcessSnapshot) -> None:
        """Returns a diff between given snapshots of the same process.

        Args:
            snapshot1 (ProcessSnapshot): A process snapshot.
            snapshot2 (ProcessSnapshot): A process snapshot.
        """
        super().__init__(snapshot1, snapshot2)

        # Register diffs
        self._save_reg_diffs()

        # Memory map diffs
        self._resolve_maps_diff()

        # Thread diffs
        self._generate_thread_diffs()

        if (self.snapshot1._process_name == self.snapshot2._process_name) and (
            self.snapshot1.aslr_enabled or self.snapshot2.aslr_enabled
        ):
            liblog.warning("ASLR is enabled in either or both snapshots. Diff may be messy.")

    def _generate_thread_diffs(self: ProcessSnapshotDiff) -> None:
        """Generates thread diffs between the two snapshots.

        Thread diffs
         - Born and dead threads are saved as snapshots
         - Threads that keep existing are saved as diffs and are accessed through the usual threads property
        """
        self.born_threads = []
        self.dead_threads = []
        self.threads_diff = []

        snapshot1_by_tid = {thread.tid: thread for thread in self.snapshot1.threads}
        snapshot2_by_tid = {thread.tid: thread for thread in self.snapshot2.threads}

        for tid, t1 in snapshot1_by_tid.items():
            t2 = snapshot2_by_tid.get(tid)
            if t2 is None:
                self.dead_threads.append(t1)
            else:
                diff = LightweightThreadSnapshotDiff(t1, t2, self)
                self.threads_diff.append(diff)

        for tid, t2 in snapshot2_by_tid.items():
            if tid not in snapshot1_by_tid:
                self.born_threads.append(t2)
