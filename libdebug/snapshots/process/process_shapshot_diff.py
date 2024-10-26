#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#
from __future__ import annotations

from libdebug.snapshots.diff import Diff
from libdebug.snapshots.process.process_snapshot import ProcessSnapshot
from libdebug.snapshots.thread.lw_thread_snapshot_diff import LightweightThreadSnapshotDiff


class ProcessSnapshotDiff(Diff):
    """This object represents a diff between process snapshots."""

    def __init__(self: ProcessSnapshotDiff, snapshot1: ProcessSnapshot, snapshot2: ProcessSnapshot) -> None:
        """Returns a diff between given snapshots of the same process.

        Args:
            snapshot1 (ProcessSnapshot): A process snapshot.
            snapshot2 (ProcessSnapshot): A process snapshot.
        """
        if not isinstance(snapshot1, ProcessSnapshot) or not isinstance(snapshot2, ProcessSnapshot):
            raise TypeError("Both arguments must be ProcessSnapshot objects.")

        super().__init__(snapshot1, snapshot2)

        # Register diffs
        self._save_reg_diffs()

        # Memory map diffs
        self._resolve_maps_diff()

        # Thread diffs
        self._generate_thread_diffs()

    def _generate_thread_diffs(self: ProcessSnapshotDiff) -> None:
        # Thread diffs
        # - Born and dead threads are saved as snapshots
        # - Threads that keep existing are saved as diffs and are accessed through the usual threads property
        self.born_threads = []
        self.dead_threads = []
        self.threads_diff = []

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
                diff = LightweightThreadSnapshotDiff(t1, t2, self)
                self.threads_diff.append(diff)

        for t2 in self.snapshot2.threads:
            t1 = None

            for candidate in self.snapshot1.threads:
                if t2.tid == candidate.tid:
                    t1 = candidate
                    break

            if t1 is None:
                self.born_threads.append(t2)
