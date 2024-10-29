#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#
from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.snapshots.thread.thread_snapshot import ThreadSnapshot

if TYPE_CHECKING:
    from libdebug.snapshots.memory.memory_map_snapshot_list import MemoryMapSnapshotList
    from libdebug.snapshots.memory.snapshot_memory_view import SnapshotMemoryView
    from libdebug.snapshots.process.process_snapshot import ProcessSnapshot
    from libdebug.state.thread_context import ThreadContext


class LightweightThreadSnapshot(ThreadSnapshot):
    """This object represents a snapshot of the target thread. It has to be initialized by a ProcessSnapshot, since it initializes its properties with shared process state. It holds information about a thread's state.

    Snapshot levels:
    - base: Registers
    - writable: Registers, writable memory
    - full: Registers, memory
    """

    def __init__(
        self: LightweightThreadSnapshot,
        thread: ThreadContext,
        process_snapshot: ProcessSnapshot,
    ) -> None:
        """Creates a new snapshot object for the given thread.

        Args:
            thread (ThreadContext): The thread to take a snapshot of.
            process_snapshot (ProcessSnapshot): The process snapshot to which the thread belongs.
        """
        # Set id of the snapshot and increment the counter
        self.snapshot_id = thread._snapshot_count
        thread._snapshot_count += 1

        # Basic snapshot info
        self.thread_id = thread.thread_id
        self.tid = thread.tid

        # If there is a name, append the thread id
        if process_snapshot.name is None:
            self.name = None
        else:
            self.name = f"{process_snapshot.name} - Thread {self.tid}"

        # Get thread registers
        self._save_regs(thread)

        self._proc_snapshot = process_snapshot

    @property
    def level(self: LightweightThreadSnapshot) -> str:
        """Returns the snapshot level."""
        return self._proc_snapshot.level

    @property
    def arch(self: LightweightThreadSnapshot) -> str:
        """Returns the architecture of the thread snapshot."""
        return self._proc_snapshot.arch

    @property
    def maps(self: LightweightThreadSnapshot) -> MemoryMapSnapshotList:
        """Returns the memory map snapshot list associated with the process snapshot."""
        return self._proc_snapshot.maps

    @property
    def _memory(self: LightweightThreadSnapshot) -> SnapshotMemoryView:
        """Returns the memory view associated with the process snapshot."""
        return self._proc_snapshot._memory
