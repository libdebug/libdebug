#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#
from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.liblog import liblog
from libdebug.snapshots.memory.memory_map_snapshot_list import MemoryMapSnapshotList
from libdebug.snapshots.memory.snapshot_memory_view import SnapshotMemoryView
from libdebug.snapshots.snapshot import Snapshot
from libdebug.snapshots.thread.lw_thread_snapshot import LightweightThreadSnapshot

if TYPE_CHECKING:
    from libdebug.debugger.debugger import Debugger
    from libdebug.snapshots.registers.snapshot_registers import SnapshotRegisters


class ProcessSnapshot(Snapshot):
    """This object represents a snapshot of the target process. It holds information about the process's state.

    Snapshot levels:
    - base: Registers
    - writable: Registers, writable memory maps
    - full: Registers, stack, memory
    """

    def __init__(self: ProcessSnapshot, debugger: Debugger, level: str = "base", name: str = None) -> None:
        """Creates a new snapshot object for the given process.

        Args:
            debugger (Debugger): The thread to take a snapshot of.
            level (str, optional): The level of the snapshot. Defaults to "base".
            name (str, optional): A name associated to the snapshot. Defaults to None.
        """
        # Set id of the snapshot and increment the counter
        self.snapshot_id = debugger._internal_debugger._snapshot_count
        debugger._internal_debugger._snapshot_count += 1

        # Basic snapshot info
        self.process_id = debugger.pid
        self.pid = debugger.pid
        self.name = name
        self.level = level
        self._process_full_path = debugger._internal_debugger._process_full_path
        self._process_name = debugger._internal_debugger._process_name

        # Memory maps
        match level:
            case "base":
                map_list = debugger.maps.as_list()
                self.maps = MemoryMapSnapshotList(map_list, self._process_name, self._process_full_path)

                self._memory = None
            case "writable":
                if not debugger.fast_memory:
                    liblog.warning(
                        "Memory snapshot requested but fast memory is not enabled. This will take a long time.",
                    )

                # Save all memory pages
                self._save_memory_maps(debugger, writable_only=True)

                self._memory = SnapshotMemoryView(self, debugger.symbols)
            case "full":
                if not debugger.fast_memory:
                    liblog.warning(
                        "Memory snapshot requested but fast memory is not enabled. This will take a long time.",
                    )

                # Save all memory pages
                self._save_memory_maps(debugger, writable_only=False)

                self._memory = SnapshotMemoryView(self, debugger.symbols)
            case _:
                raise ValueError(f"Invalid snapshot level {level}")

        # Snapshot the threads
        self._save_threads(debugger)

        # Log the creation of the snapshot
        named_addition = " named " + self.name if name is not None else ""
        liblog.debugger(
            f"Created snapshot {self.snapshot_id} of level {self.level} for process {self.pid}{named_addition}"
        )

    def _save_threads(self: ProcessSnapshot, debugger: Debugger) -> None:
        self.threads = []

        for thread in debugger.threads:
            # Create a lightweight snapshot for the thread
            lw_snapshot = LightweightThreadSnapshot(thread, self)

            self.threads.append(lw_snapshot)

    @property
    def regs(self: ProcessSnapshot) -> SnapshotRegisters:
        """Returns the registers of the process snapshot."""
        return self.threads[0].regs
