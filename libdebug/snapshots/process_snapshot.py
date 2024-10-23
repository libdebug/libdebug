#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#
from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.data.memory_map import MemoryMap
from libdebug.liblog import liblog
from libdebug.debugger.debugger import Debugger
from libdebug.snapshots.thread_snapshot import ThreadSnapshot
from libdebug.snapshots.lw_thread_snapshot import LightweightThreadSnapshot
from libdebug.snapshots.snapshot_registers import SnapshotRegisters

if TYPE_CHECKING:
    from libdebug.state.thread_context import ThreadContext


class ProcessSnapshot:
    """This object represents a snapshot of the target process. It holds information about the process's state.

    Snapshot levels:
    - base: Registers
    - full: Registers, stack, memory
    """

    def __init__(self: ProcessSnapshot, d: Debugger, level: str = "base", name: str = None) -> None:
        """Creates a new snapshot object for the given process.

        Args:
            d (Debugger): The thread to take a snapshot of.
            level (str, optional): The level of the snapshot. Defaults to "base".
            name (str, optional): A name associated to the snapshot. Defaults to None.
        """
        # Set id of the snapshot and increment the counter
        self.snapshot_id = d._internal_debugger._snapshot_count
        d._internal_debugger._snapshot_count += 1

        # Basic snapshot info
        self.process_id = d.pid
        self.pid = d.pid
        self.name = name
        self.level = level

        # Create a register field for the snapshot

        self.regs = SnapshotRegisters(d.thread_id, d.threads[0]._register_holder.provide_regs())

        # Set all registers in the field
        all_regs = dir(d.regs)
        all_regs = [reg for reg in all_regs if not reg.startswith("_") and reg != "register_file"]

        for reg_name in all_regs:
            reg_value = d.regs.__getattribute__(reg_name)
            self.regs.__setattr__(reg_name, reg_value)

        # Memory maps
        match level:
            case "base":
                self.maps = d.maps.copy()
            case "full":
                _save_memory_contents(self, d)
            case _:
                raise ValueError(f"Invalid snapshot level {level}")
            
        self.threads = []
            
        for thread in d.threads:

            # Create a lightweight snapshot for the thread
            lw_snapshot = LightweightThreadSnapshot(thread, level, name, self.maps)

            self.threads.append(lw_snapshot)

        # Log the creation of the snapshot
        named_addition = " named " + self.name if name is not None else ""
        liblog.debugger(f"Created snapshot {self.snapshot_id} of level {self.level} for process {self.pid}{named_addition}")

        def _save_memory_contents(self: ThreadSnapshot, debugger: Debugger) -> None:
            """Saves memory maps of the process to the snapshot."""

            self.saved_memory_maps = []

            for curr_map in debugger.maps:
                contents = debugger.memory[curr_map.start:curr_map.end, "absolute"]
                saved_map = MemoryMap(curr_map.start, curr_map.end, curr_map.permissions, curr_map.size, curr_map.offset, curr_map.backing_file, contents)
                self.maps.append(saved_map)