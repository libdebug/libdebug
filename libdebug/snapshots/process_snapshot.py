#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#
from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.data.memory_map import MemoryMap
from libdebug.snapshots.memory_map_snapshot_list import MemoryMapSnapshotList
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

    def __init__(self: ProcessSnapshot, debugger: Debugger, level: str = "base", name: str = None) -> None:
        """Creates a new snapshot object for the given process.

        Args:
            d (Debugger): The thread to take a snapshot of.
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

        # Create a register field for the snapshot

        self.regs = SnapshotRegisters(debugger.thread_id, debugger.threads[0]._register_holder.provide_regs())

        # Set all registers in the field
        all_regs = dir(debugger.regs)
        all_regs = [reg for reg in all_regs if not reg.startswith("_") and reg != "register_file"]

        for reg_name in all_regs:
            reg_value = debugger.regs.__getattribute__(reg_name)
            self.regs.__setattr__(reg_name, reg_value)

        # Memory maps
        match level:
            case "base":
                map_list = debugger.maps.as_list()
                self.maps = MemoryMapSnapshotList(map_list, self._process_name, self._process_full_path)
            case "full":
                if not debugger.fast_memory:
                    liblog.warning("Memory snapshot requested but fast memory is not enabled. This will take a long time.")

                self._save_memory_maps(debugger)
            case _:
                raise ValueError(f"Invalid snapshot level {level}")
            
        self.threads = []
            
        for thread in debugger.threads:

            # Create a lightweight snapshot for the thread
            lw_snapshot = LightweightThreadSnapshot(thread, level, name, self.maps)

            self.threads.append(lw_snapshot)

        # Log the creation of the snapshot
        named_addition = " named " + self.name if name is not None else ""
        liblog.debugger(f"Created snapshot {self.snapshot_id} of level {self.level} for process {self.pid}{named_addition}")

    def _save_memory_maps(self: ThreadSnapshot, debugger: Debugger) -> None:
        """Saves memory maps of the process to the snapshot."""

        map_list = []

        for curr_map in debugger.maps:
            
            if curr_map.backing_file not in ["vvar", "vsyscall"]:
                # Save the contents of the memory map
                contents = debugger.memory[curr_map.start:curr_map.end, "absolute"]
            else:
                contents = None
            
            saved_map = MemoryMap(curr_map.start, curr_map.end, curr_map.permissions, curr_map.size, curr_map.offset, curr_map.backing_file, contents)
            map_list.append(saved_map)

        process_name = debugger._internal_debugger._process_name
        full_process_path = debugger._internal_debugger._process_full_path

        self.maps = MemoryMapSnapshotList(map_list, process_name, full_process_path)