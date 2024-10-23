#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#
from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.data.memory_map import MemoryMap
from libdebug.liblog import liblog
from libdebug.snapshots.snapshot_registers import SnapshotRegisters

if TYPE_CHECKING:
    from libdebug.state.thread_context import ThreadContext


class ThreadSnapshot:
    """This object represents a snapshot of the target thread. It holds information about a thread's state.

    Snapshot levels:
    - base: Registers
    - full: Registers, stack, memory
    """

    def __init__(self: ThreadSnapshot, thread: ThreadContext, level: str = "base", name: str = None) -> None:
        """Creates a new snapshot object for the given thread.

        Args:
            thread (ThreadContext): The thread to take a snapshot of.
            level (str, optional): The level of the snapshot. Defaults to "base".
            name (str, optional): A name associated to the snapshot. Defaults to None.
        """
        # Set id of the snapshot and increment the counter
        self.snapshot_id = thread._snapshot_count
        thread._snapshot_count += 1

        # Basic snapshot info
        self.thread_id = thread.thread_id
        self.tid = thread.tid
        self.name = name
        self.level = level

        # Create a register field for the snapshot

        self.regs = SnapshotRegisters(thread.thread_id, thread._register_holder.provide_regs())

        # Set all registers in the field
        all_regs = dir(thread.regs)
        all_regs = [reg for reg in all_regs if not reg.startswith("_") and reg != "register_file"]

        for reg_name in all_regs:
            reg_value = thread.regs.__getattribute__(reg_name)
            self.regs.__setattr__(reg_name, reg_value)

        # Memory maps
        match level:
            case "base":
                self.maps = thread.debugger.maps.copy()
            case "full":
                # Save all memory pages
                _save_memory_maps(self, thread)
            case _:
                raise ValueError(f"Invalid snapshot level {level}")

        # Log the creation of the snapshot
        named_addition = " named " + self.name if name is not None else ""
        liblog.debugger(f"Created snapshot {self.snapshot_id} of level {self.level} for thread {self.tid}{named_addition}")

        def _save_memory_maps(self: ThreadSnapshot, thread: ThreadContext) -> None:
            """Saves memory maps of the thread to the snapshot."""

            self.saved_memory_maps = []

            for curr_map in thread.debugger.maps:
                contents = thread.memory[curr_map.start:curr_map.end, "absolute"]
                saved_map = MemoryMap(curr_map.start, curr_map.end, curr_map.permissions, curr_map.size, curr_map.offset, curr_map.backing_file, contents)
                self.maps.append(saved_map)