#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#
from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.data.memory_map_list import MemoryMapList
from libdebug.liblog import liblog
from libdebug.snapshots.snapshot_registers import SnapshotRegisters
from libdebug.snapshots.thread_snapshot import ThreadSnapshot

if TYPE_CHECKING:
    from libdebug.state.thread_context import ThreadContext


class LightweightThreadSnapshot(ThreadSnapshot):
    """This object represents a snapshot of the target thread. It has to be initialized by a ProcessSnapshot, since it initializes its properties with shared process state. It holds information about a thread's state.

    Snapshot levels:
    - base: Registers
    - full: Registers, stack, memory
    """

    def __init__(self: LightweightThreadSnapshot, thread: ThreadContext, level: str = "base", name: str = None, maps: MemoryMapList = None) -> None:
        """Creates a new snapshot object for the given thread.

        Args:
            thread (ThreadContext): The thread to take a snapshot of.
            level (str, optional): The level of the snapshot. Defaults to "base".
            name (str, optional): A name associated to the snapshot. Defaults to None.
            maps (MemoryMapList, optional): Memory maps from ProcessSnapshot. Defaults to None.
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
        self.maps = maps
