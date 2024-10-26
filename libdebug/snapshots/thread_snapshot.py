#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#
from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.data.memory_map import MemoryMap
from libdebug.liblog import liblog
from libdebug.snapshots.memory.memory_map_snapshot_list import MemoryMapSnapshotList
from libdebug.snapshots.memory.snapshot_memory_view import SnapshotMemoryView
from libdebug.snapshots.registers.snapshot_registers import SnapshotRegisters

if TYPE_CHECKING:
    from libdebug.state.thread_context import ThreadContext


class ThreadSnapshot:
    """This object represents a snapshot of the target thread. It holds information about a thread's state.

    Snapshot levels:
    - base: Registers
    - writable: Registers, writable memory maps
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
        self._process_full_path = thread.debugger._internal_debugger._process_full_path
        self._process_name = thread.debugger._internal_debugger._process_name

        self._save_regs(thread)

        # Memory maps
        match level:
            case "base":
                map_list = thread.debugger.maps.as_list()
                self.maps = MemoryMapSnapshotList(map_list, self._process_name, self._process_full_path)
            case "writable":
                if not thread.debugger.fast_memory:
                    liblog.warning(
                        "Memory snapshot requested but fast memory is not enabled. This will take a long time."
                    )

                # Save all memory pages
                self._save_memory_maps(thread, writable_only=True)

                self.memory = SnapshotMemoryView(self, thread.debugger.symbols)
            case "full":
                if not thread.debugger.fast_memory:
                    liblog.warning(
                        "Memory snapshot requested but fast memory is not enabled. This will take a long time."
                    )

                # Save all memory pages
                self._save_memory_maps(thread, writable_only=False)

                self.memory = SnapshotMemoryView(self, thread.debugger.symbols)
            case _:
                raise ValueError(f"Invalid snapshot level {level}")

        # Log the creation of the snapshot
        named_addition = " named " + self.name if name is not None else ""
        liblog.debugger(
            f"Created snapshot {self.snapshot_id} of level {self.level} for thread {self.tid}{named_addition}"
        )

    def _save_regs(self: ThreadSnapshot, thread: ThreadContext) -> None:
        # Create a register field for the snapshot
        self.regs = SnapshotRegisters(thread.thread_id, thread._register_holder.provide_regs())

        # Set all registers in the field
        all_regs = dir(thread.regs)
        all_regs = [reg for reg in all_regs if not reg.startswith("_") and reg != "register_file"]

        for reg_name in all_regs:
            reg_value = thread.regs.__getattribute__(reg_name)
            self.regs.__setattr__(reg_name, reg_value)

    def _save_memory_maps(self: ThreadSnapshot, thread: ThreadContext, writable_only: bool) -> None:
        """Saves memory maps of the thread to the snapshot."""
        map_list = []

        for curr_map in thread.debugger.maps:
            # Skip non-writable maps if requested
            # Always skip maps that fail on read
            if not writable_only or "w" in curr_map.permissions:
                try:
                    contents = thread.debugger.memory[curr_map.start : curr_map.end, "absolute"]
                except (ValueError, OSError, OverflowError):
                    # There are some memory regions that cannot be read, such as [vvar], [vdso], etc.
                    contents = None
            else:
                contents = None

            saved_map = MemoryMap(
                curr_map.start,
                curr_map.end,
                curr_map.permissions,
                curr_map.size,
                curr_map.offset,
                curr_map.backing_file,
                contents,
            )
            map_list.append(saved_map)

        process_name = thread._internal_debugger._process_name
        full_process_path = thread._internal_debugger._process_full_path

        self.maps = MemoryMapSnapshotList(map_list, process_name, full_process_path)
