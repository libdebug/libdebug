#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from abc import abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.debugger.debugger import Debugger
    from libdebug.snapshots.diff import Diff
    from libdebug.snapshots.memory.snapshot_memory_view import SnapshotMemoryView
    from libdebug.state.thread_context import ThreadContext

from libdebug.architectures.stack_unwinding_provider import stack_unwinding_provider
from libdebug.data.memory_map import MemoryMap
from libdebug.liblog import liblog
from libdebug.snapshots.memory.memory_map_snapshot_list import MemoryMapSnapshotList
from libdebug.snapshots.registers.snapshot_registers import SnapshotRegisters
from libdebug.utils.pprint_primitives import (
    pprint_backtrace_util,
    pprint_maps_util,
    pprint_registers_all_util,
    pprint_registers_util,
)


class Snapshot:
    """This object represents a snapshot of a system task.

    Snapshot levels:
    - base: Registers
    - writable: Registers, writable memory
    - full: Registers, memory
    """
    def _save_regs(self: Snapshot, thread: ThreadContext) -> None:
        # Create a register field for the snapshot
        self.regs = SnapshotRegisters(
            thread.thread_id,
            thread._register_holder.provide_regs(),
            thread._register_holder.provide_special_regs(),
            thread._register_holder.provide_vector_fp_regs(),
        )

        # Set all registers in the field
        all_regs = dir(thread.regs)
        all_regs = [reg for reg in all_regs if not reg.startswith("_") and reg != "register_file"]

        for reg_name in all_regs:
            reg_value = thread.regs.__getattribute__(reg_name)
            self.regs.__setattr__(reg_name, reg_value)

    def _save_memory_maps(self: Snapshot, debugger: Debugger, writable_only: bool) -> None:
        """Saves memory maps of the process to the snapshot."""
        map_list = []

        for curr_map in debugger.maps:
            # Skip non-writable maps if requested
            # Always skip maps that fail on read
            if not writable_only or "w" in curr_map.permissions:
                try:
                    contents = debugger.memory[curr_map.start : curr_map.end, "absolute"]
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

        process_name = debugger._internal_debugger._process_name
        full_process_path = debugger._internal_debugger._process_full_path

        self.maps = MemoryMapSnapshotList(map_list, process_name, full_process_path)

    @property
    def registers(self: Snapshot) -> SnapshotRegisters:
        """Alias for regs."""
        return self.regs

    @property
    def memory(self: Snapshot) -> SnapshotMemoryView:
        """Returns a view of the memory of the thread."""
        if self._memory is None:
            if self.level != "base":
                liblog.error("Inconsistent snapshot state: memory snapshot is not available.")

            raise ValueError("Memory snapshot is not available at base level.")

        return self._memory

    @property
    def mem(self: Snapshot) -> SnapshotMemoryView:
        """Alias for memory."""
        return self.memory

    @abstractmethod
    def diff(self: Snapshot, other: Snapshot) -> Diff:
        """Creates a diff object between two snapshots."""

    @abstractmethod
    def save(self: Snapshot, file_path: str) -> None:
        """Saves the snapshot object to a file."""

    @staticmethod
    @abstractmethod
    def load(snapshot_dict: object) -> Snapshot:
        """Loads a snapshot object from a serialized object."""

    def backtrace(self: Snapshot) -> list[int]:
        """Returns the current backtrace of the thread."""
        stack_unwinder = stack_unwinding_provider(self.arch)
        return stack_unwinder.unwind(self)

    def pprint_registers(self: Snapshot) -> None:
        """Pretty prints the thread's registers."""
        pprint_registers_util(
            self.regs,
            self.maps,
            self.regs._generic_regs
        )

    def pprint_regs(self: Snapshot) -> None:
        """Alias for the `pprint_registers` method.

        Pretty prints the thread's registers.
        """
        self.pprint_registers()

    def pprint_registers_all(self: Snapshot) -> None:
        """Pretty prints all the thread's registers."""
        pprint_registers_all_util(
            self.regs,
            self.maps,
            self.regs._generic_regs,
            self.regs._special_regs,
            self.regs._vec_fp_regs,
        )

    def pprint_regs_all(self: Snapshot) -> None:
        """Alias for the `pprint_registers_all` method.

        Pretty prints all the thread's registers.
        """
        self.pprint_registers_all()

    def pprint_backtrace(self: ThreadContext) -> None:
        """Pretty prints the current backtrace of the thread."""
        if self.level == "base":
            raise ValueError("Backtrace is not available at base level. Stack is not available.")

        stack_unwinder = stack_unwinding_provider(self.arch)
        backtrace = stack_unwinder.unwind(self)
        pprint_backtrace_util(backtrace, self.maps, self._memory._symbol_ref)

    def pprint_maps(self: Snapshot) -> None:
        """Prints the memory maps of the process."""
        pprint_maps_util(self.maps)
