#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from abc import abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.debugger.internal_debugger import InternalDebugger
    from libdebug.snapshots.diff import Diff
    from libdebug.snapshots.memory.snapshot_memory_view import SnapshotMemoryView
    from libdebug.state.thread_context import ThreadContext

from libdebug.architectures.stack_unwinding_provider import stack_unwinding_provider
from libdebug.liblog import liblog
from libdebug.snapshots.memory.memory_map_snapshot import MemoryMapSnapshot
from libdebug.snapshots.memory.memory_map_snapshot_list import MemoryMapSnapshotList
from libdebug.snapshots.registers.snapshot_registers import SnapshotRegisters
from libdebug.utils.platform_utils import get_platform_gp_register_size
from libdebug.utils.pprint_primitives import (
    pprint_backtrace_util,
    pprint_maps_util,
    pprint_memory_util,
    pprint_registers_all_util,
    pprint_registers_util,
)


class Snapshot:
    """This object represents a snapshot of a system task.

    Snapshot levels:
    - base: Registers
    - writable: Registers, writable memory contents
    - full: Registers, all readable memory contents
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
        all_regs = [reg for reg in all_regs if isinstance(thread.regs.__getattribute__(reg), int | float)]

        for reg_name in all_regs:
            reg_value = thread.regs.__getattribute__(reg_name)
            self.regs.__setattr__(reg_name, reg_value)

    def _save_memory_maps(self: Snapshot, debugger: InternalDebugger, writable_only: bool) -> None:
        """Saves memory maps of the process to the snapshot."""
        process_name = debugger._process_name
        full_process_path = debugger._process_full_path
        self.maps = MemoryMapSnapshotList([], process_name, full_process_path)

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

            saved_map = MemoryMapSnapshot(
                curr_map.start,
                curr_map.end,
                curr_map.permissions,
                curr_map.size,
                curr_map.offset,
                curr_map.backing_file,
                contents,
            )
            self.maps.append(saved_map)

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

    def save(self: Snapshot, file_path: str) -> None:
        """Saves the snapshot object to a file."""
        self._serialization_helper.save(self, file_path)

    def backtrace(self: Snapshot) -> list[int]:
        """Returns the current backtrace of the thread."""
        if self.level == "base":
            raise ValueError("Backtrace is not available at base level. Stack is not available.")

        stack_unwinder = stack_unwinding_provider(self.arch)
        return stack_unwinder.unwind(self)

    def pprint_registers(self: Snapshot) -> None:
        """Pretty prints the thread's registers."""
        pprint_registers_util(self.regs, self.maps, self.regs._generic_regs)

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

    def pprint_memory(
        self: Snapshot,
        start: int,
        end: int,
        file: str = "hybrid",
        override_word_size: int | None = None,
        integer_mode: bool = False,
    ) -> None:
        """Pretty print the memory diff.

        Args:
            start (int): The start address of the memory diff.
            end (int): The end address of the memory diff.
            file (str, optional): The backing file for relative / absolute addressing. Defaults to "hybrid".
            override_word_size (int, optional): The word size to use for the diff in place of the ISA word size. Defaults to None.
            integer_mode (bool, optional): If True, the diff will be printed as hex integers (system endianness applies). Defaults to False.
        """
        if self.level == "base":
            raise ValueError("Memory is not available at base level.")

        if start > end:
            tmp = start
            start = end
            end = tmp

        word_size = get_platform_gp_register_size(self.arch) if override_word_size is None else override_word_size

        # Resolve the address
        if file == "absolute":
            address_start = start
        elif file == "hybrid":
            try:
                # Try to resolve the address as absolute
                self.memory[start, 1, "absolute"]
                address_start = start
            except ValueError:
                # If the address is not in the maps, we use the binary file
                address_start = start + self.maps.filter("binary")[0].start
                file = "binary"
        else:
            map_file = self.maps.filter(file)[0]
            address_start = start + map_file.base
            file = map_file.backing_file if file != "binary" else "binary"

        extract = self.memory[start:end, file]

        file_info = f" (file: {file})" if file not in ("absolute", "hybrid") else ""
        print(f"Memory from {start:#x} to {end:#x}{file_info}:")

        pprint_memory_util(
            address_start,
            extract,
            word_size,
            self.maps,
            integer_mode=integer_mode,
        )

