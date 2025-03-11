#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from itertools import zip_longest
from typing import TYPE_CHECKING

from libdebug.architectures.stack_unwinding_provider import stack_unwinding_provider
from libdebug.snapshots.memory.memory_map_diff import MemoryMapDiff
from libdebug.snapshots.memory.memory_map_diff_list import MemoryMapDiffList
from libdebug.snapshots.registers.register_diff import RegisterDiff
from libdebug.snapshots.registers.register_diff_accessor import RegisterDiffAccessor
from libdebug.utils.libcontext import libcontext
from libdebug.utils.platform_utils import get_platform_gp_register_size
from libdebug.utils.pprint_primitives import (
    get_colored_saved_address_util,
    pad_colored_string,
    pprint_diff_line,
    pprint_diff_substring,
    pprint_inline_diff,
    pprint_memory_diff_util,
    pprint_reg_diff_large_util,
    pprint_reg_diff_util,
)

if TYPE_CHECKING:
    from libdebug.snapshots.registers.snapshot_registers import SnapshotRegisters
    from libdebug.snapshots.snapshot import Snapshot


class Diff:
    """This object represents a diff between two snapshots."""

    def __init__(self: Diff, snapshot1: Snapshot, snapshot2: Snapshot) -> None:
        """Initialize the Diff object with two snapshots.

        Args:
            snapshot1 (Snapshot): The first snapshot.
            snapshot2 (Snapshot): The second snapshot.
        """
        if snapshot1.snapshot_id < snapshot2.snapshot_id:
            self.snapshot1 = snapshot1
            self.snapshot2 = snapshot2
        else:
            self.snapshot1 = snapshot2
            self.snapshot2 = snapshot1

        # The level of the diff is the lowest level among the two snapshots
        if snapshot1.level == "base" or snapshot2.level == "base":
            self.level = "base"
        elif snapshot1.level == "writable" or snapshot2.level == "writable":
            self.level = "writable"
        else:
            self.level = "full"

        if self.snapshot1.arch != self.snapshot2.arch:
            raise ValueError("Snapshots have different architectures. Automatic diff is not supported.")

    def _save_reg_diffs(self: Snapshot) -> None:
        self.regs = RegisterDiffAccessor(
            self.snapshot1.regs._generic_regs,
            self.snapshot1.regs._special_regs,
            self.snapshot1.regs._vec_fp_regs,
        )

        all_regs = dir(self.snapshot1.regs)
        all_regs = [reg for reg in all_regs if isinstance(self.snapshot1.regs.__getattribute__(reg), int | float)]

        for reg_name in all_regs:
            old_value = self.snapshot1.regs.__getattribute__(reg_name)
            new_value = self.snapshot2.regs.__getattribute__(reg_name)
            has_changed = old_value != new_value

            diff = RegisterDiff(
                old_value=old_value,
                new_value=new_value,
                has_changed=has_changed,
            )

            # Create diff object
            self.regs.__setattr__(reg_name, diff)

    def _resolve_maps_diff(self: Diff) -> None:
        # Handle memory maps
        all_maps_diffs = []
        handled_map2_indices = []

        for map1 in self.snapshot1.maps:
            # Find the corresponding map in the second snapshot
            map2 = None

            for map2_index, candidate in enumerate(self.snapshot2.maps):
                if map1.is_same_identity(candidate):
                    map2 = candidate
                    handled_map2_indices.append(map2_index)
                    break

            if map2 is None:
                diff = MemoryMapDiff(
                    old_map_state=map1,
                    new_map_state=None,
                    has_changed=True,
                )
            else:
                diff = MemoryMapDiff(
                    old_map_state=map1,
                    new_map_state=map2,
                    has_changed=(map1 != map2),
                )

            all_maps_diffs.append(diff)

        new_pages = [self.snapshot2.maps[i] for i in range(len(self.snapshot2.maps)) if i not in handled_map2_indices]

        for new_page in new_pages:
            diff = MemoryMapDiff(
                old_map_state=None,
                new_map_state=new_page,
                has_changed=True,
            )

            all_maps_diffs.append(diff)

        # Convert the list to a MemoryMapDiffList
        self.maps = MemoryMapDiffList(
            all_maps_diffs,
            self.snapshot1._process_name,
            self.snapshot1._process_full_path,
        )

    @property
    def registers(self: Snapshot) -> SnapshotRegisters:
        """Alias for regs."""
        return self.regs

    def pprint_maps(self: Diff) -> None:
        """Pretty print the memory maps diff."""
        has_prev_changed = False

        for diff in self.maps:
            ref = diff.old_map_state if diff.old_map_state is not None else diff.new_map_state

            map_state_str = ""
            map_state_str += "Memory Map:\n"
            map_state_str += f"    start: {ref.start:#x}\n"
            map_state_str += f"    end: {ref.end:#x}\n"
            map_state_str += f"    permissions: {ref.permissions}\n"
            map_state_str += f"    size: {ref.size:#x}\n"
            map_state_str += f"    offset: {ref.offset:#x}\n"
            map_state_str += f"    backing_file: {ref.backing_file}\n"

            # If is added
            if diff.old_map_state is None:
                pprint_diff_line(map_state_str, is_added=True)

                has_prev_changed = True
            # If is removed
            elif diff.new_map_state is None:
                pprint_diff_line(map_state_str, is_added=False)

                has_prev_changed = True
            elif diff.old_map_state.end != diff.new_map_state.end:
                printed_line = map_state_str

                new_map_end = diff.new_map_state.end

                start_strike = printed_line.find("end:") + 4
                end_strike = printed_line.find("\n", start_strike)

                pprint_inline_diff(printed_line, start_strike, end_strike, f"{hex(new_map_end)}")

                has_prev_changed = True
            elif diff.old_map_state.permissions != diff.new_map_state.permissions:
                printed_line = map_state_str

                new_map_permissions = diff.new_map_state.permissions

                start_strike = printed_line.find("permissions:") + 12
                end_strike = printed_line.find("\n", start_strike)

                pprint_inline_diff(printed_line, start_strike, end_strike, new_map_permissions)

                has_prev_changed = True
            elif diff.old_map_state.content != diff.new_map_state.content:
                printed_line = map_state_str + "    [content changed]\n"
                color_start = printed_line.find("[content changed]")

                pprint_diff_substring(printed_line, color_start, color_start + len("[content changed]"))

                has_prev_changed = True
            else:
                if has_prev_changed:
                    print("\n[...]\n")

                has_prev_changed = False

    def pprint_memory(
        self: Diff,
        start: int,
        end: int,
        file: str = "hybrid",
        override_word_size: int = None,
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
            raise ValueError("Memory diff is not available at base snapshot level.")

        if start > end:
            tmp = start
            start = end
            end = tmp

        word_size = (
            get_platform_gp_register_size(self.snapshot1.arch) if override_word_size is None else override_word_size
        )

        # Resolve the address
        if file == "absolute":
            address_start = start
        elif file == "hybrid":
            try:
                # Try to resolve the address as absolute
                self.snapshot1.memory[start, 1, "absolute"]
                address_start = start
            except ValueError:
                # If the address is not in the maps, we use the binary file
                address_start = start + self.snapshot1.maps.filter("binary")[0].start
                file = "binary"
        else:
            map_file = self.snapshot1.maps.filter(file)[0]
            address_start = start + map_file.base
            file = map_file.backing_file if file != "binary" else "binary"

        extract_before = self.snapshot1.memory[start:end, file]
        extract_after = self.snapshot2.memory[start:end, file]

        file_info = f" (file: {file})" if file not in ("absolute", "hybrid") else ""
        print(f"Memory diff from {start:#x} to {end:#x}{file_info}:")

        pprint_memory_diff_util(
            address_start,
            extract_before,
            extract_after,
            word_size,
            self.snapshot1.maps,
            integer_mode=integer_mode,
        )

    def pprint_regs(self: Diff) -> None:
        """Pretty print the general_purpose registers diffs."""
        # Header with column alignment
        print("{:<19} {:<24} {:<20}\n".format("Register", "Old Value", "New Value"))
        print("-" * 58 + "")

        # Log all integer changes
        for attr_name in self.regs._generic_regs:
            attr = self.regs.__getattribute__(attr_name)

            if attr.has_changed:
                pprint_reg_diff_util(
                    attr_name,
                    self.snapshot1.maps,
                    self.snapshot2.maps,
                    attr.old_value,
                    attr.new_value,
                )

    def pprint_regs_all(self: Diff) -> None:
        """Pretty print the registers diffs (including special and vector registers)."""
        # Header with column alignment
        print("{:<19} {:<24} {:<20}\n".format("Register", "Old Value", "New Value"))
        print("-" * 58 + "")

        # Log all integer changes
        for attr_name in self.regs._generic_regs + self.regs._special_regs:
            attr = self.regs.__getattribute__(attr_name)

            if attr.has_changed:
                pprint_reg_diff_util(
                    attr_name,
                    self.snapshot1.maps,
                    self.snapshot2.maps,
                    attr.old_value,
                    attr.new_value,
                )

        print()

        # Log all vector changes
        for attr1_name, attr2_name in self.regs._vec_fp_regs:
            attr1 = self.regs.__getattribute__(attr1_name)
            attr2 = self.regs.__getattribute__(attr2_name)

            if attr1.has_changed or attr2.has_changed:
                pprint_reg_diff_large_util(
                    (attr1_name, attr2_name),
                    (attr1.old_value, attr2.old_value),
                    (attr1.new_value, attr2.new_value),
                )

    def pprint_registers(self: Diff) -> None:
        """Alias afor pprint_regs."""
        self.pprint_regs()

    def pprint_registers_all(self: Diff) -> None:
        """Alias for pprint_regs_all."""
        self.pprint_regs_all()

    def pprint_backtrace(self: Diff) -> None:
        """Pretty print the backtrace diff."""
        if self.level == "base":
            raise ValueError("Backtrace is not available at base level. Stack is not available")

        prev_log_level = libcontext.general_logger
        libcontext.general_logger = "SILENT"
        stack_unwinder = stack_unwinding_provider(self.snapshot1.arch)
        backtrace1 = stack_unwinder.unwind(self.snapshot1)
        backtrace2 = stack_unwinder.unwind(self.snapshot2)

        maps1 = self.snapshot1.maps
        maps2 = self.snapshot2.maps

        symbols = self.snapshot1.memory._symbol_ref

        # Columns are Before, Unchanged, After
        #  __    __
        # |__|  |__|
        # |__|  |__|
        # |__|__|__|
        # |__|__|__|
        # |__|__|__|
        column1 = []
        column2 = []
        column3 = []

        for addr1, addr2 in zip_longest(reversed(backtrace1), reversed(backtrace2)):
            col1 = get_colored_saved_address_util(addr1, maps1, symbols).strip() if addr1 else None
            col2 = None
            col3 = None

            if addr2:
                if addr1 == addr2:
                    col2 = col1
                    col1 = None
                else:
                    col3 = get_colored_saved_address_util(addr2, maps2, symbols).strip()

            column1.append(col1)
            column2.append(col2)
            column3.append(col3)

        max_str_len = max([len(x) if x else 0 for x in column1 + column2 + column3])

        print("Backtrace diff:")
        print("-" * (max_str_len * 3 + 6))
        print(f"{'Before':<{max_str_len}} | {'Unchanged':<{max_str_len}} | {'After':<{max_str_len}}")
        for col1_val, col2_val, col3_val in zip(reversed(column1), reversed(column2), reversed(column3), strict=False):
            col1 = pad_colored_string(col1_val, max_str_len) if col1_val else " " * max_str_len
            col2 = pad_colored_string(col2_val, max_str_len) if col2_val else " " * max_str_len
            col3 = pad_colored_string(col3_val, max_str_len) if col3_val else " " * max_str_len

            print(f"{col1} | {col2} | {col3}")

        print("-" * (max_str_len * 3 + 6))

        libcontext.general_logger = prev_log_level
