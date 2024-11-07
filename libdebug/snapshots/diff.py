#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.snapshots.memory.memory_map_diff import MemoryMapDiff
from libdebug.snapshots.memory.memory_map_diff_list import MemoryMapDiffList
from libdebug.snapshots.registers.register_diff import RegisterDiff
from libdebug.snapshots.registers.register_diff_accessor import RegisterDiffAccessor
from libdebug.utils.platform_utils import get_platform_register_size
from libdebug.utils.pprint_primitives import (
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

                start_strike = printed_line.find("end=") + 4
                end_strike = printed_line.find(", perm")

                pprint_inline_diff(printed_line, start_strike, end_strike, f"{hex(new_map_end)}")

                has_prev_changed = True
            elif diff.has_changed:
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
            get_platform_register_size(self.snapshot1.arch) if override_word_size is None else override_word_size
        )

        extract_before = self.snapshot1.memory[start:end, file]
        extract_after = self.snapshot2.memory[start:end, file]

        file_info = f" (file: {file})" if file not in ("absolute", "hybrid") else ""

        print(f"Memory diff from {start:#x} to {end:#x}{file_info}:")

        # Resolve the address
        if file == "absolute":
            address_start = start
        elif file == "hybrid":
            try:
                # Try to resolve the address as absolute
                self.snapshot1.maps.filter(start)
                address_start = start
            except ValueError:
                # If the address is not in the maps, we use the binary file
                address_start = start + self.snapshot1.maps[0].base
        else:
            address_start = start + self.snapshot1.maps.filter(file)[0].base

        pprint_memory_diff_util(
            address_start,
            extract_before,
            extract_after,
            word_size,
            address_width=get_platform_register_size(self.snapshot1.arch),
            integer_mode=integer_mode,
        )

    def pprint_regs(self: Diff) -> None:
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
                    self.snapshot1.maps,
                    self.snapshot2.maps,
                    (attr1.old_value, attr2.old_value),
                    (attr1.new_value, attr2.new_value),
                )

    def pprint_registers(self: Diff) -> None:
        """Alias afor pprint_regs."""
        self.pprint_regs()
