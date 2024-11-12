#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#
from __future__ import annotations

import json
from base64 import b64decode, b64encode
from pathlib import Path
from typing import TYPE_CHECKING

from libdebug.data.memory_map import MemoryMap
from libdebug.data.symbol import Symbol
from libdebug.data.symbol_list import SymbolList
from libdebug.liblog import liblog
from libdebug.snapshots.memory.memory_map_snapshot_list import MemoryMapSnapshotList
from libdebug.snapshots.memory.snapshot_memory_view import SnapshotMemoryView
from libdebug.snapshots.registers.snapshot_registers import SnapshotRegisters
from libdebug.snapshots.snapshot import Snapshot
from libdebug.snapshots.thread.thread_snapshot_diff import ThreadSnapshotDiff

if TYPE_CHECKING:
    from libdebug.snapshots.diff import Diff
    from libdebug.state.thread_context import ThreadContext


class ThreadSnapshot(Snapshot):
    """This object represents a snapshot of the target thread. It holds information about a thread's state.

    Snapshot levels:
    - base: Registers
    - writable: Registers, writable memory contents
    - full: Registers, all readable memory contents
    """

    def __init__(self: ThreadSnapshot, thread: ThreadContext, level: str = "base", name: str | None = None) -> None:
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
        self.arch = thread._internal_debugger.arch
        self._process_full_path = thread.debugger._internal_debugger._process_full_path
        self._process_name = thread.debugger._internal_debugger._process_name

        # Get thread registers
        self._save_regs(thread)

        # Memory maps
        match level:
            case "base":
                map_list = thread.debugger.maps.as_list()
                self.maps = MemoryMapSnapshotList(map_list, self._process_name, self._process_full_path)

                self._memory = None
            case "writable":
                if not thread.debugger.fast_memory:
                    liblog.warning(
                        "Memory snapshot requested but fast memory is not enabled. This will take a long time.",
                    )

                # Save all writable memory pages
                self._save_memory_maps(thread.debugger._internal_debugger, writable_only=True)

                self._memory = SnapshotMemoryView(self, thread.debugger.symbols)
            case "full":
                if not thread.debugger.fast_memory:
                    liblog.warning(
                        "Memory snapshot requested but fast memory is not enabled. This will take a long time.",
                    )

                # Save all memory pages
                self._save_memory_maps(thread._internal_debugger, writable_only=False)

                self._memory = SnapshotMemoryView(self, thread.debugger.symbols)
            case _:
                raise ValueError(f"Invalid snapshot level {level}")

        # Log the creation of the snapshot
        named_addition = " named " + self.name if name is not None else ""
        liblog.debugger(
            f"Created snapshot {self.snapshot_id} of level {self.level} for thread {self.tid}{named_addition}",
        )

    def diff(self: ThreadSnapshot, other: ThreadSnapshot) -> Diff:
        """Creates a diff object between two snapshots."""
        if not isinstance(other, ThreadSnapshot):
            raise TypeError("Both arguments must be ThreadSnapshot objects.")

        return ThreadSnapshotDiff(self, other)

    def save(self: ThreadSnapshot, file_path: str) -> None:
        """Saves the snapshot object to a file."""
        all_reg_names = dir(self.regs)
        all_reg_names = [
            reg_name for reg_name in all_reg_names if isinstance(getattr(self.regs, reg_name), int | float)
        ]

        serializable_dict = {
            "type": "thread",
            "arch": self.arch,
            "snapshot_id": self.snapshot_id,
            "thread_id": self.thread_id,
            "level": self.level,
            "name": self.name,
            "regs": {reg_name: getattr(self.regs, reg_name) for reg_name in all_reg_names},
            "architectural_registers": {
                "generic": self.regs._generic_regs,
                "special": self.regs._special_regs,
                "vector_fp": self.regs._vec_fp_regs,
            },
            "_process_full_path": self._process_full_path,
            "_process_name": self._process_name,
        }

        # Save memory maps
        saved_maps = []

        for memory_map in self.maps:
            saved_map = {
                "start": memory_map.start,
                "end": memory_map.end,
                "permissions": memory_map.permissions,
                "size": memory_map.size,
                "offset": memory_map.offset,
                "backing_file": memory_map.backing_file,
                "content": b64encode(memory_map.content).decode("utf-8") if memory_map.content is not None else None,
            }
            saved_maps.append(saved_map)

        serializable_dict["maps"] = saved_maps

        # Symbols
        saved_symbols = None if self._memory is None else []

        if saved_symbols is not None:
            for symbol in self._memory._symbol_ref:
                saved_symbol = {
                    "start": symbol.start,
                    "end": symbol.end,
                    "name": symbol.name,
                    "backing_file": symbol.backing_file,
                }
                saved_symbols.append(saved_symbol)

        serializable_dict["symbols"] = saved_symbols

        # Save the snapshot to a file
        with Path(file_path).open("w") as file:
            json.dump(serializable_dict, file)

    @staticmethod
    def load(snapshot_dict: object) -> ThreadSnapshot:
        """Loads a snapshot object from a serialized object."""
        loaded_snap = ThreadSnapshot.__new__(ThreadSnapshot)

        loaded_snap.snapshot_id = snapshot_dict["snapshot_id"]

        # Basic snapshot info
        loaded_snap.arch = snapshot_dict["arch"]
        loaded_snap.thread_id = snapshot_dict["thread_id"]
        loaded_snap.tid = loaded_snap.thread_id
        loaded_snap.name = snapshot_dict["name"]
        loaded_snap.level = snapshot_dict["level"]
        loaded_snap._process_full_path = snapshot_dict["_process_full_path"]
        loaded_snap._process_name = snapshot_dict["_process_name"]

        # Create a register field for the snapshot
        loaded_snap.regs = SnapshotRegisters(
            loaded_snap.thread_id,
            snapshot_dict["architectural_registers"]["generic"],
            snapshot_dict["architectural_registers"]["special"],
            snapshot_dict["architectural_registers"]["vector_fp"],
        )

        # Get thread registers
        for reg_name, reg_value in snapshot_dict["regs"].items():
            loaded_snap.regs.__setattr__(reg_name, reg_value)

        # Recreate memory maps
        loaded_maps = snapshot_dict["maps"]

        raw_map_list = []

        for saved_map in loaded_maps:
            new_map = MemoryMap(
                saved_map["start"],
                saved_map["end"],
                saved_map["permissions"],
                saved_map["size"],
                saved_map["offset"],
                saved_map["backing_file"],
                b64decode(saved_map["content"]) if saved_map["content"] is not None else None,
            )

            raw_map_list.append(new_map)

        # Recreate the list
        loaded_snap.maps = MemoryMapSnapshotList(
            raw_map_list,
            loaded_snap._process_name,
            loaded_snap._process_full_path,
        )

        # Recreate the symbol list
        raw_loaded_symbols = snapshot_dict["symbols"]

        if raw_loaded_symbols is not None:
            sym_list = []

            for saved_symbol in raw_loaded_symbols:
                new_symbol = Symbol(
                    saved_symbol["start"],
                    saved_symbol["end"],
                    saved_symbol["name"],
                    saved_symbol["backing_file"],
                )

                sym_list.append(new_symbol)

            sym_list = SymbolList(sym_list, loaded_snap)
            loaded_snap._memory = SnapshotMemoryView(loaded_snap, sym_list)
        elif loaded_snap.level != "base":
            raise ValueError("Memory snapshot loading requested but no symbols were saved.")
        else:
            loaded_snap._memory = None

        return loaded_snap
