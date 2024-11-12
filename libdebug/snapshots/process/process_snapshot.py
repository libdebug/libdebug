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
from libdebug.snapshots.process.process_shapshot_diff import ProcessSnapshotDiff
from libdebug.snapshots.registers.snapshot_registers import SnapshotRegisters
from libdebug.snapshots.snapshot import Snapshot
from libdebug.snapshots.thread.lw_thread_snapshot import LightweightThreadSnapshot

if TYPE_CHECKING:
    from libdebug.debugger.internal_debugger import InternalDebugger
    from libdebug.snapshots.diff import Diff


class ProcessSnapshot(Snapshot):
    """This object represents a snapshot of the target process. It holds information about the process's state.

    Snapshot levels:
    - base: Registers
    - writable: Registers, writable memory contents
    - full: Registers, stack, all readable memory contents
    """

    def __init__(
        self: ProcessSnapshot, debugger: InternalDebugger, level: str = "base", name: str | None = None
    ) -> None:
        """Creates a new snapshot object for the given process.

        Args:
            debugger (Debugger): The thread to take a snapshot of.
            level (str, optional): The level of the snapshot. Defaults to "base".
            name (str, optional): A name associated to the snapshot. Defaults to None.
        """
        # Set id of the snapshot and increment the counter
        self.snapshot_id = debugger._snapshot_count
        debugger._snapshot_count += 1

        # Basic snapshot info
        self.process_id = debugger.process_id
        self.pid = self.process_id
        self.name = name
        self.level = level
        self.arch = debugger.arch
        self._process_full_path = debugger._process_full_path
        self._process_name = debugger._process_name

        # Memory maps
        match level:
            case "base":
                map_list = debugger.maps.as_list()
                self.maps = MemoryMapSnapshotList(map_list, self._process_name, self._process_full_path)

                self._memory = None
            case "writable":
                if not debugger.fast_memory:
                    liblog.warning(
                        "Memory snapshot requested but fast memory is not enabled. This will take a long time.",
                    )

                # Save all memory pages
                self._save_memory_maps(debugger, writable_only=True)

                self._memory = SnapshotMemoryView(self, debugger.symbols)
            case "full":
                if not debugger.fast_memory:
                    liblog.warning(
                        "Memory snapshot requested but fast memory is not enabled. This will take a long time.",
                    )

                # Save all memory pages
                self._save_memory_maps(debugger, writable_only=False)

                self._memory = SnapshotMemoryView(self, debugger.symbols)
            case _:
                raise ValueError(f"Invalid snapshot level {level}")

        # Snapshot the threads
        self._save_threads(debugger)

        # Log the creation of the snapshot
        named_addition = " named " + self.name if name is not None else ""
        liblog.debugger(
            f"Created snapshot {self.snapshot_id} of level {self.level} for process {self.pid}{named_addition}"
        )

    def _save_threads(self: ProcessSnapshot, debugger: InternalDebugger) -> None:
        self.threads = []

        for thread in debugger.threads:
            # Create a lightweight snapshot for the thread
            lw_snapshot = LightweightThreadSnapshot(thread, self)

            self.threads.append(lw_snapshot)

    @property
    def regs(self: ProcessSnapshot) -> SnapshotRegisters:
        """Returns the registers of the process snapshot."""
        return self.threads[0].regs

    def diff(self: ProcessSnapshot, other: ProcessSnapshot) -> Diff:
        """Returns the diff between two process snapshots."""
        if not isinstance(other, ProcessSnapshot):
            raise TypeError("Both arguments must be ProcessSnapshot objects.")

        return ProcessSnapshotDiff(self, other)

    def save(self: ProcessSnapshot, file_path: str) -> None:
        """Saves the snapshot object to a file."""
        all_reg_names = dir(self.regs)
        all_reg_names = [
            reg_name for reg_name in all_reg_names if isinstance(getattr(self.regs, reg_name), int | float)
        ]

        thread_snapshots = []

        for thread in self.threads:
            thread_dict = {
                "snapshot_id": thread.snapshot_id,
                "thread_id": thread.thread_id,
                "regs": {reg_name: getattr(thread.regs, reg_name) for reg_name in all_reg_names},
            }

            thread_snapshots.append(thread_dict)

        serializable_dict = {
            "type": "process",
            "arch": self.arch,
            "snapshot_id": self.snapshot_id,
            "process_id": self.process_id,
            "level": self.level,
            "name": self.name,
            "architectural_registers": {
                "generic": self.regs._generic_regs,
                "special": self.regs._special_regs,
                "vector_fp": self.regs._vec_fp_regs,
            },
            "threads": thread_snapshots,
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

        with Path(file_path).open("w") as file:
            json.dump(serializable_dict, file)

    @staticmethod
    def load(snapshot_dict: object) -> ProcessSnapshot:
        """Loads a snapshot object from a file."""
        loaded_snap = ProcessSnapshot.__new__(ProcessSnapshot)

        loaded_snap.snapshot_id = snapshot_dict["snapshot_id"]

        # Basic snapshot info
        loaded_snap.arch = snapshot_dict["arch"]
        loaded_snap.process_id = snapshot_dict["process_id"]
        loaded_snap.pid = loaded_snap.process_id
        loaded_snap.name = snapshot_dict["name"]
        loaded_snap.level = snapshot_dict["level"]
        loaded_snap._process_full_path = snapshot_dict["_process_full_path"]
        loaded_snap._process_name = snapshot_dict["_process_name"]

        # Get thread registers
        loaded_snap.threads = []

        for thread_dict in snapshot_dict["threads"]:
            thread_snap = LightweightThreadSnapshot.__new__(LightweightThreadSnapshot)
            thread_snap.snapshot_id = thread_dict["snapshot_id"]
            thread_snap.thread_id = thread_dict["thread_id"]
            thread_snap.tid = thread_snap.thread_id
            thread_snap._proc_snapshot = loaded_snap

            # Create a register field for the snapshot
            thread_snap.regs = SnapshotRegisters(
                thread_snap.thread_id,
                snapshot_dict["architectural_registers"]["generic"],
                snapshot_dict["architectural_registers"]["special"],
                snapshot_dict["architectural_registers"]["vector_fp"],
            )

            # Get thread registers
            for reg_name, reg_value in thread_dict["regs"].items():
                thread_snap.regs.__setattr__(reg_name, reg_value)

            loaded_snap.threads.append(thread_snap)

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

        # Memory view
        loaded_snap._memory = (
            SnapshotMemoryView(loaded_snap, snapshot_dict["symbols"]) if loaded_snap.level != "base" else None
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
