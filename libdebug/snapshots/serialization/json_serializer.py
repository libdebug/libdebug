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

from libdebug.data.symbol import Symbol
from libdebug.data.symbol_list import SymbolList
from libdebug.snapshots.memory.memory_map_snapshot import SnapshotMemoryMap
from libdebug.snapshots.memory.memory_map_snapshot_list import MemoryMapSnapshotList
from libdebug.snapshots.memory.snapshot_memory_view import SnapshotMemoryView
from libdebug.snapshots.process.process_snapshot import ProcessSnapshot
from libdebug.snapshots.registers.snapshot_registers import SnapshotRegisters
from libdebug.snapshots.thread.lw_thread_snapshot import LightweightThreadSnapshot
from libdebug.snapshots.thread.thread_snapshot import ThreadSnapshot

if TYPE_CHECKING:
    from libdebug.snapshots.snapshot import Snapshot


class JSONSerializer:
    """Helper class to serialize and deserialize snapshots using JSON format."""

    def load(self: JSONSerializer, file_path: str) -> Snapshot:
        """Load a snapshot from a JSON file.

        Args:
            file_path (str): The path to the JSON file containing the snapshot.

        Returns:
            Snapshot: The loaded snapshot object.
        """
        with Path(file_path).open() as file:
            snapshot_dict = json.load(file)

        # Determine the type of snapshot
        is_process_snapshot = "process_id" in snapshot_dict

        # Create a new instance of the appropriate class
        if is_process_snapshot:
            loaded_snap = ProcessSnapshot.__new__(ProcessSnapshot)
            loaded_snap.process_id = snapshot_dict["process_id"]
            loaded_snap.pid = loaded_snap.process_id
        else:
            loaded_snap = ThreadSnapshot.__new__(ThreadSnapshot)
            loaded_snap.thread_id = snapshot_dict["thread_id"]
            loaded_snap.tid = loaded_snap.thread_id

        # Basic snapshot info
        loaded_snap.snapshot_id = snapshot_dict["snapshot_id"]
        loaded_snap.arch = snapshot_dict["arch"]
        loaded_snap.name = snapshot_dict["name"]
        loaded_snap.level = snapshot_dict["level"]
        loaded_snap._process_full_path = snapshot_dict.get("_process_full_path", None)
        loaded_snap._process_name = snapshot_dict.get("_process_name", None)

        # Create a register field for the snapshot
        if not is_process_snapshot:
            loaded_snap.regs = SnapshotRegisters(
                getattr(loaded_snap, "thread_id", None),
                snapshot_dict["architectural_registers"]["generic"],
                snapshot_dict["architectural_registers"]["special"],
                snapshot_dict["architectural_registers"]["vector_fp"],
            )

            # Load registers
            for reg_name, reg_value in snapshot_dict["regs"].items():
                loaded_snap.regs.__setattr__(reg_name, reg_value)

        # Recreate memory maps
        loaded_maps = snapshot_dict["maps"]
        raw_map_list = []

        for saved_map in loaded_maps:
            new_map = SnapshotMemoryMap(
                saved_map["start"],
                saved_map["end"],
                saved_map["permissions"],
                saved_map["size"],
                saved_map["offset"],
                saved_map["backing_file"],
                b64decode(saved_map["content"]) if saved_map["content"] is not None else None,
            )
            raw_map_list.append(new_map)

        loaded_snap.maps = MemoryMapSnapshotList(
            raw_map_list,
            loaded_snap._process_name,
            loaded_snap._process_full_path,
        )

        # Handle threads for ProcessSnapshot
        if is_process_snapshot:
            loaded_snap.threads = []
            for thread_dict in snapshot_dict["threads"]:
                thread_snap = LightweightThreadSnapshot.__new__(LightweightThreadSnapshot)
                thread_snap.snapshot_id = thread_dict["snapshot_id"]
                thread_snap.thread_id = thread_dict["thread_id"]
                thread_snap.tid = thread_snap.thread_id
                thread_snap._proc_snapshot = loaded_snap

                thread_snap.regs = SnapshotRegisters(
                    thread_snap.thread_id,
                    snapshot_dict["architectural_registers"]["generic"],
                    snapshot_dict["architectural_registers"]["special"],
                    snapshot_dict["architectural_registers"]["vector_fp"],
                )

                for reg_name, reg_value in thread_dict["regs"].items():
                    thread_snap.regs.__setattr__(reg_name, reg_value)

                loaded_snap.threads.append(thread_snap)

        # Handle symbols
        raw_loaded_symbols = snapshot_dict.get("symbols", None)
        if raw_loaded_symbols is not None:
            sym_list = [
                Symbol(
                    saved_symbol["start"],
                    saved_symbol["end"],
                    saved_symbol["name"],
                    saved_symbol["backing_file"],
                )
                for saved_symbol in raw_loaded_symbols
            ]
            sym_list = SymbolList(sym_list, loaded_snap)
            loaded_snap._memory = SnapshotMemoryView(loaded_snap, sym_list)
        elif loaded_snap.level != "base":
            raise ValueError("Memory snapshot loading requested but no symbols were saved.")
        else:
            loaded_snap._memory = None

        return loaded_snap

    def dump(self: JSONSerializer, snapshot: Snapshot, out_path: str) -> None:
        """Dump a snapshot to a JSON file.

        Args:
            snapshot (Snapshot): The snapshot to be dumped.
            out_path (str): The path to the output JSON file.
        """

        def get_register_names(regs: SnapshotRegisters) -> list[str]:
            return [reg_name for reg_name in dir(regs) if isinstance(getattr(regs, reg_name), int | float)]

        def save_memory_maps(maps: MemoryMapSnapshotList) -> list[dict]:
            return [
                {
                    "start": memory_map.start,
                    "end": memory_map.end,
                    "permissions": memory_map.permissions,
                    "size": memory_map.size,
                    "offset": memory_map.offset,
                    "backing_file": memory_map.backing_file,
                    "content": b64encode(memory_map.content).decode("utf-8")
                    if memory_map.content is not None
                    else None,
                }
                for memory_map in maps
            ]

        def save_symbols(memory: SnapshotMemoryView) -> list[dict] | None:
            if memory is None:
                return None
            return [
                {
                    "start": symbol.start,
                    "end": symbol.end,
                    "name": symbol.name,
                    "backing_file": symbol.backing_file,
                }
                for symbol in memory._symbol_ref
            ]

        all_reg_names = get_register_names(snapshot.regs)

        serializable_dict = {
            "type": "process" if hasattr(snapshot, "threads") else "thread",
            "arch": snapshot.arch,
            "snapshot_id": snapshot.snapshot_id,
            "level": snapshot.level,
            "name": snapshot.name,
            "architectural_registers": {
                "generic": snapshot.regs._generic_regs,
                "special": snapshot.regs._special_regs,
                "vector_fp": snapshot.regs._vec_fp_regs,
            },
            "maps": save_memory_maps(snapshot.maps),
            "symbols": save_symbols(snapshot._memory),
        }

        if hasattr(snapshot, "threads"):
            # ProcessSnapshot-specific data
            thread_snapshots = [
                {
                    "snapshot_id": thread.snapshot_id,
                    "thread_id": thread.thread_id,
                    "regs": {reg_name: getattr(thread.regs, reg_name) for reg_name in all_reg_names},
                }
                for thread in snapshot.threads
            ]
            serializable_dict.update(
                {
                    "process_id": snapshot.process_id,
                    "threads": thread_snapshots,
                    "_process_full_path": snapshot._process_full_path,
                    "_process_name": snapshot._process_name,
                }
            )
        else:
            # ThreadSnapshot-specific data
            serializable_dict.update(
                {
                    "thread_id": snapshot.thread_id,
                    "regs": {reg_name: getattr(snapshot.regs, reg_name) for reg_name in all_reg_names},
                    "_process_full_path": snapshot._process_full_path,
                    "_process_name": snapshot._process_name,
                }
            )

        with Path(out_path).open("w") as file:
            json.dump(serializable_dict, file)
