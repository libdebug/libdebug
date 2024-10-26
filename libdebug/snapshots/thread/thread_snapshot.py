#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#
from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

from libdebug.liblog import liblog
from libdebug.snapshots.memory.memory_map_snapshot_list import MemoryMapSnapshotList
from libdebug.snapshots.memory.snapshot_memory_view import SnapshotMemoryView
from libdebug.snapshots.snapshot import Snapshot

if TYPE_CHECKING:
    from libdebug.snapshots.diff import Diff
    from libdebug.state.thread_context import ThreadContext


class ThreadSnapshot(Snapshot):
    """This object represents a snapshot of the target thread. It holds information about a thread's state.

    Snapshot levels:
    - base: Registers
    - writable: Registers, writable memory
    - full: Registers, memory
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

                # Save all memory pages
                self._save_memory_maps(thread.debugger, writable_only=True)

                self._memory = SnapshotMemoryView(self, thread.debugger.symbols)
            case "full":
                if not thread.debugger.fast_memory:
                    liblog.warning(
                        "Memory snapshot requested but fast memory is not enabled. This will take a long time.",
                    )

                # Save all memory pages
                self._save_memory_maps(thread.debugger, writable_only=False)

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
        from libdebug.snapshots.thread.thread_snapshot_diff import ThreadSnapshotDiff

        return ThreadSnapshotDiff(self, other)


    def save(self: ThreadSnapshot, file_path: str) -> None:
        """Saves the snapshot object to a file."""
        all_reg_names = dir(self.regs)
        all_reg_names = [reg_name for reg_name in all_reg_names if isinstance(getattr(self.regs, reg_name), int | float)]

        serializable_dict = {
            "type": "thread",
            "snapshot_id": self.snapshot_id,
            "thread_id": self.thread_id,
            "level": self.level,
            "name": self.name,
            "regs": {reg_name: getattr(self.regs, reg_name) for reg_name in all_reg_names},
            "maps": self.maps,
            "symbols": self._memory.symbols if self._memory is not None else None,
            "_process_full_path": self._process_full_path,
            "_process_name": self._process_name,
        }

        with Path(file_path).open("w") as file:
            json.dump(serializable_dict, file)

    @staticmethod
    def load(snapshot_dict: object) -> ThreadSnapshot:
        """Loads a snapshot object from a serialized object."""
        loaded_snap = ThreadSnapshot.__new__(ThreadSnapshot)

        loaded_snap.snapshot_id = snapshot_dict["snapshot_id"]

        # Basic snapshot info
        loaded_snap.thread_id = snapshot_dict["thread_id"]
        loaded_snap.tid = loaded_snap.thread_id
        loaded_snap.name = snapshot_dict["name"]
        loaded_snap.level = snapshot_dict["level"]
        loaded_snap._process_full_path = snapshot_dict["_process_full_path"]
        loaded_snap._process_name = snapshot_dict["_process_name"]

        # Get thread registers
        for reg_name, reg_value in snapshot_dict["regs"].items():
            setattr(loaded_snap.regs, reg_name, reg_value)

        # Memory maps
        loaded_snap.maps = MemoryMapSnapshotList(
            snapshot_dict["maps"],
            loaded_snap._process_name,
            loaded_snap._process_full_path,
        )

        # Memory view
        loaded_snap._memory = SnapshotMemoryView(loaded_snap, snapshot_dict["symbols"]) if snapshot_dict["symbols"] is not None else None

        return loaded_snap
