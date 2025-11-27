#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Gabriele Digregorio, Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.snapshots.process.process_snapshot import ProcessSnapshot
    from libdebug.snapshots.snapshot import Snapshot


class SnapshotMixin:
    """Snapshot management helpers."""

    def create_snapshot(self: SnapshotMixin, level: str = "base", name: str | None = None) -> ProcessSnapshot:
        """Create a snapshot of the current process state.

        Snapshot levels:
        - base: Registers
        - writable: Registers, writable memory contents
        - full: Registers, all memory contents

        Args:
            level (str): The level of the snapshot.
            name (str, optional): The name of the snapshot. Defaults to None.

        Returns:
            ProcessSnapshot: The created snapshot.
        """
        return self._internal_debugger.create_snapshot(level, name)

    def load_snapshot(self: SnapshotMixin, file_path: str) -> Snapshot:
        """Load a snapshot of the thread / process state.

        Args:
            file_path (str): The path to the snapshot file.
        """
        return self._internal_debugger.load_snapshot(file_path)
