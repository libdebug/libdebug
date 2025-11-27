#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Gabriele Digregorio, Roberto Alessandro Bertolini, Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.data.gdb_resume_event import GdbResumeEvent


class GdbMixin:
    """Migration to and from GDB."""

    def gdb(
        self: GdbMixin,
        migrate_breakpoints: bool = True,
        open_in_new_process: bool = True,
        blocking: bool = True,
    ) -> GdbResumeEvent:
        """Migrates the current debugging session to GDB.

        Args:
            migrate_breakpoints (bool): Whether to migrate over the breakpoints set in libdebug to GDB.
            open_in_new_process (bool): Whether to attempt to open GDB in a new process instead of the current one.
            blocking (bool): Whether to block the script until GDB is closed.
        """
        return self._internal_debugger.gdb(migrate_breakpoints, open_in_new_process, blocking)

    @property
    def is_in_gdb(self: GdbMixin) -> bool:
        """Returns whether the process is in GDB."""
        return self._internal_debugger._is_migrated_to_gdb

    def wait_for_gdb(self: GdbMixin) -> None:
        """Waits for the GDB process to migrate back to libdebug."""
        self._internal_debugger.wait_for_gdb()
