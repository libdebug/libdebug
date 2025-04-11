#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations


class GdbMigrationSignal(BaseException):
    """
    The exception raised whenerever a GDB migration is requested in a callback.

    This class abuses the exception mechanic in Python to force a GDB migration
    from inside a callback at the specific line of code it is requested.
    """

    migrate_breakpoints: bool
    """Whether to migrate over the breakpoints set in libdebug to GDB."""

    open_in_new_process: bool
    """Whether to attempt to open GDB in a new process instead of the current one."""

    def __init__(self: GdbMigrationSignal, migrate_breakpoints: bool, open_in_new_process: bool) -> None:
        """Initializes a new GdbMigrationSignal with the given parameters."""
        self.migrate_breakpoints = migrate_breakpoints
        self.open_in_new_process = open_in_new_process
