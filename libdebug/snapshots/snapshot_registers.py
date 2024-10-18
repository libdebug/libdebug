#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebiacno. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from libdebug.data.registers import Registers


class SnapshotRegisters(Registers):
    """Abtract class that holds the state of the architectural-dependent registers of a process."""

    def __init__(self: SnapshotRegisters, thread_id: int, generic_regs: list[str]) -> None:
        """Initializes the Registers object.

        Args:
            thread_id (int): The thread ID.
            generic_regs (list[str]): The list of registers to include in the repr.
        """
        self._thread_id = thread_id
        self._generic_regs = generic_regs
