#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Francesco Panebianco. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from libdebug.data.registers import Registers


class SnapshotRegisters(Registers):
    """Class that holds the state of the architectural-dependent registers of a snapshot."""

    def __init__(self: SnapshotRegisters, thread_id: int, generic_regs: list[str], special_regs: list[str], vec_fp_regs: list[str]) -> None:
        """Initializes the Registers object.

        Args:
            thread_id (int): The thread ID.
            generic_regs (list[str]): The list of registers to include in the repr.
            special_regs (list[str]): The list of special registers to include in the repr.
            vec_fp_regs (list[str]): The list of vector and floating point registers to include in the repr
        """
        self._thread_id = thread_id
        self._generic_regs = generic_regs
        self._special_regs = special_regs
        self._vec_fp_regs = vec_fp_regs
