#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from libdebug.data.registers import Registers
from libdebug.debugger.internal_debugger_instance_manager import get_global_internal_debugger


class Amd64Registers(Registers):
    """This class holds the state of the architectural-dependent registers of a process."""

    def __init__(self: Amd64Registers, thread_id: int, generic_regs: list[str]) -> None:
        """Initializes the Registers object."""
        self._internal_debugger = get_global_internal_debugger()
        self._thread_id = thread_id
        self._generic_regs = generic_regs

    def __repr__(self: Amd64Registers) -> str:
        """Returns a string representation of the object."""
        return super().__repr__()
