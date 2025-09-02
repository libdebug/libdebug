#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024-2025 Gabriele Digregorio, Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from libdebug.debugger.internal_debugger import InternalDebugger


class Registers:
    """Abtract class that holds the state of the architectural-dependent registers of a process."""

    def __init__(
        self: Registers,
        thread_id: int,
        generic_regs: list[str],
        internal_debugger: InternalDebugger,
    ) -> None:
        """Initializes the Registers object."""
        self._internal_debugger = internal_debugger
        self._thread_id = thread_id
        self._generic_regs = generic_regs

    def __repr__(self: Registers) -> str:
        """Returns a string representation of the object."""
        repr_str = f"Registers(thread_id={self._thread_id})"

        attributes = self._generic_regs
        max_len = max(len(attr) for attr in attributes) + 1

        repr_str += "".join(f"\n  {attr + ':':<{max_len}} {getattr(self, attr):#x}" for attr in attributes)

        return repr_str

    def filter(self: Registers, value: float) -> list[str]:
        """Filters the registers by value.

        Args:
            value (float): The value to search for.

        Returns:
            list[str]: A list of names of the registers containing the value.
        """
        attributes = self.__class__.__dict__
        return [attr for attr in attributes if getattr(self, attr) == value]
