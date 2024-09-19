#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Roberto Alessandro Bertolini, Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass

from libdebug.data.registers import Registers
from libdebug.debugger.internal_debugger_instance_manager import get_global_internal_debugger


@dataclass
class Aarch64Registers(Registers):
    """This class holds the state of the architectural-dependent registers of a process."""

    def __init__(self: Aarch64Registers, thread_id: int) -> None:
        """Initializes the Registers object."""
        self._internal_debugger = get_global_internal_debugger()
        self._thread_id = thread_id

    def __repr__(self: Aarch64Registers) -> str:
        """Returns a string representation of the object."""
        repr_str = f"Aarch64Registers(thread_id={self._thread_id})"

        attributes = [attr for attr in Aarch64Registers.__dict__ if not attr.startswith("_")]
        max_len = max(len(attr) for attr in attributes) + 1

        repr_str += "".join(f"\n\t{attr + ':':<{max_len}} {getattr(self, attr):#010x}" for attr in attributes)

        return repr_str
