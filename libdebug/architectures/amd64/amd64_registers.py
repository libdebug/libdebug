#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2024 Gabriele Digregorio. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from dataclasses import dataclass

from libdebug.data.registers import Registers
from libdebug.debugger.internal_debugger_instance_manager import get_global_internal_debugger

AMD64_REGS = [
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rdi",
    "rsi",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "rbp",
    "rsp",
    "rip",
]


@dataclass
class Amd64Registers(Registers):
    """This class holds the state of the architectural-dependent registers of a process."""

    def __init__(self: Amd64Registers, thread_id: int) -> None:
        """Initializes the Registers object."""
        self._internal_debugger = get_global_internal_debugger()
        self._thread_id = thread_id

    def __repr__(self: Amd64Registers) -> str:
        """Returns a string representation of the object."""
        repr_str = f"Amd64Registers(thread_id={self._thread_id})"

        attributes = [attr for attr in Amd64Registers.__dict__ if attr in AMD64_REGS or attr.startswith("zmm")]
        max_len = max(len(attr) for attr in attributes) + 1

        repr_str += "".join(f"\n\t{attr + ':':<{max_len}} {getattr(self, attr):#x}" for attr in attributes)

        return repr_str
