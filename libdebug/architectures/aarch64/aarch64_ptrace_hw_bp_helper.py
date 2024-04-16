#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2024 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from typing import Callable

from libdebug.architectures.ptrace_hardware_breakpoint_manager import (
    PtraceHardwareBreakpointManager,
)
from libdebug.data.breakpoint import Breakpoint
from libdebug.liblog import liblog
from libdebug.state.thread_context import ThreadContext

AARCH64_DBREGS_OFF = {}

AARCH64_VALID_SIZES = {1, 2, 4, 8}
AARCH64_DBGREGS_COUNT = 16
AARCH64_COND_VAL = {"x": 0, "r": 1, "w": 2, "rw": 3}

# Internally, we check the address & 0x1000 to determine if it's a watchpoint.
# Then we query either the DBG or WVR register.
for i in range(AARCH64_DBGREGS_COUNT):
    AARCH64_DBREGS_OFF[f"DBG{i}"] = 0x8 + i * 16
    AARCH64_DBREGS_OFF[f"WVR{i}"] = 0x1000 + 0x8 + i * 16


class Aarch64HardwareBreakpointManager(PtraceHardwareBreakpointManager):
    """A hardware breakpoint manager for the aarch64 architecture.

    Attributes:
        thread (ThreadContext): The target thread.
        peek_user (callable): A function that reads a number of bytes from the target thread registers.
        poke_user (callable): A function that writes a number of bytes to the target thread registers.
        breakpoint_count (int): The number of hardware breakpoints set.
        watchpoint_count (int): The number of hardware watchpoints set.
    """

    def __init__(
        self,
        thread: ThreadContext,
        peek_user: Callable[[int, int], int],
        poke_user: Callable[[int, int, int], None],
    ):
        super().__init__(thread, peek_user, poke_user)

        self.breakpoint_registers: dict[str, Breakpoint | None] = {}
        self.watchpoint_registers: dict[str, Breakpoint | None] = {}

        for i in range(AARCH64_DBGREGS_COUNT):
            self.breakpoint_registers[f"DBG{i}"] = None
            self.watchpoint_registers[f"WVR{i}"] = None

        self.watchpoint_count = 0

    def install_breakpoint(self, bp: Breakpoint):
        """Installs a hardware breakpoint at the provided location."""
        if self.breakpoint_count >= AARCH64_DBGREGS_COUNT:
            liblog.error(
                f"Cannot set more than {AARCH64_DBGREGS_COUNT} hardware breakpoints."
            )
            return

        if bp.length not in AARCH64_VALID_SIZES:
            raise ValueError(f"Invalid breakpoint length: {bp.length}.")

        if bp.address % 4 != 0:
            raise ValueError("Breakpoint address must be 4-byte aligned.")

        if bp.condition == "x":
            register = next(
                reg for reg, bp in self.breakpoint_registers.items() if bp is None
            )
            self.breakpoint_count += 1
        else:
            register = next(
                reg for reg, bp in self.watchpoint_registers.items() if bp is None
            )
            self.watchpoint_count += 1

        # https://android.googlesource.com/platform/bionic/+/master/tests/sys_ptrace_test.cpp
        # https://android.googlesource.com/toolchain/gdb/+/fb3e0dcd57c379215f4c7d1c036bd497f1dccb4b/gdb-7.11/gdb/nat/aarch64-linux-hw-point.c
        length = (1 << bp.length) - 1
        enable = 1
        condition = AARCH64_COND_VAL[bp.condition]
        control = length << 5 | condition << 3 | enable

        self.poke_user(
            self.thread.thread_id, AARCH64_DBREGS_OFF[register] + 0, bp.address
        )
        self.poke_user(self.thread.thread_id, AARCH64_DBREGS_OFF[register] + 8, control)

        self.breakpoint_registers[register] = bp

        liblog.debugger(f"Installed hardware breakpoint on register {register}.")

    def remove_breakpoint(self, bp: Breakpoint):
        """Removes a hardware breakpoint at the provided location."""
        register = next(reg for reg, b in self.breakpoint_registers.items() if b == bp)

        if register is None:
            liblog.error("Breakpoint not found.")
            return

        if bp.condition == "x":
            self.breakpoint_count -= 1
        else:
            self.watchpoint_count -= 1

        self.poke_user(self.thread.thread_id, AARCH64_DBREGS_OFF[register] + 0, 0)
        self.poke_user(self.thread.thread_id, AARCH64_DBREGS_OFF[register] + 8, 0)

        self.breakpoint_registers[register] = None

        liblog.debugger(f"Removed hardware breakpoint on register {register}.")

    def available_breakpoints(self) -> int:
        return AARCH64_DBGREGS_COUNT - self.breakpoint_count
