#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 Roberto Alessandro Bertolini.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
#

from libdebug.architectures.ptrace_hardware_breakpoint_manager import (
    PtraceHardwareBreakpointManager,
)
from libdebug.data.breakpoint import Breakpoint
from libdebug.liblog import liblog


AMD64_DBGREGS_OFF = {
    "DR0": 0x350,
    "DR1": 0x358,
    "DR2": 0x360,
    "DR3": 0x368,
    "DR4": 0x370,
    "DR5": 0x378,
    "DR6": 0x380,
    "DR7": 0x388,
}
AMD64_DBGREGS_CTRL_LOCAL = {"DR0": 1 << 0, "DR1": 1 << 2, "DR2": 1 << 4, "DR3": 1 << 6}
AMD64_DBGREGS_CTRL_COND = {"DR0": 16, "DR1": 20, "DR2": 24, "DR3": 28}
AMD64_DBGREGS_CTRL_COND_VAL = {"X": 0, "W": 1, "RW": 3}
AMD64_DBGREGS_CTRL_LEN = {"DR0": 18, "DR1": 22, "DR2": 26, "DR3": 30}
AMD64_DBGREGS_CTRL_LEN_VAL = {1: 0, 2: 1, 8: 2, 4: 3}

AMD64_DBREGS_COUNT = 4


class Amd64PtraceHardwareBreakpointManager(PtraceHardwareBreakpointManager):
    """A hardware breakpoint manager for the amd64 architecture.

    Attributes:
        peek_mem (callable): A function that reads a number of bytes from the target process memory.
        poke_mem (callable): A function that writes a number of bytes to the target process memory.
        breakpoint_count (int): The number of hardware breakpoints set.
    """

    def __init__(self, peek_mem, poke_mem):
        super().__init__(peek_mem, poke_mem)
        self.breakpoint_registers = {
            "DR0": None,
            "DR1": None,
            "DR2": None,
            "DR3": None,
        }

    def install_breakpoint(self, bp: Breakpoint):
        """Installs a hardware breakpoint at the provided location."""
        if self.breakpoint_count >= AMD64_DBREGS_COUNT:
            raise RuntimeError("No more hardware breakpoints available.")

        # Find the first available breakpoint register
        register = next(
            reg for reg, bp in self.breakpoint_registers.items() if bp is None
        )
        liblog.debugger(f"Installing hardware breakpoint on register {register}.")

        # Write the breakpoint address in the register
        self.poke_mem(AMD64_DBGREGS_OFF[register], bp.address)

        # Set the breakpoint control register
        ctrl = (
            AMD64_DBGREGS_CTRL_LOCAL[register]
            | (
                AMD64_DBGREGS_CTRL_COND_VAL[bp.condition]
                << AMD64_DBGREGS_CTRL_COND[register]
            )
            | (
                AMD64_DBGREGS_CTRL_LEN_VAL[bp.length]
                << AMD64_DBGREGS_CTRL_LEN[register]
            )
        )

        # Read the current value of the register
        current_ctrl = self.peek_mem(AMD64_DBGREGS_OFF["DR7"])

        # Clear condition and length fields for the current register
        current_ctrl &= ~(0x3 << AMD64_DBGREGS_CTRL_COND[register])
        current_ctrl &= ~(0x3 << AMD64_DBGREGS_CTRL_LEN[register])

        # Set the new value of the register
        current_ctrl |= ctrl

        # Write the new value of the register
        self.poke_mem(AMD64_DBGREGS_OFF["DR7"], current_ctrl)

        # Save the breakpoint
        self.breakpoint_registers[register] = bp

        liblog.debugger(f"Hardware breakpoint installed on register {register}.")

        self.breakpoint_count += 1

    def remove_breakpoint(self, bp: Breakpoint):
        """Removes a hardware breakpoint at the provided location."""
        if self.breakpoint_count <= 0:
            raise RuntimeError("No more hardware breakpoints to remove.")

        # Find the breakpoint register
        register = next(
            reg for reg, bp_ in self.breakpoint_registers.items() if bp_ == bp
        )

        if register is None:
            raise RuntimeError("Hardware breakpoint not found.")

        liblog.debugger(f"Removing hardware breakpoint on register {register}.")

        # Clear the breakpoint address in the register
        self.poke_mem(AMD64_DBGREGS_OFF[register], 0)

        # Read the current value of the control register
        current_ctrl = self.peek_mem(AMD64_DBGREGS_OFF["DR7"])

        # Clear the breakpoint control register
        current_ctrl &= ~AMD64_DBGREGS_CTRL_LOCAL[register]

        # Write the new value of the register
        self.poke_mem(AMD64_DBGREGS_OFF["DR7"], current_ctrl)

        # Remove the breakpoint
        self.breakpoint_registers[register] = None

        liblog.debugger(f"Hardware breakpoint removed from register {register}.")

        self.breakpoint_count -= 1

    def available_breakpoints(self) -> int:
        """Returns the number of available hardware breakpoint registers."""
        return AMD64_DBREGS_COUNT - self.breakpoint_count
