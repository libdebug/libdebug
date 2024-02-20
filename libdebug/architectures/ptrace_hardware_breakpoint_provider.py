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
from libdebug.architectures.amd64.amd64_ptrace_hw_bp_helper import (
    Amd64PtraceHardwareBreakpointManager,
)
from typing import Callable
from libdebug.utils.libcontext import libcontext


def ptrace_hardware_breakpoint_manager_provider(
    peek_mem: Callable[[int], int] = None,
    poke_mem: Callable[[int, int], None] = None,
) -> PtraceHardwareBreakpointManager:
    """Returns an instance of the hardware breakpoint manager to be used by the `Debugger` class."""
    architecture = libcontext.arch

    match architecture:
        case "amd64":
            return Amd64PtraceHardwareBreakpointManager(peek_mem, poke_mem)
        case _:
            raise NotImplementedError(f"Architecture {architecture} not available.")
