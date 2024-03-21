#
# This file is part of libdebug Python library (https://github.com/io-no/libdebug).
# Copyright (c) 2023 - 2024 Roberto Alessandro Bertolini.
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

from typing import Callable

from libdebug.architectures.amd64.amd64_ptrace_hw_bp_helper import (
    Amd64PtraceHardwareBreakpointManager,
)
from libdebug.architectures.ptrace_hardware_breakpoint_manager import (
    PtraceHardwareBreakpointManager,
)
from libdebug.state.thread_context import ThreadContext
from libdebug.utils.libcontext import libcontext


def ptrace_hardware_breakpoint_manager_provider(
    thread: ThreadContext,
    peek_user: Callable[[int, int], int],
    poke_user: Callable[[int, int, int], None],
) -> PtraceHardwareBreakpointManager:
    """Returns an instance of the hardware breakpoint manager to be used by the `_InternalDebugger` class."""
    architecture = libcontext.arch

    match architecture:
        case "amd64":
            return Amd64PtraceHardwareBreakpointManager(thread, peek_user, poke_user)
        case _:
            raise NotImplementedError(f"Architecture {architecture} not available.")
