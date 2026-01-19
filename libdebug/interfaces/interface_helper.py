#
# This file is part of libdebug Python library (https://github.com/libdebug/libdebug).
# Copyright (c) 2023-2025 Roberto Alessandro Bertolini. All rights reserved.
# Licensed under the MIT license. See LICENSE file in the project root for details.
#

from __future__ import annotations

from typing import TYPE_CHECKING

from libdebug.interfaces.interfaces import AvailableInterfaces
from libdebug.ptrace.ptrace_interface import PtraceInterface

if TYPE_CHECKING:
    from libdebug.debugger.internal_debugger import InternalDebugger
    from libdebug.interfaces.debugging_interface import DebuggingInterface


def provide_debugging_interface(
    internal_debugger: InternalDebugger,
    interface: AvailableInterfaces = AvailableInterfaces.PTRACE,
) -> DebuggingInterface:
    """Returns an instance of the debugging interface to be used by the `_InternalDebugger` class."""
    match interface:
        case AvailableInterfaces.PTRACE:
            return PtraceInterface(internal_debugger)
        case _:
            raise NotImplementedError(f"Interface {interface} not available.")
